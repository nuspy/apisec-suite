"""Analisi LLM dei finding, dopo il merge di tutti gli engine.

Qui sta la differenza rispetto all'analisi che APISCAN fa da solo: l'LLM non
vede i risultati di *un* tool, vede quelli uniti di tutti. Puo' quindi dire
cose che nessun engine da solo puo' dire - che due segnalazioni sono lo stesso
difetto visto da angoli diversi, che un header mancante e un BOLA sullo stesso
endpoint compongono un percorso di attacco, che un finding e' implausibile
viste le prove raccolte da un altro engine.

Una regola sta sopra tutto il resto, ed e' cablata nel codice, non solo nei
prompt:

    **L'LLM annota, non cancella.** Un verdetto di "falso positivo" diventa un
    campo del finding, non la sua rimozione. Un modello che sbaglia deve poter
    costare al massimo una riga di rumore in un report, mai una vulnerabilita'
    vera che sparisce prima di essere letta da un umano.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Sequence

from ..config import LLMSettings
from ..findings import Finding, Severity, count_by_severity, sort_findings
from .bridge import LLMUnavailable
from .client import LLMClient, LLMError

#: Verdetti ammessi. Qualunque altra cosa il modello restituisca viene
#: normalizzata a `incerto`: un valore inatteso non deve diventare un giudizio.
VERDICTS = ("confermato", "probabile", "incerto", "falso-positivo")

_SYSTEM = (
    "Sei un revisore di sicurezza applicativa specializzato in API. "
    "Analizzi risultati di scansioni DAST gia' eseguite. "
    "Rispondi sempre e solo con JSON valido, senza testo attorno. "
    "Sii conservativo: se le prove non bastano per escludere un difetto, "
    "il verdetto e' 'incerto', mai 'falso-positivo'."
)

#: Quanti finding per chiamata. Batch piccoli tengono il prompt sotto controllo
#: e limitano il danno se una singola chiamata fallisce.
BATCH_SIZE = 8


@dataclass
class AnalysisReport:
    """Esito dell'analisi. Tutti i campi sono opzionali per costruzione."""

    executive_summary: str = ""
    attack_paths: list[str] = field(default_factory=list)
    priorities: list[str] = field(default_factory=list)
    model: str = ""
    provider: str = ""
    #: Finding analizzati con successo.
    analyzed: int = 0
    #: Errori incontrati, non fatali.
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "executive_summary": self.executive_summary,
            "attack_paths": self.attack_paths,
            "priorities": self.priorities,
            "model": self.model,
            "provider": self.provider,
            "analyzed": self.analyzed,
            "errors": self.errors,
        }


class Analyst:
    """Applica l'analisi LLM a una lista di finding."""

    def __init__(self, settings: LLMSettings, client: LLMClient | None = None) -> None:
        self.settings = settings
        self.client = client or LLMClient(settings)

    # ------------------------------------------------------------------ #

    def run(self, findings: Sequence[Finding],
            progress: Callable[[str], None] | None = None) -> AnalysisReport:
        """Triage dei finding + sintesi complessiva.

        Non solleva: qualunque problema del modello finisce in
        `AnalysisReport.errors`, perche' una scansione riuscita non deve
        risultare fallita perche' un LLM non ha risposto.
        """
        report = AnalysisReport()

        def say(message: str) -> None:
            if progress is not None:
                progress(message)

        if not findings:
            report.executive_summary = "Nessun finding da analizzare."
            return report

        try:
            endpoint = self.client.endpoint
            report.model = endpoint.model
            report.provider = endpoint.provider_label or endpoint.provider_id
            say(f"[*] Analisi LLM tramite {endpoint.describe()}")
        except LLMUnavailable as exc:
            report.errors.append(str(exc))
            say(f"[!] Analisi LLM saltata: {exc}")
            return report

        batches = list(_chunks(list(findings), BATCH_SIZE))
        for index, batch in enumerate(batches, start=1):
            say(f"[*] Triage batch {index}/{len(batches)} ({len(batch)} finding)")
            try:
                self._triage_batch(batch)
                report.analyzed += len(batch)
            except (LLMError, LLMUnavailable) as exc:
                report.errors.append(f"triage batch {index}: {exc}")
                say(f"[!] Triage batch {index} fallito: {exc}")

        say("[*] Sintesi complessiva")
        try:
            self._summarize(findings, report)
        except (LLMError, LLMUnavailable) as exc:
            report.errors.append(f"sintesi: {exc}")
            say(f"[!] Sintesi fallita: {exc}")

        return report

    # ------------------------------------------------------------------ #

    def _triage_batch(self, batch: Sequence[Finding]) -> None:
        prompt = _triage_prompt(batch)
        data = self.client.chat_json(prompt, _SYSTEM)
        entries = _as_entries(data)

        by_index = {i: f for i, f in enumerate(batch, start=1)}
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            finding = by_index.get(_as_int(entry.get("id")))
            if finding is None:
                continue
            verdict = str(entry.get("verdetto") or "").strip().lower()
            finding.llm_verdict = verdict if verdict in VERDICTS else "incerto"
            finding.llm_rationale = str(entry.get("motivazione") or "").strip()
            remediation = str(entry.get("rimedio") or "").strip()
            if remediation and not finding.remediation:
                finding.remediation = remediation

    def _summarize(self, findings: Sequence[Finding],
                   report: AnalysisReport) -> None:
        prompt = _summary_prompt(findings)
        data = self.client.chat_json(prompt, _SYSTEM)
        if not isinstance(data, dict):
            raise LLMError("la sintesi non e' un oggetto JSON")
        report.executive_summary = str(data.get("sintesi") or "").strip()
        report.attack_paths = [str(x) for x in (data.get("percorsi_attacco") or [])
                               if str(x).strip()]
        report.priorities = [str(x) for x in (data.get("priorita") or [])
                             if str(x).strip()]


# ---------------------------------------------------------------------- #
# Prompt
# ---------------------------------------------------------------------- #

def _triage_prompt(batch: Sequence[Finding]) -> str:
    items = []
    for index, finding in enumerate(batch, start=1):
        items.append({
            "id": index,
            "titolo": finding.title,
            "engine": finding.engine,
            "regola": finding.rule_id,
            "severita_dichiarata": finding.severity.value,
            "cvss": finding.cvss,
            "cvss_e_una_stima": finding.cvss_estimated,
            "owasp": finding.owasp,
            "cwe": finding.cwe,
            "endpoint": f"{finding.method} {finding.normalized_path}".strip(),
            "descrizione": finding.description[:600],
            "confermato_anche_da": finding.corroborated_by,
            "prova": finding.evidence.summary(max_body=500),
        })

    return (
        "Analizza questi risultati di scansione di sicurezza su un'API.\n"
        "Per ognuno stabilisci se il difetto e' reale, sulla base delle prove "
        "riportate.\n\n"
        "Criteri:\n"
        "- 'confermato': la prova mostra il difetto in modo inequivocabile.\n"
        "- 'probabile': la prova e' coerente col difetto ma non conclusiva.\n"
        "- 'incerto': le prove non bastano per decidere. Usalo come default.\n"
        "- 'falso-positivo': solo se la prova CONTRADDICE il difetto.\n"
        "Un finding confermato da piu' engine indipendenti e' piu' credibile.\n\n"
        "Rispondi con un array JSON, un oggetto per finding:\n"
        '[{"id": 1, "verdetto": "confermato|probabile|incerto|falso-positivo", '
        '"motivazione": "una o due frasi, in italiano", '
        '"rimedio": "azione concreta, in italiano"}]\n\n'
        "FINDING:\n"
        + json.dumps(items, ensure_ascii=False, indent=1)
    )


def _summary_prompt(findings: Sequence[Finding]) -> str:
    counts = count_by_severity(findings)
    top = sort_findings(findings)[:25]
    compact = [
        {
            "titolo": f.title,
            "severita": f.severity.value,
            "owasp": f.owasp[0] if f.owasp else "",
            "endpoint": f"{f.method} {f.normalized_path}".strip(),
            "engine": f.engine,
            "verdetto_llm": f.llm_verdict,
        }
        for f in top
    ]

    return (
        "Sintetizza l'esito di una scansione di sicurezza su un'API.\n\n"
        f"Conteggio per severita': {json.dumps(counts, ensure_ascii=False)}\n"
        f"Finding totali: {len(findings)}\n\n"
        "Finding piu' gravi:\n"
        + json.dumps(compact, ensure_ascii=False, indent=1)
        + "\n\nRispondi in JSON, in italiano:\n"
        '{"sintesi": "3-6 frasi per un lettore tecnico che non ha eseguito la '
        'scansione: cosa e\' stato trovato e quanto e\' grave", '
        '"percorsi_attacco": ["combinazioni di finding che insieme aprono un '
        'attacco che nessuno di loro apre da solo"], '
        '"priorita": ["azioni in ordine di urgenza, la piu\' urgente per prima"]}'
    )


# ---------------------------------------------------------------------- #

def _chunks(items: list[Finding], size: int) -> Iterable[list[Finding]]:
    for start in range(0, len(items), size):
        yield items[start:start + size]


def _as_entries(data: Any) -> list[Any]:
    """Il modello puo' rispondere con un array o incapsularlo in un oggetto."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("finding", "findings", "risultati", "results", "items"):
            value = data.get(key)
            if isinstance(value, list):
                return value
        if "id" in data:
            return [data]
    return []


def _as_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return -1


def severity_after_triage(finding: Finding) -> Severity:
    """Severita' da mostrare tenendo conto del verdetto LLM.

    Un falso positivo secondo il modello viene *degradato* a informativo, non
    rimosso: resta nel report, ordinato in fondo, con la motivazione accanto.
    Chi legge decide.
    """
    if finding.llm_verdict == "falso-positivo":
        return Severity.INFO
    return finding.severity
