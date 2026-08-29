"""Fusione dei finding provenienti da engine diversi.

Senza questo passaggio il report combinato sarebbe tre report incollati: lo
stesso header HSTS mancante comparirebbe come "HSTS Missing" (vulnapi) e come
"Security Misconfiguration" (APISCAN), e chi legge non saprebbe se sono due
problemi o uno.

La fusione fa due cose, in quest'ordine:

1. **Unisce i duplicati** dello stesso difetto, dentro e fra gli engine, sulla
   chiave `(categoria, metodo, path normalizzato)`.
2. **Registra la corroborazione**: un difetto trovato da due engine
   indipendenti e' piu' credibile di uno trovato da uno solo, e il campo
   `corroborated_by` lo rende esplicito nel report e nei prompt dell'analista.

Cosa NON fa, deliberatamente: scartare. Un finding che non collide con nessuno
resta. La fusione riduce il rumore, non la copertura.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Iterable, Sequence

from ..findings import Finding, Severity, count_by_severity, sort_findings


@dataclass
class MergeStats:
    """Cosa e' successo durante la fusione, per il report e per i log."""

    total_input: int = 0
    total_output: int = 0
    merged_away: int = 0
    #: Finding confermati da piu' di un engine.
    corroborated: int = 0
    per_engine: dict[str, int] = field(default_factory=dict)

    def summary(self) -> str:
        engines = ", ".join(f"{k}: {v}" for k, v in sorted(self.per_engine.items()))
        return (f"{self.total_input} finding grezzi ({engines}) -> "
                f"{self.total_output} dopo la fusione, "
                f"{self.corroborated} confermati da piu' engine")


def merge_findings(
    groups: Iterable[Sequence[Finding]] | Sequence[Finding],
) -> tuple[list[Finding], MergeStats]:
    """Unisce i finding e restituisce la lista ordinata piu' le statistiche.

    Accetta sia una lista piatta sia una sequenza di liste (una per engine).
    """
    flat: list[Finding] = []
    for item in groups:
        if isinstance(item, Finding):
            flat.append(item)
        else:
            flat.extend(item)

    stats = MergeStats(total_input=len(flat))
    for finding in flat:
        stats.per_engine[finding.engine] = stats.per_engine.get(finding.engine, 0) + 1

    buckets: dict[str, list[Finding]] = defaultdict(list)
    for finding in flat:
        buckets[finding.dedup_key()].append(finding)

    merged: list[Finding] = []
    for group in buckets.values():
        merged.append(_collapse(group))

    stats.total_output = len(merged)
    stats.merged_away = stats.total_input - stats.total_output
    stats.corroborated = sum(1 for f in merged if len(f.corroborated_by) > 1)
    return sort_findings(merged), stats


def _collapse(group: list[Finding]) -> Finding:
    """Riduce un gruppo di duplicati a un solo finding.

    Il rappresentante e' scelto, non sintetizzato: costruire un finding nuovo
    mescolando campi di piu' engine produrrebbe una prova che non appartiene a
    nessuna esecuzione reale, e la prova deve restare verificabile.
    """
    if len(group) == 1:
        finding = group[0]
        finding.corroborated_by = [finding.engine]
        return finding

    best = max(group, key=_quality)

    engines: list[str] = []
    for finding in group:
        if finding.engine not in engines:
            engines.append(finding.engine)
    best.corroborated_by = engines

    # Le classificazioni si uniscono: un engine puo' conoscere la CWE e
    # l'altro no, e tenere la piu' ricca non falsifica nulla.
    best.cwe = _union(f.cwe for f in group)
    best.owasp = _union(f.owasp for f in group)
    best.references = _union(f.references for f in group)

    # La descrizione piu' informativa, se il rappresentante non ne ha una.
    if not best.description:
        for finding in group:
            if finding.description:
                best.description = finding.description
                break
    if not best.remediation:
        for finding in group:
            if finding.remediation:
                best.remediation = finding.remediation
                break

    # La prova migliore, se il rappresentante non ne ha.
    if best.evidence.is_empty():
        for finding in group:
            if not finding.evidence.is_empty():
                best.evidence = finding.evidence
                break

    best.raw = {**best.raw, "merged_from": [
        {"engine": f.engine, "rule_id": f.rule_id, "title": f.title,
         "severity": f.severity.value}
        for f in group if f is not best
    ]}
    return best


def _quality(finding: Finding) -> tuple:
    """Ordine di preferenza fra duplicati.

    Un CVSS misurato batte una severita' dichiarata: vulnapi calcola un vettore
    CVSS 4.0 vero, APISCAN scrive una parola. A parita', vince chi ha la prova.
    """
    return (
        finding.severity.rank,
        0 if finding.cvss_estimated else 1,
        finding.cvss,
        0 if finding.evidence.is_empty() else 1,
        len(finding.description),
    )


def _union(lists: Iterable[Sequence[str]]) -> list[str]:
    """Unione preservando l'ordine di prima apparizione."""
    out: list[str] = []
    for items in lists:
        for item in items:
            if item and item not in out:
                out.append(item)
    return out


# ---------------------------------------------------------------------- #

def coverage_matrix(findings: Sequence[Finding]) -> dict[str, dict[str, int]]:
    """Quante segnalazioni per categoria OWASP e per engine.

    E' la tabella che rende visibile la complementarieta': le colonne vuote di
    un engine sono esattamente le lacune che l'altro copre.
    """
    from ..findings import OWASP_API_2023

    matrix: dict[str, dict[str, int]] = {
        key: defaultdict(int) for key in OWASP_API_2023
    }
    matrix["(non classificato)"] = defaultdict(int)

    for finding in findings:
        key = finding.owasp[0] if finding.owasp else "(non classificato)"
        if key not in matrix:
            matrix[key] = defaultdict(int)
        for engine in (finding.corroborated_by or [finding.engine]):
            matrix[key][engine] += 1

    return {k: dict(v) for k, v in matrix.items()}


def risk_score(findings: Sequence[Finding]) -> float:
    """Punteggio di rischio 0-100 per il gate di CI.

    Non e' una media: una singola vulnerabilita' critica deve pesare piu' di
    venti segnalazioni informative, quindi domina il massimo, corretto in su
    dalla quantita' di problemi gravi.
    """
    if not findings:
        return 0.0
    counts = count_by_severity(findings)
    peak = max((f.cvss for f in findings), default=0.0)
    volume = (counts[Severity.CRITICAL.value] * 4
              + counts[Severity.HIGH.value] * 2
              + counts[Severity.MEDIUM.value])
    return round(min(100.0, peak * 8.0 + min(volume, 25) * 0.8), 1)


def gate_failed(findings: Sequence[Finding], threshold: str = "high") -> bool:
    """La pipeline deve fallire?

    `threshold` e' la severita' minima che fa fallire. Un finding degradato a
    informativo dall'analista LLM non fa fallire la build, ma resta nel report.
    """
    limit = _threshold_rank(threshold)
    for finding in findings:
        if finding.llm_verdict == "falso-positivo":
            continue
        if finding.severity.rank >= limit:
            return True
    return False


def _threshold_rank(threshold: str) -> int:
    try:
        return Severity.parse(threshold).rank
    except Exception:
        return Severity.HIGH.rank
