"""Engine APISCAN: lo scanner Python di Perry Mertens (AGPL-3.0).

E' l'unico dei tre a coprire i rischi che richiedono stato e contesto - BOLA,
BFLA multi-ruolo, mass assignment, business logic, SSRF, injection - cioe'
esattamente quelli che vulnapi non affronta per costruzione. Le due coperture
sono complementari, ed e' il motivo per cui la suite li esegue entrambi invece
di scegliere.

Due scelte di integrazione che vale la pena spiegare:

**I finding si leggono da SQLite, non dall'HTML.** APISCAN accetta `--db-path`
e ci scrive ogni finding in una tabella `finding` con metodo, endpoint,
richiesta, risposta e severita'. E' una sorgente strutturata e stabile, mentre
il parsing dei report HTML si romperebbe al primo ritocco del template.

**Il processo gira in una cartella nostra.** APISCAN scrive i suoi artefatti in
`Path.cwd()`; lanciandolo con `cwd` sulla cartella della run, i suoi HTML
finiscono ordinati sotto la run invece che sparsi nella cartella di lavoro
dell'utente. Gli import continuano a funzionare perche' Python mette in
`sys.path[0]` la cartella dello *script*, non quella di lavoro.
"""
from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from typing import Any, Iterable, Sequence

from ..config import ScanConfig
from ..findings import Evidence, Finding, Severity
from .base import Availability, Engine, python_executable

#: `risk_key` di APISCAN -> categoria OWASP API Security Top 10 (2023).
#:
#: I valori sono quelli che APISCAN passa davvero a `store_issues()`, non
#: quelli di `manual_file_map` (che serve ai nomi dei file HTML e usa nomi
#: diversi: "Misconfig" contro "Misconfiguration", "BrokenAuth" contro
#: "Authentication"). Gli alias della mappa dei file restano accettati, cosi'
#: la lettura non si rompe se upstream li uniforma.
RISK_TO_OWASP: dict[str, str] = {
    "BOLA": "API1:2023",
    "Authentication": "API2:2023",
    "Property": "API3:2023",
    "Resource": "API4:2023",
    "AdminAccess": "API5:2023",
    "BusinessFlows": "API6:2023",
    "SSRF": "API7:2023",
    "Misconfiguration": "API8:2023",
    "Inventory": "API9:2023",
    "UnsafeConsumption": "API10:2023",
    # Le catene di escalation partono da un BOLA e arrivano a una funzione
    # non autorizzata: si classificano sull'origine.
    "Chain-Escalation": "API1:2023",
    # Alias dei nomi file, per robustezza.
    "BrokenAuth": "API2:2023",
    "Misconfig": "API8:2023",
}

#: CWE rappresentativa per categoria, per i report che la richiedono (SARIF).
RISK_TO_CWE: dict[str, str] = {
    "BOLA": "CWE-639",
    "Authentication": "CWE-287",
    "Property": "CWE-915",
    "Resource": "CWE-770",
    "AdminAccess": "CWE-285",
    "BusinessFlows": "CWE-840",
    "SSRF": "CWE-918",
    "Misconfiguration": "CWE-16",
    "Inventory": "CWE-1059",
    "UnsafeConsumption": "CWE-1104",
    "Chain-Escalation": "CWE-639",
    "BrokenAuth": "CWE-287",
    "Misconfig": "CWE-16",
}

#: Stati che NON sono un difetto. APISCAN registra in tabella anche i test
#: superati, e portarseli nel report combinato lo renderebbe illeggibile.
_NON_ISSUE_STATUS = {"pass", "passed", "ok", "clean", "not_vulnerable", "info_only"}


class ApiscanEngine(Engine):
    name = "apiscan"
    label = "APISCAN"
    license = "AGPL-3.0"
    default_timeout_s = 5400.0

    def __init__(self, script: str = "") -> None:
        super().__init__()
        self._script_hint = script
        self._db_path: Path | None = None

    # ------------------------------------------------------------------ #

    def script_path(self) -> Path | None:
        """Percorso di `apiscan.py`, cercato dove ha senso che sia."""
        candidates: list[Path] = []
        if self._script_hint:
            candidates.append(Path(self._script_hint))
        env = os.getenv("APISCAN_HOME", "").strip()
        if env:
            candidates.append(Path(env) / "apiscan.py")
        root = Path(__file__).resolve().parents[2]
        candidates += [
            root / "vendor" / "apiscanner" / "apiscan.py",
            root / "apiscanner" / "apiscan.py",
            root / "apiscan.py",
        ]
        for candidate in candidates:
            if candidate.is_file():
                return candidate.resolve()
        return None

    def home(self) -> Path | None:
        script = self.script_path()
        return script.parent if script else None

    def check(self) -> Availability:
        script = self.script_path()
        if script is None:
            return Availability(
                ok=False,
                detail="apiscan.py non trovato",
                hint="esegui `python bootstrap.py --apiscan` per clonarlo in vendor/",
            )
        try:
            import requests  # noqa: F401
        except ImportError:
            return Availability(
                ok=False, path=str(script),
                detail="dipendenze APISCAN mancanti",
                hint="pip install -r vendor/apiscanner/requirements.txt",
            )
        return Availability(ok=True, path=str(script), detail=f"script: {script}")

    def limitations(self) -> list[str]:
        return [
            "Nessuna suite di test automatica a monte: i falsi positivi e i "
            "falsi negativi non sono misurati.",
            "Non produce SARIF ne' JSON dei finding: la suite li estrae dal "
            "database SQLite delle evidenze.",
            "Non valida la conformita' delle risposte al contratto OpenAPI.",
            "AGPL-3.0: distribuendo la suite come servizio in rete va "
            "pubblicato il sorgente completo.",
        ]

    # ------------------------------------------------------------------ #

    def working_dir(self, cfg: ScanConfig) -> Path | None:
        # APISCAN scrive `audit_<host>_<timestamp>/` nella cwd: puntandola
        # sulla cartella della run, i suoi artefatti restano raccolti li'.
        return cfg.engine_dir(self.name)

    def prepare(self, cfg: ScanConfig) -> None:
        self._db_path = cfg.engine_dir(self.name) / "results.db"
        if self._db_path.exists():
            self._db_path.unlink()

    def build_env(self, cfg: ScanConfig) -> dict[str, str]:
        env = super().build_env(cfg)
        # Le progress bar di tqdm scrivono \r senza \n e bloccano i lettori
        # a righe: senza questo la GUI resta muta per tutta la scansione.
        env["TQDM_DISABLE"] = "1"
        env.update(cfg.apiscan_env)

        if cfg.llm.enabled and cfg.llm.drive_apiscan:
            # APISCAN legge la configurazione LLM dall'ambiente e ha gia' un
            # provider `openai_compat`: valorizzando queste variabili con un
            # endpoint risolto da llmswitch, parla con qualunque provider del
            # registry senza che una riga del suo codice cambi.
            from ..llm.bridge import apiscan_env_for
            env.update(apiscan_env_for(cfg.llm))
        return env

    # ------------------------------------------------------------------ #

    def build_command(self, cfg: ScanConfig) -> list[str]:
        script = self.script_path()
        if script is None:
            raise RuntimeError("apiscan.py non trovato")
        assert self._db_path is not None

        if cfg.apiscan_argv_override:
            # La GUI ha gia' tradotto i propri widget in flag: si aggiunge solo
            # `--db-path`, che serve alla suite per rileggere i finding.
            cmd = [python_executable(), str(script)]
            cmd += _absolutize_argv(cfg.apiscan_argv_override)
            if "--db-path" not in cmd:
                cmd += ["--db-path", str(self._db_path)]
            return cmd

        cmd = [python_executable(), str(script), "--url", cfg.target_url]

        if cfg.openapi:
            cmd += ["--swagger", cfg.openapi]
        if cfg.crawl:
            cmd.append("--crawl")

        cmd += ["--db-path", str(self._db_path)]

        if cfg.threads > 0:
            cmd += ["--threads", str(cfg.threads)]
        if cfg.timeout > 0:
            cmd += ["--timeout", str(cfg.timeout)]
        if cfg.proxy.strip():
            cmd += ["--proxy", cfg.proxy.strip()]
        if cfg.insecure:
            cmd.append("--insecure")
        if cfg.debug:
            cmd.append("--debug")

        cmd += self._auth_args(cfg)

        # Senza --apiN esplicite APISCAN esegue tutte le categorie: si passano
        # solo quando la selezione e' un sottoinsieme, altrimenti undici flag
        # ridondanti rendono il comando illeggibile nei log.
        checks = [c for c in cfg.apiscan_checks if c]
        if checks and set(checks) != {f"api{i}" for i in range(1, 11)}:
            for check in checks:
                cmd.append(f"--{check}")

        if cfg.llm.enabled and cfg.llm.drive_apiscan and "api11" in checks:
            if "--api11" not in cmd:
                cmd.append("--api11")

        cmd += list(cfg.apiscan_extra_args)
        return cmd

    def _auth_args(self, cfg: ScanConfig) -> list[str]:
        """Traduce la configurazione neutra nei flag di APISCAN."""
        auth = cfg.auth
        args: list[str] = []
        flow = (auth.flow or "none").strip().lower()
        if flow and flow != "none":
            args += ["--flow", flow]

        if auth.token.strip():
            args += ["--token", auth.token.strip()]
        if auth.basic_auth.strip():
            args += ["--basic-auth", auth.basic_auth.strip()]
        if auth.ntlm.strip():
            args += ["--ntlm", auth.ntlm.strip()]
        if auth.api_key.strip():
            args += ["--apikey", auth.api_key.strip()]
            if auth.api_key_header.strip():
                args += ["--apikey-header", auth.api_key_header.strip()]

        for flag, value in (
            ("--client-id", auth.client_id), ("--client-secret", auth.client_secret),
            ("--token-url", auth.token_url), ("--auth-url", auth.auth_url),
            ("--redirect-uri", auth.redirect_uri), ("--scope", auth.scope),
            ("--client-cert", auth.client_cert), ("--client-key", auth.client_key),
            ("--cert-password", auth.cert_password),
            ("--login-url", auth.login_url),
            ("--login-username", auth.login_username),
            ("--login-password", auth.login_password),
            ("--token-path", auth.token_path),
        ):
            if str(value).strip():
                args += [flag, str(value).strip()]
        return args

    # ------------------------------------------------------------------ #

    def collect(self, cfg: ScanConfig) -> list[Finding]:
        db = self._db_path or (cfg.engine_dir(self.name) / "results.db")
        findings = list(read_findings_db(db)) if db.exists() else []
        return findings

    def artifacts(self, cfg: ScanConfig) -> list[Path]:
        """Report HTML prodotti da APISCAN, per allegarli alla run."""
        base = cfg.engine_dir(self.name)
        return sorted(base.glob("audit_*/*.html")) + sorted(base.glob("*.html"))


# ---------------------------------------------------------------------- #
# Lettura del database delle evidenze
# ---------------------------------------------------------------------- #

#: Flag di APISCAN il cui valore e' un percorso di file.
_PATH_FLAGS = frozenset({
    "--swagger", "--db-path", "--client-cert", "--client-key",
    "--headers-file", "--ids-file", "--export_vars",
})


def _absolutize_argv(argv: Sequence[str]) -> list[str]:
    """Rende assoluti i percorsi dentro una riga di comando gia' costruita.

    Serve agli argomenti che arrivano dalla GUI: sono relativi alla cartella
    da cui l'utente ha avviato l'applicazione, mentre l'engine gira nella
    cartella della run.
    """
    out: list[str] = []
    expect_path = False
    for item in argv:
        if expect_path:
            expect_path = False
            candidate = Path(str(item))
            out.append(str(candidate.resolve()) if candidate.is_file() else item)
            continue
        out.append(item)
        if item in _PATH_FLAGS:
            expect_path = True
    return out


def read_findings_db(db_path: Path) -> Iterable[Finding]:
    """Legge la tabella `finding` di APISCAN e la normalizza.

    Apre in sola lettura: il file puo' essere ancora aperto dal processo di
    APISCAN se la raccolta avviene dopo un'interruzione, e non deve essere
    modificato in nessun caso.
    """
    uri = f"file:{db_path.as_posix()}?mode=ro"
    try:
        conn = sqlite3.connect(uri, uri=True, timeout=10)
    except sqlite3.Error as exc:
        raise RuntimeError(f"database APISCAN non apribile: {exc}") from exc

    try:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        try:
            cur.execute("SELECT * FROM finding")
        except sqlite3.Error:
            # Nessuna tabella `finding`: la scansione non e' arrivata a
            # scrivere nulla. Non e' un errore da propagare.
            return []
        rows = cur.fetchall()
    finally:
        conn.close()

    out: list[Finding] = []
    for row in rows:
        finding = _row_to_finding(dict(row))
        if finding is not None:
            out.append(finding)
    return out


def _row_to_finding(row: dict[str, Any]) -> Finding | None:
    status = str(row.get("status") or "").strip().lower()
    if status in _NON_ISSUE_STATUS:
        return None

    risk_key = str(row.get("risk_key") or "").strip()
    severity = Severity.parse(row.get("severity"))
    endpoint = str(row.get("endpoint") or "")
    owasp = RISK_TO_OWASP.get(risk_key, "")
    cwe = RISK_TO_CWE.get(risk_key, "")

    return Finding(
        engine="apiscan",
        rule_id=f"apiscan.{risk_key or 'unknown'}",
        title=str(row.get("title") or risk_key or "finding"),
        severity=severity,
        # APISCAN dichiara una parola, non un punteggio: il CVSS resta una
        # stima, ed e' marcato come tale.
        cvss=0.0,
        cvss_estimated=True,
        cwe=[cwe] if cwe else [],
        owasp=[owasp] if owasp else [],
        method=str(row.get("method") or ""),
        path=_path_of(endpoint),
        url=endpoint,
        description=str(row.get("description") or ""),
        evidence=Evidence(
            request_method=str(row.get("method") or ""),
            request_url=endpoint,
            request_headers=_parse_headers(row.get("req_headers")),
            request_body=_as_text(row.get("req_body")),
            response_status=_as_int(row.get("res_status")),
            response_headers=_parse_headers(row.get("res_headers")),
            response_body=_as_text(row.get("res_body"))[:4000],
        ),
        raw={"risk_key": risk_key, "category": row.get("category"),
             "status": row.get("status"), "run_id": row.get("run_id")},
    )


def _path_of(endpoint: str) -> str:
    if not endpoint:
        return ""
    if endpoint.startswith("/"):
        return endpoint
    from urllib.parse import urlsplit
    try:
        return urlsplit(endpoint).path or endpoint
    except Exception:
        return endpoint


def _parse_headers(value: Any) -> dict[str, str]:
    """Gli header sono salvati come JSON, ma non sempre nella stessa forma.

    APISCAN li redige prima di scriverli e a seconda del modulo escono come
    oggetto, come lista di coppie, o come testo gia' formattato. Vengono
    accettate tutte e tre.
    """
    if not value:
        return {}
    if isinstance(value, dict):
        return {str(k): str(v) for k, v in value.items()}

    import json
    text = str(value)
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return {"raw": text[:1000]}

    if isinstance(data, dict):
        return {str(k): str(v) for k, v in data.items()}
    if isinstance(data, list):
        out: dict[str, str] = {}
        for item in data:
            if isinstance(item, (list, tuple)) and len(item) == 2:
                out[str(item[0])] = str(item[1])
            elif isinstance(item, dict):
                out.update({str(k): str(v) for k, v in item.items()})
        return out
    return {"raw": text[:1000]}


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _as_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
