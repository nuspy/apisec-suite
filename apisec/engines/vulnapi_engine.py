"""Engine vulnapi: il binario Go di Cerberauth.

Copre bene cio' che si vede senza stato: fingerprinting, header e cookie di
sicurezza, batteria JWT, authentication bypass, TRACE/TRACK, method override.
Non copre nulla che richieda due utenti o due ruoli - e' un tool `context-free`
per scelta di design, non per lacuna implementativa.

Due asperita' che questo modulo appiana, entrambe trovate sul campo:

1. **vulnapi rifiuta un OpenAPI senza `servers`** ("no valid base url has been
   found in OpenAPI file"). FastAPI, Flask-smorest e parecchi generatori non lo
   emettono. APISCAN invece prende la base URL da `--url`. Qui si scrive una
   copia dell'OpenAPI con `servers` valorizzato dal `target_url` gia'
   configurato, cosi' l'utente compila un campo solo.

2. **Lo schema del report cambia fra la release e il branch main.** La v0.9.0
   pubblicata emette `{reports: [...], curl|openapi: {issues: [...]}}`; il main
   e' passato a `reportx` e emette `{findings: [...]}` con SARIF nativo. Il
   parser riconosce entrambi invece di legarsi a una versione.
"""
from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import Any

from ..config import ScanConfig
from ..findings import Evidence, Finding, Severity
from .base import Availability, Engine, resolve_executable

#: Ordine di ricerca del binario. La copia dentro il progetto ha la precedenza:
#: garantisce la stessa versione su tutte le macchine del team.
_BINARY_NAMES = ("vulnapi.exe", "vulnapi") if os.name == "nt" else ("vulnapi",)

#: `failed` = il check ha rilevato il problema. `passed` = tutto a posto.
#: `skipped` = non applicabile (i check JWT senza un token, per esempio).
_VULNERABLE_STATUS = "failed"


class VulnapiEngine(Engine):
    name = "vulnapi"
    label = "VulnAPI"
    license = "MIT"
    # Su un OpenAPI con molte operazioni vulnapi e' lento: applica un rate
    # limit interno e moltiplica 30+ check per ogni operazione. Misurato:
    # oltre 13 minuti su 10 endpoint senza aver finito. Il default e' alto
    # apposta, e resta configurabile.
    default_timeout_s = 5400.0

    def __init__(self, binary: str = "") -> None:
        super().__init__()
        self._binary_hint = binary
        self._report_path: Path | None = None
        self._openapi_path: Path | None = None

    # ------------------------------------------------------------------ #

    def binary(self) -> str:
        candidates = [self._binary_hint] if self._binary_hint else []
        candidates.append(os.getenv("VULNAPI_BIN", ""))
        # bin/ del progetto, risalendo da apisec/engines/ alla radice.
        project_bin = Path(__file__).resolve().parents[2] / "bin"
        candidates += [str(project_bin / n) for n in _BINARY_NAMES]
        candidates += list(_BINARY_NAMES)
        return resolve_executable(*candidates)

    def check(self) -> Availability:
        path = self.binary()
        if not path:
            return Availability(
                ok=False,
                detail="binario vulnapi non trovato",
                hint="esegui `python bootstrap.py --vulnapi` per scaricarlo",
            )
        return Availability(ok=True, path=path, detail=f"binario: {path}")

    def limitations(self) -> list[str]:
        return [
            "Non copre BOLA (API1), BFLA (API5), mass assignment (API3), "
            "business logic (API6), SSRF (API7) ne' injection: e' context-free "
            "e testa ogni operazione isolatamente.",
            "Non valida la conformita' delle risposte al contratto OpenAPI.",
            "Gli unici flow di autenticazione supportati sono quelli "
            "esprimibili come header o come opzione curl: niente OAuth2 con "
            "scambio di token ne' form-login.",
        ]

    # ------------------------------------------------------------------ #

    def prepare(self, cfg: ScanConfig) -> None:
        self._report_path = cfg.engine_dir(self.name) / "vulnapi-report.json"
        if self._report_path.exists():
            self._report_path.unlink()
        self._openapi_path = None
        if cfg.vulnapi_mode == "openapi" and cfg.openapi:
            self._openapi_path = self._ensure_servers(cfg)

    def _ensure_servers(self, cfg: ScanConfig) -> Path:
        """Restituisce un OpenAPI che vulnapi accetta.

        Se il file originale ha gia' un `servers` utilizzabile lo si usa
        com'e'. Altrimenti se ne scrive una copia nella cartella della run con
        `servers` preso dal `target_url`: modificare il file dell'utente
        sarebbe sbagliato, e lasciarlo com'e' farebbe fallire l'engine.
        """
        source = cfg.openapi
        run_dir = cfg.engine_dir(self.name)

        if source.lower().startswith(("http://", "https://")):
            # Una URL la scarica vulnapi da solo; se le manca `servers`
            # fallira' con un messaggio esplicito, e non abbiamo il file da
            # correggere senza scaricarlo noi.
            return Path(source)

        src = Path(source)
        try:
            raw = src.read_text(encoding="utf-8")
            spec = json.loads(raw) if src.suffix.lower() == ".json" else _load_yaml(raw)
        except Exception as exc:
            raise RuntimeError(f"OpenAPI illeggibile ({src}): {exc}") from exc

        if _has_usable_server(spec):
            return src

        base = cfg.target_url.strip().rstrip("/")
        if not base:
            raise RuntimeError(
                "l'OpenAPI non dichiara `servers` e non c'e' un target_url da "
                "cui derivarlo: vulnapi rifiuterebbe il file"
            )
        spec["servers"] = [{"url": base}]
        patched = run_dir / "openapi.patched.json"
        patched.write_text(json.dumps(spec, ensure_ascii=False), encoding="utf-8")
        return patched

    # ------------------------------------------------------------------ #

    def build_command(self, cfg: ScanConfig) -> list[str]:
        binary = self.binary()
        if not binary:
            raise RuntimeError("binario vulnapi non trovato")
        assert self._report_path is not None

        cmd: list[str] = [binary, "scan"]

        if cfg.vulnapi_mode == "curl":
            cmd += ["curl", cfg.target_url]
        else:
            target = self._openapi_path or Path(cfg.openapi)
            cmd += ["openapi", str(target)]

        cmd += [
            "--report-format", "json",
            "--report-file", str(self._report_path),
            "--no-progress",
            # La suite gira anche in CI e su macchine altrui: non si spedisce
            # telemetria per conto dell'utente senza che l'abbia chiesto.
            "--sqa-opt-out",
        ]

        for header, value in cfg.auth.as_headers().items():
            cmd += ["-H", f"{header}: {value}"]

        if cfg.insecure:
            cmd.append("--insecure")
        if cfg.proxy.strip():
            cmd += ["--proxy", cfg.proxy.strip()]
        if cfg.timeout and cfg.timeout > 0:
            cmd += ["--max-time", str(cfg.timeout)]

        # mTLS: vulnapi usa le stesse opzioni di curl.
        if cfg.auth.client_cert:
            cmd += ["--cert", cfg.auth.client_cert]
        if cfg.auth.client_key:
            cmd += ["--key", cfg.auth.client_key]
        if cfg.auth.cert_password:
            cmd += ["--pass", cfg.auth.cert_password]

        for scan in cfg.vulnapi_scans:
            cmd += ["--scans", scan]
        for scan in cfg.vulnapi_exclude:
            cmd += ["--exclude-scans", scan]

        cmd += list(cfg.vulnapi_extra_args)
        return cmd

    # ------------------------------------------------------------------ #

    def collect(self, cfg: ScanConfig) -> list[Finding]:
        path = self._report_path or (cfg.engine_dir(self.name) / "vulnapi-report.json")
        if not path.exists():
            return []
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise RuntimeError(f"report vulnapi illeggibile: {exc}") from exc
        return parse_vulnapi_report(data)


# ---------------------------------------------------------------------- #
# Parsing
# ---------------------------------------------------------------------- #

def parse_vulnapi_report(data: dict[str, Any]) -> list[Finding]:
    """Normalizza un report vulnapi, in uno qualunque dei due schemi noti."""
    if isinstance(data.get("findings"), list):
        return [_from_reportx(f) for f in data["findings"]]
    if isinstance(data.get("reports"), list):
        return _from_legacy(data)
    return []


def _from_legacy(data: dict[str, Any]) -> list[Finding]:
    """Schema v0.9.0: `reports[]` con `issues[]` e `scans[]`.

    Le issue portano solo l'esito; la prova (richiesta e risposta) sta negli
    `scans` del report che le contiene, collegata per id. Senza questo join il
    report combinato avrebbe i difetti ma non le prove.
    """
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()

    for report in data.get("reports") or []:
        if not isinstance(report, dict):
            continue
        scans_by_id = {
            s.get("id"): s for s in (report.get("scans") or [])
            if isinstance(s, dict) and s.get("id")
        }
        operation = report.get("operation") or {}

        for issue in report.get("issues") or []:
            if not isinstance(issue, dict):
                continue
            if (issue.get("status") or "").lower() != _VULNERABLE_STATUS:
                continue

            issue_id = str(issue.get("id") or "")
            # Lo stesso check puo' comparire in piu' report (uno per
            # operazione): la coppia (check, operazione) lo tiene unico.
            op_id = str(operation.get("id") or "")
            if (issue_id, op_id) in seen:
                continue
            seen.add((issue_id, op_id))

            evidence, method, url = _evidence_from_scans(issue, scans_by_id)
            cvss = issue.get("cvss") or {}
            score = _as_float(cvss.get("score"))
            classifications = issue.get("classifications") or {}

            findings.append(Finding(
                engine="vulnapi",
                rule_id=issue_id,
                title=str(issue.get("name") or issue_id or "finding"),
                # Il punteggio viene da vulnapi, non da noi: e' una misura.
                cvss=score,
                cvss_estimated=False,
                severity=Severity.from_cvss(score),
                cwe=_as_list(classifications.get("cwe")),
                owasp=_owasp_ids(classifications.get("owasp")),
                method=method,
                path=_path_of(url, operation),
                url=url,
                description=_describe(issue_id, classifications),
                references=_as_list(classifications.get("capec")),
                evidence=evidence,
                raw={"issue": issue, "operation": operation,
                     "cvss_vector": cvss.get("vector", "")},
            ))
    return findings


def _from_reportx(item: dict[str, Any]) -> Finding:
    """Schema del branch main: `findings[]` prodotti da reportx."""
    score = _as_float(item.get("cvss40Score") or item.get("cvssScore")
                      or item.get("score"))
    operation = item.get("operation") or {}
    url = str(item.get("url") or operation.get("url") or "")
    method = str(item.get("method") or operation.get("method") or "")
    return Finding(
        engine="vulnapi",
        rule_id=str(item.get("id") or item.get("checkId") or ""),
        title=str(item.get("name") or item.get("title") or "finding"),
        cvss=score,
        cvss_estimated=False,
        severity=Severity.from_cvss(score),
        cwe=_as_list(item.get("cwe")),
        owasp=_owasp_ids(item.get("owasp")),
        method=method,
        path=_path_of(url, operation),
        url=url,
        description=str(item.get("description") or ""),
        remediation=str(item.get("remediation") or ""),
        references=_as_list(item.get("references")),
        evidence=_evidence_from_reportx(item),
        raw={"finding": item},
    )


def _evidence_from_scans(
    issue: dict[str, Any], scans_by_id: dict[str, Any]
) -> tuple[Evidence, str, str]:
    """Ricostruisce la prova dallo scan a cui l'issue fa riferimento."""
    for ref in issue.get("scans") or []:
        if not isinstance(ref, dict):
            continue
        scan = scans_by_id.get(ref.get("id"))
        if not isinstance(scan, dict):
            continue
        request = scan.get("request") or {}
        response = scan.get("response") or {}
        method = str(request.get("method") or "")
        url = str(request.get("url") or "")
        return (
            Evidence(
                request_method=method,
                request_url=url,
                request_headers=_flatten_headers(request.get("headers")),
                request_body=_as_text(request.get("body")),
                response_status=_as_int(response.get("statusCode")),
                response_headers=_flatten_headers(response.get("headers")),
                response_body=_as_text(response.get("body"))[:4000],
            ),
            method,
            url,
        )
    return Evidence(), "", ""


def _evidence_from_reportx(item: dict[str, Any]) -> Evidence:
    ev = item.get("evidence") or {}
    request = ev.get("request") or {}
    response = ev.get("response") or {}
    return Evidence(
        request_method=str(request.get("method") or ""),
        request_url=str(request.get("url") or ""),
        request_headers=_flatten_headers(request.get("headers")),
        request_body=_as_text(request.get("body")),
        response_status=_as_int(response.get("statusCode") or response.get("status")),
        response_headers=_flatten_headers(response.get("headers")),
        response_body=_as_text(response.get("body"))[:4000],
    )


def _flatten_headers(headers: Any) -> dict[str, str]:
    """Go serializza gli header come `{"Nome": ["valore"]}`. Qui servono piatti."""
    if not isinstance(headers, dict):
        return {}
    out: dict[str, str] = {}
    for key, value in headers.items():
        if isinstance(value, (list, tuple)):
            out[str(key)] = ", ".join(str(v) for v in value)
        else:
            out[str(key)] = str(value)
    return out


def _owasp_ids(value: Any) -> list[str]:
    """Estrae gli identificativi dalle etichette OWASP.

    vulnapi scrive "API8:2023 Security Misconfiguration"; per la deduplica
    serve solo "API8:2023", altrimenti una differenza di formulazione fra
    engine impedisce la collisione.
    """
    out: list[str] = []
    for item in _as_list(value):
        token = item.strip().split(" ", 1)[0].strip()
        if token:
            out.append(token)
    return out


def _describe(issue_id: str, classifications: dict[str, Any]) -> str:
    parts = [p for p in (
        classifications.get("owasp") if isinstance(classifications.get("owasp"), str) else "",
    ) if p]
    cwes = _as_list(classifications.get("cwe"))
    if cwes:
        parts.append("CWE: " + ", ".join(cwes))
    return " | ".join(parts) or issue_id


def _path_of(url: str, operation: dict[str, Any]) -> str:
    """Path per la deduplica: quello del contratto se c'e', altrimenti la URL."""
    for key in ("path", "url"):
        value = operation.get(key)
        if isinstance(value, str) and value:
            return value if value.startswith("/") else _url_path(value)
    return _url_path(url)


def _url_path(url: str) -> str:
    if not url:
        return ""
    from urllib.parse import urlsplit
    try:
        return urlsplit(url).path or "/"
    except Exception:
        return url


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value.strip() else []
    if isinstance(value, (list, tuple, set)):
        return [str(v) for v in value if str(v).strip()]
    return [str(value)]


def _as_float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _as_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False)
    except Exception:
        return str(value)


def _load_yaml(raw: str) -> dict[str, Any]:
    try:
        import yaml
    except ImportError as exc:
        raise RuntimeError(
            "OpenAPI in YAML ma PyYAML non e' installato: pip install PyYAML"
        ) from exc
    data = yaml.safe_load(raw)
    if not isinstance(data, dict):
        raise RuntimeError("l'OpenAPI YAML non contiene un oggetto")
    return data


def _has_usable_server(spec: dict[str, Any]) -> bool:
    """`servers` presente e con almeno una URL assoluta.

    Un `servers: [{"url": "/api"}]` relativo non basta a vulnapi, che vuole
    una base URL completa.
    """
    servers = spec.get("servers")
    if not isinstance(servers, list):
        # OpenAPI 2.0 (Swagger) usa host + schemes.
        return bool(spec.get("host"))
    for server in servers:
        if isinstance(server, dict):
            url = str(server.get("url") or "")
            if url.lower().startswith(("http://", "https://")):
                return True
    return False


def download_binary(dest_dir: Path, version: str = "v0.9.0") -> Path:
    """Scarica il binario vulnapi per questa piattaforma.

    Usato da `bootstrap.py`. Sta qui e non nel bootstrap perche' la scelta
    dell'asset dipende dalla stessa conoscenza dell'engine.
    """
    import platform
    import urllib.request
    import zipfile
    import tarfile
    import tempfile

    system = platform.system()
    machine = platform.machine().lower()
    arch = {
        "amd64": "x86_64", "x86_64": "x86_64",
        "arm64": "arm64", "aarch64": "arm64",
        "i386": "i386", "x86": "i386",
    }.get(machine, "x86_64")

    if system == "Windows":
        asset = f"vulnapi_Windows_{arch}.zip"
    elif system == "Darwin":
        asset = "vulnapi_Darwin_all.tar.gz"
    elif system == "Linux":
        asset = f"vulnapi_Linux_{arch}.tar.gz"
    else:
        raise RuntimeError(f"piattaforma non supportata: {system}")

    url = (f"https://github.com/cerberauth/vulnapi/releases/download/"
           f"{version}/{asset}")
    dest_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as tmp:
        archive = Path(tmp) / asset
        urllib.request.urlretrieve(url, archive)
        if asset.endswith(".zip"):
            with zipfile.ZipFile(archive) as zf:
                zf.extractall(dest_dir)
        else:
            with tarfile.open(archive) as tf:
                tf.extractall(dest_dir)

    for name in _BINARY_NAMES:
        candidate = dest_dir / name
        if candidate.exists():
            if os.name != "nt":
                candidate.chmod(0o755)
            return candidate
    raise RuntimeError(f"binario non trovato nell'archivio {asset}")
