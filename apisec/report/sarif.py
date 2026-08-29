"""Export SARIF 2.1.0.

SARIF e' il formato che GitHub Code Scanning, Azure DevOps, DefectDojo e il
visualizzatore SARIF di VS Code sanno gia' leggere. Produrlo e' cio' che rende
la suite utilizzabile in pipeline invece che solo a schermo - ed e' anche il
formato che 42Crunch emette, il che permette di fondere il suo output con il
nostro nello stesso file di risultati.

Nota sulle posizioni: un finding DAST non ha una riga di codice sorgente. Si
usa quindi il file OpenAPI come artefatto e, quando lo si riesce a localizzare,
la riga in cui il path compare. Se non lo si trova, si punta al file senza
riga: meglio una posizione approssimata che nessun risultato visibile.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Sequence

from ..findings import Finding, Severity

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = ("https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
                "Schemata/sarif-schema-2.1.0.json")

#: SARIF ammette solo questi quattro livelli.
_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def build_sarif(findings: Sequence[Finding], *, tool_name: str = "apisec-suite",
                tool_version: str = "1.0.0",
                openapi_path: str = "",
                information_uri: str = "https://github.com/nuspy/apisec-suite",
                ) -> dict[str, Any]:
    """Costruisce il documento SARIF completo."""
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    locator = _OpenAPILocator(openapi_path)

    for finding in findings:
        rule_id = finding.rule_id or f"{finding.engine}.unknown"
        if rule_id not in rules:
            rules[rule_id] = _rule(finding, rule_id)
        results.append(_result(finding, rule_id, locator))

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name": tool_name,
                    "version": tool_version,
                    "informationUri": information_uri,
                    "rules": list(rules.values()),
                }
            },
            "results": results,
            "columnKind": "utf16CodeUnits",
        }],
    }


def _rule(finding: Finding, rule_id: str) -> dict[str, Any]:
    tags = ["security", "api", f"engine/{finding.engine}"]
    tags += [f"OWASP/{o}" for o in finding.owasp]
    tags += [c for c in finding.cwe if c]

    description = finding.description or finding.title
    rule: dict[str, Any] = {
        "id": rule_id,
        "name": _rule_name(rule_id),
        "shortDescription": {"text": _one_line(finding.title)},
        "fullDescription": {"text": _one_line(description)},
        "defaultConfiguration": {"level": _LEVEL[finding.severity]},
        "properties": {
            "tags": tags,
            "problem.severity": finding.severity.value,
            "security-severity": f"{finding.cvss:.1f}",
            "engine": finding.engine,
        },
    }
    if finding.remediation:
        rule["help"] = {"text": finding.remediation,
                        "markdown": f"**Rimedio**\n\n{finding.remediation}"}
    return rule


def _result(finding: Finding, rule_id: str,
            locator: "_OpenAPILocator") -> dict[str, Any]:
    message = finding.title
    if finding.method or finding.normalized_path:
        message += f" — {finding.method} {finding.normalized_path}".rstrip()
    if len(finding.corroborated_by) > 1:
        message += f" [confermato da: {', '.join(finding.corroborated_by)}]"
    if finding.llm_verdict:
        message += f" [verdetto LLM: {finding.llm_verdict}]"

    result: dict[str, Any] = {
        "ruleId": rule_id,
        "level": _LEVEL[finding.severity],
        "message": {"text": message},
        "locations": [locator.location(finding)],
        "partialFingerprints": {"apisecSuite/v1": finding.fingerprint()},
        "properties": {
            "engine": finding.engine,
            "severity": finding.severity.value,
            "cvss": finding.cvss,
            "cvssEstimated": finding.cvss_estimated,
            "owasp": finding.owasp,
            "cwe": finding.cwe,
            "corroboratedBy": finding.corroborated_by,
        },
    }

    if finding.llm_verdict:
        result["properties"]["llmVerdict"] = finding.llm_verdict
        result["properties"]["llmRationale"] = finding.llm_rationale

    evidence = finding.evidence.summary()
    if evidence:
        # `attachments` non e' supportato da tutti i consumatori, mentre una
        # proprieta' testuale sopravvive ovunque.
        result["properties"]["evidence"] = evidence[:4000]

    return result


class _OpenAPILocator:
    """Trova la riga in cui un path compare dentro il file OpenAPI."""

    def __init__(self, openapi_path: str) -> None:
        self.path = openapi_path
        self.uri = _artifact_uri(openapi_path) if openapi_path else "openapi.json"
        self._lines: list[str] = []
        if openapi_path and not openapi_path.lower().startswith(("http://", "https://")):
            try:
                self._lines = Path(openapi_path).read_text(
                    encoding="utf-8", errors="replace").splitlines()
            except OSError:
                self._lines = []

    def location(self, finding: Finding) -> dict[str, Any]:
        region = self._region(finding.path)
        physical: dict[str, Any] = {"artifactLocation": {"uri": self.uri}}
        if region:
            physical["region"] = region
        location: dict[str, Any] = {"physicalLocation": physical}
        if finding.url:
            location["properties"] = {"targetUrl": finding.url}
        if finding.method and finding.path:
            location["logicalLocations"] = [{
                "name": f"{finding.method} {finding.path}",
                "kind": "member",
            }]
        return location

    def _region(self, path: str) -> dict[str, Any] | None:
        if not self._lines or not path:
            return None
        # Si cerca il path come chiave JSON/YAML: `"/users/{id}":` oppure
        # `/users/{id}:`. Il primo riscontro basta.
        needle = re.escape(path.split("?")[0])
        pattern = re.compile(rf'["\']?{needle}["\']?\s*:')
        for index, line in enumerate(self._lines, start=1):
            if pattern.search(line):
                return {"startLine": index}
        return None


def _artifact_uri(path: str) -> str:
    """URI relativo, che e' quello che GitHub sa risolvere nel repository."""
    try:
        return Path(path).resolve().relative_to(Path.cwd().resolve()).as_posix()
    except (ValueError, OSError):
        return Path(path).name


_RE_NON_ID = re.compile(r"[^A-Za-z0-9]+")


def _rule_name(rule_id: str) -> str:
    """Nome in PascalCase, come si aspettano i visualizzatori SARIF."""
    return "".join(part.capitalize() for part in _RE_NON_ID.split(rule_id) if part)


def _one_line(text: str) -> str:
    return " ".join((text or "").split())[:1000] or "n/d"


def write_sarif(findings: Sequence[Finding], dest: Path, **kwargs: Any) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(
        json.dumps(build_sarif(findings, **kwargs), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return dest


def merge_sarif_files(paths: Sequence[Path], dest: Path) -> Path:
    """Fonde piu' documenti SARIF in uno solo, concatenando i `runs`.

    Serve per unire il SARIF di 42Crunch prodotto in CI con quello della suite:
    piu' `runs` nello stesso file sono validi, e GitHub li mostra insieme
    mantenendo distinta la provenienza.
    """
    runs: list[Any] = []
    for path in paths:
        if not path.exists():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        runs.extend(data.get("runs") or [])

    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps({
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": runs,
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    return dest
