"""Generatore di workflow GitHub Actions.

42Crunch e' l'unico dei tre strumenti a fare *contract conformance* - validare
le risposte reali contro l'OpenAPI - ma non e' eseguibile in locale in modo
sensato: l'entrypoint si aspetta il contesto di un runner (`INPUT_*`,
`GITHUB_*`), la logica sta in un'immagine proprietaria, e ogni esecuzione
consuma la quota freemium.

    Limiti freemium, dalla documentazione ufficiale: 25 scansioni per
    repository al mese, massimo tre repository per organizzazione, solo i
    security quality gate predefiniti e solo il dizionario dati standard.

La soluzione adottata: la suite non lo esegue, ne **genera il workflow**. In CI
42Crunch gira dove ha senso che giri, produce SARIF, e il suo SARIF viene
unito a quello della suite in un unico caricamento verso Code Scanning.

Il YAML e' scritto a mano invece che con PyYAML: i workflow di GitHub vivono
di commenti esplicativi e di ordine delle chiavi, e un dump automatico li
perderebbe entrambi.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

#: Versioni pinnate. Un workflow generato oggi deve continuare a funzionare
#: fra sei mesi, e `@main` non lo garantisce.
ACTION_CHECKOUT = "actions/checkout@v4"
ACTION_SETUP_PYTHON = "actions/setup-python@v5"
ACTION_UPLOAD = "actions/upload-artifact@v4"
ACTION_CODEQL_UPLOAD = "github/codeql-action/upload-sarif@v3"
ACTION_42C_AUDIT = "42Crunch/api-security-audit-action-freemium@v1"
ACTION_42C_SCAN = "42Crunch/api-security-scan-action-freemium@v1"


@dataclass
class WorkflowOptions:
    """Cosa mettere nel workflow generato."""

    name: str = "API Security"
    #: File OpenAPI nel repository, relativo alla radice.
    api_definition: str = "openapi.json"
    #: URL dell'API da colpire. In CI conviene una variabile d'ambiente.
    target_url: str = "${{ vars.API_TARGET_URL }}"
    #: Secret GitHub da cui prendere il token per invocare l'API.
    credential_secret: str = "API_TOKEN"
    python_version: str = "3.12"
    branches: list[str] = field(default_factory=lambda: ["main"])
    #: Audit statico dell'OpenAPI: non tocca l'API, non richiede un bersaglio.
    include_42crunch_audit: bool = True
    #: Scansione dinamica: consuma la quota, quindi non su ogni push.
    include_42crunch_scan: bool = True
    #: Con quota limitata, ha senso solo su richiesta o schedulato.
    crunch_on_demand_only: bool = True
    include_suite: bool = True
    #: Severita' minima che fa fallire la pipeline.
    fail_on: str = "high"
    upload_to_code_scanning: bool = True
    #: Cron opzionale, per la scansione periodica.
    schedule_cron: str = "0 3 * * 1"


def generate_workflow(opts: WorkflowOptions) -> str:
    """Restituisce il contenuto YAML del workflow."""
    triggers = _triggers(opts)
    jobs: list[str] = []

    if opts.include_42crunch_audit:
        jobs.append(_job_audit(opts))
    if opts.include_42crunch_scan:
        jobs.append(_job_scan(opts))
    if opts.include_suite:
        jobs.append(_job_suite(opts))
    if opts.upload_to_code_scanning and len(jobs) > 1:
        jobs.append(_job_merge(opts))

    return f"""# Generato da apisec-suite.
#
# Tre strumenti, tre coperture diverse, un solo caricamento verso Code Scanning:
#
#   42c-audit   qualita' del contratto OpenAPI. Statico: non tocca l'API.
#   42c-scan    conformance dinamica. E' l'unico a validare le risposte contro
#               il contratto, ed e' il motivo per cui 42Crunch resta nel giro.
#   suite       VulnAPI + APISCAN: OWASP API Top 10, BOLA e BFLA compresi.
#
# QUOTA FREEMIUM 42Crunch: 25 scansioni per repository al mese, massimo tre
# repository per organizzazione. Per questo i job 42Crunch sono separati da
# quello della suite: si esauriscono da soli senza fermare il resto.
#
# Prima di usarlo, configurare:
#   - variabile di repository  API_TARGET_URL
#   - secret                   {opts.credential_secret}
#   - file OpenAPI             {opts.api_definition}

name: {opts.name}

{triggers}
permissions:
  contents: read

jobs:
{chr(10).join(jobs)}"""


# ---------------------------------------------------------------------- #

def _triggers(opts: WorkflowOptions) -> str:
    branches = ", ".join(opts.branches) or "main"
    lines = [
        "on:",
        "  # Esecuzione manuale: e' il modo giusto di spendere la quota 42Crunch.",
        "  workflow_dispatch:",
        "  pull_request:",
        f"    branches: [ {branches} ]",
        "  push:",
        f"    branches: [ {branches} ]",
    ]
    if opts.schedule_cron:
        lines += [
            "  schedule:",
            f"    # Scansione periodica: {opts.schedule_cron}",
            f"    - cron: '{opts.schedule_cron}'",
        ]
    return "\n".join(lines) + "\n"


def _crunch_condition(opts: WorkflowOptions) -> str:
    """Quando far girare i job 42Crunch.

    Con 25 esecuzioni al mese, farli partire a ogni push le brucia in una
    settimana di lavoro normale.
    """
    if not opts.crunch_on_demand_only:
        return ""
    return ("    if: github.event_name == 'workflow_dispatch' || "
            "github.event_name == 'schedule'\n")


def _job_audit(opts: WorkflowOptions) -> str:
    return f"""  42c-audit:
    name: 42Crunch — audit del contratto OpenAPI
    runs-on: ubuntu-latest
{_crunch_condition(opts)}    permissions:
      contents: read
      security-events: write
    steps:
      - uses: {ACTION_CHECKOUT}

      - name: Audit dell'OpenAPI
        uses: {ACTION_42C_AUDIT}
        continue-on-error: true   # la quota esaurita non deve rompere la pipeline
        with:
          api-definition: {opts.api_definition}
          upload-to-code-scanning: false
          log-level: info
          sarif-report: 42c-audit.sarif

      - uses: {ACTION_UPLOAD}
        if: always()
        with:
          name: sarif-42c-audit
          path: 42c-audit.sarif
          if-no-files-found: ignore
"""


def _job_scan(opts: WorkflowOptions) -> str:
    return f"""  42c-scan:
    name: 42Crunch — conformance dinamica
    runs-on: ubuntu-latest
{_crunch_condition(opts)}    permissions:
      contents: read
      security-events: write
    steps:
      - uses: {ACTION_CHECKOUT}

      - name: Scansione dinamica
        uses: {ACTION_42C_SCAN}
        continue-on-error: true
        with:
          api-definition: {opts.api_definition}
          target-url: {opts.target_url}
          api-credential: ${{{{ secrets.{opts.credential_secret} }}}}
          upload-to-code-scanning: false
          log-level: info
          sarif-report: 42c-scan.sarif
          scan-report: 42c-scan-raw.json

      - uses: {ACTION_UPLOAD}
        if: always()
        with:
          name: sarif-42c-scan
          path: |
            42c-scan.sarif
            42c-scan-raw.json
          if-no-files-found: ignore
"""


def _job_suite(opts: WorkflowOptions) -> str:
    return f"""  suite:
    name: apisec-suite — VulnAPI + APISCAN
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: {ACTION_CHECKOUT}

      - uses: {ACTION_SETUP_PYTHON}
        with:
          python-version: '{opts.python_version}'
          cache: pip

      - name: Installazione della suite e degli engine
        run: |
          python -m pip install --upgrade pip
          pip install -r requirements.txt
          # Scarica il binario vulnapi e clona APISCAN in vendor/.
          python bootstrap.py --all --quiet

      - name: Scansione
        env:
          API_TOKEN: ${{{{ secrets.{opts.credential_secret} }}}}
        run: |
          python apisec_cli.py \\
            --url '{opts.target_url}' \\
            --openapi '{opts.api_definition}' \\
            --engines vulnapi,apiscan \\
            --flow token --token "$API_TOKEN" \\
            --output apisec_out \\
            --fail-on {opts.fail_on} \\
            --sarif apisec.sarif

      - uses: {ACTION_UPLOAD}
        if: always()
        with:
          name: apisec-report
          path: |
            apisec.sarif
            apisec_out/**
          if-no-files-found: warn
"""


def _job_merge(opts: WorkflowOptions) -> str:
    needs = []
    if opts.include_42crunch_audit:
        needs.append("42c-audit")
    if opts.include_42crunch_scan:
        needs.append("42c-scan")
    if opts.include_suite:
        needs.append("suite")

    return f"""  code-scanning:
    name: Caricamento unificato verso Code Scanning
    runs-on: ubuntu-latest
    needs: [{', '.join(needs)}]
    # `always()` perche' un job saltato per quota esaurita non deve impedire
    # di pubblicare i risultati degli altri.
    if: always()
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: {ACTION_CHECKOUT}

      - uses: actions/download-artifact@v4
        with:
          path: sarif-in
          merge-multiple: true

      - name: Unione dei SARIF
        run: |
          python - <<'PY'
          import json, pathlib
          runs = []
          for path in sorted(pathlib.Path("sarif-in").rglob("*.sarif")):
              try:
                  runs.extend(json.loads(path.read_text(encoding="utf-8")).get("runs", []))
                  print(f"unito: {{path}}")
              except Exception as exc:
                  print(f"saltato {{path}}: {{exc}}")
          pathlib.Path("merged.sarif").write_text(json.dumps({{
              "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
              "version": "2.1.0",
              "runs": runs,
          }}), encoding="utf-8")
          print(f"{{len(runs)}} run totali")
          PY

      - uses: {ACTION_CODEQL_UPLOAD}
        with:
          sarif_file: merged.sarif
          category: apisec-suite
"""


def write_workflow(opts: WorkflowOptions, dest: Path) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(generate_workflow(opts), encoding="utf-8")
    return dest
