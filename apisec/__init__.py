"""apisec-suite — orchestrazione di piu' scanner di sicurezza per API.

Mette insieme tre strumenti che da soli lasciano scoperto qualcosa:

    VulnAPI (MIT)        header, cookie, JWT, auth bypass, fingerprinting.
                         Veloce e deterministico, ma context-free: non vede
                         BOLA, BFLA, business logic.
    APISCAN (AGPL-3.0)   l'intera OWASP API Top 10, BOLA e BFLA compresi.
                         Copertura ampia, nessuna suite di test a monte.
    42Crunch (freemium)  contract conformance, l'unico dei tre a validare le
                         risposte contro l'OpenAPI. Non eseguibile in locale:
                         la suite ne genera il workflow di CI.

Gli engine girano come processi separati e comunicano solo attraverso i loro
file di output. Questo tiene le licenze distinte - AGPL e MIT non si toccano -
e impedisce che il crash di uno porti giu' gli altri.

    from apisec import ScanConfig, run_scan

    cfg = ScanConfig(target_url="https://api.example.test",
                     openapi="openapi.json")
    outcome = run_scan(cfg, progress=print)
    print(outcome.artifacts["sarif"])
"""
from __future__ import annotations

from .config import AuthConfig, ConfigError, LLMSettings, ScanConfig
from .findings import Evidence, Finding, Severity, sort_findings
from .runner import ScanOutcome, ScanRunner, run_scan

__version__ = "1.0.0"

__all__ = [
    "AuthConfig", "ConfigError", "LLMSettings", "ScanConfig",
    "Evidence", "Finding", "Severity", "sort_findings",
    "ScanOutcome", "ScanRunner", "run_scan",
    "__version__",
]
