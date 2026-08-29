"""Orchestratore: esegue gli engine, fonde i risultati, scrive i report.

E' il cuore della suite, ed e' condiviso: la GUI e la CLI headless chiamano lo
stesso `run_scan`, cosi' che una scansione lanciata a mano e una lanciata in
pipeline producano esattamente gli stessi artefatti.

Gli engine girano **in sequenza, non in parallelo**. Non e' una svista: due
scanner che martellano insieme la stessa API falsano le misure di rate limiting
(API4), si sporcano a vicenda i test di stato, e su un bersaglio fragile ne
raddoppiano le probabilita' di crash. La lentezza qui e' una scelta.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Sequence

from .config import ScanConfig
from .engines import build_engines
from .engines.base import EngineResult, LineSink
from .findings import Finding, count_by_severity
from .report.html import write_html
from .report.merge import MergeStats, merge_findings, risk_score
from .report.sarif import write_sarif

#: Callback di avanzamento: riceve una riga gia' formattata.
Progress = Callable[[str], None]


@dataclass
class ScanOutcome:
    """Esito completo di una scansione multi-engine."""

    cfg: ScanConfig
    findings: list[Finding] = field(default_factory=list)
    results: list[EngineResult] = field(default_factory=list)
    stats: MergeStats | None = None
    analysis: object | None = None
    #: Esito della ricerca del documento OpenAPI, quando e' stata eseguita.
    discovery: object | None = None
    artifacts: dict[str, Path] = field(default_factory=dict)
    duration_s: float = 0.0

    @property
    def counts(self) -> dict[str, int]:
        return count_by_severity(self.findings)

    @property
    def score(self) -> float:
        return risk_score(self.findings)

    @property
    def failed_engines(self) -> list[str]:
        return [r.engine for r in self.results if r.error and not r.skipped]

    def summary_lines(self) -> list[str]:
        counts = self.counts
        lines = [
            f"Finding: {len(self.findings)} "
            f"(critici {counts['critical']}, alti {counts['high']}, "
            f"medi {counts['medium']}, bassi {counts['low']}, "
            f"info {counts['info']})",
            f"Punteggio di rischio: {self.score:g}/100",
        ]
        if self.stats is not None:
            lines.append(self.stats.summary())
        for result in self.results:
            state = ("saltato" if result.skipped
                     else f"errore: {result.error}" if result.error
                     else f"{len(result.findings)} finding")
            lines.append(f"  {result.engine}: {state} ({result.duration_s:.1f}s)")
        return lines


class ScanRunner:
    """Esegue una scansione. Riutilizzabile, ma non concorrente su se' stesso."""

    def __init__(self, cfg: ScanConfig) -> None:
        self.cfg = cfg
        self.engines = build_engines(cfg.engines)
        self._cancelled = False

    def cancel(self) -> None:
        """Interrompe la scansione. L'engine in corso viene terminato."""
        self._cancelled = True
        for engine in self.engines:
            engine.cancel()

    # ------------------------------------------------------------------ #

    def run(self, progress: Progress | None = None,
            line_sink: LineSink | None = None) -> ScanOutcome:
        started = time.monotonic()
        outcome = ScanOutcome(cfg=self.cfg)

        def say(message: str) -> None:
            if progress is not None:
                progress(message)

        self.cfg.require_valid()
        for note in self.cfg.warnings():
            say(f"[!] {note}")

        run_dir = self.cfg.run_dir()
        say(f"[*] Cartella della run: {run_dir}")

        if self.cfg.auto_discover and not self.cfg.openapi:
            outcome.discovery = self._discover(say)

        sink: LineSink = line_sink or (lambda engine, line: say(f"[{engine}] {line}"))

        for engine in self.engines:
            if self._cancelled:
                say("[!] Scansione interrotta: engine successivi non eseguiti")
                break
            say(f"[*] === {engine.label} ({engine.license}) ===")
            result = engine.run(self.cfg, sink=sink)
            outcome.results.append(result)

        # --- fusione ---
        groups = [r.findings for r in outcome.results]
        merged, stats = merge_findings(groups)
        outcome.findings = merged
        outcome.stats = stats
        say(f"[+] {stats.summary()}")

        # --- analisi LLM ---
        if self.cfg.llm.enabled and self.cfg.llm.analyze_findings and merged:
            outcome.analysis = self._analyze(merged, say)

        # --- artefatti ---
        outcome.artifacts = self._write_reports(outcome, say)
        outcome.duration_s = time.monotonic() - started
        say(f"[+] Completato in {outcome.duration_s:.1f}s")
        return outcome

    # ------------------------------------------------------------------ #

    def _discover(self, say: Progress) -> object | None:
        """Cerca il documento OpenAPI sul bersaglio e configura gli engine.

        Tre esiti, tutti gestiti: documento trovato e usato; niente trovato ma
        crawl disponibile, quindi APISCAN se lo costruisce; niente trovato e
        niente crawl, e allora VulnAPI passa alla modalita' curl invece di
        fallire, perche' su una sola URL qualcosa trova comunque.
        """
        from .discovery import discover, save_spec, synthesize_spec

        say("[*] === Ricerca del documento OpenAPI ===")
        try:
            result = discover(
                self.cfg.target_url,
                headers=self.cfg.auth.as_headers(),
                timeout=self.cfg.timeout if self.cfg.timeout > 0 else 8.0,
                workers=max(4, min(self.cfg.threads, 16)),
                insecure=self.cfg.insecure,
                proxy=self.cfg.proxy,
                extra_paths=self.cfg.discover_extra_paths,
                analyze_js=self.cfg.discover_analyze_js,
                read_robots=self.cfg.discover_read_robots,
                osint=self.cfg.discover_osint,
                progress=say,
            )
        except Exception as exc:
            say(f"[!] Ricerca fallita: {exc}")
            return None

        for line in result.summary_lines():
            say(f"    {line}")

        best = result.best
        if best is not None:
            path = save_spec(result, self.cfg.engine_dir("discovery"))
            if path is not None:
                self.cfg.openapi = str(path)
                say(f"[+] Uso il documento trovato: {best.url}")
                say(f"    salvato in {path}")
            return result

        # Nessun documento vero, ma forse una superficie ricostruita: la si
        # trasforma in un OpenAPI sintetico. E' meno di un contratto ma piu' di
        # un crawl alla cieca, perche' include i path visti solo nel JavaScript
        # o negli archivi, che il crawler non raggiungerebbe.
        if self.cfg.synthesize_fallback:
            synth = synthesize_spec(result, self.cfg.target_url,
                                    self.cfg.engine_dir("discovery"))
            if synth is not None:
                self.cfg.openapi = str(synth)
                count = len(result.endpoint_map.endpoints)
                say(f"[+] Nessun documento ufficiale, ma ho ricostruito "
                    f"{count} endpoint: uso un OpenAPI sintetizzato.")
                say(f"    salvato in {synth}")
                say("[!] E' una mappa, non un contratto: mancano tipi e schemi, "
                    "e la copertura dipende da cosa e' stato ricostruito.")
                return result

        # Niente documento e niente endpoint: si ripiega sul crawl.
        if self.cfg.crawl_fallback and "apiscan" in self.cfg.engines:
            self.cfg.crawl = True
            say("[!] Nessun documento trovato: APISCAN ne costruira' uno "
                "crawlando gli endpoint (piu' lento e meno accurato).")
            if "vulnapi" in self.cfg.engines and self.cfg.vulnapi_mode == "openapi":
                # VulnAPI non sa crawlare e senza contratto non parte: in
                # modalita' curl esamina almeno la URL di base.
                self.cfg.vulnapi_mode = "curl"
                say("[!] VulnAPI passa alla modalita' curl: senza contratto "
                    "esaminera' solo la URL di base.")
        elif "vulnapi" in self.cfg.engines and self.cfg.vulnapi_mode == "openapi":
            self.cfg.vulnapi_mode = "curl"
            say("[!] Nessun documento trovato: VulnAPI passa alla modalita' curl.")

        return result

    def _analyze(self, findings: Sequence[Finding], say: Progress) -> object | None:
        try:
            from .llm.analyst import Analyst
        except ImportError as exc:
            say(f"[!] Analisi LLM non disponibile: {exc}")
            return None
        try:
            return Analyst(self.cfg.llm).run(findings, progress=say)
        except Exception as exc:
            # L'analisi e' un di piu': non deve poter far fallire la scansione.
            say(f"[!] Analisi LLM fallita: {exc}")
            return None

    def _write_reports(self, outcome: ScanOutcome,
                       say: Progress) -> dict[str, Path]:
        run_dir = self.cfg.run_dir()
        artifacts: dict[str, Path] = {}

        json_path = run_dir / "findings.json"
        json_path.write_text(json.dumps({
            "config": self.cfg.to_dict(),
            "stats": {
                "total_input": outcome.stats.total_input if outcome.stats else 0,
                "total_output": outcome.stats.total_output if outcome.stats else 0,
                "corroborated": outcome.stats.corroborated if outcome.stats else 0,
                "per_engine": outcome.stats.per_engine if outcome.stats else {},
            },
            "score": outcome.score,
            "counts": outcome.counts,
            "engines": [
                {"engine": r.engine, "skipped": r.skipped, "error": r.error,
                 "returncode": r.returncode, "duration_s": round(r.duration_s, 2),
                 "findings": len(r.findings)}
                for r in outcome.results
            ],
            "analysis": (outcome.analysis.to_dict()
                         if hasattr(outcome.analysis, "to_dict") else None),
            "discovery": _discovery_dict(outcome.discovery),
            "findings": [f.to_dict() for f in outcome.findings],
        }, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
        artifacts["json"] = json_path

        sarif_path = write_sarif(
            outcome.findings, run_dir / "apisec.sarif",
            openapi_path=self.cfg.openapi,
        )
        artifacts["sarif"] = sarif_path

        limitations = {e.label: e.limitations() for e in self.engines}
        html_path = write_html(
            outcome.findings, run_dir / "report.html",
            cfg=self.cfg, stats=outcome.stats, analysis=outcome.analysis,
            discovery=outcome.discovery,
            engine_results=outcome.results, limitations=limitations,
        )
        artifacts["html"] = html_path

        for name, path in artifacts.items():
            say(f"[+] {name}: {path}")
        return artifacts


def _discovery_dict(discovery: object | None) -> dict | None:
    """Serializza l'esito della ricerca, senza il corpo dei documenti.

    Il contenuto degli spec non entra nel JSON dei finding: e' gia' salvato su
    disco, e duplicarlo qui renderebbe il file pesante e illeggibile.
    """
    if discovery is None:
        return None
    emap = getattr(discovery, "endpoint_map", None)
    surface = None
    if emap is not None and getattr(emap, "endpoints", None):
        surface = {
            "count": len(emap.endpoints),
            "per_source": dict(getattr(emap, "per_source", {}) or {}),
            "js_files_read": getattr(emap, "js_files_read", 0),
            "endpoints": [
                {"path": ep.path, "methods": sorted(ep.methods),
                 "sources": sorted(ep.sources), "templated": ep.templated}
                for ep in emap.endpoints.values()
            ],
        }

    return {
        "base_url": getattr(discovery, "base_url", ""),
        "server": getattr(discovery, "server", ""),
        "powered_by": getattr(discovery, "powered_by", ""),
        "requests_made": getattr(discovery, "requests_made", 0),
        "graphql": list(getattr(discovery, "graphql", []) or []),
        "well_known": list(getattr(discovery, "well_known", []) or []),
        "saved_to": str(getattr(discovery, "saved_to", "") or ""),
        "synthesized_to": str(getattr(discovery, "synthesized_to", "") or ""),
        "surface": surface,
        "errors": list(getattr(discovery, "errors", []) or []),
        "specs": [
            {
                "url": s.url, "confidence": s.confidence, "kind": s.kind,
                "version": s.version, "title": s.title, "paths": s.paths,
                "operations": s.operations, "source": s.source, "size": s.size,
            }
            for s in (getattr(discovery, "specs", []) or [])
        ],
    }


def run_scan(cfg: ScanConfig, progress: Progress | None = None,
             line_sink: LineSink | None = None) -> ScanOutcome:
    """Scorciatoia per chi non ha bisogno di poter annullare."""
    return ScanRunner(cfg).run(progress=progress, line_sink=line_sink)
