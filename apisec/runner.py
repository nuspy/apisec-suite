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
        run_dir = self.cfg.run_dir()
        say(f"[*] Cartella della run: {run_dir}")

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
            engine_results=outcome.results, limitations=limitations,
        )
        artifacts["html"] = html_path

        for name, path in artifacts.items():
            say(f"[+] {name}: {path}")
        return artifacts


def run_scan(cfg: ScanConfig, progress: Progress | None = None,
             line_sink: LineSink | None = None) -> ScanOutcome:
    """Scorciatoia per chi non ha bisogno di poter annullare."""
    return ScanRunner(cfg).run(progress=progress, line_sink=line_sink)
