"""Fusione dei risultati ed export nei formati che gli altri strumenti leggono."""
from __future__ import annotations

from .html import render_html, write_html
from .merge import (
    MergeStats,
    coverage_matrix,
    gate_failed,
    merge_findings,
    risk_score,
)
from .sarif import build_sarif, merge_sarif_files, write_sarif

__all__ = [
    "render_html", "write_html",
    "MergeStats", "coverage_matrix", "gate_failed", "merge_findings", "risk_score",
    "build_sarif", "merge_sarif_files", "write_sarif",
]
