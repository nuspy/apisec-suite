"""Generazione di configurazioni CI/CD."""
from __future__ import annotations

from .workflow import WorkflowOptions, generate_workflow, write_workflow

__all__ = ["WorkflowOptions", "generate_workflow", "write_workflow"]
