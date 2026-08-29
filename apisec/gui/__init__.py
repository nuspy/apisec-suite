"""Interfaccia grafica della suite.

L'import di `app` tira dentro `apiscan_gui` e quindi Tkinter: e' volutamente
pigro, cosi' che la CLI e l'uso come libreria funzionino su macchine senza
ambiente grafico.
"""
from __future__ import annotations

__all__ = ["ApiSecSuiteApp", "main"]


def __getattr__(name: str):
    if name in __all__:
        from . import app
        return getattr(app, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
