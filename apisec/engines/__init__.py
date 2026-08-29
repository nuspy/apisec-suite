"""Registro degli engine disponibili."""
from __future__ import annotations

from typing import Sequence

from .apiscan_engine import ApiscanEngine
from .base import Availability, Engine, EngineResult, LineSink
from .vulnapi_engine import VulnapiEngine

#: Ordine di esecuzione predefinito. vulnapi per primo perche' e' veloce sul
#: singolo endpoint e il suo fingerprinting fotografa il bersaglio prima che
#: APISCAN inizi a modificarne lo stato con i test di scrittura.
ENGINE_ORDER = ("vulnapi", "apiscan")

_REGISTRY: dict[str, type[Engine]] = {
    "vulnapi": VulnapiEngine,
    "apiscan": ApiscanEngine,
}


def available_engines() -> list[str]:
    return list(ENGINE_ORDER)


def build_engines(names: Sequence[str]) -> list[Engine]:
    """Istanzia gli engine richiesti, nell'ordine canonico.

    I nomi sconosciuti vengono ignorati invece di sollevare: una
    configurazione salvata da una versione futura non deve impedire di
    lanciare quelli che si conoscono.
    """
    wanted = {n.strip().lower() for n in names if n and n.strip()}
    return [_REGISTRY[name]() for name in ENGINE_ORDER if name in wanted]


def engine_status() -> dict[str, Availability]:
    """Disponibilita' di ogni engine su questa macchina, per la GUI."""
    return {name: cls().check() for name, cls in _REGISTRY.items()}


__all__ = [
    "Availability", "Engine", "EngineResult", "LineSink",
    "ApiscanEngine", "VulnapiEngine",
    "ENGINE_ORDER", "available_engines", "build_engines", "engine_status",
]
