"""Layer LLM della suite, costruito sopra llmswitch.

Un solo punto di configurazione per tutti i consumatori:

    la suite          usa `LLMClient` e `Analyst` sui finding gia' uniti
    APISCAN           riceve `LLM_PROVIDER`/`LLM_API_BASE`/`LLM_MODEL` iniettate
                      nell'ambiente del suo processo, e usa il proprio client
    i CLI-agenti      passano dallo shim OpenAI-compatibile di `apisec.llm.shim`

Il risultato e' che i 23 tipi di provider di llmswitch - LM Studio, vLLM,
llama.cpp, OpenAI, Claude, Gemini, Grok, Qwen, DeepSeek, Kimi, Z.AI,
NVIDIA NIM, Nebius, Unsloth, i quattro abbonamenti OAuth e i tre CLI-agenti -
sono disponibili a tutti gli engine, non solo a quello che aveva gia' un
client LLM suo.
"""
from __future__ import annotations

from .analyst import Analyst, AnalysisReport
from .bridge import (
    DEFAULT_CONSUMER,
    DEFAULT_REGISTRY_APP,
    Endpoint,
    LLMUnavailable,
    ProviderInfo,
    apiscan_env_for,
    available,
    describe_current,
    list_consumers,
    list_providers,
    list_registries,
    list_types,
    resolve,
    unavailable_reason,
)
from .client import LLMClient, LLMError, Reply
from .shim import ShimError, ensure_shim, shutdown_all

__all__ = [
    "Analyst", "AnalysisReport",
    "DEFAULT_CONSUMER", "DEFAULT_REGISTRY_APP", "Endpoint", "LLMUnavailable",
    "ProviderInfo", "apiscan_env_for", "available", "describe_current",
    "list_consumers", "list_providers", "list_registries", "list_types",
    "resolve", "unavailable_reason",
    "LLMClient", "LLMError", "Reply",
    "ShimError", "ensure_shim", "shutdown_all",
]
