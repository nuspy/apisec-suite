"""Ponte verso llmswitch: un solo posto in cui si decide quale LLM parla.

llmswitch (https://github.com/nuspy/llmswitch, qui atteso in locale) tiene un
registry di provider - locali, a consumo, ad abbonamento OAuth, e CLI-agenti -
e sa risolvere `(base_url, api_key, modello)` per un dato *consumer*. La suite
si presenta come consumer e non conosce ne' chiavi ne' endpoint: li chiede.

Perche' passa da qui anche APISCAN, che un client LLM ce l'ha gia':

    APISCAN legge la propria configurazione LLM da variabili d'ambiente
    (`LLM_PROVIDER`, `LLM_API_BASE`, `LLM_MODEL`, `LLM_API_KEY`) e ha gia' un
    provider `openai_compat`. Valorizzando quelle variabili con un endpoint
    risolto da llmswitch, APISCAN parla con tutti i provider del registry
    - LM Studio, vLLM, llama.cpp, Grok, Qwen, Kimi, Nebius, gli abbonamenti
    OAuth - **senza che una riga del suo codice cambi**. L'integrazione e'
    additiva, non invasiva, e sopravvive agli aggiornamenti upstream.

I CLI-agenti (Claude Code, Codex, Antigravity) non hanno un endpoint HTTP: per
loro si alza uno shim OpenAI-compatibile in locale, e da fuori sono
indistinguibili da qualunque altro provider. Vedi `apisec.llm.shim`.
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..config import LLMSettings

#: Percorsi in cui cercare llmswitch se non e' installato come pacchetto.
#: Il primo e' quello dichiarato dall'utente; gli altri sono convenzioni.
_SEARCH_PATHS = (
    os.getenv("LLMSWITCH_HOME", ""),
    r"C:\Projects\llmswitch",
    str(Path.home() / "Projects" / "llmswitch"),
    str(Path.home() / "llmswitch"),
)

#: Uso a cui e' assegnato il provider dentro un registry. "chat" e' la
#: convenzione di llmswitch per la conversazione generica, ed e' quello che
#: serve qui: la suite chiacchiera con un modello, non vettorializza.
DEFAULT_CONSUMER = "chat"

#: Registry condiviso predefinito. Vedi `LLMSettings.registry_app` per il
#: motivo per cui NON e' il nome di questa applicazione.
DEFAULT_REGISTRY_APP = "llmswitch"


class LLMUnavailable(RuntimeError):
    """Nessun provider LLM utilizzabile. Non e' un errore fatale per la suite."""


@dataclass
class Endpoint:
    """Un provider LLM risolto, pronto per un client OpenAI-compatibile."""

    base_url: str
    api_key: str
    model: str
    #: openai | anthropic | gemini | cli — determina la forma delle richieste.
    api: str = "openai"
    provider_id: str = ""
    provider_label: str = ""
    #: True se il modello gira su questa macchina.
    local: bool = False
    #: Motivo della risoluzione, quando llmswitch lo fornisce (utile in GUI:
    #: "modello gia' in memoria" contro "caricato ora").
    reason: str = ""

    def describe(self) -> str:
        where = "locale" if self.local else "remoto"
        parts = [f"{self.provider_label or self.provider_id or self.api} ({where})"]
        if self.model:
            parts.append(self.model)
        if self.reason:
            parts.append(self.reason)
        return " · ".join(parts)


# ---------------------------------------------------------------------- #
# Accesso a llmswitch
# ---------------------------------------------------------------------- #

_import_error: str = ""


def _import_llmswitch() -> Any | None:
    """Importa llmswitch, cercandolo anche fuori da sys.path.

    Restituisce None invece di sollevare: la suite deve funzionare senza LLM,
    e un'analisi mancante non e' una scansione fallita.
    """
    global _import_error
    try:
        import llmswitch  # type: ignore
        return llmswitch
    except ImportError as exc:
        _import_error = str(exc)

    for candidate in _SEARCH_PATHS:
        if not candidate:
            continue
        path = Path(candidate)
        if not (path / "llmswitch" / "__init__.py").is_file():
            continue
        if str(path) not in sys.path:
            sys.path.insert(0, str(path))
        try:
            import llmswitch  # type: ignore
            return llmswitch
        except ImportError as exc:
            _import_error = f"{path}: {exc}"
    return None


def available() -> bool:
    return _import_llmswitch() is not None


def unavailable_reason() -> str:
    if available():
        return ""
    return (
        f"llmswitch non importabile ({_import_error or 'non trovato'}). "
        f"Impostare LLMSWITCH_HOME sulla cartella del progetto, oppure "
        f"`pip install -e <cartella-llmswitch>`."
    )


def _registry(app_name: str = DEFAULT_REGISTRY_APP) -> Any:
    mod = _import_llmswitch()
    if mod is None:
        raise LLMUnavailable(unavailable_reason())
    return mod.Registry(app_name=app_name)


def list_registries() -> list[tuple[str, int]]:
    """Registry llmswitch presenti sulla macchina: `(nome_app, n_provider)`.

    llmswitch tiene un file per applicazione, e chi ha gia' configurato dei
    provider per un altro progetto non deve rifare il lavoro qui. La GUI usa
    questa lista per farglieli riusare.
    """
    import json

    mod = _import_llmswitch()
    if mod is None:
        return []
    try:
        base = Path(mod.default_registry_path(DEFAULT_REGISTRY_APP)).parent.parent
    except Exception:
        return []

    found: list[tuple[str, int]] = []
    try:
        candidates = sorted(base.glob("*/llm_providers.json"))
    except OSError:
        return []

    for path in candidates:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            count = len(data.get("providers") or [])
        except (OSError, ValueError):
            continue
        found.append((path.parent.name, count))
    # Prima quelli popolati: sono gli unici immediatamente utilizzabili.
    found.sort(key=lambda item: (-item[1], item[0]))
    return found


def list_consumers(app_name: str = DEFAULT_REGISTRY_APP) -> list[str]:
    """Consumer gia' assegnati in un registry, per popolare la GUI."""
    mod = _import_llmswitch()
    if mod is None:
        return []
    try:
        data = mod.Registry(app_name=app_name).public()
    except Exception:
        return []
    assignments = data.get("assignments") if isinstance(data, dict) else None
    return sorted(assignments.keys()) if isinstance(assignments, dict) else []


# ---------------------------------------------------------------------- #
# Interrogazione, per la GUI
# ---------------------------------------------------------------------- #

@dataclass
class ProviderInfo:
    """Un provider del registry, come lo mostra la GUI."""

    pid: str
    label: str
    type: str
    local: bool
    api: str
    configured: bool
    model: str = ""
    note: str = ""


def list_providers(app_name: str = DEFAULT_REGISTRY_APP) -> list[ProviderInfo]:
    """Provider configurati nel registry indicato."""
    mod = _import_llmswitch()
    if mod is None:
        return []
    try:
        reg = mod.Registry(app_name=app_name)
        data = reg.public()
    except Exception:
        return []

    types = getattr(mod, "TYPES", {}) or {}
    out: list[ProviderInfo] = []
    for prov in _iter_providers(data):
        ptype = str(prov.get("type") or "")
        spec = types.get(ptype, {})
        # Il registry salva il nome scelto dall'utente in `name`; `label` e'
        # il nome del *tipo* e vale solo come ripiego.
        out.append(ProviderInfo(
            pid=str(prov.get("id") or ""),
            label=str(prov.get("name") or prov.get("label")
                      or spec.get("label") or ptype),
            type=ptype,
            local=bool(spec.get("local")),
            api=str(spec.get("api") or "openai"),
            configured=True,
            model=str(prov.get("model") or ""),
            note=str(spec.get("note") or ""),
        ))
    return out


def list_types(app_name: str = DEFAULT_REGISTRY_APP) -> list[ProviderInfo]:
    """Tutti i tipi supportati da llmswitch, configurati o meno.

    Serve alla GUI per mostrare cosa si *potrebbe* usare, non solo cosa e' gia'
    stato impostato.
    """
    mod = _import_llmswitch()
    if mod is None:
        return []
    types = getattr(mod, "TYPES", {}) or {}
    configured = {p.type for p in list_providers(app_name)}
    return [
        ProviderInfo(
            pid="", label=str(spec.get("label") or key), type=key,
            local=bool(spec.get("local")), api=str(spec.get("api") or "openai"),
            configured=key in configured, note=str(spec.get("note") or ""),
        )
        for key, spec in types.items()
    ]


def _iter_providers(data: Any) -> list[dict[str, Any]]:
    """`Registry.public()` cambia forma fra le versioni: qui si appiattisce."""
    if isinstance(data, dict):
        for key in ("providers", "provider", "items"):
            value = data.get(key)
            if isinstance(value, list):
                return [p for p in value if isinstance(p, dict)]
        if isinstance(data.get("id"), str):
            return [data]
        return [v for v in data.values() if isinstance(v, dict) and v.get("id")]
    if isinstance(data, list):
        return [p for p in data if isinstance(p, dict)]
    return []


# ---------------------------------------------------------------------- #
# Risoluzione
# ---------------------------------------------------------------------- #

def resolve(settings: LLMSettings) -> Endpoint:
    """Endpoint utilizzabile per le impostazioni date.

    Solleva `LLMUnavailable` se non c'e' nulla di utilizzabile: chi chiama
    decide se e' un problema (l'utente ha chiesto l'analisi) o no.
    """
    mod = _import_llmswitch()
    if mod is None:
        raise LLMUnavailable(unavailable_reason())

    consumer = settings.consumer or DEFAULT_CONSUMER
    reg = mod.Registry(app_name=settings.registry_app or DEFAULT_REGISTRY_APP)

    prov = _provider_record(reg, settings, consumer)
    ptype = str((prov or {}).get("type") or "")
    spec = (getattr(mod, "TYPES", {}) or {}).get(ptype, {})
    api = str(spec.get("api") or "openai")

    # I CLI-agenti non hanno endpoint: li si espone tramite lo shim locale.
    if api == "cli":
        from .shim import ensure_shim
        base_url, model = ensure_shim(ptype, settings)
        return Endpoint(
            base_url=base_url, api_key="local",
            model=settings.model or model or ptype,
            api="openai", provider_id=ptype,
            provider_label=str(spec.get("label") or ptype),
            local=True, reason="agente CLI esposto come endpoint locale",
        )

    if settings.provider_id and prov is not None:
        # Provider scelto esplicitamente: `endpoint_for` seguirebbe comunque
        # l'assegnazione del consumer, quindi si risolve dal record. Scrivere
        # un'assegnazione nel registry per ottenere lo stesso effetto
        # cambierebbe la configurazione dell'utente per un uso temporaneo.
        resolved = _resolve_from_record(reg, prov, spec, settings)
    else:
        try:
            resolved = reg.endpoint_for(consumer, carica=settings.may_load_model)
        except TypeError:
            # Versioni piu' vecchie non hanno il parametro `carica`.
            resolved = reg.endpoint_for(consumer)
        except Exception as exc:
            raise LLMUnavailable(f"risoluzione fallita: {exc}") from exc

    if not resolved:
        raise LLMUnavailable(
            f"nessun provider assegnato al consumer «{consumer}» nel registry "
            f"«{settings.registry_app}». Assegnarne uno con llmswitch, "
            f"scegliere un altro registry, oppure indicare provider_id."
        )

    base_url, api_key, model = resolved
    if settings.model:
        model = settings.model

    return Endpoint(
        base_url=str(base_url or "").rstrip("/"),
        api_key=str(api_key or "local"),
        model=str(model or ""),
        api=api,
        provider_id=str((prov or {}).get("id") or ptype),
        provider_label=str(spec.get("label") or ptype),
        local=bool(spec.get("local")),
        reason=_resolution_reason(reg, prov, settings),
    )


def _resolve_from_record(reg: Any, prov: dict[str, Any], spec: dict[str, Any],
                         settings: LLMSettings) -> tuple[str, str, str] | None:
    """`(base_url, api_key, modello)` da un record di provider specifico.

    Sui provider locali la scelta del modello resta di llmswitch, che sa cosa
    c'e' in VRAM: qui non si aggira la sua regola, la si invoca direttamente.
    """
    api_key = str(prov.get("api_key") or "local").strip() or "local"
    base_url = (str(prov.get("base_url") or "").strip()
                or str(spec.get("base_url") or "").strip())
    model = str(prov.get("model") or "").strip()

    if spec.get("local") and spec.get("api") != "cli":
        try:
            engines = reg._engines_for(prov)  # noqa: SLF001 — nessuna API pubblica
            preferred = "vllm" if prov.get("type") == "vllm" else "lmstudio"
            if settings.may_load_model:
                result = engines.resolve(preferred)
            else:
                result = engines.warm(preferred)
            if result is not None and getattr(result, "model", ""):
                return (str(result.base_url), api_key, str(result.model))
        except Exception:
            # Se la regola VRAM non e' applicabile si ricade sui valori
            # dichiarati: sara' il server a rifiutare, con un messaggio suo.
            pass

    if not base_url:
        return None
    return (base_url, api_key, model)


def _provider_record(reg: Any, settings: LLMSettings,
                     consumer: str) -> dict[str, Any] | None:
    """Il provider da usare: quello indicato, o quello assegnato al consumer."""
    if settings.provider_id:
        try:
            for prov in _iter_providers(reg.public()):
                if str(prov.get("id")) == settings.provider_id:
                    return prov
        except Exception:
            pass
    try:
        return reg.provider_for(consumer)
    except Exception:
        return None


def _resolution_reason(reg: Any, prov: dict[str, Any] | None,
                       settings: LLMSettings) -> str:
    """Motivo leggibile della scelta, quando il provider e' locale.

    llmswitch lo espone attraverso `LocalEngines.resolve()`; qui si tenta di
    recuperarlo senza far fallire nulla se l'API cambia.
    """
    if not prov:
        return ""
    try:
        engines = reg._engines_for(prov)  # noqa: SLF001 — API interna, best effort
        preferred = "vllm" if prov.get("type") == "vllm" else "lmstudio"
        result = (engines.resolve(preferred) if settings.may_load_model
                  else engines.warm(preferred))
        return str(getattr(result, "reason", "") or "")
    except Exception:
        return ""


# ---------------------------------------------------------------------- #
# Iniezione verso APISCAN
# ---------------------------------------------------------------------- #

#: Chiavi che APISCAN cerca per la chiave API, in ordine di precedenza.
#: Vengono valorizzate tutte quelle rilevanti perche' `_collect_api_key`
#: scorre la lista e si ferma alla prima non vuota.
_APISCAN_KEY_VARS = ("LLM_API_KEY", "OPENAI_API_KEY")


def apiscan_env_for(settings: LLMSettings) -> dict[str, str]:
    """Variabili d'ambiente che fanno usare ad APISCAN il provider scelto.

    Ritorna un dizionario vuoto se non c'e' nulla di utilizzabile: APISCAN
    ricadra' sulla propria configurazione, e la scansione prosegue comunque.
    """
    try:
        endpoint = resolve(settings)
    except LLMUnavailable:
        return {}

    if not endpoint.base_url and endpoint.api != "anthropic":
        return {}

    env: dict[str, str] = {
        "LLM_MODEL": endpoint.model,
        "LLM_TEMPERATURE": str(settings.temperature),
        "LLM_MAX_TOKENS": str(settings.max_tokens),
        "LLM_READ_TIMEOUT": str(int(settings.timeout_s)),
    }

    if endpoint.api == "anthropic":
        # APISCAN ha un ramo nativo per Anthropic: usa `x-api-key`,
        # `anthropic-version` e l'endpoint /v1/messages.
        env["LLM_PROVIDER"] = "anthropic"
        env["LLM_API_BASE"] = endpoint.base_url or "https://api.anthropic.com"
        env["ANTHROPIC_API_KEY"] = endpoint.api_key
    else:
        # Tutto il resto passa dal ramo OpenAI-compatibile, che APISCAN usa
        # con `{LLM_API_BASE}/chat/completions` e Authorization: Bearer.
        env["LLM_PROVIDER"] = "openai_compat"
        env["LLM_API_BASE"] = endpoint.base_url

    for var in _APISCAN_KEY_VARS:
        env.setdefault(var, endpoint.api_key or "local")

    return env


def describe_current(settings: LLMSettings) -> str:
    """Riga di stato per la GUI. Non solleva mai."""
    if not settings.enabled:
        return "LLM disattivato"
    try:
        return resolve(settings).describe()
    except LLMUnavailable as exc:
        return f"non disponibile: {exc}"
    except Exception as exc:  # difensivo: la GUI non deve morire per questo
        return f"errore: {exc}"
