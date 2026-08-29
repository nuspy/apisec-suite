"""Shim OpenAI-compatibile per i CLI-agenti di llmswitch.

Claude Code, Codex e Antigravity non espongono un endpoint HTTP: si lanciano
come programmi e si legge quello che stampano. E' l'unico modo conforme di far
pagare le chiamate a un abbonamento, perche' il client ufficiale e' autorizzato
mentre un'applicazione terza con le stesse credenziali no.

Questo modulo alza un server locale che parla `/v1/chat/completions` e traduce
verso `llmswitch.agents.genera()`. Da fuori l'agente e' indistinguibile da
qualunque altro provider OpenAI-compatibile, e quindi diventa utilizzabile
**anche da APISCAN**, che sa parlare solo HTTP.

Cosa si deve sapere prima di usarlo:

* **Sono agenti, non modelli.** Ragionano e usano strumenti prima di
  rispondere: la latenza misurata da llmswitch va da ~4 s (Claude Code) a ~16 s
  (Codex) per una risposta di due lettere. Per l'analisi di poche decine di
  finding va benissimo; per centinaia di chiamate conviene un modello vero.
* **Niente streaming.** L'agente restituisce il testo quando ha finito. Le
  richieste con `stream: true` ricevono comunque una risposta completa, non un
  flusso di eventi.
* **Chiuso in locale.** Bind su 127.0.0.1 e un token di sessione casuale
  obbligatorio: senza, qualunque altro processo dell'utente potrebbe far
  consumare l'abbonamento.
"""
from __future__ import annotations

import json
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from ..config import LLMSettings

#: Un server per tipo di agente, riusato per tutta la vita del processo.
_shims: dict[str, "_Shim"] = {}
_lock = threading.Lock()


class ShimError(RuntimeError):
    pass


class _Shim:
    """Server attivo per un agente."""

    def __init__(self, agent: str, port: int, token: str,
                 server: ThreadingHTTPServer, thread: threading.Thread) -> None:
        self.agent = agent
        self.port = port
        self.token = token
        self.server = server
        self.thread = thread

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}/v1"

    def shutdown(self) -> None:
        try:
            self.server.shutdown()
            self.server.server_close()
        except Exception:
            pass


def ensure_shim(agent: str, settings: LLMSettings) -> tuple[str, str]:
    """Avvia (o riusa) lo shim per `agent`. Ritorna `(base_url, modello)`.

    Il token di sessione viene esposto come `api_key`: chi risolve l'endpoint
    lo passa nell'header Authorization come farebbe con qualunque provider.
    """
    with _lock:
        existing = _shims.get(agent)
        if existing is not None and existing.thread.is_alive():
            return existing.base_url, settings.model or agent

        agents_mod = _agents_module()
        if agent not in getattr(agents_mod, "AGENTI", {}):
            raise ShimError(f"agente sconosciuto in llmswitch: {agent}")
        if not _agent_installed(agents_mod, agent):
            raise ShimError(
                f"l'agente «{agent}» non risulta installato o non e' nel PATH"
            )

        token = secrets.token_urlsafe(24)
        handler = _make_handler(agent, token, settings, agents_mod)
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        server.daemon_threads = True
        port = server.server_address[1]

        thread = threading.Thread(
            target=server.serve_forever, name=f"apisec-shim-{agent}", daemon=True)
        thread.start()

        shim = _Shim(agent, port, token, server, thread)
        _shims[agent] = shim
        return shim.base_url, settings.model or agent


def shim_token(agent: str) -> str:
    """Token di sessione dello shim, o stringa vuota se non e' attivo."""
    shim = _shims.get(agent)
    return shim.token if shim else ""


def shutdown_all() -> None:
    """Ferma tutti gli shim. Da chiamare alla chiusura dell'applicazione."""
    with _lock:
        for shim in list(_shims.values()):
            shim.shutdown()
        _shims.clear()


# ---------------------------------------------------------------------- #

def _agents_module() -> Any:
    from .bridge import _import_llmswitch, LLMUnavailable, unavailable_reason
    mod = _import_llmswitch()
    if mod is None:
        raise ShimError(unavailable_reason())
    try:
        from llmswitch import agents  # type: ignore
        return agents
    except ImportError as exc:
        raise ShimError(f"llmswitch.agents non importabile: {exc}") from exc


def _agent_installed(agents_mod: Any, agent: str) -> bool:
    for fn_name in ("disponibile", "installato"):
        fn = getattr(agents_mod, fn_name, None)
        if callable(fn):
            try:
                return bool(fn(agent))
            except Exception:
                continue
    installed = getattr(agents_mod, "installati", None)
    if callable(installed):
        try:
            return agent in (installed() or [])
        except Exception:
            return True
    return True  # in dubbio si prova: sara' `genera` a dire di no


def _make_handler(agent: str, token: str, settings: LLMSettings,
                  agents_mod: Any) -> type[BaseHTTPRequestHandler]:

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "apisec-shim/1.0"

        # Il logging di default scrive su stderr a ogni richiesta e sporca
        # l'output della scansione.
        def log_message(self, fmt: str, *args: Any) -> None:
            return

        # -------------------------------------------------------------- #

        def _authorized(self) -> bool:
            header = self.headers.get("Authorization", "")
            if header.lower().startswith("bearer "):
                return secrets.compare_digest(header.split(" ", 1)[1].strip(), token)
            return secrets.compare_digest(self.headers.get("x-api-key", ""), token)

        def _send_json(self, status: int, payload: dict[str, Any]) -> None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _error(self, status: int, message: str, kind: str = "invalid_request_error") -> None:
            self._send_json(status, {"error": {"message": message, "type": kind}})

        # -------------------------------------------------------------- #

        def do_GET(self) -> None:  # noqa: N802 — imposto da BaseHTTPRequestHandler
            if self.path.rstrip("/") in ("/v1/models", "/models"):
                if not self._authorized():
                    return self._error(401, "token non valido", "authentication_error")
                spec = getattr(agents_mod, "AGENTI", {}).get(agent)
                models = list(getattr(spec, "elenco_modelli", ()) or ()) or [agent]
                return self._send_json(200, {
                    "object": "list",
                    "data": [{"id": m, "object": "model", "owned_by": "llmswitch"}
                             for m in models],
                })
            if self.path.rstrip("/") in ("/health", "/v1/health"):
                return self._send_json(200, {"status": "ok", "agent": agent})
            self._error(404, f"percorso non gestito: {self.path}")

        def do_POST(self) -> None:  # noqa: N802
            if self.path.rstrip("/") not in ("/v1/chat/completions", "/chat/completions"):
                return self._error(404, f"percorso non gestito: {self.path}")
            if not self._authorized():
                return self._error(401, "token non valido", "authentication_error")

            try:
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b"{}"
                payload = json.loads(raw.decode("utf-8"))
            except Exception as exc:
                return self._error(400, f"corpo non valido: {exc}")

            messages = payload.get("messages") or []
            if not isinstance(messages, list) or not messages:
                return self._error(400, "campo `messages` mancante o vuoto")

            prompt = _flatten_messages(messages)
            model = str(payload.get("model") or settings.model or "")
            # Un client OpenAI deve mandare *qualcosa* in `model`, e senza una
            # scelta esplicita quel qualcosa e' il nome dell'agente. Girarlo a
            # `genera` diventerebbe `claude --model claude_cli`, che l'agente
            # rifiuta: qui torna a essere "nessuna preferenza".
            if model == agent:
                model = ""

            started = time.time()
            try:
                text = agents_mod.genera(
                    agent, prompt, model=model,
                    timeout_s=float(payload.get("timeout") or settings.timeout_s),
                )
            except Exception as exc:
                # Un agente che fallisce e' un 502: il proxy c'e', il monte a
                # valle no. Distinguere aiuta chi legge i log.
                return self._error(502, f"agente «{agent}» fallito: {exc}",
                                   "upstream_error")

            return self._send_json(200, {
                "id": f"chatcmpl-shim-{secrets.token_hex(8)}",
                "object": "chat.completion",
                "created": int(started),
                "model": model or agent,
                "choices": [{
                    "index": 0,
                    "message": {"role": "assistant", "content": text},
                    "finish_reason": "stop",
                }],
                # I CLI-agenti non riportano il consumo: dichiararlo a zero e'
                # piu' onesto che inventare numeri.
                "usage": {"prompt_tokens": 0, "completion_tokens": 0,
                          "total_tokens": 0},
            })

    return Handler


def _flatten_messages(messages: list[Any]) -> str:
    """Appiattisce una conversazione in un prompt unico.

    Gli agenti CLI prendono un testo e basta: non hanno il concetto di ruoli
    ne' di cronologia. I ruoli restano come etichette, che e' quanto di piu'
    fedele si possa fare senza inventare una semantica che l'agente non ha.
    """
    parts: list[str] = []
    for message in messages:
        if not isinstance(message, dict):
            continue
        role = str(message.get("role") or "user").lower()
        content = message.get("content")

        if isinstance(content, list):
            # Formato a blocchi: si tiene solo il testo.
            chunks = [str(block.get("text") or "")
                      for block in content
                      if isinstance(block, dict) and block.get("type") in (None, "text")]
            text = "\n".join(c for c in chunks if c)
        else:
            text = str(content or "")

        if not text.strip():
            continue
        if role == "system":
            parts.append(f"[istruzioni]\n{text}")
        elif role == "assistant":
            parts.append(f"[risposta precedente]\n{text}")
        else:
            parts.append(text)
    return "\n\n".join(parts)
