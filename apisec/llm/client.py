"""Client LLM della suite.

Volutamente minimale: parla il dialetto OpenAI `chat/completions` e quello
Anthropic `messages`, che insieme coprono tutti i provider di llmswitch (i CLI
diventano OpenAI-compatibili passando dallo shim). Non usa gli SDK dei singoli
vendor perche' aggiungerebbero dipendenze per fare due POST.

`requests` e' gia' richiesto da APISCAN, quindi non introduce nulla di nuovo.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from ..config import LLMSettings
from .bridge import Endpoint, LLMUnavailable, resolve


class LLMError(RuntimeError):
    """La chiamata al modello e' fallita."""


@dataclass
class Reply:
    text: str
    model: str = ""
    #: Token consumati, quando il provider li dichiara.
    prompt_tokens: int = 0
    completion_tokens: int = 0


class LLMClient:
    """Chiamate sincrone a un endpoint risolto da llmswitch."""

    def __init__(self, settings: LLMSettings, endpoint: Endpoint | None = None) -> None:
        self.settings = settings
        self._endpoint = endpoint
        self._session: Any = None

    # ------------------------------------------------------------------ #

    @property
    def endpoint(self) -> Endpoint:
        if self._endpoint is None:
            self._endpoint = resolve(self.settings)
        return self._endpoint

    def _http(self) -> Any:
        if self._session is None:
            import requests
            session = requests.Session()
            session.headers.update({"User-Agent": "apisec-suite/1.0"})
            self._session = session
        return self._session

    def describe(self) -> str:
        try:
            return self.endpoint.describe()
        except LLMUnavailable as exc:
            return f"non disponibile: {exc}"

    def test(self) -> tuple[bool, str]:
        """Prova una chiamata reale. Ritorna `(ok, messaggio)`."""
        try:
            reply = self.chat("Rispondi con la sola parola: ok",
                              max_tokens=16, timeout_s=60)
        except Exception as exc:
            return False, str(exc)
        text = reply.text.strip()
        return bool(text), f"{self.endpoint.describe()} -> {text[:120] or '(vuoto)'}"

    # ------------------------------------------------------------------ #

    def chat(self, prompt: str, system: str = "", *,
             max_tokens: int | None = None, temperature: float | None = None,
             timeout_s: float | None = None) -> Reply:
        endpoint = self.endpoint
        if not endpoint.base_url:
            raise LLMError("endpoint senza base_url")

        temperature = (self.settings.temperature if temperature is None
                       else temperature)
        max_tokens = self.settings.max_tokens if max_tokens is None else max_tokens
        timeout = self.settings.timeout_s if timeout_s is None else timeout_s

        if endpoint.api == "anthropic":
            return self._chat_anthropic(prompt, system, max_tokens,
                                        temperature, timeout)
        return self._chat_openai(prompt, system, max_tokens, temperature, timeout)

    def _chat_openai(self, prompt: str, system: str, max_tokens: int,
                     temperature: float, timeout: float) -> Reply:
        endpoint = self.endpoint
        messages: list[dict[str, str]] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": endpoint.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stream": False,
        }
        headers = {"Content-Type": "application/json"}
        if endpoint.api_key:
            headers["Authorization"] = f"Bearer {endpoint.api_key}"

        url = f"{endpoint.base_url.rstrip('/')}/chat/completions"
        data = self._post(url, payload, headers, timeout)

        choices = data.get("choices") or []
        if not choices:
            raise LLMError(f"risposta senza `choices`: {str(data)[:300]}")
        text = str((choices[0].get("message") or {}).get("content") or "")
        usage = data.get("usage") or {}
        return Reply(
            text=text,
            model=str(data.get("model") or endpoint.model),
            prompt_tokens=int(usage.get("prompt_tokens") or 0),
            completion_tokens=int(usage.get("completion_tokens") or 0),
        )

    def _chat_anthropic(self, prompt: str, system: str, max_tokens: int,
                        temperature: float, timeout: float) -> Reply:
        endpoint = self.endpoint
        payload: dict[str, Any] = {
            "model": endpoint.model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": [{"role": "user", "content": prompt}],
        }
        if system:
            payload["system"] = system

        headers = {
            "Content-Type": "application/json",
            "x-api-key": endpoint.api_key,
            "anthropic-version": "2023-06-01",
        }
        base = endpoint.base_url.rstrip("/")
        # llmswitch puo' restituire la base con o senza /v1.
        url = f"{base}/messages" if base.endswith("/v1") else f"{base}/v1/messages"
        data = self._post(url, payload, headers, timeout)

        blocks = data.get("content") or []
        text = "".join(
            str(b.get("text") or "") for b in blocks
            if isinstance(b, dict) and b.get("type") in (None, "text")
        )
        usage = data.get("usage") or {}
        return Reply(
            text=text,
            model=str(data.get("model") or endpoint.model),
            prompt_tokens=int(usage.get("input_tokens") or 0),
            completion_tokens=int(usage.get("output_tokens") or 0),
        )

    def _post(self, url: str, payload: dict[str, Any],
              headers: dict[str, str], timeout: float) -> dict[str, Any]:
        import requests
        try:
            response = self._http().post(
                url, json=payload, headers=headers,
                timeout=(15, max(timeout, 30)),
            )
        except requests.RequestException as exc:
            raise LLMError(f"richiesta a {url} fallita: {exc}") from exc

        if response.status_code >= 400:
            raise LLMError(
                f"HTTP {response.status_code} da {url}: {response.text[:400]}")
        try:
            return response.json()
        except ValueError as exc:
            raise LLMError(f"risposta non JSON da {url}: "
                           f"{response.text[:300]}") from exc

    # ------------------------------------------------------------------ #

    def chat_json(self, prompt: str, system: str = "", **kwargs: Any) -> Any:
        """Come `chat`, ma pretende JSON e lo estrae anche se incapsulato.

        I modelli piccoli, e gli agenti CLI in particolare, tendono a
        incorniciare il JSON in un blocco markdown o a premetterci una frase.
        Fallire per questo sarebbe uno spreco: si estrae il primo oggetto o
        array bilanciato che si trova.
        """
        reply = self.chat(prompt, system, **kwargs)
        return extract_json(reply.text)


_FENCE = re.compile(r"```(?:json)?\s*(.+?)\s*```", re.S | re.I)


def extract_json(text: str) -> Any:
    """Primo valore JSON valido contenuto in `text`."""
    text = (text or "").strip()
    if not text:
        raise LLMError("risposta vuota")

    try:
        return json.loads(text)
    except ValueError:
        pass

    match = _FENCE.search(text)
    if match:
        try:
            return json.loads(match.group(1))
        except ValueError:
            text = match.group(1)

    for opener, closer in (("{", "}"), ("[", "]")):
        start = text.find(opener)
        if start < 0:
            continue
        depth = 0
        in_string = False
        escaped = False
        for index in range(start, len(text)):
            char = text[index]
            if in_string:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    in_string = False
                continue
            if char == '"':
                in_string = True
            elif char == opener:
                depth += 1
            elif char == closer:
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[start:index + 1])
                    except ValueError:
                        break
    raise LLMError(f"nessun JSON valido nella risposta: {text[:300]}")
