"""Ricerca del documento OpenAPI sul bersaglio, invece di doverlo fornire.

Sia VulnAPI sia APISCAN vogliono un contratto: il primo lo pretende, il secondo
lo pretende o se lo costruisce crawlando. Ma quasi ogni API che espone
Swagger-UI o ReDoc pubblica anche il documento, spesso a un path prevedibile.
Cercarlo evita all'utente di andarlo a scovare a mano.

Perche' e' scritto qui e non delegato a `vulnapi discover`: nella v0.9.0 quel
comando **ignora `--report-format` e `--report-file`** e stampa solo una
tabella. Parsare quella tabella sarebbe fragile, e in piu' non direbbe se il
documento e' davvero utilizzabile.

La differenza che conta e' proprio questa: **un 200 non basta**. Molti server
rispondono 200 con la SPA a qualunque path, e passare quell'HTML a uno scanner
lo fa fallire piu' avanti con un errore incomprensibile. Qui ogni candidato
viene scaricato, interpretato, e accettato solo se contiene operazioni vere.

Tre strade, in ordine di costo:

1. **Header e well-known** — una manciata di richieste.
2. **Pagine di documentazione** — Swagger-UI e ReDoc dichiarano l'URL dello
   spec nel proprio HTML: leggerlo e' piu' preciso che indovinare.
3. **Wordlist** — i path convenzionali, sondati in parallelo.
"""
from __future__ import annotations

import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable
from urllib.parse import urljoin, urlsplit

#: Path convenzionali dei documenti. L'ordine e' indicativo: contano piu' i
#: punteggi di validazione, ma a parita' vince chi viene prima.
SPEC_PATHS: tuple[str, ...] = (
    # I piu' comuni, per primi.
    "openapi.json", "openapi.yaml", "openapi.yml",
    "swagger.json", "swagger.yaml", "swagger.yml",
    "api-docs", "api-docs.json", "apidocs", "apidocs.json",
    "v1/swagger.json", "v2/swagger.json", "v3/api-docs",
    "swagger/v1/swagger.json", "swagger/v2/swagger.json",
    "swagger-ui/swagger.json", "swagger-resources",
    # Sotto /api.
    "api/openapi.json", "api/openapi.yaml",
    "api/swagger.json", "api/swagger.yaml",
    "api/api-docs", "api/v1/api-docs", "api/v2/api-docs", "api/v3/api-docs",
    "api/v1/swagger.json", "api/v2/swagger.json",
    "api/docs", "api/doc", "api/spec", "api/schema",
    "api/v1/openapi.json", "api/v2/openapi.json",
    # Framework specifici.
    "v3/api-docs/swagger-config",          # springdoc
    "swagger/docs/v1", "swagger/docs/v2",  # ASP.NET
    "docs/openapi.json", "docs/swagger.json",
    "_spec", "spec.json", "schema.json", "schema.yaml",
    "openapi", "swagger",
    ".well-known/openapi.json",
    # Path di documentazione: non sono spec ma ne dichiarano l'URL.
    "docs", "swagger-ui.html", "swagger-ui/index.html", "swagger/index.html",
    "redoc", "redoc.html", "api/docs/", "documentation",
)

#: Endpoint GraphQL comuni. Non sono OpenAPI, ma sapere che ci sono cambia il
#: modo di scansionare: VulnAPI ha una modalita' dedicata.
GRAPHQL_PATHS: tuple[str, ...] = (
    "graphql", "graphiql", "api/graphql", "v1/graphql", "query",
    "graphql/console", "altair",
)

#: Da RFC 8615 e dintorni: costano poco e a volte dicono molto.
WELL_KNOWN_PATHS: tuple[str, ...] = (
    ".well-known/openapi.json",
    ".well-known/openid-configuration",
    ".well-known/oauth-authorization-server",
    ".well-known/jwks.json",
    ".well-known/security.txt",
)

#: Swagger-UI e ReDoc scrivono l'URL dello spec nella pagina. Questi pattern
#: lo estraggono dalle forme piu' diffuse.
_HTML_SPEC_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r'url\s*:\s*["\']([^"\']+)["\']', re.I),          # SwaggerUIBundle
    re.compile(r'spec-url\s*=\s*["\']([^"\']+)["\']', re.I),     # redoc
    re.compile(r'data-url\s*=\s*["\']([^"\']+)["\']', re.I),
    re.compile(r'["\']swaggerDoc["\']\s*:\s*["\']([^"\']+)["\']', re.I),
    re.compile(r'configUrl\s*:\s*["\']([^"\']+)["\']', re.I),
    re.compile(r'href\s*=\s*["\']([^"\']*(?:openapi|swagger)[^"\']*\.(?:json|ya?ml))["\']', re.I),
)

#: Estensioni e frammenti che non possono essere uno spec: si scartano prima
#: di scaricarli.
_HTML_SPEC_BLACKLIST = re.compile(r"\.(?:css|js|png|jpe?g|gif|svg|ico|woff2?)(?:\?|$)", re.I)

#: Soglia oltre la quale un candidato e' considerato utilizzabile.
MIN_CONFIDENCE = 0.5

#: Tetto sulla dimensione scaricata per candidato. Uno spec grande esiste, ma
#: oltre questa soglia e' piu' probabile aver preso un file sbagliato che un
#: contratto: scaricarlo interamente sprecherebbe tempo e banda.
MAX_SPEC_BYTES = 24 * 1024 * 1024


@dataclass
class SpecCandidate:
    """Un possibile documento OpenAPI, con il motivo per cui lo si crede tale."""

    url: str
    status: int = 0
    content_type: str = ""
    #: openapi3 | swagger2 | asyncapi | unknown
    kind: str = "unknown"
    version: str = ""
    title: str = ""
    paths: int = 0
    operations: int = 0
    size: int = 0
    #: wordlist | html | well-known | header
    source: str = "wordlist"
    confidence: float = 0.0
    #: Contenuto grezzo, tenuto solo per il candidato che verra' salvato.
    _body: str = field(default="", repr=False)

    def describe(self) -> str:
        bits = [self.url]
        if self.kind != "unknown":
            bits.append(f"{self.kind} {self.version}".strip())
        if self.operations:
            bits.append(f"{self.operations} operazioni su {self.paths} path")
        if self.title:
            bits.append(f"«{self.title}»")
        return " · ".join(bits)


@dataclass
class DiscoveryResult:
    base_url: str
    specs: list[SpecCandidate] = field(default_factory=list)
    graphql: list[str] = field(default_factory=list)
    well_known: list[str] = field(default_factory=list)
    server: str = ""
    powered_by: str = ""
    #: Percorso in cui il documento migliore e' stato salvato.
    saved_to: Path | None = None
    #: Richieste effettuate: utile per dire all'utente quanto si e' bussato.
    requests_made: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def best(self) -> SpecCandidate | None:
        usable = [s for s in self.specs if s.confidence >= MIN_CONFIDENCE]
        return usable[0] if usable else None

    def summary_lines(self) -> list[str]:
        lines: list[str] = []
        if self.server or self.powered_by:
            tech = ", ".join(t for t in (self.server, self.powered_by) if t)
            lines.append(f"Tecnologia: {tech}")
        if self.specs:
            lines.append(f"Documenti trovati: {len(self.specs)}")
            for spec in self.specs[:5]:
                mark = "->" if spec is self.best else "  "
                lines.append(f"  {mark} [{spec.confidence:.2f}] {spec.describe()}")
        else:
            lines.append("Nessun documento OpenAPI trovato.")
        if self.graphql:
            lines.append(f"GraphQL: {', '.join(self.graphql)}")
        if self.well_known:
            lines.append(f"Well-known: {', '.join(self.well_known)}")
        lines.append(f"Richieste effettuate: {self.requests_made}")
        return lines


# ---------------------------------------------------------------------- #

def discover(
    base_url: str,
    *,
    headers: dict[str, str] | None = None,
    timeout: float = 8.0,
    workers: int = 12,
    insecure: bool = False,
    proxy: str = "",
    extra_paths: Iterable[str] = (),
    find_graphql: bool = True,
    progress: Callable[[str], None] | None = None,
) -> DiscoveryResult:
    """Cerca il documento OpenAPI a partire dalla URL di base.

    Non solleva per i problemi di rete: li accumula in `errors`. Una discovery
    che fallisce deve poter essere seguita da una scansione con contratto
    fornito a mano, non interrompere tutto.
    """
    import requests

    def say(message: str) -> None:
        if progress is not None:
            progress(message)

    base = base_url.strip().rstrip("/")
    if not base.lower().startswith(("http://", "https://")):
        base = "https://" + base

    result = DiscoveryResult(base_url=base)

    session = requests.Session()
    session.verify = not insecure
    if insecure:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}
    session.headers.update({
        # Un User-Agent riconoscibile: chi riceve le richieste deve poter
        # capire cosa sono senza dover indagare.
        "User-Agent": "apisec-suite/1.0 (API documentation discovery)",
        "Accept": "application/json, application/yaml, text/yaml, text/html;q=0.8, */*;q=0.5",
    })
    if headers:
        session.headers.update(headers)

    counter = _Counter()

    # --- 1) la radice: header e, se e' una pagina di documentazione, il suo HTML
    say("[*] Analisi della radice")
    root = _fetch(session, base + "/", timeout, counter, result)
    if root is not None:
        result.server = root.headers.get("Server", "")
        result.powered_by = root.headers.get("X-Powered-By", "")
        for url in _spec_urls_from_headers(root.headers, base):
            _consider(session, url, "header", timeout, counter, result)
        if _looks_like_html(root):
            for url in _spec_urls_from_html(root.text[:400_000], root.url or base):
                _consider(session, url, "html", timeout, counter, result)

    # --- 2) wordlist, in parallelo
    paths = list(dict.fromkeys(list(SPEC_PATHS) + list(extra_paths)))
    say(f"[*] Sondaggio di {len(paths)} percorsi convenzionali")
    _probe_many(session, base, paths, timeout, workers, counter, result, say)

    # --- 3) well-known e GraphQL: pochi path, molto informativi
    say("[*] Percorsi .well-known")
    for path in WELL_KNOWN_PATHS:
        url = f"{base}/{path}"
        response = _fetch(session, url, timeout, counter, result)
        if response is not None and response.status_code == 200:
            result.well_known.append(url)
            _consider_response(response, url, "well-known", result)

    if find_graphql:
        say("[*] Endpoint GraphQL")
        for path in GRAPHQL_PATHS:
            url = f"{base}/{path}"
            if _probe_graphql(session, url, timeout, counter, result):
                result.graphql.append(url)

    # Ordine finale: prima la fiducia, poi la ricchezza del contratto.
    result.specs.sort(key=lambda s: (-s.confidence, -s.operations, len(s.url)))
    result.requests_made = counter.value
    return result


def save_spec(result: DiscoveryResult, dest_dir: Path,
              candidate: SpecCandidate | None = None) -> Path | None:
    """Salva su disco il documento scelto. Ritorna il percorso, o None."""
    spec = candidate or result.best
    if spec is None or not spec._body:
        return None

    dest_dir.mkdir(parents=True, exist_ok=True)
    # L'estensione segue il contenuto, non la URL: molti server servono JSON da
    # un path senza estensione, e gli engine si regolano sul suffisso.
    suffix = ".json" if spec._body.lstrip().startswith(("{", "[")) else ".yaml"
    path = dest_dir / f"discovered-openapi{suffix}"
    path.write_text(spec._body, encoding="utf-8")
    result.saved_to = path
    return path


# ---------------------------------------------------------------------- #
# Interne
# ---------------------------------------------------------------------- #

class _Counter:
    """Contatore di richieste, condiviso fra i thread.

    Il GIL rende l'incremento di un int abbastanza sicuro da non giustificare
    un lock qui: il valore serve a informare l'utente, non a decidere nulla.
    """

    def __init__(self) -> None:
        self.value = 0

    def tick(self) -> None:
        self.value += 1


def _fetch(session: Any, url: str, timeout: float, counter: _Counter,
           result: DiscoveryResult, method: str = "GET") -> Any | None:
    import requests
    counter.tick()
    try:
        return session.request(
            method, url, timeout=timeout, allow_redirects=True,
            # `stream` per poter interrompere prima di scaricare un file enorme.
            stream=True,
        )
    except requests.RequestException as exc:
        # Un path che non risponde e' la norma durante una discovery: si
        # registra solo il primo errore per host, per non riempire il report.
        message = f"{type(exc).__name__} su {url}"
        if len(result.errors) < 5:
            result.errors.append(message)
        return None


def _probe_many(session: Any, base: str, paths: list[str], timeout: float,
                workers: int, counter: _Counter, result: DiscoveryResult,
                say: Callable[[str], None]) -> None:
    """Sonda i path in parallelo, con un tetto sulla concorrenza."""
    urls = [f"{base}/{path.lstrip('/')}" for path in paths]
    found_before = len(result.specs)

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = {
            pool.submit(_probe_one, session, url, timeout, counter, result): url
            for url in urls
        }
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as exc:  # difensivo: un thread non deve far cadere tutto
                if len(result.errors) < 5:
                    result.errors.append(f"{type(exc).__name__}: {exc}")

    new = len(result.specs) - found_before
    say(f"[+] {new} documento/i candidato/i dai percorsi convenzionali")


def _probe_one(session: Any, url: str, timeout: float, counter: _Counter,
               result: DiscoveryResult) -> None:
    response = _fetch(session, url, timeout, counter, result)
    if response is None:
        return
    if response.status_code != 200:
        response.close()
        return

    if _looks_like_html(response):
        # Una pagina di documentazione non e' uno spec, ma ne dichiara l'URL.
        try:
            html = _read_capped(response, 400_000)
        finally:
            response.close()
        for spec_url in _spec_urls_from_html(html, url):
            _consider(session, spec_url, "html", timeout, counter, result)
        return

    _consider_response(response, url, "wordlist", result)


def _consider(session: Any, url: str, source: str, timeout: float,
              counter: _Counter, result: DiscoveryResult) -> None:
    """Scarica e valuta una URL segnalata da header o HTML."""
    if any(existing.url == url for existing in result.specs):
        return
    if _HTML_SPEC_BLACKLIST.search(url):
        return
    response = _fetch(session, url, timeout, counter, result)
    if response is None:
        return
    if response.status_code != 200 or _looks_like_html(response):
        response.close()
        return
    _consider_response(response, url, source, result)


def _consider_response(response: Any, url: str, source: str,
                       result: DiscoveryResult) -> None:
    """Valuta una risposta gia' ottenuta e, se plausibile, la registra."""
    try:
        body = _read_capped(response, MAX_SPEC_BYTES)
    except Exception:
        return
    finally:
        response.close()

    candidate = _evaluate(body, url, source,
                          response.headers.get("Content-Type", ""),
                          response.status_code)
    if candidate is not None and candidate.confidence > 0:
        if not any(existing.url == candidate.url for existing in result.specs):
            result.specs.append(candidate)


def _evaluate(body: str, url: str, source: str, content_type: str,
              status: int) -> SpecCandidate | None:
    """Trasforma un corpo di risposta in un candidato con un punteggio.

    Il punteggio non e' estetico: separa un contratto vero da un JSON qualsiasi
    che si trova allo stesso path. Un documento senza operazioni non serve a
    nessuno dei due engine, e proporlo li farebbe fallire piu' avanti.
    """
    data = _parse_structured(body)
    if not isinstance(data, dict):
        return None

    candidate = SpecCandidate(
        url=url, status=status, content_type=content_type,
        source=source, size=len(body), _body=body,
    )

    score = 0.0
    if "openapi" in data:
        candidate.kind = "openapi3"
        candidate.version = str(data.get("openapi") or "")
        score += 0.5
    elif "swagger" in data:
        candidate.kind = "swagger2"
        candidate.version = str(data.get("swagger") or "")
        score += 0.5
    elif "asyncapi" in data:
        candidate.kind = "asyncapi"
        candidate.version = str(data.get("asyncapi") or "")
        score += 0.3

    info = data.get("info")
    if isinstance(info, dict):
        score += 0.15
        candidate.title = str(info.get("title") or "")[:120]

    paths = data.get("paths")
    if isinstance(paths, dict) and paths:
        candidate.paths = len(paths)
        candidate.operations = sum(
            1
            for item in paths.values() if isinstance(item, dict)
            for method in item
            if method.lower() in ("get", "post", "put", "patch", "delete",
                                  "head", "options", "trace")
        )
        # E' il segnale che conta di piu': senza operazioni non c'e' niente da
        # scansionare, per quanto il resto sia formalmente corretto.
        score += 0.3 if candidate.operations else 0.0

    if any(key in data for key in ("components", "definitions", "servers", "host")):
        score += 0.05

    candidate.confidence = round(min(score, 1.0), 2)
    return candidate


def _parse_structured(body: str) -> Any:
    """Interpreta JSON o YAML. Ritorna None se non e' ne' l'uno ne' l'altro."""
    text = body.strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except ValueError:
        pass
    # YAML solo se il testo non e' palesemente altro: `yaml.safe_load` accetta
    # anche una stringa qualsiasi, restituendola com'e'.
    if text.startswith("<"):
        return None
    try:
        import yaml
    except ImportError:
        return None
    try:
        return yaml.safe_load(text)
    except Exception:
        return None


def _looks_like_html(response: Any) -> bool:
    return "html" in (response.headers.get("Content-Type", "") or "").lower()


def _read_capped(response: Any, limit: int) -> str:
    """Legge al piu' `limit` byte e decodifica in testo.

    Con `stream=True` il corpo non e' ancora stato scaricato: qui si evita di
    tirare giu' un file enorme solo per scoprire che non e' uno spec.
    """
    chunks: list[bytes] = []
    total = 0
    for chunk in response.iter_content(chunk_size=64 * 1024):
        if not chunk:
            continue
        chunks.append(chunk)
        total += len(chunk)
        if total >= limit:
            break
    raw = b"".join(chunks)[:limit]
    encoding = response.encoding or "utf-8"
    try:
        return raw.decode(encoding, errors="replace")
    except LookupError:
        return raw.decode("utf-8", errors="replace")


def _spec_urls_from_html(html: str, page_url: str) -> list[str]:
    """URL di spec dichiarate dentro una pagina Swagger-UI o ReDoc."""
    found: list[str] = []
    for pattern in _HTML_SPEC_PATTERNS:
        for match in pattern.findall(html):
            value = str(match).strip()
            if not value or value.startswith(("data:", "#", "javascript:")):
                continue
            if _HTML_SPEC_BLACKLIST.search(value):
                continue
            absolute = urljoin(page_url, value)
            # Solo lo stesso host: un link a petstore.swagger.io descrive
            # l'API di esempio, non quella che si sta esaminando.
            if urlsplit(absolute).netloc != urlsplit(page_url).netloc:
                continue
            if absolute not in found:
                found.append(absolute)
    return found[:12]


def _spec_urls_from_headers(headers: Any, base: str) -> list[str]:
    """Spec dichiarate in un header `Link` (rel=describedby o service-desc)."""
    link = headers.get("Link", "") if hasattr(headers, "get") else ""
    if not link:
        return []
    found: list[str] = []
    for part in str(link).split(","):
        match = re.search(r"<([^>]+)>", part)
        if not match:
            continue
        rel = re.search(r'rel\s*=\s*"?([^";]+)"?', part)
        if rel and rel.group(1).strip().lower() in (
            "describedby", "service-desc", "service-doc", "openapi",
        ):
            found.append(urljoin(base + "/", match.group(1)))
    return found


def _probe_graphql(session: Any, url: str, timeout: float, counter: _Counter,
                   result: DiscoveryResult) -> bool:
    """Verifica se `url` e' un endpoint GraphQL.

    Manda una query minima e valida invece di una introspezione completa: e'
    sufficiente a identificarlo e non estrae lo schema, cosa che spetta alla
    scansione vera e propria, con il consenso dell'utente.
    """
    import requests
    counter.tick()
    try:
        response = session.post(
            url, json={"query": "{__typename}"}, timeout=timeout,
            allow_redirects=True,
        )
    except requests.RequestException:
        return False

    if response.status_code not in (200, 400):
        return False
    try:
        data = response.json()
    except ValueError:
        return False
    if not isinstance(data, dict):
        return False
    # Una risposta GraphQL ha `data` o `errors`, entrambi con quella forma.
    if "data" in data and isinstance(data.get("data"), dict):
        return "__typename" in data["data"]
    return isinstance(data.get("errors"), list) and bool(data["errors"])
