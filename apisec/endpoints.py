"""Ricostruzione della superficie API da fonti diverse dal documento.

Quando un'API non pubblica un OpenAPI, la sua superficie non e' invisibile: e'
sparsa. Il bundle JavaScript della SPA contiene i path che chiama, `robots.txt`
li elenca per escluderli, la sitemap li dichiara, e gli archivi pubblici
ricordano quelli storici. Mettere insieme questi frammenti ricostruisce una
mappa che nessuna delle fonti da sola possiede.

E' la risposta al caso piu' frustrante della ricerca del documento: il server
che risponde 200 con la stessa SPA a qualunque indirizzo. Quella SPA *e'* la
mappa — basta leggerla invece di bussare a caso.

Da questi endpoint si sintetizza poi un OpenAPI minimale (vedi `synthesize`)
che entrambi gli engine sanno consumare. Non e' un contratto vero — mancano
schemi e tipi — ma dice agli scanner quali path esistono, ed e' meglio di un
crawl alla cieca.

Perimetro: le fonti in questo modulo, tranne quelle marcate OSINT, contattano
solo l'host del bersaglio. Le OSINT (Wayback, Common Crawl) interrogano servizi
terzi e sono opt-in, perche' inviano il nome del dominio a chi lo registra.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit
from typing import Any, Callable, Iterable

#: Metodi HTTP che consideriamo operazioni di un endpoint.
HTTP_METHODS = ("get", "post", "put", "patch", "delete", "head", "options")

#: Un path plausibile per un'API: comincia con /, non e' una risorsa statica.
_STATIC_SUFFIX = re.compile(
    r"\.(?:js|mjs|css|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|webp|avif|"
    r"mp4|webm|pdf|zip|gz|woff|html?)(?:$|[?#])", re.I)

#: Frammenti che indicano un template, da normalizzare a {id}.
_TEMPLATE_SEG = re.compile(
    r"^(?:\{[^}]+\}|:[^/]+|\$\{[^}]+\}|<[^>]+>|%[0-9a-f]{2}.*|\d+|"
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|"
    r"[0-9a-f]{24,})$", re.I)

# ---- pattern per estrarre path dai sorgenti JavaScript ----
# Ognuno cattura la parte-path in gruppo 1. Sono volutamente conservativi:
# meglio perdere un endpoint che riempire la mappa di stringhe a caso.
_JS_PATTERNS: tuple[re.Pattern[str], ...] = (
    # "/api/v1/users" o '/api/users' come stringa letterale con /api, /v1, /rest...
    re.compile(r"""["'`](\/(?:api|rest|v\d+|graphql|internal|admin|auth|oauth|"""
               r"""service|services|gateway|public|private)\/[^"'`\s]{0,200})["'`]""", re.I),
    # fetch("/qualcosa"), axios.get('/qualcosa'), $http.post(`/qualcosa`)
    re.compile(r"""(?:fetch|axios(?:\.\w+)?|\.(?:get|post|put|patch|delete|request)|"""
               r"""ajax|http(?:\.\w+)?)\s*\(\s*["'`](\/[^"'`\s]{1,200})["'`]""", re.I),
    # url: "/qualcosa"  |  baseURL: "/qualcosa"  |  endpoint: "/qualcosa"
    re.compile(r"""(?:url|uri|path|endpoint|route|baseURL|apiUrl|api_url)\s*[:=]\s*"""
               r"""["'`](\/[^"'`\s]{1,200})["'`]""", re.I),
    # template string con interpolazione: `/api/users/${id}` -> path con {id}
    re.compile(r"""["'`](\/(?:[^"'`\s$]{0,80}\$\{[^}]+\}[^"'`\s]{0,80})+)["'`]"""),
)

#: URL di sorgenti JS dentro l'HTML: <script src=...> e riferimenti a chunk.
_SCRIPT_SRC = re.compile(r'<script[^>]+src\s*=\s*["\']([^"\']+)["\']', re.I)
_CHUNK_REF = re.compile(r'["\']([^"\']+?\.(?:js|mjs))["\']')

#: Tetto sui sorgenti JS scaricati e sulla loro dimensione: un bundle enorme
#: esiste, ma oltre queste soglie il rendimento cala e il rischio di prendere
#: minified-noise sale.
MAX_JS_FILES = 20
MAX_JS_BYTES = 6 * 1024 * 1024


@dataclass
class Endpoint:
    """Un path scoperto, con i metodi noti e da dove viene."""

    path: str
    methods: set[str] = field(default_factory=set)
    #: js | robots | sitemap | wayback | commoncrawl | probe | link
    sources: set[str] = field(default_factory=set)
    #: True se il path contiene un parametro (era /users/{id} o /users/42).
    templated: bool = False

    def merge(self, other: "Endpoint") -> None:
        self.methods |= other.methods
        self.sources |= other.sources
        self.templated = self.templated or other.templated


@dataclass
class EndpointMap:
    """Superficie ricostruita: path unici, con metodi e provenienza."""

    base_url: str
    endpoints: dict[str, Endpoint] = field(default_factory=dict)
    #: Conteggi per fonte, per il report: da dove sono venuti gli endpoint.
    per_source: dict[str, int] = field(default_factory=dict)
    js_files_read: int = 0
    errors: list[str] = field(default_factory=list)

    def add(self, path: str, *, method: str = "", source: str = "") -> None:
        norm = _normalize(path)
        if norm is None:
            return
        templated = norm != _strip_template(norm)
        endpoint = self.endpoints.get(norm)
        if endpoint is None:
            endpoint = Endpoint(path=norm, templated=templated)
            self.endpoints[norm] = endpoint
        if method:
            endpoint.methods.add(method.lower())
        if source:
            endpoint.sources.add(source)
            self.per_source[source] = self.per_source.get(source, 0) + 1

    def paths(self) -> list[str]:
        return sorted(self.endpoints)

    def summary_lines(self) -> list[str]:
        lines = [f"Endpoint ricostruiti: {len(self.endpoints)}"]
        if self.per_source:
            by = ", ".join(f"{src}: {n}"
                           for src, n in sorted(self.per_source.items()))
            lines.append(f"  per fonte — {by}")
        if self.js_files_read:
            lines.append(f"  sorgenti JavaScript letti: {self.js_files_read}")
        return lines


# ---------------------------------------------------------------------- #
# Fonti che contattano solo il bersaglio
# ---------------------------------------------------------------------- #

def collect_from_target(
    session: Any,
    base: str,
    *,
    timeout: float,
    analyze_js: bool = True,
    read_robots: bool = True,
    on_request: Callable[[], None] | None = None,
    progress: Callable[[str], None] | None = None,
) -> EndpointMap:
    """Ricostruisce la superficie interrogando solo l'host del bersaglio."""
    emap = EndpointMap(base_url=base)

    def say(msg: str) -> None:
        if progress is not None:
            progress(msg)

    def tick() -> None:
        if on_request is not None:
            on_request()

    if read_robots:
        say("[*] robots.txt e sitemap.xml")
        _from_robots(session, base, timeout, emap, tick)
        _from_sitemap(session, base, timeout, emap, tick)

    if analyze_js:
        say("[*] Analisi dei sorgenti JavaScript")
        _from_javascript(session, base, timeout, emap, tick, say)

    return emap


def _from_robots(session: Any, base: str, timeout: float, emap: EndpointMap,
                 tick: Callable[[], None]) -> None:
    """Path da robots.txt. Le direttive Disallow spesso rivelano l'interessante."""
    text = _get_text(session, f"{base}/robots.txt", timeout, emap, tick)
    if not text:
        return
    for line in text.splitlines():
        line = line.strip()
        m = re.match(r"(?:Allow|Disallow|Sitemap)\s*:\s*(\S+)", line, re.I)
        if not m:
            continue
        value = m.group(1)
        if value.lower().startswith(("http://", "https://")):
            # Una Sitemap assoluta: la si esaminera' nel passo dedicato.
            continue
        emap.add(value, source="robots")


def _from_sitemap(session: Any, base: str, timeout: float, emap: EndpointMap,
                  tick: Callable[[], None]) -> None:
    """Path dalle URL elencate nella sitemap."""
    text = _get_text(session, f"{base}/sitemap.xml", timeout, emap, tick)
    if not text:
        return
    host = urlsplit(base).netloc
    for loc in re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", text, re.I):
        parts = urlsplit(loc)
        if parts.netloc and parts.netloc != host:
            continue
        emap.add(parts.path, source="sitemap")


def _from_javascript(session: Any, base: str, timeout: float, emap: EndpointMap,
                     tick: Callable[[], None],
                     say: Callable[[str], None]) -> None:
    """Scarica gli script della pagina ed estrae i path che vi compaiono.

    Segue una volta i riferimenti a chunk (webpack spezza il codice in file
    caricati a runtime), ma senza ricorsione profonda: il grosso degli endpoint
    sta nei primi bundle, e inseguire ogni chunk moltiplicherebbe le richieste
    per un rendimento calante.
    """
    home = _get_text(session, base + "/", timeout, emap, tick)
    if not home:
        return

    host = urlsplit(base).netloc
    script_urls: list[str] = []
    for src in _SCRIPT_SRC.findall(home):
        absolute = urljoin(base + "/", src)
        if urlsplit(absolute).netloc == host and absolute not in script_urls:
            script_urls.append(absolute)

    seen: set[str] = set()
    to_read = script_urls[:MAX_JS_FILES]
    chunk_budget = MAX_JS_FILES

    while to_read and emap.js_files_read < MAX_JS_FILES:
        url = to_read.pop(0)
        if url in seen:
            continue
        seen.add(url)

        code = _get_text(session, url, timeout, emap, tick, cap=MAX_JS_BYTES)
        if not code:
            continue
        emap.js_files_read += 1

        before = len(emap.endpoints)
        for pattern in _JS_PATTERNS:
            for match in pattern.findall(code):
                emap.add(str(match), source="js")
        found = len(emap.endpoints) - before
        if found:
            say(f"    {url.rsplit('/', 1)[-1]}: {found} path")

        # I chunk webpack: si aggiungono i primi trovati, entro il budget.
        if chunk_budget > 0:
            for ref in _CHUNK_REF.findall(code)[:8]:
                absolute = urljoin(url, ref)
                if (urlsplit(absolute).netloc == host and absolute not in seen
                        and absolute not in to_read):
                    to_read.append(absolute)
                    chunk_budget -= 1
                    if chunk_budget <= 0:
                        break


# ---------------------------------------------------------------------- #
# Fonti OSINT (contattano servizi terzi) — opt-in
# ---------------------------------------------------------------------- #

def collect_from_osint(
    session: Any,
    base: str,
    *,
    timeout: float,
    on_request: Callable[[], None] | None = None,
    progress: Callable[[str], None] | None = None,
) -> EndpointMap:
    """Path storici da archivi pubblici. Contatta web.archive.org e commoncrawl.

    Invia il nome del dominio a servizi terzi, che lo registrano: da usare solo
    con consapevolezza. Passivo verso il bersaglio, che non riceve richieste.
    """
    emap = EndpointMap(base_url=base)

    def say(msg: str) -> None:
        if progress is not None:
            progress(msg)

    def tick() -> None:
        if on_request is not None:
            on_request()

    host = urlsplit(base).netloc
    say(f"[*] OSINT passivo per {host} (contatta servizi terzi)")
    _from_wayback(session, host, timeout, emap, tick, say)
    _from_commoncrawl(session, host, timeout, emap, tick, say)

    # Distingue «gli archivi non hanno nulla» da «non li ho raggiunti»: la
    # seconda e' un problema di rete (proxy, firewall, DNS), non un risultato.
    if not emap.endpoints and emap.errors:
        say("[!] Nessun endpoint dagli archivi, ma ci sono stati errori di "
            "rete: web.archive.org o commoncrawl.org potrebbero essere "
            "irraggiungibili da questa macchina (proxy o firewall).")
    return emap


def _from_wayback(session: Any, host: str, timeout: float, emap: EndpointMap,
                  tick: Callable[[], None], say: Callable[[str], None]) -> None:
    """URL note dalla Wayback Machine (Internet Archive)."""
    url = ("https://web.archive.org/cdx/search/cdx"
           f"?url={host}/*&output=text&fl=original&collapse=urlkey&limit=5000")
    text = _get_text(session, url, timeout, emap, tick, cap=8 * 1024 * 1024)
    if not text:
        return
    before = len(emap.endpoints)
    for line in text.splitlines():
        parts = urlsplit(line.strip())
        if parts.netloc.endswith(host):
            emap.add(parts.path, source="wayback")
    say(f"    Wayback: {len(emap.endpoints) - before} path")


def _from_commoncrawl(session: Any, host: str, timeout: float,
                      emap: EndpointMap, tick: Callable[[], None],
                      say: Callable[[str], None]) -> None:
    """URL dall'indice piu' recente di Common Crawl."""
    import json
    # L'indice piu' recente ha un nome che cambia: lo si chiede al collinfo.
    idx_text = _get_text(session, "https://index.commoncrawl.org/collinfo.json",
                         timeout, emap, tick)
    if not idx_text:
        return
    try:
        collections = json.loads(idx_text)
        cdx_api = collections[0]["cdx-api"]
    except (ValueError, KeyError, IndexError):
        return

    url = f"{cdx_api}?url={host}/*&output=json&limit=3000"
    text = _get_text(session, url, timeout, emap, tick, cap=8 * 1024 * 1024)
    if not text:
        return
    before = len(emap.endpoints)
    for line in text.splitlines():
        try:
            record = json.loads(line)
        except ValueError:
            continue
        parts = urlsplit(str(record.get("url", "")))
        if parts.netloc.endswith(host):
            emap.add(parts.path, source="commoncrawl")
    say(f"    Common Crawl: {len(emap.endpoints) - before} path")


# ---------------------------------------------------------------------- #
# Sintesi dell'OpenAPI
# ---------------------------------------------------------------------- #

def synthesize(emap: EndpointMap, target_url: str,
               title: str = "API ricostruita (apisec-suite)") -> dict[str, Any]:
    """Costruisce un OpenAPI 3.1 minimale dagli endpoint scoperti.

    Non e' un contratto vero: non conosce corpi, tipi ne' risposte. Dichiara
    solo quali path esistono e con quali metodi, che e' cio' che serve agli
    engine per sapere dove bussare. I parametri di path ({id}) diventano
    parametri OpenAPI, cosi' gli scanner li riconoscono come punti di
    manipolazione — la base dei test BOLA.
    """
    base = f"{urlsplit(target_url).scheme}://{urlsplit(target_url).netloc}"
    paths: dict[str, Any] = {}

    for path in emap.paths():
        endpoint = emap.endpoints[path]
        # Senza metodi noti si assume GET: e' l'ipotesi piu' sicura da mandare
        # a uno scanner, e sara' lui a scoprire gli altri metodi.
        methods = sorted(endpoint.methods) or ["get"]
        operations: dict[str, Any] = {}
        for method in methods:
            if method not in HTTP_METHODS:
                continue
            operation: dict[str, Any] = {
                "summary": f"Ricostruito da: {', '.join(sorted(endpoint.sources))}",
                "responses": {"default": {"description": "sconosciuta"}},
            }
            params = _path_parameters(path)
            if params:
                operation["parameters"] = params
            operations[method] = operation
        if operations:
            paths[path] = operations

    return {
        "openapi": "3.1.0",
        "info": {
            "title": title,
            "version": "0.0.0",
            "description": (
                "Documento sintetizzato da apisec-suite dagli endpoint scoperti "
                "(JavaScript, robots.txt, sitemap, archivi). NON e' il contratto "
                "ufficiale: mancano schemi, tipi e risposte. Elenca i path noti "
                "perche' gli scanner sappiano dove agire."
            ),
        },
        "servers": [{"url": base}],
        "paths": paths,
    }


def _path_parameters(path: str) -> list[dict[str, Any]]:
    """Parametri OpenAPI per i segmenti templated di un path."""
    params: list[dict[str, Any]] = []
    for name in re.findall(r"\{([^}]+)\}", path):
        params.append({
            "name": name,
            "in": "path",
            "required": True,
            "schema": {"type": "string"},
        })
    return params


# ---------------------------------------------------------------------- #
# Normalizzazione dei path
# ---------------------------------------------------------------------- #

def _normalize(raw: str) -> str | None:
    """Ripulisce un path grezzo, o lo scarta se non e' plausibile.

    Scarta URL assolute con altro host, risorse statiche, e stringhe che non
    somigliano a un path. Riduce i segmenti-valore a {id} per non moltiplicare
    lo stesso endpoint.
    """
    if not raw:
        return None
    raw = raw.strip().strip("\"'`")
    if not raw:
        return None

    # Se e' assoluta, tienila solo se ha uno schema http; scartane l'origine.
    if raw.lower().startswith(("http://", "https://")):
        parts = urlsplit(raw)
        raw = parts.path or "/"
    elif raw.startswith("//"):
        return None  # protocol-relative verso altro host

    raw = raw.split("?", 1)[0].split("#", 1)[0]
    if not raw.startswith("/"):
        return None
    if _STATIC_SUFFIX.search(raw):
        return None
    # Path con caratteri improbabili per un endpoint (spazi, HTML, glob).
    if any(ch in raw for ch in (" ", "<", ">", "\\", "\n")):
        return None
    if len(raw) > 200 or raw.count("/") > 12:
        return None

    segments = []
    for seg in raw.split("/"):
        if seg == "":
            continue
        segments.append("{id}" if _TEMPLATE_SEG.match(seg) else seg)
    normalized = "/" + "/".join(segments)

    # Un path fatto solo di {id} o troppo generico non aiuta.
    if normalized in ("/", "/{id}") and not segments:
        return None
    return normalized


def _strip_template(path: str) -> str:
    return path.replace("{id}", "")


def merge_maps(*maps: EndpointMap) -> EndpointMap:
    """Fonde piu' mappe in una, sommando metodi, fonti e conteggi."""
    merged = EndpointMap(base_url=maps[0].base_url if maps else "")
    for emap in maps:
        merged.js_files_read += emap.js_files_read
        merged.errors.extend(emap.errors)
        for path, endpoint in emap.endpoints.items():
            existing = merged.endpoints.get(path)
            if existing is None:
                merged.endpoints[path] = Endpoint(
                    path=endpoint.path, methods=set(endpoint.methods),
                    sources=set(endpoint.sources), templated=endpoint.templated)
            else:
                existing.merge(endpoint)
        for src, count in emap.per_source.items():
            merged.per_source[src] = merged.per_source.get(src, 0) + count
    return merged


# ---------------------------------------------------------------------- #

def _get_text(session: Any, url: str, timeout: float, emap: EndpointMap,
              tick: Callable[[], None], cap: int = 2 * 1024 * 1024) -> str:
    """GET che ritorna il testo, o "" in caso di problema. Non solleva mai."""
    import requests
    tick()
    try:
        response = session.get(url, timeout=timeout, allow_redirects=True,
                               stream=True)
    except requests.RequestException as exc:
        if len(emap.errors) < 8:
            emap.errors.append(f"{type(exc).__name__} su {url}")
        return ""
    try:
        if response.status_code != 200:
            return ""
        chunks: list[bytes] = []
        total = 0
        for chunk in response.iter_content(chunk_size=64 * 1024):
            if not chunk:
                continue
            chunks.append(chunk)
            total += len(chunk)
            if total >= cap:
                break
        encoding = response.encoding or "utf-8"
        return b"".join(chunks)[:cap].decode(encoding, errors="replace")
    except Exception as exc:
        if len(emap.errors) < 8:
            emap.errors.append(f"lettura {url}: {exc}")
        return ""
    finally:
        response.close()
