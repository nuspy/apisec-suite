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
#: punteggi di validazione, ma a parita' vince chi viene prima. La lista e'
#: ampliata con i percorsi piu' ricorrenti dai dataset pubblici (SecLists,
#: Kiterunner) e dai default dei framework piu' diffusi.
SPEC_PATHS: tuple[str, ...] = (
    # --- i piu' comuni, per primi ---
    "openapi.json", "openapi.yaml", "openapi.yml",
    "swagger.json", "swagger.yaml", "swagger.yml",
    "api-docs", "api-docs.json", "api-docs.yaml",
    "apidocs", "apidocs.json",
    "v1/swagger.json", "v2/swagger.json", "v3/swagger.json",
    "v1/openapi.json", "v2/openapi.json", "v3/openapi.json",
    "v3/api-docs", "v2/api-docs", "v1/api-docs",
    "swagger/v1/swagger.json", "swagger/v2/swagger.json",
    "swagger-ui/swagger.json", "swagger-resources",
    "swagger-resources/configuration/ui",
    # --- sotto /api ---
    "api/openapi.json", "api/openapi.yaml", "api/openapi.yml",
    "api/swagger.json", "api/swagger.yaml", "api/swagger.yml",
    "api/api-docs", "api/v1/api-docs", "api/v2/api-docs", "api/v3/api-docs",
    "api/v1/swagger.json", "api/v2/swagger.json", "api/v3/swagger.json",
    "api/v1/openapi.json", "api/v2/openapi.json", "api/v3/openapi.json",
    "api/docs", "api/doc", "api/spec", "api/schema", "api/swagger",
    "api/swagger-ui.html", "api/swagger/ui", "api/swagger-resources",
    "api/documentation", "api/openapi", "api/index.html",
    # --- framework specifici ---
    "v3/api-docs/swagger-config",              # springdoc
    "v2/api-docs?group=", "swagger/docs/v1", "swagger/docs/v2",  # ASP.NET
    "swagger/v1/swagger.yaml",
    "docs/openapi.json", "docs/swagger.json", "docs/api-docs.json",
    "_spec", "spec.json", "spec.yaml", "schema.json", "schema.yaml",
    "graphql/schema.json",                     # apollo/graphql
    "wp-json", "wp-json/wp/v2",                # WordPress REST
    "rest/v1/openapi.json", "rest/api-docs",
    ".well-known/openapi.json",
    "openapi", "swagger", "swagger.yaml",
    "static/openapi.json", "static/swagger.json",
    "assets/openapi.json", "public/openapi.json",
    # --- pagine di documentazione: non sono spec ma ne dichiarano l'URL ---
    "docs", "docs/", "documentation", "swagger-ui.html",
    "swagger-ui/", "swagger-ui/index.html", "swagger/index.html",
    "swagger/", "api-docs/", "redoc", "redoc.html", "api/docs/",
    "rapidoc", "rapidoc.html", "scalar", "reference",     # UI moderne
    "developer", "developers", "api/reference",
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
    #: Superficie ricostruita da JS/robots/sitemap/OSINT, quando quelle fonti
    #: sono attive. Alimenta la sintesi di un OpenAPI quando non se ne trova uno.
    endpoint_map: Any = None
    #: Percorso dell'OpenAPI sintetizzato dagli endpoint, se e' stato prodotto.
    synthesized_to: Path | None = None
    #: Basi effettivamente sondate: con una URL che ha un path si risale anche
    #: ai livelli superiori, ed e' bene che l'utente sappia dove si e' guardato.
    bases_probed: list[str] = field(default_factory=list)
    #: Quante risposte per codice di stato. Distingue "non c'e' niente" da
    #: "e' tutto protetto" da "l'host non risponde".
    status_counts: dict[int, int] = field(default_factory=dict)
    #: Richieste fallite prima di ricevere una risposta.
    network_errors: int = 0
    #: L'host ha risposto almeno una volta.
    reachable: bool = False

    @property
    def best(self) -> SpecCandidate | None:
        usable = [s for s in self.specs if s.confidence >= MIN_CONFIDENCE]
        return usable[0] if usable else None

    def diagnosis(self) -> list[str]:
        """Perche' non si e' trovato nulla, e cosa si puo' fare.

        «Nessun documento trovato» da solo non dice se il bersaglio non ne ha,
        se sono tutti protetti, o se non lo si e' proprio raggiunto: sono tre
        situazioni con tre rimedi diversi.
        """
        if self.best is not None:
            return []

        notes: list[str] = []

        if not self.reachable:
            notes.append(
                f"L'host non ha risposto a nessuna delle {self.requests_made} "
                f"richieste ({self.network_errors} errori di rete). Verificare "
                f"che la URL sia raggiungibile da questa macchina, lo schema "
                f"http/https, ed eventuali proxy o firewall."
            )
            if self.errors:
                notes.append(f"Primo errore: {self.errors[0]}")
            return notes

        protected = sum(self.status_counts.get(code, 0) for code in (401, 403))
        if protected:
            notes.append(
                f"{protected} percorsi hanno risposto 401/403: il documento "
                f"potrebbe esserci ma essere protetto. Compilare le credenziali "
                f"nel tab Authentication e ripetere la ricerca."
            )

        # La soglia evita di scomodare la spiegazione del "risponde 200 a
        # tutto" quando i 200 sono uno o due: li' e' semplicemente la radice
        # che risponde, e il messaggio pertinente e' un altro.
        ok_count = self.status_counts.get(200, 0)
        if ok_count >= 3 and not self.specs:
            notes.append(
                f"{ok_count} percorsi hanno risposto 200 ma nessuno conteneva "
                f"un contratto valido: probabilmente il server risponde con la "
                f"stessa pagina a qualunque indirizzo."
            )

        if self.status_counts.get(429):
            notes.append(
                f"{self.status_counts[429]} risposte 429 (troppe richieste): "
                f"il bersaglio sta limitando il traffico e la ricerca puo' "
                f"essere incompleta. Riprovare con meno thread."
            )

        redirects = sum(count for code, count in self.status_counts.items()
                        if 300 <= code < 400)
        if redirects:
            notes.append(
                f"{redirects} redirect non seguiti fino a una risposta utile: "
                f"il servizio potrebbe stare a un indirizzo diverso."
            )

        if not notes:
            notes.append(
                "Il bersaglio ha risposto ma nessun percorso conteneva un "
                "documento. Se sai dove sta, indicalo con --discover-path "
                "(oppure compila il campo Swagger a mano)."
            )
        notes.append(f"Percorsi di base esaminati: {', '.join(self.bases_probed)}")
        return notes

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
        if self.status_counts:
            summary = ", ".join(
                f"{code}×{count}"
                for code, count in sorted(self.status_counts.items())
            )
            lines.append(f"Risposte: {summary}")
        lines.append(f"Richieste effettuate: {self.requests_made}"
                     + (f" ({self.network_errors} senza risposta)"
                        if self.network_errors else ""))
        lines.extend(self.diagnosis())
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
    analyze_js: bool = True,
    read_robots: bool = True,
    osint: bool = False,
    progress: Callable[[str], None] | None = None,
) -> DiscoveryResult:
    """Cerca il documento OpenAPI a partire dalla URL di base.

    Oltre ai percorsi convenzionali e alle pagine di documentazione, quando
    `analyze_js`/`read_robots` sono attivi ricostruisce la superficie
    dell'API dai bundle JavaScript, da robots.txt e dalla sitemap; con `osint`
    interroga anche gli archivi pubblici (che contattano servizi terzi). Gli
    endpoint cosi' trovati servono a due cose: sondare path aggiuntivi per
    scovare lo spec vero, e — se non se ne trova nessuno — sintetizzarne uno.

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

    counter = _Counter(result)

    # Con una URL che ha un path (`https://host/api/v1`) il documento sta
    # spesso piu' in alto: su `https://host/openapi.json` o `/docs`. Cercare
    # solo sotto il path indicato e' il motivo piu' comune per cui una ricerca
    # non trova niente pur essendoci qualcosa.
    bases = _candidate_bases(base)
    result.bases_probed = list(bases)
    if len(bases) > 1:
        say(f"[*] La URL ha un percorso: cerco anche in "
            f"{', '.join(bases[1:])}")

    # --- 1) la radice di ogni base: header e pagine di documentazione
    for index, current in enumerate(bases):
        say(f"[*] Analisi di {current}")
        root = _fetch(session, current + "/", timeout, counter, result)
        if root is None:
            continue
        if index == 0 or not result.server:
            result.server = root.headers.get("Server", "") or result.server
            result.powered_by = (root.headers.get("X-Powered-By", "")
                                 or result.powered_by)
        for url in _spec_urls_from_headers(root.headers, current):
            _consider(session, url, "header", timeout, counter, result)
        if _looks_like_html(root):
            try:
                html_text = _read_capped(root, 400_000)
            finally:
                root.close()
            for url in _spec_urls_from_html(html_text, current + "/"):
                _consider(session, url, "html", timeout, counter, result)
        else:
            root.close()

    # --- 2) wordlist, in parallelo su ogni base
    paths = list(dict.fromkeys(list(SPEC_PATHS) + list(extra_paths)))
    for index, current in enumerate(bases):
        # Sulla base indicata dall'utente si prova tutto; sui livelli superiori
        # solo i percorsi piu' probabili, per non moltiplicare le richieste.
        subset = paths if index == 0 else paths[:24]
        say(f"[*] Sondaggio di {len(subset)} percorsi su {current}")
        _probe_many(session, current, subset, timeout, workers, counter,
                    result, say)

    # --- 2b) ricostruzione della superficie da JS, robots, sitemap, OSINT
    # Gli endpoint trovati diventano path da sondare (magari lo spec sta sotto
    # uno di essi) e, se non si trova un documento, la base per sintetizzarne
    # uno.
    if analyze_js or read_robots or osint:
        from . import endpoints as _ep

        emaps: list[Any] = []
        target_emap = _ep.collect_from_target(
            session, base, timeout=timeout,
            analyze_js=analyze_js, read_robots=read_robots,
            on_request=counter.tick, progress=say,
        )
        emaps.append(target_emap)

        if osint:
            say("[!] OSINT attivo: interrogo archivi pubblici. Il dominio del "
                "bersaglio viene inviato a servizi terzi, che lo registrano.")
            osint_emap = _ep.collect_from_osint(
                session, base, timeout=max(timeout, 15.0),
                on_request=counter.tick, progress=say,
            )
            emaps.append(osint_emap)

        emap = _ep.merge_maps(*emaps)
        result.endpoint_map = emap
        result.errors.extend(emap.errors[:3])
        for line in emap.summary_lines():
            say(f"    {line}")

        # Gli endpoint che *sembrano* documenti (finiscono in .json/.yaml o
        # contengono swagger/openapi) meritano un tentativo diretto.
        for path in emap.paths():
            low = path.lower()
            if (low.endswith((".json", ".yaml", ".yml"))
                    or "swagger" in low or "openapi" in low or "api-docs" in low):
                _consider(session, base.rstrip("/") + path, "endpoint-map",
                          timeout, counter, result)

    # --- 3) well-known e GraphQL: pochi path, molto informativi
    say("[*] Percorsi .well-known")
    for path in WELL_KNOWN_PATHS:
        url = f"{base}/{path}"
        response = _fetch(session, url, timeout, counter, result)
        if response is None or response.status_code != 200:
            continue
        # Un server che serve la propria SPA a qualunque indirizzo risponde
        # 200 anche qui: elencarli tutti come "well-known trovati" sarebbe
        # cinque falsi positivi di fila. Un descrittore vero non e' HTML.
        if _looks_like_html(response):
            response.close()
            continue
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


def synthesize_spec(result: DiscoveryResult, target_url: str,
                    dest_dir: Path, min_endpoints: int = 1) -> Path | None:
    """Sintetizza e salva un OpenAPI dagli endpoint ricostruiti.

    Da usare quando non si e' trovato un documento vero ma la ricostruzione
    della superficie ha prodotto endpoint. Il file risultante non e' un
    contratto — mancano tipi e schemi — ma dice agli scanner dove agire, ed e'
    piu' preciso di un crawl perche' include path che il crawler non
    raggiunge (quelli visti solo nel JavaScript o negli archivi).
    """
    import json

    emap = result.endpoint_map
    if emap is None or len(emap.endpoints) < min_endpoints:
        return None

    from . import endpoints as _ep
    spec = _ep.synthesize(emap, target_url)
    if not spec.get("paths"):
        return None

    dest_dir.mkdir(parents=True, exist_ok=True)
    path = dest_dir / "synthesized-openapi.json"
    path.write_text(json.dumps(spec, ensure_ascii=False, indent=2),
                    encoding="utf-8")
    result.synthesized_to = path
    return path


# ---------------------------------------------------------------------- #
# Interne
# ---------------------------------------------------------------------- #

def _candidate_bases(base: str) -> list[str]:
    """La base indicata piu' i suoi livelli superiori, dal piu' specifico.

        https://host/api/v1  ->  [https://host/api/v1, https://host/api,
                                  https://host]

    Si fermano a tre per non moltiplicare le richieste: oltre il secondo
    livello di risalita la probabilita' di trovare il documento cala molto piu'
    in fretta di quanto cresca il costo.
    """
    parts = urlsplit(base)
    origin = f"{parts.scheme}://{parts.netloc}"
    segments = [s for s in parts.path.split("/") if s]

    bases = [base.rstrip("/")]
    while segments:
        segments.pop()
        candidate = origin + ("/" + "/".join(segments) if segments else "")
        if candidate not in bases:
            bases.append(candidate)
        if len(bases) >= 3:
            break
    return bases


class _Counter:
    """Contabilita' delle richieste, condivisa fra i thread di sondaggio.

    Con un lock e non affidandosi al GIL: `d[k] = d.get(k, 0) + 1` non e'
    atomico e sotto concorrenza perde incrementi. Questi numeri finiscono nella
    diagnosi mostrata all'utente quando la ricerca non trova nulla, e un
    conteggio sbagliato manderebbe fuori strada proprio quando serve orientarsi.
    """

    def __init__(self, result: "DiscoveryResult") -> None:
        import threading
        self._lock = threading.Lock()
        self._result = result
        self.value = 0

    def tick(self) -> None:
        with self._lock:
            self.value += 1

    def record_status(self, code: int) -> None:
        with self._lock:
            self._result.reachable = True
            self._result.status_counts[code] = (
                self._result.status_counts.get(code, 0) + 1)

    def record_error(self, message: str) -> None:
        with self._lock:
            self._result.network_errors += 1
            if len(self._result.errors) < 5:
                self._result.errors.append(message)


def _fetch(session: Any, url: str, timeout: float, counter: _Counter,
           result: DiscoveryResult, method: str = "GET") -> Any | None:
    import requests
    counter.tick()
    try:
        response = session.request(
            method, url, timeout=timeout, allow_redirects=True,
            # `stream` per poter interrompere prima di scaricare un file enorme.
            stream=True,
        )
    except requests.RequestException as exc:
        # Un path che non risponde e' la norma durante una discovery: si
        # registrano solo i primi errori, per non riempire il report.
        counter.record_error(f"{type(exc).__name__} su {url}")
        return None

    # Le statistiche servono a distinguere «non c'e' niente» da «e' tutto
    # protetto» da «non ho raggiunto l'host»: tre esiti con tre rimedi diversi.
    counter.record_status(response.status_code)
    return response


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
