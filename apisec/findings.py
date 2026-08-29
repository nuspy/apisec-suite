"""Modello di finding unificato.

Tre engine con tre vocabolari diversi devono finire nella stessa tabella,
altrimenti il report combinato e' solo tre report incollati. Qui vive la forma
comune e le regole di conversione verso di essa.

Le decisioni non ovvie, spiegate una volta sola:

* **La severita' e' derivata dal CVSS quando c'e', dichiarata quando non c'e'.**
  vulnapi fornisce un punteggio CVSS 4.0 reale; APISCAN una stringa
  ("High", "Medium"). Tenere due scale separate renderebbe impossibile
  ordinare un report combinato, quindi la stringa viene mappata su un punteggio
  rappresentativo e il campo `cvss_estimated` dice che quel numero e' una
  stima, non una misura.

* **Il path viene normalizzato a template.** Lo stesso difetto su `/users/1` e
  `/users/2` e' un difetto solo. Senza normalizzazione un BOLA testato su venti
  id diventa venti righe di report.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Iterable


class Severity(str, Enum):
    """Scala unica. L'ordinamento e' quello di `RANK`, non quello alfabetico."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return RANK[self]

    @classmethod
    def from_cvss(cls, score: float) -> "Severity":
        """Soglie CVSS 3.1/4.0 standard."""
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        if score > 0.0:
            return cls.LOW
        return cls.INFO

    @classmethod
    def parse(cls, value: Any) -> "Severity":
        """Accetta le stringhe di qualunque engine, comprese quelle sporche."""
        if isinstance(value, cls):
            return value
        text = str(value or "").strip().lower()
        if not text:
            return cls.INFO
        for alias, sev in _SEVERITY_ALIASES.items():
            if text == alias or text.startswith(alias):
                return sev
        return cls.INFO


RANK: dict[Severity, int] = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}

_SEVERITY_ALIASES: dict[str, Severity] = {
    "critical": Severity.CRITICAL, "crit": Severity.CRITICAL,
    "blocker": Severity.CRITICAL, "kritiek": Severity.CRITICAL,
    "high": Severity.HIGH, "hoog": Severity.HIGH, "error": Severity.HIGH,
    "major": Severity.HIGH, "severe": Severity.HIGH,
    "medium": Severity.MEDIUM, "moderate": Severity.MEDIUM,
    "warning": Severity.MEDIUM, "middel": Severity.MEDIUM, "warn": Severity.MEDIUM,
    "low": Severity.LOW, "minor": Severity.LOW, "laag": Severity.LOW,
    "info": Severity.INFO, "informational": Severity.INFO, "note": Severity.INFO,
    "none": Severity.INFO, "ok": Severity.INFO, "pass": Severity.INFO,
}

#: Punteggio rappresentativo per gli engine che dichiarano solo una parola.
#: Volutamente al centro della fascia: non e' una misura, e non deve sembrarlo.
SEVERITY_TO_CVSS: dict[Severity, float] = {
    Severity.CRITICAL: 9.5,
    Severity.HIGH: 8.0,
    Severity.MEDIUM: 5.5,
    Severity.LOW: 2.5,
    Severity.INFO: 0.0,
}

#: Categorie OWASP API Security Top 10 (2023), per le etichette dei report.
OWASP_API_2023: dict[str, str] = {
    "API1:2023": "Broken Object Level Authorization",
    "API2:2023": "Broken Authentication",
    "API3:2023": "Broken Object Property Level Authorization",
    "API4:2023": "Unrestricted Resource Consumption",
    "API5:2023": "Broken Function Level Authorization",
    "API6:2023": "Unrestricted Access to Sensitive Business Flows",
    "API7:2023": "Server Side Request Forgery",
    "API8:2023": "Security Misconfiguration",
    "API9:2023": "Improper Inventory Management",
    "API10:2023": "Unsafe Consumption of APIs",
}

# Segmenti di path che sono valori, non nomi di risorsa. Numeri, UUID, hash,
# date, e stringhe lunghe senza vocali (token). Vengono ridotti a {id} per la
# deduplica.
_RE_NUMERIC = re.compile(r"^\d+$")
_RE_UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_RE_HEXHASH = re.compile(r"^[0-9a-f]{16,}$", re.I)
_RE_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_RE_TEMPLATE = re.compile(r"^[{:<].+[}>]?$")


def normalize_path(path: str) -> str:
    """Riduce un path concreto al suo template.

        /users/42/orders/8ab3f...  ->  /users/{id}/orders/{id}
        /users/{user_id}           ->  /users/{id}

    Serve alla deduplica: engine diversi provano id diversi sullo stesso
    endpoint, e senza questo passaggio ogni id genera una riga.
    """
    if not path:
        return "/"
    path = path.split("?", 1)[0].split("#", 1)[0]
    if not path.startswith("/"):
        path = "/" + path
    out: list[str] = []
    for seg in path.split("/"):
        if not seg:
            continue
        if (_RE_NUMERIC.match(seg) or _RE_UUID.match(seg) or _RE_HEXHASH.match(seg)
                or _RE_DATE.match(seg) or _RE_TEMPLATE.match(seg)):
            out.append("{id}")
        else:
            out.append(seg)
    return "/" + "/".join(out) if out else "/"


@dataclass
class Evidence:
    """Prova a supporto del finding. Vuota e' lecito: non tutti gli engine la danno."""

    request_method: str = ""
    request_url: str = ""
    request_headers: dict[str, str] = field(default_factory=dict)
    request_body: str = ""
    response_status: int | None = None
    response_headers: dict[str, str] = field(default_factory=dict)
    response_body: str = ""

    def is_empty(self) -> bool:
        return not (self.request_url or self.response_status or self.response_body)

    def summary(self, max_body: int = 400) -> str:
        """Riassunto testuale, per i prompt LLM e i report a schermo."""
        parts: list[str] = []
        if self.request_method or self.request_url:
            parts.append(f"{self.request_method} {self.request_url}".strip())
        if self.request_body:
            parts.append(f"request body: {self.request_body[:max_body]}")
        if self.response_status is not None:
            parts.append(f"HTTP {self.response_status}")
        if self.response_body:
            parts.append(f"response: {self.response_body[:max_body]}")
        return "\n".join(parts)


@dataclass
class Finding:
    """Un difetto, come lo vede la suite dopo la normalizzazione."""

    engine: str
    rule_id: str
    title: str
    severity: Severity = Severity.INFO
    cvss: float = 0.0
    #: True quando `cvss` e' derivato dalla severita' dichiarata, non misurato.
    cvss_estimated: bool = True
    cwe: list[str] = field(default_factory=list)
    owasp: list[str] = field(default_factory=list)
    method: str = ""
    path: str = ""
    url: str = ""
    description: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    evidence: Evidence = field(default_factory=Evidence)
    #: Payload nativo dell'engine, conservato per diagnosi e per l'LLM.
    raw: dict[str, Any] = field(default_factory=dict)
    #: Popolati dal merge: engine che hanno confermato lo stesso difetto.
    corroborated_by: list[str] = field(default_factory=list)
    #: Popolati dall'analista LLM, quando gira.
    llm_verdict: str = ""
    llm_rationale: str = ""

    def __post_init__(self) -> None:
        self.severity = Severity.parse(self.severity)
        self.method = (self.method or "").upper()
        # Un CVSS reale ha la precedenza sulla severita' dichiarata: e' una
        # misura contro un'etichetta.
        if self.cvss and not self.cvss_estimated:
            self.severity = Severity.from_cvss(self.cvss)
        elif not self.cvss:
            self.cvss = SEVERITY_TO_CVSS[self.severity]
            self.cvss_estimated = True

    @property
    def normalized_path(self) -> str:
        return normalize_path(self.path or self.url)

    @property
    def owasp_label(self) -> str:
        if not self.owasp:
            return ""
        first = self.owasp[0]
        name = OWASP_API_2023.get(first, "")
        return f"{first} {name}".strip()

    def dedup_key(self) -> str:
        """Chiave di identita' cross-engine.

        Non include l'engine ne' il rule_id: lo scopo e' proprio far collidere
        lo stesso difetto trovato da tool diversi con nomi diversi.

        Usa la *classe di difetto* e non la categoria OWASP. Su dati reali la
        categoria e' troppo grossolana: HSTS assente, CSP assente, CORS
        wildcard, X-Frame-Options assente e nosniff assente sono tutti
        "API8:2023" sullo stesso endpoint, e una chiave basata sulla categoria
        li fonderebbe in un unico finding perdendo cinque difetti veri.
        """
        return "|".join((defect_class(self), self.method, self.normalized_path))

    def fingerprint(self) -> str:
        """Identita' stabile del singolo finding, engine incluso."""
        base = "|".join((self.engine, self.rule_id, self.method,
                         self.normalized_path, self.title))
        return hashlib.sha256(base.encode("utf-8", "replace")).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        data["normalized_path"] = self.normalized_path
        data["fingerprint"] = self.fingerprint()
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        data = dict(data)
        data.pop("normalized_path", None)
        data.pop("fingerprint", None)
        ev = data.pop("evidence", None) or {}
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        clean = {k: v for k, v in data.items() if k in known}
        clean["evidence"] = Evidence(**ev) if isinstance(ev, dict) else Evidence()
        return cls(**clean)


_RE_NON_WORD = re.compile(r"[^a-z0-9]+")


def _title_slug(title: str) -> str:
    """Slug del titolo, usato come categoria di ripiego nella dedup key."""
    return _RE_NON_WORD.sub("-", (title or "").lower()).strip("-")[:60]


# ---------------------------------------------------------------------- #
# Classi di difetto
# ---------------------------------------------------------------------- #
#
# Ogni voce e' `(classe, termini)`: la classe viene assegnata se TUTTI i
# termini compaiono nel testo identificativo del finding (rule_id + titolo +
# descrizione). L'ordine conta, vince la prima che corrisponde, quindi le
# regole piu' specifiche stanno prima delle piu' generali.
#
# Questa tabella e' il punto in cui si dichiara che due engine stanno parlando
# dello stesso difetto. E' esplicita e verificabile di proposito: dedurlo da
# una somiglianza di testo produrrebbe fusioni casuali, e fondere due difetti
# distinti costa piu' di quanto costi lasciarli separati.

_DEFECT_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    # --- JWT: difetti distinti, non una sola famiglia ---
    ("jwt-alg-none", ("jwt", "alg_none")),
    ("jwt-alg-none", ("alg", "none")),
    ("jwt-blank-secret", ("blank_secret",)),
    ("jwt-blank-secret", ("blank", "secret")),
    ("jwt-weak-secret", ("weak_secret",)),
    ("jwt-weak-secret", ("weak", "secret")),
    ("jwt-not-verified", ("not_verified",)),
    ("jwt-null-signature", ("null_signature",)),
    ("jwt-null-signature", ("null", "signature")),
    ("jwt-kid-injection", ("kid_injection",)),
    ("jwt-kid-injection", ("kid", "injection")),

    # --- autenticazione ---
    ("auth-bypass-method-override", ("method_override", "authentication")),
    ("auth-bypass", ("authentication_bypass",)),
    ("auth-bypass", ("authentication", "bypass")),
    ("accept-unauthenticated", ("accept_unauthenticated",)),
    ("accept-unauthenticated", ("unauthenticated",)),

    # --- header di sicurezza: uno per difetto ---
    ("hsts-missing", ("hsts",)),
    ("hsts-missing", ("strict-transport-security",)),
    ("csp-frame-ancestors-missing", ("frame_ancestors",)),
    ("csp-frame-ancestors-missing", ("frame-ancestors",)),
    ("csp-missing", ("csp",)),
    ("csp-missing", ("content-security-policy",)),
    # CORS. I due engine lo nominano in modo molto diverso: vulnapi scrive
    # "CORS Allow-Origin Header is set to wildcard (*)", APISCAN abbrevia in
    # "ACAO=*, ACAC=true, Wildcard with credentials". Senza queste varianti lo
    # stesso difetto non collide mai.
    ("cors-wildcard", ("cors", "wildcard")),
    ("cors-wildcard", ("acao=*",)),
    ("cors-wildcard", ("wildcard", "credentials")),
    ("cors-wildcard", ("access-control-allow-origin", "wildcard")),
    ("cors-missing", ("cors",)),
    ("cors-missing", ("acao",)),
    ("frame-options-missing", ("frame_options",)),
    ("frame-options-missing", ("x-frame-options",)),
    ("frame-options-missing", ("clickjack",)),
    ("content-type-options-missing", ("content_options",)),
    ("content-type-options-missing", ("x-content-type-options",)),
    ("content-type-options-missing", ("nosniff",)),

    # --- cookie ---
    ("cookie-not-http-only", ("cookie", "http_only")),
    ("cookie-not-http-only", ("cookie", "httponly")),
    ("cookie-not-secure", ("cookie", "not_secure")),
    ("cookie-same-site-none", ("cookie", "same_site_none")),
    ("cookie-without-same-site", ("cookie", "without_same_site")),
    ("cookie-without-expires", ("cookie", "without_expires")),
    ("cookie-without-expires", ("cookie", "expires")),

    # --- metodi HTTP ---
    ("http-trace", ("trace",)),
    ("http-track", ("track",)),
    ("method-override", ("method_override",)),
    ("method-override", ("method override",)),

    # --- GraphQL ---
    ("graphql-introspection", ("introspection",)),

    # --- ricognizione ---
    ("fingerprint", ("fingerprint",)),
    ("server-signature", ("server_signature",)),
    ("openapi-exposed", ("discoverable_openapi",)),
    ("openapi-exposed", ("schema", "exposed")),
    ("openapi-exposed", ("specification exposed",)),
    ("graphql-exposed", ("discoverable_graphql",)),
    ("exposed-files", ("exposed_files",)),
    ("well-known", ("well-known",)),
    ("healthcheck", ("healthcheck",)),

    # --- autorizzazione ---
    ("bola", ("bola",)),
    ("bola", ("object level authorization",)),
    ("bola", ("idor",)),
    ("bfla", ("bfla",)),
    ("bfla", ("function level authorization",)),
    ("bfla", ("adminaccess",)),
    ("mass-assignment", ("mass assignment",)),
    ("mass-assignment", ("property level",)),
    ("privilege-escalation", ("escalation",)),

    # --- iniezioni ---
    ("injection-sql", ("sql",)),
    ("injection-nosql", ("nosql",)),
    ("injection-xss", ("xss",)),
    ("injection-xss", ("cross-site scripting",)),
    ("injection-path", ("path traversal",)),
    ("injection-path", ("directory traversal",)),
    ("injection-lfi", ("lfi",)),
    ("injection-ssti", ("ssti",)),
    ("injection-ssti", ("template injection",)),
    ("injection-xxe", ("xxe",)),
    ("injection-ldap", ("ldap",)),
    ("injection-rce", ("remote code execution",)),
    ("injection-command", ("command injection",)),

    # --- altri rischi OWASP ---
    ("ssrf", ("ssrf",)),
    ("ssrf", ("server side request forgery",)),
    ("resource-consumption", ("resource consumption",)),
    ("resource-consumption", ("rate limit",)),
    ("business-flow", ("business flow",)),
    ("inventory", ("inventory",)),
    ("unsafe-consumption", ("unsafe consumption",)),
    ("data-exposure", ("data exposure",)),
    ("data-exposure", ("sensitive data",)),
)


def defect_class(finding: "Finding") -> str:
    """Classe del difetto, per far collidere le segnalazioni equivalenti.

    Chi non corrisponde a nessuna regola ricade sullo slug del titolo: una
    classe per titolo non fonde mai nulla di cross-engine, che e' il
    comportamento prudente giusto quando non si sa.
    """
    haystack = " ".join((
        finding.rule_id or "",
        finding.title or "",
        (finding.raw or {}).get("risk_key", "") if isinstance(finding.raw, dict) else "",
    )).lower()

    for name, terms in _DEFECT_RULES:
        if all(term in haystack for term in terms):
            return name

    return f"other:{_title_slug(finding.title)}"


def sort_findings(findings: Iterable[Finding]) -> list[Finding]:
    """Ordinamento canonico dei report: peggio prima, poi per endpoint."""
    return sorted(
        findings,
        key=lambda f: (-f.severity.rank, -f.cvss, f.normalized_path, f.title),
    )


def count_by_severity(findings: Iterable[Finding]) -> dict[str, int]:
    counts = {s.value: 0 for s in Severity}
    for f in findings:
        counts[f.severity.value] += 1
    return counts
