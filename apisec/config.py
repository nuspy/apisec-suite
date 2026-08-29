"""Configurazione condivisa fra gli engine.

Il punto della suite e' che si configura *una volta* il bersaglio e le
credenziali, e ogni engine se ne serve tradotte nel proprio dialetto. Questo
modulo tiene i dati; la traduzione vive in `apisec.engines`.

La configurazione dell'autenticazione e' il pezzo di maggior valore
dell'integrazione: APISCAN ha otto flow (token, OAuth2 client credentials,
basic, digest, NTLM, OAuth2 authorization code, mTLS, form-login con
auto-detect) mentre vulnapi accetta principalmente header e security scheme.
Compilarli due volte sarebbe la parte piu' fastidiosa del lavoro, quindi si
compilano qui.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field, fields
from datetime import datetime
from pathlib import Path
from typing import Any


class ConfigError(ValueError):
    """Configurazione non utilizzabile: manca qualcosa di obbligatorio."""


@dataclass
class AuthConfig:
    """Credenziali, in forma neutra rispetto all'engine."""

    #: none | token | client | basic | digest | ntlm | auth | form
    flow: str = "none"
    token: str = ""
    basic_auth: str = ""          # "user:password"
    ntlm: str = ""                # "DOMAIN\\user:password"
    api_key: str = ""
    api_key_header: str = "X-API-Key"
    # OAuth2
    client_id: str = ""
    client_secret: str = ""
    token_url: str = ""
    auth_url: str = ""
    redirect_uri: str = ""
    scope: str = ""
    # mTLS
    client_cert: str = ""
    client_key: str = ""
    cert_password: str = ""
    # Form login (auto-detect di APISCAN)
    login_url: str = ""
    login_username: str = ""
    login_password: str = ""
    token_path: str = ""
    #: Header aggiuntivi applicati da ogni engine che li supporta.
    extra_headers: dict[str, str] = field(default_factory=dict)
    #: Token per ruolo, per i test BFLA di APISCAN: {"admin": "ey..."}.
    role_tokens: dict[str, str] = field(default_factory=dict)

    def bearer(self) -> str:
        """Il token da mandare come Authorization: Bearer, se ce n'e' uno."""
        return self.token.strip()

    def as_headers(self) -> dict[str, str]:
        """Le credenziali riducibili a header HTTP.

        vulnapi non ha i flow di APISCAN, ma accetta `-H`: tutto cio' che si
        puo' esprimere come header viene passato di li'. Quello che non si puo'
        (OAuth2 con scambio, form-login) resta appannaggio di APISCAN, e
        l'engine lo dichiara nelle proprie `limitations`.
        """
        headers = dict(self.extra_headers)
        if self.token.strip():
            headers["Authorization"] = f"Bearer {self.token.strip()}"
        if self.api_key.strip():
            headers[self.api_key_header or "X-API-Key"] = self.api_key.strip()
        return headers


@dataclass
class LLMSettings:
    """Quale provider LLM usare, e per cosa.

    `consumer` e' il nome con cui questa applicazione si presenta al registry di
    llmswitch: e' li' che l'utente decide quale provider serve quale uso, senza
    che la suite debba conoscere chiavi o endpoint.
    """

    enabled: bool = False
    #: Quale *file* di registry aprire. llmswitch tiene un registry per
    #: applicazione (`%LOCALAPPDATA%/<app>/llm_providers.json`), quindi usare
    #: qui il nome della suite creerebbe un registry vuoto ignorando i provider
    #: che l'utente ha gia' configurato altrove. Il default punta al registry
    #: condiviso; la GUI elenca quelli esistenti.
    registry_app: str = "llmswitch"
    #: A quale *uso* e' assegnato il provider dentro quel registry. E' una cosa
    #: diversa dal file: un registry mappa piu' consumer ("chat", "embed", ...)
    #: su provider diversi.
    consumer: str = "chat"
    #: Provider id esplicito; vuoto = quello assegnato al consumer nel registry.
    provider_id: str = ""
    model: str = ""
    temperature: float = 0.1
    max_tokens: int = 2048
    timeout_s: float = 180.0
    #: Se False, un provider locale non carica un modello di sua iniziativa:
    #: usa quello gia' in VRAM o niente. La decisione di occupare la GPU e'
    #: dell'utente, non di uno scanner che gira in background.
    may_load_model: bool = False
    #: Passa la configurazione LLM anche ad APISCAN (--api11), via env.
    drive_apiscan: bool = True
    #: Fai girare l'analista della suite sui finding uniti di tutti gli engine.
    analyze_findings: bool = True


@dataclass
class ScanConfig:
    """Tutto cio' che serve a lanciare una scansione multi-engine."""

    target_url: str = ""
    openapi: str = ""
    output_dir: Path = field(default_factory=lambda: Path.cwd() / "apisec_out")
    engines: list[str] = field(default_factory=lambda: ["vulnapi", "apiscan"])
    auth: AuthConfig = field(default_factory=AuthConfig)
    llm: LLMSettings = field(default_factory=LLMSettings)

    # --- scoperta del contratto ---
    #: Cerca il documento OpenAPI sul bersaglio quando non ne viene fornito uno.
    #: Sonda i path convenzionali e legge le pagine Swagger-UI/ReDoc.
    auto_discover: bool = False
    #: Percorsi aggiuntivi da sondare, oltre a quelli convenzionali.
    discover_extra_paths: list[str] = field(default_factory=list)
    #: Se la ricerca non trova nulla, lascia che APISCAN costruisca un
    #: contratto crawlando gli endpoint. E' piu' lento e meno accurato di un
    #: documento vero, ma e' meglio di non scansionare affatto.
    crawl_fallback: bool = True

    # --- comuni a piu' engine ---
    threads: int = 16
    timeout: float = 5.0
    proxy: str = ""
    insecure: bool = False
    debug: bool = False

    # --- specifici APISCAN, esposti perche' la GUI li ha gia' ---
    apiscan_checks: list[str] = field(default_factory=list)   # ["api1", ...]
    apiscan_extra_args: list[str] = field(default_factory=list)
    apiscan_env: dict[str, str] = field(default_factory=dict)
    crawl: bool = False
    #: Riga di comando completa per APISCAN, che sostituisce quella costruita
    #: dall'engine. Serve alla GUI: `apiscan_gui._build_args()` sa gia'
    #: tradurre *tutti* i suoi widget in flag, comprese le opzioni che la
    #: suite non modella. Riusarla evita di dover rincorrere ogni opzione che
    #: APISCAN aggiunge, al prezzo di una lista opaca — accettabile perche'
    #: chi la produce e' l'unico a doverla capire.
    apiscan_argv_override: list[str] = field(default_factory=list)

    # --- specifici vulnapi ---
    vulnapi_scans: list[str] = field(default_factory=list)     # --scans
    vulnapi_exclude: list[str] = field(default_factory=list)   # --exclude-scans
    vulnapi_mode: str = "openapi"                              # openapi | curl
    vulnapi_extra_args: list[str] = field(default_factory=list)

    #: Identificativo della run, usato per i nomi dei file di output.
    run_id: str = ""

    def __post_init__(self) -> None:
        # Assoluta, non relativa: gli engine girano con la cwd sulla cartella
        # della run, e un percorso relativo verrebbe risolto una seconda volta
        # rispetto a se stesso, annidando le cartelle.
        self.output_dir = Path(self.output_dir).expanduser().resolve()
        if not self.run_id:
            self.run_id = datetime.now().strftime("%Y%m%d-%H%M%S")
        self._absolutize_paths()

    def _absolutize_paths(self) -> None:
        """Rende assoluti i percorsi dei file passati agli engine.

        Gli engine girano con la working directory sulla cartella della run,
        non su quella da cui e' partito il comando: un `--swagger
        tests/openapi.json` relativo verrebbe cercato nel posto sbagliato e
        l'engine fallirebbe con "file non trovato". Si risolve qui, una volta,
        finche' la cwd e' ancora quella dell'utente.
        """
        for name in ("openapi",):
            value = getattr(self, name, "")
            setattr(self, name, _absolute_if_file(value))
        for name in ("client_cert", "client_key"):
            value = getattr(self.auth, name, "")
            setattr(self.auth, name, _absolute_if_file(value))

    # ------------------------------------------------------------------ #

    def validate(self) -> list[str]:
        """Errori bloccanti. Lista vuota = configurazione utilizzabile."""
        errors: list[str] = []
        if not self.target_url.strip():
            errors.append("target_url e' obbligatorio")
        elif not self.target_url.strip().lower().startswith(("http://", "https://")):
            errors.append("target_url deve iniziare con http:// o https://")
        if not self.engines:
            errors.append("nessun engine selezionato")
        if ("vulnapi" in self.engines and self.vulnapi_mode == "openapi"
                and not self.openapi and not self.auto_discover):
            errors.append(
                "vulnapi in modalita' openapi richiede un file OpenAPI: "
                "fornirlo, oppure attivare la ricerca automatica"
            )
        if self.openapi and not Path(self.openapi).exists():
            # Una URL remota e' lecita: vulnapi e APISCAN la scaricano loro.
            if not self.openapi.lower().startswith(("http://", "https://")):
                errors.append(f"file OpenAPI non trovato: {self.openapi}")
        return errors

    def require_valid(self) -> None:
        errors = self.validate()
        if errors:
            raise ConfigError("; ".join(errors))

    def warnings(self) -> list[str]:
        """Configurazioni lecite ma che non fanno quello che sembra.

        Non bloccano la scansione: la avviano dicendo cosa succedera' davvero.
        """
        notes: list[str] = []

        # In APISCAN `--api11` non si somma alle altre categorie, le
        # SOSTITUISCE: `selected_apis = [11] if args.api11 else [...]`.
        # Selezionarlo insieme ad API1-API10 fa girare la sola analisi AI, e
        # senza questo avviso l'utente crede di aver eseguito tutto.
        checks = set(self.apiscan_checks)
        if "api11" in checks and checks - {"api11"}:
            others = ", ".join(sorted(checks - {"api11"}))
            notes.append(
                f"APISCAN: API11 (analisi AI) esclude le altre categorie. "
                f"Verranno saltate: {others}. Per eseguirle tutte, lancia due "
                f"scansioni separate."
            )

        if self.llm.enabled and self.llm.drive_apiscan and "api11" not in checks:
            notes.append(
                "LLM attivo ma API11 non selezionato: APISCAN ricevera' la "
                "configurazione del provider senza usarla. L'analisi della "
                "suite sui finding uniti gira comunque."
            )

        if self.insecure:
            notes.append(
                "Verifica dei certificati TLS disattivata (--insecure): il "
                "traffico e' esposto a intercettazione."
            )

        if "vulnapi" in self.engines and self.vulnapi_mode == "curl":
            notes.append(
                "VulnAPI in modalita' curl esamina solo l'URL indicato, non "
                "gli endpoint dell'OpenAPI: la copertura sara' molto ridotta."
            )

        return notes

    def run_dir(self) -> Path:
        """Cartella della run, creata al primo accesso."""
        d = self.output_dir / f"scan_{self.run_id}"
        d.mkdir(parents=True, exist_ok=True)
        return d

    def engine_dir(self, engine: str) -> Path:
        d = self.run_dir() / engine
        d.mkdir(parents=True, exist_ok=True)
        return d

    # ------------------------------------------------------------------ #

    def to_dict(self) -> dict[str, Any]:
        """Serializzazione, con le credenziali oscurate.

        Viene salvata accanto ai report: deve poter finire in un allegato o in
        un artifact di CI senza portarsi dietro i segreti.
        """
        data: dict[str, Any] = {}
        for f in fields(self):
            value = getattr(self, f.name)
            if f.name == "auth":
                data[f.name] = _redact_auth(value)
            elif f.name == "llm":
                data[f.name] = {k: getattr(value, k) for k in vars(value)}
            elif isinstance(value, Path):
                data[f.name] = str(value)
            else:
                data[f.name] = value
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ScanConfig":
        data = dict(data)
        auth = data.pop("auth", None) or {}
        llm = data.pop("llm", None) or {}
        known = {f.name for f in fields(cls)}
        clean = {k: v for k, v in data.items() if k in known}
        cfg = cls(**clean)
        if isinstance(auth, dict):
            akeys = {f.name for f in fields(AuthConfig)}
            cfg.auth = AuthConfig(**{k: v for k, v in auth.items() if k in akeys})
        if isinstance(llm, dict):
            lkeys = {f.name for f in fields(LLMSettings)}
            cfg.llm = LLMSettings(**{k: v for k, v in llm.items() if k in lkeys})
        return cfg


_SECRET_FIELDS = {
    "token", "basic_auth", "ntlm", "api_key", "client_secret",
    "cert_password", "login_password",
}


def _redact_auth(auth: AuthConfig) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for f in fields(auth):
        value = getattr(auth, f.name)
        if f.name in _SECRET_FIELDS and value:
            out[f.name] = "***"
        elif f.name == "role_tokens":
            out[f.name] = {k: "***" for k in value}
        elif f.name == "extra_headers":
            out[f.name] = {
                k: ("***" if k.lower() in ("authorization", "cookie", "x-api-key")
                    else v)
                for k, v in value.items()
            }
        else:
            out[f.name] = value
    return out


def _absolute_if_file(value: str) -> str:
    """Percorso assoluto se punta a un file esistente, altrimenti invariato.

    Le URL e i percorsi inesistenti restano come sono: la prima non e' un
    file, il secondo deve produrre un errore riconoscibile invece di
    trasformarsi in un percorso assoluto altrettanto inesistente.
    """
    text = str(value or "").strip()
    if not text or text.lower().startswith(("http://", "https://")):
        return text
    try:
        path = Path(text)
        return str(path.resolve()) if path.is_file() else text
    except OSError:
        return text


def default_output_dir() -> Path:
    """Cartella di output predefinita, sovrascrivibile via APISEC_OUT."""
    env = os.getenv("APISEC_OUT", "").strip()
    return Path(env) if env else Path.cwd() / "apisec_out"
