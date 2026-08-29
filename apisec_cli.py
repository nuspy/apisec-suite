#!/usr/bin/env python3
"""apisec-suite — interfaccia a riga di comando.

Stessa orchestrazione della GUI, senza schermo: e' quello che gira in CI.

    python apisec_cli.py --url https://api.example.test --openapi openapi.json
    python apisec_cli.py --url ... --engines vulnapi --fail-on medium
    python apisec_cli.py --url ... --llm --llm-provider lmstudio-1

Codici di uscita:
    0  scansione completata, nessun finding sopra la soglia
    1  finding sopra la soglia (`--fail-on`)
    2  configurazione non valida
    3  nessun engine ha potuto girare
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from apisec import AuthConfig, ConfigError, LLMSettings, ScanConfig  # noqa: E402
from apisec.report.merge import gate_failed  # noqa: E402
from apisec.runner import ScanRunner  # noqa: E402

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_CONFIG = 2
EXIT_NO_ENGINE = 3


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="apisec_cli.py",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    target = parser.add_argument_group("bersaglio")
    # Non `required`: `--llm-list` non ha bisogno di un bersaglio. La presenza
    # viene verificata in `main`, dove si sa gia' cosa si sta facendo.
    target.add_argument("--url", default="",
                        help="URL base dell'API da scansionare (obbligatorio, "
                             "tranne con --llm-list)")
    target.add_argument("--openapi", "--swagger", dest="openapi", default="",
                        help="file OpenAPI/Swagger, oppure una sua URL")
    target.add_argument("--crawl", action="store_true",
                        help="lascia che APISCAN scopra gli endpoint da solo")

    engines = parser.add_argument_group("engine")
    engines.add_argument("--engines", default="vulnapi,apiscan",
                         help="engine da eseguire, separati da virgola "
                              "(default: vulnapi,apiscan)")
    engines.add_argument("--vulnapi-mode", choices=("openapi", "curl"),
                         default="openapi",
                         help="vulnapi: dall'OpenAPI o su una sola URL")
    engines.add_argument("--scans", default="",
                         help="vulnapi: solo questi check, separati da virgola")
    engines.add_argument("--exclude-scans", default="",
                         help="vulnapi: escludi questi check")
    engines.add_argument("--checks", default="",
                         help="APISCAN: categorie da eseguire, es. api1,api5 "
                              "(default: tutte)")

    auth = parser.add_argument_group("autenticazione")
    auth.add_argument("--flow", default="none",
                      choices=("none", "token", "client", "basic", "digest",
                               "ntlm", "auth", "form"))
    auth.add_argument("--token", default="", help="Bearer token")
    auth.add_argument("--basic-auth", default="", help="utente:password")
    auth.add_argument("--ntlm", default="", help="DOMINIO\\utente:password")
    auth.add_argument("--apikey", default="")
    auth.add_argument("--apikey-header", default="X-API-Key")
    auth.add_argument("--client-id", default="")
    auth.add_argument("--client-secret", default="")
    auth.add_argument("--token-url", default="")
    auth.add_argument("--auth-url", default="")
    auth.add_argument("--redirect-uri", default="")
    auth.add_argument("--scope", default="")
    auth.add_argument("--client-cert", default="", help="certificato client mTLS")
    auth.add_argument("--client-key", default="")
    auth.add_argument("--cert-password", default="")
    auth.add_argument("--login-url", default="", help="form login: pagina")
    auth.add_argument("--login-username", default="")
    auth.add_argument("--login-password", default="")
    auth.add_argument("--header", action="append", default=[],
                      metavar="NOME:VALORE",
                      help="header aggiuntivo, ripetibile")

    net = parser.add_argument_group("rete")
    net.add_argument("--threads", type=int, default=16)
    net.add_argument("--timeout", type=float, default=5.0)
    net.add_argument("--proxy", default="")
    net.add_argument("--insecure", action="store_true",
                     help="non verificare i certificati TLS (pericoloso)")
    net.add_argument("--engine-timeout", type=float, default=0,
                     help="secondi massimi per engine (0 = default dell'engine)")

    llm = parser.add_argument_group("LLM")
    llm.add_argument("--llm", action="store_true",
                     help="abilita l'analisi LLM dei finding")
    llm.add_argument("--llm-provider", default="",
                     help="id del provider nel registry llmswitch")
    llm.add_argument("--llm-model", default="")
    llm.add_argument("--llm-registry", default="llmswitch",
                     help="quale registry llmswitch aprire (ne esiste uno per "
                          "applicazione); usa --llm-list per vedere quelli "
                          "presenti")
    llm.add_argument("--llm-consumer", default="chat",
                     help="a quale uso e' assegnato il provider dentro il "
                          "registry (default: chat)")
    llm.add_argument("--llm-list", action="store_true",
                     help="elenca registry e provider disponibili, poi esci")
    llm.add_argument("--llm-may-load", action="store_true",
                     help="consenti di caricare un modello locale se la VRAM "
                          "e' libera (default: usa solo cio' che e' gia' in "
                          "memoria)")
    llm.add_argument("--llm-drive-apiscan", action="store_true", default=True,
                     help="passa la configurazione LLM anche ad APISCAN")
    llm.add_argument("--no-llm-drive-apiscan", dest="llm_drive_apiscan",
                     action="store_false")

    out = parser.add_argument_group("output")
    out.add_argument("--output", "-o", default="apisec_out",
                     help="cartella di output (default: apisec_out)")
    out.add_argument("--sarif", default="",
                     help="copia il SARIF anche in questo percorso")
    out.add_argument("--fail-on", default="high",
                     choices=("critical", "high", "medium", "low", "info", "never"),
                     help="severita' minima che fa uscire con codice 1")
    out.add_argument("--quiet", "-q", action="store_true",
                     help="mostra solo il riepilogo finale")
    out.add_argument("--debug", action="store_true")

    return parser


def config_from_args(args: argparse.Namespace) -> ScanConfig:
    headers: dict[str, str] = {}
    for raw in args.header:
        if ":" not in raw:
            raise ConfigError(f"header senza ':' -> {raw}")
        name, value = raw.split(":", 1)
        headers[name.strip()] = value.strip()

    auth = AuthConfig(
        flow=args.flow,
        token=args.token,
        basic_auth=args.basic_auth,
        ntlm=args.ntlm,
        api_key=args.apikey,
        api_key_header=args.apikey_header,
        client_id=args.client_id,
        client_secret=args.client_secret,
        token_url=args.token_url,
        auth_url=args.auth_url,
        redirect_uri=args.redirect_uri,
        scope=args.scope,
        client_cert=args.client_cert,
        client_key=args.client_key,
        cert_password=args.cert_password,
        login_url=args.login_url,
        login_username=args.login_username,
        login_password=args.login_password,
        extra_headers=headers,
    )

    llm = LLMSettings(
        enabled=args.llm,
        registry_app=args.llm_registry,
        consumer=args.llm_consumer,
        provider_id=args.llm_provider,
        model=args.llm_model,
        may_load_model=args.llm_may_load,
        drive_apiscan=args.llm_drive_apiscan,
    )

    return ScanConfig(
        target_url=args.url,
        openapi=args.openapi,
        output_dir=Path(args.output),
        engines=[e.strip() for e in args.engines.split(",") if e.strip()],
        auth=auth,
        llm=llm,
        threads=args.threads,
        timeout=args.timeout,
        proxy=args.proxy,
        insecure=args.insecure,
        debug=args.debug,
        crawl=args.crawl,
        apiscan_checks=[c.strip() for c in args.checks.split(",") if c.strip()],
        vulnapi_mode=args.vulnapi_mode,
        vulnapi_scans=[s.strip() for s in args.scans.split(",") if s.strip()],
        vulnapi_exclude=[s.strip() for s in args.exclude_scans.split(",")
                         if s.strip()],
    )


def print_llm_inventory() -> int:
    """Elenca registry, provider e consumer di llmswitch."""
    from apisec.llm import (
        available, list_consumers, list_providers, list_registries,
        list_types, unavailable_reason,
    )

    if not available():
        print(f"[!] {unavailable_reason()}", file=sys.stderr)
        return EXIT_CONFIG

    registries = list_registries()
    print("=== Registry llmswitch ===")
    if not registries:
        print("  nessuno trovato")
    for name, count in registries:
        print(f"  {name:24} {count} provider")
        for prov in list_providers(name):
            where = "locale" if prov.local else "remoto"
            model = f" · {prov.model}" if prov.model else ""
            print(f"      {prov.pid:16} {prov.label} ({where}, {prov.api})"
                  f"{model}")
        consumers = list_consumers(name)
        if consumers:
            print(f"      consumer: {', '.join(consumers)}")

    # Per marcare cosa e' gia' configurato serve il registry popolato, non
    # quello di default che qui sarebbe quasi sempre vuoto.
    populated = next((name for name, count in registries if count),
                     registries[0][0] if registries else "llmswitch")
    print(f"\n=== Tipi supportati (configurati in «{populated}») ===")
    for spec in list_types(populated):
        mark = "*" if spec.configured else " "
        where = "locale" if spec.local else "remoto"
        print(f"  {mark} {spec.type:14} {spec.label} ({where}, api={spec.api})")
    print("\n  * = ne esiste almeno uno configurato")
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.llm_list:
        return print_llm_inventory()

    if not args.url.strip():
        print("[!] --url e' obbligatorio (tranne con --llm-list)",
              file=sys.stderr)
        return EXIT_CONFIG

    try:
        cfg = config_from_args(args)
        cfg.require_valid()
    except ConfigError as exc:
        print(f"[!] Configurazione non valida: {exc}", file=sys.stderr)
        return EXIT_CONFIG

    def progress(line: str) -> None:
        if not args.quiet or line.startswith(("[+]", "[!]")):
            print(line, flush=True)

    def sink(engine: str, line: str) -> None:
        if not args.quiet:
            print(f"  {engine} | {line}", flush=True)

    runner = ScanRunner(cfg)
    try:
        outcome = runner.run(progress=progress, line_sink=sink)
    except KeyboardInterrupt:
        print("\n[!] Interrotto. Termino gli engine in corso...", file=sys.stderr)
        runner.cancel()
        return EXIT_CONFIG

    print()
    print("=" * 62)
    for line in outcome.summary_lines():
        print(line)
    print("=" * 62)

    if args.sarif:
        import shutil
        destination = Path(args.sarif)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(outcome.artifacts["sarif"], destination)
        print(f"SARIF copiato in {destination}")

    # Nessun engine ha girato: e' un problema di ambiente, non un esito pulito.
    # Restituire 0 qui farebbe passare una pipeline che non ha testato nulla.
    if all(r.skipped or r.error for r in outcome.results):
        print("[!] Nessun engine ha completato l'esecuzione.", file=sys.stderr)
        return EXIT_NO_ENGINE

    if args.fail_on != "never" and gate_failed(outcome.findings, args.fail_on):
        print(f"[!] Trovati finding di severita' >= {args.fail_on}.",
              file=sys.stderr)
        return EXIT_FINDINGS

    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
