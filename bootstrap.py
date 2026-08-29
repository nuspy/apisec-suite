#!/usr/bin/env python3
"""Prepara la suite: scarica gli engine e verifica le dipendenze.

    python bootstrap.py --all          scarica tutto
    python bootstrap.py --vulnapi      solo il binario Go
    python bootstrap.py --apiscan      solo il clone di APISCAN
    python bootstrap.py --check        non scarica nulla, dice solo cosa manca

Gli engine non sono ridistribuiti dentro questo repository: vengono presi dalle
loro fonti ufficiali. E' una scelta di igiene sulle licenze (APISCAN e' AGPL,
va preso e mantenuto come progetto suo) e di manutenzione (gli aggiornamenti
arrivano da chi li sviluppa).
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VENDOR = ROOT / "vendor"
BIN = ROOT / "bin"

APISCAN_REPO = "https://github.com/perrym/apiscanner.git"
VULNAPI_VERSION = "v0.9.0"


def _say(message: str, quiet: bool = False) -> None:
    if not quiet:
        print(message)


def install_vulnapi(quiet: bool = False, version: str = VULNAPI_VERSION) -> bool:
    sys.path.insert(0, str(ROOT))
    from apisec.engines.vulnapi_engine import VulnapiEngine, download_binary

    existing = VulnapiEngine().binary()
    if existing:
        _say(f"[=] vulnapi gia' presente: {existing}", quiet)
        return True

    _say(f"[*] Scarico vulnapi {version}...", quiet)
    try:
        path = download_binary(BIN, version=version)
    except Exception as exc:
        _say(f"[!] Download fallito: {exc}", quiet)
        _say(f"    Scaricare a mano da "
             f"https://github.com/cerberauth/vulnapi/releases/tag/{version} "
             f"ed estrarre in {BIN}", quiet)
        return False
    _say(f"[+] vulnapi installato: {path}", quiet)
    return True


def install_apiscan(quiet: bool = False) -> bool:
    dest = VENDOR / "apiscanner"
    if (dest / "apiscan.py").is_file():
        _say(f"[=] APISCAN gia' presente: {dest}", quiet)
        return True
    if shutil.which("git") is None:
        _say("[!] git non trovato: clonare a mano "
             f"{APISCAN_REPO} in {dest}", quiet)
        return False

    _say(f"[*] Clono APISCAN in {dest}...", quiet)
    VENDOR.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", APISCAN_REPO, str(dest)],
            check=True, capture_output=quiet,
        )
    except subprocess.CalledProcessError as exc:
        _say(f"[!] Clone fallito: {exc}", quiet)
        return False
    _say(f"[+] APISCAN clonato. Le sue dipendenze sono in "
         f"{dest / 'requirements.txt'}", quiet)
    return True


def check_python_deps(quiet: bool = False) -> bool:
    """Verifica le dipendenze runtime, distinguendo quelle indispensabili."""
    required = {"requests": "requests"}
    optional = {
        "yaml": "PyYAML (OpenAPI in formato YAML)",
        "tkinter": "Tkinter (interfaccia grafica)",
    }

    ok = True
    for module, label in required.items():
        try:
            __import__(module)
            _say(f"[=] {label}", quiet)
        except ImportError:
            _say(f"[!] MANCA {label} — pip install {module}", quiet)
            ok = False

    for module, label in optional.items():
        try:
            __import__(module)
            _say(f"[=] {label}", quiet)
        except ImportError:
            _say(f"[~] opzionale assente: {label}", quiet)
    return ok


def check_llmswitch(quiet: bool = False) -> bool:
    sys.path.insert(0, str(ROOT))
    from apisec.llm import (
        available, list_providers, list_registries, unavailable_reason,
    )

    if not available():
        _say(f"[~] llmswitch non disponibile: {unavailable_reason()}", quiet)
        _say("    L'analisi LLM restera' disattivata; le scansioni funzionano "
             "comunque.", quiet)
        return False

    # llmswitch tiene un registry per applicazione: guardare solo quello di
    # default direbbe "0 provider" anche a chi ne ha gia' configurati per un
    # altro progetto, che sono invece riutilizzabili da qui.
    registries = list_registries()
    if not registries:
        _say("[~] llmswitch disponibile, ma nessun registry trovato.", quiet)
        _say("    Configura un provider con llmswitch, poi selezionalo nel "
             "tab LLM.", quiet)
        return True

    total = sum(count for _, count in registries)
    _say(f"[=] llmswitch disponibile — {len(registries)} registry, "
         f"{total} provider in tutto", quiet)
    for name, count in registries:
        marker = " " if count else "~"
        _say(f"      [{marker}] {name:20} {count} provider", quiet)
        if count:
            for prov in list_providers(name)[:8]:
                where = "locale" if prov.local else "remoto"
                _say(f"            {prov.pid or prov.type:14} {prov.label} "
                     f"({where})", quiet)
    if total == 0:
        _say("    Nessun provider configurato: l'analisi LLM restera' "
             "disattivata.", quiet)
    return True


def status(quiet: bool = False) -> int:
    sys.path.insert(0, str(ROOT))
    from apisec.engines import engine_status

    _say("=== Engine ===", quiet)
    all_ok = True
    for name, availability in engine_status().items():
        mark = "=" if availability.ok else "!"
        _say(f"[{mark}] {name}: {availability.detail}", quiet)
        if not availability.ok:
            all_ok = False
            if availability.hint:
                _say(f"    {availability.hint}", quiet)

    _say("\n=== Dipendenze Python ===", quiet)
    deps_ok = check_python_deps(quiet)

    _say("\n=== LLM ===", quiet)
    check_llmswitch(quiet)

    return 0 if (all_ok and deps_ok) else 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--all", action="store_true",
                        help="installa tutti gli engine")
    parser.add_argument("--vulnapi", action="store_true",
                        help="scarica il binario vulnapi")
    parser.add_argument("--apiscan", action="store_true",
                        help="clona APISCAN in vendor/")
    parser.add_argument("--check", action="store_true",
                        help="verifica lo stato senza installare nulla")
    parser.add_argument("--vulnapi-version", default=VULNAPI_VERSION,
                        help=f"versione di vulnapi (default {VULNAPI_VERSION})")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    if args.check or not (args.all or args.vulnapi or args.apiscan):
        return status(args.quiet)

    ok = True
    if args.all or args.vulnapi:
        ok &= install_vulnapi(args.quiet, args.vulnapi_version)
    if args.all or args.apiscan:
        ok &= install_apiscan(args.quiet)

    if not args.quiet:
        print()
        status(args.quiet)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
