#!/usr/bin/env python3
"""apisec-suite — avvio dell'interfaccia grafica.

    python apisec_gui.py

E' la GUI di APISCAN estesa: i tab Target, Authentication, Form Login, OWASP
Scans e Advanced sono quelli originali e continuano a comandare APISCAN; i tab
Engine, LLM e CI/CD sono della suite. La stessa configurazione di
autenticazione alimenta tutti gli engine.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))


def main() -> int:
    try:
        from apisec.gui.app import main as gui_main
    except ImportError as exc:
        print(f"[!] Avvio impossibile: {exc}", file=sys.stderr)
        print("    Provare con: python bootstrap.py --all", file=sys.stderr)
        return 1
    gui_main()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
