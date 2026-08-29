#!/usr/bin/env bash
#
# Avvia l'interfaccia grafica di apisec-suite (Linux e macOS).
#
# Usa il Python del venv creato da install.sh: invocare direttamente
# l'interprete equivale ad attivare l'ambiente, senza modificare la shell.
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_PY="$ROOT/.venv/bin/python"

if [ ! -x "$VENV_PY" ]; then
    printf '\n  \033[31mAmbiente non installato.\033[0m\n'
    printf '  Esegui prima:  ./install.sh\n\n'
    exit 1
fi

# Senza Tkinter non c'e' finestra: meglio un messaggio chiaro che un traceback.
if ! "$VENV_PY" -c 'import tkinter' 2>/dev/null; then
    printf '\n  \033[31mTkinter non e'"'"' disponibile: la GUI non puo'"'"' partire.\033[0m\n'
    if [ "$(uname -s)" = "Darwin" ]; then
        printf '  \033[33mbrew install python-tk\033[0m\n'
        printf '  oppure usa il Python di python.org, che include Tk\n'
    else
        printf '  \033[33mDebian/Ubuntu:  sudo apt install python3-tk\033[0m\n'
        printf '  \033[33mFedora:         sudo dnf install python3-tkinter\033[0m\n'
        printf '  \033[33mArch:           sudo pacman -S tk\033[0m\n'
    fi
    printf '  In alternativa usa la riga di comando:  ./run-scan.sh --help\n\n'
    exit 1
fi

# Su Linux senza sessione grafica Tk fallisce con un errore poco leggibile.
if [ "$(uname -s)" != "Darwin" ] && [ -z "${DISPLAY:-}" ] && [ -z "${WAYLAND_DISPLAY:-}" ]; then
    printf '\n  \033[31mNessuna sessione grafica (DISPLAY e WAYLAND_DISPLAY non impostate).\033[0m\n'
    printf '  Su una macchina remota serve X11 forwarding:  ssh -X ...\n'
    printf '  Altrimenti usa la riga di comando:  ./run-scan.sh --help\n\n'
    exit 1
fi

printf '  \033[36mAvvio dell'"'"'interfaccia...\033[0m\n'
exec "$VENV_PY" "$ROOT/apisec_gui.py" "$@"
