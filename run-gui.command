#!/usr/bin/env bash
#
# apisec-suite - avvio con doppio click dal Finder (macOS).
#
# L'estensione .command dice al Finder di eseguirlo in Terminale. Serve il bit
# di esecuzione, che install.sh imposta; se il file arriva da un download,
# macOS potrebbe metterlo in quarantena e chiedere conferma al primo avvio.
#
# Il doppio click parte dalla home, non dalla cartella del file: da qui il
# `cd` esplicito, senza il quale nulla verrebbe trovato.
#
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

VENV_PY="$ROOT/.venv/bin/python"

printf '\n  apisec-suite\n'
printf '  \033[2m%s\033[0m\n\n' "$ROOT"

# La finestra del Terminale si chiude appena lo script finisce: senza una pausa
# un messaggio d'errore sparirebbe prima di poter essere letto.
pausa_e_esci() {
    printf '\n  Premi Invio per chiudere questa finestra.'
    read -r _ || true
    exit "${1:-0}"
}

if [ ! -x "$VENV_PY" ]; then
    printf '  \033[31mAmbiente non installato.\033[0m\n\n'
    printf '  Apri il Terminale in questa cartella ed esegui:\n'
    printf '      \033[36m./install.sh\033[0m\n'
    pausa_e_esci 1
fi

if ! "$VENV_PY" -c 'import tkinter' 2>/dev/null; then
    printf '  \033[31mTkinter non disponibile: la GUI non puo'"'"' partire.\033[0m\n\n'
    printf '  Il Python di Homebrew non include Tk per impostazione predefinita:\n'
    printf '      \033[36mbrew install python-tk\033[0m\n\n'
    printf '  In alternativa installa Python da python.org, che lo include, e\n'
    printf '  ricrea l'"'"'ambiente con:  \033[36m./install.sh --force\033[0m\n'
    pausa_e_esci 1
fi

printf '  \033[36mAvvio dell'"'"'interfaccia...\033[0m\n'
printf '  \033[2m(questa finestra puo'"'"' restare aperta: chiudendola si chiude l'"'"'app)\033[0m\n\n'

"$VENV_PY" "$ROOT/apisec_gui.py"
STATUS=$?

if [ $STATUS -ne 0 ]; then
    printf '\n  \033[31mL'"'"'applicazione e'"'"' terminata con codice %d.\033[0m\n' "$STATUS"
    pausa_e_esci "$STATUS"
fi
exit 0
