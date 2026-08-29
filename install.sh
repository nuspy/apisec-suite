#!/usr/bin/env bash
#
# apisec-suite - installazione per Linux e macOS.
#
# Crea un ambiente virtuale isolato, installa le dipendenze della suite e di
# APISCAN, scarica il binario VulnAPI e clona APISCAN in vendor/.
#
# L'installazione sta tutta nella cartella del progetto: non tocca il Python di
# sistema e si disinstalla cancellando .venv, bin e vendor.
#
#   ./install.sh                        installazione completa
#   ./install.sh --python python3.12    interprete specifico
#   ./install.sh --skip-engines         solo la suite, senza gli engine
#   ./install.sh --force                ricrea il venv da zero
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$ROOT/.venv"
VENV_PY="$VENV_DIR/bin/python"

# Versione minima verificata: sotto la 3.10 alcune annotazioni usate da APISCAN
# non reggono a runtime.
MIN_MAJOR=3
MIN_MINOR=10

PYTHON_HINT=""
SKIP_ENGINES=0
FORCE=0

while [ $# -gt 0 ]; do
    case "$1" in
        --python)        PYTHON_HINT="${2:-}"; shift 2 ;;
        --python=*)      PYTHON_HINT="${1#*=}"; shift ;;
        --skip-engines)  SKIP_ENGINES=1; shift ;;
        --force)         FORCE=1; shift ;;
        -h|--help)       sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "Opzione sconosciuta: $1" >&2; exit 2 ;;
    esac
done

# Colori solo se stdout e' un terminale: in pipeline sporcherebbero i log.
if [ -t 1 ]; then
    C_CYAN=$'\033[36m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'
    C_RED=$'\033[31m';  C_DIM=$'\033[2m';    C_OFF=$'\033[0m'
else
    C_CYAN=""; C_GREEN=""; C_YELLOW=""; C_RED=""; C_DIM=""; C_OFF=""
fi

step() { printf '\n%s==> %s%s\n' "$C_CYAN" "$1" "$C_OFF"; }
ok()   { printf '  %sOK%s  %s\n' "$C_GREEN" "$C_OFF" "$1"; }
warn() { printf '  %s!%s   %s\n' "$C_YELLOW" "$C_OFF" "$1"; }
die()  { printf '  %sX%s   %s\n' "$C_RED" "$C_OFF" "$1" >&2; exit 1; }

case "$(uname -s)" in
    Darwin) OS="macOS" ;;
    Linux)  OS="Linux" ;;
    *)      OS="$(uname -s)" ;;
esac

find_python() {
    local candidates=()
    [ -n "$PYTHON_HINT" ] && candidates+=("$PYTHON_HINT")
    candidates+=(python3.13 python3.12 python3.11 python3.10 python3 python)

    local exe version major minor
    for exe in "${candidates[@]}"; do
        command -v "$exe" >/dev/null 2>&1 || continue
        version="$("$exe" -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null)" || continue
        major="${version%%.*}"
        minor="${version##*.}"
        if [ "$major" -gt "$MIN_MAJOR" ] 2>/dev/null || \
           { [ "$major" -eq "$MIN_MAJOR" ] && [ "$minor" -ge "$MIN_MINOR" ]; } 2>/dev/null; then
            "$exe" -c 'import sys; print(sys.executable)'
            return 0
        fi
    done
    return 1
}

# ---------------------------------------------------------------------------

printf '\n  apisec-suite - installazione (%s)\n' "$OS"
printf '  %s%s%s\n' "$C_DIM" "$ROOT" "$C_OFF"

step "Interprete Python"
SYSTEM_PY="$(find_python)" || die "Nessun Python >= $MIN_MAJOR.$MIN_MINOR trovato.
      Linux:  sudo apt install python3 python3-venv python3-tk
      macOS:  brew install python-tk    (oppure python.org, che include Tk)"
ok "$($SYSTEM_PY --version 2>&1): $SYSTEM_PY"

step "Ambiente virtuale"
if [ -d "$VENV_DIR" ] && [ "$FORCE" -eq 1 ]; then
    warn "Rimuovo il venv esistente (--force)"
    rm -rf "$VENV_DIR"
fi
if [ -x "$VENV_PY" ]; then
    ok "Gia' presente: $VENV_DIR"
else
    # Su Debian/Ubuntu il modulo venv e' in un pacchetto separato e l'errore
    # che ne esce non e' immediato da capire.
    if ! "$SYSTEM_PY" -m venv "$VENV_DIR" 2>/dev/null; then
        die "Creazione del venv fallita.
      Su Debian/Ubuntu serve: sudo apt install python3-venv"
    fi
    ok "Creato: $VENV_DIR"
fi

step "Dipendenze della suite"
"$VENV_PY" -m pip install --upgrade pip --quiet --disable-pip-version-check
"$VENV_PY" -m pip install -r "$ROOT/requirements.txt" --quiet --disable-pip-version-check \
    || die "Installazione delle dipendenze fallita"
ok "requirements.txt installato"

step "Tkinter (serve alla GUI)"
if "$VENV_PY" -c 'import tkinter' 2>/dev/null; then
    ok "disponibile"
else
    # Tkinter non si installa da pip: e' un binding a Tcl/Tk di sistema.
    warn "assente: la GUI non partira'. La CLI funziona comunque."
    if [ "$OS" = "macOS" ]; then
        warn "  brew install python-tk"
        warn "  oppure usa il Python di python.org, che include Tk"
    else
        warn "  Debian/Ubuntu:  sudo apt install python3-tk"
        warn "  Fedora:         sudo dnf install python3-tkinter"
        warn "  Arch:           sudo pacman -S tk"
    fi
fi

if [ "$SKIP_ENGINES" -eq 0 ]; then
    step "Engine (VulnAPI + APISCAN)"
    "$VENV_PY" "$ROOT/bootstrap.py" --all || \
        warn "Bootstrap parzialmente fallito: vedi l'output qui sopra."

    APISCAN_REQ="$ROOT/vendor/apiscanner/requirements.txt"
    if [ -f "$APISCAN_REQ" ]; then
        step "Dipendenze di APISCAN"
        # Sono parecchie e alcune compilano: se falliscono non devono far
        # fallire l'installazione, perche' VulnAPI resta utilizzabile.
        if "$VENV_PY" -m pip install -r "$APISCAN_REQ" --quiet --disable-pip-version-check; then
            ok "installate"
        else
            warn "Alcune dipendenze di APISCAN non si sono installate."
            warn "L'engine APISCAN potrebbe non partire; VulnAPI funziona."
        fi
    fi
else
    warn "Engine saltati (--skip-engines)"
fi

step "Verifica finale"
"$VENV_PY" "$ROOT/bootstrap.py" --check || true

chmod +x "$ROOT"/run-*.sh 2>/dev/null || true
[ -f "$ROOT/run-gui.command" ] && chmod +x "$ROOT/run-gui.command"

printf '\n  %sInstallazione completata.%s\n\n' "$C_GREEN" "$C_OFF"
printf '  Interfaccia grafica     ./run-gui.sh\n'
printf '  Scansione da terminale  ./run-scan.sh --url https://api.example.test --openapi openapi.json\n'
printf '  Target di test          ./run-testtarget.sh\n'
if [ "$OS" = "macOS" ]; then
    printf '  Doppio click nel Finder run-gui.command\n'
fi
printf '\n  %sGli engine eseguono test attivi: usali solo su API di cui sei%s\n' "$C_YELLOW" "$C_OFF"
printf '  %sproprietario o per cui hai autorizzazione scritta.%s\n\n' "$C_YELLOW" "$C_OFF"
