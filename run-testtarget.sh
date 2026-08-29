#!/usr/bin/env bash
#
# Avvia il target di test deliberatamente vulnerabile.
#
# API FastAPI insicura di proposito, con OpenAPI auto-generato. Esiste perche'
# gli engine inviano payload di attacco e provarli su sistemi di terzi non e'
# accettabile.
#
# Il bind e' su 127.0.0.1: raggiungibile solo da questa macchina.
#
#   ./run-testtarget.sh            porta 8000
#   ./run-testtarget.sh --port 9000
#
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_PY="$ROOT/.venv/bin/python"
PORT=8000

while [ $# -gt 0 ]; do
    case "$1" in
        --port)   PORT="${2:-8000}"; shift 2 ;;
        --port=*) PORT="${1#*=}"; shift ;;
        -h|--help) sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "Opzione sconosciuta: $1" >&2; exit 2 ;;
    esac
done

if [ ! -x "$VENV_PY" ]; then
    printf '\n  \033[31mAmbiente non installato.\033[0m\n'
    printf '  Esegui prima:  ./install.sh\n\n'
    exit 1
fi

# FastAPI e uvicorn non sono fra le dipendenze della suite: servono solo al
# target di test, e chi non lo usa non deve installarli.
if ! "$VENV_PY" -c 'import fastapi, uvicorn' 2>/dev/null; then
    printf '  \033[36mInstallo FastAPI e uvicorn (servono solo al target di test)...\033[0m\n'
    "$VENV_PY" -m pip install fastapi uvicorn --quiet --disable-pip-version-check || {
        printf '  \033[31mInstallazione fallita.\033[0m\n'
        exit 1
    }
fi

printf '\n  \033[36mTarget di test su http://127.0.0.1:%s\033[0m\n' "$PORT"
printf '  \033[2mOpenAPI: http://127.0.0.1:%s/openapi.json\033[0m\n' "$PORT"
printf '  \033[33mDeliberatamente insicuro. Ctrl+C per fermarlo.\033[0m\n\n'
printf '  \033[2mPer scansionarlo, da un altro terminale:\033[0m\n'
printf '  \033[2m  curl -s http://127.0.0.1:%s/openapi.json -o openapi.json\033[0m\n' "$PORT"
printf '  \033[2m  ./run-scan.sh --url http://127.0.0.1:%s --openapi openapi.json --fail-on never\033[0m\n\n' "$PORT"

exec "$VENV_PY" "$ROOT/tests/vulnerable_api.py" --port "$PORT"
