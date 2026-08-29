#!/usr/bin/env bash
#
# Esegue una scansione da riga di comando, senza interfaccia grafica.
#
# Tutti gli argomenti passano ad apisec_cli.py e il codice di uscita viene
# propagato, cosi' che funzioni dentro una pipeline.
#
#   0  scansione completata, nessun finding sopra la soglia
#   1  finding sopra la soglia (--fail-on)
#   2  configurazione non valida
#   3  nessun engine ha potuto girare
#
#   ./run-scan.sh --url https://api.example.test --openapi openapi.json
#   ./run-scan.sh --url ... --flow token --token "$API_TOKEN" --fail-on high
#   ./run-scan.sh --help
#
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_PY="$ROOT/.venv/bin/python"

if [ ! -x "$VENV_PY" ]; then
    printf '\n  \033[31mAmbiente non installato.\033[0m\n'
    printf '  Esegui prima:  ./install.sh\n\n'
    exit 2
fi

if [ $# -eq 0 ]; then
    set -- --help
fi

# `exec` sostituisce la shell: i segnali (Ctrl+C) arrivano direttamente a
# Python, che interrompe gli engine in modo pulito invece di lasciarli orfani.
exec "$VENV_PY" "$ROOT/apisec_cli.py" "$@"
