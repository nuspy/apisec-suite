<#
.SYNOPSIS
    Avvia il target di test deliberatamente vulnerabile.

.DESCRIPTION
    API FastAPI insicura di proposito, con OpenAPI auto-generato. Esiste perche'
    gli engine inviano payload di attacco e provarli su sistemi di terzi non e'
    accettabile.

    Il bind e' su 127.0.0.1: raggiungibile solo da questa macchina.

.PARAMETER Port
    Porta di ascolto (default 8000).

.EXAMPLE
    .\run-testtarget.ps1
    .\run-testtarget.ps1 -Port 9000
#>
[CmdletBinding()]
param(
    [int]$Port = 8000
)

$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot
$VenvPython = Join-Path $Root ".venv\Scripts\python.exe"

if (-not (Test-Path $VenvPython)) {
    Write-Host ""
    Write-Host "  Ambiente non installato." -ForegroundColor Red
    Write-Host "  Esegui prima:  .\install.ps1" -ForegroundColor Yellow
    Write-Host ""
    exit 1
}

# Il target usa FastAPI e uvicorn, che non sono fra le dipendenze della suite:
# servono solo a lui, e chi non usa il target di test non deve installarli.
& $VenvPython -c "import fastapi, uvicorn" 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "  Installo FastAPI e uvicorn (servono solo al target di test)..." -ForegroundColor Cyan
    & $VenvPython -m pip install fastapi uvicorn --quiet --disable-pip-version-check
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  Installazione fallita." -ForegroundColor Red
        exit 1
    }
}

Write-Host ""
Write-Host "  Target di test su http://127.0.0.1:$Port" -ForegroundColor Cyan
Write-Host "  OpenAPI: http://127.0.0.1:$Port/openapi.json" -ForegroundColor DarkGray
Write-Host "  Deliberatamente insicuro. Ctrl+C per fermarlo." -ForegroundColor Yellow
Write-Host ""
Write-Host "  Per scansionarlo, da un'altra finestra:" -ForegroundColor DarkGray
Write-Host "    curl -s http://127.0.0.1:$Port/openapi.json -o openapi.json" -ForegroundColor DarkGray
Write-Host "    .\run-scan.ps1 --url http://127.0.0.1:$Port --openapi openapi.json --fail-on never" -ForegroundColor DarkGray
Write-Host ""

& $VenvPython (Join-Path $Root "tests\vulnerable_api.py") --port $Port
exit $LASTEXITCODE
