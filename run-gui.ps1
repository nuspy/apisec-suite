<#
.SYNOPSIS
    Avvia l'interfaccia grafica di apisec-suite.

.DESCRIPTION
    Usa il Python del venv creato da install.ps1. Non serve attivare l'ambiente
    a mano: invocare direttamente l'interprete del venv equivale ad attivarlo,
    e non lascia la sessione in uno stato modificato.

.EXAMPLE
    .\run-gui.ps1
#>
[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot

# `pythonw.exe` non apre la finestra nera della console dietro alla GUI.
# Se manca (installazioni ridotte) si ripiega su python.exe.
$VenvPythonW = Join-Path $Root ".venv\Scripts\pythonw.exe"
$VenvPython  = Join-Path $Root ".venv\Scripts\python.exe"

if (-not (Test-Path $VenvPython)) {
    Write-Host ""
    Write-Host "  Ambiente non installato." -ForegroundColor Red
    Write-Host "  Esegui prima:  .\install.ps1" -ForegroundColor Yellow
    Write-Host ""
    exit 1
}

# Tkinter assente significa nessuna finestra: meglio dirlo qui che lasciare
# scomparire un traceback in una console che si chiude da sola.
& $VenvPython -c "import tkinter" 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "  Tkinter non e' disponibile in questo Python: la GUI non puo' partire." -ForegroundColor Red
    Write-Host "  Reinstalla Python spuntando 'tcl/tk and IDLE' nell'installer." -ForegroundColor Yellow
    Write-Host "  In alternativa usa la riga di comando:  .\run-scan.ps1 --help" -ForegroundColor Yellow
    Write-Host ""
    exit 1
}

$Interpreter = if (Test-Path $VenvPythonW) { $VenvPythonW } else { $VenvPython }
$Entry = Join-Path $Root "apisec_gui.py"

Write-Host "  Avvio dell'interfaccia..." -ForegroundColor Cyan

if ($Interpreter -eq $VenvPythonW) {
    # Con pythonw il processo si stacca e non c'e' output da attendere: si
    # lascia la finestra all'utente e si restituisce subito il controllo.
    Start-Process -FilePath $Interpreter -ArgumentList $Entry -WorkingDirectory $Root
    exit 0
}

& $Interpreter $Entry
exit $LASTEXITCODE
