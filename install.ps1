<#
.SYNOPSIS
    Installa apisec-suite su Windows: venv, dipendenze, engine.

.DESCRIPTION
    Crea un ambiente virtuale isolato, installa le dipendenze della suite e di
    APISCAN, scarica il binario VulnAPI e clona APISCAN in vendor/.

    L'installazione e' interamente dentro la cartella del progetto: non tocca
    il Python di sistema e si disinstalla cancellando .venv, bin e vendor.

.PARAMETER Python
    Interprete da usare. Per default cerca py -3, poi python3, poi python.

.PARAMETER SkipEngines
    Non scaricare VulnAPI ne' clonare APISCAN. Utile per lavorare solo sul
    codice della suite.

.PARAMETER Force
    Ricrea il venv anche se esiste gia'.

.EXAMPLE
    .\install.ps1
    .\install.ps1 -Python "C:\Python312\python.exe"
    .\install.ps1 -Force
#>
[CmdletBinding()]
param(
    [string]$Python = "",
    [switch]$SkipEngines,
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot
$VenvDir = Join-Path $Root ".venv"
$VenvPython = Join-Path $VenvDir "Scripts\python.exe"

# Versione minima verificata. Sotto la 3.10 diverse annotazioni usate da
# APISCAN non reggono a runtime.
$MinMajor, $MinMinor = 3, 10

function Write-Step($Message) { Write-Host "`n==> $Message" -ForegroundColor Cyan }
function Write-Ok($Message)   { Write-Host "  OK  $Message" -ForegroundColor Green }
function Write-Warn2($Message){ Write-Host "  !   $Message" -ForegroundColor Yellow }
function Write-Err($Message)  { Write-Host "  X   $Message" -ForegroundColor Red }

function Find-Python {
    <# Primo interprete che soddisfa la versione minima. #>
    if ($Python) {
        if (-not (Test-Path $Python)) {
            $resolved = (Get-Command $Python -ErrorAction SilentlyContinue).Source
            if (-not $resolved) { throw "Interprete non trovato: $Python" }
            $Python = $resolved
        }
        return $Python
    }

    # `py -3` per primo: su Windows il launcher sceglie l'installazione giusta
    # anche quando `python` e' lo stub dello Store che apre la vetrina.
    $candidates = @()
    if (Get-Command py -ErrorAction SilentlyContinue) {
        $candidates += ,@("py", @("-3"))
    }
    foreach ($name in @("python3", "python")) {
        $cmd = Get-Command $name -ErrorAction SilentlyContinue
        if ($cmd) { $candidates += ,@($cmd.Source, @()) }
    }

    foreach ($candidate in $candidates) {
        $exe, $prefix = $candidate
        try {
            $args = $prefix + @("-c", "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}'); print(sys.executable)")
            $out = & $exe @args 2>$null
            if ($LASTEXITCODE -ne 0 -or -not $out) { continue }
            $version, $exePath = $out[0], $out[1]
            $major, $minor = $version.Split(".")
            if ([int]$major -gt $MinMajor -or ([int]$major -eq $MinMajor -and [int]$minor -ge $MinMinor)) {
                Write-Ok "Python $version trovato: $exePath"
                return $exePath
            }
            Write-Warn2 "Python $version troppo vecchio (serve >= $MinMajor.$MinMinor): $exePath"
        } catch { continue }
    }
    throw "Nessun Python >= $MinMajor.$MinMinor trovato. Installalo da https://www.python.org/downloads/ e riprova."
}

# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "  apisec-suite - installazione (Windows)" -ForegroundColor White
Write-Host "  $Root" -ForegroundColor DarkGray

Write-Step "Interprete Python"
$SystemPython = Find-Python

Write-Step "Ambiente virtuale"
if ((Test-Path $VenvDir) -and $Force) {
    Write-Warn2 "Rimuovo il venv esistente (-Force)"
    Remove-Item -Recurse -Force $VenvDir
}
if (Test-Path $VenvPython) {
    Write-Ok "Gia' presente: $VenvDir"
} else {
    & $SystemPython -m venv $VenvDir
    if ($LASTEXITCODE -ne 0) { throw "Creazione del venv fallita" }
    Write-Ok "Creato: $VenvDir"
}

Write-Step "Dipendenze della suite"
& $VenvPython -m pip install --upgrade pip --quiet --disable-pip-version-check
& $VenvPython -m pip install -r (Join-Path $Root "requirements.txt") --quiet --disable-pip-version-check
if ($LASTEXITCODE -ne 0) { throw "Installazione delle dipendenze fallita" }
Write-Ok "requirements.txt installato"

Write-Step "Tkinter (serve alla GUI)"
& $VenvPython -c "import tkinter" 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Ok "disponibile"
} else {
    # Su Windows Tkinter fa parte dell'installer ufficiale, ma e' deselezionabile.
    Write-Warn2 "assente: la GUI non partira'. Reinstalla Python spuntando"
    Write-Warn2 "'tcl/tk and IDLE' nell'installer. La CLI funziona comunque."
}

if (-not $SkipEngines) {
    Write-Step "Engine (VulnAPI + APISCAN)"
    & $VenvPython (Join-Path $Root "bootstrap.py") --all
    if ($LASTEXITCODE -ne 0) {
        Write-Warn2 "Bootstrap parzialmente fallito: rilancia '.\install.ps1' oppure"
        Write-Warn2 "consulta l'output qui sopra."
    }

    $ApiscanReq = Join-Path $Root "vendor\apiscanner\requirements.txt"
    if (Test-Path $ApiscanReq) {
        Write-Step "Dipendenze di APISCAN"
        # APISCAN ne ha parecchie e alcune sono pesanti: se fallisce non deve
        # far fallire l'installazione, perche' VulnAPI resta utilizzabile.
        & $VenvPython -m pip install -r $ApiscanReq --quiet --disable-pip-version-check
        if ($LASTEXITCODE -eq 0) {
            Write-Ok "installate"
        } else {
            Write-Warn2 "Alcune dipendenze di APISCAN non si sono installate."
            Write-Warn2 "L'engine APISCAN potrebbe non partire; VulnAPI funziona."
        }
    }
} else {
    Write-Warn2 "Engine saltati (-SkipEngines)"
}

Write-Step "Verifica finale"
# L'output del sottoprocesso va instradato su Write-Host: lasciato allo stdout
# nativo finirebbe fuori ordine quando l'installazione viene rediretta su file.
& $VenvPython (Join-Path $Root "bootstrap.py") --check 2>&1 |
    ForEach-Object { Write-Host "  $_" }

Write-Host ""
Write-Host "  Installazione completata." -ForegroundColor Green
Write-Host ""
Write-Host "  Interfaccia grafica     .\run-gui.ps1"
Write-Host "  Scansione da terminale  .\run-scan.ps1 --url https://api.example.test --openapi openapi.json"
Write-Host "  Target di test          .\run-testtarget.ps1"
Write-Host ""
Write-Host "  Gli engine eseguono test attivi: usali solo su API di cui sei" -ForegroundColor Yellow
Write-Host "  proprietario o per cui hai autorizzazione scritta." -ForegroundColor Yellow
Write-Host ""
