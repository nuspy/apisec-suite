<#
.SYNOPSIS
    Esegue una scansione da riga di comando, senza interfaccia grafica.

.DESCRIPTION
    Passa tutti gli argomenti ad apisec_cli.py e ne restituisce il codice di
    uscita, cosi' che funzioni dentro una pipeline.

    Codici di uscita:
        0  scansione completata, nessun finding sopra la soglia
        1  finding sopra la soglia (--fail-on)
        2  configurazione non valida
        3  nessun engine ha potuto girare

.EXAMPLE
    .\run-scan.ps1 --url https://api.example.test --openapi openapi.json
    .\run-scan.ps1 --url https://api.example.test --flow token --token $env:API_TOKEN --fail-on high
    .\run-scan.ps1 --help
#>
[CmdletBinding()]
param(
    # ValueFromRemainingArguments perche' i flag sono quelli della CLI Python
    # (--url, --openapi, ...): PowerShell non deve provare a interpretarli.
    #
    # [object[]] e NON [string[]]: in PowerShell la virgola e' l'operatore di
    # costruzione array, quindi `--engines vulnapi,apiscan` arriva come un
    # array di due elementi. Con [string[]] verrebbe convertito in
    # "vulnapi apiscan" (join con spazio), la virgola sparirebbe, e la
    # scansione partirebbe con zero engine senza dire niente. Tenendolo
    # [object[]] l'array resta tale e si puo' ricomporre correttamente.
    [Parameter(ValueFromRemainingArguments = $true)]
    [object[]]$Arguments
)

$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot
$VenvPython = Join-Path $Root ".venv\Scripts\python.exe"

if (-not (Test-Path $VenvPython)) {
    Write-Host ""
    Write-Host "  Ambiente non installato." -ForegroundColor Red
    Write-Host "  Esegui prima:  .\install.ps1" -ForegroundColor Yellow
    Write-Host ""
    exit 2
}

if (-not $Arguments -or $Arguments.Count -eq 0) {
    $Arguments = @("--help")
}

# Ricompone gli array creati dalla virgola nella forma che la CLI si aspetta.
$Flat = foreach ($item in $Arguments) {
    if ($item -is [System.Array]) { ($item | ForEach-Object { "$_" }) -join "," }
    else { "$item" }
}

& $VenvPython (Join-Path $Root "apisec_cli.py") @Flat
exit $LASTEXITCODE
