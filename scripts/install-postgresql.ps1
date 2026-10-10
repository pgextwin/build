[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [int]$Major,

    [Parameter(Mandatory = $true)]
    [string]$ChocolateyPackage,

    [Parameter(Mandatory = $true)]
    [string]$ChocolateyVersion,

    [Parameter(Mandatory = $true)]
    [int]$TestPort
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Bounded retry for transient Chocolatey community feed failures.
# The final status and PostgreSQL server installation remain hard gates.
$successCodes = @(0, 1641, 3010)
$maxAttempts = 3
$code = -1
for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
    Write-Host "Installing $ChocolateyPackage version $ChocolateyVersion (attempt $attempt/$maxAttempts)."
    & choco install $ChocolateyPackage "--version=$ChocolateyVersion" --yes --no-progress --params "/Password:postgres"
    $code = $LASTEXITCODE
    if ($successCodes -contains $code) { break }
    if ($attempt -lt $maxAttempts) {
        Write-Warning "Chocolatey exited with $code; retrying after a bounded cooldown."
        Start-Sleep -Seconds (10 * $attempt)
    }
}
if ($successCodes -notcontains $code) {
    throw "Chocolatey failed after $maxAttempts attempts with exit code $code."
}

$pgRoot = Join-Path $env:ProgramFiles "PostgreSQL\$Major"

if (-not (Test-Path "$pgRoot\include\server\postgres.h")) {
    throw "PostgreSQL server headers were not found: $pgRoot\include\server\postgres.h"
}

if (-not (Test-Path "$pgRoot\lib\postgres.lib")) {
    throw "PostgreSQL import library was not found: $pgRoot\lib\postgres.lib"
}

"PGROOT=$pgRoot" >> $env:GITHUB_ENV
"PGPORT=$TestPort" >> $env:GITHUB_ENV
"$pgRoot\bin" >> $env:GITHUB_PATH

Write-Host "PGROOT=$pgRoot"
Write-Host "PGPORT=$TestPort"
Write-Host "Added PostgreSQL bin directory to subsequent-step PATH: $pgRoot\bin"
