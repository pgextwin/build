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

& choco install $ChocolateyPackage "--version=$ChocolateyVersion" --yes --no-progress --params "/Password:postgres"
$code = $LASTEXITCODE

if (@(0, 1641, 3010) -notcontains $code) {
    throw "Chocolatey failed with exit code $code."
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
