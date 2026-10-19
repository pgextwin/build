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
    # Explicitly allow only the already tested server + CLI components;
    # preserve the proven pgAdmin/StackBuilder exclusions (PR #110).
    # The hosted Windows image already supplies VC++ runtimes; the real
    # PG14-18 trial proved complete server, MSVC build and SQL smoke.
    & choco install $ChocolateyPackage "--version=$ChocolateyVersion" --yes --no-progress --params "/Password:postgres" --ia "--enable-components server,commandlinetools --disable-components pgAdmin,stackbuilder --create_shortcuts 0 --install_runtimes 0"
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
# Component allowlisting must never silently omit the server/CLI/extension
# runtime needed for the actual Windows DLL and CREATE EXTENSION smoke.
foreach ($relative in @('bin\postgres.exe', 'bin\pg_config.exe', 'bin\initdb.exe',
                        'bin\pg_ctl.exe', 'bin\pg_isready.exe', 'bin\psql.exe',
                        'share\extension\plpgsql.control')) {
    if (-not (Test-Path -LiteralPath (Join-Path $pgRoot $relative) -PathType Leaf)) {
        throw "Required PostgreSQL component missing after Chocolatey: $relative"
    }
}
$version = (& (Join-Path $pgRoot 'bin\pg_config.exe') --version).Trim()
if ($LASTEXITCODE -ne 0 -or $version -notmatch ('^PostgreSQL\s+' + $Major + '(?:\.|\s)')) {
    throw "Unexpected PostgreSQL major after component-only install: $version"
}

"PGROOT=$pgRoot" >> $env:GITHUB_ENV
"PGPORT=$TestPort" >> $env:GITHUB_ENV
"$pgRoot\bin" >> $env:GITHUB_PATH

Write-Host "PGROOT=$pgRoot"
Write-Host "PGPORT=$TestPort"
Write-Host "Added PostgreSQL bin directory to subsequent-step PATH: $pgRoot\bin"
