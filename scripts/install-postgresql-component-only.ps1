[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidateRange(14,18)][int]$Major,
    [Parameter(Mandatory = $true)][string]$ChocolateyPackage,
    [Parameter(Mandatory = $true)][string]$ChocolateyVersion,
    [Parameter(Mandatory = $true)][ValidateRange(1,65535)][int]$TestPort
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# PR-only Chocolatey experiment. Keep the production installer unchanged
# until all five real build + database-smoke jobs are verified.
$metadata = Get-Content (Join-Path $PSScriptRoot '..\metadata\postgresql.json') -Raw | ConvertFrom-Json
$matching = @($metadata.postgresql | Where-Object { $_.major -eq $Major })
if ($matching.Count -ne 1 -or
    $matching[0].chocolateyPackage -cne $ChocolateyPackage -or
    $matching[0].chocolateyVersion -cne $ChocolateyVersion) {
    throw 'Chocolatey package and version must match approved fleet metadata.'
}
$root = Join-Path $env:ProgramFiles ("PostgreSQL\" + $Major)
$preexisting = Test-Path -LiteralPath $root
if ($preexisting -and $Major -ne 17) {
    throw "Unexpected existing PG$Major installation; never overwrite."
}
if ($preexisting) {
    Write-Host 'PG17 already installed on the GitHub runner; verify its exact version and full build/runtime dependencies. No installation-time benchmark is claimed for this reuse.'
}
$sw = [Diagnostics.Stopwatch]::StartNew()
$successCodes = @(0, 1641, 3010)
$maxAttempts = 3
$exit = -1
if (-not $preexisting) {
for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
    Write-Host "PG$Major Chocolatey selected components: server+commandlinetools; omit pgAdmin+stackbuilder; no shortcuts/runtime reinstall; attempt $attempt/$maxAttempts"
    # Reuse proven PR #110 exclusion; explicit allowlist guards the subset.
    & choco install $ChocolateyPackage "--version=$ChocolateyVersion" --yes --no-progress --params "/Password:postgres" --ia "--enable-components server,commandlinetools --disable-components pgAdmin,stackbuilder --create_shortcuts 0 --install_runtimes 0"
    $exit = $LASTEXITCODE
    if ($successCodes -contains $exit) { break }
    if ($attempt -lt $maxAttempts) {
        Write-Warning "PG$Major Chocolatey failed $exit; bounded retry after cooldown."
        Start-Sleep -Seconds (10 * $attempt)
    }
}
if ($successCodes -notcontains $exit) {
    throw "Chocolatey PG$Major failed after $maxAttempts attempts: code=$exit"
}
} else { $exit = 0 }
$files = @(
  'bin\postgres.exe', 'bin\pg_config.exe', 'bin\initdb.exe', 'bin\pg_ctl.exe',
  'bin\pg_isready.exe', 'bin\psql.exe',
  'include\server\postgres.h', 'lib\postgres.lib', 'share\extension\plpgsql.control'
)
foreach ($rel in $files) {
    if (-not (Test-Path -LiteralPath (Join-Path $root $rel) -PathType Leaf)) {
        throw "Required server, tool or extension-build component missing: $rel"
    }
}
$version = (& (Join-Path $root 'bin\pg_config.exe') --version).Trim()
if ($LASTEXITCODE -ne 0 -or $version -notmatch ('^PostgreSQL\s+' + $Major + '(?:\.|\s)')) {
    throw "Incorrect installed PostgreSQL version: $version"
}
$sw.Stop()
$seconds = [Math]::Round($sw.Elapsed.TotalSeconds, 2)
$env:PGROOT = $root
$env:PGPORT = [string]$TestPort
$env:PATH = (Join-Path $root 'bin') + [IO.Path]::PathSeparator + $env:PATH
if ($env:GITHUB_ENV) {
    "PGROOT=$root" >> $env:GITHUB_ENV
    "PGPORT=$TestPort" >> $env:GITHUB_ENV
}
if ($env:GITHUB_PATH) { (Join-Path $root 'bin') >> $env:GITHUB_PATH }
$installKind = if ($preexisting) { 'REUSED_RUNNER_PREINSTALL_NOT_BENCHMARK' } else { 'FRESH_CHOCOLATEY' }
Write-Host "PGEXTWIN_CHOCO_MINIMUM PG=$Major MODE=$installKind EXIT=$exit SECONDS=$seconds VERSION=$version COMPONENTS=server,commandlinetools"
if ($env:GITHUB_STEP_SUMMARY) {
    "| PG$Major | $installKind | $seconds | $version |" >> $env:GITHUB_STEP_SUMMARY
}
