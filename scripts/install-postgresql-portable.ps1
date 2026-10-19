[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidateRange(14, 18)][int]$Major,
    [Parameter(Mandatory = $true)][ValidateRange(1, 65535)][int]$TestPort,
    [string]$PinsPath = (Join-Path $PSScriptRoot '..\metadata\postgresql-portable-zip-pins.json')
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Separate PR-only pilot: never silently replace the established Chocolatey
# installer in signed production workflows. Every external ZIP is SHA256-pinned.
$overall = [Diagnostics.Stopwatch]::StartNew()
$phase = [Diagnostics.Stopwatch]::new()
$pins = Get-Content -LiteralPath $PinsPath -Raw | ConvertFrom-Json
if ($pins.schemaVersion -ne 1 -or $pins.purpose -cne 'READ_ONLY_PR_BENCHMARK_NOT_RELEASE') {
    throw 'Portable pin schema/purpose mismatch.'
}
$all = @($pins.files.PSObject.Properties.Name | Sort-Object)
if (($all -join ',') -cne '14,15,16,17,18') { throw 'All five majors require independent pins.' }
$pin = $pins.files.PSObject.Properties[[string]$Major].Value
$baseline = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\metadata\postgresql.json') -Raw | ConvertFrom-Json
$baselineRow = @($baseline.postgresql | Where-Object { $_.major -eq $Major })
if ($baselineRow.Count -ne 1 -or $baselineRow[0].minor -cne $pin.minor) {
    throw "PostgreSQL $Major minor release differs from approved fleet metadata."
}
if ($pin.file -cnotmatch ('^postgresql-' + $Major + '\.' + [regex]::Escape($pin.minor.Split('.')[1]) + '-[0-9]+-windows-x64-binaries\.zip$')) {
    throw 'Unapproved ZIP name or PostgreSQL minor version.'
}
if ($pin.sha256 -cnotmatch '^[0-9a-f]{64}$') { throw 'Missing full SHA256 pin.' }

$uri = 'https://get.enterprisedb.com/postgresql/' + $pin.file
$root = Join-Path $env:ProgramFiles ("PostgreSQL\" + $Major)
if (Test-Path -LiteralPath $root) {
    throw "Portable test refuses to replace an existing PostgreSQL installation: $root"
}
$base = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [IO.Path]::GetTempPath() }
$work = Join-Path $base ("pgextwin-pg" + $Major + "-portable")
$archive = Join-Path $work $pin.file
$stage = Join-Path $work 'extract'
if (Test-Path -LiteralPath $work) { throw "Refusing stale portable staging directory: $work" }
New-Item -ItemType Directory -Path $work -Force | Out-Null
$downloadSecs = 0
$verifySecs = 0
$extractSecs = 0

try {
    $phase.Restart()
    $oldProgress = $ProgressPreference
    $ProgressPreference = 'SilentlyContinue'
    try {
        # Network 503/timeouts are not proof of a safe downloaded ZIP.
        # Two fresh attempts; the SHA256 hard gate still follows both.
        for ($attempt=1; $attempt -le 2; $attempt++) {
            try {
                Write-Host "PG$Major portable attempt $attempt/2: $uri"
                Invoke-WebRequest -Uri $uri -OutFile $archive -MaximumRedirection 5 -TimeoutSec 420 -ErrorAction Stop
                break
            } catch {
                if (Test-Path -LiteralPath $archive) { Remove-Item -LiteralPath $archive -Force }
                if ($attempt -eq 2) { throw }
                Start-Sleep -Seconds 5
            }
        }
    } finally {
        $ProgressPreference = $oldProgress
    }
    $phase.Stop()
    $downloadSecs = [Math]::Round($phase.Elapsed.TotalSeconds, 2)

    $phase.Restart()
    $actual = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -cne $pin.sha256) {
        throw "EDB ZIP SHA256 mismatch for PG$Major. Expected $($pin.sha256); obtained $actual. Execution DENIED."
    }
    Add-Type -AssemblyName System.IO.Compression
    $zip = [IO.Compression.ZipFile]::OpenRead($archive)
    try {
        $entries = @($zip.Entries)
        if ($entries.Count -lt 30) { throw 'Truncated/unexpected PostgreSQL ZIP archive.' }
        foreach ($item in $entries) {
            $name = $item.FullName.Replace('\','/')
            if (-not $name.StartsWith('pgsql/', [StringComparison]::Ordinal) -or
                $name -match '(^|/)\.\.(/|$)' -or $name.Contains(':') -or
                $name.StartsWith('/') -or $name.Contains('//')) {
                throw "Portable archive includes unexpected or traversing path: $name"
            }
        }
    } finally { $zip.Dispose() }
    $phase.Stop()
    $verifySecs = [Math]::Round($phase.Elapsed.TotalSeconds, 2)
    Write-Host "PG$Major original EDB ZIP SHA256 VERIFIED: $actual"

    $phase.Restart()
    New-Item -ItemType Directory -Path $stage -Force | Out-Null
    $unzip = @(
        (Join-Path $env:ProgramData 'chocolatey\tools\7z.exe'),
        (Join-Path $env:ProgramFiles '7-Zip\7z.exe')
    ) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    if ($unzip) {
        & $unzip x -y -bd "-o$stage" $archive
        if ($LASTEXITCODE -ne 0) { throw "7-Zip extraction failed for PG$Major ($LASTEXITCODE)" }
    } else {
        Expand-Archive -LiteralPath $archive -DestinationPath $stage -Force
    }
    $payload = Join-Path $stage 'pgsql'
    if (-not (Test-Path -LiteralPath $payload -PathType Container)) {
        throw "Verified archive missing expected pgsql directory for PG$Major."
    }
    $parent = Split-Path -Parent $root
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
    Move-Item -LiteralPath $payload -Destination $root -ErrorAction Stop
    $phase.Stop()
    $extractSecs = [Math]::Round($phase.Elapsed.TotalSeconds, 2)

    # Strict binary + headers + import libraries + SQL data gates:
    # this must be a complete buildable and runnable PostgreSQL server, not
    # merely a cached psql client bundle.
    foreach ($rel in @('bin\postgres.exe','bin\pg_config.exe','bin\initdb.exe',
                       'bin\pg_ctl.exe','bin\pg_isready.exe','bin\psql.exe',
                       'include\server\postgres.h','lib\postgres.lib',
                       'share\extension\plpgsql.control')) {
        if (-not (Test-Path -LiteralPath (Join-Path $root $rel) -PathType Leaf)) {
            throw "PG$Major portable ZIP lacks required server/build component: $rel"
        }
    }
    $version = (& (Join-Path $root 'bin\pg_config.exe') --version).Trim()
    if ($LASTEXITCODE -ne 0 -or $version -cnotmatch ('^PostgreSQL ' + $Major + '\.' + [regex]::Escape($pin.minor.Split('.')[1]) + '(\D|$)')) {
        throw "PG$Major verified ZIP reports an unexpected version: $version"
    }
    $env:PGROOT = $root
    $env:PGPORT = [string]$TestPort
    $env:PATH = (Join-Path $root 'bin') + [IO.Path]::PathSeparator + $env:PATH
    if ($env:GITHUB_ENV) {
        "PGROOT=$root" >> $env:GITHUB_ENV
        "PGPORT=$TestPort" >> $env:GITHUB_ENV
    }
    if ($env:GITHUB_PATH) { (Join-Path $root 'bin') >> $env:GITHUB_PATH }
    $overall.Stop()
    Write-Host "PGEXTWIN_PORTABLE_PG=$Major SHA256=$actual DOWNLOAD_S=$downloadSecs VERIFY_S=$verifySecs EXTRACT_S=$extractSecs TOTAL_S=$([Math]::Round($overall.Elapsed.TotalSeconds,2))"
    if ($env:GITHUB_STEP_SUMMARY) {
        "| PG$Major | ZIP+SHA pinned | $downloadSecs s | $verifySecs s | $extractSecs s | $([Math]::Round($overall.Elapsed.TotalSeconds,2)) s |" >> $env:GITHUB_STEP_SUMMARY
    }
} finally {
    # Never cache the archive, leave runner state behind, or use production
    # signing/Release tokens. Installed tree lasts until this isolated job ends.
    if (Test-Path -LiteralPath $work) {
        Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
    }
}
