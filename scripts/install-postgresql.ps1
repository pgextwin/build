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
# HTTP 406 from this exact V2 feed is also a documented operational failure
# in the actual Issue #311 fleet Windows jobs; it is NOT a package-version
# acceptance and can only unlock independently fixed-size/SHA256 EDB bytes.
# The final status and PostgreSQL server installation remain hard gates.
# PowerShell 7.4+ can promote a nonzero native choco exit into a terminating
# NativeCommandExitException when ErrorActionPreference=Stop, *before* we
# inspect $LASTEXITCODE. That bypasses bounded retry and the existing
# independently SHA256-verified EDB installer fallback for real HTTP 503.
# Only suppress this automatic native-exit exception in this script scope.
# Every nonzero exit remains explicitly checked and DENIED unless all three
# attempts independently show the already-approved Chocolatey V2 outage.
$PSNativeCommandUseErrorActionPreference = $false
$successCodes = @(0, 1641, 3010)
$maxAttempts = 3
$code = -1
$feedOutageCount = 0
for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
    Write-Host "Installing $ChocolateyPackage version $ChocolateyVersion (attempt $attempt/$maxAttempts)."
    # Explicitly allow only the already tested server + CLI components;
    # preserve the proven pgAdmin/StackBuilder exclusions (PR #110).
    # The hosted Windows image already supplies VC++ runtimes; the real
    # PG14-18 trial proved complete server, MSVC build and SQL smoke.
    $attemptOutput = @(& choco install $ChocolateyPackage "--version=$ChocolateyVersion" --yes --no-progress --params "/Password:postgres" --ia "--enable-components server,commandlinetools --disable-components pgAdmin,stackbuilder --create_shortcuts 0 --install_runtimes 0" 2>&1)
    $code = $LASTEXITCODE
    $attemptOutput | ForEach-Object { Write-Host $_ }
    if ($successCodes -contains $code) { break }
    # A failed checksum, mismatching version, or non-gateway-outage error must DENY.
    $failureText = $attemptOutput -join [Environment]::NewLine
    if ($failureText.Contains('https://community.chocolatey.org/api/v2/') -and
        ($failureText -match '(406 \(Not Acceptable\)|502 \(Bad Gateway\)|503 \(Service Unavailable\)|504 \(Gateway Timeout\))')) {
        $feedOutageCount++
    }
    if ($attempt -lt $maxAttempts) {
        Write-Warning "Chocolatey exited with $code; retrying after a bounded cooldown."
        Start-Sleep -Seconds (10 * $attempt)
    }
}
if ($successCodes -notcontains $code) {
    if ($feedOutageCount -ne $maxAttempts) {
        throw "Chocolatey failed after $maxAttempts attempts, without verified V2 HTTP 406/502/503/504 in every attempt; EDB fallback DENY."
    }
    # Only the exact EDB installer bytes independently retrieved and SHA256
    # verified in successful Issue #75 Runs 39038000517 + 39038162434 may be
    # used when the Chocolatey V2 registry itself is unavailable.
    # These are fixed executable-byte pins, NOT a Release authorization.
    $edb = @{
        '14' = @{ Version = '14.24.0'; File = 'postgresql-14.24-1-windows-x64.exe'; Sha256 = '52a51ec49c38a68a9f93f677b23e975ba709354ddab8283ef2558f3e7cb7f998'; Bytes = 360966784 }
        '15' = @{ Version = '15.19.0'; File = 'postgresql-15.19-1-windows-x64.exe'; Sha256 = '09dc76dc45332e031074df8e5d19d9eac64b2b98b51e279099b7461a5c12a92a'; Bytes = 362808024 }
        '16' = @{ Version = '16.15.5'; File = 'postgresql-16.15-5-windows-x64.exe'; Sha256 = '4065dbc5ffb52010e7357dfd6a74934878f1c6faf7a75cad1411a22e11b7b929'; Bytes = 404741880 }
        '17' = @{ Version = '17.11.4'; File = 'postgresql-17.11-4-windows-x64.exe'; Sha256 = 'c9828fd3a4daebbeeace19bec2de5f38d73c047fce47278148b525cfbe28a5e4'; Bytes = 410984080 }
        '18' = @{ Version = '18.6.5'; File = 'postgresql-18.6-5-windows-x64.exe'; Sha256 = '227e2bc08091b4c2b8338c7d61b11d057f895711480b006f90bfcfcd2410a58a'; Bytes = 414966472 }
    }
    $majorKey = [string]$Major
    if (-not $edb.ContainsKey($majorKey) -or
        $ChocolateyPackage -cne "postgresql$Major" -or
        $ChocolateyVersion -cne $edb[$majorKey].Version) {
        throw "Chocolatey failure; direct installer fallback DENY for unknown package/version"
    }
    $pin = $edb[$majorKey]
    $uri = "https://get.enterprisedb.com/postgresql/$($pin.File)"
    $installer = Join-Path ([IO.Path]::GetTempPath()) ("pgextwin-edb-$Major-" + [Guid]::NewGuid().ToString('N') + '.exe')
    try {
        Write-Warning "Chocolatey unavailable; downloading only the independently byte-verified EDB PG$Major installer."
        Invoke-WebRequest -Uri $uri -OutFile $installer -MaximumRedirection 3 -ErrorAction Stop
        if (-not (Test-Path -LiteralPath $installer -PathType Leaf)) { throw "EDB installer missing" }
        $length = (Get-Item -LiteralPath $installer).Length
        if ($length -ne $pin.Bytes) { throw "EDB installer byte size mismatch: $length" }
        $actual = (Get-FileHash -LiteralPath $installer -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -cne $pin.Sha256) { throw "EDB installer SHA256 mismatch; execution DENY" }
        Write-Host "PASS: PG$Major EDB original EXE exact bytes and SHA256 verified"
        # Same server+CLI component subset as the successful Chocolatey path.
        # This runs only in an ephemeral GitHub Windows CI environment.
        $arguments = @('--mode','unattended','--unattendedmodeui','none',
                       '--superpassword','postgres','--enable_acledit','1',
                       '--enable-components','server,commandlinetools',
                       '--disable-components','pgAdmin,stackbuilder',
                       '--create_shortcuts','0','--install_runtimes','0')
        $process = Start-Process -FilePath $installer -ArgumentList $arguments -Wait -PassThru
        if ($successCodes -notcontains $process.ExitCode) {
            throw "SHA256-verified EDB installer failed: exit $($process.ExitCode)"
        }
    } finally {
        if (Test-Path -LiteralPath $installer) {
            Remove-Item -LiteralPath $installer -Force -ErrorAction SilentlyContinue
        }
    }
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
