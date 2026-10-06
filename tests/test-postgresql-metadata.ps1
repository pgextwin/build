[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$PostgreSqlConfigPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($PostgreSqlConfigPath)) {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    $PostgreSqlConfigPath = Join-Path $repoRoot "metadata/postgresql.json"
}

$metadata = Get-Content $PostgreSqlConfigPath -Raw | ConvertFrom-Json

if (-not $metadata.PSObject.Properties.Name.Contains("schemaVersion") -or $metadata.schemaVersion -ne 1) {
    throw "PostgreSQL metadata must define schemaVersion 1."
}

if (-not $metadata.PSObject.Properties.Name.Contains("postgresql")) {
    throw "PostgreSQL metadata is missing required property 'postgresql'."
}

$entries = @($metadata.postgresql)
if ($entries.Count -eq 0) {
    throw "PostgreSQL metadata must contain at least one version entry."
}

$requiredProperties = @(
    "major",
    "minor",
    "chocolateyPackage",
    "chocolateyVersion",
    "eol",
    "testPort"
)

$seenMajors = [System.Collections.Generic.HashSet[int]]::new()
$previousMajor = $null

foreach ($entry in $entries) {
    foreach ($required in $requiredProperties) {
        if (-not $entry.PSObject.Properties.Name.Contains($required)) {
            throw "PostgreSQL metadata entry is missing required property '$required'."
        }
    }

    $majorText = [string]$entry.major
    $major = 0

    if (-not [int]::TryParse($majorText, [ref]$major) -or $major -lt 10) {
        throw "PostgreSQL major '$majorText' must be an integer greater than or equal to 10."
    }

    if (-not $seenMajors.Add($major)) {
        throw "PostgreSQL major $major is duplicated in metadata."
    }

    if ($null -ne $previousMajor -and $major -le $previousMajor) {
        throw "PostgreSQL metadata must be ordered by ascending major version."
    }

    $previousMajor = $major

    $minor = [string]$entry.minor
    if ([string]::IsNullOrWhiteSpace($minor) -or $minor -notmatch "^$major\.[0-9]+$") {
        throw "PostgreSQL major $major has invalid minor version '$minor'."
    }

    if ([string]::IsNullOrWhiteSpace([string]$entry.chocolateyPackage)) {
        throw "PostgreSQL major $major has an empty chocolateyPackage."
    }

    if ([string]::IsNullOrWhiteSpace([string]$entry.chocolateyVersion)) {
        throw "PostgreSQL major $major has an empty chocolateyVersion."
    }

    $eolText = [string]$entry.eol
    if ($eolText -notmatch "^[0-9]{4}-[0-9]{2}-[0-9]{2}$") {
        throw "PostgreSQL major $major EOL '$eolText' must use yyyy-MM-dd format."
    }

    try {
        [void][DateTime]::ParseExact(
            $eolText,
            "yyyy-MM-dd",
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::None
        )
    }
    catch {
        throw "PostgreSQL major $major EOL '$eolText' is not a valid calendar date."
    }

    $testPort = 0
    if (-not [int]::TryParse([string]$entry.testPort, [ref]$testPort) -or
        $testPort -lt 1 -or
        $testPort -gt 65535) {
        throw "PostgreSQL major $major has invalid testPort '$($entry.testPort)'."
    }
}

Write-Host "PostgreSQL lifecycle metadata validation passed for $($entries.Count) major version(s)."
