[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$outputFile = Join-Path ([IO.Path]::GetTempPath()) ("pgextwin-output-" + [Guid]::NewGuid().ToString("N") + ".txt")

try {
    $env:GITHUB_OUTPUT = $outputFile

    & (Join-Path $repoRoot "scripts/resolve-matrix.ps1") `
        -ExtensionConfigPath (Join-Path $PSScriptRoot "fixtures/extension-range.json") `
        -PostgreSqlConfigPath (Join-Path $PSScriptRoot "fixtures/postgresql.json")

    $lines = Get-Content $outputFile
    $values = @{}

    foreach ($line in $lines) {
        $parts = $line -split "=", 2
        if ($parts.Count -eq 2) {
            $values[$parts[0]] = $parts[1]
        }
    }

    if ($values["extension_name"] -ne "fixture") {
        throw "Unexpected extension_name: $($values['extension_name'])"
    }

    $matrix = $values["matrix"] | ConvertFrom-Json
    $majors = @($matrix.include | ForEach-Object { [int]$_.major })

    if ($majors.Count -ne 2 -or $majors[0] -ne 14 -or $majors[1] -ne 16) {
        throw "Expected PostgreSQL majors 14 and 16, got: $($majors -join ', ')"
    }

    if ($values["verify_upstream_license"] -ne "true") {
        throw "License verification output was not true."
    }

    Write-Host "resolve-matrix.ps1 self-test passed."
}
finally {
    Remove-Item $outputFile -Force -ErrorAction SilentlyContinue
}
