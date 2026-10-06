[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$resolver = Join-Path $repoRoot "scripts/resolve-matrix.ps1"
$postgresFixture = Join-Path $PSScriptRoot "fixtures/postgresql.json"

function Invoke-ResolverFixture {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ExtensionFixture,

        [Parameter(Mandatory = $false)]
        [string]$EffectiveDate = "2026-10-06"
    )

    $outputFile = Join-Path ([IO.Path]::GetTempPath()) ("pgextwin-output-" + [Guid]::NewGuid().ToString("N") + ".txt")

    try {
        $env:GITHUB_OUTPUT = $outputFile

        & $resolver `
            -ExtensionConfigPath (Join-Path $PSScriptRoot "fixtures/$ExtensionFixture") `
            -PostgreSqlConfigPath $postgresFixture `
            -EffectiveDate $EffectiveDate

        $values = @{}

        foreach ($line in (Get-Content $outputFile)) {
            $parts = $line -split "=", 2
            if ($parts.Count -eq 2) {
                $values[$parts[0]] = $parts[1]
            }
        }

        return $values
    }
    finally {
        Remove-Item $outputFile -Force -ErrorAction SilentlyContinue
    }
}

$uniform = Invoke-ResolverFixture -ExtensionFixture "extension-range.json"

if ($uniform["extension_name"] -ne "fixture") {
    throw "Unexpected uniform extension_name: $($uniform['extension_name'])"
}

if ($uniform["upstream_mode"] -ne "uniform") {
    throw "Expected uniform upstream mode, got: $($uniform['upstream_mode'])"
}

if ($uniform["upstream_ref"] -ne "v1" -or $uniform["upstream_version"] -ne "1") {
    throw "Unexpected uniform upstream outputs."
}

$uniformMatrix = $uniform["matrix"] | ConvertFrom-Json
$uniformMajors = @($uniformMatrix.include | ForEach-Object { [int]$_.major })

if ($uniformMajors.Count -ne 2 -or $uniformMajors[0] -ne 14 -or $uniformMajors[1] -ne 16) {
    throw "Expected PostgreSQL majors 14 and 16, got: $($uniformMajors -join ', ')"
}

foreach ($entry in $uniformMatrix.include) {
    if ($entry.upstreamRef -ne "v1" -or $entry.upstreamVersion -ne "1") {
        throw "Uniform upstream metadata was not copied into matrix entry for PostgreSQL $($entry.major)."
    }

    if (@($entry.licenseFiles).Count -ne 1 -or
        $entry.licenseFiles[0].repositoryPath -ne "LICENSE" -or
        $entry.licenseFiles[0].upstreamPath -ne "LICENSE") {
        throw "Legacy license mapping was not copied into matrix entry for PostgreSQL $($entry.major)."
    }
}

if ($uniform["verify_upstream_license"] -ne "true") {
    throw "License verification output was not true."
}

$uniformLicenseFiles = $uniform["license_files"] | ConvertFrom-Json

if (@($uniformLicenseFiles).Count -ne 1 -or
    $uniformLicenseFiles[0].repositoryPath -ne "LICENSE" -or
    $uniformLicenseFiles[0].upstreamPath -ne "LICENSE") {
    throw "Legacy upstreamPath was not normalized to the expected single license-file mapping."
}

$multiLicense = Invoke-ResolverFixture -ExtensionFixture "extension-multi-license.json"

$multiLicenseFiles = $multiLicense["license_files"] | ConvertFrom-Json

if (@($multiLicenseFiles).Count -ne 2) {
    throw "Expected two license file mappings."
}

if ($multiLicenseFiles[0].repositoryPath -ne "COPYRIGHT" -or
    $multiLicenseFiles[0].upstreamPath -ne "COPYRIGHT") {
    throw "Unexpected first multi-license mapping."
}

if ($multiLicenseFiles[1].repositoryPath -ne "COPYRIGHT.postgresql" -or
    $multiLicenseFiles[1].upstreamPath -ne "COPYRIGHT.postgresql") {
    throw "Unexpected second multi-license mapping."
}

$multiLicenseMatrix = $multiLicense["matrix"] | ConvertFrom-Json
$multiLicenseEntry = @($multiLicenseMatrix.include)[0]

if (@($multiLicenseEntry.licenseFiles).Count -ne 2) {
    throw "Expected two uniform license mappings in the build matrix."
}

$perMajorLicense = Invoke-ResolverFixture -ExtensionFixture "extension-per-major-license.json"

if ($perMajorLicense["license_mode"] -ne "perPostgresql") {
    throw "Expected perPostgresql license mode."
}

if ($perMajorLicense["license_files"] -ne "") {
    throw "Global license_files output must be empty in perPostgresql license mode."
}

$perMajorLicenseMatrix = $perMajorLicense["matrix"] | ConvertFrom-Json
$pg14License = @($perMajorLicenseMatrix.include | Where-Object { [int]$_.major -eq 14 })[0]
$pg16License = @($perMajorLicenseMatrix.include | Where-Object { [int]$_.major -eq 16 })[0]

if (@($pg14License.licenseFiles).Count -ne 2 -or
    $pg14License.licenseFiles[0].repositoryPath -ne "licenses/pg14/COPYRIGHT" -or
    $pg14License.licenseFiles[1].repositoryPath -ne "licenses/pg14/COPYRIGHT.postgresql") {
    throw "Unexpected PostgreSQL 14 per-major license mappings."
}

if (@($pg16License.licenseFiles).Count -ne 2 -or
    $pg16License.licenseFiles[0].repositoryPath -ne "licenses/pg16/COPYRIGHT" -or
    $pg16License.licenseFiles[1].repositoryPath -ne "licenses/pg16/COPYRIGHT.postgresql") {
    throw "Unexpected PostgreSQL 16 per-major license mappings."
}

$perMajor = Invoke-ResolverFixture -ExtensionFixture "extension-per-major.json"

if ($perMajor["extension_name"] -ne "fixture-per-major") {
    throw "Unexpected per-major extension_name: $($perMajor['extension_name'])"
}

if ($perMajor["upstream_mode"] -ne "perPostgresql") {
    throw "Expected perPostgresql upstream mode, got: $($perMajor['upstream_mode'])"
}

if ($perMajor["upstream_ref"] -ne "" -or $perMajor["upstream_version"] -ne "") {
    throw "Global upstream ref/version must be empty in perPostgresql mode."
}

$perMajorMatrix = $perMajor["matrix"] | ConvertFrom-Json
$pg14 = @($perMajorMatrix.include | Where-Object { [int]$_.major -eq 14 })[0]
$pg16 = @($perMajorMatrix.include | Where-Object { [int]$_.major -eq 16 })[0]

if ($pg14.upstreamRef -ne "REL14_1_4_4" -or $pg14.upstreamVersion -ne "1.4.4") {
    throw "Unexpected PostgreSQL 14 per-major upstream metadata."
}

if ($pg16.upstreamRef -ne "REL16_1_6_2" -or $pg16.upstreamVersion -ne "1.6.2") {
    throw "Unexpected PostgreSQL 16 per-major upstream metadata."
}

$missingOutput = Join-Path ([IO.Path]::GetTempPath()) ("pgextwin-output-" + [Guid]::NewGuid().ToString("N") + ".txt")
$missingFailed = $false

try {
    $env:GITHUB_OUTPUT = $missingOutput

    try {
        & $resolver -ExtensionConfigPath (Join-Path $PSScriptRoot "fixtures/extension-per-major-missing.json") -PostgreSqlConfigPath $postgresFixture
    }
    catch {
        if ($_.Exception.Message -like "*no mapping for eligible PostgreSQL major 16*") {
            $missingFailed = $true
        }
        else {
            throw
        }
    }
}
finally {
    Remove-Item $missingOutput -Force -ErrorAction SilentlyContinue
}

if (-not $missingFailed) {
    throw "Expected resolver to reject a missing per-PostgreSQL upstream mapping."
}


$lifecycleBefore = Invoke-ResolverFixture -ExtensionFixture "extension-lifecycle-mixed.json" -EffectiveDate "2026-11-11"
$lifecycleBeforeMajors = @(($lifecycleBefore["matrix"] | ConvertFrom-Json).include | ForEach-Object { [int]$_.major })

if ($lifecycleBeforeMajors.Count -ne 2 -or
    $lifecycleBeforeMajors[0] -ne 14 -or
    $lifecycleBeforeMajors[1] -ne 16) {
    throw "EOL-1 day: expected PostgreSQL majors 14 and 16, got: $($lifecycleBeforeMajors -join ', ')"
}

if ($lifecycleBeforeMajors -contains 13) {
    throw "Already-EOL PostgreSQL 13 must not be included in the matrix."
}

$lifecycleOn = Invoke-ResolverFixture -ExtensionFixture "extension-lifecycle-mixed.json" -EffectiveDate "2026-11-12"
$lifecycleOnMajors = @(($lifecycleOn["matrix"] | ConvertFrom-Json).include | ForEach-Object { [int]$_.major })

if ($lifecycleOnMajors.Count -ne 2 -or
    $lifecycleOnMajors[0] -ne 14 -or
    $lifecycleOnMajors[1] -ne 16) {
    throw "EOL day: expected PostgreSQL majors 14 and 16, got: $($lifecycleOnMajors -join ', ')"
}

$lifecycleAfter = Invoke-ResolverFixture -ExtensionFixture "extension-lifecycle-mixed.json" -EffectiveDate "2026-11-13"
$lifecycleAfterMajors = @(($lifecycleAfter["matrix"] | ConvertFrom-Json).include | ForEach-Object { [int]$_.major })

if ($lifecycleAfterMajors.Count -ne 1 -or $lifecycleAfterMajors[0] -ne 16) {
    throw "EOL+1 day: expected only PostgreSQL 16, got: $($lifecycleAfterMajors -join ', ')"
}

$allEolOutput = Join-Path ([IO.Path]::GetTempPath()) ("pgextwin-output-" + [Guid]::NewGuid().ToString("N") + ".txt")
$allEolFailed = $false

try {
    $env:GITHUB_OUTPUT = $allEolOutput

    try {
        & $resolver \`
            -ExtensionConfigPath (Join-Path $PSScriptRoot "fixtures/extension-eol-only.json") \`
            -PostgreSqlConfigPath $postgresFixture \`
            -EffectiveDate "2026-11-13"
    }
    catch {
        if ($_.Exception.Message -like "*No maintained PostgreSQL versions are eligible*") {
            $allEolFailed = $true
        }
        else {
            throw
        }
    }
}
finally {
    Remove-Item $allEolOutput -Force -ErrorAction SilentlyContinue
}

if (-not $allEolFailed) {
    throw "Expected resolver to fail when every manifest-allowed PostgreSQL major is past EOL."
}

$invalidDateOutput = Join-Path ([IO.Path]::GetTempPath()) ("pgextwin-output-" + [Guid]::NewGuid().ToString("N") + ".txt")
$invalidDateFailed = $false

try {
    $env:GITHUB_OUTPUT = $invalidDateOutput

    try {
        & $resolver \`
            -ExtensionConfigPath (Join-Path $PSScriptRoot "fixtures/extension-range.json") \`
            -PostgreSqlConfigPath $postgresFixture \`
            -EffectiveDate "2026/11/12"
    }
    catch {
        if ($_.Exception.Message -like "*yyyy-MM-dd*") {
            $invalidDateFailed = $true
        }
        else {
            throw
        }
    }
}
finally {
    Remove-Item $invalidDateOutput -Force -ErrorAction SilentlyContinue
}

if (-not $invalidDateFailed) {
    throw "Expected resolver to reject an EffectiveDate outside yyyy-MM-dd format."
}

Write-Host "resolve-matrix.ps1 self-tests passed."
