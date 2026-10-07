param(
    [Parameter(Mandatory = $true)]
    [string]$GrypePath,

    [string]$ConfigPath = ".pgextwin-build\config\grype-report-only.yaml",

    [string]$DistDirectory = "dist"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$grype = [System.IO.Path]::GetFullPath((Join-Path $PWD $GrypePath))
$config = [System.IO.Path]::GetFullPath((Join-Path $PWD $ConfigPath))
$dist = [System.IO.Path]::GetFullPath((Join-Path $PWD $DistDirectory))

if (-not (Test-Path $grype)) {
    throw "Grype executable not found: $grype"
}
if (-not (Test-Path $config)) {
    throw "Grype baseline configuration not found: $config"
}
if (-not (Test-Path $dist)) {
    throw "Distribution directory not found: $dist"
}

$zipFiles = @(Get-ChildItem -Path $dist -Filter "*.zip" -File)
$sbomFiles = @(Get-ChildItem -Path $dist -Filter "*.spdx.json" -File)
if ($zipFiles.Count -ne 1) {
    throw "Expected exactly one final ZIP for vulnerability scanning, found $($zipFiles.Count)."
}
if ($sbomFiles.Count -ne 1) {
    throw "Expected exactly one SPDX JSON for vulnerability scanning, found $($sbomFiles.Count)."
}

$zip = $zipFiles[0]
$sbom = $sbomFiles[0]
$expectedSbomName = "$($zip.BaseName).spdx.json"
if ($sbom.Name -ne $expectedSbomName) {
    throw "SBOM filename mismatch. Expected '$expectedSbomName', found '$($sbom.Name)'."
}

$reportPath = Join-Path $dist "$($zip.BaseName).vulnerabilities.json"
if (Test-Path $reportPath) {
    Remove-Item -Force $reportPath
}

# A fresh hosted runner normally begins without a local Grype DB. Update explicitly so
# database acquisition/update failures are operational failures instead of silent degradation.
& $grype --config $config db update
if ($LASTEXITCODE -ne 0) {
    throw "Grype vulnerability database update failed."
}

$dbStatusText = (& $grype --config $config db status -o json | Out-String)
if ($LASTEXITCODE -ne 0) {
    throw "Grype vulnerability database status check failed."
}
try {
    $dbStatus = $dbStatusText | ConvertFrom-Json
}
catch {
    throw "Grype vulnerability database status output was not valid JSON: $($_.Exception.Message)"
}
if (-not $dbStatus.valid) {
    throw "Grype vulnerability database is not valid: $($dbStatus.error)"
}

Write-Host "Grype vulnerability database ready."
Write-Host "  Schema: $($dbStatus.schemaVersion)"
Write-Host "  Built:  $($dbStatus.built)"
Write-Host "  From:   $($dbStatus.from)"
Write-Host "  Valid:  $($dbStatus.valid)"

# The canonical scan source is the already-generated and validated SPDX SBOM.
# Step 10 intentionally uses no --fail-on, --only-fixed, ignore rule, or VEX suppression.
& $grype --config $config "sbom:$($sbom.FullName)" -o json --file $reportPath
if ($LASTEXITCODE -ne 0) {
    throw "Grype failed while scanning validated SPDX SBOM '$($sbom.FullName)'."
}
if (-not (Test-Path $reportPath)) {
    throw "Grype completed without producing the expected vulnerability report: $reportPath"
}
if ((Get-Item $reportPath).Length -le 0) {
    throw "Grype produced an empty vulnerability report: $reportPath"
}

Write-Host "Generated point-in-time vulnerability report."
Write-Host "  ZIP:    $($zip.FullName)"
Write-Host "  SBOM:   $($sbom.FullName)"
Write-Host "  Report: $reportPath"
