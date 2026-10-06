[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$SyftPath,

    [Parameter(Mandatory = $true)]
    [string]$ExtensionName,

    [Parameter(Mandatory = $true)]
    [string]$ExtensionVersion,

    [string]$DistDir = "dist"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not (Test-Path $SyftPath)) {
    throw "Syft executable was not found: $SyftPath"
}
if (-not (Test-Path $DistDir)) {
    throw "Package dist directory was not found: $DistDir"
}

$zipFiles = @(Get-ChildItem -Path $DistDir -Filter "*.zip" -File)
if ($zipFiles.Count -ne 1) {
    throw "Expected exactly one final ZIP for SBOM generation, found $($zipFiles.Count)."
}

$zip = $zipFiles[0]
if (-not $zip.BaseName.StartsWith("$ExtensionName-", [System.StringComparison]::Ordinal)) {
    throw "Final ZIP '$($zip.Name)' does not match expected extension '$ExtensionName'."
}

$sbomPath = Join-Path $zip.DirectoryName "$($zip.BaseName).spdx.json"
if (Test-Path $sbomPath) {
    Remove-Item -Path $sbomPath -Force
}

# The source package identifies the exact distributable ZIP. "pgextwin" is the
# package supplier/distributor; it is not presented as the upstream author.
$env:SYFT_CHECK_FOR_APP_UPDATE = "false"
& $SyftPath scan $zip.FullName `
    --output "spdx-json@2.3=$sbomPath" `
    --source-name $zip.BaseName `
    --source-version $ExtensionVersion `
    --source-supplier "pgextwin"

if ($LASTEXITCODE -ne 0) {
    throw "Syft failed while scanning final ZIP '$($zip.Name)'."
}
if (-not (Test-Path $sbomPath)) {
    throw "Syft completed without producing the expected SPDX JSON: $sbomPath"
}
if ((Get-Item $sbomPath).Length -le 0) {
    throw "Syft produced an empty SPDX JSON file: $sbomPath"
}

Write-Host "Generated SPDX 2.3 JSON SBOM from final ZIP."
Write-Host "  ZIP:  $($zip.FullName)"
Write-Host "  SBOM: $sbomPath"
