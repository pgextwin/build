[CmdletBinding()]
param(
    [string]$DestinationDir = ".pgextwin-tools\syft"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Supply-chain pin for the exact official Anchore Syft Windows release asset.
$SyftVersion = "1.54.1"
$SyftArchiveSha256 = "8b56e8285e295e0bbed26eeea9b16ed51c493be97ccdf42dae6326c84fe8e19f"
$ArchiveName = "syft_${SyftVersion}_windows_amd64.zip"
$DownloadUrl = "https://github.com/anchore/syft/releases/download/v${SyftVersion}/${ArchiveName}"

$destination = [System.IO.Path]::GetFullPath($DestinationDir)
$syftExe = Join-Path $destination "syft.exe"
$tempArchive = Join-Path ([System.IO.Path]::GetTempPath()) ("pgextwin-syft-" + [guid]::NewGuid().ToString("N") + ".zip")

try {
    if (Test-Path $destination) {
        Remove-Item -Path $destination -Recurse -Force
    }
    New-Item -ItemType Directory -Force -Path $destination | Out-Null

    Write-Host "Downloading Anchore Syft $SyftVersion from the exact official release asset."
    Invoke-WebRequest -Uri $DownloadUrl -OutFile $tempArchive -UseBasicParsing

    $actualSha256 = (Get-FileHash -Path $tempArchive -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualSha256 -ne $SyftArchiveSha256) {
        throw "Syft archive SHA-256 mismatch. Expected $SyftArchiveSha256, found $actualSha256."
    }

    Expand-Archive -Path $tempArchive -DestinationPath $destination -Force
    if (-not (Test-Path $syftExe)) {
        throw "Expected Syft executable was not found after extraction: $syftExe"
    }

    $versionOutput = (& $syftExe --version | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) {
        throw "Downloaded Syft executable failed its version check."
    }
    if ($versionOutput -notmatch ('(?<![0-9])' + [regex]::Escape($SyftVersion) + '(?![0-9])')) {
        throw "Downloaded Syft reported an unexpected version: '$versionOutput'"
    }

    Write-Host "Syft installation verified."
    Write-Host "  version: $SyftVersion"
    Write-Host "  archive SHA-256: $actualSha256"
    Write-Host "  executable: $syftExe"
}
finally {
    if (Test-Path $tempArchive) {
        Remove-Item -Path $tempArchive -Force
    }
}
