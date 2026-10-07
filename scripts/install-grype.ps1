param(
    [string]$DestinationRoot = ".pgextwin-tools\grype"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$Version = "0.120.1"
$AssetName = "grype_0.120.1_windows_amd64.zip"
$ExpectedSha256 = "32e3c811f31822d17592908bafdc6288aaaca3d52583c479167a8dc8399ed65d"
$DownloadUrl = "https://github.com/anchore/grype/releases/download/v$Version/$AssetName"

$destination = [System.IO.Path]::GetFullPath((Join-Path $PWD $DestinationRoot))
$archivePath = Join-Path ([System.IO.Path]::GetTempPath()) ("pgextwin-" + [Guid]::NewGuid().ToString("N") + "-" + $AssetName)

try {
    Write-Host "Installing Grype $Version from the checksum-pinned official Windows amd64 release asset."
    Invoke-WebRequest -Uri $DownloadUrl -OutFile $archivePath

    $actualSha256 = (Get-FileHash -Path $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualSha256 -ne $ExpectedSha256) {
        throw "Grype archive SHA-256 mismatch. Expected $ExpectedSha256, found $actualSha256."
    }

    if (Test-Path $destination) {
        Remove-Item -Recurse -Force $destination
    }
    New-Item -ItemType Directory -Force -Path $destination | Out-Null
    Expand-Archive -Path $archivePath -DestinationPath $destination -Force

    $grypeExe = Join-Path $destination "grype.exe"
    if (-not (Test-Path $grypeExe)) {
        throw "Grype archive did not contain the expected executable: $grypeExe"
    }

    $versionJson = (& $grypeExe version -o json | Out-String)
    if ($LASTEXITCODE -ne 0) {
        throw "Installed Grype executable failed version inspection."
    }

    $versionInfo = $versionJson | ConvertFrom-Json
    if ([string]$versionInfo.version -ne $Version) {
        throw "Installed Grype version mismatch. Expected $Version, found '$($versionInfo.version)'."
    }

    Write-Host "Grype installation verified."
    Write-Host "  Version: $Version"
    Write-Host "  Asset:   $AssetName"
    Write-Host "  SHA-256: $ExpectedSha256"
    Write-Host "  Path:    $grypeExe"
}
finally {
    if (Test-Path $archivePath) {
        Remove-Item -Force $archivePath
    }
}
