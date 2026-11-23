[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('Prepare', 'Finalize')][string]$Action,
    [Parameter(Mandatory)][string]$WorkDir,
    [Parameter(Mandatory)][string]$MatrixJson,
    [Parameter(Mandatory)][string]$ExtensionName,
    [Parameter(Mandatory)][string]$UpstreamRepository,
    [Parameter(Mandatory)][string]$BuildRepository,
    [Parameter(Mandatory)][string]$BuildCommit,
    [Parameter(Mandatory)][ValidateSet('normal', 'release-attested')][string]$BuildMode,
    [switch]$VerifyLicense
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'windows-package.ps1')

$matrix = $MatrixJson | ConvertFrom-Json
$packagingDir = $PWD.Path
$upstreamDir = Join-Path $packagingDir 'upstream'
$hooks = Join-Path $packagingDir 'windows/ci'
$map = Join-Path $hooks 'package.json'
$buildHook = Join-Path $hooks 'build.ps1'
$tokens = Get-PackageTokens $ExtensionName $UpstreamRepository $matrix $upstreamDir
$stage = Join-Path $WorkDir 'package'
$licenseList = Join-Path $WorkDir 'verified-license-list.json'
if ($Action -eq 'Finalize') {
    $workflow = if ($BuildMode -eq 'normal') { 'build-extension.yml' } else { 'build-extension-attested.yml' }
    $finalizer = Get-PackageFinalizerInputs $tokens $packagingDir $upstreamDir $env:GITHUB_REPOSITORY `
        $BuildRepository $BuildCommit $BuildMode ".github/workflows/$workflow"
    & (Join-Path $PSScriptRoot 'finalize-package.ps1') @finalizer `
        -StageDir $stage -AssetName (Get-WindowsPackageAssetName $tokens) -VerifiedLicenseList $licenseList
    return
}

if (!$VerifyLicense -or !$matrix.upstreamCommit) {
    throw 'The package map requires a pinned upstream commit and upstream license verification.'
}
$licenses = Invoke-PackageLicenseVerification $matrix $packagingDir $upstreamDir $WorkDir

if (Test-Path -LiteralPath $buildHook) {
    & $buildHook -PgRoot $env:PGROOT -UpstreamDir $upstreamDir
}
$plan = Resolve-WindowsPackage $map $packagingDir $upstreamDir (Join-Path $packagingDir 'build') `
    $licenses.stage $licenses.verified $tokens
Copy-PackageFiles $plan $env:PGROOT install
& (Join-Path $hooks 'smoke-test.ps1') -PgRoot $env:PGROOT -PgPort ([int]$env:PGPORT) -PostgreSqlMajor $matrix.major
Write-WindowsPackageStage $plan $stage $licenseList
