[CmdletBinding()]
param(
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
$common = Test-Path -LiteralPath $map
$buildHook = Join-Path $hooks 'build.ps1'
$tokens = Get-PackageTokens $ExtensionName $UpstreamRepository $matrix $upstreamDir
$workflow = if ($BuildMode -eq 'normal') { 'build-extension.yml' } else { 'build-extension-attested.yml' }
$finalizer = Get-PackageFinalizerInputs $tokens $packagingDir $upstreamDir $env:GITHUB_REPOSITORY `
    $BuildRepository $BuildCommit $BuildMode ".github/workflows/$workflow"
$work = [IO.Directory]::CreateTempSubdirectory('pgextwin-package-').FullName

try {
    if ($common -and (!$VerifyLicense -or !$matrix.upstreamCommit)) {
        throw 'The package map requires a pinned upstream commit and upstream license verification.'
    }
    if ($VerifyLicense) {
        $licenses = Invoke-PackageLicenseVerification $matrix $packagingDir $upstreamDir $work -RestoreWorktrees:(!$common)
    }

    if (!$common -or (Test-Path -LiteralPath $buildHook)) {
        & $buildHook -PgRoot $env:PGROOT -UpstreamDir $upstreamDir
    }

    if ($common) {
        $plan = Resolve-WindowsPackage $map $packagingDir $upstreamDir (Join-Path $packagingDir 'build') `
            $licenses.stage $licenses.verified $tokens
        Copy-PackageFiles $plan $env:PGROOT install
    } else {
        & (Join-Path $hooks 'install.ps1') -PgRoot $env:PGROOT -UpstreamDir $upstreamDir
    }

    & (Join-Path $hooks 'smoke-test.ps1') -PgRoot $env:PGROOT -PgPort ([int]$env:PGPORT) -PostgreSqlMajor $matrix.major

    if ($common) {
        $stage = Join-Path $work 'package'
        $licenseList = Join-Path $work 'verified-license-list.json'
        Write-WindowsPackageStage $plan $stage $licenseList
        & (Join-Path $PSScriptRoot 'finalize-package.ps1') @finalizer `
            -StageDir $stage -AssetName (Get-WindowsPackageAssetName $tokens) -VerifiedLicenseList $licenseList
    } else {
        $legacy = Get-LegacyPackageInputs $tokens $upstreamDir
        & (Join-Path $hooks 'package.ps1') @legacy
        & (Join-Path $PSScriptRoot 'finalize-package.ps1') @finalizer
    }
} finally {
    Remove-Item -LiteralPath $work -Recurse -Force
}
