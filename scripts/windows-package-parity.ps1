[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$MatrixJson,
    [Parameter(Mandatory)][string]$ExtensionName,
    [Parameter(Mandatory)][string]$UpstreamRepository,
    [Parameter(Mandatory)][string]$PackagingRepository,
    [Parameter(Mandatory)][string]$BuildCommit
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'windows-package.ps1')

function Get-InstallationInventory {
    param([string]$Root)
    $items = @{}
    foreach ($directory in @('share/extension', 'lib', 'bin')) {
        foreach ($file in Get-ChildItem -LiteralPath (Join-Path $Root $directory) -Recurse -File) {
            $relative = [IO.Path]::GetRelativePath($Root, $file.FullName).Replace('\', '/')
            $items[$relative] = @{ size = $file.Length; sha256 = (Get-FileHash -LiteralPath $file.FullName).Hash.ToLowerInvariant() }
        }
    }
    return $items
}

function Get-PlacedFiles {
    param($Original, $Installed)
    $result = [ordered]@{}
    foreach ($path in ($Installed.Keys | Sort-Object -CaseSensitive)) {
        $item = $Installed[$path]
        if (!$Original.ContainsKey($path) -or $Original[$path].sha256 -cne $item.sha256) {
            $result[$path] = $item
        }
    }
    if (@($Original.Keys | Where-Object { !$Installed.ContainsKey($_) }).Count) {
        throw 'An installation removed files from the test PostgreSQL distribution.'
    }
    return $result | ConvertTo-Json -Depth 5
}

if ($env:GITHUB_EVENT_NAME -cne 'workflow_dispatch' -or $env:GITHUB_REF -cne 'refs/heads/main') {
    throw 'Run package parity from build main via workflow_dispatch.'
}
$matrix = $MatrixJson | ConvertFrom-Json
$root = $PWD.Path
$legacyDir = Join-Path $root 'legacy'
$candidateDir = Join-Path $root 'candidate'
$upstreamDir = Join-Path $root 'upstream'
$oldHooks = Join-Path $legacyDir 'windows/ci'
$tokens = Get-PackageTokens $ExtensionName $UpstreamRepository $matrix $upstreamDir
if (!$matrix.upstreamCommit) { throw 'Parity requires a pinned upstream commit.' }

$evidence = Join-Path $root 'parity'
[void][IO.Directory]::CreateDirectory($evidence)
$work = [IO.Directory]::CreateTempSubdirectory('pgextwin-parity-').FullName
try {
    $licenses = Invoke-PackageLicenseVerification $matrix $candidateDir $upstreamDir $work -RestoreWorktrees
    Push-Location $legacyDir
    try {
        & (Join-Path $oldHooks 'build.ps1') -PgRoot $env:PGROOT -UpstreamDir $upstreamDir
    } finally { Pop-Location }

    $plan = Resolve-WindowsPackage (Join-Path $candidateDir 'windows/ci/package.json') $candidateDir $upstreamDir `
        (Join-Path $candidateDir 'build') $licenses.stage $licenses.verified $tokens -LicenseSourceStage $licenses.sourceStage
    $afterPg = Join-Path $work 'postgresql'
    [void][IO.Directory]::CreateDirectory($afterPg)
    foreach ($directory in @('share', 'lib', 'bin')) {
        Copy-Item -LiteralPath (Join-Path $env:PGROOT $directory) -Destination $afterPg -Recurse
    }
    $original = Get-InstallationInventory $env:PGROOT
    & (Join-Path $oldHooks 'install.ps1') -PgRoot $env:PGROOT -UpstreamDir $upstreamDir
    Copy-PackageFiles $plan $afterPg install
    $beforeList = Get-PlacedFiles $original (Get-InstallationInventory $env:PGROOT)
    $afterList = Get-PlacedFiles $original (Get-InstallationInventory $afterPg)
    Set-Content -LiteralPath (Join-Path $evidence 'before-install.json') -Value $beforeList -Encoding utf8
    Set-Content -LiteralPath (Join-Path $evidence 'after-install.json') -Value $afterList -Encoding utf8
    $installEquivalent = $beforeList -ceq $afterList

    & (Join-Path $oldHooks 'smoke-test.ps1') -PgRoot $env:PGROOT -PgPort ([int]$env:PGPORT) -PostgreSqlMajor $matrix.major
    & (Join-Path $candidateDir 'windows/ci/smoke-test.ps1') -PgRoot $afterPg -PgPort ([int]$env:PGPORT) -PostgreSqlMajor $matrix.major

    $failures = [Collections.Generic.List[string]]::new()
    if (!$installEquivalent) { $failures.Add('Installed file paths or bytes differ.') }
    $asset = Get-WindowsPackageAssetName $tokens
    foreach ($mode in @('normal', 'release-attested')) {
        # Use a relative DistDir for legacy hooks that resolve it under their repository.
        $beforeDistName = "parity-dist-$mode"
        $beforeDist = Join-Path $legacyDir $beforeDistName
        if (Test-Path -LiteralPath $beforeDist) { throw "Legacy parity output already exists: '$beforeDist'." }
        $stage = Join-Path $work "$mode-stage"
        $afterDist = Join-Path $evidence "$mode/after"
        $beforeOut = Join-Path $evidence "$mode/before"
        [void][IO.Directory]::CreateDirectory($beforeOut)
        $licenseList = Join-Path $evidence 'verified-license-list.json'
        $workflow = if ($mode -eq 'release-attested') { 'build-extension-attested.yml' } else { 'build-extension.yml' }
        $finalizer = Get-PackageFinalizerInputs $tokens $candidateDir $upstreamDir $PackagingRepository `
            'pgextwin/build' $BuildCommit $mode ".github/workflows/$workflow"
        Write-WindowsPackageStage $plan $stage $licenseList
        $legacy = Get-LegacyPackageInputs $tokens $upstreamDir
        Push-Location $legacyDir
        try {
            & (Join-Path $oldHooks 'package.ps1') @legacy -DistDir $beforeDistName
        } finally { Pop-Location }
        & (Join-Path $PSScriptRoot 'finalize-package.ps1') @finalizer -DistDir $beforeDist `
            -VerifiedLicenseList $licenseList
        & (Join-Path $PSScriptRoot 'finalize-package.ps1') @finalizer -DistDir $afterDist `
            -StageDir $stage -AssetName $asset -VerifiedLicenseList $licenseList
        $beforeZips = @(Get-ChildItem -LiteralPath $beforeDist -File -Filter '*.zip')
        if ($beforeZips.Count -ne 1) { throw "Expected exactly one legacy ZIP for $mode." }
        Copy-Item -LiteralPath $beforeZips[0].FullName -Destination $beforeOut
        & python (Join-Path $PSScriptRoot 'compare-windows-packages.py') `
            --before (Join-Path $beforeOut $beforeZips[0].Name) --after (Join-Path $afterDist $asset) `
            --licenses $licenseList --output (Join-Path $evidence "package-equivalence-$mode-pg$($matrix.major).json")
        if ($LASTEXITCODE -ne 0) { $failures.Add("ZIP comparison failed for $mode.") }
    }
    if ($failures.Count) { throw ($failures -join ' ') }
} finally {
    Remove-Item -LiteralPath $work -Recurse -Force
}
