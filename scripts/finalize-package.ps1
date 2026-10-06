[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ExtensionName,

    [Parameter(Mandatory = $true)]
    [string]$UpstreamDir,

    [Parameter(Mandatory = $true)]
    [string]$UpstreamRepository,

    [Parameter(Mandatory = $true)]
    [string]$UpstreamRef,

    [Parameter(Mandatory = $true)]
    [string]$UpstreamVersion,

    [Parameter(Mandatory = $true)]
    [int]$PostgreSqlMajor,

    [Parameter(Mandatory = $true)]
    [string]$PostgreSqlTestedVersion,

    [Parameter(Mandatory = $true)]
    [string]$ChocolateyPackage,

    [Parameter(Mandatory = $true)]
    [string]$ChocolateyPackageVersion,

    [Parameter(Mandatory = $true)]
    [string]$PackagingRepository,

    [Parameter(Mandatory = $true)]
    [string]$BuildRepository,

    [Parameter(Mandatory = $true)]
    [string]$BuildCommit,

    [Parameter(Mandatory = $true)]
    [string]$ReusableWorkflow,

    [Parameter(Mandatory = $true)]
    [ValidateSet("normal", "release-attested")]
    [string]$BuildMode,

    [Parameter(Mandatory = $true)]
    [long]$WorkflowRunId,

    [Parameter(Mandatory = $true)]
    [int]$WorkflowRunAttempt,

    [Parameter(Mandatory = $true)]
    [string]$WorkflowRunUrl,

    [Parameter(Mandatory = $true)]
    [string]$WorkflowEvent,

    [Parameter(Mandatory = $true)]
    [string]$WorkflowRef,

    [string]$DistDir = "dist",
    [string]$PackagingDir = ".",
    [string]$BuildInfrastructureDir = ".pgextwin-build",
    [string]$RequestedRunnerLabel = "windows-latest",
    [string]$PackagingCommit,
    [string]$UpstreamCommit,
    [string]$BuildCheckoutCommit,
    [string]$CompilerVersion,
    [string]$RunnerOs = $env:RUNNER_OS,
    [string]$RunnerArchitecture = $env:RUNNER_ARCH,
    [string]$RunnerImageOs = $env:ImageOS,
    [string]$RunnerImageVersion = $env:ImageVersion
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Resolve-GitCommit {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepositoryPath,

        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    $sha = (& git -C $RepositoryPath rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($sha)) {
        throw "Failed to resolve $Description commit SHA from '$RepositoryPath'."
    }

    return $sha.ToLowerInvariant()
}

function Assert-FullSha {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if ($Value -notmatch '^[0-9a-fA-F]{40}$') {
        throw "$Name must be an exact 40-character Git commit SHA."
    }
}

function Resolve-MsvcCompilerVersion {
    param([string]$Override)

    if (-not [string]::IsNullOrWhiteSpace($Override)) {
        return $Override
    }

    $candidates = New-Object System.Collections.Generic.List[string]
    $command = Get-Command "cl.exe" -ErrorAction SilentlyContinue
    if ($null -ne $command) {
        $candidates.Add($command.Source)
    }

    $programFilesX86 = [Environment]::GetEnvironmentVariable("ProgramFiles(x86)")
    if (-not [string]::IsNullOrWhiteSpace($programFilesX86)) {
        $vswhere = Join-Path $programFilesX86 "Microsoft Visual Studio\Installer\vswhere.exe"
        if (Test-Path $vswhere) {
            $installation = [string](& $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath | Select-Object -First 1)
            if (-not [string]::IsNullOrWhiteSpace($installation)) {
                $toolsRoot = Join-Path $installation.Trim() "VC\Tools\MSVC"
                $toolRoots = @(Get-ChildItem -Path $toolsRoot -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending)
                foreach ($toolRoot in $toolRoots) {
                    $candidate = Join-Path $toolRoot.FullName "bin\Hostx64\x64\cl.exe"
                    if (Test-Path $candidate) {
                        $candidates.Add($candidate)
                    }
                }
            }
        }
    }

    foreach ($candidate in $candidates | Select-Object -Unique) {
        $fileVersion = [string](Get-Item $candidate).VersionInfo.FileVersion
        $match = [regex]::Match($fileVersion, '([0-9]+(?:\.[0-9]+){2,4})')
        if ($match.Success) {
            return $match.Groups[1].Value
        }
    }

    Write-Warning "Unable to resolve the actual cl.exe file version. toolchain.compilerVersion will be null."
    return $null
}

function Get-PackageInfoField {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Text,

        [Parameter(Mandatory = $true)]
        [string]$Label
    )

    $pattern = '(?m)^' + [regex]::Escape($Label) + ':\s*(.+?)\s*$'
    $match = [regex]::Match($Text, $pattern)
    if (-not $match.Success) {
        throw "PACKAGE-INFO.txt is missing required compatibility field '$Label'."
    }

    return $match.Groups[1].Value.Trim()
}

function Assert-PackageInfoField {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Text,

        [Parameter(Mandatory = $true)]
        [string]$Label,

        [Parameter(Mandatory = $true)]
        [string]$Expected
    )

    $actual = Get-PackageInfoField -Text $Text -Label $Label
    if ($actual -ne $Expected) {
        throw "PACKAGE-INFO.txt field '$Label' disagrees with PACKAGE-INFO.json input. Expected '$Expected', found '$actual'."
    }
}

if (-not (Test-Path $DistDir)) {
    throw "Package dist directory was not found: $DistDir"
}

$stageDirectories = @(Get-ChildItem -Path $DistDir -Directory)
$zipFiles = @(Get-ChildItem -Path $DistDir -Filter "*.zip" -File)

if ($stageDirectories.Count -ne 1) {
    throw "Expected exactly one package staging directory under '$DistDir', found $($stageDirectories.Count)."
}
if ($zipFiles.Count -ne 1) {
    throw "Expected exactly one package ZIP under '$DistDir', found $($zipFiles.Count)."
}

$stage = $stageDirectories[0]
$zipPath = $zipFiles[0].FullName
$packageInfoTextPath = Join-Path $stage.FullName "PACKAGE-INFO.txt"
if (-not (Test-Path $packageInfoTextPath)) {
    throw "Existing human-readable PACKAGE-INFO.txt was not found in staging directory."
}

if ([string]::IsNullOrWhiteSpace($PackagingCommit)) {
    $PackagingCommit = Resolve-GitCommit -RepositoryPath $PackagingDir -Description "packaging repository"
}
if ([string]::IsNullOrWhiteSpace($UpstreamCommit)) {
    $UpstreamCommit = Resolve-GitCommit -RepositoryPath $UpstreamDir -Description "upstream repository"
}
if ([string]::IsNullOrWhiteSpace($BuildCheckoutCommit)) {
    $BuildCheckoutCommit = Resolve-GitCommit -RepositoryPath $BuildInfrastructureDir -Description "shared build infrastructure"
}

$PackagingCommit = $PackagingCommit.ToLowerInvariant()
$UpstreamCommit = $UpstreamCommit.ToLowerInvariant()
$BuildCommit = $BuildCommit.ToLowerInvariant()
$BuildCheckoutCommit = $BuildCheckoutCommit.ToLowerInvariant()

Assert-FullSha -Value $PackagingCommit -Name "PackagingCommit"
Assert-FullSha -Value $UpstreamCommit -Name "UpstreamCommit"
Assert-FullSha -Value $BuildCommit -Name "BuildCommit"
Assert-FullSha -Value $BuildCheckoutCommit -Name "BuildCheckoutCommit"

if ($BuildCheckoutCommit -ne $BuildCommit) {
    throw "Checked-out pgextwin/build commit '$BuildCheckoutCommit' does not match job.workflow_sha '$BuildCommit'."
}

$compilerVersionValue = Resolve-MsvcCompilerVersion -Override $CompilerVersion

$runnerOsValue = if ([string]::IsNullOrWhiteSpace($RunnerOs)) { "Windows" } else { $RunnerOs }
$runnerArchitectureValue = if ([string]::IsNullOrWhiteSpace($RunnerArchitecture)) { "X64" } else { $RunnerArchitecture }
$runnerImageOsValue = if ([string]::IsNullOrWhiteSpace($RunnerImageOs)) { $null } else { $RunnerImageOs }
$runnerImageVersionValue = if ([string]::IsNullOrWhiteSpace($RunnerImageVersion)) { $null } else { $RunnerImageVersion }

$metadata = [ordered]@{
    schemaVersion = 1
    buildMode = $BuildMode
    package = [ordered]@{
        name = $ExtensionName
        platform = "windows"
        architecture = "x64"
    }
    upstream = [ordered]@{
        repository = $UpstreamRepository
        ref = $UpstreamRef
        version = $UpstreamVersion
        commit = $UpstreamCommit
    }
    source = [ordered]@{
        packagingRepository = $PackagingRepository
        packagingCommit = $PackagingCommit
    }
    buildInfrastructure = [ordered]@{
        repository = $BuildRepository
        commit = $BuildCheckoutCommit
        workflow = $ReusableWorkflow
    }
    postgresql = [ordered]@{
        major = $PostgreSqlMajor
        testedVersion = $PostgreSqlTestedVersion
        installation = [ordered]@{
            packageManager = "chocolatey"
            package = $ChocolateyPackage
            packageVersion = $ChocolateyPackageVersion
        }
    }
    toolchain = [ordered]@{
        compiler = "MSVC"
        compilerVersion = $compilerVersionValue
    }
    workflowRun = [ordered]@{
        id = $WorkflowRunId
        attempt = $WorkflowRunAttempt
        url = $WorkflowRunUrl
        event = $WorkflowEvent
        ref = $WorkflowRef
    }
    runner = [ordered]@{
        os = $runnerOsValue
        architecture = $runnerArchitectureValue
        requestedLabel = $RequestedRunnerLabel
        imageOS = $runnerImageOsValue
        imageVersion = $runnerImageVersionValue
    }
}

$packageInfoText = Get-Content -Path $packageInfoTextPath -Raw
Assert-PackageInfoField -Text $packageInfoText -Label "Upstream repository" -Expected $UpstreamRepository
Assert-PackageInfoField -Text $packageInfoText -Label "Upstream ref" -Expected $UpstreamRef
Assert-PackageInfoField -Text $packageInfoText -Label "Upstream commit" -Expected $UpstreamCommit
Assert-PackageInfoField -Text $packageInfoText -Label "PostgreSQL major" -Expected ([string]$PostgreSqlMajor)
Assert-PackageInfoField -Text $packageInfoText -Label "PostgreSQL tested" -Expected $PostgreSqlTestedVersion
Assert-PackageInfoField -Text $packageInfoText -Label "Architecture" -Expected "Windows x64"

$jsonPath = Join-Path $stage.FullName "PACKAGE-INFO.json"
$json = $metadata | ConvertTo-Json -Depth 8
Set-Content -Path $jsonPath -Value $json -Encoding utf8

Remove-Item -Path $zipPath -Force
Compress-Archive -Path (Join-Path $stage.FullName "*") -DestinationPath $zipPath -CompressionLevel Optimal

if (-not (Test-Path $zipPath)) {
    throw "Final package ZIP was not produced: $zipPath"
}

Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive = [System.IO.Compression.ZipFile]::OpenRead($zipPath)
try {
    $entry = $archive.GetEntry("PACKAGE-INFO.json")
    if ($null -eq $entry) {
        throw "Final package ZIP does not contain root PACKAGE-INFO.json."
    }

    $reader = New-Object System.IO.StreamReader($entry.Open(), [System.Text.Encoding]::UTF8, $true)
    try {
        $embeddedJson = $reader.ReadToEnd()
    }
    finally {
        $reader.Dispose()
    }

    $embedded = $embeddedJson | ConvertFrom-Json
    if ($embedded.schemaVersion -ne 1 -or $embedded.package.name -ne $ExtensionName) {
        throw "Embedded PACKAGE-INFO.json did not survive final ZIP generation intact."
    }
}
finally {
    $archive.Dispose()
}

Write-Host "Finalized package metadata and rebuilt: $zipPath"
