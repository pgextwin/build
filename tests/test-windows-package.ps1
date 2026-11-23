[CmdletBinding()]
param([string]$OutputPath = 'windows-package-contract.json')

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '../scripts/windows-package.ps1')

function New-TestMap {
    return @{
        schemaVersion = 1; distribution = 'sql-only'
        files = @(
            @{ source = 'upstream'; path = 'example.control'; destination = 'share/extension/example.control'; targets = @('install', 'zip') }
            @{ source = 'upstream'; path = 'example--*.sql'; destination = 'share/extension/{fileName}'; targets = @('install', 'zip')
                expectedCount = 2; requiredMatches = @('example--{version}.sql', 'example--1.0--2.0.sql') }
            @{ source = 'upstream'; path = 'README.md'; destination = 'UPSTREAM-README.md'; targets = @('zip'); optional = $true }
            @{ source = 'license'; path = 'LICENSE'; destination = 'LICENSE'; targets = @('zip') }
        )
        packageInfo = @(
            'Upstream repository: {upstreamRepository}', 'Upstream ref: {upstreamRef}', 'Upstream commit: {upstreamCommit}',
            'PostgreSQL major: {pgMajor}', 'PostgreSQL tested: {pgTested}', 'Architecture: {architecture}'
        )
    }
}

function Invoke-ContractCase {
    param([string]$Name, [scriptblock]$Setup, [string]$ExpectedError)
    $caseDir = Join-Path $work $Name
    $upstream = Join-Path $caseDir 'upstream'
    $verifiedStage = Join-Path $caseDir 'verified'
    $pgRoot = Join-Path $caseDir 'pg-new'
    [void][IO.Directory]::CreateDirectory($upstream)
    [void][IO.Directory]::CreateDirectory($verifiedStage)
    [void][IO.Directory]::CreateDirectory($pgRoot)
    Set-Content -LiteralPath (Join-Path $upstream 'example.control') -Value "default_version = '2.0'"
    Set-Content -LiteralPath (Join-Path $upstream 'example--2.0.sql') -Value 'SELECT 1;'
    Set-Content -LiteralPath (Join-Path $upstream 'example--1.0--2.0.sql') -Value 'SELECT 2;'
    [IO.File]::WriteAllBytes((Join-Path $verifiedStage 'LICENSE'), [byte[]]@(65, 10, 66))
    $verified = @{
        schemaVersion = 1; upstreamCommit = $tokens.upstreamCommit
        licenses = @(@{ repositoryPath = 'LICENSE'; upstreamPath = 'LICENSE'; size = 3
            sha256 = (Get-FileHash -LiteralPath (Join-Path $verifiedStage 'LICENSE')).Hash.ToLowerInvariant() })
    }
    $map = New-TestMap
    & $Setup
    $mapPath = Join-Path $caseDir 'package.json'
    $map | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $mapPath
    $case = @{ name = $Name; exitCode = 0; expectedExitCode = [int][bool]$ExpectedError }
    try {
        $plan = Resolve-WindowsPackage $mapPath $caseDir $upstream (Join-Path $caseDir 'build') $verifiedStage $verified $tokens
        Copy-PackageFiles $plan $pgRoot install
        $stage = Join-Path $caseDir 'package'
        $list = Join-Path $caseDir 'verified-license-list.json'
        Write-WindowsPackageStage $plan $stage $list

        $oldShare = Join-Path $caseDir 'pg-old/share/extension'
        [void][IO.Directory]::CreateDirectory($oldShare)
        Copy-Item -LiteralPath (Join-Path $upstream 'example.control') -Destination $oldShare
        Get-ChildItem -LiteralPath $upstream -File -Filter 'example--*.sql' | Copy-Item -Destination $oldShare
        $case.before = @(Get-ChildItem -LiteralPath $oldShare -File | Sort-Object Name | ForEach-Object {
            @{ path = "share/extension/$($_.Name)"; size = $_.Length; sha256 = (Get-FileHash -LiteralPath $_.FullName).Hash }
        })
        $case.after = @(Get-ChildItem -LiteralPath (Join-Path $pgRoot 'share/extension') -File | Sort-Object Name | ForEach-Object {
            @{ path = "share/extension/$($_.Name)"; size = $_.Length; sha256 = (Get-FileHash -LiteralPath $_.FullName).Hash }
        })
        foreach ($file in $case.before) {
            $oldBytes = [IO.File]::ReadAllBytes((Join-Path $caseDir "pg-old/$($file.path)"))
            $newBytes = [IO.File]::ReadAllBytes((Join-Path $pgRoot $file.path))
            if ([Convert]::ToBase64String($oldBytes) -cne [Convert]::ToBase64String($newBytes)) {
                throw "Installed bytes differ at '$($file.path)'."
            }
        }
        if ($case.before.Count -ne $case.after.Count) { throw 'Installed path count differs.' }

        $asset = 'example-2.0-pg17-windows-x64.zip'
        $metadata = @{
            ExtensionName = 'example'; UpstreamDir = $upstream; PackagingCommit = ('a' * 40)
            UpstreamCommit = $tokens.upstreamCommit; UpstreamRepository = $tokens.upstreamRepository
            UpstreamRef = $tokens.upstreamRef; UpstreamVersion = $tokens.version
            PostgreSqlMajor = 17; PostgreSqlTestedVersion = '17.11'; ChocolateyPackage = 'postgresql17'
            ChocolateyPackageVersion = '17.11.4'; PackagingRepository = 'pgextwin/example'
            BuildRepository = 'pgextwin/build'; BuildCommit = ('b' * 40); BuildCheckoutCommit = ('b' * 40)
            ReusableWorkflow = '.github/workflows/build-extension.yml'; BuildMode = 'normal'
            WorkflowRunId = 1; WorkflowRunAttempt = 1; WorkflowRunUrl = 'https://github.com/pgextwin/example/actions/runs/1'
            WorkflowEvent = 'pull_request'; WorkflowRef = 'refs/pull/1/merge'
            DistDir = (Join-Path $caseDir 'dist'); StageDir = $stage; AssetName = $asset; VerifiedLicenseList = $list
        }
        if ($Name -eq 'zip-license-modified') {
            [IO.File]::WriteAllBytes((Join-Path $stage 'LICENSE'), [byte[]]@(70, 10, 66))
        }
        & (Join-Path $PSScriptRoot '../scripts/finalize-package.ps1') @metadata
        if (!(Test-Path -LiteralPath (Join-Path $metadata.DistDir $asset))) { throw 'Verified ZIP was not produced.' }
    } catch {
        $case.exitCode = 1
        $case.error = $_.Exception.Message
    }
    $case.passed = $case.exitCode -eq $case.expectedExitCode -and (!$ExpectedError -or $case.error -like "*$ExpectedError*")
    return $case
}

$tokens = @{
    extensionName = 'example'; upstreamRepository = 'sample/example'; upstreamCommit = ('c' * 40)
    upstreamRef = '2.0'; version = '2.0'; pgMajor = '17'; pgTested = '17.11'; architecture = 'Windows x64'
}
$work = [IO.Directory]::CreateTempSubdirectory('pgextwin-contract-').FullName
try {
    $cases = @(
        Invoke-ContractCase valid {}
        Invoke-ContractCase missing { Remove-Item -LiteralPath (Join-Path $upstream 'example.control') } 'Required package file missing'
        Invoke-ContractCase extra-glob { New-Item -ItemType File -Path (Join-Path $upstream 'example--unexpected.sql') | Out-Null } 'Expected 2 matches'
        Invoke-ContractCase wrong-glob { Rename-Item -LiteralPath (Join-Path $upstream 'example--2.0.sql') 'example--unexpected.sql' } 'Required glob match'
        Invoke-ContractCase control-version { Set-Content -LiteralPath (Join-Path $upstream 'example.control') -Value "default_version = '1.0'" } 'Control default_version'
        Invoke-ContractCase absolute { $map.files[0].path = 'C:/example.control' } 'Invalid relative'
        Invoke-ContractCase parent-relative { $map.files[0].path = '../example.control' } 'Invalid relative'
        Invoke-ContractCase outside-root {
            $outside = Join-Path $caseDir 'outside'
            [void][IO.Directory]::CreateDirectory($outside)
            $link = Join-Path $upstream 'link'
            $type = if ($IsWindows) { 'Junction' } else { 'SymbolicLink' }
            New-Item -ItemType $type -Path $link -Target $outside | Out-Null
            $map.files[0].path = 'link/example.control'
        } 'Reparse point'
        Invoke-ContractCase collision {
            $map.files += @{ source = 'upstream'; path = 'example.control'; destination = 'SHARE/extension/EXAMPLE.control'; targets = @('zip') }
        } 'Conflicting zip destination'
        Invoke-ContractCase reserved {
            $map.files += @{ source = 'upstream'; path = 'example.control'; destination = 'PACKAGE-INFO.txt'; targets = @('zip') }
        } 'Reserved package destination'
        Invoke-ContractCase sql-with-dll {
            New-Item -ItemType File -Path (Join-Path $upstream 'example.dll') | Out-Null
            $map.files += @{ source = 'upstream'; path = 'example.dll'; destination = 'lib/example.dll'; targets = @('zip') }
        } 'SQL-only package cannot contain a DLL'
        Invoke-ContractCase license-missing { Remove-Item -LiteralPath (Join-Path $verifiedStage 'LICENSE') } 'Required package file missing'
        Invoke-ContractCase license-modified { [IO.File]::WriteAllBytes((Join-Path $verifiedStage 'LICENSE'), [byte[]]@(70, 10, 66)) } 'Verified license bytes changed'
        Invoke-ContractCase license-bypass {
            New-Item -ItemType File -Path (Join-Path $upstream 'LICENSE') | Out-Null
            $map.files[3].source = 'upstream'
        } 'must come from the verification stage'
        Invoke-ContractCase zip-license-modified {} 'Final package ZIP license bytes differ'
    )
    @{ schemaVersion = 1; platform = $PSVersionTable.OS; cases = $cases } |
        ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $OutputPath -Encoding utf8
    $failed = @($cases | Where-Object { !$_.passed })
    if ($failed.Count) { throw ('Unexpected contract results: ' + ($failed | ConvertTo-Json -Depth 8)) }
    Write-Host "Passed $($cases.Count) Windows package contract cases."
} finally {
    Remove-Item -LiteralPath $work -Recurse -Force
}
