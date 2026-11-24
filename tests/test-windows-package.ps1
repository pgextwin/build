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
    $sourceStage = Join-Path $caseDir 'verified-sources'
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
    $mapPath = Join-Path $caseDir 'package.json'
    $case = @{ name = $Name; exitCode = 0; expectedExitCode = [int][bool]$ExpectedError }
    try {
        & $Setup
        $map | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $mapPath
        $verified = $verified | ConvertTo-Json -Depth 8 | ConvertFrom-Json
        $plan = Resolve-WindowsPackage $mapPath $caseDir $upstream (Join-Path $caseDir 'build') $verifiedStage $verified $tokens -LicenseSourceStage $sourceStage
        Copy-PackageFiles $plan $pgRoot install
        $stage = Join-Path $caseDir 'package'
        $list = Join-Path $caseDir 'verified-license-list.json'
        Write-WindowsPackageStage $plan $stage $list
        if ($Name -eq 'license-readme-range') {
            $readme = Join-Path $stage 'UPSTREAM-README.md'
            $source = Join-Path $sourceStage 'README.md'
            if ((Get-FileHash $readme).Hash -cne (Get-FileHash $source).Hash) {
                throw 'The staged documentation differs from the verified source blob.'
            }
            $record = Get-Content -LiteralPath $list -Raw | ConvertFrom-Json
            if ($record.licenses[0].upstreamOffset -ne 2) { throw 'The license offset is absent from the evidence.' }
            $info = [IO.File]::ReadAllText((Join-Path $stage 'PACKAGE-INFO.txt'))
            if ($info -match '[\r\n]$') { throw 'Unexpected terminal newline in PACKAGE-INFO.txt.' }
        }

        $oldRoot = Join-Path $caseDir 'pg-old'
        $oldShare = Join-Path $oldRoot 'share/extension'
        [void][IO.Directory]::CreateDirectory($oldShare)
        Copy-Item -LiteralPath (Join-Path $upstream 'example.control') -Destination $oldShare
        Get-ChildItem -LiteralPath $upstream -File -Filter 'example--*.sql' | Copy-Item -Destination $oldShare
        if ($map.distribution -eq 'dll-sql') {
            $oldLib = Join-Path $oldRoot 'lib'
            [void][IO.Directory]::CreateDirectory($oldLib)
            Copy-Item -LiteralPath (Join-Path $caseDir 'build/Release/example.dll') -Destination $oldLib
        }
        foreach ($target in @('before', 'after')) {
            $root = if ($target -eq 'before') { $oldRoot } else { $pgRoot }
            $case[$target] = @(Get-ChildItem -LiteralPath $root -Recurse -File | Sort-Object FullName | ForEach-Object {
                @{ path = [IO.Path]::GetRelativePath($root, $_.FullName).Replace('\', '/')
                    size = $_.Length; sha256 = (Get-FileHash -LiteralPath $_.FullName).Hash }
            })
        }
        foreach ($file in $case.before) {
            $oldBytes = [IO.File]::ReadAllBytes((Join-Path $oldRoot $file.path))
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
        $zipPath = Join-Path $metadata.DistDir $asset
        if (!(Test-Path -LiteralPath $zipPath)) { throw 'Verified ZIP was not produced.' }
        if ($map.distribution -eq 'dll-sql') {
            $zip = [IO.Compression.ZipFile]::OpenRead($zipPath)
            try {
                $case.zipEntries = @($zip.Entries.FullName | Sort-Object)
                $optionalPath = 'upstream-scripts/dump-metadata'
                if (($optionalPath -cin $case.zipEntries) -ne (Test-Path -LiteralPath (Join-Path $upstream 'scripts/dump-metadata'))) {
                    throw 'ZIP-only optional file does not match source presence.'
                }
                foreach ($file in $case.before) {
                    $entry = $zip.GetEntry($file.path)
                    if (!$entry) { throw "Missing ZIP entry '$($file.path)'." }
                    $stream = $entry.Open()
                    try {
                        if ([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($stream)) -cne $file.sha256) {
                            throw "ZIP bytes differ at '$($file.path)'."
                        }
                    } finally { $stream.Dispose() }
                }
            } finally { $zip.Dispose() }
        }
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
$setLicenseRange = {
    [void][IO.Directory]::CreateDirectory($sourceStage)
    $readme = Join-Path $sourceStage 'README.md'
    $original = [byte[]]@(88, 10, 65, 10, 66)
    [IO.File]::WriteAllBytes($readme, $original)
    $verified.licenses[0].upstreamPath = 'README.md'
    $verified.licenses[0].upstreamOffset = 2
    $verified.licenses[0].upstreamSize = $original.Length
    $verified.licenses[0].upstreamSha256 = (Get-FileHash -LiteralPath $readme).Hash.ToLowerInvariant()
    $map.files[2] = @{ source = 'licenseDocument'; path = 'README.md'; destination = 'UPSTREAM-README.md'; targets = @('zip') }
    $map.packageInfoFinalNewline = $false
}
$setDll = {
    $map.distribution = 'dll-sql'
    [void][IO.Directory]::CreateDirectory((Join-Path $caseDir 'build/Release'))
    [IO.File]::WriteAllBytes((Join-Path $caseDir 'build/Release/example.dll'), [byte[]]@(77, 90, 0, 255))
    $map.files += @{ source = 'buildOutput'; path = 'Release/example.dll'; destination = 'lib/example.dll'; targets = @('install', 'zip') }
    $map.files += @{ source = 'upstream'; path = 'scripts/dump-metadata'; destination = 'upstream-scripts/dump-metadata'
        targets = @('zip'); optional = $true }
}
$setSqlInstallPath = {
    Rename-Item -LiteralPath (Join-Path $upstream 'example--2.0.sql') 'example--1.0.sql'
    $map.files[1].Remove('requiredMatches')
    $map.sqlInstallPath = @('1.0', '{version}')
}
$setSeparateSqlVersion = {
    & $setSqlInstallPath
    Rename-Item -LiteralPath (Join-Path $upstream 'example--1.0--2.0.sql') 'example--1.0--1.6.sql'
    Set-Content -LiteralPath (Join-Path $upstream 'example.control') -Value "default_version = '1.6'"
    $map.sqlVersion = '1.6'
    $map.sqlInstallPath = @('1.0', '1.6')
}
try {
    $cases = @(
        Invoke-ContractCase valid {}
        Invoke-ContractCase restore-worktrees {
            $original = [byte[]]@(65, 10, 66)
            foreach ($repo in @($upstream, $caseDir)) {
                $license = Join-Path $repo 'LICENSE'
                [IO.File]::WriteAllBytes($license, $original)
                git -C $repo init -q
                if ($LASTEXITCODE -ne 0) { throw "Could not initialize test Git repository." }
                git -C $repo -c core.autocrlf=false add LICENSE
                if ($LASTEXITCODE -ne 0) { throw "Could not stage test license." }
                git -C $repo -c user.name='test' -c user.email='test@example.invalid' commit -qm 'Pin test license'
                if ($LASTEXITCODE -ne 0) { throw "Could not commit test license." }
                [IO.File]::WriteAllBytes($license, [byte[]]@(65, 13, 10, 66))
            }
            $matrix = @{ licenseFiles = @(@{ repositoryPath = 'LICENSE'; upstreamPath = 'LICENSE' }) }
            $verification = Invoke-PackageLicenseVerification $matrix $caseDir $upstream $caseDir -RestoreWorktrees
            foreach ($folder in @($upstream, $caseDir, $verification.stage)) {
                $actual = [IO.File]::ReadAllBytes((Join-Path $folder 'LICENSE'))
                if ([Convert]::ToBase64String($actual) -cne [Convert]::ToBase64String($original)) {
                    throw "License restoration changed the original bytes."
                }
            }
        }
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
        Invoke-ContractCase dll-sql-optional-present {
            & $setDll
            & $setSqlInstallPath
            [void][IO.Directory]::CreateDirectory((Join-Path $upstream 'scripts'))
            Set-Content -LiteralPath (Join-Path $upstream 'scripts/dump-metadata') -Value 'metadata helper'
        }
        Invoke-ContractCase dll-sql-optional-absent { & $setDll }
        Invoke-ContractCase dll-wrong-destination {
            & $setDll
            $map.files[4].destination = 'bin/example.dll'
        } 'DLL destination must be under lib/'
        Invoke-ContractCase dll-missing {
            & $setDll
            Remove-Item -LiteralPath (Join-Path $caseDir 'build/Release/example.dll')
        } 'Required package file missing'
        Invoke-ContractCase sql-install-path-missing-upgrade {
            & $setSqlInstallPath
            Rename-Item -LiteralPath (Join-Path $upstream 'example--1.0--2.0.sql') 'example--1.0--3.0.sql'
        } "sqlInstallPath requires 'share/extension/example--1.0--2.0.sql'"
        Invoke-ContractCase sql-install-path-wrong-version {
            & $setSqlInstallPath
            $map.sqlInstallPath = @('1.0', '3.0')
        } 'end at the expected SQL version'
        Invoke-ContractCase separate-sql-version { & $setSeparateSqlVersion }
        Invoke-ContractCase separate-sql-version-control-mismatch {
            & $setSeparateSqlVersion
            Set-Content -LiteralPath (Join-Path $upstream 'example.control') -Value "default_version = '2.0'"
        } 'Control default_version'
        Invoke-ContractCase invalid-sql-version { $map.sqlVersion = '../1.6' } 'sqlVersion requires'
        Invoke-ContractCase license-readme-range { & $setLicenseRange }
        Invoke-ContractCase license-readme-tampered {
            & $setLicenseRange
            [IO.File]::WriteAllBytes((Join-Path $sourceStage 'README.md'), [byte[]]@(89, 10, 65, 10, 66))
        } 'Verified license bytes changed'
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
