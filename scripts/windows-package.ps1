# Shared Windows placement, used by normal CI, signing and read-only parity.
Set-StrictMode -Version Latest

function Assert-PackageObject {
    param($Object, [string[]]$Required, [string[]]$Optional)
    if ($Object -isnot [System.Collections.IDictionary]) { throw 'Expected a JSON object in the package map.' }
    foreach ($key in $Required) {
        if ($key -cnotin $Object.Keys) { throw "Package map is missing '$key'." }
    }
    foreach ($key in $Object.Keys) {
        if ($key -cnotin ($Required + $Optional)) { throw "Unknown package map field '$key'." }
    }
}

function Assert-PackagePath {
    param([string]$Path, [switch]$Glob)
    $segments = $Path.Split('/')
    for ($i = 0; $i -lt $segments.Count; $i++) {
        $segment = $segments[$i]
        $invalid = if ($Glob -and $i -eq $segments.Count - 1) { '[<>:"\\|\[\]\x00-\x1f]' } else { '[<>:"\\|\[\]*?\x00-\x1f]' }
        if (!$segment -or $segment -match $invalid -or $segment -match '[ .]$' -or
            $segment -match '^(?:CON|PRN|AUX|NUL|COM[1-9¹²³]|LPT[1-9¹²³]|CONIN\$|CONOUT\$)(?:\.|$)') {
            throw "Invalid relative Windows package path '$Path'."
        }
    }
}

function Get-PackageItem {
    param([string]$Root, [string]$Path)
    Assert-PackagePath $Path
    $current = Get-Item -LiteralPath $Root -Force -ErrorAction SilentlyContinue
    if (!$current) { return }
    if (!$current.PSIsContainer -or ($current.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Invalid package root '$Root'."
    }
    foreach ($segment in $Path.Split('/')) {
        if (!$current.PSIsContainer) { throw "Non-directory parent in package path '$Path'." }
        $current = Get-Item -LiteralPath (Join-Path $current.FullName $segment) -Force -ErrorAction SilentlyContinue
        if (!$current) { return }
        if ($current.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "Reparse point in package path '$Path' under '$Root'."
        }
    }
    return $current
}

function Expand-PackageTokens {
    param([string]$Text, [System.Collections.IDictionary]$Tokens)
    return [regex]::Replace($Text, '\{([A-Za-z][A-Za-z0-9]*)\}', {
        param($match)
        $key = $match.Groups[1].Value
        if ($key -cnotin $Tokens.Keys) { throw "Unknown package token '$key'." }
        return [string]$Tokens[$key]
    })
}

function Assert-PackageLicenseBytes {
    param([IO.FileInfo]$File, $License)
    if ($File.Length -ne $License.size -or (Get-FileHash -LiteralPath $File.FullName).Hash -ine $License.sha256) {
        throw "Verified license bytes changed for '$($License.repositoryPath)'."
    }
}

function Resolve-WindowsPackage {
    param(
        [string]$MapPath, [string]$PackagingDir, [string]$UpstreamDir, [string]$BuildOutputDir,
        [string]$LicenseStage, $VerifiedLicenses, [System.Collections.IDictionary]$Tokens,
        [string]$LicenseSourceStage
    )
    $map = Get-Content -LiteralPath $MapPath -Raw | ConvertFrom-Json -AsHashtable
    Assert-PackageObject $map -Required @('schemaVersion', 'distribution', 'files', 'packageInfo') `
        -Optional @('packageInfoFinalNewline', 'sqlVersion', 'sqlInstallPath', 'perPostgresql')
    if ($map.Contains('packageInfoFinalNewline') -and $map.packageInfoFinalNewline -isnot [bool]) {
        throw 'packageInfoFinalNewline must be a boolean.'
    }
    if ($map.schemaVersion -isnot [long] -or $map.schemaVersion -ne 1 -or
        $map.distribution -cnotin @('sql-only', 'dll-sql', 'dll-only') -or
        $map.files -isnot [array] -or !$map.files.Count -or $map.packageInfo -isnot [array] -or !$map.packageInfo.Count) {
        throw 'Invalid schema version, distribution, files or packageInfo in package map.'
    }
    $filesForMajor = $map.files
    if ($map.Contains('perPostgresql')) {
        $series = $map.perPostgresql
        if ($series -isnot [System.Collections.IDictionary] -or !$series.Count) {
            throw 'perPostgresql must map PostgreSQL majors to package settings.'
        }
        foreach ($major in $series.Keys) {
            if ($major -cnotmatch '\A[1-9][0-9]*\z') { throw "Invalid PostgreSQL major '$major' in package map." }
            Assert-PackageObject $series[$major] -Optional @('sqlVersion', 'sqlInstallPath', 'files')
            if ($series[$major].Contains('files') -and ($series[$major].files -isnot [array] -or !$series[$major].files.Count)) {
                throw "Package files for PostgreSQL $major must be a nonempty array."
            }
        }
        $major = [string]$Tokens.pgMajor
        if (!$series.Contains($major)) { throw "Package map has no settings for PostgreSQL $major." }
        $settings = $series[$major]
        if ($settings.Contains('files')) { $filesForMajor += $settings.files }
        foreach ($key in @('sqlVersion', 'sqlInstallPath')) {
            if ($settings.Contains($key)) { $map[$key] = $settings[$key] }
        }
    }
    $sqlVersionPattern = '\A[A-Za-z0-9_.+]+(?:-[A-Za-z0-9_.+]+)*\z'
    $sqlVersion = $Tokens.version
    if ($map.Contains('sqlVersion')) {
        if ($map.distribution -eq 'dll-only' -or $map.sqlVersion -isnot [string] -or $map.sqlVersion -cnotmatch $sqlVersionPattern) {
            throw 'sqlVersion requires a valid PostgreSQL extension version in a package containing SQL.'
        }
        $sqlVersion = $map.sqlVersion
    }
    if ($map.Contains('sqlInstallPath') -and ($map.distribution -eq 'dll-only' -or
        $map.sqlInstallPath -isnot [array] -or $map.sqlInstallPath.Count -lt 2)) {
        throw 'sqlInstallPath requires an ordered list of at least two SQL versions.'
    }
    if ($null -eq $VerifiedLicenses -or $VerifiedLicenses.schemaVersion -ne 1 -or
        $VerifiedLicenses.upstreamCommit -cne $Tokens.upstreamCommit -or !$VerifiedLicenses.licenses.Count) {
        throw 'Package map requires licenses verified against this upstream commit.'
    }
    $roots = @{ upstream = $UpstreamDir; packaging = $PackagingDir; buildOutput = $BuildOutputDir; license = $LicenseStage
        licenseDocument = $LicenseSourceStage }
    $licenses = @{}
    foreach ($license in $VerifiedLicenses.licenses) {
        Assert-PackagePath $license.repositoryPath
        Assert-PackagePath $license.upstreamPath
        if ($licenses.ContainsKey($license.repositoryPath)) { throw "Duplicate verified license '$($license.repositoryPath)'." }
        $licenses.Add($license.repositoryPath, $license)
    }
    $sourceDocuments = @{}
    foreach ($license in $VerifiedLicenses.licenses) {
        if ($license.PSObject.Properties['upstreamOffset']) {
            $sourceDocuments[$license.upstreamPath] = @{
                size = $license.upstreamSize; sha256 = $license.upstreamSha256; repositoryPath = $license.upstreamPath
            }
        }
    }
    $matchedLicenses = @{}
    $files = [Collections.Generic.List[object]]::new()
    $destinations = @{ install = @{}; zip = @{} }
    foreach ($row in $filesForMajor) {
        Assert-PackageObject $row -Required @('source', 'path', 'destination', 'targets') -Optional @('optional', 'expectedCount', 'requiredMatches')
        if ($row.source -isnot [string] -or $row.source -cnotin $roots.Keys -or $row.path -isnot [string] -or
            $row.destination -isnot [string] -or $row.targets -isnot [array] -or !$row.targets.Count -or
            @($row.targets | Where-Object { $_ -cnotin @('install', 'zip') }).Count -or
            @($row.targets | Select-Object -Unique).Count -ne $row.targets.Count -or
            ($row.Contains('optional') -and $row['optional'] -isnot [bool])) {
            throw 'Invalid package row source, path, destination, targets or optional flag.'
        }
        $path = Expand-PackageTokens $row.path $Tokens
        $glob = $row.Contains('expectedCount')
        if ($row.source -eq 'licenseDocument' -and
            (!$LicenseSourceStage -or !$sourceDocuments.ContainsKey($path) -or $glob -or $row['optional'] -or
                $row.targets.Count -ne 1 -or $row.targets[0] -cne 'zip' -or $row.destination -cne 'UPSTREAM-README.md')) {
            throw "License document '$path' must use the verified source blob as UPSTREAM-README.md."
        }
        Assert-PackagePath $path -Glob:$glob
        if ($glob) {
            if ($row.source -eq 'license' -or $row['optional'] -or $row.expectedCount -isnot [long] -or
                $row.expectedCount -lt 1 -or $path.Split('/')[-1] -notmatch '[*?]' -or
                !$row.destination.Contains('{fileName}')) {
                throw "Invalid counted glob '$path'."
            }
            $segments = $path.Split('/')
            $parent = if ($segments.Count -eq 1) { Get-Item -LiteralPath $roots[$row.source] -Force -ErrorAction SilentlyContinue } else {
                Get-PackageItem $roots[$row.source] ($segments[0..($segments.Count - 2)] -join '/')
            }
            $matches = @()
            if ($parent) {
                if (!$parent.PSIsContainer -or ($parent.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                    throw "Invalid glob directory for '$path'."
                }
                $matches = @(Get-ChildItem -LiteralPath $parent.FullName -Force |
                    Where-Object Name -Like $segments[-1] | Sort-Object Name)
            }
            if ($matches.Count -ne $row.expectedCount) {
                throw "Expected $($row.expectedCount) matches for '$path', found $($matches.Count)."
            }
            if ($row.Contains('requiredMatches')) {
                if ($row.requiredMatches -isnot [array]) { throw "requiredMatches for '$path' must be an array." }
                foreach ($required in $row.requiredMatches) {
                    if ($required -isnot [string] -or (Expand-PackageTokens $required $Tokens) -cnotin $matches.Name) {
                        throw "Required glob match '$required' was not found for '$path'."
                    }
                }
            }
        } else {
            if ($row.Contains('requiredMatches')) { throw "requiredMatches requires a counted glob." }
            $matches = @(Get-PackageItem $roots[$row.source] $path)
            if (!$matches.Count -and !$row['optional']) { throw "Required package file missing: '$path'." }
        }
        if ($row.source -eq 'license' -and
            ($row['optional'] -or $row.targets.Count -ne 1 -or $row.targets[0] -cne 'zip' -or !$licenses.ContainsKey($path) -or $matchedLicenses.ContainsKey($path))) {
            throw "License '$path' must select one verified blob for ZIP placement."
        }
        foreach ($file in $matches) {
            if ($file -isnot [IO.FileInfo] -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                throw "Package source is not an ordinary file: '$($file.FullName)'."
            }
            $destination = Expand-PackageTokens $row.destination ($Tokens + @{ fileName = $file.Name })
            Assert-PackagePath $destination
            if ($destination -match '^PACKAGE-INFO\.(?:txt|json)(?:/|$)') { throw "Reserved package destination '$destination'." }
            $relative = [IO.Path]::GetRelativePath($roots[$row.source], $file.FullName).Replace('\', '/')
            if ($row.source -ne 'license') {
                $isLicenseName = '(?:^|/)(?:LICENSE|LICENCE|COPYING|COPYRIGHT|NOTICE)(?:[.\-_]|$)'
                if ($relative -match $isLicenseName -or $destination -match $isLicenseName -or
                    ($row.source -eq 'upstream' -and $relative -in $VerifiedLicenses.licenses.upstreamPath) -or
                    ($row.source -eq 'packaging' -and $licenses.ContainsKey($relative))) {
                    throw "License '$relative' must come from the verification stage."
                }
            }
            if ($map.distribution -eq 'sql-only' -and ($file.Extension -ieq '.dll' -or $destination -match '\.dll$')) {
                throw "SQL-only package cannot contain a DLL: '$destination'."
            }
            if (($file.Extension -ieq '.dll' -or $destination -match '\.dll$') -and $destination -notmatch '^lib/[^/]+$') {
                throw "DLL destination must be under lib/: '$destination'."
            }
            if ($destination -match '\.(?:sql|control)$' -and $destination -notmatch '^share/extension/[^/]+$') {
                throw "SQL/control destination must be under share/extension/: '$destination'."
            }
            $verifiedFile = $null
            if ($row.source -eq 'licenseDocument') {
                $verifiedFile = $sourceDocuments[$path]
                Assert-PackageLicenseBytes $file $verifiedFile
            }
            if ($row.source -eq 'license') {
                $license = $licenses[$path]
                Assert-PackageLicenseBytes $file $license
                $verifiedFile = $license
                $licenseEntry = @{ repositoryPath = $license.repositoryPath; upstreamPath = $license.upstreamPath
                    zipPath = $destination; size = $license.size; sha256 = $license.sha256 }
                foreach ($field in @('upstreamOffset', 'upstreamSize', 'upstreamSha256')) {
                    if ($license.PSObject.Properties[$field]) { $licenseEntry[$field] = $license.$field }
                }
                $matchedLicenses.Add($path, $licenseEntry)
            }
            foreach ($target in $row.targets) {
                if ($target -eq 'install' -and $destination -notmatch '^(?:share/extension|lib|bin)/' -and
                    !($file.Extension -ieq '.h' -and $destination -match '^include/[^/]+\.h$')) {
                    throw "Invalid install destination '$destination'."
                }
                $selected = $destinations[$target]
                foreach ($other in $selected.Keys) {
                    if ($other -ieq $destination -or $other.StartsWith("$destination/", [StringComparison]::OrdinalIgnoreCase) -or
                        $destination.StartsWith("$other/", [StringComparison]::OrdinalIgnoreCase)) {
                        throw "Conflicting $target destination '$destination' and '$other'."
                    }
                }
                $selected.Add($destination, $file.FullName)
            }
            $files.Add(@{ source = $file.FullName; destination = $destination; targets = $row.targets; verified = $verifiedFile })
        }
    }
    if ($matchedLicenses.Count -ne $licenses.Count) { throw 'Package map must place every verified license.' }
    if ($map.distribution -ne 'dll-only') {
        $controlPath = 'share/extension/' + $Tokens.extensionName + '.control'
        $sqlPath = 'share/extension/' + $Tokens.extensionName + '--' + $sqlVersion + '.sql'
        $controls = @($destinations.Values | ForEach-Object { if ($_.ContainsKey($controlPath)) { $_[$controlPath] } } | Select-Object -Unique)
        if ($map.Contains('sqlInstallPath')) {
            # PostgreSQL can install from a base script followed by update scripts.
            $versions = @(foreach ($version in $map.sqlInstallPath) {
                if ($version -isnot [string]) { throw 'sqlInstallPath versions must be strings.' }
                $version = Expand-PackageTokens $version $Tokens
                if ($version -cnotmatch $sqlVersionPattern) {
                    throw "Invalid sqlInstallPath version '$version'."
                }
                $version
            })
            if ($versions[-1] -cne $sqlVersion -or @($versions | Select-Object -Unique).Count -ne $versions.Count) {
                throw 'sqlInstallPath must use distinct versions and end at the expected SQL version.'
            }
            $sqlPrefix = 'share/extension/' + $Tokens.extensionName + '--'
            $requiredSql = @("${sqlPrefix}$($versions[0]).sql")
            for ($i = 1; $i -lt $versions.Count; $i++) {
                $requiredSql += "${sqlPrefix}$($versions[$i - 1])--$($versions[$i]).sql"
            }
            foreach ($target in $destinations.Keys) {
                if ($destinations[$target].ContainsKey($controlPath)) {
                    foreach ($path in $requiredSql) {
                        if (!$destinations[$target].ContainsKey($path)) {
                            throw "sqlInstallPath requires '$path' in $target."
                        }
                    }
                }
            }
        }
        if (!$controls.Count -or (!$map.Contains('sqlInstallPath') -and
            !($destinations.install.ContainsKey($sqlPath) -or $destinations.zip.ContainsKey($sqlPath)))) {
            throw "Package map requires '$controlPath' and '$sqlPath'."
        }
        foreach ($control in $controls) {
            $versions = [regex]::Matches([IO.File]::ReadAllText($control), "(?m)^\s*default_version\s*=\s*'([^']+)'")
            if ($versions.Count -ne 1 -or $versions[0].Groups[1].Value -cne $sqlVersion) {
                throw "Control default_version does not match '$sqlVersion' in '$controlPath'."
            }
        }
    }
    $lines = foreach ($line in $map.packageInfo) {
        if ($line -isnot [string] -or $line -match '[\r\n]') { throw 'packageInfo must contain individual text lines.' }
        Expand-PackageTokens $line $Tokens
    }
    return @{
        files = $files.ToArray()
        packageInfo = @($lines)
        packageInfoFinalNewline = !$map.Contains('packageInfoFinalNewline') -or $map.packageInfoFinalNewline
        verifiedLicenses = @{
            schemaVersion = 1; upstreamCommit = $VerifiedLicenses.upstreamCommit
            licenses = @($matchedLicenses.Values | Sort-Object { $_.zipPath })
        }
    }
}

function Copy-PackageFiles {
    param($Plan, [string]$Root, [ValidateSet('install', 'zip')][string]$Target)
    $selected = @($Plan.files | Where-Object { $Target -cin $_.targets })
    foreach ($file in $selected) {
        $existing = Get-PackageItem $Root $file.destination
        if ($existing -and $existing.PSIsContainer) { throw "File destination is a directory: '$($file.destination)'." }
        if ($file.verified) { Assert-PackageLicenseBytes (Get-Item -LiteralPath $file.source -Force) $file.verified }
    }
    foreach ($file in $selected) {
        $destination = Join-Path $Root $file.destination
        [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($destination))
        [IO.File]::Copy($file.source, $destination, $true)
    }
}

function Write-WindowsPackageStage {
    param($Plan, [string]$Stage, [string]$LicenseList)
    if (Test-Path -LiteralPath $Stage) { throw "Package stage must be new: '$Stage'." }
    [void][IO.Directory]::CreateDirectory($Stage)
    Copy-PackageFiles $Plan $Stage zip
    $info = $Plan.packageInfo -join [Environment]::NewLine
    if ($Plan.packageInfoFinalNewline) { $info += [Environment]::NewLine }
    Set-Content -LiteralPath (Join-Path $Stage 'PACKAGE-INFO.txt') -Value $info -Encoding utf8 -NoNewline
    $Plan.verifiedLicenses | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $LicenseList -Encoding utf8
}

function Get-PackageCommit {
    param([string]$Root)
    $commit = & git -C $Root rev-parse HEAD
    if ($LASTEXITCODE -ne 0 -or $commit -cnotmatch '^[0-9a-f]{40}$') {
        throw "Could not resolve a full commit SHA for '$Root'."
    }
    return $commit
}

function Get-PackageTokens {
    param([string]$ExtensionName, [string]$UpstreamRepository, $Matrix, [string]$UpstreamDir)
    $commit = Get-PackageCommit $UpstreamDir
    if ($Matrix.upstreamCommit -and $commit -cne $Matrix.upstreamCommit) {
        throw "Upstream SHA mismatch: expected $($Matrix.upstreamCommit), got $commit."
    }
    return @{
        extensionName = $ExtensionName; upstreamRepository = $UpstreamRepository; upstreamCommit = $commit
        upstreamRef = $Matrix.upstreamRef; version = $Matrix.upstreamVersion; pgMajor = $Matrix.major
        pgTested = $Matrix.minor; pgPackage = $Matrix.chocolateyPackage; pgPackageVersion = $Matrix.chocolateyVersion
        architecture = 'Windows x64'
    }
}

function Invoke-PackageLicenseVerification {
    param($Matrix, [string]$PackagingDir, [string]$UpstreamDir, [string]$WorkDir, [switch]$RestoreWorktrees)
    $config = Join-Path $WorkDir 'license-pins.json'
    $stage = Join-Path $WorkDir 'verified-licenses'
    $manifest = Join-Path $WorkDir 'verified-blobs.json'
    $sourceStage = Join-Path $WorkDir 'verified-license-sources'
    ConvertTo-Json -InputObject @($Matrix.licenseFiles) -Depth 5 |
        Set-Content -LiteralPath $config -Encoding utf8
    [string[]]$restoreArgs = @()
    if ($RestoreWorktrees) { $restoreArgs += '--restore-worktrees' }
    & python (Join-Path $PSScriptRoot 'verify-license-bytes.py') --license-files $config --upstream-dir $UpstreamDir `
        --packaging-dir $PackagingDir --stage-dir $stage --source-stage-dir $sourceStage --verified-list $manifest @restoreArgs | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Upstream license byte verification failed.' }
    return @{
        stage = $stage
        sourceStage = $sourceStage
        verified = (Get-Content -LiteralPath $manifest -Raw | ConvertFrom-Json)
    }
}

function Get-PackageFinalizerInputs {
    param($Tokens, [string]$PackagingDir, [string]$UpstreamDir, [string]$PackagingRepository,
          [string]$BuildRepository, [string]$BuildCommit, [string]$BuildMode, [string]$ReusableWorkflow)
    return @{
        ExtensionName = $Tokens.extensionName; UpstreamDir = $UpstreamDir; UpstreamRepository = $Tokens.upstreamRepository
        UpstreamRef = $Tokens.upstreamRef; UpstreamVersion = $Tokens.version; UpstreamCommit = $Tokens.upstreamCommit
        PostgreSqlMajor = $Tokens.pgMajor; PostgreSqlTestedVersion = $Tokens.pgTested
        ChocolateyPackage = $Tokens.pgPackage; ChocolateyPackageVersion = $Tokens.pgPackageVersion
        PackagingDir = $PackagingDir; PackagingRepository = $PackagingRepository; PackagingCommit = (Get-PackageCommit $PackagingDir)
        BuildInfrastructureDir = (Split-Path -Parent $PSScriptRoot); BuildRepository = $BuildRepository
        BuildCommit = $BuildCommit; ReusableWorkflow = $ReusableWorkflow; BuildMode = $BuildMode
        WorkflowRunId = $env:GITHUB_RUN_ID; WorkflowRunAttempt = $env:GITHUB_RUN_ATTEMPT
        WorkflowRunUrl = "$env:GITHUB_SERVER_URL/$env:GITHUB_REPOSITORY/actions/runs/$env:GITHUB_RUN_ID"
        WorkflowEvent = $env:GITHUB_EVENT_NAME; WorkflowRef = $env:GITHUB_REF
    }
}

function Get-WindowsPackageAssetName {
    param($Tokens)
    return "$($Tokens.extensionName)-$($Tokens.upstreamRef)-pg$($Tokens.pgMajor)-windows-x64.zip"
}

function Get-LegacyPackageInputs {
    param($Tokens, [string]$UpstreamDir)
    return @{
        UpstreamDir = $UpstreamDir; UpstreamRepository = $Tokens.upstreamRepository
        UpstreamRef = $Tokens.upstreamRef; UpstreamVersion = $Tokens.version
        PostgreSqlMajor = $Tokens.pgMajor; PostgreSqlMinor = $Tokens.pgTested
    }
}
