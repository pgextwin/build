[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ExtensionConfigPath,

    [Parameter(Mandatory = $true)]
    [string]$PostgreSqlConfigPath,

    [Parameter(Mandatory = $false)]
    [string]$EffectiveDate
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$extension = Get-Content $ExtensionConfigPath -Raw | ConvertFrom-Json
$postgres = Get-Content $PostgreSqlConfigPath -Raw | ConvertFrom-Json

if ($extension.schemaVersion -ne 1) {
    throw "Unsupported extension config schemaVersion: $($extension.schemaVersion)"
}

foreach ($required in @("name", "upstream", "postgresql")) {
    if (-not $extension.PSObject.Properties.Name.Contains($required)) {
        throw "Extension config is missing required property '$required'."
    }
}

if (-not $extension.upstream.PSObject.Properties.Name.Contains("repository") -or
    [string]::IsNullOrWhiteSpace([string]$extension.upstream.repository)) {
    throw "Extension config upstream section is missing 'repository'."
}

$hasUniformRef = $extension.upstream.PSObject.Properties.Name.Contains("ref")
$hasUniformVersion = $extension.upstream.PSObject.Properties.Name.Contains("version")
$hasPerPostgresql = $extension.upstream.PSObject.Properties.Name.Contains("perPostgresql")

if ($hasPerPostgresql) {
    if ($hasUniformRef -or $hasUniformVersion) {
        throw "upstream must use either uniform 'ref'/'version' or 'perPostgresql', not both."
    }

    if ($null -eq $extension.upstream.perPostgresql -or
        @($extension.upstream.perPostgresql.PSObject.Properties).Count -eq 0) {
        throw "upstream.perPostgresql must contain at least one PostgreSQL-major mapping."
    }

    $upstreamMode = "perPostgresql"
}
else {
    if (-not $hasUniformRef -or -not $hasUniformVersion -or
        [string]::IsNullOrWhiteSpace([string]$extension.upstream.ref) -or
        [string]::IsNullOrWhiteSpace([string]$extension.upstream.version)) {
        throw "upstream must define both 'ref' and 'version' when 'perPostgresql' is not used."
    }

    $upstreamMode = "uniform"
}

$allowedMajors = @()

if ($extension.postgresql.PSObject.Properties.Name.Contains("majors")) {
    $allowedMajors = @($extension.postgresql.majors | ForEach-Object { [int]$_ })
}
else {
    if (-not $extension.postgresql.PSObject.Properties.Name.Contains("minMajor") -or
        -not $extension.postgresql.PSObject.Properties.Name.Contains("maxMajor")) {
        throw "postgresql must define either 'majors' or both 'minMajor' and 'maxMajor'."
    }

    $min = [int]$extension.postgresql.minMajor
    $max = [int]$extension.postgresql.maxMajor

    if ($min -gt $max) {
        throw "postgresql.minMajor must be less than or equal to maxMajor."
    }

    $allowedMajors = @($min..$max)
}

if ([string]::IsNullOrWhiteSpace($EffectiveDate)) {
    $currentDate = [DateTime]::UtcNow.Date
}
else {
    try {
        $currentDate = [DateTime]::ParseExact(
            $EffectiveDate,
            "yyyy-MM-dd",
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::None
        ).Date
    }
    catch {
        throw "EffectiveDate must be a valid calendar date in yyyy-MM-dd format."
    }
}

$supported = @(
    $postgres.postgresql | Where-Object {
        $major = [int]$_.major
        $eol = [DateTime]::ParseExact(
            $_.eol,
            "yyyy-MM-dd",
            [Globalization.CultureInfo]::InvariantCulture
        ).Date

        $allowedMajors -contains $major -and $eol -ge $currentDate
    }
)

if ($supported.Count -eq 0) {
    throw "No maintained PostgreSQL versions are eligible for extension '$($extension.name)'."
}

$matrixEntries = @(
    foreach ($entry in $supported) {
        $majorKey = [string][int]$entry.major

        if ($upstreamMode -eq "uniform") {
            $upstreamRef = [string]$extension.upstream.ref
            $upstreamVersion = [string]$extension.upstream.version
            $upstreamCommit = if ($extension.upstream.PSObject.Properties.Name.Contains("commit")) { [string]$extension.upstream.commit } else { "" }
        }
        else {
            $mappingProperty = $extension.upstream.perPostgresql.PSObject.Properties[$majorKey]

            if ($null -eq $mappingProperty) {
                throw "upstream.perPostgresql has no mapping for eligible PostgreSQL major $majorKey."
            }

            $mapping = $mappingProperty.Value

            if (-not $mapping.PSObject.Properties.Name.Contains("ref") -or
                -not $mapping.PSObject.Properties.Name.Contains("version") -or
                [string]::IsNullOrWhiteSpace([string]$mapping.ref) -or
                [string]::IsNullOrWhiteSpace([string]$mapping.version)) {
                throw "upstream.perPostgresql.$majorKey must define non-empty 'ref' and 'version'."
            }

            $upstreamRef = [string]$mapping.ref
            $upstreamVersion = [string]$mapping.version
            $upstreamCommit = if ($mapping.PSObject.Properties.Name.Contains("commit")) { [string]$mapping.commit } else { "" }
        }

        $resolved = [ordered]@{}

        foreach ($property in $entry.PSObject.Properties) {
            $resolved[$property.Name] = $property.Value
        }

        $resolved["upstreamRef"] = $upstreamRef
        $resolved["upstreamVersion"] = $upstreamVersion
        $resolved["upstreamCommit"] = $upstreamCommit

        [PSCustomObject]$resolved
    }
)

function Resolve-LicenseFileList {
    param(
        [AllowEmptyCollection()]$Entries,
        [string]$Context
    )

    if ($null -eq $Entries -or @($Entries).Count -eq 0) {
        throw "$Context must contain at least one entry."
    }

    $resolved = [Collections.Generic.List[object]]::new()
    $upstreamCount = 0
    $seenGenerated = @{}
    $upstreamRepoPaths = @{}
    $nonUpstreamRepoPaths = @{}

    foreach ($file in @($Entries)) {
        if ($null -eq $file -or $file -isnot [PSCustomObject]) {
            throw "Each $Context entry must be an object."
        }

        $propertyNames = @($file.PSObject.Properties.Name)
        if ($propertyNames -cnotcontains "origin") {
            foreach ($name in $propertyNames) {
                if ($name -cnotin @("repositoryPath", "upstreamPath")) {
                    throw "Unsupported property '$name' in $Context entry."
                }
            }
            if ($propertyNames -cnotcontains "repositoryPath" -or
                $propertyNames -cnotcontains "upstreamPath" -or
                $file.repositoryPath -isnot [string] -or
                $file.upstreamPath -isnot [string] -or
                [string]::IsNullOrWhiteSpace($file.repositoryPath) -or
                [string]::IsNullOrWhiteSpace($file.upstreamPath)) {
                throw "Each $Context entry must define non-empty 'repositoryPath' and 'upstreamPath'."
            }

            $repoPath = [string]$file.repositoryPath
            $repoKey = $repoPath.ToLowerInvariant()
            if ($nonUpstreamRepoPaths.ContainsKey($repoKey)) {
                throw "Duplicate license repositoryPath '$repoPath' in $Context."
            }
            $upstreamRepoPaths[$repoKey] = $true

            $resolved.Add([ordered]@{
                repositoryPath = $repoPath
                upstreamPath   = [string]$file.upstreamPath
            })
            $upstreamCount++
        }
        else {
            $origin = [string]$file.origin
            if ($origin -ceq "packaging") {
                foreach ($name in $propertyNames) {
                    if ($name -cnotin @("origin", "repositoryPath", "sha256")) {
                        throw "Unsupported property '$name' in $Context packaging entry."
                    }
                }
                if ($propertyNames -cnotcontains "repositoryPath" -or
                    $propertyNames -cnotcontains "sha256" -or
                    $file.repositoryPath -isnot [string] -or
                    $file.sha256 -isnot [string] -or
                    [string]::IsNullOrWhiteSpace($file.repositoryPath) -or
                    $file.sha256 -cnotmatch '\A[0-9a-f]{64}\z') {
                    throw "Each $Context packaging entry must define non-empty 'repositoryPath' and 64-char lowercase hex 'sha256'."
                }

                $repoPath = [string]$file.repositoryPath
                $repoKey = $repoPath.ToLowerInvariant()
                if ($nonUpstreamRepoPaths.ContainsKey($repoKey) -or $upstreamRepoPaths.ContainsKey($repoKey)) {
                    throw "Duplicate license repositoryPath '$repoPath' in $Context."
                }
                $nonUpstreamRepoPaths[$repoKey] = $true

                $resolved.Add([ordered]@{
                    origin         = "packaging"
                    repositoryPath = $repoPath
                    sha256         = [string]$file.sha256
                })
            }
            elseif ($origin -ceq "build") {
                foreach ($name in $propertyNames) {
                    if ($name -cnotin @("origin", "repositoryPath", "generatedSource", "generatedPath", "sha256")) {
                        throw "Unsupported property '$name' in $Context build entry."
                    }
                }
                if ($propertyNames -cnotcontains "repositoryPath" -or
                    $propertyNames -cnotcontains "generatedSource" -or
                    $propertyNames -cnotcontains "generatedPath" -or
                    $propertyNames -cnotcontains "sha256" -or
                    $file.repositoryPath -isnot [string] -or
                    $file.generatedSource -isnot [string] -or
                    $file.generatedPath -isnot [string] -or
                    $file.sha256 -isnot [string] -or
                    [string]::IsNullOrWhiteSpace($file.repositoryPath) -or
                    $file.generatedSource -cnotin @("upstream", "buildOutput") -or
                    [string]::IsNullOrWhiteSpace($file.generatedPath) -or
                    $file.sha256 -cnotmatch '\A[0-9a-f]{64}\z') {
                    throw "Each $Context build entry must define non-empty 'repositoryPath', 'generatedSource' ('upstream' or 'buildOutput'), 'generatedPath', and 64-char lowercase hex 'sha256'."
                }

                $repoPath = [string]$file.repositoryPath
                $repoKey = $repoPath.ToLowerInvariant()
                if ($nonUpstreamRepoPaths.ContainsKey($repoKey) -or $upstreamRepoPaths.ContainsKey($repoKey)) {
                    throw "Duplicate license repositoryPath '$repoPath' in $Context."
                }
                $nonUpstreamRepoPaths[$repoKey] = $true

                $generatedKey = $file.generatedSource + ":" + $file.generatedPath.ToLowerInvariant()
                if ($seenGenerated.ContainsKey($generatedKey)) {
                    throw "Duplicate generated license source/path '$generatedKey' in $Context."
                }
                $seenGenerated[$generatedKey] = $true

                $resolved.Add([ordered]@{
                    origin          = "build"
                    repositoryPath  = $repoPath
                    generatedSource = [string]$file.generatedSource
                    generatedPath   = [string]$file.generatedPath
                    sha256          = [string]$file.sha256
                })
            }
            else {
                throw "Unsupported license origin '$origin' in $Context."
            }
        }
    }

    if ($upstreamCount -lt 1) {
        throw "$Context must include at least one upstream-verified license entry."
    }

    return $resolved.ToArray()
}

$verifyLicense = $true
$licenseMode = "uniform"
$licenseFiles = @(
    [ordered]@{
        repositoryPath = "LICENSE"
        upstreamPath = "LICENSE"
    }
)
$licensePerPostgresql = $null

if ($extension.PSObject.Properties.Name.Contains("license")) {
    if ($extension.license.PSObject.Properties.Name.Contains("verifyAgainstUpstream")) {
        $verifyLicense = [bool]$extension.license.verifyAgainstUpstream
    }

    $hasLegacyLicensePath = $extension.license.PSObject.Properties.Name.Contains("upstreamPath")
    $hasLicenseFiles = $extension.license.PSObject.Properties.Name.Contains("files")
    $hasPerPostgresqlLicense = $extension.license.PSObject.Properties.Name.Contains("perPostgresql")

    $licenseModes = @($hasLegacyLicensePath, $hasLicenseFiles, $hasPerPostgresqlLicense).Where({ $_ }).Count
    if ($licenseModes -ne 1) {
        throw "license must use exactly one of 'upstreamPath', 'files', or 'perPostgresql'."
    }

    if ($hasLicenseFiles) {
        $licenseFiles = @(Resolve-LicenseFileList -Entries $extension.license.files -Context "license.files")
    }
    elseif ($hasPerPostgresqlLicense) {
        if ($null -eq $extension.license.perPostgresql -or
            @($extension.license.perPostgresql.PSObject.Properties).Count -eq 0) {
            throw "license.perPostgresql must contain at least one PostgreSQL-major mapping."
        }

        $licenseMode = "perPostgresql"
        $licensePerPostgresql = $extension.license.perPostgresql
    }
    elseif ($hasLegacyLicensePath -and
            -not [string]::IsNullOrWhiteSpace([string]$extension.license.upstreamPath)) {
        $licenseFiles = @(
            [ordered]@{
                repositoryPath = "LICENSE"
                upstreamPath = [string]$extension.license.upstreamPath
            }
        )
    }
}

# The existing pgTAP manifest opts out of whole-file comparison because the
# license is a suffix of README.md. Verify that suffix against the LICENSE blob.
if ($extension.name -ceq 'pgtap' -and $extension.upstream.repository -ceq 'theory/pgtap' -and
    $licenseMode -eq 'uniform' -and $licenseFiles.Count -eq 1 -and
    $licenseFiles[0].Contains('upstreamPath') -and
    $licenseFiles[0].repositoryPath -ceq 'LICENSE' -and $licenseFiles[0].upstreamPath -ceq 'README.md') {
    $licenseFiles[0].upstreamStartMarker = 'Copyright (c)'
    $verifyLicense = $true
}

foreach ($entry in $matrixEntries) {
    if ($licenseMode -eq "perPostgresql") {
        $majorKey = [string][int]$entry.major
        $mappingProperty = $licensePerPostgresql.PSObject.Properties[$majorKey]

        if ($null -eq $mappingProperty) {
            throw "license.perPostgresql has no mapping for eligible PostgreSQL major $majorKey."
        }

        $resolvedLicenseFiles = @(Resolve-LicenseFileList -Entries $mappingProperty.Value -Context "license.perPostgresql.$majorKey")
    }
    else {
        $resolvedLicenseFiles = @($licenseFiles)
    }

    $entry | Add-Member -NotePropertyName licenseFiles -NotePropertyValue @($resolvedLicenseFiles)
}

$matrix = @{ include = $matrixEntries } | ConvertTo-Json -Compress -Depth 10

$uniformRef = ""
$uniformVersion = ""

if ($upstreamMode -eq "uniform") {
    $uniformRef = [string]$extension.upstream.ref
    $uniformVersion = [string]$extension.upstream.version
}

$outputs = [ordered]@{
    matrix                  = $matrix
    extension_name          = [string]$extension.name
    upstream_repository     = [string]$extension.upstream.repository
    upstream_mode           = $upstreamMode
    upstream_ref            = $uniformRef
    upstream_version        = $uniformVersion
    verify_upstream_license = $verifyLicense.ToString().ToLowerInvariant()
    license_mode            = $licenseMode
    license_files           = if ($licenseMode -eq "uniform") { $licenseFiles | ConvertTo-Json -Compress -Depth 5 } else { "" }
}

foreach ($entry in $outputs.GetEnumerator()) {
    "$($entry.Key)=$($entry.Value)" >> $env:GITHUB_OUTPUT
}

Write-Host "Extension: $($extension.name)"
Write-Host "Upstream repository: $($extension.upstream.repository)"
Write-Host "Upstream mode: $upstreamMode"
Write-Host "Lifecycle effective date: $($currentDate.ToString('yyyy-MM-dd'))"
Write-Host "Build matrix: $matrix"
