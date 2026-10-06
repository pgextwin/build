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
        }

        $resolved = [ordered]@{}

        foreach ($property in $entry.PSObject.Properties) {
            $resolved[$property.Name] = $property.Value
        }

        $resolved["upstreamRef"] = $upstreamRef
        $resolved["upstreamVersion"] = $upstreamVersion

        [PSCustomObject]$resolved
    }
)

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
        $licenseFiles = @(
            foreach ($file in $extension.license.files) {
                if (-not $file.PSObject.Properties.Name.Contains("repositoryPath") -or
                    -not $file.PSObject.Properties.Name.Contains("upstreamPath") -or
                    [string]::IsNullOrWhiteSpace([string]$file.repositoryPath) -or
                    [string]::IsNullOrWhiteSpace([string]$file.upstreamPath)) {
                    throw "Each license.files entry must define non-empty 'repositoryPath' and 'upstreamPath'."
                }

                [ordered]@{
                    repositoryPath = [string]$file.repositoryPath
                    upstreamPath = [string]$file.upstreamPath
                }
            }
        )
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

foreach ($entry in $matrixEntries) {
    if ($licenseMode -eq "perPostgresql") {
        $majorKey = [string][int]$entry.major
        $mappingProperty = $licensePerPostgresql.PSObject.Properties[$majorKey]

        if ($null -eq $mappingProperty) {
            throw "license.perPostgresql has no mapping for eligible PostgreSQL major $majorKey."
        }

        $resolvedLicenseFiles = @(
            foreach ($file in $mappingProperty.Value) {
                if (-not $file.PSObject.Properties.Name.Contains("repositoryPath") -or
                    -not $file.PSObject.Properties.Name.Contains("upstreamPath") -or
                    [string]::IsNullOrWhiteSpace([string]$file.repositoryPath) -or
                    [string]::IsNullOrWhiteSpace([string]$file.upstreamPath)) {
                    throw "Each license.perPostgresql.$majorKey entry must define non-empty 'repositoryPath' and 'upstreamPath'."
                }

                [ordered]@{
                    repositoryPath = [string]$file.repositoryPath
                    upstreamPath = [string]$file.upstreamPath
                }
            }
        )
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
