[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$UpstreamDir,
      [Parameter(Mandatory=$true)][string]$UpstreamRepository,
      [Parameter(Mandatory=$true)][string]$UpstreamRef,
      [Parameter(Mandatory=$true)][string]$UpstreamVersion,
      [Parameter(Mandatory=$true)][int]$PostgreSqlMajor,
      [Parameter(Mandatory=$true)][string]$PostgreSqlMinor,
      [string]$DistDir='dist')
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$config = Get-Content (Join-Path $PSScriptRoot '../../config/extension.json') -Raw | ConvertFrom-Json
if ($UpstreamRepository -cne [string]$config.upstream.repository -or $UpstreamRef -cne [string]$config.upstream.ref -or
    $UpstreamVersion -cne [string]$config.upstream.version -or $PostgreSqlMajor -notin @(15,16,17,18) -or
    $PostgreSqlMinor -notmatch ('^'+$PostgreSqlMajor+'\.' )) { throw 'Unapproved upstream / PostgreSQL package metadata' }
$sha = (& git -C $UpstreamDir rev-parse HEAD).Trim().ToLowerInvariant()
if ($LASTEXITCODE -ne 0 -or $sha -cne [string]$config.upstream.commit) { throw 'Upstream SHA mismatch' }
$name = "hypopg-$UpstreamRef-pg$PostgreSqlMajor-windows-x64"
$stage = Join-Path $DistDir $name
$zip = Join-Path $DistDir "$name.zip"
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
if (Test-Path $zip) { Remove-Item $zip -Force }
New-Item (Join-Path $stage 'lib') -ItemType Directory -Force | Out-Null
New-Item (Join-Path $stage 'share/extension') -ItemType Directory -Force | Out-Null
$mapping = @{
    'hypopg.dll'='lib/hypopg.dll'
    'hypopg.control'='share/extension/hypopg.control'
    'LICENSE'='LICENSE'
    'README.md'='UPSTREAM-README.md'
}
foreach ($src in $mapping.Keys) {
    $path = Join-Path $UpstreamDir $src
    if (-not (Test-Path $path -PathType Leaf)) { throw "Missing package input: $src" }
    Copy-Item $path (Join-Path $stage $mapping[$src]) -Force
}
$sql = @(Get-ChildItem $UpstreamDir -File -Filter 'hypopg--*.sql')
if ($sql.Name -cnotcontains 'hypopg--1.4.3.sql') { throw 'Missing SQL install file' }
foreach ($f in $sql) { Copy-Item $f.FullName (Join-Path $stage 'share/extension') -Force }
$info = @"
HypoPG Windows x64 (unofficial pgextwin pilot)
Upstream: $UpstreamRepository
Ref: $UpstreamRef
SHA: $sha
Version: $UpstreamVersion
PostgreSQL major: $PostgreSqlMajor
PostgreSQL minor tested: $PostgreSqlMinor
License: PostgreSQL; see LICENSE
Install by copying lib/hypopg.dll and share/extension files to the respective PostgreSQL directories.
Then run CREATE EXTENSION hypopg. This is not an official HypoPG release.
"@
[IO.File]::WriteAllText((Join-Path $stage 'PACKAGE-INFO.txt'),$info,[Text.UTF8Encoding]::new($false))
Copy-Item (Join-Path $PSScriptRoot '../../README.md') (Join-Path $stage 'PGEXTWIN-README.md') -Force
Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zip -CompressionLevel Optimal
if (-not (Test-Path $zip)) { throw 'ZIP not generated' }
Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive = [IO.Compression.ZipFile]::OpenRead((Resolve-Path $zip).Path)
try {
    $items = @($archive.Entries | ForEach-Object {$_.FullName.Replace('\','/')})
    foreach ($path in @('lib/hypopg.dll','share/extension/hypopg.control','share/extension/hypopg--1.4.3.sql','LICENSE','PACKAGE-INFO.txt')) {
        if ($items -cnotcontains $path) { throw "Missing ZIP entry $path" }
    }
}
finally { $archive.Dispose() }
Write-Host "Validated $zip"
