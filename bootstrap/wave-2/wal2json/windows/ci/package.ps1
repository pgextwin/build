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
    $PostgreSqlMinor -notmatch ('^'+$PostgreSqlMajor+'\.' )) { throw 'Unexpected metadata' }
$sha = (& git -C $UpstreamDir rev-parse HEAD).Trim().ToLowerInvariant()
if ($LASTEXITCODE -ne 0 -or $sha -cne [string]$config.upstream.commit) { throw 'Pinned SHA mismatch' }
$name = "wal2json-$UpstreamRef-pg$PostgreSqlMajor-windows-x64"
$stage = Join-Path $DistDir $name
$zip = Join-Path $DistDir "$name.zip"
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
if (Test-Path $zip) { Remove-Item $zip -Force }
New-Item (Join-Path $stage 'lib') -ItemType Directory -Force | Out-Null
foreach ($mapping in @(
  @{From='wal2json.dll'; To='lib/wal2json.dll'},
  @{From='LICENSE'; To='LICENSE'},
  @{From='README.md'; To='UPSTREAM-README.md'}
)) {
    $source = Join-Path $UpstreamDir $mapping.From
    if (-not (Test-Path $source -PathType Leaf)) { throw "Missing package file $source" }
    Copy-Item $source (Join-Path $stage $mapping.To) -Force
}
$info = @"
wal2json Windows x64 output plugin (unofficial pgextwin pilot)
Upstream: $UpstreamRepository
Ref: $UpstreamRef
SHA: $sha
Version: $UpstreamVersion
PostgreSQL major: $PostgreSqlMajor
PostgreSQL tested: $PostgreSqlMinor
License: BSD-3-Clause; see LICENSE

Install lib/wal2json.dll in PostgreSQL/lib, set wal_level=logical and configure logical replication slots.
PostgreSQL security-updated versions require output_plugin_libraries to include wal2json.
This is an output plugin, not a SQL extension: DO NOT run CREATE EXTENSION wal2json.
Official documentation: https://www.postgresql.org/docs/18/runtime-config-replication.html
"@
[IO.File]::WriteAllText((Join-Path $stage 'PACKAGE-INFO.txt'),$info,[Text.UTF8Encoding]::new($false))
Copy-Item (Join-Path $PSScriptRoot '../../README.md') (Join-Path $stage 'PGEXTWIN-README.md') -Force
Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zip -CompressionLevel Optimal
if (-not (Test-Path $zip)) { throw 'ZIP not generated' }
Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive = [IO.Compression.ZipFile]::OpenRead((Resolve-Path $zip).Path)
try {
    $items = @($archive.Entries | ForEach-Object {$_.FullName.Replace('\','/')})
    foreach ($path in @('lib/wal2json.dll','LICENSE','PACKAGE-INFO.txt')) {
        if ($items -cnotcontains $path) { throw "Missing ZIP entry: $path" }
    }
}
finally { $archive.Dispose() }
Write-Host "Validated $zip"
