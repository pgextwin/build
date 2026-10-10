[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$PgRoot,
      [Parameter(Mandatory=$true)][string]$UpstreamDir)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$dll = Join-Path $UpstreamDir 'wal2json.dll'
if (-not (Test-Path $dll -PathType Leaf)) { throw 'wal2json DLL missing' }
$target = Join-Path $PgRoot 'lib/wal2json.dll'
Copy-Item $dll $target -Force
if (-not (Test-Path $target -PathType Leaf)) { throw 'Installation failed' }
Write-Host 'Installed wal2json output plugin; CREATE EXTENSION is not applicable'
