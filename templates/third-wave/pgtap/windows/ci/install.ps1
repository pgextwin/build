[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$PgRoot,[Parameter(Mandatory=$true)][string]$UpstreamDir)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$dest=Join-Path $PgRoot 'share/extension'
if(-not(Test-Path $dest -PathType Container)){throw 'Missing PostgreSQL extension directory'}
foreach($file in @('pgtap.control','pgtap--1.3.4.sql')){
  $source=Join-Path $UpstreamDir $file
  if(-not(Test-Path $source -PathType Leaf)){throw "Missing $file"}
  Copy-Item $source (Join-Path $dest $file) -Force
}
Write-Host 'Installed pgTAP SQL-only distribution'
