[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$PgRoot,
      [Parameter(Mandatory=$true)][string]$UpstreamDir)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$dll = Join-Path $UpstreamDir 'hypopg.dll'
$control = Join-Path $UpstreamDir 'hypopg.control'
$sql = @(Get-ChildItem $UpstreamDir -File -Filter 'hypopg--*.sql')
if (-not (Test-Path $dll -PathType Leaf) -or -not (Test-Path $control -PathType Leaf) -or
    $sql.Count -eq 0 -or $sql.Name -cnotcontains 'hypopg--1.4.3.sql') {
    throw 'Required HypoPG DLL/control/install SQL not found'
}
$extdir = Join-Path $PgRoot 'share/extension'
if (-not (Test-Path $extdir)) { throw 'PostgreSQL extension directory missing' }
Copy-Item $dll (Join-Path $PgRoot 'lib/hypopg.dll') -Force
Copy-Item $control (Join-Path $extdir 'hypopg.control') -Force
foreach ($f in $sql) { Copy-Item $f.FullName (Join-Path $extdir $f.Name) -Force }
Write-Host "Installed HypoPG DLL and $($sql.Count) SQL scripts"
