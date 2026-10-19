[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$PgRoot,[Parameter(Mandatory=$true)][string]$UpstreamDir)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$name=(Get-Content (Join-Path $PSScriptRoot '../../config/extension.json') -Raw|ConvertFrom-Json).name
$extdir=Join-Path $PgRoot 'share/extension'
if(-not(Test-Path $extdir -PathType Container)){throw 'Missing share/extension'}
$sql=if($name -eq 'pg_variables'){'pg_variables--1.2.sql'}elseif($name -eq 'pg_store_plans'){'pg_store_plans--1.10.sql'}else{throw 'Unsupported extension'}
foreach($file in @("$name.dll","$name.control",$sql)){
  $source=Join-Path $UpstreamDir $file
  if(-not(Test-Path $source -PathType Leaf)){throw "Missing $file"}
  $dir=if($file.EndsWith('.dll')){Join-Path $PgRoot 'lib'}else{$extdir}
  Copy-Item $source (Join-Path $dir $file) -Force
}
Write-Host "Installed $name"
