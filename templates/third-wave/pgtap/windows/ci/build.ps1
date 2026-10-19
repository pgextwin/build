[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$PgRoot,[Parameter(Mandatory=$true)][string]$UpstreamDir)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$c=Get-Content (Join-Path $PSScriptRoot '../../config/extension.json') -Raw | ConvertFrom-Json
$actual=(& git -C $UpstreamDir rev-parse HEAD).Trim().ToLowerInvariant()
if($LASTEXITCODE -ne 0 -or $actual -cne [string]$c.upstream.commit){throw 'SHA mismatch'}
$pg=(& (Join-Path $PgRoot 'bin/pg_config.exe') --version).Trim()
if($LASTEXITCODE -ne 0 -or $pg -notmatch '^PostgreSQL\s+(14|15|16|17|18)(?:\.|\s)'){throw 'Unsupported PostgreSQL'}
$control=Get-Content (Join-Path $UpstreamDir 'pgtap.control') -Raw
if($control -notmatch "(?m)^default_version\s*=\s*'1\.3\.4'\s*$"){throw 'Wrong pgTAP version'}
$sql=Get-Content (Join-Path $UpstreamDir 'sql/pgtap.sql.in') -Raw
if(-not $sql.Contains('__OS__') -or -not $sql.Contains('__VERSION__')){throw 'SQL template changed'}
$sql=$sql.Replace('__OS__','MSWin32').Replace('__VERSION__','1.3')
[IO.File]::WriteAllText((Join-Path $UpstreamDir 'pgtap--1.3.4.sql'),$sql,[Text.UTF8Encoding]::new($false))
Write-Host 'pgTAP SQL-only package source generated; no DLL required'
