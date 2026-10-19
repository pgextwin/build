
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$UpstreamDir,
      [Parameter(Mandatory=$true)][string]$UpstreamRepository,
      [Parameter(Mandatory=$true)][string]$UpstreamRef,
      [Parameter(Mandatory=$true)][string]$UpstreamVersion,
      [Parameter(Mandatory=$true)][int]$PostgreSqlMajor,
      [Parameter(Mandatory=$true)][string]$PostgreSqlMinor,
      [string]$DistDir='dist')
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$c=Get-Content (Join-Path $PSScriptRoot '../../config/extension.json') -Raw|ConvertFrom-Json
$name=[string]$c.name
$sha=(& git -C $UpstreamDir rev-parse HEAD).Trim().ToLowerInvariant()
if($LASTEXITCODE -ne 0 -or $sha -cne [string]$c.upstream.commit -or
   $UpstreamRepository -cne [string]$c.upstream.repository -or
   $UpstreamRef -cne [string]$c.upstream.ref -or
   $UpstreamVersion -cne [string]$c.upstream.version -or
   $PostgreSqlMajor -notin @(14,15,16,17,18) -or
   $PostgreSqlMinor -notmatch ('^'+$PostgreSqlMajor+'\.')){throw 'Package identity mismatch'}
$label="$name-$UpstreamVersion-pg$PostgreSqlMajor-windows-x64"
$distRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot "../../$DistDir"))
New-Item -Path $distRoot -ItemType Directory -Force | Out-Null
$stage=Join-Path $distRoot $label
$zip=Join-Path $distRoot "$label.zip"
if(Test-Path $stage){Remove-Item $stage -Recurse -Force}
if(Test-Path $zip){Remove-Item $zip -Force}
New-Item (Join-Path $stage 'share/extension') -ItemType Directory -Force|Out-Null
$sql=if($name -eq 'pgtap'){'pgtap--1.3.4.sql'}elseif($name -eq 'pg_variables'){'pg_variables--1.2.sql'}else{'pg_store_plans--1.10.sql'}
foreach($f in @("$name.control",$sql)){
  $source=Join-Path $UpstreamDir $f
  if(-not(Test-Path $source -PathType Leaf)){throw "Required package file missing: $f"}
  Copy-Item $source (Join-Path $stage 'share/extension') -Force
}
if($name -ne 'pgtap'){
  $dll=Join-Path $UpstreamDir "$name.dll"
  if(-not(Test-Path $dll -PathType Leaf)){throw "Required native DLL missing: $dll"}
  New-Item (Join-Path $stage 'lib') -ItemType Directory -Force|Out-Null
  Copy-Item $dll (Join-Path $stage 'lib') -Force
}
Copy-Item (Join-Path $PSScriptRoot '../../LICENSE') (Join-Path $stage 'LICENSE') -Force
if(Test-Path (Join-Path $UpstreamDir 'README.md')){Copy-Item (Join-Path $UpstreamDir 'README.md') (Join-Path $stage 'UPSTREAM-README.md') -Force}
Copy-Item (Join-Path $PSScriptRoot '../../README.md') (Join-Path $stage 'PGEXTWIN-README.md') -Force
$info=@"
$name unofficial Windows x64 package
Upstream repository: $UpstreamRepository
Upstream ref: $UpstreamRef
Upstream commit: $sha
Version: $UpstreamVersion
PostgreSQL major: $PostgreSqlMajor
PostgreSQL tested: $PostgreSqlMinor
Architecture: Windows x64
"@
[IO.File]::WriteAllText((Join-Path $stage 'PACKAGE-INFO.txt'),$info,[Text.UTF8Encoding]::new($false))
Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zip -CompressionLevel Optimal
Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive=[IO.Compression.ZipFile]::OpenRead((Resolve-Path $zip).Path)
try{
  $items=@($archive.Entries|ForEach-Object{$_.FullName.Replace('\','/')})
  foreach($required in @("share/extension/$name.control","share/extension/$sql",'LICENSE','PACKAGE-INFO.txt')){
    if($items -cnotcontains $required){throw "ZIP entry missing $required"}
  }
  if($name -eq 'pgtap' -and @($items|Where-Object{$_ -match '\.dll$'}).Count -gt 0){throw 'SQL-only pgTAP cannot contain DLL'}
  if($name -ne 'pgtap' -and $items -cnotcontains "lib/$name.dll"){throw 'Missing native DLL'}
}finally{$archive.Dispose()}
Write-Host "PASS: ZIP layout validated $zip"
