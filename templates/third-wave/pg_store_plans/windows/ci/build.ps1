
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$PgRoot,[Parameter(Mandatory=$true)][string]$UpstreamDir)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$c=Get-Content (Join-Path $PSScriptRoot '../../config/extension.json') -Raw|ConvertFrom-Json
$name=[string]$c.name
$actual=(& git -C $UpstreamDir rev-parse HEAD).Trim().ToLowerInvariant()
if($LASTEXITCODE -ne 0 -or $actual -cne [string]$c.upstream.commit){throw 'Immutable upstream pin mismatch'}
$pg=(& (Join-Path $PgRoot 'bin/pg_config.exe') --version).Trim()
if($LASTEXITCODE -ne 0 -or $pg -notmatch '^PostgreSQL\s+(14|15|16|17|18)(?:\.|\s)'){throw "Unsupported PG $pg"}
$sources=if($name -eq 'pg_variables'){@('pg_variables.c','pg_variables_record.c')}elseif($name -eq 'pg_store_plans'){@('pg_store_plans.c','pgsp_json.c','pgsp_json_text.c','pgsp_explain.c')}else{throw 'Unexpected extension'}
if($name -eq 'pg_store_plans'){
  $path=Join-Path $UpstreamDir 'pg_store_plans.c'
  $text=[IO.File]::ReadAllText($path)
  foreach($h in @('#include <unistd.h>','#include <dlfcn.h>')){
    if(([regex]::Matches($text,[regex]::Escape($h))).Count -ne 1){throw "Source layout drift: $h"}
  }
  $text=$text.Replace('#include <dlfcn.h>','').Replace('#include <unistd.h>','#include <io.h>')
  # Postgres Windows PGDLLEXPORT declarations match PG_FUNCTION_INFO_V1.
  $pattern='(?m)^Datum([ \t]+)(pg_store_plans(?:_[A-Za-z0-9_]+)?)\s*\(PG_FUNCTION_ARGS\);'
  $count=[regex]::Matches($text,$pattern).Count
  if($count -ne 10){throw "Unexpected pg_store_plans C declarations: $count"}
  $text=[regex]::Replace($text,$pattern,'PGDLLEXPORT Datum$1$2(PG_FUNCTION_ARGS);')
  [IO.File]::WriteAllText($path,$text,[Text.UTF8Encoding]::new($false))
  # PG14/15 EDB Windows dev package omits generated parser/gram.h.
  # Copy a guarded token-ID shim derived from the matching PG grammars.
  $json=Join-Path $UpstreamDir 'pgsp_json.c'
  $source=[IO.File]::ReadAllText($json)
  $legacy='#include "parser/gram.h"'
  if(([regex]::Matches($source,[regex]::Escape($legacy))).Count -ne 1){throw 'pgsp_json parser source drift'}
  $source=$source.Replace($legacy,'#include "pgextwin-token-compat.h"')
  [IO.File]::WriteAllText($json,$source,[Text.UTF8Encoding]::new($false))
  Copy-Item (Join-Path $PSScriptRoot 'pg14-15-token-compat.h') (Join-Path $UpstreamDir 'pgextwin-token-compat.h') -Force
}
$exports=@('Pg_magic_func','_PG_init')
foreach($file in $sources){
  $path=Join-Path $UpstreamDir $file
  if(-not(Test-Path $path -PathType Leaf)){throw "Source missing $file"}
  $src=[IO.File]::ReadAllText($path)
  foreach($m in [regex]::Matches($src,'PG_FUNCTION_INFO_V1\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)')){
    $f=$m.Groups[1].Value
    $exports+=@($f,"pg_finfo_$f")
  }
}
$exports=@($exports|Sort-Object -Unique)
if($exports.Count -lt 8){throw 'Unexpectedly few C exports'}
$def=Join-Path $UpstreamDir "$name.pgextwin.def"
[IO.File]::WriteAllLines($def,[string[]](@("LIBRARY $name",'EXPORTS')+@($exports|ForEach-Object{"    $_"})),[Text.Encoding]::ASCII)
$vswhere=Join-Path ([Environment]::GetFolderPath('ProgramFilesX86')) 'Microsoft Visual Studio/Installer/vswhere.exe'
if(-not(Test-Path $vswhere)){throw 'MSVC vswhere missing'}
$vs=[string](& $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath|Select-Object -First 1)
if([string]::IsNullOrWhiteSpace($vs)){throw 'MSVC toolchain unavailable'}
$vsdev=Join-Path $vs.Trim() 'Common7/Tools/VsDevCmd.bat'
if(-not(Test-Path $vsdev)){throw 'Missing VsDevCmd'}
$tmp=Join-Path $UpstreamDir '.pgextwin-obj'
New-Item $tmp -ItemType Directory -Force|Out-Null
$cmd=Join-Path $tmp 'build.cmd'
$lines=[System.Collections.Generic.List[string]]::new()
$lines.Add('@echo off')
$lines.Add('call "'+$vsdev+'" -arch=x64 -host_arch=x64 >nul')
$lines.Add('if errorlevel 1 exit /b %errorlevel%')
$objs=@()
foreach($file in $sources){
  $source=Join-Path $UpstreamDir $file
  $obj=Join-Path $tmp ($file -replace '\.c$','.obj')
  $objs+=('"'+$obj+'"')
  $includes=@('include/server/port/win32_msvc','include/server/port/win32','include/server','include')
  $flags=@('/nologo','/O2','/MD','/DWIN32','/DWIN32_NO_STATUS','/D__WINDOWS__','/D_CRT_SECURE_NO_WARNINGS','/D_CRT_NONSTDC_NO_WARNINGS')
  foreach($inc in $includes){$flags+=('/I"'+(Join-Path $PgRoot $inc)+'"')}
  $flags+=('/I"'+$UpstreamDir+'"')
  $lines.Add('cl '+($flags -join ' ')+' /c "'+$source+'" /Fo"'+$obj+'"')
  $lines.Add('if errorlevel 1 exit /b %errorlevel%')
}
$dll=Join-Path $UpstreamDir "$name.dll"
$lines.Add('link /nologo /DLL /MACHINE:X64 /OUT:"'+$dll+'" /DEF:"'+$def+'" '+($objs -join ' ')+' "'+(Join-Path $PgRoot 'lib/postgres.lib')+'"')
$lines.Add('if errorlevel 1 exit /b %errorlevel%')
$lines.Add('dumpbin /nologo /exports "'+$dll+'"')
$lines.Add('if errorlevel 1 exit /b %errorlevel%')
[IO.File]::WriteAllLines($cmd,[string[]]$lines.ToArray(),[Text.Encoding]::ASCII)
$output=@(& cmd.exe /d /c $cmd)
if($LASTEXITCODE -ne 0 -or -not(Test-Path $dll -PathType Leaf)){
  $output|ForEach-Object{Write-Host $_}
  throw "MSVC compile/link failed for $name"
}
$dump=$output -join [Environment]::NewLine
foreach($symbol in $exports){if($dump -notmatch ('(?m)\s'+[regex]::Escape($symbol)+'\s*$')){throw "Missing DLL export $symbol"}}
if($name -eq 'pg_variables'){
  $parts=@('pg_variables--1.0.sql','pg_variables--1.0--1.1.sql','pg_variables--1.1--1.2.sql')
  $sql=@()
  foreach($f in $parts){$p=Join-Path $UpstreamDir $f;if(-not(Test-Path $p)){throw "Missing $f"};$sql+=Get-Content $p -Raw}
  [IO.File]::WriteAllText((Join-Path $UpstreamDir 'pg_variables--1.2.sql'),($sql -join "`n"),[Text.UTF8Encoding]::new($false))
}
Write-Host "PASS: $name native DLL exports and generated SQL validated"
