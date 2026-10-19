
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
  $text=$text.Replace('#include <dlfcn.h>','').Replace('#include <unistd.h>',"#include <io.h>`n#define unlink _unlink")
  [IO.File]::WriteAllText($path,$text,[Text.UTF8Encoding]::new($false))
}
# PG14-18 MemoryContextMethods::stats takes a fifth print_to_stderr parameter.
# The upstream v1.2.1 call has only four; adapt the disposable pinned checkout.
$pgv=Join-Path $UpstreamDir 'pg_variables.c'
$source=[IO.File]::ReadAllText($pgv)
$old='(*context->methods->stats) (context, NULL, NULL, &totals);'
if(([regex]::Matches($source,[regex]::Escape($old))).Count -ne 1){throw 'pg_variables stats ABI pattern changed'}
$source=$source.Replace($old,'(*context->methods->stats) (context, NULL, NULL, &totals, false);')

# Older upstream AssertArg() is not provided by later PostgreSQL headers.
# Preserve its assertion semantics using the supported Assert() macro.
$oldAssert='AssertArg(MemoryContextIsValid(context));'
if(([regex]::Matches($source,[regex]::Escape($oldAssert))).Count -ne 1){throw 'AssertArg upstream layout drift'}
$source=$source.Replace($oldAssert,'Assert(MemoryContextIsValid(context));')
[IO.File]::WriteAllText($pgv,$source,[Text.UTF8Encoding]::new($false))
# access/tuptoaster.h was removed in core PG14-18;
# the called toast_flatten_tuple_to_datum() API is now declared in access/heaptoast.h.
# Rewrite only this expected include in the disposable, SHA-verified checkout.
$record=Join-Path $UpstreamDir 'pg_variables_record.c'
$recordSource=[IO.File]::ReadAllText($record)
$oldHeader='#include "access/tuptoaster.h"'
if(([regex]::Matches($recordSource,[regex]::Escape($oldHeader))).Count -ne 1){
  throw 'Upstream pg_variables_record.c include layout drift'
}
$recordSource=$recordSource.Replace($oldHeader,'#include "access/heaptoast.h"')
[IO.File]::WriteAllText($record,$recordSource,[Text.UTF8Encoding]::new($false))

$exports=@('Pg_magic_func','_PG_init','_PG_fini')
# Upstream macro-generated SQL entry points are not spelled as concrete
# PG_FUNCTION_INFO_V1(name) invocations; include every expanded V1 getter/setter.
$getterTypes=@('int','text','numeric','timestamp','timestamptz','date','jsonb','any','array')
$macroSource=[IO.File]::ReadAllText($pgv)
foreach($kind in @('GET','SET')){
  foreach($type in $getterTypes){
    $pattern=if($kind -eq 'GET'){"(?m)^VARIABLE_GET_TEMPLATE\(\s*0\s*,\s*1\s*,\s*[23]\s*,\s*$type\s*,"}else{"(?m)^VARIABLE_SET_TEMPLATE\(\s*$type\s*,"}
    if(([regex]::Matches($macroSource,$pattern)).Count -ne 1){throw "Missing expected upstream macro expansion: $kind $type"}
    $symbol=if($kind -eq 'GET'){"variable_get_$type"}else{"variable_set_$type"}
    $exports+=@($symbol,"pg_finfo_$symbol")
  }
}
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
