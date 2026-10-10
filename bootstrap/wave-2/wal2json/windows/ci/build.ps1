[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$PgRoot,
      [Parameter(Mandatory=$true)][string]$UpstreamDir)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$config = Get-Content (Join-Path $PSScriptRoot '../../config/extension.json') -Raw | ConvertFrom-Json
$expected = [string]$config.upstream.commit
if ($expected -cnotmatch '^[a-f0-9]{40}$' -or $config.upstream.repository -cne 'eulerto/wal2json') { throw 'Invalid upstream identity' }
$actual = (& git -C $UpstreamDir rev-parse HEAD).Trim().ToLowerInvariant()
if ($LASTEXITCODE -ne 0 -or $actual -cne $expected) { throw "Upstream SHA mismatch: $actual" }
$pgVersion = (& (Join-Path $PgRoot 'bin/pg_config.exe') --version).Trim()
if ($LASTEXITCODE -ne 0 -or $pgVersion -notmatch '^PostgreSQL\s+(15|16|17|18)(?:\.|\s)') {
    throw "Unsupported PostgreSQL pilot target: $pgVersion"
}
$source = Join-Path $UpstreamDir 'wal2json.c'
if (-not (Test-Path $source -PathType Leaf)) { throw 'Missing source' }
$code = Get-Content $source -Raw
if ($code -notmatch '\bPG_MODULE_MAGIC\b' -or
    $code -notmatch '\bPGDLLEXPORT\s+_PG_output_plugin_init\s*\(' -or
    $code -notmatch '#define\s+WAL2JSON_VERSION\s+"2\.6"') {
    throw 'Upstream plugin API or version changed; re-audit before compiling'
}
$def = Join-Path $UpstreamDir 'pgextwin-exports.def'
[IO.File]::WriteAllLines($def,[string[]]@('LIBRARY wal2json','EXPORTS','    Pg_magic_func','    _PG_output_plugin_init'),[Text.Encoding]::ASCII)
$vswhere = Join-Path ([Environment]::GetFolderPath('ProgramFilesX86')) 'Microsoft Visual Studio/Installer/vswhere.exe'
if (-not (Test-Path $vswhere)) { throw 'vswhere missing' }
$vsroot = (& $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath | Select-Object -First 1)
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($vsroot)) { throw 'MSVC x64 toolchain missing' }
$vsdev = Join-Path $vsroot.Trim() 'Common7/Tools/VsDevCmd.bat'
$temp = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [IO.Path]::GetTempPath() }
$cmd = Join-Path $temp 'wal2json-msvc-build.cmd'
$obj = Join-Path $UpstreamDir 'wal2json.obj'
$dll = Join-Path $UpstreamDir 'wal2json.dll'
$lines = @(
    '@echo off',
    ('call "' + $vsdev + '" -arch=x64 -host_arch=x64'),
    'if errorlevel 1 exit /b %errorlevel%',
    ('cd /d "' + $UpstreamDir + '"'),
    ('cl /nologo /O2 /MD /DWIN32 /D__WINDOWS__ /DWIN32_NO_STATUS /D_CRT_SECURE_NO_WARNINGS /D_CRT_NONSTDC_NO_WARNINGS /I"{0}" /I"{1}" /I"{2}" /I"{3}" /c "{4}" /Fo"{5}"' -f
        (Join-Path $PgRoot 'include/server/port/win32_msvc'),(Join-Path $PgRoot 'include/server/port/win32'),
        (Join-Path $PgRoot 'include/server'),(Join-Path $PgRoot 'include'),$source,$obj),
    'if errorlevel 1 exit /b %errorlevel%',
    ('link /nologo /DLL /MACHINE:X64 /OUT:"{0}" /DEF:"{1}" "{2}" "{3}"' -f
        $dll,$def,$obj,(Join-Path $PgRoot 'lib/postgres.lib')),
    'if errorlevel 1 exit /b %errorlevel%',
    ('dumpbin /nologo /exports "' + $dll + '"'),
    'if errorlevel 1 exit /b %errorlevel%'
)
[IO.File]::WriteAllLines($cmd,[string[]]$lines,[Text.Encoding]::ASCII)
$output = @(& cmd.exe /d /c $cmd)
if ($LASTEXITCODE -ne 0 -or -not (Test-Path $dll)) {
    $output | ForEach-Object { Write-Host $_ }
    throw 'wal2json MSVC compile/link/dumpbin failed (do not waive)'
}
$dump = $output -join [Environment]::NewLine
foreach ($symbol in @('Pg_magic_func','_PG_output_plugin_init')) {
    if ($dump -notmatch ('(?m)\s' + [regex]::Escape($symbol) + '\s*$')) {
        throw "Required output plugin export missing: $symbol"
    }
}
Write-Host "Built pinned wal2json 2.6 with output plugin entry point"
