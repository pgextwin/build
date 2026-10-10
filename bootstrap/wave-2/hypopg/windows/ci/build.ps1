[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$PgRoot,
      [Parameter(Mandatory=$true)][string]$UpstreamDir)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$config = Get-Content (Join-Path $PSScriptRoot '../../config/extension.json') -Raw | ConvertFrom-Json
$expected = [string]$config.upstream.commit
if ($expected -cnotmatch '^[a-f0-9]{40}$' -or $config.upstream.repository -cne 'HypoPG/hypopg') { throw 'Invalid upstream identity' }
$actual = (& git -C $UpstreamDir rev-parse HEAD).Trim().ToLowerInvariant()
if ($LASTEXITCODE -ne 0 -or $actual -cne $expected) { throw "Upstream commit mismatch: $actual" }
$pgVersion = (& (Join-Path $PgRoot 'bin/pg_config.exe') --version).Trim()
if ($LASTEXITCODE -ne 0 -or $pgVersion -notmatch '^PostgreSQL\s+(15|16|17|18)(?:\.|\s)') { throw "Unsupported PostgreSQL version: $pgVersion" }
$control = Get-Content (Join-Path $UpstreamDir 'hypopg.control') -Raw
if ($control -notmatch "(?m)^default_version\s*=\s*'1\.4\.3'\s*$") { throw 'Unexpected upstream SQL version' }
$src = @('hypopg.c','hypopg_index.c','import/hypopg_import.c','import/hypopg_import_index.c')
$functions = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
foreach ($file in $src) {
    $path = Join-Path $UpstreamDir $file
    if (-not (Test-Path $path -PathType Leaf)) { throw "Source missing: $file" }
    $code = Get-Content $path -Raw
    foreach ($match in [regex]::Matches($code, '\bPG_FUNCTION_INFO_V1\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)')) {
        [void]$functions.Add($match.Groups[1].Value)
    }
}
if ($functions.Count -lt 10 -or -not $functions.Contains('hypopg_create_index') -or -not $functions.Contains('hypopg_reset')) {
    throw 'Unexpected HypoPG export inventory'
}
$module = Get-Content (Join-Path $UpstreamDir 'hypopg.c') -Raw
if ($module -notmatch '\bPG_MODULE_MAGIC\b' -or $module -notmatch '\b_PG_init\s*\(') { throw 'Missing magic or initializer' }
$exports = @('Pg_magic_func','_PG_init')
foreach ($f in $functions) { $exports += $f; $exports += "pg_finfo_$f" }
$exports = @($exports | Sort-Object -Unique)
$def = Join-Path $UpstreamDir 'pgextwin-exports.def'
[IO.File]::WriteAllLines($def,[string[]](@('LIBRARY hypopg','EXPORTS') + @($exports | ForEach-Object {"    $_"})),[Text.Encoding]::ASCII)

$vswhere = Join-Path ([Environment]::GetFolderPath('ProgramFilesX86')) 'Microsoft Visual Studio/Installer/vswhere.exe'
if (-not (Test-Path $vswhere)) { throw 'vswhere.exe was not found' }
$vsroot = (& $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath | Select-Object -First 1)
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($vsroot)) { throw 'Visual Studio C++ x64 toolchain missing' }
$vsdev = Join-Path $vsroot.Trim() 'Common7/Tools/VsDevCmd.bat'
if (-not (Test-Path $vsdev)) { throw 'VsDevCmd.bat missing' }
$commands = [System.Collections.Generic.List[string]]::new()
$commands.Add('@echo off')
$commands.Add('call "' + $vsdev + '" -arch=x64 -host_arch=x64')
$commands.Add('if errorlevel 1 exit /b %errorlevel%')
$commands.Add('cd /d "' + $UpstreamDir + '"')
$objects = [System.Collections.Generic.List[string]]::new()
foreach ($file in $src) {
    $source = Join-Path $UpstreamDir $file
    $obj = Join-Path $UpstreamDir (($file -replace '[/\\]','_') -replace '\.c$','.obj')
    $objects.Add('"' + $obj + '"')
    $commands.Add(('cl /nologo /O2 /MD /DWIN32 /DWIN32_NO_STATUS /D__WINDOWS__ /D_CRT_SECURE_NO_WARNINGS /D_CRT_NONSTDC_NO_WARNINGS /I"{0}" /I"{1}" /I"{2}" /I"{3}" /I"{4}" /c "{5}" /Fo"{6}"' -f
        (Join-Path $PgRoot 'include/server/port/win32_msvc'),(Join-Path $PgRoot 'include/server/port/win32'),
        (Join-Path $PgRoot 'include/server'),(Join-Path $PgRoot 'include'),$UpstreamDir,$source,$obj))
    $commands.Add('if errorlevel 1 exit /b %errorlevel%')
}
$dll = Join-Path $UpstreamDir 'hypopg.dll'
$commands.Add(('link /nologo /DLL /MACHINE:X64 /OUT:"{0}" /DEF:"{1}" {2} "{3}"' -f
    $dll,$def,($objects -join ' '),(Join-Path $PgRoot 'lib/postgres.lib')))
$commands.Add('if errorlevel 1 exit /b %errorlevel%')
$commands.Add('dumpbin /nologo /exports "' + $dll + '"')
$commands.Add('if errorlevel 1 exit /b %errorlevel%')
$temp = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [IO.Path]::GetTempPath() }
$cmd = Join-Path $temp 'hypopg-msvc-build.cmd'
[IO.File]::WriteAllLines($cmd,[string[]]$commands.ToArray(),[Text.Encoding]::ASCII)
$output = @(& cmd.exe /d /c $cmd)
if ($LASTEXITCODE -ne 0 -or -not (Test-Path $dll)) {
    $output | ForEach-Object { Write-Host $_ }
    throw 'HypoPG MSVC compile/link/dumpbin failed'
}
$dump = $output -join [Environment]::NewLine
foreach ($symbol in $exports) {
    if ($dump -notmatch ('(?m)\s' + [regex]::Escape($symbol) + '\s*$')) {
        throw "Required DLL export missing: $symbol"
    }
}
Write-Host "Built pinned HypoPG 1.4.3; verified $($exports.Count) DLL exports."
