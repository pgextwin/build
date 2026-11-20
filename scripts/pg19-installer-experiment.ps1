[CmdletBinding()]
param([Parameter(Mandatory=$true)][ValidateSet('A','B','C')][string]$Case)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"
$PSNativeCommandUseErrorActionPreference = $false
$uri = "https://get.enterprisedb.com/postgresql/postgresql-19.0-1-windows-x64.exe"
$expectedBytes = 115245552
$expectedSha256 = "2e3dcb6d764fbdbbeb6dff688990b65b72abe85cd552862277605fedea9632fe"
$exe = Join-Path $env:RUNNER_TEMP "postgresql-19.0-1-windows-x64.exe"
Invoke-WebRequest -Uri $uri -OutFile $exe -MaximumRedirection 3
$len = (Get-Item $exe).Length
$sha = (Get-FileHash $exe -Algorithm SHA256).Hash.ToLowerInvariant()
Write-Host "DOWNLOADED bytes=$len sha256=$sha"
if ($len -ne $expectedBytes -or $sha -cne $expectedSha256) { throw "PIN MISMATCH; execution DENY" }
Write-Host "PIN VERIFIED"
$trace = Join-Path $env:RUNNER_TEMP "pg19-case$Case-debugtrace.log"
$common = @('--mode','unattended','--unattendedmodeui','none','--superpassword','postgres','--debugtrace',$trace)
switch ($Case) {
  'A' { $args = $common + @('--install_runtimes','0','--enable_acledit','1','--enable-components','server,commandlinetools','--disable-components','pgAdmin,stackbuilder','--create_shortcuts','0','--install_runtimes','0') }
  'B' { $args = $common + @('--install_runtimes','0','--enable_acledit','1','--enable-components','server,commandlinetools','--disable-components','stackbuilder','--install-pgadmin','0','--create_shortcuts','0') }
  'C' { $args = $common }
}
Write-Host "CASE $Case ARGS: $($args -join ' ')"
$p = Start-Process -FilePath $exe -ArgumentList $args -Wait -PassThru
Write-Host "CASE $Case INSTALLER EXIT: $($p.ExitCode)"
$pgcfg = "C:\Program Files\PostgreSQL\19\bin\pg_config.exe"
if (Test-Path $pgcfg) { Write-Host "PG_CONFIG: $(& $pgcfg --version)" } else { Write-Host "PG_CONFIG: absent" }
Get-ChildItem $env:TEMP -Filter "*installer*.log" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 3 | ForEach-Object {
  Write-Host "LOGFILE: $($_.FullName)"
  Get-Content $_.FullName -Tail 30 | ForEach-Object { Write-Host "LOG | $_" }
}
if (Test-Path $trace) { Get-Content $trace -Tail 60 | ForEach-Object { Write-Host "TRACE | $_" } }
