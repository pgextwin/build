
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$PgRoot,
      [Parameter(Mandatory=$true)][int]$PgPort,
      [Parameter(Mandatory=$true)][int]$PostgreSqlMajor)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if($PostgreSqlMajor -notin @(14,15,16,17,18)){throw 'PG14-18 only'}
$name=(Get-Content (Join-Path $PSScriptRoot '../../config/extension.json') -Raw | ConvertFrom-Json).name
$bin=Join-Path $PgRoot 'bin'
$temp=if($env:RUNNER_TEMP){$env:RUNNER_TEMP}else{[IO.Path]::GetTempPath()}
$root=Join-Path $temp ('third-wave-'+$name+'-'+[guid]::NewGuid().ToString('N'))
$data=Join-Path $root 'data'
$log=Join-Path $root 'server.log'
New-Item $root -ItemType Directory -Force|Out-Null
$started=$false
try{
  $version=(& (Join-Path $bin 'pg_config.exe') --version).Trim()
  if($LASTEXITCODE -ne 0 -or $version -notmatch ('^PostgreSQL\s+'+$PostgreSqlMajor+'(?:\.|\s)')){throw "Wrong PG $version"}
  & (Join-Path $bin 'initdb.exe') -D $data -U postgres -A trust --encoding=UTF8 --no-locale
  if($LASTEXITCODE -ne 0){throw 'initdb failed'}
  $opts="-p $PgPort -c listen_addresses=127.0.0.1"
  if($name -eq 'pg_store_plans'){$opts+=' -c shared_preload_libraries=pg_store_plans -c compute_query_id=on'}
  & (Join-Path $bin 'pg_ctl.exe') -D $data -l $log -o $opts start
  if($LASTEXITCODE -ne 0){throw 'pg_ctl failed'}
  $started=$true
  $ready=$false
  for($i=0;$i -lt 45;$i++){
    & (Join-Path $bin 'pg_isready.exe') -h 127.0.0.1 -p $PgPort -q
    if($LASTEXITCODE -eq 0){$ready=$true;break}
    Start-Sleep -Seconds 2
  }
  if(-not $ready){throw 'PG readiness timeout'}
  $out=@(& (Join-Path $bin 'psql.exe') -X -w -A -t -h 127.0.0.1 -p $PgPort -U postgres -d postgres -v ON_ERROR_STOP=1 -f (Join-Path $PSScriptRoot 'test-feature.sql') 2>&1)
  if($LASTEXITCODE -ne 0){$out|ForEach-Object{Write-Host $_};throw "$name SQL test failed"}
  if($name -eq 'pgtap'){
    $tap=$out -join [Environment]::NewLine
    if($tap -notmatch '(?m)^1\.\.2\r?$' -or
       $tap -notmatch '(?m)^ok 1 - pgextwin positive\r?$' -or
       $tap -notmatch '(?m)^not ok 2 - pgextwin intentional failure\r?$'){
       throw "TAP positive/negative assertion audit failed: $tap"
    }
  }
  if($name -eq 'pg_variables'){
    $test=@(& (Join-Path $bin 'psql.exe') -X -w -A -t -h 127.0.0.1 -p $PgPort -U postgres -d postgres -v ON_ERROR_STOP=1 -c "SELECT count(*) FROM pgv_list() WHERE package='pgextwin_session'" 2>&1)
    if($LASTEXITCODE -ne 0 -or ($test -join '').Trim() -ne '0'){throw "Session variable leaked: $($test -join ' ')"}
  }
  Write-Host "PASS: $name PG$PostgreSqlMajor functional SQL"
}catch{
  if(Test-Path $log){Get-Content $log -Tail 150|ForEach-Object{Write-Host $_}}
  throw
}finally{
  if($started -or (Test-Path (Join-Path $data 'postmaster.pid'))){
    try{& (Join-Path $bin 'pg_ctl.exe') -D $data -m immediate stop|Out-Null}catch{Write-Warning "Stop: $_"}
  }
  if(Test-Path $root){try{Remove-Item $root -Recurse -Force}catch{Write-Warning "Cleanup: $_"}}
}
