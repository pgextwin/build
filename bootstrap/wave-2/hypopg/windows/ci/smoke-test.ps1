[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$PgRoot,
      [Parameter(Mandatory=$true)][int]$PgPort,
      [Parameter(Mandatory=$true)][int]$PostgreSqlMajor)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($PostgreSqlMajor -notin @(15,16,17,18)) { throw 'Only PG15-18 are allowed in this pilot' }
$bin = Join-Path $PgRoot 'bin'
$version = (& (Join-Path $bin 'pg_config.exe') --version).Trim()
if ($LASTEXITCODE -ne 0 -or $version -notmatch ('^PostgreSQL\s+' + $PostgreSqlMajor + '(?:\.|\s)')) {
    throw "Wrong PostgreSQL distribution: $version"
}
$temp = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [IO.Path]::GetTempPath() }
$root = Join-Path $temp ('hypopg-smoke-' + [Guid]::NewGuid().ToString('N'))
$data = Join-Path $root 'data'
$log = Join-Path $root 'server.log'
$sqlFile = Join-Path $root 'functional.sql'
$started = $false
New-Item -Path $root -ItemType Directory -Force | Out-Null
try {
    & (Join-Path $bin 'initdb.exe') -D $data -U postgres -A trust --encoding=UTF8 --no-locale
    if ($LASTEXITCODE -ne 0) { throw 'initdb failed' }
    & (Join-Path $bin 'pg_ctl.exe') -D $data -l $log -o "-p $PgPort -c listen_addresses=127.0.0.1" start
    if ($LASTEXITCODE -ne 0) { throw 'pg_ctl start failed' }
    $started = $true
    $ready = $false
    for ($i=0; $i -lt 45; $i++) {
        & (Join-Path $bin 'pg_isready.exe') -h 127.0.0.1 -p $PgPort -q
        if ($LASTEXITCODE -eq 0) { $ready = $true; break }
        Start-Sleep -Seconds 2
    }
    if (-not $ready) { throw 'Temporary PostgreSQL never became ready' }

@'
\set ON_ERROR_STOP on
CREATE EXTENSION hypopg;
DO $$ BEGIN
    IF (SELECT extversion FROM pg_extension WHERE extname='hypopg') IS DISTINCT FROM '1.4.3' THEN
        RAISE EXCEPTION 'Wrong HypoPG extension version';
    END IF;
END $$;
CREATE TABLE public.pgextwin_hypopg_probe (key_value integer NOT NULL, filler text NOT NULL);
INSERT INTO public.pgextwin_hypopg_probe
SELECT i, repeat('pgextwin', 20) FROM generate_series(1, 100000) AS i;
ANALYZE public.pgextwin_hypopg_probe;
SET enable_bitmapscan = off;
DO $$
DECLARE plan_line text; plan_text text := '';
BEGIN
    FOR plan_line IN EXECUTE
      'EXPLAIN (COSTS OFF) SELECT * FROM public.pgextwin_hypopg_probe WHERE key_value=4242'
    LOOP
        plan_text := plan_text || ' ' || plan_line;
    END LOOP;
    IF plan_text NOT LIKE '%Seq Scan%' THEN
        RAISE EXCEPTION 'Unexpected baseline plan: %', plan_text;
    END IF;
END $$;
SELECT * FROM hypopg_create_index(
  'CREATE INDEX ON public.pgextwin_hypopg_probe (key_value)'
);
DO $$
DECLARE plan_line text; plan_text text := '';
BEGIN
    IF (SELECT count(*) FROM hypopg_list_indexes
        WHERE table_name='pgextwin_hypopg_probe') <> 1 THEN
        RAISE EXCEPTION 'HypoPG did not register exactly one hypothetical index';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_index
               WHERE indrelid='public.pgextwin_hypopg_probe'::regclass) THEN
        RAISE EXCEPTION 'A real index unexpectedly appeared';
    END IF;
    FOR plan_line IN EXECUTE
      'EXPLAIN (COSTS OFF) SELECT * FROM public.pgextwin_hypopg_probe WHERE key_value=4242'
    LOOP
        plan_text := plan_text || ' ' || plan_line;
    END LOOP;
    IF plan_text NOT LIKE '%Index Scan%' THEN
        RAISE EXCEPTION 'Hypothetical index did not change plan: %', plan_text;
    END IF;
END $$;
SELECT hypopg_reset();
DO $$
DECLARE plan_line text; plan_text text := '';
BEGIN
    IF EXISTS (SELECT 1 FROM hypopg_list_indexes) THEN
        RAISE EXCEPTION 'HypoPG reset did not clear backend-local indexes';
    END IF;
    FOR plan_line IN EXECUTE
      'EXPLAIN (COSTS OFF) SELECT * FROM public.pgextwin_hypopg_probe WHERE key_value=4242'
    LOOP
        plan_text := plan_text || ' ' || plan_line;
    END LOOP;
    IF plan_text NOT LIKE '%Seq Scan%' THEN
        RAISE EXCEPTION 'Reset did not restore baseline plan: %', plan_text;
    END IF;
END $$;
DROP TABLE public.pgextwin_hypopg_probe;
DROP EXTENSION hypopg;
'@ | Set-Content -Path $sqlFile -Encoding utf8

    & (Join-Path $bin 'psql.exe') -X -w -h 127.0.0.1 -p $PgPort -U postgres -d postgres -v ON_ERROR_STOP=1 -f $sqlFile
    if ($LASTEXITCODE -ne 0) { throw 'HypoPG planner test failed' }
    Write-Host "PASS: PG$PostgreSqlMajor CREATE EXTENSION, hypothetical index, EXPLAIN change, no physical index and reset"
}
catch {
    if (Test-Path $log) {
        Write-Host '----- PostgreSQL test log -----'
        Get-Content $log -Tail 250 | ForEach-Object { Write-Host $_ }
    }
    throw
}
finally {
    if ($started -or (Test-Path (Join-Path $data 'postmaster.pid'))) {
        try { & (Join-Path $bin 'pg_ctl.exe') -D $data -m immediate stop | Out-Null }
        catch { Write-Warning "Failed to stop temporary PostgreSQL: $_" }
    }
    if (Test-Path $root) {
        try { Remove-Item $root -Recurse -Force }
        catch { Write-Warning "Failed to remove temporary PostgreSQL data: $_" }
    }
}
