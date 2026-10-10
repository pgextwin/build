[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$PgRoot,
      [Parameter(Mandatory=$true)][int]$PgPort,
      [Parameter(Mandatory=$true)][int]$PostgreSqlMajor)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($PostgreSqlMajor -notin @(15,16,17,18)) { throw 'Unsupported PostgreSQL major' }
$bin = Join-Path $PgRoot 'bin'
$version = (& (Join-Path $bin 'pg_config.exe') --version).Trim()
if ($LASTEXITCODE -ne 0 -or $version -notmatch ('^PostgreSQL\s+' + $PostgreSqlMajor + '(?:\.|\s)')) {
    throw "PostgreSQL version mismatch: $version"
}
$temp = if ($env:RUNNER_TEMP) {$env:RUNNER_TEMP} else {[IO.Path]::GetTempPath()}
$root = Join-Path $temp ('wal2json-smoke-' + [Guid]::NewGuid().ToString('N'))
$data = Join-Path $root 'data'
$log = Join-Path $root 'server.log'
$sqlPath = Join-Path $root 'logical-dml-json.sql'
$started = $false
New-Item $root -ItemType Directory -Force | Out-Null
try {
    & (Join-Path $bin 'initdb.exe') -D $data -U postgres -A trust --encoding=UTF8 --no-locale
    if ($LASTEXITCODE -ne 0) { throw 'initdb failed' }

    # CVE-2026-6471: an explicit trusted-output-plugin allowlist is required.
    # Never set unrestricted plugin loading just to make this test pass.
    $conf = Join-Path $data 'postgresql.conf'
    Add-Content $conf -Value "wal_level = logical"
    Add-Content $conf -Value "max_replication_slots = 4"
    Add-Content $conf -Value "max_wal_senders = 4"
    Add-Content $conf -Value "output_plugin_libraries = 'pgoutput, test_decoding, wal2json'"
    & (Join-Path $bin 'pg_ctl.exe') -D $data -l $log -o "-p $PgPort -c listen_addresses=127.0.0.1" start
    if ($LASTEXITCODE -ne 0) { throw 'PostgreSQL could not start with logical decoding enabled' }
    $started = $true
    $ready = $false
    for ($i=0; $i -lt 45; $i++) {
        & (Join-Path $bin 'pg_isready.exe') -h 127.0.0.1 -p $PgPort -q
        if ($LASTEXITCODE -eq 0) { $ready = $true; break }
        Start-Sleep -Seconds 2
    }
    if (-not $ready) { throw 'PostgreSQL did not become ready' }

@'
\set ON_ERROR_STOP on
DO $$ BEGIN
  IF current_setting('wal_level') <> 'logical' THEN
    RAISE EXCEPTION 'wal_level was not logical';
  END IF;
  IF position('wal2json' IN current_setting('output_plugin_libraries')) = 0 THEN
    RAISE EXCEPTION 'wal2json is not allowlisted as a trusted output plugin';
  END IF;
END $$;
CREATE TABLE public.pgextwin_wal2json_probe (id integer PRIMARY KEY, payload text NOT NULL);
ALTER TABLE public.pgextwin_wal2json_probe REPLICA IDENTITY FULL;
SELECT slot_name FROM pg_create_logical_replication_slot('pgextwin_wal2json_pilot','wal2json');
INSERT INTO public.pgextwin_wal2json_probe (id,payload) VALUES (1,'begin');
UPDATE public.pgextwin_wal2json_probe SET payload='changed' WHERE id=1;
DELETE FROM public.pgextwin_wal2json_probe WHERE id=1;
CREATE TEMP TABLE pgextwin_wal2json_decoded AS
SELECT data::jsonb AS payload
FROM pg_logical_slot_get_changes('pgextwin_wal2json_pilot',NULL,NULL,'format-version','1');
DO $$
DECLARE change_kind text;
BEGIN
  FOREACH change_kind IN ARRAY ARRAY['insert','update','delete'] LOOP
    IF NOT EXISTS (
      SELECT 1
      FROM pgextwin_wal2json_decoded d
      CROSS JOIN LATERAL jsonb_array_elements(d.payload->'change') AS item
      WHERE item->>'kind'=change_kind
        AND item->>'schema'='public'
        AND item->>'table'='pgextwin_wal2json_probe'
    ) THEN
      RAISE EXCEPTION 'No decoded wal2json JSON change for kind %',change_kind;
    END IF;
  END LOOP;
  IF (SELECT count(*) FROM public.pgextwin_wal2json_probe) <> 0 THEN
    RAISE EXCEPTION 'DML fixture was not deleted';
  END IF;
END $$;
SELECT pg_drop_replication_slot('pgextwin_wal2json_pilot');
DROP TABLE public.pgextwin_wal2json_probe;
'@ | Set-Content -Path $sqlPath -Encoding utf8
    & (Join-Path $bin 'psql.exe') -X -w -h 127.0.0.1 -p $PgPort -U postgres -d postgres -v ON_ERROR_STOP=1 -f $sqlPath
    if ($LASTEXITCODE -ne 0) { throw 'wal2json end-to-end logical DML JSON verification failed' }
    Write-Host "PASS: PG$PostgreSqlMajor wal2json trusted output plugin, logical slot, INSERT/UPDATE/DELETE JSON, and cleanup"
}
catch {
    if (Test-Path $log) {
        Write-Host '----- PostgreSQL diagnostic log -----'
        Get-Content $log -Tail 250 | ForEach-Object { Write-Host $_ }
    }
    throw
}
finally {
    if ($started -or (Test-Path (Join-Path $data 'postmaster.pid'))) {
        try { & (Join-Path $bin 'pg_ctl.exe') -D $data -m immediate stop | Out-Null }
        catch { Write-Warning "Could not stop temporary PostgreSQL: $_" }
    }
    if (Test-Path $root) {
        try { Remove-Item $root -Recurse -Force }
        catch { Write-Warning "Could not remove temporary PostgreSQL files: $_" }
    }
}
