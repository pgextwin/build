# Phase 4 second-extension plan: pg_cron

## Decision

Use **pg_cron** as the second pgextwin extension pilot.

- Upstream: `citusdata/pg_cron`
- Initial pinned release: `v1.6.8`
- Upstream release version: `1.6.8`
- Extension SQL version: `1.6`
- Pinned upstream commit: `5cedfa472ccc83567aa23ec645925ed8489a7797`
- Upstream tag signature: verified
- License: Citus Data PostgreSQL-style permissive license
- Shared preload requirement: `pg_cron`
- Primary Windows build system: upstream `Makefile.win` + MSVC `nmake`

## Why pg_cron

pg_cron is a strong second pilot because it exercises a very different runtime profile from pg_bigm.

pg_bigm is an index/search extension. pg_cron is a background-worker extension that:

1. must be loaded through `shared_preload_libraries`,
2. launches a scheduler background worker,
3. may launch additional database background workers,
4. links PostgreSQL client libraries such as libpq,
5. needs real runtime behavior to be tested rather than only `CREATE EXTENSION`,
6. has official Windows source-build support but no official GitHub Release binary assets.

This makes pg_cron useful for proving that the shared workflow is not specialized around pg_bigm.

## Upstream Windows status

pg_cron `v1.6.8`, released 2026-09-08, added official native Windows build support.

The upstream release notes explicitly include:

- native Windows build support,
- native Windows regression-test fixes,
- improved MinGW support,
- PostgreSQL 19 support.

The upstream README now documents this native Windows procedure:

```cmd
set "PGROOT=C:\Program Files\PostgreSQL\18"
nmake /F Makefile.win
nmake /F Makefile.win install
```

The upstream GitHub Release for `v1.6.8` has no binary assets. Therefore pgextwin does not need to maintain a Windows source fork; it can provide reproducible CI-tested binaries built directly from the official tag.

There are third-party Windows forks and build repositories in the community. pgextwin's value is not inventing a Windows port, but providing a maintained, reproducible, multi-PostgreSQL-version binary distribution for ordinary Windows PostgreSQL installations.

## Supported PostgreSQL matrix

Initial pgextwin target:

```text
PostgreSQL 14
PostgreSQL 15
PostgreSQL 16
PostgreSQL 17
PostgreSQL 18
```

This matches the currently maintained PostgreSQL versions in `pgextwin/build/metadata/postgresql.json`.

Upstream pg_cron supports PostgreSQL 10 or newer, and v1.6.8 explicitly adds PostgreSQL 19 support. The initial pgextwin package therefore does not need extension-specific exclusions for PG14–18 unless the actual Windows matrix proves otherwise.

## Proposed manifest

```json
{
  "schemaVersion": 1,
  "name": "pg_cron",
  "upstream": {
    "repository": "citusdata/pg_cron",
    "ref": "v1.6.8",
    "version": "1.6.8"
  },
  "postgresql": {
    "minMajor": 14,
    "maxMajor": 18
  },
  "windows": {
    "architecture": "x64"
  },
  "license": {
    "verifyAgainstUpstream": true,
    "upstreamPath": "LICENSE"
  }
}
```

## Build hook

The extension-specific `windows/ci/build.ps1` should:

1. locate Visual Studio through `vswhere.exe`,
2. enter the x64 Visual Studio developer environment,
3. set `PGROOT` to the selected PostgreSQL installation,
4. change directory to the pinned upstream source,
5. run:

```cmd
nmake /F Makefile.win all
```

Expected output:

```text
pg_cron.dll
pg_cron--1.0.sql
```

No source patch should be required for v1.6.8.

The upstream `Makefile.win` links:

```text
postgres.lib
libpq.lib
libintl.lib
ws2_32.lib
```

The ordinary Windows PostgreSQL installation used by pgextwin CI is expected to provide the PostgreSQL import libraries.

## Install hook

The test installation hook should copy:

```text
pg_cron.dll
  -> <PGROOT>/lib/pg_cron.dll

pg_cron.control
pg_cron--1.0.sql
pg_cron--*--*.sql
  -> <PGROOT>/share/extension/
```

## Functional smoke test

A pg_cron release must not pass based only on loading the DLL or running `CREATE EXTENSION`.

The Level-4 smoke test should:

1. initialize a temporary PostgreSQL cluster,
2. start PostgreSQL with:
   - `shared_preload_libraries=pg_cron`
   - `cron.database_name=postgres`
   - `cron.use_background_workers=on`
   - sufficient `max_worker_processes`,
3. run `CREATE EXTENSION pg_cron`,
4. create a probe table,
5. schedule a 1-second pg_cron job,
6. verify that the scheduled job actually inserts a row,
7. unschedule the job,
8. drop the probe table and extension,
9. stop the temporary cluster in a `finally` path.

Using `cron.use_background_workers=on` avoids making the primary CI result depend on libpq password configuration while still validating the scheduler and worker execution path.

## Package layout

Expected ZIP:

```text
lib/
  pg_cron.dll

share/
  extension/
    pg_cron.control
    pg_cron--1.0.sql
    pg_cron--1.0--1.1.sql
    pg_cron--1.1--1.2.sql
    pg_cron--1.2--1.3.sql
    pg_cron--1.3--1.4.sql
    pg_cron--1.4--1.4-1.sql
    pg_cron--1.4-1--1.5.sql
    pg_cron--1.5--1.6.sql

LICENSE
UPSTREAM-README.md
UPSTREAM-CHANGELOG.md
PACKAGE-INFO.txt
```

Asset naming:

```text
pg_cron-v1.6.8-pg14-windows-x64.zip
pg_cron-v1.6.8-pg15-windows-x64.zip
pg_cron-v1.6.8-pg16-windows-x64.zip
pg_cron-v1.6.8-pg17-windows-x64.zip
pg_cron-v1.6.8-pg18-windows-x64.zip
```

## Documentation requirements

The future `pgextwin/pg_cron` repository should provide:

- `README.md`
- `README_ja.md`
- `docs/windows_ja.md`
- exact upstream `LICENSE`
- explicit statement that binaries are unofficial
- links to official pg_cron documentation
- clear instructions for:
  - `shared_preload_libraries`
  - `cron.database_name`
  - `cron.timezone`
  - `cron.use_background_workers`
  - libpq/pg_hba/pgpass considerations
  - the one-database-per-cluster pg_cron metadata limitation

The documentation should make clear that pgextwin only distributes the Windows binary package. pg_cron behavior and configuration remain defined by upstream.

## Phase 4 success criteria

- `pgextwin/pg_cron` exists as a public repository,
- upstream `v1.6.8` is pinned,
- exact upstream license verification succeeds,
- no vendored upstream C source is kept in the packaging repository,
- official `Makefile.win` is used without source patching where possible,
- PG14–18 all build successfully,
- PostgreSQL starts with pg_cron preloaded,
- `CREATE EXTENSION pg_cron` succeeds,
- a scheduled 1-second job actually executes,
- one ZIP is produced for every supported PostgreSQL major,
- English and Japanese documentation is present,
- the shared reusable workflow requires no pg_cron-specific special case.

If a shared-workflow change is necessary, it must remain extension-generic and preserve the pg_bigm pilot.

---

# Phase 4 第2Extension計画: pg_cron

第2pilotには **pg_cron** を採用します。

pg_cron v1.6.8ではupstream自身がnative Windows buildを正式に追加しており、`Makefile.win` とVisual Studio/`nmake`を使った手順も公式READMEに掲載されています。一方、公式GitHub ReleaseにはWindowsバイナリassetがありません。

そのためpgextwinでは独自Windows forkを作るのではなく、公式タグを固定して、メンテナンス対象PostgreSQL 14〜18について継続的にビルド・実機能テストしたWindows x64 ZIPを提供します。

機能テストは `CREATE EXTENSION` だけでなく、`shared_preload_libraries=pg_cron` で起動し、1秒間隔のジョブを登録して実際にSQLが実行されることまで確認します。

このpilotの目的は、pgextwinの共通workflowが検索・インデックス系拡張だけでなく、background workerを持つ拡張にも適用できることを証明することです。
