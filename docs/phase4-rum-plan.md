# Phase 4 second-extension plan: RUM

## Decision

Use **RUM** as the second pgextwin extension pilot.

- Upstream: `postgrespro/rum`
- Initial pinned release candidate: `1.3.15`
- Extension version inside that release: `1.3`
- License: PostgreSQL License
- External runtime dependencies: none identified beyond PostgreSQL
- Shared preload requirement: none

## Why RUM

The second pilot must prove that `pgextwin/build` is not accidentally specialized for pg_bigm.

RUM is a useful second profile because:

1. it is a substantial multi-source C extension rather than a two-source module,
2. it implements a PostgreSQL index access method,
3. it has a large upstream regression-test surface,
4. its stable GitHub Release does not publish Windows binary assets,
5. upstream history contains repeated Windows installation/build questions,
6. current upstream code includes explicit Windows build handling.

HypoPG was considered but deprioritized because a 2026 upstream issue already provides Windows build scripts and PG17/18/19beta DLLs, which creates avoidable overlap with pgextwin's purpose.

## Upstream facts for 1.3.15

The stable tag contains:

- `rum.control` with `default_version = '1.3'`,
- a PGXS Makefile,
- a Meson build file,
- PostgreSQL License text,
- multiple C source files under `src/`.

The Meson file explicitly handles `host_system == 'windows'`, but also states that standalone PGXS infrastructure is not supported by that Meson configuration and that it is intended to be compiled inside the PostgreSQL contrib source tree.

Therefore pgextwin should not depend on that Meson path for the initial package.

## Proposed Windows build profile

Use an out-of-tree **CMake + MSVC** wrapper, analogous to pg_bigm, while compiling the unmodified pinned upstream C sources.

Expected source set for RUM 1.3.15:

```text
src/btree_rum.c
src/rum_arr_utils.c
src/rum_ts_utils.c
src/rumbtree.c
src/rumbulk.c
src/rumdatapage.c
src/rumentrypage.c
src/rumget.c
src/ruminsert.c
src/rumscan.c
src/rumsort.c
src/rumtsquery.c
src/rumutil.c
src/rumvacuum.c
src/rumvalidate.c
```

The build wrapper should:

- require `PGROOT/include/server/postgres.h`,
- require `PGROOT/lib/postgres.lib`,
- include PostgreSQL's `port/win32_msvc`, `port/win32`, server, and client include directories,
- include upstream `src/`,
- build `rum.dll`,
- link `postgres.lib`,
- use the MSVC DLL runtime,
- leave upstream source files unchanged whenever possible.

PostgreSQL's `PG_FUNCTION_INFO_V1` macro marks SQL-callable functions with `PGDLLEXPORT` on Windows, so a hand-maintained .DEF file should not be introduced unless the actual build proves additional non-SQL symbols must be exported.

## SQL/package handling

The upstream Makefile generates `rum--1.3.sql` from `rum_init.sql`.

The pgextwin package hook should reproduce that result by copying:

```text
rum_init.sql → share/extension/rum--1.3.sql
rum.control → share/extension/rum.control
rum--1.0--1.1.sql
rum--1.1--1.2.sql
rum--1.2--1.3.sql
```

The final ZIP should contain:

```text
lib/rum.dll
share/extension/rum.control
share/extension/rum--1.3.sql
share/extension/rum--1.0--1.1.sql
share/extension/rum--1.1--1.2.sql
share/extension/rum--1.2--1.3.sql
LICENSE
UPSTREAM-README.md
PACKAGE-INFO.txt
```

## Proposed manifest

```json
{
  "schemaVersion": 1,
  "name": "rum",
  "upstream": {
    "repository": "postgrespro/rum",
    "ref": "1.3.15",
    "version": "1.3.15"
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

The compatibility range must still be confirmed by the actual PG14–18 matrix. A failed major is not to be silently dropped; first determine whether it is an upstream compatibility issue or a Windows-port issue.

## Functional smoke test

The minimum Level-4 test should:

1. start a temporary PostgreSQL cluster,
2. run `CREATE EXTENSION rum`,
3. create a table containing text and `tsvector`,
4. insert several rows,
5. create a RUM index using `rum_tsvector_ops`,
6. run a full-text query that uses the RUM index,
7. verify the expected result,
8. clean up the table and extension.

A later enhancement can run a selected subset of upstream regression tests, but the initial pilot must at least validate real RUM index creation and use.

## Phase 4 success criteria

- new `pgextwin/rum` repository exists,
- upstream 1.3.15 is pinned,
- license is verified,
- CMake/MSVC build succeeds without vendoring upstream C sources,
- PG14–18 are tested,
- `CREATE EXTENSION rum` succeeds,
- a real RUM-index query succeeds,
- one ZIP per supported PostgreSQL major is produced,
- README and README_ja document the unofficial Windows distribution,
- reusable workflow requires no pg_bigm-specific change.

If the shared workflow must change, the change must be generic and justified by both pg_bigm and RUM.

---

# Phase 4 第2Extension計画: RUM

第2pilotには **RUM** を採用します。HypoPGは2026年にWindows DLL提供の動きがあるため重複回避の観点から外し、Windows binary assetを公式Releaseで提供していないRUMを優先します。

初期対象は `postgrespro/rum` の `1.3.15` とし、upstreamソースを改変せず、CMake + MSVCのWindows wrapperで `rum.dll` を生成する方針です。

機能テストでは `CREATE EXTENSION rum` だけでなく、実際にRUMインデックスを作成し、全文検索結果を確認します。

この第2pilotの最重要目的は、共通workflowがpg_bigm専用ではないことを証明することです。
