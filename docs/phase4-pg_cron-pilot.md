# Phase 4 pilot completion: pg_cron

## Result

The pg_cron technical pilot is complete.

The shared pgextwin reusable workflow has now been validated with a second extension profile that differs materially from pg_bigm:

- upstream native Windows build with MSVC/nmake,
- background-worker runtime behavior,
- shared_preload_libraries requirement,
- SQL-callable functions,
- real scheduled-job execution,
- PostgreSQL 14–18 matrix packaging.

## Upstream

- Repository: `citusdata/pg_cron`
- Release: `v1.6.8`
- Version: `1.6.8`
- Pinned upstream commit: `5cedfa472ccc83567aa23ec645925ed8489a7797`
- License: PostgreSQL-style permissive license
- Windows build system: upstream `Makefile.win`

pg_cron v1.6.8 includes upstream native Windows build support. pgextwin does not need to maintain a source fork for the supported path.

## Validation method

Before `pgextwin/pg_cron` exists, the implementation was exercised from a disposable branch in `ShutenOishi/pg_bigm`.

- Probe PR: `ShutenOishi/pg_bigm#6`
- Probe branch: `phase4/pg-cron-probe`
- Final probe commit: `ece437788d3b1f9672e306918c9479abf91813b1`
- Final workflow run: `37343976468`
- Shared workflow commit used by the run: `0c0262d31e665534f5dff3ae49c20a55fb268a83`

The probe PR was closed without merging after validation.

## PostgreSQL 14/15 compatibility finding

The initial pg_cron v1.6.8 Windows build loaded successfully on PostgreSQL 16–18 but `CREATE EXTENSION pg_cron` failed on PostgreSQL 14/15 because SQL-callable C functions such as `cron_schedule` were not exported from the DLL.

The cause is a PostgreSQL header behavior difference:

- PostgreSQL 14/15: `PG_FUNCTION_INFO_V1()` exports the `pg_finfo_*` metadata function but does not mark the SQL function itself with `PGDLLEXPORT`.
- PostgreSQL 16+: `PG_FUNCTION_INFO_V1()` marks the SQL function itself with `PGDLLEXPORT`, and the central headers also mark `_PG_init/_PG_fini` appropriately for Windows.

The pgextwin compatibility hook therefore applies only for PostgreSQL 14/15:

1. discover functions declared through `PG_FUNCTION_INFO_V1(...)`,
2. generate a temporary `.def` export list,
3. export `_PG_init` plus the SQL-callable functions,
4. create a temporary compatibility copy of `Makefile.win`,
5. add `/DEF:pg_cron.pgextwin.def` to the link command,
6. leave upstream C source unchanged.

`_PG_fini` is not exported because pg_cron declares it but does not define it.

The hook contains a guard that fails if the expected upstream link command changes, requiring review rather than silently producing an unverified binary.

PostgreSQL 16–18 continue to use the upstream `Makefile.win` unchanged.

## Functional smoke test

Each successful matrix entry validates actual scheduler execution, not only DLL loading.

The test:

1. initializes a temporary PostgreSQL cluster,
2. starts PostgreSQL with:
   - `shared_preload_libraries=pg_cron`
   - `cron.database_name=postgres`
   - `cron.use_background_workers=on`
   - sufficient `max_worker_processes`,
3. runs `CREATE EXTENSION pg_cron`,
4. creates a probe table,
5. schedules a one-second pg_cron job,
6. waits for the job to insert a row,
7. verifies the row exists,
8. unschedules the job,
9. drops the test table and extension,
10. stops PostgreSQL in the cleanup path.

This satisfies pgextwin Level-4 functional validation.

## Final matrix

| PostgreSQL | Result |
|---|---|
| 14 | PASS |
| 15 | PASS |
| 16 | PASS |
| 17 | PASS |
| 18 | PASS |

The final full-matrix run completed successfully for every supported PostgreSQL major.

## Final artifacts

The probe run produced:

- `pg_cron-pg14-windows-x64`
  - SHA-256 artifact digest: `520c360cbca55da96327996b8a353684076f1478f7b55d22cbd5003b69852319`
- `pg_cron-pg15-windows-x64`
  - SHA-256 artifact digest: `343474a9fa5d9769793cb5e045d03f8f83ad910b531cb2afc1276ea9d0a03821`
- `pg_cron-pg16-windows-x64`
  - SHA-256 artifact digest: `d02fddffb612e5259594032a34944e9dc42ce46d5dc602f789e5843f55871cdd`
- `pg_cron-pg17-windows-x64`
  - SHA-256 artifact digest: `f5cb4d261e9c3387c950ad7482d230501cc518616c5deeb98772f6ad627a64f2`
- `pg_cron-pg18-windows-x64`
  - SHA-256 artifact digest: `7d7ce4453af3c86b4271d8a3976acc70688d75f61748e2572bf050c7a7880e19`

These are CI probe artifacts, not public pgextwin Releases.

## Phase 4 technical acceptance criteria

| Criterion | Result |
|---|---|
| Shared reusable workflow supports a second extension | PASS |
| Upstream v1.6.8 pinned | PASS |
| Exact upstream LICENSE verification | PASS |
| No vendored upstream C source required | PASS |
| Native MSVC/nmake build works | PASS |
| PG14/15 compatibility handled without C source patch | PASS |
| PG14–18 build successfully | PASS |
| PostgreSQL starts with pg_cron preloaded | PASS |
| CREATE EXTENSION succeeds | PASS |
| Scheduled job actually executes | PASS |
| Per-major ZIP artifacts produced | PASS |
| Shared workflow requires no pg_cron-specific special case | PASS |

## Remaining administrative/productization work

The technical pilot is complete, but Phase 4 is not productized until:

1. public repository `pgextwin/pg_cron` is created,
2. the validated probe implementation is copied into that repository,
3. English/Japanese README and Windows documentation are finalized,
4. CI passes in the real repository,
5. a release branch creates the first official pgextwin pg_cron Release,
6. the release is added to `pgextwin/catalog`,
7. the website consumes the published catalog entry.

Repository creation is an administrative GitHub operation and is the next Work-mode boundary.

---

# Phase 4 pilot完了: pg_cron

## 結果

pg_cronを使った第2Extension技術pilotは完了しました。

pg_bigmとは異なり、pg_cronはbackground worker、`shared_preload_libraries`、MSVC/nmakeによるupstream公式Windowsビルド、実際の定期ジョブ実行を必要とします。そのため、共通Reusable Workflowがpg_bigm固有の構成ではないことを確認できました。

最終的にPostgreSQL 14 / 15 / 16 / 17 / 18の全5世代で、ビルド、preload、`CREATE EXTENSION`、1秒ジョブの実実行、ZIP生成、artifact uploadまで成功しています。

PostgreSQL 14/15ではPostgreSQL側のWindows DLL export仕様差により追加互換処理が必要でした。upstream Cソースは変更せず、一時的なDEFファイルで `_PG_init` とSQL-callable関数だけをexportしています。PostgreSQL 16以降はupstream `Makefile.win` をそのまま使用します。

次の境界はGitHub管理操作です。正式な `pgextwin/pg_cron` repositoryを作成した後、この検証済み実装を移植して正式Releaseまで進めます。
