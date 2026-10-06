# Phase 5 technical pilot completion: pg_hint_plan

## Result

The pg_hint_plan Windows technical pilot is complete.

The final probe validated PostgreSQL 14, 15, 16, 17, and 18 end-to-end with PostgreSQL-major-specific upstream releases, exact upstream license verification, MSVC x64 builds, real optimizer-hint behavior, packaging, and the PostgreSQL 14–16 query-jumble compatibility path.

The probe was intentionally run from a disposable branch in `pgextwin/pg_bigm` before creation of the permanent `pgextwin/pg_hint_plan` repository.

- Probe PR: `pgextwin/pg_bigm#8`
- Probe branch: `phase5/pg-hint-plan-probe`
- Final probe commit: `0bc90ad9a2124b47291ae2b797a313cc47f02950`
- Final workflow run: `37380814888`
- Final result: PostgreSQL 14–18 PASS; Release job skipped as intended

The probe PR is not a product change to pg_bigm and must not be merged.

## Upstream release mapping

pg_hint_plan maintains a separate stable release series for each PostgreSQL major version.

| PostgreSQL | Upstream ref | pg_hint_plan version |
|---:|---|---:|
| 14 | `REL14_1_4_4` | 1.4.4 |
| 15 | `REL15_1_5_3` | 1.5.3 |
| 16 | `REL16_1_6_2` | 1.6.2 |
| 17 | `REL17_1_7_1` | 1.7.1 |
| 18 | `REL18_1_8_0` | 1.8.0 |

This requirement led to a reusable-workflow improvement: the pgextwin extension manifest now supports `upstream.perPostgresql.<major>.ref/version` in addition to the original uniform upstream ref/version form.

## License handling

pg_hint_plan does not use a single LICENSE file for the complete redistribution notice set.

The upstream release contains:

- `COPYRIGHT`
- `COPYRIGHT.postgresql`

The latter differs between some PostgreSQL-major-specific release series.

The shared pgextwin manifest and workflow were therefore extended to support:

1. the original single `license.upstreamPath` form,
2. uniform `license.files[]`,
3. PostgreSQL-major-specific `license.perPostgresql.<major>[]`.

Every selected file is SHA-256 compared against the exact file in the pinned upstream checkout before the build starts.

## PostgreSQL 17 and 18 build path

The PostgreSQL 17 and 18 pg_hint_plan release series includes `query_scan.l` as a separate scanner source.

The Windows probe:

1. installs `winflexbison3` when `win_flex.exe` is unavailable,
2. generates `query_scan.c` from the pinned upstream `query_scan.l`,
3. compiles `pg_hint_plan.c` and `query_scan.c` with MSVC x64,
4. creates a temporary DLL definition file for implemented module entry points,
5. links against the installed PostgreSQL import library,
6. leaves upstream source files unmodified.

The first PG17/18-only probe run (`37359326417`) passed both majors end-to-end.

## PostgreSQL 14–16 query-jumble compatibility

The PostgreSQL 14–16 pg_hint_plan release series directly calls PostgreSQL backend functions including:

- `EnableQueryId()`
- `JumbleQuery()`

Those functions are not available as ordinary exported functions through the standard Windows PostgreSQL import library used by an extension build.

The pilot deliberately did not use an opaque precompiled query-jumble object. Instead, it reconstructs the required object from the **exact official PostgreSQL source release matching the installed binary minor version**.

For the currently maintained matrix:

| PostgreSQL | Official source | SHA-256 pinned by probe | Core source rebuilt |
|---:|---|---|---|
| 14.24 | `postgresql-14.24.tar.bz2` | `a7fa7ed3d558172355f51406097a7bd4f6b473be80f311ef7cda96bf383d8897` | `src/backend/utils/misc/queryjumble.c` |
| 15.19 | `postgresql-15.19.tar.bz2` | `e1a64a87a46b825b88c082e4518161a47aab53c45694964f8ba1df28f7859f89` | `src/backend/utils/misc/queryjumble.c` |
| 16.15 | `postgresql-16.15.tar.bz2` | `c1575341fa7bd40f5274ea465b34390f4dc64cdd0770af327005caaeb9f6b7ed` | `src/backend/nodes/queryjumblefuncs.c` |

The build hook:

1. derives the exact PostgreSQL version from `pg_config --version`,
2. refuses unknown/unreviewed minor versions,
3. downloads the matching official PostgreSQL source archive,
4. verifies the pinned SHA-256,
5. extracts the source,
6. compiles only the required query-jumble object with the matching installed PostgreSQL headers,
7. links that object into the pg_hint_plan DLL.

For PostgreSQL 16, the release source archive also supplies the generated `queryjumblefuncs.funcs.c` and `queryjumblefuncs.switch.c` required by `queryjumblefuncs.c`.

MSVC emits C4273 warnings for `compute_query_id` / `query_id_enabled` in the PostgreSQL 15/16 compatibility-object build because the installed headers declare those backend globals with DLL import linkage. The final DLL nevertheless builds and runs. The pilot therefore includes runtime functional validation of the dependent path rather than treating compiler/link success as sufficient.

## Functional smoke test

For every supported PostgreSQL major the probe:

1. initializes a temporary cluster,
2. starts PostgreSQL with `shared_preload_libraries=pg_hint_plan`,
3. runs `CREATE EXTENSION pg_hint_plan`,
4. creates and analyzes a 50,000-row probe table,
5. applies a `SeqScan(...)` comment hint and verifies the actual EXPLAIN output uses a sequential scan,
6. applies an `IndexScan(...)` comment hint and verifies the actual EXPLAIN output uses the requested index.

For PostgreSQL 14–16 the final smoke test additionally executes:

- `SET compute_query_id = on`
- `SET pg_hint_plan.enable_hint_table = on`

and runs a planning operation after enabling the hint-table path. This explicitly exercises the `EnableQueryId()` / `JumbleQuery()` compatibility path supplied by the rebuilt official PostgreSQL query-jumble object.

## Final matrix

| PostgreSQL | Result |
|---:|---|
| 14 | PASS |
| 15 | PASS |
| 16 | PASS |
| 17 | PASS |
| 18 | PASS |

Final workflow run: `37380814888`

## Final probe artifacts

- `pg_hint_plan-pg14-windows-x64`
  - artifact digest: `sha256:61e2a14ce1909c99db6ccf46351cd4773a74639dbbb88d6665b44308b3dc701b`
- `pg_hint_plan-pg15-windows-x64`
  - artifact digest: `sha256:c55473d62ced8aeaccefe199d58b41a9af323873ef24c85994af34cee0fac3a4`
- `pg_hint_plan-pg16-windows-x64`
  - artifact digest: `sha256:27c9f245758993ef0f5029cf336bcc0813beb31282a32987cfb294525f94dfed`
- `pg_hint_plan-pg17-windows-x64`
  - artifact digest: `sha256:48ec26cbca44397415abb6b8a57fe64bc498deef6d54b8e3d8ac97cc9dd168d3`
- `pg_hint_plan-pg18-windows-x64`
  - artifact digest: `sha256:7a43a34544490e052fe39ddf823135aec477a3c893a87403b71c789b349881c1`

These are CI probe artifacts only, not public pgextwin Releases.

## Shared-infrastructure improvements proven by the pilot

The pg_hint_plan pilot required and validated three generic improvements in `pgextwin/build`:

1. PostgreSQL-major-specific upstream ref/version mappings,
2. exact verification of multiple upstream license files,
3. PostgreSQL-major-specific license-file mappings.

All forms preserve backward compatibility with the existing pg_bigm and pg_cron manifests.

## Technical acceptance criteria

| Criterion | Result |
|---|---|
| PostgreSQL-major-specific upstream releases supported | PASS |
| Exact upstream license notices verified | PASS |
| PostgreSQL-major-specific license text supported | PASS |
| PG17/18 Flex scanner generation on Windows | PASS |
| Native MSVC x64 build | PASS |
| PG14/15 official queryjumble object rebuild | PASS |
| PG16 official queryjumblefuncs object rebuild | PASS |
| No opaque precompiled compatibility object required | PASS |
| PostgreSQL 14–18 preload succeeds | PASS |
| CREATE EXTENSION succeeds | PASS |
| SeqScan hint changes the actual plan | PASS |
| IndexScan hint changes the actual plan | PASS |
| PG14–16 hint-table/query-id compatibility path executes | PASS |
| Per-major ZIP artifacts produced | PASS |
| Public Release intentionally not produced by probe | PASS |

## Historical productization follow-up

The technical pilot was complete at this point. At the time of this report, productization still required:

1. create public repository `pgextwin/pg_hint_plan`,
2. copy the validated implementation into that repository,
3. finalize English/Japanese documentation and Windows-specific guidance,
4. run the full PostgreSQL 14–18 matrix in the real repository,
5. publish the first official pgextwin pg_hint_plan Release,
6. add the verified Release to `pgextwin/catalog`,
7. verify it is rendered by the website.

All seven productization steps above were subsequently completed. `pgextwin/pg_hint_plan` now has a public PostgreSQL 14–18 Release and a catalog entry; the initial eight-extension roadmap is complete.

---

# Phase 5 技術pilot完了: pg_hint_plan

pg_hint_planのWindows技術pilotは完了しました。

PostgreSQL 14〜18の全5世代について、各PostgreSQL向けのupstream releaseを固定し、licenseの厳密照合、MSVC x64 build、`shared_preload_libraries`、`CREATE EXTENSION`、実際のSeqScan/IndexScan Hint適用、ZIP生成まで成功しています。

PG14〜16では標準Windows import libraryから利用できないPostgreSQL coreのquery-jumble関数へ依存するため、対応する公式PostgreSQL source archiveをSHA-256検証した上で、必要なquery-jumble objectだけをCI中に再コンパイルしてlinkします。既成の不透明なprebuilt objectは使用しません。

最終runではPG14〜16についてhint tableを有効化する経路まで実行し、`EnableQueryId()` / `JumbleQuery()` を含む互換経路がruntimeでも動作することを確認しました。

この時点での次の境界は正式な `pgextwin/pg_hint_plan` repositoryの作成でした。その後、repository作成・PG14〜18 Release公開・catalog登録まで完了し、現在は初期8 Extensionロードマップ全体が完了しています。
