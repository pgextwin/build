# Phase 9 technical pilot and productization: pg_ivm

## Result

The pg_ivm Windows technical pilot and productization are complete.

The final implementation validates upstream pg_ivm `v1.16` / 1.16 end-to-end on PostgreSQL 14, 15, 16, 17, and 18.

- Repository: `pgextwin/pg_ivm`
- Productization PR: `pgextwin/pg_ivm#1`
- Merge commit: `1f93499e8f9f1da0d9ddac626a31be89f4f9fce4`
- Full pre-merge validation run: `37412621272`
- Release workflow run: `37433225642`
- Public Release: `v1.16-windows.1`
- Result: PostgreSQL 14–18 PASS
- Catalog publication: complete

## Upstream

- Repository: `sraoss/pg_ivm`
- Ref: `v1.16`
- Version: 1.16
- License: PostgreSQL-style terms in upstream `LICENSE`
- Upstream compatibility: PostgreSQL 13–18
- pgextwin release target: maintained PostgreSQL 14–18

## Windows build result

pg_ivm v1.16 already contains an MSVC-aware Meson build path. pgextwin uses that upstream build path rather than maintaining a forked source tree.

A historical Windows linkage mismatch was reported upstream in issue #138. Upstream commit `49b52bcd5ec96c2c496212e4a9cd11b023dad0a9` added the required `PGDLLEXPORT` declarations, and v1.16 contains that fix.

### PostgreSQL 14/15 export compatibility

The pilot found an additional difference in the older Windows PostgreSQL export model.

pgextwin generates an explicit DEF file from upstream `PG_FUNCTION_INFO_V1(...)` declarations and exports:

- `Pg_magic_func`
- `_PG_init`
- every SQL-callable function declared with `PG_FUNCTION_INFO_V1(...)`
- every matching `pg_finfo_<function>` V1 ABI metadata function

The same explicit export set is used on PG16–18 and verified with `dumpbin /exports`.

### PostgreSQL 14 backend data-symbol compatibility

On PostgreSQL 14, two data symbols referenced by pg_ivm's copied backend compatibility code are not linkable through the ordinary Windows `postgres.lib`:

- `InvalidObjectAddress`
- `quote_all_identifiers`

In the disposable build checkout only:

- the `CreateTableAsRelExists(stmt)` control flow is preserved while the invalid ObjectAddress return is constructed locally with `ObjectAddressSet(...)`,
- the `quote_all_identifiers` GUC is read with the exported `GetConfigOption(...)` function instead of importing the backend data variable.

No PostgreSQL replacement binary or opaque compatibility object is distributed.

## Functional smoke test

For every supported PostgreSQL major CI:

1. verifies the exact upstream LICENSE,
2. builds `pg_ivm.dll` with Meson/MSVC x64,
3. verifies the expected DLL export surface,
4. installs the extension files,
5. starts PostgreSQL with pg_ivm preloaded,
6. runs `CREATE EXTENSION pg_ivm`,
7. creates a primary-key base table,
8. creates a real IMMV with `pgivm.create_immv(...)`,
9. performs INSERT, UPDATE, and DELETE on the base table,
10. verifies the IMMV immediately reflects all changes,
11. verifies `pgivm.get_immv_def(...)`,
12. builds and uploads the Windows x64 ZIP.

This validates actual incremental maintenance behavior, not only DLL loading.

## Published assets

Release `v1.16-windows.1` contains:

- `pg_ivm-v1.16-pg14-windows-x64.zip`
  - SHA-256: `1c804f15ba1a9904c08a4225cfb2d0ef62e666469b630e03067c66fc32f2f900`
- `pg_ivm-v1.16-pg15-windows-x64.zip`
  - SHA-256: `6be1fbfc4b373b15cb9e0a73a82fe0dd3afe1b10a9232cc87e04c1be964c5523`
- `pg_ivm-v1.16-pg16-windows-x64.zip`
  - SHA-256: `002173aaa176ef60373d532ba4ce21a71d759ec2a1b1f02abdf066220ab235a4`
- `pg_ivm-v1.16-pg17-windows-x64.zip`
  - SHA-256: `2f8b408f3e126a8ecae528e39599990da61ceee6ca2a9cc99a0df442b9773366`
- `pg_ivm-v1.16-pg18-windows-x64.zip`
  - SHA-256: `a103918c0f8cb8d1e379416a0052db3f046780585e7ff099cec5a2c7ba8582d5`
- `SHA256SUMS.txt`

## Operational note

pg_ivm should be loaded through `shared_preload_libraries` or `session_preload_libraries` as documented upstream. The pgextwin catalog records `pg_ivm` as a shared-preload dependency for the normal server-wide installation path.

For dump/restore or PostgreSQL major upgrades, preserve/recreate IMMV metadata using the current upstream procedure. v1.16 provides `pgivm.get_restore_immv_commands()` and the helper script `scripts/pg_ivm_dump_metadata`.

## Technical acceptance criteria

| Criterion | Result |
|---|---|
| Upstream `v1.16` pinned | PASS |
| Exact upstream LICENSE verification | PASS |
| PG14–18 MSVC x64 build | PASS |
| PG14/15 explicit DLL export compatibility | PASS |
| PG14 backend data-symbol compatibility | PASS |
| Required DLL exports verified | PASS |
| PostgreSQL starts with pg_ivm preloaded | PASS |
| CREATE EXTENSION succeeds | PASS |
| Real IMMV creation succeeds | PASS |
| INSERT propagation succeeds | PASS |
| UPDATE propagation succeeds | PASS |
| DELETE propagation succeeds | PASS |
| IMMV definition verification succeeds | PASS |
| PG14–18 ZIP artifacts produced | PASS |
| Public Release published | PASS |
| Catalog entry published | PASS |

## Next roadmap item

The fixed initial roadmap now proceeds to **pg_qualstats**.

The pg_qualstats pilot uses upstream `2.1.4`. Upstream already includes explicit Windows export fixes and a Windows-safe replacement for a non-exported PostgreSQL data symbol. The first pgextwin gate is PostgreSQL 17/18, with real predicate-statistics collection rather than only DLL loading.

---

# Phase 9 技術pilot・正式公開完了: pg_ivm

pg_ivm 1.16 のWindows対応は完了しました。

PostgreSQL 14〜18の全5世代で、MSVC x64 build、DLL export検証、preload、`CREATE EXTENSION`、実IMMV作成、base tableへのINSERT / UPDATE / DELETEの即時反映、ZIP生成まで成功しています。

PG14/15では旧Windows exportモデルに合わせた明示DEFを利用し、PG14では通常の `postgres.lib` から参照できないbackend data symbolを、同等のローカル値・export済み関数経由へ置換します。upstream v1.16自体をforkするのではなく、CIの一時checkoutだけを変更します。

Release `v1.16-windows.1` はPG14〜18向け5 ZIPとSHA-256一覧を公開済みで、pgextwin catalogにも登録済みです。

次は固定ロードマップ最後の pg_qualstats へ進みます。
