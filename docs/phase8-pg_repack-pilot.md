# Phase 8 technical pilot and productization: pg_repack

## Result

The pg_repack Windows technical pilot and productization are complete.

The final implementation validates upstream pg_repack `ver_1.5.3` / 1.5.3 end-to-end on PostgreSQL 14, 15, 16, 17, and 18.

- Repository: `pgextwin/pg_repack`
- Productization PR: `pgextwin/pg_repack#1`
- Merge commit: `8c23dd6406056d9886b4ac3d5c9111c6b4806786`
- Release workflow run: `37408201041`
- Public Release: `v1.5.3-windows.1`
- Result: PostgreSQL 14–18 PASS
- Catalog publication: complete

## Upstream

- Repository: `reorg/pg_repack`
- Ref: `ver_1.5.3`
- Version: 1.5.3
- License: BSD-style terms in upstream `COPYRIGHT`

pg_repack has two Windows deliverables:

- the server extension `pg_repack.dll`,
- the frontend client `pg_repack.exe`.

Both are built and functionally validated for every PostgreSQL major.

## PostgreSQL 18 module-magic compatibility

pg_repack 1.5.3 predates PostgreSQL 18's extended module-magic support.

The pgextwin build applies the same source-level compatibility direction later adopted upstream by commit:

`82120316e840773e4521314917a97c26b4b5f520`

For PostgreSQL 18, the disposable CI checkout uses `PG_MODULE_MAGIC_EXT` with the pg_repack module name and version. Older PostgreSQL majors retain the normal `PG_MODULE_MAGIC` path.

The pinned upstream source remains the source of truth; pgextwin does not maintain a forked source tree.

## Windows frontend compatibility

The pg_repack frontend helper historically includes PostgreSQL's generic `c.h`. On Windows, the build workspace switches the frontend path to `postgres_fe.h`, selecting PostgreSQL's frontend-specific Win32 mappings.

Modern EDB PostgreSQL Windows installations do not necessarily ship the internal static `libpgport` and `libpgcommon` archives needed by `pg_repack.exe`.

When those archives are absent, CI:

1. reads the exact installed PostgreSQL major/minor from `pg_config.exe`,
2. resolves the matching official `postgres/postgres` release tag,
3. checks out that official PostgreSQL source,
4. uses PostgreSQL's supported Meson/MSVC Windows build path,
5. builds only `libpgport` and `libpgcommon`,
6. links those archives into `pg_repack.exe`.

This avoids storing opaque precompiled compatibility libraries.

Because PostgreSQL frontend support code is statically linked into the client executable, each package includes `POSTGRESQL-COPYRIGHT` copied from the exact PostgreSQL source used for that package.

## Functional smoke test

For every supported PostgreSQL major CI:

1. initializes a temporary PostgreSQL cluster,
2. installs `pg_repack.dll`, `pg_repack.exe`, control, and SQL files,
3. runs `CREATE EXTENSION pg_repack`,
4. creates a primary-key probe table with 20,000 rows,
5. performs UPDATE and DELETE operations,
6. records row count and relation filenode,
7. runs the built `pg_repack.exe` against the probe table,
8. verifies row count is preserved,
9. verifies the relation filenode changes,
10. verifies `repack.version()` reports `pg_repack 1.5.3`,
11. packages the Windows x64 artifact.

This verifies an actual physical table reorganization, not merely DLL loading.

## Published assets

Release `v1.5.3-windows.1` contains:

- `pg_repack-ver_1.5.3-pg14-windows-x64.zip`
  - SHA-256: `ee9650c56fc3b3fdd474da7b686c7a520c6f7982b2ef2a246a99d24401dbfb3e`
- `pg_repack-ver_1.5.3-pg15-windows-x64.zip`
  - SHA-256: `787995b868be030c158b0f65847c3c8989079d1182bd8a92a8a5e7c0a3946c39`
- `pg_repack-ver_1.5.3-pg16-windows-x64.zip`
  - SHA-256: `04c0ca2d871c146ed66d65e316dce6cd2ec84c9f0294c8019cc815291ae33ddf`
- `pg_repack-ver_1.5.3-pg17-windows-x64.zip`
  - SHA-256: `5c14f8e221e78601e641efaa77590a0f051be4271ddbf902f38579d9ab934800`
- `pg_repack-ver_1.5.3-pg18-windows-x64.zip`
  - SHA-256: `da4ded47136e438b876cd2bd55fc0dfe19cb8b2681f51bd5e1e05aac2135b31d`
- `SHA256SUMS.txt`

## Technical acceptance criteria

| Criterion | Result |
|---|---|
| Upstream `ver_1.5.3` pinned | PASS |
| Exact upstream copyright verification | PASS |
| PG14–18 MSVC x64 server DLL build | PASS |
| PG14–18 frontend executable build | PASS |
| PostgreSQL 18 module-magic compatibility | PASS |
| Exact PostgreSQL minor frontend-support provenance | PASS |
| PostgreSQL license notice packaged | PASS |
| CREATE EXTENSION succeeds | PASS |
| Real pg_repack.exe table operation succeeds | PASS |
| Row count preserved | PASS |
| Relation filenode changes | PASS |
| PG14–18 ZIP artifacts produced | PASS |
| Public Release published | PASS |
| Catalog entry published | PASS |

## Next roadmap item

The fixed roadmap now proceeds to **pg_ivm**.

The initial pg_ivm pilot uses upstream `v1.16`, which declares PostgreSQL 13–18 compatibility and already contains an MSVC-aware Meson build path. The first gate is PostgreSQL 17/18, including preload, `CREATE EXTENSION`, IMMV creation, and immediate propagation of INSERT/UPDATE/DELETE changes.

---

# Phase 8 技術pilot・正式公開完了: pg_repack

pg_repack 1.5.3 のWindows対応は完了しました。

PostgreSQL 14〜18の全5世代で、`pg_repack.dll` と `pg_repack.exe` のbuild、`CREATE EXTENSION`、実テーブルに対する `pg_repack.exe` 実行、row count維持、relation filenode変化、ZIP生成まで確認しています。

PostgreSQL 18のmodule-magic差分と、EDB Windows配布に含まれない場合がある `libpgport` / `libpgcommon` については、build workspace内だけで互換処理し、対象minorと同一のPostgreSQL公式sourceからfrontend support libraryを再buildする方式にしました。

Release `v1.5.3-windows.1` はPG14〜18向け5 ZIPとSHA-256一覧を公開済みで、pgextwin catalogにも登録済みです。

次は固定ロードマップ順で pg_ivm へ進みます。
