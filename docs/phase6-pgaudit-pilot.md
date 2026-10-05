# Phase 6 technical pilot completion: pgAudit

## Result

The pgAudit Windows technical pilot is complete.

The final probe validated PostgreSQL 14, 15, 16, 17, and 18 end-to-end using the stable pgAudit release intended for each PostgreSQL major version.

- Probe PR: `pgextwin/pg_bigm#11`
- Probe branch: `phase6/pgaudit-probe`
- Final workflow run: `37383373102`
- Result: PostgreSQL 14–18 PASS
- Release job: skipped as intended

The probe PR was closed without merging.

## Upstream release mapping

| PostgreSQL | pgAudit ref/version |
|---:|---|
| 14 | `1.6.3` |
| 15 | `1.7.1` |
| 16 | `16.1` |
| 17 | `17.1` |
| 18 | `18.0` |

Each ref is an official pgAudit release. Upstream GitHub Releases contain no Windows binary assets.

## Windows build

The probe builds the pinned upstream `pgaudit.c` with MSVC x64 and links it against the target PostgreSQL installation.

The DLL export definition is generated from the pinned source and includes:

- `Pg_magic_func`
- `_PG_init`
- SQL-callable functions declared by `PG_FUNCTION_INFO_V1(...)`
  - `pgaudit_ddl_command_end`
  - `pgaudit_sql_drop`

This explicitly addresses a recurring failure mode in historical Windows build reports where a DLL compiled but PostgreSQL could not resolve pgAudit's event-trigger entry points.

## Functional smoke test

A successful build is not accepted as sufficient.

For every PostgreSQL major the probe:

1. initializes a temporary PostgreSQL cluster,
2. starts PostgreSQL with `shared_preload_libraries=pgaudit`,
3. runs `CREATE EXTENSION pgaudit`,
4. enables pgAudit READ, WRITE, and DDL session logging,
5. creates a probe table,
6. inserts a row,
7. selects the row,
8. reads the actual PostgreSQL server log,
9. requires matching pgAudit records for:
   - `DDL,CREATE TABLE`,
   - `WRITE,INSERT`,
   - `READ,SELECT`,
10. disables pgAudit logging,
11. drops the probe table and extension,
12. stops PostgreSQL in cleanup.

This specifically covers historical Windows reports where pgAudit could appear installed but fail to emit correct `AUDIT:` records.

## Final artifacts

- `pgaudit-pg14-windows-x64`
  - `sha256:a636d3d34a40f13b96928d0777d23a3b46736aa941402b54990a06e3bdaa3337`
- `pgaudit-pg15-windows-x64`
  - `sha256:b097b484623ab896e9530e0362c9ef8abbe7a574e7cce082f41eda069793c534`
- `pgaudit-pg16-windows-x64`
  - `sha256:cf453a37b7852f568abe4960091d06d0c0a5d5697d6afd402ba8027382ccb621`
- `pgaudit-pg17-windows-x64`
  - `sha256:30142060a66224fa1ac7a892049f624b59f1291dab097ba9954e534d72bb8f01`
- `pgaudit-pg18-windows-x64`
  - `sha256:896e7eb1cf397c368026351a19528cce81e47582fe2a2a369e6e7900922f9e73`

These are CI probe artifacts only, not public pgextwin Releases.

## Technical acceptance criteria

| Criterion | Result |
|---|---|
| Major-specific upstream releases pinned | PASS |
| Exact upstream LICENSE verification | PASS |
| MSVC x64 DLL build | PASS |
| Required DLL exports available | PASS |
| PostgreSQL starts with pgAudit preloaded | PASS |
| CREATE EXTENSION succeeds | PASS |
| DDL audit record emitted | PASS |
| WRITE audit record emitted | PASS |
| READ audit record emitted | PASS |
| PostgreSQL 14–18 all pass | PASS |
| Per-major ZIP artifacts produced | PASS |
| Public Release intentionally not produced | PASS |

## Remaining productization work

1. create public repository `pgextwin/pgaudit`,
2. copy the validated implementation into that repository,
3. add English/Japanese documentation and Windows guidance,
4. rerun the full PG14–18 matrix in the real repository,
5. publish the first pgextwin pgAudit Release,
6. add the verified Release to `pgextwin/catalog`,
7. verify website rendering.

Repository creation remains a GitHub administrative boundary.

---

# Phase 6 技術pilot完了: pgAudit

pgAuditのWindows技術pilotは完了しました。

PostgreSQL 14〜18の全5世代で、対象pgAudit releaseを固定し、MSVC x64 build、`shared_preload_libraries=pgaudit`、`CREATE EXTENSION`、実SQL実行、実際のPostgreSQL server logに出力された `AUDIT:` レコードの確認、ZIP生成まで成功しています。

特に過去のWindows issueで報告されていた「DLLは作れたが関数を解決できない」「Extensionは入ったように見えるがaudit logが出ない」という失敗を避けるため、必要symbolの明示exportと、DDL/WRITE/READの実ログ確認をrelease gateにしています。

次はロードマップ順でset_userの技術pilotへ進みます。
