# Phase 7 technical pilot completion: set_user

## Result

The set_user Windows technical pilot is complete.

The final probe validated PostgreSQL 14, 15, 16, 17, and 18 end-to-end against upstream set_user `REL4_2_0` / 4.2.0.

- Probe PR: `pgextwin/pg_bigm#12`
- Probe branch: `phase7/set-user-probe`
- Final workflow run: `37385038114`
- Result: PostgreSQL 14–18 PASS
- Release job: skipped as intended

The probe PR was closed without merging.

## Upstream

- Repository: `pgaudit/set_user`
- Ref: `REL4_2_0`
- Version: 4.2.0
- License: PostgreSQL License
- Supported upstream baseline: PostgreSQL 13+

## Windows compatibility finding

Upstream set_user 4.2.0 contains the declaration:

```c
extern Datum set_user(PG_FUNCTION_ARGS);
```

and later uses:

```c
PG_FUNCTION_INFO_V1(set_user);
```

On PostgreSQL 16 and newer, `PG_FUNCTION_INFO_V1()` emits a declaration for the SQL-callable function with `PGDLLEXPORT` on Windows. The preceding non-export declaration therefore creates a Windows linkage conflict, matching the failure reported upstream in issue #86.

The pgextwin probe applies a minimal build-time compatibility edit to the checked-out source:

```c
extern Datum set_user(PG_FUNCTION_ARGS);
```

becomes:

```c
extern PGDLLEXPORT Datum set_user(PG_FUNCTION_ARGS);
```

The upstream repository is not forked or permanently modified; the checkout is patched only inside the disposable CI workspace.

The build also emits an explicit DLL export definition containing:

- `Pg_magic_func`
- `_PG_init`
- `_PG_fini`
- `set_user`
- `set_session_auth`

This keeps PostgreSQL 14/15 compatible while matching the newer PostgreSQL Windows export model.

## Functional smoke test

For every supported PostgreSQL major the probe:

1. initializes a temporary PostgreSQL cluster,
2. starts PostgreSQL with `shared_preload_libraries=set_user`,
3. runs `CREATE EXTENSION set_user`,
4. creates a non-superuser probe role,
5. calls `set_user('pgextwin_setuser_target')`,
6. verifies in the same session that:
   - `current_user = 'pgextwin_setuser_target'`
   - `session_user = 'postgres'`,
7. calls `reset_user()`,
8. verifies `current_user` and `session_user` are both restored to `postgres`,
9. requires PostgreSQL server-log entries for both role transitions,
10. drops the probe role and extension,
11. stops PostgreSQL in cleanup.

This verifies actual privilege-transition behavior rather than only DLL loading or extension creation.

## Packaging

The package includes:

- `lib/set_user.dll`
- `share/extension/set_user.control`
- generated base extension SQL
- upstream upgrade SQL scripts
- `include/set_user.h`
- upstream LICENSE
- upstream README / CHANGELOG where available
- `PACKAGE-INFO.txt`

The header is included because upstream installs `set_user.h` for extensions that register set_user post-execution hooks.

## Final artifacts

- `set_user-pg14-windows-x64`
  - `sha256:c4d226a9bed4cbc8628ea399e41d2d349eef65fd0a31ec3b14aa8d0fab4f43c3`
- `set_user-pg15-windows-x64`
  - `sha256:c567cef83c2e43afcc08fdecdf95a25e21e39af3164a6dbdde12099f8ebc3600`
- `set_user-pg16-windows-x64`
  - `sha256:f8fa8da3a0a989e40804d50672ed8c959959b3f669dd323bcc5aae10b77bc4c9`
- `set_user-pg17-windows-x64`
  - `sha256:ff53851ba9e476c36aca3ba39a086a2bc50b95c207cf11bf33ca046828f04995`
- `set_user-pg18-windows-x64`
  - `sha256:8295443ca686ab9a8d0e40a2614a834c192a5a0f1195f8fcb740375919cfef7a`

These are CI probe artifacts only, not public pgextwin Releases.

## Technical acceptance criteria

| Criterion | Result |
|---|---|
| Upstream REL4_2_0 pinned | PASS |
| Exact upstream LICENSE verification | PASS |
| PG14–18 MSVC x64 build | PASS |
| PostgreSQL 16+ linkage conflict handled | PASS |
| Explicit module/function exports | PASS |
| PostgreSQL starts with set_user preloaded | PASS |
| CREATE EXTENSION succeeds | PASS |
| set_user changes current_user | PASS |
| reset_user restores original user | PASS |
| Transition audit messages reach server log | PASS |
| Public header packaged | PASS |
| PG14–18 ZIP artifacts produced | PASS |
| Public Release intentionally not produced | PASS |

## Remaining productization work

1. create public repository `pgextwin/set_user`,
2. move the validated implementation into that repository,
3. add English/Japanese documentation and Windows guidance,
4. rerun the full PG14–18 matrix in the real repository,
5. publish the first pgextwin set_user Release,
6. add the verified Release to `pgextwin/catalog`,
7. verify website rendering.

Repository creation remains a GitHub administrative boundary.

---

# Phase 7 技術pilot完了: set_user

set_userのWindows技術pilotは完了しました。

PostgreSQL 14〜18の全5世代で、set_user 4.2.0を固定し、MSVC x64 build、Windows linkage互換処理、`shared_preload_libraries=set_user`、`CREATE EXTENSION`、実際のユーザー切替、`reset_user()` による復帰、server log上の遷移記録、ZIP生成まで成功しています。

特にPostgreSQL 16以降で問題になる `extern Datum set_user(...)` と `PG_FUNCTION_INFO_V1(set_user)` のWindows export linkage衝突を、upstream repositoryをforkせずCI workspace上の最小patchで解消できることを確認しました。

次はロードマップ順で pg_repack の技術pilotへ進みます。
