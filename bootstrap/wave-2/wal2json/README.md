# wal2json for Windows — pgextwin technical pilot

Unofficial Windows x64 packaging of the [wal2json](https://github.com/eulerto/wal2json) logical decoding output plugin, upstream tag `wal2json_2_6` pinned at commit `75629c2e1e81a12350cc9d63782fc53252185d8d`.

Targets: PostgreSQL 15, 16, 17 and 18 x64. **PG18 is a hard gate** until compilation, PostgreSQL startup, logical replication slot creation and INSERT/UPDATE/DELETE JSON decoding all pass. The plugin is loaded by PostgreSQL logical decoding; `CREATE EXTENSION` does **not** apply.

For PostgreSQL releases with CVE-2026-6471 mitigations (including PG18.6), `output_plugin_libraries` must explicitly include `wal2json` in addition to PostgreSQL's standard output plugins. The isolated CI cluster must set `wal_level=logical`, `max_replication_slots>0` and the whitelist. See https://www.postgresql.org/docs/18/runtime-config-replication.html and https://www.postgresql.org/docs/18/release-18-6.html.

The Windows build only attempts to link the server DLL import library `postgres.lib`; missing imports are genuine compatibility pilot blockers rather than reasons to trust unverified foreign static libraries. Independently verify all actual exports and end-to-end logical decoding.

**Not a public Release.** Do not list this plugin as implemented in Catalog or Website until all required CI and supply-chain evidence passes.
