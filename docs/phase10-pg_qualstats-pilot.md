# Phase 10 pg_qualstats Windows pilot report

## Result

pg_qualstats 2.1.4 is complete for the initial pgextwin target set:

- PostgreSQL 14, 15, 16, 17, and 18
- Windows x64
- standard Windows PostgreSQL installations
- functional validation, not compile-only validation
- public GitHub Release and catalog publication

Published release:

- `v2.1.4-windows.1`
- https://github.com/pgextwin/pg_qualstats/releases/tag/v2.1.4-windows.1

## Upstream

- repository: `powa-team/pg_qualstats`
- pinned ref: `2.1.4`
- version: 2.1.4
- license: PostgreSQL-style; repository `LICENSE` is kept identical to upstream

Upstream 2.1.4 is the source of truth for extension behavior and SQL interfaces. pgextwin does not maintain a permanent source fork.

The upstream release history also leaves a practical Windows distribution gap for current PostgreSQL majors: recent 2.1.x releases do not provide a complete current PG14–18 Windows package set, while older Windows assets did not cover the current PG17/18 target. pgextwin therefore builds the pinned upstream source reproducibly for every supported major.

## Windows build compatibility

Upstream 2.1.4 contains a preprocessor conditional inside the argument list of a compatibility `ShmemInitHash(...)` macro invocation.

GCC accepts this source layout, but MSVC rejects the `#if/#else` tokens while collecting macro arguments. The pgextwin build hook rewrites only the disposable CI checkout so that the conditional is outside the macro invocation while preserving the same hash flags.

This is a build-layout compatibility transformation, not a behavioral fork.

## DLL exports

The Windows build generates an explicit export definition containing:

- `Pg_magic_func`
- `_PG_init`
- every function declared through upstream `PG_FUNCTION_INFO_V1(...)`
- every corresponding `pg_finfo_<function>` symbol

The resulting DLL export table is checked with `dumpbin` before packaging.

## Functional validation

The smoke test for every supported PostgreSQL major:

1. installs the built DLL, control file, and SQL files,
2. starts PostgreSQL with `shared_preload_libraries=pg_qualstats`,
3. sets `pg_qualstats.sample_rate=1` for deterministic collection,
4. creates the extension,
5. resets pg_qualstats statistics,
6. creates a 1000-row probe table,
7. executes predicates including `payload = 3`, `payload = 7`, and `id > 900`,
8. verifies that `pg_qualstats` contains rows for the probe relation and predicate attribute,
9. verifies that `pg_qualstats_pretty` exposes the collected predicate information.

This ensures that release acceptance requires actual predicate-statistics behavior rather than DLL load alone.

## Acceptance runs

Key CI gates:

- PG17/18 first gate: workflow run `37434948343` — success
- final PG14–18 pilot: workflow run `37436331602` — all five majors success
- release run: workflow run `37437694835` — all PG14–18 build/test jobs success and Release publication success

The release run was built from merge commit:

- `068dd2db703154912fb9cbfde39a3adb2e7e3afe`

## Published assets

The Release contains:

- `pg_qualstats-2.1.4-pg14-windows-x64.zip`
- `pg_qualstats-2.1.4-pg15-windows-x64.zip`
- `pg_qualstats-2.1.4-pg16-windows-x64.zip`
- `pg_qualstats-2.1.4-pg17-windows-x64.zip`
- `pg_qualstats-2.1.4-pg18-windows-x64.zip`
- `SHA256SUMS.txt`

Each package also records the upstream source identity in `PACKAGE-INFO.txt`.

## Documentation and catalog

The extension repository provides:

- English README
- Japanese README
- Japanese Windows-specific guide
- upstream license copy
- bilingual GitHub Release notes, English first and Japanese second

Catalog publication was prepared and validated before release, then merged only after the release assets existed:

- catalog PR #8: `Publish pg_qualstats 2.1.4 catalog entry`
- catalog merge commit: `bcf31665ffb5f6be6bf192e378c2af2b8661ee20`

The catalog declares `shared_preload_libraries = pg_qualstats` and PG14–18 availability.

## Conclusion

pg_qualstats satisfies the same pgextwin release gate as the preceding extensions: pinned upstream source, exact license handling, reproducible Windows x64 build, explicit compatibility handling, extension-specific functional testing, per-major packages, checksums, bilingual documentation, GitHub Release publication, and catalog publication.

With this release, all eight extensions in the initial fixed pgextwin roadmap are complete.
