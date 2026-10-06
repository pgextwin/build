# pgextwin extension roadmap

This document records the fixed implementation order for the initial pgextwin extension set.

## Fixed order

| Order | Extension | Upstream | Status / next gate |
|---:|---|---|---|
| 1 | pg_bigm | pgbigm/pg_bigm | Complete: public repository, PG14–18 Release, catalog publication, and post-transfer CI verified. |
| 2 | pg_cron | citusdata/pg_cron | Complete: public repository, PG14–18 functional Release `v1.6.8-windows.1`, and catalog publication. |
| 3 | pg_hint_plan | ossc-db/pg_hint_plan | Complete: public repository, PostgreSQL 14–18 Release `v1.8.0-windows.1`, and catalog publication. |
| 4 | pgAudit | pgaudit/pgaudit | Complete: public repository, PostgreSQL 14–18 Release `v18.0-windows.1`, and catalog publication. |
| 5 | set_user | pgaudit/set_user | Complete: public repository, PostgreSQL 14–18 Release `v4.2.0-windows.1`, and catalog publication. |
| 6 | pg_repack | reorg/pg_repack | Complete: public repository, PostgreSQL 14–18 functional Release `v1.5.3-windows.1`, and catalog publication. |
| 7 | pg_ivm | sraoss/pg_ivm | In progress: upstream `v1.16` Windows pilot on PostgreSQL 17/18 using its Meson/MSVC path; expand to PostgreSQL 14–16 after the first gate passes. |
| 8 | pg_qualstats | powa-team/pg_qualstats | Planned after pg_ivm; also treated as a Windows-release revival candidate. |

The order is intentional and should not be reshuffled without an explicit roadmap decision.

## Target environment

The initial pgextwin target remains:

- ordinary PostgreSQL Windows x64 installations,
- including standard EDB/community Windows PostgreSQL installations,
- currently maintained PostgreSQL major versions,
- one extension per repository,
- canonical binaries in each extension repository's GitHub Releases.

PostgreSQL lifecycle filtering remains centralized in pgextwin/build.

## Existing Windows distributions

Extensions that already have sufficiently usable official or established community Windows distributions are not primary pgextwin targets. Such projects can still be used as implementation references.

The initial research excluded or deprioritized projects such as oracle_fdw, TimescaleDB, PostGIS, pgRouting, pgSphere, pgvector, orafce, plpgsql_check, and http where existing Windows distribution materially reduces the value of duplicating the work.

## Commercial Windows binaries as a reference

SRA OSS currently states that it supplies Windows binaries for pg_hint_plan, pgAudit, and pg_repack to PostgreSQL support customers. These are valuable implementation and compatibility references, but they are not general public GitHub-style binary releases for ordinary Windows PostgreSQL users.

Accordingly, the roadmap keeps these extensions as pgextwin targets. pgextwin's role is public, reproducible, CI-tested distribution for standard Windows PostgreSQL installations rather than replacing vendor support offerings.

## pg_hint_plan infrastructure requirement

pg_hint_plan uses a separate stable release series for each PostgreSQL major version.

For the currently targeted PostgreSQL 14–18 set, the latest published stable releases are:

- PostgreSQL 14: REL14_1_4_4 / 1.4.4
- PostgreSQL 15: REL15_1_5_3 / 1.5.3
- PostgreSQL 16: REL16_1_6_2 / 1.6.2
- PostgreSQL 17: REL17_1_7_1 / 1.7.1
- PostgreSQL 18: REL18_1_8_0 / 1.8.0

The shared manifest/workflow now supports PostgreSQL-major-specific upstream refs while retaining backward compatibility with the existing single-ref manifests used by pg_bigm and pg_cron.

The `upstream.perPostgresql` manifest mode provides one ref/version mapping for every eligible PostgreSQL major. The matrix resolver copies the resolved `upstreamRef` and `upstreamVersion` into each build entry before checkout and packaging.

The shared license contract also supports multiple exact upstream license-file comparisons. This is required for pg_hint_plan because redistribution needs both its primary `COPYRIGHT` terms and the PostgreSQL-derived-code notice in `COPYRIGHT.postgresql`.

The Windows technical pilot is complete on PostgreSQL 14–18. PostgreSQL 17/18 use the upstream scanner source generated with win_flex. PostgreSQL 14–16 rebuild the required query-jumble object from the exact official PostgreSQL source release after SHA-256 verification, avoiding opaque precompiled compatibility objects. The final smoke test validates preload, `CREATE EXTENSION`, real `SeqScan(...)` and `IndexScan(...)` hint behavior, and the PG14–16 hint-table/query-id compatibility path. See [Phase 5 pg_hint_plan pilot report](phase5-pg_hint_plan-pilot.md).

## pg_repack infrastructure result

pg_repack is complete on PostgreSQL 14–18. The package contains both the server extension DLL and the `pg_repack.exe` client. When EDB's normal Windows installation does not provide PostgreSQL's internal frontend support archives, the build resolves the exact installed PostgreSQL minor and rebuilds only `libpgport` and `libpgcommon` from the matching official PostgreSQL source with the PostgreSQL Meson/MSVC path.

The PostgreSQL 18 build also applies the module-magic compatibility direction later adopted upstream. Functional CI requires a real table repack and verifies both row preservation and a relation filenode change. See [Phase 8 pg_repack report](phase8-pg_repack-pilot.md).

## Quality gate for every extension

A pgextwin release should normally require:

1. pinned upstream source,
2. upstream license verification,
3. Windows x64 build,
4. extension installation into the target PostgreSQL,
5. CREATE EXTENSION where applicable,
6. at least one extension-specific functional scenario,
7. per-major ZIP packaging,
8. SHA-256 checksums,
9. English/Japanese documentation,
10. no public Release until the complete supported matrix passes.

The common workflow must remain extension-generic. Extension-specific build or compatibility logic belongs in that extension repository's windows/ci hooks.
