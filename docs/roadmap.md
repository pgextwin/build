# pgextwin extension roadmap

This document records the fixed implementation order for the initial pgextwin extension set.

## Fixed order

| Order | Extension | Upstream | Status / next gate |
|---:|---|---|---|
| 1 | pg_bigm | pgbigm/pg_bigm | Complete: public repository, PG14–18 Release, catalog publication, and post-transfer CI verified. |
| 2 | pg_cron | citusdata/pg_cron | Complete: public repository, PG14–18 functional Release `v1.6.8-windows.1`, and catalog publication. |
| 3 | pg_hint_plan | ossc-db/pg_hint_plan | Active technical pilot. Per-PostgreSQL upstream refs and multiple-license verification are supported by the shared build infrastructure. |
| 4 | pgAudit | pgaudit/pgaudit | Planned after pg_hint_plan. Security/auditing wave. |
| 5 | set_user | pgaudit/set_user | Planned immediately after pgAudit so the two security-oriented extensions are handled together. |
| 6 | pg_repack | reorg/pg_repack | Planned after the security wave. Includes extension/server-side and client-tool packaging concerns. |
| 7 | pg_ivm | sraoss/pg_ivm | Planned after pg_repack. |
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

The Windows technical pilot has already passed end-to-end on PostgreSQL 17 and 18: MSVC build, preload, `CREATE EXTENSION`, a real `SeqScan(...)` optimizer-hint check, and package generation. PostgreSQL 14–16 are being validated separately because those release lines directly depend on PostgreSQL query-jumble core code on Windows.

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
