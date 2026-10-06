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
| 7 | pg_ivm | sraoss/pg_ivm | Complete: public repository, PostgreSQL 14–18 functional Release `v1.16-windows.1`, and catalog publication. |
| 8 | pg_qualstats | powa-team/pg_qualstats | Complete: public repository, PostgreSQL 14–18 functional Release `v2.1.4-windows.1`, and catalog publication. |

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

## pg_ivm infrastructure result

pg_ivm is complete on PostgreSQL 14–18. Upstream v1.16 provides an MSVC-aware Meson build path. pgextwin adds an explicit, audited DLL export definition for the SQL-callable surface and V1 metadata, plus narrowly scoped PostgreSQL 14 compatibility for backend data symbols that are not linkable through the ordinary Windows import library.

Functional CI starts PostgreSQL with pg_ivm preloaded, creates a real IMMV, and verifies immediate INSERT, UPDATE, and DELETE propagation. See [Phase 9 pg_ivm report](phase9-pg_ivm-pilot.md).

## pg_qualstats infrastructure result

pg_qualstats is complete on PostgreSQL 14–18. pgextwin builds upstream 2.1.4 with MSVC x64 and applies one disposable-source compatibility rewrite because MSVC rejects the upstream preprocessor conditional embedded inside the compatibility `ShmemInitHash(...)` macro argument list. The rewrite preserves the same hash flags without maintaining a forked source tree.

The Windows DLL export surface is generated from `Pg_magic_func`, `_PG_init`, every upstream `PG_FUNCTION_INFO_V1(...)` declaration, and each matching `pg_finfo_*` symbol, then verified with `dumpbin`.

Functional CI preloads pg_qualstats, creates the extension, runs real predicates against a probe table, and verifies both `pg_qualstats` rows and `pg_qualstats_pretty` output. PostgreSQL 14–18 all passed the release matrix before publication. See [Phase 10 pg_qualstats report](phase10-pg_qualstats-pilot.md).

The initial eight-extension roadmap is now complete. Any extension added after pg_qualstats should be treated as a new roadmap decision rather than implicitly extending this fixed initial order.

## Next platform work

The initial eight-extension roadmap remains closed.

**Step 2 — PostgreSQL lifecycle / PG14 EOL build foundation: complete.** The shared resolver has a deterministic effective-date test seam, the EOL date is explicitly inclusive, lifecycle metadata is validated in CI, and the historical-release retention policy is documented. PostgreSQL 14 remains a normal build target through 2026-11-12 and leaves new normal matrices beginning 2026-11-13.

**Step 3 — lifecycle visibility: complete.** Catalog and website responsibility is separated between historical binary availability and current maintenance state.

**Step 4 — PostgreSQL 19 readiness / compatibility audit: complete.** The resolver/schema/workflow have no PostgreSQL 18 ceiling, synthetic fixtures prove PostgreSQL 19 and temporary six-major resolution without changing production metadata, Windows distribution prerequisites and all eight upstreams have been audited, and the production onboarding gate is documented in [PostgreSQL 19 readiness](postgresql-19-readiness.md).

**Step 5 — GitHub Actions trust baseline: complete.** External Actions and internal reusable workflows use immutable full commit SHAs, shared build source self-pins through `job.workflow_repository` / `job.workflow_sha`, normal builds are read-only, release publication is separately write-scoped, and the organization requires full-SHA action references.

**Step 6 — Artifact Attestation / release build provenance: complete.** Release builds use a dedicated attested reusable workflow to generate and verify GitHub Artifact Attestations for final Windows ZIPs before those unchanged bytes are passed to the release publication workflow. Normal PR/main builds remain read-only. See [Artifact Attestations and build provenance](artifact-attestations.md).

The following remain separate future milestones:

1. PostgreSQL 19 production onboarding after the documented GA/Windows/upstream gates are satisfied
2. SBOM and broader supply-chain provenance work beyond Step 6
3. PACKAGE-INFO v2 and broader package metadata / catalog improvements
4. website improvements beyond lifecycle visibility
5. upstream update automation
6. second extension wave

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
