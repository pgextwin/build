# Second Wave selection — Step 15 (decision date: 2026-10-08)

**Scope:** exactly the six Step 14 candidates, for ordinary PostgreSQL Windows x64. Research and planning only; no extension repository, Windows compilation, source patch, release, distribution record or PG19 production metadata.

**Snapshot:** catalog main `1c671a1f66f56e10a9d9c00fb330b26dd1649961`, website main `ae5fc035b964dc69caafbe1a744718055e1526af`, build main `4cdfae8aacf90695324f604401a7e149c2e8b8f0` before edits. Landscape 20 = 8 implemented + 6 candidate + 6 not-planned. This is a decision-time assessment, not proof of Windows builds.

## Scope and formal outcome

| Rank | Candidate | Decision | Stable upstream ref | PG18 | PG19 | Estimated Windows effort |
|---|---|---|---|---|---|---|
| #1 | plpgsql_check | wave-2 | `v2.10.13` | supported | documented upstream; **not GA-certified** | Medium |
| #2 | HypoPG | wave-2 | `1.4.3` | supported | documented upstream; **not GA-certified** | Medium |
| #3 | wal2json | wave-2, PG18 hard pilot gate | `wal2json_2_6` | **unknown, MUST probe** | unknown | Low–Medium (registry: low, estimated risk: medium) |
| — | pg_partman | reserve | `v5.5.0` | supported | under review | Very High |
| — | pg_stat_monitor | reserve | `2.4.0` | supported | unknown | Very High |
| — | orafce | research | `VERSION_4_16_13` | supported | under review (Meson PG19 conditional only) | High |

### Explicit scoring model

All dimensions are subjective analyst scores from 0 (least attractive) to 5 (most attractive); **not factual measurements**, and release gates always override a score.

| Criterion | Weight | Why |
|---|---:|---|
| General-public Windows availability gap | 20% | Supply usable binaries where users cannot get current official ones |
| Production/developer ecosystem value | 20% | Prioritize genuinely used extension capabilities |
| Windows implementation feasibility | 15% | Limit unbounded native-toolchain risk |
| Functional Test Contract v2 feasibility | 15% | A passing CREATE EXTENSION alone is not enough |
| Upstream maintenance health | 10% | Sustainable upgrades/security fixes |
| PostgreSQL 18 support evidence | 10% | Current production-major requirement |
| PostgreSQL 19 readiness evidence | 5% | Pre-release signal, never a GA support claim |
| Low duplication of suitable distribution | 5% | Commercial/vendor-specific builds do not automatically close standard Windows gap |

Total = sum(weight × rating / 5), rounded only at the end. Ratings ordered as **gap/value/build/test/maintenance/PG18/PG19/no duplication**:

| Candidate | Ratings (0–5 each) | Weighted /100 | Assessment |
|---|---|---:|---|
| plpgsql_check | 4/4/4/5/5/5/5/4 | **88** | Best low-risk technical pilot; useful developer diagnostics and first-party Windows build docs |
| HypoPG | 4/4/3/5/4/5/5/4 | **83** | Strong PG18/19 evidence and deterministic planner-test surface |
| wal2json | 5/5/3/4/3/2/1/5 | **77** | Outstanding public CDC gap; conditional until PG18 functional proof |
| pg_partman | 5/5/1/2/5/5/1/5 | **75** | Large scope: PL/pgSQL, background worker, privileges and operational security |
| pg_stat_monitor | 5/4/1/3/4/5/1/5 | **72** | Shared memory, preload, hooks and Windows runtime add risk |
| orafce | 3/3/2/3/4/5/1/2 | **60** | Broad ICU/SQL surface, modest differentiation from existing Windows/vendor channels |

A gap score reflects **ordinary community PostgreSQL x64** availability, not presence in a cloud service, EDB Advanced Server, Fujitsu product or Percona Linux package. Stars are not scored. HypoPG's older upstream Windows artifacts and issue-attached current DLL are specifically distinguished.

## Candidate evidence, build adaptations and minimum functional tests

### plpgsql_check — Wave 2 #1

Latest stable tag `v2.10.13`, published 2026-10-07. Upstream README explicitly states PostgreSQL 14–19 support and includes Windows build guidance; `README.meson_msvc` and `meson.build` explicitly select MSVC, a PostgreSQL `postgres.lib`, and extra Windows server include paths. `postgresql19-plpgsql_check.spec` is an additional PG19 packaging/probe signal, **not release verification on Windows**. No current first-party GitHub Release Windows assets. Historical author-linked Windows DLL posts in README are not equivalent to a maintained current official release.

- **Build**: C shared module via Meson + Ninja + Visual Studio x64; upstream PGXS Makefile is not a native Windows nmake recipe. Meson has PG19-specific C11 handling. No required external Rust/Python/Perl application runtime or client executable; upstream packaging/helper script uses Python when chosen. Referenced server/internal PL/pgSQL symbols may need careful Windows DLL import/export adaptation. Use stable upstream tag and a disposable source checkout, never a fork.
- **Exports**: verify `Pg_magic_func` (or PG18 module-magic extension export), `_PG_init`, every SQL `PG_FUNCTION_INFO_V1` entry, and matching `pg_finfo_*` functions with `dumpbin /exports`. Export source can be generated from the pinned tree, but **must** be audited against actual SQL symbols. No assumed export list before linking.
- **Runtime**: `CREATE EXTENSION plpgsql_check` (control requires `plpgsql`). Active `plpgsql_check_function_tb` linting does not require shared preload. Shared profiler/tracer modes are optional and intentionally excluded from initial runtime guarantee.
- **Test Contract scenario `detect-invalid-record-field`**: create `t(a integer)` and PL/pgSQL function looping over its rows while referencing non-existent `r.missing`; `SELECT * FROM plpgsql_check_function_tb('public.probe()')` must yield a field-not-found/identifier diagnostic even with no rows. A corrected function must not yield the same error. Fail on unexpected SQL errors or empty diagnostics. CI should use deterministic assertion substrings rather than full error text or line offsets.
- **License**: tag file `LICENSE` contains MIT permission/notice wording, irrespective of potentially stale RPM spec `License: BSD`. Include verbatim license and attribution in binary package.

Evidence: [release](https://github.com/okbob/plpgsql_check/releases/tag/v2.10.13), [README compatibility / test API](https://github.com/okbob/plpgsql_check/blob/v2.10.13/README.md), [Windows instructions](https://github.com/okbob/plpgsql_check/blob/v2.10.13/README.meson_msvc), [Meson source](https://github.com/okbob/plpgsql_check/blob/v2.10.13/meson.build), [LICENSE](https://github.com/okbob/plpgsql_check/blob/v2.10.13/LICENSE).

### HypoPG — Wave 2 #2

Stable `1.4.3` (2026-06-19) release explicitly fixes PG19; 1.4.2 previously fixed PG18. Current upstream default branch contains work beyond released tag; pin **1.4.3**, not a future unreleased control file.

- **Windows availability**: upstream official 1.4.1 assets include x64 ZIP/installer **only up to PG16**; issue #112 has community-maintained-by-contributor builds for PG17, PG18 and PG19 beta. Attachments are not official current 1.4.3 assets; ABI, source mapping, provenance and security are unknown. Neither channel closes the current supported-major official binary gap.
- **Build**: C, PGXS Makefile, planner hooks, copied backend indexing source under `import/`. Custom MSVC/nmake or Meson arrangement required; no client executable or separate native library indicated. Hooks and internal planner symbols must be audited against Windows `postgres.lib` exports. Likely effort Medium.
- **Exports**: `Pg_magic_func`, `_PG_init`, SQL-callable and `pg_finfo_*` surface; audited DEF and `dumpbin` gate.
- **Test Contract `hypothetical-index-changes-plan`**: ANALYZE a populated table, baseline `EXPLAIN` sequential scan, call `hypopg_create_index('CREATE INDEX ON ...')`, confirm an index-oriented plan without physically creating any index, `hypopg_drop_index` or `hypopg_reset`, confirm removal. Test within **same backend session**. Planner cost determinism requires suitably sized table / stable settings.
- **Runtime**: `CREATE EXTENSION hypopg`; backend/session-local hooks; no shared preload or BGW.
- **License**: upstream `LICENSE` is PostgreSQL-style permissive license. Include full notice.

Evidence: [1.4.3 release](https://github.com/HypoPG/hypopg/releases/tag/1.4.3), [old official Windows release](https://github.com/HypoPG/hypopg/releases/tag/1.4.1), [PG18/19 changelog](https://github.com/HypoPG/hypopg/blob/1.4.3/CHANGELOG.md), [community binaries, issue #112](https://github.com/HypoPG/hypopg/issues/112), [LICENSE](https://github.com/HypoPG/hypopg/blob/1.4.3/LICENSE).

### wal2json — Wave 2 #3 (conditional)

Stable `wal2json_2_6` / 2.6 (2024-04-25); official release has **no attached binary assets**. Upstream README explicitly documents Visual Studio out-of-tree build from `wal2json.vcxproj` against installed PostgreSQL; project currently hard-codes PostgreSQL 16 paths and links `postgres.lib`, `libpgcommon.lib`, `libpgport.lib`, which normal Windows server packages may not supply as static libraries.

- **Build**: single C output-plugin DLL, Visual Studio solution/project with absolute paths requiring parameterization. Verify PG18 headers/API compile, imports and missing archives; never blindly link incompatible libpgcommon/libpgport. Source explicitly declares `PGDLLEXPORT _PG_output_plugin_init(OutputPluginCallbacks *)` and `PG_MODULE_MAGIC`. Confirm exported `_PG_output_plugin_init` plus version-appropriate magic through `dumpbin`.
- **Support**: source contains modern compatibility branches, but neither source availability nor a previous PG17 fix proves PG18 or PG19 runtime support. `pg18Support = unknown` is intentional and a hard **pilot gate**: no formal PG18 Release until an actual Windows PG18 compile, startup, logical slot, DML JSON validation and cleanup pass. PG19 unknown.
- **Runtime**: `wal_level=logical`, `max_replication_slots > 0`; server restart; create a logical replication slot as a privileged user with replication rights. `CREATE EXTENSION` is **not applicable** (logical decoding output plugin rather than SQL extension). Windows PostgreSQL runtime and CI must permit logical decoding on test cluster.
- **Test Contract `logical-dml-json`**: create table with PRIMARY KEY and `REPLICA IDENTITY FULL` if needed; create `pg_create_logical_replication_slot('pgextwin_wal2json', 'wal2json')`; INSERT, UPDATE, DELETE in committed transactions; consume via `pg_logical_slot_get_changes` and parse JSON; assert change kinds, relation/column/value fields. Drop slot in finally block; deterministic WAL flush/transaction boundaries and failure cleanup are essential. Confirm slot can be created/consumed on Windows in GitHub-hosted runner.
- **License**: BSD-3-Clause terms in upstream `LICENSE` require full copyright/conditions/disclaimer in binary distribution materials.

Evidence: [release](https://github.com/eulerto/wal2json/releases/tag/wal2json_2_6), [README Windows and prerequisites](https://github.com/eulerto/wal2json/blob/wal2json_2_6/README.md), [Visual Studio project](https://github.com/eulerto/wal2json/blob/wal2json_2_6/wal2json.vcxproj), [LICENSE](https://github.com/eulerto/wal2json/blob/wal2json_2_6/LICENSE).

### pg_partman — Reserve

Stable 5.5.0, PG14+, PG18 supported; upstream release 5.5.0 includes hardening of background-worker superuser configuration, schema/search_path and RLS guidance. Wide SQL/PLpgSQL extension plus optional native `pg_partman_bgw`; upstream `make NO_BGW=1 install` installs the SQL-only features. Do **not** assume BGW is mandatory for initial useful tests; but a future binary decision must define whether to distribute the BGW or explicitly document its absence. No independent client executable. PG19 under review, not proof of support. 

Test `partition-maintenance-routing`: create time/ID partition parent, configure partman, call `run_maintenance_proc` or documented matching maintenance function, insert boundary rows, verify child partition membership / additional partition creation. Test non-superuser maintenance role, privileged schema ownership, relevant RLS separately in later security gate. Functional feasibility Medium; Windows full packaging Very High. PostgreSQL permissive `LICENSE.txt` (copyright of Snowflake/Crunchy/OmniTI) must be included. Managed services including RDS and Snowflake are a demand signal, not general Windows binary availability.

Evidence: [5.5.0](https://github.com/pgpartman/pg_partman/releases/tag/v5.5.0), [README](https://github.com/pgpartman/pg_partman/blob/v5.5.0/README.md), [security changelog](https://github.com/pgpartman/pg_partman/blob/v5.5.0/CHANGELOG.md), [LICENSE](https://github.com/pgpartman/pg_partman/blob/v5.5.0/LICENSE.txt).

### pg_stat_monitor — Reserve

Stable 2.4.0, upstream Percona verifies PG14–18 for PGDG and its distribution; PG19 unknown. Native C via PGXS Makefile, with Meson file oriented toward PostgreSQL contrib integration; shared-memory state, query hooks and `shared_preload_libraries = 'pg_stat_monitor'` are mandatory to collect statistics. PostgreSQL/Percona Linux packages and managed adoption do not constitute standard public Windows DLL releases. No separate client executable.

Test `preload-records-time-bucket`: bootstrap with preload, restart, CREATE EXTENSION, run unique SELECT/DML workload, inspect `pg_stat_monitor` for query counters, non-null bucket and recognizable normalized query; tolerate race/bucket intervals with bounded retry. Interaction with `pg_stat_statements` hooks and shared-memory behavior require isolation. Test feasible but startup-sensitive. Effort Very High. PostgreSQL-style permissive `LICENSE`, include verbatim.

Evidence: [2.4.0](https://github.com/percona/pg_stat_monitor/releases/tag/2.4.0), [supported PG14–18 and preload](https://github.com/percona/pg_stat_monitor/blob/2.4.0/README.md), [Makefile](https://github.com/percona/pg_stat_monitor/blob/2.4.0/Makefile), [LICENSE](https://github.com/percona/pg_stat_monitor/blob/2.4.0/LICENSE).

### orafce — Research

Stable tag `VERSION_4_16_13` (4.16.13). Explicit Windows MSVC, Meson documentation and PG18 build path exist; `README.msvc` notes compiler/runtime alignment and ICU include/link requirements. Meson includes a PG19 C standard conditional, but that alone is not PG19 production-support certification. Wide native C and SQL surface including Oracle-compatible date, string, packages, PL/VARCHAR features, parser generated files and ICU; no separate client utility and no mandatory BGW for minimal functions. Presently no sufficiently verified, current official Windows binary route for ordinary PostgreSQL was found; do not infer one from EDB Advanced Server's built-in compatibility.

Test `oracle-trunc-date-and-nvl`: `CREATE EXTENSION orafce` and assert deterministic Oracle-compatible date truncation/last_day or `nvl` behavior, with explicit schema-qualified calls and timezone. Further research must choose narrow export/test scope and inspect historical Windows acquisition routes. Effort High. Upstream `LICENSE` and `COPYRIGHT.orafce` contain the identical 0BSD text; include both notices as shipped upstream when applicable.

Evidence: [4.16.13](https://github.com/orafce/orafce/releases/tag/VERSION_4_16_13), [Windows Meson](https://github.com/orafce/orafce/blob/VERSION_4_16_13/README.meson_msvc), [Visual Studio / ICU](https://github.com/orafce/orafce/blob/VERSION_4_16_13/README.msvc), [LICENSE](https://github.com/orafce/orafce/blob/VERSION_4_16_13/LICENSE).

## Existing not-planned acquisition regression

All six remain `not-planned`, with no irrelevant metadata changes:

- **oracle_fdw**: official 2.9.0 PG14–18 win64 ZIP assets verified; Oracle Instant Client dependency.
- **PostGIS**: OSGeo/PostGIS official native installers, including PG18 package directory.
- **pgRouting**: bundled with PostGIS Windows releases; verify package/version match.
- **pgvector**: conda-forge `win-64` route is for **conda PostgreSQL**, not automatically ABI-compatible with standard EDB installation.
- **pgSphere**: PostGIS extras/bundles, precise PG major/ABI must be verified by downloader.
- **TimescaleDB**: official 2.30.2 release contains PG16/17/18 Windows amd64 ZIPs.

The Step 14 alternative-acquisition registry remains authoritative for individual URLs and compatibility qualifications. HypoPG is the only candidate with a significant newly classified source: upstream's historical 1.4.1 Windows official assets (PG14–16); current PG17/18 attachment provenance remains separate. No candidate-to-not-planned transition justified.

## License and redistribution decision

All six have readable, pinned upstream **LICENSE** files; BSD/PostgreSQL/MIT/0BSD-like permissive terms permit binary redistribution subject to preserving applicable copyright/license notice and warranty text. The official package process must copy unmodified pinned license files and check any additional bundled source/library notices in the pilot. License is **not** inferred from metadata alone; note the plpgsql_check RPM spec says BSD while actual `LICENSE` contains MIT permission text. No proprietary SDK or binary redistributable may be bundled without a separate right to do so. pg_partman `LICENSE.txt`, orafce `LICENSE` and `COPYRIGHT.orafce` are distinct filenames.

## PostgreSQL 14 policy / PG19 prioritization

**Policy B formally selected.** On 2026-10-08, PostgreSQL 14 has approximately five weeks before its published 2026-11-12 EOL. PG14–18 creates five normal jobs per new extension; PG15–18 cuts one matrix axis (20% fewer major jobs), while retaining historical initial-eight support as documented. The marginal utility of newly onboarding a legacy major before its EOL is lower than reliable Windows integration and imminent PG19 readiness. Policy A creates upgrade and build debt immediately; Policy C weakens predictability. Preservation of existing verified PG14 releases is separate from new-extension support.

Before PG19 production onboarding, Wave 2 pilot matrices target **PG15,16,17,18**. After an explicitly approved PG19 GA + Windows binary + upstream verification gate, target **PG15,16,17,18,19** (PG14 remains excluded for Wave 2). Do not modify `metadata/postgresql.json` or treat Beta/RC as supported production major.

PostgreSQL official Beta Information currently lists **19 Beta 4** (2026-09-24). [PG19 Open Items](https://wiki.postgresql.org/wiki/PostgreSQL_19_Open_Items) lists **RC1 planned 2026-10-15; GA planned 2026-10-29**. Thus the next planned milestone at decision time is **Wave 2 #1 technical pilot**, not production PG19 onboarding. Re-evaluate before execution if PG19 status advances to RC or GA; in RC state a separate compatibility probe may supersede starting a full release pilot.

## Step 16 handoff — #1 plpgsql_check Windows Technical Pilot (design only)

| Field | Exact design |
|---|---|
| Intended repo | `pgextwin/plpgsql_check` (**do not create during Step 15**) |
| Upstream | `https://github.com/okbob/plpgsql_check` |
| Source | exact stable tag `v2.10.13`, resolve immutable commit SHA at pilot start and verify it against upstream release |
| License | `LICENSE` at `v2.10.13`; verify hash/notice, package verbatim; audit vendored sources |
| Target PG majors | PG15, PG16, PG17, PG18; PG19 only after separate onboarding |
| Build | MSVC x64 + Meson + Ninja, use upstream `meson.build` as first path; `pg_config` points at exact PostgreSQL installation |
| Likely adaptation | locate PG server headers/import lib in Windows EDB install; verify `plpgsql` internal symbol resolution; strip unsafe project-specific paths; version-aware V1/magic export DEF if necessary; no immutable upstream source edits |
| DLL exports | `Pg_magic_func` or PG18 magic variant, `_PG_init`, SQL callable symbols + `pg_finfo_*`; generate/audit and `dumpbin` verification |
| Install hooks | extension-owned `windows/ci/build.ps1` and `windows/ci/smoke-test.ps1` contract; common reusable workflow remains extension-neutral |
| Runtime | `CREATE EXTENSION plpgsql_check`; `plpgsql` required; no shared preload required for active-mode baseline; profiler and tracer coverage explicitly not-covered |
| Test Contract v2 | `runtimeRequirements.extensionCreation=required`, `preload=optional` or `none` after upstream verification; backgroundWorker=false; client executable not applicable; stable scenario `detect-invalid-record-field`, evidence SQL diagnostics |
| Functional gate | missing-record-field diagnostic and corrected control; run each PG15–18 in actual Windows DB and assert error strings robustly |
| Package contents | `plpgsql_check.dll`, `plpgsql_check.control`, `plpgsql_check--2.10.sql` (control default version 2.10), exact `LICENSE` and required docs, `PACKAGE-INFO.json`; separate SBOM/scan/report/attestation evidence by release path |
| Naming | proposed `v2.10.13-windows.1`, assets `plpgsql_check-2.10.13-pg15-windows-x64.zip` etc through PG18, plus `SHA256SUMS.txt` |
| Update watch | add upstream tags/releases watcher using exact release identity and full immutable SHA, Issue-only notification; never automate version bump/release |
| Blocking gates | PG18 DLL ABI/import-link and PL/pgSQL internals, symbol export list, reproducible CI without implicit optional profiler preload, real test success on all PG15–18, license/SBOM and SHA verification |
| Publication | **not in Step 15**; only after next separately reviewed pilot and normal attested release checks |

#1's goal is a working **diagnostic** contract, not a promise of profiler, global preload, telemetry or PG19 support. #2's principal risk is planner internal hooks/copy of backend code; #3's principal risk is PG18 output-plugin ABI and the Windows logical replication CI environment.
