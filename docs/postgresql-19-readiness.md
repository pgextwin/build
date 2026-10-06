# PostgreSQL 19 readiness / compatibility audit

Audit date: **2026-10-06**

This document records pgextwin's pre-GA readiness for PostgreSQL 19. It is an engineering audit, **not a statement that PostgreSQL 19 is supported or distributed by pgextwin**.

PostgreSQL 19 must not be added to the production build matrix, catalog, or website merely because a pre-release build exists. Production onboarding is a separate milestone guarded by the criteria below.

## PostgreSQL 19 current stage

At the audit date:

- PostgreSQL 19 Beta 4 was released on 2026-09-24.
- PostgreSQL 19 remains a pre-release and is not intended for production use.
- The PostgreSQL 19 open-items schedule lists RC1 for 2026-10-15 and GA for 2026-10-29.
- The PostgreSQL 19 release notes still show an unset final release date.
- The PostgreSQL community Versioning Policy does not yet list a production PostgreSQL 19 minor version or final support date.

Primary references:

- https://www.postgresql.org/about/news/postgresql-19-beta-4-released-3386/
- https://www.postgresql.org/developer/beta/
- https://wiki.postgresql.org/wiki/PostgreSQL_19_Open_Items
- https://www.postgresql.org/docs/19/release-19.html
- https://www.postgresql.org/support/versioning/

Accordingly, metadata/postgresql.json remains production-only and contains PostgreSQL 14-18. PostgreSQL 19 is represented only by synthetic test fixtures in this milestone.

## Shared build infrastructure readiness

| Component | PG19-ready? | Required change for production onboarding | Current blocker |
|---|---|---|---|
| metadata/postgresql.json contract | Conditionally yes | Add a real PG19 entry only after GA, official lifecycle data, and a reproducible Windows package are known | GA/lifecycle/package data are not final |
| scripts/resolve-matrix.ps1 | Yes | None expected | None; resolver is major-generic |
| scripts/install-postgresql.ps1 | Structurally yes | Supply a stable PG19 Chocolatey package/version that installs into the standard EDB-style path | No stable postgresql19 package identified |
| reusable build-extension.yml | Yes | None expected beyond a real matrix entry | Production metadata intentionally has no PG19 entry |
| schema/extension.schema.json | Yes | None | No maximum PostgreSQL major is encoded |
| resolver/schema tests | Yes after this audit | Keep synthetic PG19 fixtures separate from production metadata | None |
| extension Windows hooks | Mostly | Per-extension probe; pg_repack needs a source-version/build-script refresh when moving beyond 1.5.3 | Standard PG19 Windows install path is not yet available to pgextwin CI |

The resolver uses the majors supplied by metadata and intersects them with the extension manifest. It has no "five supported majors" rule and no PostgreSQL 18 ceiling. The workflow matrix is similarly dynamic.

The readiness fixtures deliberately use obviously synthetic minor/package/EOL values. They prove two contracts without claiming that those values exist:

1. a range manifest with maxMajor 19 resolves a six-major PostgreSQL 14-19 matrix when all six fixture majors are maintained; and
2. an explicit majors [18, 19] manifest with per-major upstream refs resolves PostgreSQL 19 correctly.

This also proves that a temporary PostgreSQL 14-19 overlap is technically allowed. If PostgreSQL 19 is onboarded before PostgreSQL 14 reaches EOL, PostgreSQL 14 must remain eligible through 2026-11-12. The resolver will remove PG14 from new normal matrices beginning 2026-11-13 under the existing lifecycle policy; there is no reason to cap the matrix at five majors.

## Windows distribution readiness

pgextwin targets binaries that work with the standard Windows PostgreSQL distribution rather than an unrelated third-party PostgreSQL build.

At the audit date:

- PostgreSQL's normal Windows installer page lists supported releases 14-18 and does not yet present PostgreSQL 19 as a normal supported Windows release: https://www.postgresql.org/download/windows/
- EDB provides PostgreSQL 19 pre-release / Early Experience artifacts, but they are evaluation builds rather than the production distribution: https://www.enterprisedb.com/products-services-training/pgdevdownload
- EDB's software download service exposes PostgreSQL 19 Beta artifacts: https://www.enterprisedb.com/downloads/postgres-postgresql-downloads
- No stable Chocolatey postgresql19 package was identified in the community package feed during this audit: https://community.chocolatey.org/packages?q=postgresql

The current installer contract is intentionally simple: metadata supplies a Chocolatey package/version and the installed tree is expected at "%ProgramFiles%\PostgreSQL\<major>", with server headers and "lib\postgres.lib". That structure is major-generic, but pgextwin cannot run a representative production-style PG19 Windows probe until an acceptable stable package route exists.

A direct Early Experience installer path is not added merely for this audit. Doing so would create a second installation mechanism whose behavior is not used by normal production builds.

## Initial eight extensions

Readiness statuses in this document do **not** mean "Supported":

- **READY_FOR_PROBE**: upstream has concrete PG19 compatibility evidence and the next useful step is a pgextwin Windows experimental build/functional test.
- **NEEDS_PROBE**: source compatibility looks plausible, but pgextwin-specific adaptation or stronger validation is required before interpreting the result.
- **UPSTREAM_PENDING**: an upstream production-quality PG19 ref/release is still required even if a development branch can already be investigated.
- **BLOCKED**: a known incompatibility prevents a meaningful probe.

| Extension | Current pgextwin upstream | Latest upstream | PG19 upstream evidence | Readiness | Required work |
|---|---|---|---|---|---|
| pg_bigm | v1.2-20250903 | v1.2-20250903 | Release says PostgreSQL 18 or later; upstream CI includes REL_19_STABLE | READY_FOR_PROBE | Run Windows build/install/preload/functional test when the shared PG19 install route exists; production manifest change only after the gate |
| pg_cron | v1.6.8 | v1.6.8 | v1.6.8 explicitly adds PostgreSQL 19 support, native Windows build support, and Windows regression fixes | READY_FOR_PROBE | Exercise background worker startup and job execution on the standard PG19 Windows distribution |
| pg_hint_plan | per-major through REL18_1_8_0 | REL18_1_8_0 latest published PG-major release | Upstream has a PG19 branch and the PG19 release-plan issue says integration is stable, but no REL19 tag exists at audit time | UPSTREAM_PENDING | Wait for a formal REL19 ref for production; then add a PG19 perPostgresql mapping and probe planner/query-id/hint-table behavior on Windows |
| pgAudit | per-major through 18.0 | 18.0 stable; 19beta4 pre-release | 19beta4 explicitly provides PostgreSQL 19 support; upstream has REL_19 integration/stable branches and the integration workflow is eligible for CI | READY_FOR_PROBE | 19beta4 may be used only for an experimental probe; production must wait for the final PG19 upstream ref |
| set_user | REL4_2_0 | REL4_2_0 | Latest stable release explicitly mentions PG18, while current upstream CI includes PostgreSQL 19 and README support is open-ended for modern majors | READY_FOR_PROBE | Probe the exact candidate source/ref; require a clearly acceptable upstream ref before production and validate preload/privilege-switch behavior |
| pg_repack | ver_1.5.3 | ver_1.5.3 latest tag; master newer | master documentation lists PostgreSQL 19 and upstream CI includes PG19 after the PG19 compatibility work | UPSTREAM_PENDING | Prefer a tagged upstream release containing PG19 support; refresh pgextwin's exact 1.5.3 compatibility patch/version assertions and revalidate frontend support libraries |
| pg_ivm | v1.16 | v1.16 | v1.16 explicitly adds PostgreSQL 19 support | READY_FOR_PROBE | Run the existing Meson/MSVC build and IMMV functional smoke test on PG19 Windows |
| pg_qualstats | 2.1.4 | 2.1.4 | 2.1.4 explicitly adds PostgreSQL 19 support; upstream CI contains a 19beta entry | READY_FOR_PROBE | Run the existing MSVC compatibility rewrite and preload/query-statistics smoke test on PG19 Windows |

Upstream references:

- pg_bigm: https://github.com/pgbigm/pg_bigm/releases/tag/v1.2-20250903
- pg_bigm CI: https://github.com/pgbigm/pg_bigm/blob/master/.github/workflows/test.yml
- pg_cron: https://github.com/citusdata/pg_cron/blob/main/CHANGELOG.md
- pg_hint_plan releases: https://github.com/ossc-db/pg_hint_plan/releases
- pg_hint_plan PG19 plan: https://github.com/ossc-db/pg_hint_plan/issues/246
- pgAudit: https://github.com/pgaudit/pgaudit/releases/tag/19beta4
- set_user: https://github.com/pgaudit/set_user
- set_user CI: https://github.com/pgaudit/set_user/blob/main/.github/workflows/test.yml
- pg_repack: https://github.com/reorg/pg_repack
- pg_repack CI: https://github.com/reorg/pg_repack/blob/master/.github/workflows/regression.yml
- pg_ivm: https://github.com/sraoss/pg_ivm/releases/tag/v1.16
- pg_qualstats: https://github.com/powa-team/pg_qualstats/releases/tag/2.1.4
- pg_qualstats CI: https://github.com/powa-team/pg_qualstats/blob/master/.github/workflows/tests.yml

## pgextwin extension-repository audit

The existing maxMajor 18 or explicit 14-18 lists in the eight manifests are intentional declarations of the **current production support range**. They are not generic-infrastructure defects and are not changed in this milestone.

No extension repository receives maxMajor 19, a PG19 majors entry, a PG19 upstream ref, a Release, or a catalog asset here.

Important local observations:

- pg_cron's Windows build has a PostgreSQL "< 16" compatibility export path and otherwise uses upstream Makefile.win; this is not an upper bound.
- pg_hint_plan's local query-jumble source workaround is limited to "< 17". PG17+ follows the newer upstream path, so PG19 does not hit the legacy source-hash table.
- pg_ivm has a PG14-only Windows data-symbol compatibility edit. It is not a PG19 restriction.
- pg_repack is intentionally pinned to 1.5.3 and applies an exact source patch for PostgreSQL 18+ extended module magic. Its smoke test also asserts "pg_repack 1.5.3". An upstream PG19-capable tag will therefore require a deliberate build/smoke script refresh instead of blindly changing the manifest.
- pg_qualstats 2.1.4 contains PG19 compatibility and pgextwin applies a narrow MSVC preprocessing rewrite to that exact source layout. A real PG19 Windows compile is still required to confirm it.

## PostgreSQL 19 extension-facing compatibility concerns

The PostgreSQL 19 release notes contain several changes relevant to this set of extensions:

1. **Planner / optimizer hooks.** get_relation_info_hook is removed and build_simple_rel_hook is added. New planner setup/shutdown and join setup hooks are also introduced. pg_hint_plan has the highest exposure and must receive planner/hint-table functional testing, not only a compile test.
2. **Index access-method API.** Index AM handlers now use static IndexAmRoutines structures. This is another reason to exercise extensions that inspect planner/index metadata, especially pg_hint_plan and pg_qualstats.
3. **Shared memory.** ShmemRequestStruct() is added as a simplified shared memory registration API, while ShmemInitStruct() and ShmemInitHash() remain for compatibility. This reduces immediate risk for existing code but does not replace runtime preload tests for pg_qualstats, pg_cron, set_user, pgAudit, pg_bigm, and pg_ivm.
4. **Function prototype cleanup.** Some prototypes move from bit* typedefs to uint*. Compilation with warnings/errors enabled is needed to catch extension call sites that relied on the old types.
5. **Logical decoding API.** Output plugins can declare that they do not access shared catalogs. None of the initial eight is primarily a logical decoding output plugin, so this is not currently a direct blocker. It is relevant to the new core concurrent REPACK implementation described below.
6. **Windows/toolchain.** PostgreSQL 19 requires Visual Studio 2019 or later, adds MSVC AArch64 work, and improves Windows backtraces. pgextwin's x64 Visual Studio discovery uses the current installed VS C++ toolchain and has no 18 ceiling.
7. **Language/build system.** PostgreSQL moves its supported C language level to C11 and requires Meson >= 0.57.2. pgextwin's Meson-using paths currently pin Meson 1.8.3, so the version floor itself is not a blocker.
8. **Module magic.** No new PostgreSQL-19-specific module-magic incompatibility was identified in the release notes. pgextwin's pg_repack path already handles the extended module-magic model introduced for PostgreSQL 18+; that patch must be reconciled with newer pg_repack upstream source rather than duplicated.
9. **Query jumble / query ID.** No separate PG19 query-jumble API break was identified in the release notes during this audit, but pg_hint_plan's own PG19 work and query-ID behavior make its hint-table smoke scenario a mandatory acceptance test.

Official source: https://www.postgresql.org/docs/19/release-19.html

## pg_repack and PostgreSQL 19 core REPACK

PostgreSQL 19 introduces a native SQL REPACK command. It rewrites tables to reclaim space and can reorder by an index. REPACK (CONCURRENTLY) uses logical decoding to capture changes while the new files are built and holds an ACCESS EXCLUSIVE lock primarily for the final swap. It has explicit restrictions, including requirements around primary key/replica identity and limits for unlogged, partitioned, non-heap, catalog, and other relation types.

Core command reference: https://www.postgresql.org/docs/19/sql-repack.html

There is no direct SQL-name collision with the pg_repack extension/tool:

- the core feature is a SQL statement named REPACK;
- the community project installs the pg_repack extension and pg_repack/Windows pg_repack.exe client utility.

There is substantial functional overlap for the common "online table rewrite / online cluster" case, so the core command will reduce the cases where a PG19 user needs pg_repack. It does **not** make pg_repack redundant at this time.

pg_repack still exposes operational features not represented by the current core REPACK syntax/documentation, including:

- cross-database --all orchestration,
- schema/table/parent-table selection from the client,
- arbitrary-column --order-by,
- index-only rebuilds,
- online tablespace relocation and index relocation,
- parallel index rebuild jobs,
- client-side lock wait/cancel policy and automation controls.

Upstream pg_repack master already documents PostgreSQL 19 and tests PG19 in its CI matrix. The latest tagged pgextwin source remains ver_1.5.3, so pgextwin should retain pg_repack and reassess its product positioning after a tagged PG19-capable upstream release and Windows functional comparison. This audit does not remove or deprecate pg_repack.

## Why no live PG19 Windows probe was run

A live binary probe is intentionally deferred in this milestone because the normal pgextwin installation path cannot yet obtain a stable PG19 Windows package from its production package source.

Although EDB pre-release/Early Experience material exists, using a special one-off installer path would not prove that the normal pgextwin CI installation contract works. The readiness fixtures already prove the generic major-number contract without contaminating production metadata.

A future experimental probe is appropriate when a trustworthy standard Windows RC/GA distribution can be installed reproducibly without advertising it as a pgextwin production target.

## PostgreSQL 19 production onboarding gate

PostgreSQL 19 may be added to production metadata only after all applicable gates are satisfied:

- [ ] PostgreSQL 19 GA has been officially released.
- [ ] Final PostgreSQL 19 release notes/version information is available.
- [ ] PostgreSQL's official Versioning Policy provides the lifecycle/final support date needed by pgextwin metadata.
- [ ] A normal official/standard EDB Windows x64 distribution is available.
- [ ] pgextwin CI can install that distribution reproducibly through an approved package route.
- [ ] The exact major, minor, chocolateyPackage, chocolateyVersion, eol, and testPort metadata values are known.
- [ ] Adding the real PG19 metadata entry passes metadata, schema, resolver, and lifecycle tests.
- [ ] Each extension being marked PG19-supported has an acceptable upstream PG19 ref. Major-specific projects such as pg_hint_plan and pgAudit require a PG19-specific ref; PG18 refs must not be reused.
- [ ] Each onboarded extension passes its Windows build, install, functional smoke test, package check, and license verification on PG19.
- [ ] Existing maintained PostgreSQL targets continue to pass. PostgreSQL 14 remains eligible through 2026-11-12 if onboarding happens before EOL.
- [ ] No artificial five-major cap is introduced; a temporary PG14-19 six-major matrix is acceptable.
- [ ] Releases are onboarded per extension as evidence becomes available; GA alone must not mark all eight extensions supported.
- [ ] Catalog availability is added only for binaries that actually exist.
- [ ] Catalog/website maintenance state remains consistent with the lifecycle policy and does not confuse historical availability with current support.

## Recommended next action

At the 2026-10-06 checkpoint:

- **Shared Windows probe:** wait for the RC/standard Windows distribution path rather than add an ad-hoc pre-release installer mechanism now.
- **Ready for the first probe once that path exists:** pg_bigm, pg_cron, pgAudit (pre-release source only), set_user, pg_ivm, and pg_qualstats.
- **pg_hint_plan:** upstream PG19 branch work is present, but wait for a formal REL19 ref before production onboarding.
- **pg_repack:** upstream master is PG19-aware/tested, but wait for an appropriate tagged release and then refresh pgextwin's 1.5.3-specific build patches before production onboarding.

No GitHub Release, catalog PG19 entry, or website PG19 support declaration is part of this milestone.

---

## 日本語要約

この監査時点のPostgreSQL 19は **Beta 4** であり、pgextwinの正式対応対象ではありません。productionの metadata/postgresql.json はPostgreSQL 14〜18のまま維持します。

共通resolver・schema・reusable workflowにはPostgreSQL 18上限や「常に5世代」という制約はありません。合成fixtureを使って maxMajor 19 の14〜19 6世代matrixと、majors [18, 19] のmajor別upstream mappingをCIで検証します。

Windows側は通常のPostgreSQL Windows installerがまだ14〜18を正式対象としており、pgextwinが通常利用するstableな postgresql19 Chocolatey packageも確認できていません。そのため、このStepでは特殊なpre-release installer経路を追加して無理に実buildせず、標準的なRC/GA Windows配布経路が整ってからexperimental probeへ進む方針とします。

Extension upstreamはPG19対応がかなり進んでいます。pg_bigm、pg_cron、pgAudit pre-release、set_user main CI、pg_ivm、pg_qualstatsにはprobeへ進める根拠があります。pg_hint_planはPG19 branchがある一方で正式REL19 ref待ち、pg_repackはmasterでPG19対応・CI済みですがpgextwin側が1.5.3専用patchを持つため、新しいtagへ移る際にbuild/smoke scriptを見直す必要があります。

PostgreSQL 19のcore REPACKはpg_repackと機能が重なりますが、pg_repackには複数DB操作、index-only、tablespace移動、並列index rebuild等の独自機能が残るため、このStepでは配布停止・削除・deprecated化を行いません。

正式PG19対応は、GA、Lifecycle情報、標準Windows配布、再現可能なCI install、Extensionごとの正式upstream refとWindows functional testが揃ったものから個別に進めます。PG19 GAだけを理由に初期8 ExtensionすべてをSupported扱いしません。
