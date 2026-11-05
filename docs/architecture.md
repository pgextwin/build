# pgextwin architecture — protected 17-extension Windows fleet

> Current operating contract: [Chat-first publication](chat-first-publication.md), [Fleet policy](automation-fleet.md), [Test Contract v2](test-contract-v2.md), [Issue #510](https://github.com/pgextwin/build/issues/510).
> This page describes existing reusable paths, not a new release authorization. The live protected repositories and GitHub Runs remain authoritative.

## Single sources of truth

| Scope | Existing authoritative location | Responsibility |
| --- | --- | --- |
| Registered native extensions and their policy | `pgextwin/build/metadata/automation-fleet.json` on protected `main` | Repository membership, update strategy, candidate mode; currently 17 native entries. Do not maintain a second roster. |
| Per-extension source identity and target PG majors | `pgextwin/<extension>/config/extension.json` | Upstream repository, stable ref, immutable commit, PG versions, Windows x64 and license policy. |
| Upstream detection semantics | `config/update-watch.json` | Stable-only tags/releases and optional per-PG matching. Must agree with the central Fleet entry. |
| Candidate opt-in | `config/candidate-build.json` | `enabled=true`, `releasePolicy=manual-only`, `workflow=windows.yml` for a BUILD candidate. This is never Publisher authority. |
| Windows functional acceptance | `config/test-contract.json` and `windows/ci/smoke-test.ps1` | Contract v2 and real extension-owned SQL/plan/log/client/worker assertions. |
| Common schemas and validation | `pgextwin/build/schema/{extension,test-contract,update-watch}.schema.json`; shared validators and `scripts/fleet-control.py` | Versioned contract and fail-closed identities; no per-repository schema forks. |
| Public versions and website delivery | `pgextwin/catalog`, signed original GitHub Releases, `pgextwin/website` | Catalog/Website only after independently accepted formal Release. |

The current protected Fleet contains 17 native entries. It is not an assertion that 17 new upstream updates or 17 new Release builds are pending. The two external PG18 test sources from [#112](https://github.com/pgextwin/build/issues/112) are **not** an eighteenth/nineteenth native Fleet member and remain under their separate DENY policy.

## Established shared execution paths

1. **Watch/prepare:** Existing `.github/workflows/update-watch.yml` callers use pinned shared watch/candidate workflows and a live protected Fleet read. A stable update may generate a source-SHA-pinned draft PR and nonpublishing Windows `workflow_dispatch`; a bot-created `pull_request` run can separately be `action_required`. Preserve both event identities; do not relabel dispatched CI as a successful original PR event.
2. **Build/test:** Local `.github/workflows/windows.yml` calls a full-SHA-pinned central `build-extension.yml`. PG matrix resolution intersects the manifest with protected [PostgreSQL lifecycle](postgresql-lifecycle.md), not a hard-coded fleet-wide matrix. Each supported Windows PG major must pass functional smoke and the required summary. Runtime and test setup may differ.
3. **Source/sign:** The existing genuine owner `sign-main` caller and reusable attested Windows workflow are separate from unsigned CI. Original event, actor, attempt, protected main, ZIP, SPDX/Grype and two independent Sigstore audits cannot be inherited from another Run.
4. **Publish:** Formal Publisher policies, dedicated App/Environment, signed source, independent verifier, vulnerability gate, original Run and create-only Release are independently enforced. An owner Chat instruction expresses intent; it does not replace these technical gates. Never publish from a candidate PR or a `PUBLISH_DENY` path.
5. **Postpublish:** Existing Catalog signed-Release verifier proposes a narrow protected PR; required CI, protected merge, Website JA/EN and actual public ZIP/hash checks establish `PUBLIC_COMPLETE`.

Shared executable code is pinned to immutable full SHAs in each caller. Different callers may intentionally pin different **verified** versions; do not bulk-replace pins to claim uniformity. Extension-owned `windows/ci/build.ps1`, `install.ps1`, `package.ps1`, `smoke-test.ps1` and any source-specific adapter remain local.

## Smallest safe path to an additional native extension (Issue #510)

1. **Choose a real upstream and establish scope:** Verify stable release/tag, source commit, license/NOTICE, runtime dependencies, Windows/MSVC feasibility, supported PostgreSQL majors and source-specific build/SQL behavior. For a pilot, first use an already registered extension as a regression fixture; do not fabricate a new upstream Release.
2. **Reuse the declaration:** Start from a successful repository's `config/extension.json` and the central `schema/extension.schema.json`. Set the actual `name`, `upstream.repository/ref/version/commit`, `postgresql.majors` (or range), `windows.architecture=x64`, and upstream license path or file mapping. Use `upstream.perPostgresql` only when upstream truly differs per PG major. Do not add a duplicate central version ledger.
3. **Reuse watch/contract:** Add a semantically compatible `config/update-watch.json`, a contract v2 `config/test-contract.json` with observable functional scenarios, and only the necessary local Windows adapter/smoke. Select the existing shared `windows.yml`, `update-watch.yml` and signer callers; retain their original events, permissions, pin identities and default nonpublishing behavior.
4. **Register centrally once:** In a protected central PR, add one unique `pgextwin/<name>` entry to `metadata/automation-fleet.json` with matching strategy, schedule and releasePolicy. Start with `OFF`/`WATCH` if BUILD acceptance is not demonstrated. For `BUILD`, the local `candidate-build.json` must exactly opt in; a Fleet entry alone cannot enable publication. Review changes against `scripts/fleet-control.py` and existing tests.
5. **Dry-run and actual native validation:** Validate the common JSON Schemas and negative cases (unknown repo, duplicate member, mismatched watch/upstream, malformed immutable SHA, unsupported major, disabled BUILD opt-in). Use a genuine nonpublishing Windows PG matrix with ZIP/package/Test Contract proof on a disposable PG installation. Do not substitute a Linux-only schema test for Windows acceptance.
6. **Promote changes only through protected gates:** Check original required PR CI on the exact head; squash/merge through current branch protection; independently read the postmerge original `push` and results. Do not rerun successful Runs. A GUI-only `Approve and run` is handled as a real blocker, not by forging another event.
7. **Formal publishing is optional and separate:** If a **real** new stable is eligible, obtain a fresh authorized signed source tied to protected main, dual independent verification, scoped formal Publisher, create-only Release, then Catalog and Website E2E. A successful onboarding dry-run does not imply a new published extension.

## Source-specific adapter examples — no new general-purpose engine

- **`pg_hint_plan` and `pgaudit`:** Per-PostgreSQL upstream refs/commits; verify all supported major mappings rather than flattening into one version.
- **`pg_bigm`:** Dated upstream release reference; preserve its approved tag resolution and Windows packaging adapter.
- **`set_user`:** Shared preload plus actual role-transition/reset behavior; security-sensitive upstream changes require careful negative-case review, not only a successful compilation.
- **`plpgsql_check`:** Its tested SQL/C export and compatibility contract remain local. Owner issue-comment signing and formal Publisher have distinct receipt types.
- **`pg_repack`, `wal2json` and other special packages:** Respect local executable, logical decoding, preload, SQL and installation requirements declared by Test Contract v2; do not infer all ZIP layouts are identical.

This is a reuse-first contract, not an instruction to rewrite all existing callers. Keep accepted 17/17 public artifacts and protected policies intact; track independent pilot/build/onboarding acceptance on [#510](https://github.com/pgextwin/build/issues/510). The currently configured PG14–18 matrix must still honor EOL dynamically (PG14 through 2026-11-12 UTC); do not silently add pre-GA PG19 to formal releases.
