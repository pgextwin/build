# pgextwin build infrastructure

[日本語](README_ja.md) | English

Shared CI/CD infrastructure for **pgextwin**, a community project that builds and distributes unofficial Windows x64 binaries for PostgreSQL extensions.

This repository contains reusable GitHub Actions workflows, PostgreSQL build metadata, and the hook contract used by extension packaging repositories such as `pgextwin/pg_bigm`.

## Current operation: 14-extension candidate queue and manual verified Releases

All **14 extension repositories** share stable-only daily upstream detection (00:00 UTC / 09:00 JST), immutable upstream SHA-pinned **draft** candidate PRs, full Windows CI, and machine-readable candidate verification. The central `metadata/automation-fleet.json` registry has **14 BUILD / 14 candidateEnabled** entries. Candidates may be prepared automatically; **merging a candidate and formally publishing it are separate deliberate operator actions**.

All 14 extensions now use **main-only `promote.yml` workflow_dispatch**, not a `release/*` publishing trigger. Formal publication requires a merged and verified candidate, successful exact-head PostgreSQL-major Windows jobs and candidate audit, a trusted non-bot operator, an unused tag, and explicit `confirm_release=PUBLISH`. The central `metadata/release-promotion.json` manual-promotion allowlist has 14 members. A failed or partial Draft Release is not an invitation to reuse an occupied tag or silently retry.

Unattended publication remains `OBSERVE / DENY`: automatic candidate merge, automatic formal Release, and automatic Catalog merge are disabled. The Catalog signed-release proposer is separately opt-in; code availability does **not** mean the GitHub App or real post-Release end-to-end path has been accepted. See [14-extension manual queue runbook](docs/step23-manual-queue.md), [architecture](docs/architecture.md), and [fleet rollout acceptance](https://github.com/pgextwin/build/issues/61).

## Scope

The shared workflow is responsible for:

- resolving maintained PostgreSQL versions,
- installing the matching Windows PostgreSQL distribution,
- checking out the pinned upstream extension source,
- verifying the upstream license when configured,
- validating each extension's machine-readable Test Contract v2 before compilation,
- invoking extension-specific build/install/test/package hooks,
- adding and validating shared `PACKAGE-INFO.json` source/build metadata before the final ZIP is trusted,
- generating SPDX 2.3 JSON SBOMs from final ZIPs and validating their artifact identity,
- scanning the validated SPDX SBOM with checksum-pinned Grype in report-only mode and validating the point-in-time vulnerability report,
- generating and verifying release-only Build Provenance and SBOM GitHub Artifact Attestations for final ZIPs,
- uploading per-PostgreSQL-major artifacts,
- generating SHA-256 checksums,
- and publishing fresh, signed GitHub Releases **only** from a verified main-only manual `PUBLISH` promotion.

Extension-specific source adaptation and functional tests remain in each extension repository.

## Reusable workflows and trust boundary

Extension repositories use individually approved **full 40-character commit SHA pins** for common workflows and shared scripts. The read-only `windows.yml` caller invokes `pgextwin/build/.github/workflows/build-extension.yml` for PRs, main pushes, and explicit candidate CI. It never publishes a Release.

Each extension has a separate local `.github/workflows/promote.yml` triggered **only by `workflow_dispatch` on main**, with these required inputs:

- `candidate_pr`: already-merged, immutable upstream candidate PR
- `candidate_run_id`: successful exact-head candidate Windows CI
- `decision_run_id`: trusted watch run with candidate-decision artifact
- `release_tag`: fresh, never-used Windows Release tag
- `confirm_release`: exactly `PUBLISH`

The authorization job checks both local and central policy and writes a `promotion-receipt`. Only then does the attested reusable build recompile the supported PG matrix and generate/verify GitHub Build and SPDX attestations. The local guarded `publish` job invokes the shared `fleet-publish-release.py` script to verify immutable ZIP identities, SHA-256, provenance, and create-only Release identity; failures preserve a recovery receipt. Existing public tags and release assets are immutable.

The reusable `release-extension.yml` remains in this repository for historical compatibility, but **it is not the active publisher path of the 14 current extension callers**. Historical `release/*` examples must not be used as live operator instructions. Always inspect the extension's exact pinned workflow revision instead of assuming every call site uses one identical shared SHA.

See [Test Contract v2](docs/test-contract-v2.md), [Package metadata contract](docs/package-metadata.md), [SBOM contract](docs/sbom.md), [Vulnerability policy baseline](docs/vulnerability-policy.md), [Artifact Attestations and build provenance](docs/artifact-attestations.md), [GitHub Actions trust and permission policy](docs/github-actions-security.md), [Hook contract](docs/hook-contract.md), and [Architecture](docs/architecture.md).

## PostgreSQL lifecycle

PostgreSQL lifecycle filtering is centralized in this repository. A major is included in a new normal build only while it is still community-supported, allowed by the extension manifest, and backed by the required upstream ref/version. The official EOL date is inclusive; the major leaves the normal matrix on the following UTC calendar day.

As of 2026-10-06, PostgreSQL 14 is supported through **2026-11-12**. It remains in normal build matrices through that date and is excluded beginning **2026-11-13**. Existing Git tags, GitHub Releases, assets, and checksums are retained after EOL.

See [PostgreSQL lifecycle policy](docs/postgresql-lifecycle.md) for the complete policy and deterministic boundary-test contract.

## Status

- Phase 2 shared build foundation: complete
- Phase 3 pg_bigm pilot: complete — see [Phase 3 pilot report](docs/phase3-pg_bigm-pilot.md)
- Phase 4 second-extension technical pilot: complete — see [pg_cron pilot report](docs/phase4-pg_cron-pilot.md)
- Phase 5 pg_hint_plan technical pilot: complete — see [pg_hint_plan pilot report](docs/phase5-pg_hint_plan-pilot.md)
- Phase 6 pgAudit technical pilot: complete — see [pgAudit pilot report](docs/phase6-pgaudit-pilot.md)
- Phase 7 set_user technical pilot: complete — see [set_user pilot report](docs/phase7-set_user-pilot.md)
- Phase 8 pg_repack technical pilot and productization: complete — see [pg_repack pilot report](docs/phase8-pg_repack-pilot.md)
- Phase 9 pg_ivm technical pilot and productization: complete — see [pg_ivm pilot report](docs/phase9-pg_ivm-pilot.md)
- Phase 10 pg_qualstats technical pilot and productization: complete — see [pg_qualstats pilot report](docs/phase10-pg_qualstats-pilot.md)

**Initial extension roadmap: complete.** All eight initial extensions — `pg_bigm`, `pg_cron`, `pg_hint_plan`, `pgaudit`, `set_user`, `pg_repack`, `pg_ivm`, and `pg_qualstats` — have public PostgreSQL 14–18 Windows x64 Releases and catalog entries. Historical phase numbering is retained for compatibility with the existing pilot reports. See [Extension roadmap](docs/roadmap.md).

## Next platform work

The initial extension roadmap is closed. PostgreSQL lifecycle / PG14 EOL build-foundation readiness (Step 2), catalog and website lifecycle visibility (Step 3), the **PostgreSQL 19 readiness / compatibility audit (Step 4)**, **GitHub Actions trust baseline (Step 5)**, **Artifact Attestation / Release Build Provenance (Step 6)**, **PACKAGE-INFO v2 (Step 7)**, **SBOM Generation & SBOM Attestation (Step 8)**, **Test Contract v2 / Runtime Capability & Functional Validation Contract (Step 9)**, and **Vulnerability / Dependency Policy Baseline (Step 10)** are complete. See [PostgreSQL 19 readiness](docs/postgresql-19-readiness.md) and [GitHub Actions trust policy](docs/github-actions-security.md).

PostgreSQL 19 remains outside the production matrix until the documented GA/Windows/upstream gates are satisfied. Remaining work is intentionally separated into later milestones:

1. PostgreSQL 19 production onboarding after the documented GA/Windows/upstream gates are satisfied
2. future hard vulnerability gates, VEX/exception management, Dependency Submission/Review, SARIF/Security-tab integration, license policy, and PostgreSQL runtime vulnerability policy
3. catalog / website provenance and security visibility beyond current metadata
4. Python dependency locking and broader build-tool provenance
5. PostgreSQL package provenance beyond recorded Chocolatey identity
6. independently verified post-manual-Release Catalog App opt-in and first live 14-extension downstream acceptance


## Update detection automation

**Step 13** originally established stable-only upstream Issue detection for the initial eight extensions. The current **14-extension** fleet extends it with the separately gated candidate planner: the watcher detects stable upstream metadata, the SHA-pinned planner may propose a **draft** candidate, and full Windows CI plus candidate audit must verify the exact source. Watcher and planner run in dry-run mode on their workflow-file push acceptance path; production schedules remain at **09:00 JST**. No watcher or candidate planner can trigger a formal Release.

The central PostgreSQL lifecycle watch still observes the official Versioning Policy and new-major readiness without altering binaries or Releases. Read [the runbook](docs/step23-manual-queue.md) for the operative queue and [original Step 13 design](docs/update-automation.md) for the historical separation of detection from Issue reconciliation.

## License

The shared build infrastructure is distributed under the PostgreSQL License. See [LICENSE](LICENSE).
