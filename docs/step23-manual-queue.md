# 14-extension manual candidate queue and verified Release runbook

> Current operating procedure (2026-10-12). The original **Step 23 nine-extension** dry-run acceptance is recorded and completed in [build #47](https://github.com/pgextwin/build/issues/47). The continuing **14-extension** platform and downstream E2E work is in [build #61](https://github.com/pgextwin/build/issues/61).

## Operating contract

- Central `metadata/automation-fleet.json`: **14/14 BUILD**, `candidateEnabled: true`, `releasePolicy: manual-only`, daily `0 0 * * *` UTC (**09:00 JST**).
- Every extension also has `config/candidate-build.json` with `enabled:true`, manual-only, and an immutable upstream identity. **Both central and local authorization must pass.**
- The update watcher is stable-only. It may prepare a SHA-pinned automation-owned **Draft** `auto-candidate/*` PR and dispatch Windows CI. Upstream already current means no new candidate PR. A candidate is **not** a formal Release.
- All 14 extensions have **main-only** `.github/workflows/promote.yml` with explicit `confirm_release=PUBLISH`. `release/*` pushes must **not** publish and are not a supported path in current extension callers.
- `metadata/unattended-publication.json` remains **OBSERVE / DENY**. `automaticCandidateMerge`, `automaticFormalRelease` and `automaticCatalogMerge` are false. Catalog proposer and its App require separate explicit opt-in.
- Maintain full-SHA pins, branch protection, exact-head PostgreSQL Windows CI, PACKAGE-INFO, SPDX SBOM, attestation and immutable checksum requirements. **Grype remains report-only**; review findings before approving a Release.

## Review a candidate — not yet a Release

1. Open the [read-only fleet status](https://github.com/pgextwin/build/actions/workflows/fleet-status.yml), then the **target extension's own** [update-watch workflow example](https://github.com/pgextwin/plpgsql_check/actions/workflows/update-watch.yml). Inspect the latest applicable completed run and the actual `candidate-decision` artifact. **`BUILD` in a green fleet summary is insufficient.**
2. For a new Draft candidate PR, verify the stable upstream tag/ref, resolved **full immutable upstream commit SHA**, manifest-only diff, upstream release notes, license/security impact, PG-major mapping and automation identity. Reject missing/ambiguous API data, shifted upstream tag, duplicate PR and unexpected changes.
3. Require the candidate's **exact head** Windows CI success for every currently supported and configured PostgreSQL major; verify matching signed ZIP packaging, SPDX, Grype report, candidate-audit artifact, successful job receipts and source identity. Do not treat a prior commit's successful run as a current-head check.
4. A permitted operator may mark the Draft ready and merge a verified candidate PR **after required CI**. An independent human reviewer is **not** separately mandatory, but verification and branch rules may not be bypassed. Record candidate PR number, exact SHA, the latest Windows CI run ID and the stable decision run ID.
5. If a candidate is suppressed, its audit is missing, any matrix job failed, or upstream identity cannot be proven, **do not merge and do not publish**. Fix the source or evidence and repeat verification; never use an unrelated prior green run.

## Publish a formal Release — separate human action only

1. Confirm the operator intentionally wants a new Release, on the **current protected main**. Check all inputs still match the merged candidate and the latest correct head, and the proposed `release_tag` has **never** been used by either a tag or a Release.
2. On that extension's [`promote.yml` workflow](https://github.com/pgextwin/plpgsql_check/actions/workflows/promote.yml), select **main** and provide `candidate_pr`, `candidate_run_id`, `decision_run_id`, `release_tag`, and `confirm_release=PUBLISH`. This is the only publication-triggering operator action; do not initiate `release/*` branches or bypass the gate.
3. The `authorize` job checks local and central manual-operator allowlists, non-bot origin, exact upstream SHA and candidate receipts and writes `promotion-receipt`. Signed `release_build` then rebuilds the full supported PG matrix. The guarded `publish` job verifies the newly signed ZIP/SBOM provenance and exact SHA-256, creates only a fresh Release/tag identity, and writes recovery evidence if partial.
4. **If any stage fails:** do not count it as published, do not reuse an occupied tag, do not delete/overwrite previous public ZIPs, and do not silently retry a partial Release. Inspect the `promotion-recovery` artifact and address the failure under a separate explicit plan.
5. After a successful formal Release, independently check every required PG-major ZIP and companion SPDX/Grype asset, SHA256SUMS, GitHub digest, PACKAGE-INFO identity, tag ancestry, and trusted successful promotion. A successful Build **does not automatically mean Catalog or Website have updated**.

## Post-manual Release Catalog → Website

1. The 14-extension signed-Release verifier and Catalog mapper are present on `pgextwin/catalog/main` (Catalog #47, #49, #50). The trust boundary is **operator-published successful main Release → independently rehashed/attested assets → eligible new Catalog record**.
2. `sync-verified-release.yml` is manual dispatch, and **Catalog PR proposal** requires the dedicated `PGEXTWIN_CATALOG_PROPOSER_ENABLED=true` configuration plus a least-privilege GitHub App token. The default is deny/disabled. Never expose the App private key or grant organization-wide rights when the repository-scoped permission is sufficient.
3. Inspect the single changed `extensions/<name>.json` Catalog PR, validate exact Release asset URLs/digests, require Catalog native CI, then manually merge under its rules. Automatic Catalog merge is **not** enabled.
4. Verify Website build/deployment and public EN/JA extension downloads, SHA256 and provenance/Grype references. Record the actual tag, promotion run, Catalog PR/CI, website commit/run and public outcome in [fleet issue #61](https://github.com/pgextwin/build/issues/61).
5. A **live signed new-Release → Catalog PR → Website** E2E is still outstanding until the next genuine operator-approved version and App configuration. Do not manufacture a Release just to satisfy this checklist.

## Acceptance tracking

- [x] Original nine-extension dry-run candidate-decision artifacts and public Website smoke — [Step23 #47 completed](https://github.com/pgextwin/build/issues/47).
- [x] New five extension main PG14–18 CI and manual-PUBLISH local gates audited, including repaired `pg_partman` BGW.
- [x] Central 14/14 BUILD candidate lanes — [Build #70](https://github.com/pgextwin/build/pull/70), full CI and read-only fleet status successful.
- [x] Central 14/14 operator-only Release allowlist; default OBSERVE/DENY preserved — [Build #71](https://github.com/pgextwin/build/pull/71).
- [x] Initial eight legacy `release/*` publication trigger paths replaced by main-only `promote.yml` with exact-head PG14–18 CI.
- [ ] Audit every remaining new main-push Windows run after cutover; do not assume completion while jobs are in progress.
- [ ] At least one **new genuine stable update** per relevant strategy needs full real candidate PR → SHA pin → Windows CI → candidate audit evidence; successful dry-runs alone do not prove this across 14.
- [ ] Dedicated Catalog proposer GitHub App scope and repository config positively verified; leave disabled until ready.
- [ ] One actual subsequent **manual PUBLISH** → independent signed Catalog PR → Catalog CI/merge → public Website E2E validated, with no automatic formal Release.

## Safe rollback

Disable an affected candidate lane with a reviewed central policy change from `BUILD` to `WATCH` (and `candidateEnabled=false`), plus any necessary local candidate opt-out. The formal Release gate is separate and stays main-only/explicit PUBLISH. Existing candidates require triage but **existing Release tags, ZIP assets, attestations and checksums must never be deleted or rewritten as a rollback**. Keep original failures and receipts as audit evidence.
