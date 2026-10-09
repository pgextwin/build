# Step 19 — Automated upstream candidate builds

This builds on Step 13's notification-only watcher; those Issues remain a separate source of change alerts.

## Operating policy

Each extension opts in with `config/candidate-build.json`:

```json
{"schemaVersion":1,"enabled":true,"releasePolicy":"manual-only","workflow":"windows.yml"}
```

Never enable automatic publication in Step 19. The policy is intentionally constrained to the audited `windows.yml`; it is not a shell-command or arbitrary-workflow selector. Setting `enabled` to `false` disables automated candidate proposals and dispatch.

The extension's existing daily `update-watch.yml` invokes both the Step 13 Issues watcher and the Step 19 `candidate-update.yml` reusable workflow, pinned to **different explicit full commit SHAs** until both evolve together. Both use stable-only upstream detection. The candidate planner runs with `contents: read` and fails closed on malformed responses, tag identity mismatches, moved annotated-tag objects, or missing API data. An immutable candidate plan JSON is uploaded to the Actions run.

If and only if a stable version is newer than the version in `config/extension.json`, the plan includes resolved tag-to-commit identity for each affected PG series. Candidate ID is deterministic from repository and sorted (series, ref, commit); it becomes the immutable branch `auto-candidate/<20 hex>`. PostgreSQL 19 informational-only series are never proposed, and eligible production majors are still determined by the common lifecycle matrix resolver.

The proposal job has `contents: write`, `pull-requests: write` and `actions: write` only; it has **no OIDC, attestation or Release credentials**. It re-resolves every candidate tag and fails on mismatch before changing the packaging repository. It updates only the `upstream.ref`, `upstream.version`, and `upstream.commit` fields on an owned draft candidate branch, linking upstream release notes and the old version in the draft PR.

It never overwrites a human branch or PR. An owned matching branch and open PR are reused; a closed candidate PR is never reopened. It explicitly dispatches the already existing `windows.yml` with `GITHUB_TOKEN`, which is supported by GitHub Actions even when a bot-created pull request's `pull_request` CI would require approval. Before dispatch it searches for prior workflow_dispatch runs for that branch; if any are found (even failed runs), there is **no automatic repeat**. An operator may explicitly rerun a failed run after reviewing the cause. The caller and reusable workflow apply concurrency to avoid overlapping watchers, and the Windows workflow does not cancel builds.

The read-only, SHA-asserting normal build still runs Test Contract v2 functional smoke tests and packages ZIP + PACKAGE-INFO.json, SPDX 2.3 SBOM and Grype JSON for each eligible PG major. Grype remains report-only for findings. The candidate reporter is a separate job with Issues comment permission and requires every PG15–18 artifact and all PG matrix jobs to pass before posting `VERIFIED CANDIDATE` to the draft PR. It reports failures explicitly with the run URL.

This is **not** a signed release artifact. Attested Release builds and SBOM predicate verification remain a separate trusted workflow and independent audit gate. There is no automatic release, Catalog, Website, or PR merge.

## Known fail-closed behavior and operational limits

- The common candidate planner supports `github-releases`, `github-tags`, and `github-releases-per-postgresql`. For new extensions, separately audit source hooks, licenses, candidate reporting, stable regex, and the declared PG matrix before opt-in.
- For plpgsql_check, candidate source must preserve the previously audited SQL/C export symbol contract and current SQL major 2.10; changes requiring a new export contract cause a candidate build failure and manual maintenance. No failure is treated as a successful artifact build.
- For any SHA-updated **formal Release**, the independent export audit must be updated to the new SHA before an attested release. Candidate compatibility alone is not authorization for publication.
- The bootstrap GitHub repository must allow Actions to create pull requests using `GITHUB_TOKEN`; the repository/org Actions settings can disable this. `contents: write`, `pull-requests: write` and `actions: write` must be grantable to the proposal job. If these settings prohibit PR creation, the workflow fails visibly rather than claiming success. A scoped GitHub App installation token is a possible later substitute, not a prerequisite in this design.
- Duplicate dispatch prevention uses existing GitHub Actions runs (latest 100 for the branch). Old runs must remain discoverable for historical candidate IDs; for retention windows where no run remains, the draft PR comment/immutable branch should be used as a durable dispatch ledger before extending this to large-volume production. Auto re-dispatch across a completely expired run history is not accepted as a proven property.
- GitHub workflow_dispatch always uses a branch with trusted packaging hooks and a verified upstream commit. There is no pull_request_target checkout.
- A candidate with an unexpected API error cannot open/update/close Step 13 Issues or update a source manifest.
- Test fixture validation covers no-op, stable candidate, prerelease exclusion, API failure, annotated tag identity, downgrade, per-major isolation, and idempotent candidate identity; an actual future-version Windows matrix needs real upstream changes to pass.

## Release gate for Step 20

Formal release branches must use `release/v<upstream-version>-windows.<positive-build-number>`. Preflight verifies branch name, manifest version, GitHub Release absence, and Git tag absence twice (before and after attested build). Publication is create-only; no edit, upload, or `--clobber` path is permitted. In Step 20 introduce a separate manual approval environment and promotion evidence store that verifies unsigned candidate to freshly rebuilt attested Release identity, all PG matrix completions, SHA256SUMS, provenance/SBOM attestations, and no preexisting tag or asset before atomic create. After publication verify catalog schema v2 and generated Website links, with a separate rollback-safe Catalog PR if any operation fails.
