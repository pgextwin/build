# Step 21 — promotion operations and recovery

## Trust boundaries

Central `metadata/release-promotion.json` allows only plpgsql_check and requires
manual approval. The nine-entry `automation-fleet.json` and its daily 00:00 UTC
OFF/WATCH/BUILD watcher policy remain unchanged. Local `config/release-promotion.json`
must also permit manual approval.

A green candidate CI and a VERIFIED candidate-audit are necessary, never sufficient.

1. Candidate PR must be automation-owned (GitHub Actions bot and deterministic
   candidate marker), change only the upstream manifest and be human reviewed,
   merged to main and an ancestor of the actual trusted release source commit.
2. The main watch candidate-decision and workflow_dispatch candidate-audit
   artifacts must agree with the candidate PR head, immutable upstream commit,
   candidate ID, successful workflow runs and all PG15/16/17/18 artifacts.
3. Before approval, review source changes, licensing, ABI/Windows compatibility,
   Test Contract v2 and plpgsql_check export audit; merge necessary fixes.
4. Create an independently reviewed PR changing ONLY
   `approvals/<candidateId>.json`. The machine-readable record must have:
   schemaVersion=1, status=APPROVED, candidatePr, candidateRunId,
   decisionRunId, candidateId, upstreamCommit, releaseTag, all four
   review booleans true (licenseReviewed, windowsCompatibilityReviewed,
   sourceChangesReviewed, testContractReviewed) and requiredMajors=[15,16,17,18].
5. After the approval PR is merged, manually dispatch
   `plpgsql_check/.github/workflows/promote.yml` on main with candidate PR,
   decision run ID, candidate CI run ID, approval PR and a fresh tag matching
   `v<version>-windows.<positiveBuild>`. No approval → no release.
6. A fresh Windows PG15–18 attested build uses the trusted main revision,
   independent of normal candidate ZIPs. The publication job verifies PACKAGE-INFO,
   SPDX, Grype and both GitHub-signed attestations. It checks all expected assets,
   reserves a never-used Git tag exclusively, creates a new draft, verifies remote
   SHA256 digests, publishes only that new draft and re-verifies remote assets.
7. Only after publication verification does a scoped one-hour GitHub App token
   dispatch the Catalog sync workflow. It verifies the public signed Release,
   recreates Catalog v2 from Release assets and immutable Test Contract,
   opens a PR and runs validation. Auto-merge is disabled. After human merge,
   Catalog can request a Website audit; daily audit is a fallback.
   Website reads Catalog only and does not duplicate release metadata.

## GitHub UI permissions

- Organization GitHub App installed on catalog, with Actions:write + Metadata:read.
  In the plpgsql_check repository, set variable
  `PGEXTWIN_CATALOG_APP_CLIENT_ID` and secret
  `PGEXTWIN_CATALOG_APP_PRIVATE_KEY`.
- Install GitHub App on website with Actions:write + Metadata:read.
  In catalog set `PGEXTWIN_WEBSITE_APP_CLIENT_ID` (variable) and
  `PGEXTWIN_WEBSITE_APP_PRIVATE_KEY` (secret).
- Catalog must allow workflow-created PRs and Actions workflow_dispatch.
  Require review and passing CI before Catalog main merge.
- Require independent human review, protected main and successful checks for
  extension candidate and approval PRs. If Environments Required Reviewers is
  available, apply it to the publisher job as an additional approval layer.
- All cross-repository tokens are short lived and scoped to one target repository.
  No personal PAT, no pull_request_target checkout and no candidate release write.

## Failures and recovery (never overwrite existing Release)

Before tag reservation, failed runs create no Release. Review candidate identity,
policy or broken evidence, and initiate a new explicitly authorized run.

After tag reservation, a partial tag/draft is an incident: preserve the
promotion-recovery artifact and all Actions logs, source commit, tag and assets.
Do not delete, force-move, overwrite or edit existing published Releases or retry
the same tag. Quarantine the partial draft. If a new attempt is authorized,
use a new build number and a new human-approved tag-binding PR.

If the Release is already public and Catalog dispatch fails, keep the Release
unchanged. Once the App is configured, run Catalog's sync-release workflow for
the existing publicly verified tag. If Catalog PR validation fails, refuse merge.
If Website live audit fails, repair the consumer/auditor; never edit old binary assets.

## Remaining acceptance boundary

Synthetic fixtures establish fail-closed behavior but are NOT proof that a real
new upstream stable tag produces a candidate PR, actual Windows candidate artifacts,
VERIFIED audit, approved formal Release, Catalog merge and browser audit.
Do not claim a production E2E until those real run URLs and new public assets exist.
The other eight extensions stay WATCH until separately audited.
