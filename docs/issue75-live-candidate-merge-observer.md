# Issue #75 — authenticated candidate merge observations (nonpublishing Phase 2)

Owner has granted standing approval for eligible NEW stable versions for 17 extensions. This does NOT imply CI-success-only publication. The currently deployed promotion remains manual-only.

## Implemented

`scripts/automatic-candidate-merge-observer.py` is a tightly scoped **read-only** GitHub Actions main/push observer. It independently fetches and checks the original GitHub main-push payload, actual Git commit and single parent, exact bot-authored merged candidate PR (with ownership marker and unchanged config/extension.json Git blob), a human merger `ShutenOishi`, active protected main/required App15368 Windows context, exact PR HEAD check-run and unique successful PR Windows workflow. It only recognizes the central exact 17 repository roster. The CLI enforces an actual GitHub Actions push environment and allowlisted GET endpoints. Missing, ambiguous, incomplete or mismatched evidence is denied.

**This is not yet a live webhook handler or a production Release workflow**: this PR adds no trigger, does not change any signer/publisher, workflow permissions, central/local release policy, candidate approval, tag or Release.

Success is `AUTHENTICATED_PR_CI_ONLY` with explicit `candidateArtifactAuditVerified=false`, `effectiveBranchRulesAudited=false`, `signatureAndProvenanceVerified=false`, `publicationAuthorized=false`, `publishableReceipt=false`. The observer cannot create a publishable receipt and does not establish a Release version/tag or allowed candidate decision artifact. The real GitHub API response is mandatory only when this helper is run in its required authenticated main/push context.

Hostile tests check duplicate PRs/checks/runs, stale/mixed SHA, fake actors and branch protection, bot/cross-repo merges, missing or skipped/failed Windows CI, extra files, forged ownership marker, wrong versioned branch and non-main pushes.

## Remaining real-world gates

1. Attach this centrally pinned reader to a **safe nonpublishing** local main/push listener in one extension, in a normal protected PR. Validate actual independently fetched GitHub REST objects, event SHA, App15368 and branch rules. Do not publish when run metadata or branch rules are incomplete.
2. Build a trusted exact-head **candidate audit** generated without manual `workflow_dispatch` on each of 17 extensions. The normal PR CI (5/5 SUCCESS) by itself does not upload `candidate-audit` because the existing reporter only runs on dedicated candidate dispatch. Do not reuse an old run artifact for the amended PR head.
3. Introduce an explicit standing-policy automatic promotion mode only after fully independent candidate proof. Reuse actual existing signed artifacts, SLSA/SPDX, SHA256, current signer and create-only Publisher. Preserve the known working manual workflow as fallback until validated.
4. Release one real new eligible stable candidate with full evidence, then extend to all 17 and verify Catalog independently validates the new provenance. Its newly merged 6-hour discovery cannot itself authorize unsigned records.

This issue does not require a new GUI reviewer, App or Secret; no PUBLISH can pass from this observer.
