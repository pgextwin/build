# Issue #311 R11 schedule retirement: authenticated preflight (2026-10-31)

**INVENTORY_ONLY / NONPUBLISHING / PENDING**. This does not authorize schedule removal or accept R11-01, R11-02 or parent R11.

## Verified before this PR

Authenticated GitHub Contents GET of 17 real .github/workflows/update-watch.yml files confirms every extension retains hourly 30 * * * *; hypopg also retains independent 41 * * * * recovery cron. All 17 retain push, workflow_run, and a schedule-dependent authorize job. Replacement normal/negative and legacy Writer overlap are not accepted. Removing any cron is prohibited.

## Original proof provided by the PR

This GET-only Python inventory reads the protected main REST branch and exact contents Git blobs for the 17 extension workflows, and enumerates all workflow files in build, catalog and website to identify schedules and schedule-sensitive jobs. Scope missing, changed HEAD, unmatched blob, cron/trigger absent, or unprotected branch fails closed. No Release, tag, PR, dispatch, feed, App token or writer.

- Protected PR offline hostile tests only; not live evidence.
- Original protected main push performs authenticated GET and records original JSON artifact.
- Separate App-keyless Runner downloads the original artifact, repeats authenticated GET, requires byte-identical JSON.
- Record original Run/Job/Artifact and outer ZIP SHA256 only after they actually exist. This inventory alone does not accept R11. Artifacts expire; preserve real originals.

## Safe migration order

1. For each schedule workflow, accept genuine nonpublishing normal and negative substitute original Run/attempt/HEAD/ZIP/SHA, CAS, and independent readback. Do not impersonate schedule or source-kind.
2. Inspect old queued/in_progress Runs, verify genuine overlapping legacy/new Writer CAS rejection, single PUT per writer, loser HTTP409, 401 token expiry, finite restart and GET before retry on lost ACK.
3. Only then remove the particular schedule and schedule-dependent authorization via protected PR. Preserve push, pull_request, workflow_run, required CI and branch protection. hypopg extra recovery cron needs separate review.
4. Re-inventory 17 extensions plus build/catalog/website; require all targeted schedule dependencies gone and full accepted evidence before R11-01/02 or parent R11 PASS.

## Other pending gates

R10-02 still requires genuine BLOCKED_APPROVAL State terminal with per-target originals, reasons and separate authenticated readback. Existing R08 Publisher PUBLISH_DENY admission is NOT equivalent. The missing orafce dispatch-input/child ZIP remains NO_DISPATCH_INPUT_BINDING_OR_ORIGINAL_CHILD_ZIP; time adjacency does not prove linkage.

R12-02 requires one authenticated Chat request through genuine 17-target nonpublishing terminals, reason, last successful stage, safe restart point, reacquirable original proofs and an operator handoff. No replay of successful Run IDs or bypass of R11. R09-02 waits for a future eligible stable and separate human PUBLISH approval; Website Draft PR #45 remains unmerged.

Keep runtimeEnabled=false, PUBLISH_DENY, original cron, CI, protected branches, #311/#75 OPEN. No new scheduled task, external worker, forged actor, Secret reuse or unapproved publication.
