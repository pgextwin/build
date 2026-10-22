# Issue #75 — trusted GitHub main-push native audit witness

**Status:** reusable read-only workflow + denied-by-default live observer,
still **NOT A RELEASE**. This follows the already merged and tested:
- 17/17 protected update-watch common native audit rollout, 17/17 real
  main/push required Windows CI SUCCESS;
- pg_ivm actual native candidate CI 39769754052 and real audit
  39771145795 artifact 12422372611, 5/5 verified ZIP/SPDX;
- central #221/#222 immutable original Run/Artifact binder;
- central #223 bot PR-to-protected-main squash-merge pure deny-test bridge.

`.github/workflows/automatic-postmerge-audit-readonly.yml` is a
workflow_call entrypoint to a single **genuine main/push** listener that a thin
local caller can adopt later. It uses only GitHub Actions contents/actions/
pull-requests **read** permissions and immutable `job.workflow_sha` central
source. No central App/Secret/publishing privileges.

The new `scripts/automatic-postmerge-audit-live.py`:
1. Refuses any event except GitHub Actions protected main push with the exact
   immutable event SHA and repository.
2. Independently GETs the original *merged bot* candidate PR, changed file
   list, exact current main SHA/branch protection, original native Windows
   required App15368 check-runs, current main's committed manifest Git blob,
   and actual merge commit's GitHub parent/diff.
3. Uses the **pre-merge** SHA from genuine push payload to search the audit
   run history. Refuses incomplete/paginated listing and duplicate matched
   audits. GETs the actual completed historical audit Run and Artifact metadata.
4. Downloads actual original `candidate-audit-native-pr` from GitHub Actions
   by verified ID/Run, requires exactly the two original JSON files, fetches
   the referenced successful original Windows CI Run, and runs the existing
   `bind-native-candidate-audit.py` join. Then binds to the protected squash
   commit with existing `automatic-postmerge-audit-bridge.py`. Source SHA,
   per-PG ZIP/SPDX and all run/commit identities must agree.
5. Emits **only** `MERGED_NATIVE_CANDIDATE_NONPUBLISHING`, retaining
   `signedArtifactsVerified=false`, `publishableReceipt=false` and
   `publicationAuthorized=false`, without creating a release tag or invoking
   the existing signed Publisher.

This PR includes offline full-chain test fixtures, original-run duplication,
foreign PR, changed manifest SHA, forged audit and unsafe path refusal. These
offline fixtures prove rejection logic, not that an actual event has fired.

## Operational acceptance and rollback

This change adds the shared read-only implementation and no live caller.
First add a single thin `on: push` path-filtered `update-watch.yml` pilot
for the **next** future bot candidate merge (not a historical synthetic
event); require App15368 PG14–18 required CI, protected PR, real main/push
postmerge and uploaded genuine read-only witness before 17/17 rollout.
The existing successful pg_ivm 1.17 candidate PR #28 was merged to protected
main 40de60ee743a90b047f6a15b0917a139f4017a23; its main/push CI is
separate from actual witness: this script was not on main at that past push.

The owner authorized future eligible new stable releases without another
per-version human confirmation, but new **typed automatic Publisher
authorization**, genuine Sigstore/SLSA/SPDX attested Release builder validation,
source-decision and effective branch bypass proof, create-only tag checks and
Catalog independent verification are separate incomplete production gates.
Do NOT re-label candidate ZIP audit success as signed release proof; do not
weaken manual-only release policy or PUBLISH guards. This shared step does not
perform GitHub writes, create a new App, Secret or human GUI approval.
