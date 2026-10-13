# Issue #75 Phase D — nonpublishing just-in-time recheck contract

Status: **OFFLINE / SYNTHETIC ACCEPTANCE ONLY — NOT A PUBLICATION PATH**  
Date: 2026-10-13 JST  
Tracking: https://github.com/pgextwin/build/issues/75

## Established trust prerequisite (real, not synthetic)

The protected `pgextwin/plpgsql_check/main` pilot at
[run 38397010940](https://github.com/pgextwin/plpgsql_check/actions/runs/38397010940)
verified the dedicated Administration:read App, exact one-repository token
scope, two complete same-token main-bound Classic REST + GraphQL protection
snapshots, no PR bypass actors, no push restrictions or allowances, eight
App-bound required checks, strict PR protection, zero external review,
admin enforcement and no force/deletions. The run is nonpublishing with
`publishableReceipt=false`. It does not prove approval of a Release.

## Inert Phase D implementation

`scripts/chat-pr-phase-d-prepublish.py` adds a pure
`verify_inert_prepublication_recheck(reader, *, expected_main_sha, expected_operator)`
coordinator and no GitHub HTTP, token handling, event listener, Workflow
Dispatch, trusted job, Release creation, or tag writing.

**Each of two independent captures** must provide independently authenticated
and validated snapshots; a future main-bound trusted adapter (not included)
must *re-fetch* rather than reuse saved fixture or PR-provided assertions:

1. Current protected main SHA, from a fresh GitHub branch/Ref API read.
2. Independently confirmed **nonexistence** of both Git tag ref and public
   Release tag. `UNKNOWN`, `null`, timeout or failed read is not absent.
3. A **fresh** same-token Classic REST + effective Ref GraphQL composite
   verifier result with its **own two full REST/GraphQL snapshots**, bound
   to current main SHA and the exact eight required App checks. On actual
   publications this must be rechecked at the privileged boundary.
4. A fresh candidate verifier result tied to merged immutable bot candidate,
   exact candidate head and decision/Windows run identities, full maintained
   PG-major/source SHA matrix, latest signed asset/attestation/SBOM/Grype
   evidence. **This module does not perform independent asset verification**.
5. A fresh authorization-PR verifier result from authoritative GitHub push,
   exact squash parent, merged PR, operator, one committed authorization blob
   and its full PR-head required CI. The user **has not requested any real
   PUBLISH authorization**, so these inputs are tested only synthetically.
6. Run `chat-pr-authorization.bind_verified_receipt` for every capture; its
   typed context is **explicitly rejected** as a publisher receipt.

A complete capture with unknown keys, mismatched operator, stale main,
occupied tag, candidate/authorization mismatch or unverifiable Classic
policy is denied. The **raw verified snapshot dictionaries** and inert
join must be exactly unchanged on the second capture; otherwise deny.

The only success status is `DRY_RUN_PHASE_D_RECHECK_ONLY`, always
`publishingEnabled=false`, `publishableReceipt=false` and
`signedArtifactsVerified=false`. This is **not** a signed-artifact proof.
The negative fixtures run in build's protected `resolver` CI.

## What remains blocked

- No runtime adapter currently fetches and independently validates all Phase
  D approval and candidate evidence in a single trusted job. A fabricated
  synthetic candidate or self-asserted callback is not a trusted proof.
- No new Chat-PR publishing trigger, publisher receipt, or real
  `.github/release-authorizations/*.json` is created. Existing central and
  local `manual-dispatch` opt-in settings are unchanged.
- Signed Windows ZIP/attestation/PACKAGE-INFO identities still need a genuine
  same-trusted-job independent byte/signature verification before publishing.
- A two-round read is not a transaction lock: before a future write operation,
  confirm main and tag state again and reserve the tag **atomically,
  create-only**, with concurrency/replay denial and no tag overwrite.
- Separate genuine user PUBLISH intent and a future eligible candidate are
  mandatory for any production acceptance. Do not turn this synthetic result
  into `VERIFIED_CHAT_PR_AUTHORIZATION`.

## Rollback and audit

No production paths were modified. To revert only this inert preparation,
revert the isolated script, test, CI step and document via protected PR.
Existing `workflow_dispatch` manual Release remains the sole live route.
Do not modify GitHub App privileges or main protection.

Evidence to retain: the build PR head SHA, `resolver` exact-head and
postmerge CI, and Issue #75 links. Issue #75 must remain OPEN.
