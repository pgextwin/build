# ADR-0311: One authenticated, bounded Chat request to a terminal state (version 1)

Status: ACCEPTED AS A NONPUBLISHING CONTRACT DESIGN ONLY. Runtime admission, state writer, cross-repository dispatch and formal publication remain disabled until their independent R04–R10 acceptance gates. This document does not amend existing publishing policies or authorize new credentials.

Issue: pgextwin/build #311, superseding the withdrawn M/T/recurring-task and extra-cron proposals. Parent #75. Snapshot date: 2026-10-29 JST.

## Decision and scope

A human provides one Chat instruction specifying a finite set of extension repositories, the purpose, request mode and permitted action scope. The authenticated Chat GitHub connection creates an immutable request file in a dedicated pull request. After the exact-head required CI and a protected merge, the real main push is an **entry signal only**, not publication authorization. The trusted current-main coordinator checks original GitHub PR/merge/commit/actor evidence and then moves the same request through bounded stages, preserves durable checkpoints and produces a terminal result. No recurring ChatGPT task, GitHub cron, external cron or always-on server belongs to this architecture.

The request is a snapshot: no indefinite polling for future stable versions. Every target and its permitted current-main SHA are frozen for this request; a different snapshot or future candidate requires a new, expressly scoped request. Successful existing work is reused by immutable digest; modifying an input invalidates the dependent step rather than silently rerunning a successful unrelated step.

Modes:
- AUDIT_ONLY: GET, data verification, limited CI tests and nonpublishing receipts; never credentialed writer.
- PREPARE: candidate/preflight/unsigned or OIDC signed build stages only as separately gated. No formal Release or Catalog write.
- PUBLISH_ELIGIBLE: a **declaration of possible eligibility**, with concrete per-target candidate PR/CI/release tags. Its own JSON is NOT a release approval proof. Privileged Publisher still must independently obtain original user-approved protected-merge evidence and pass all existing live release gates; a generic request push alone is not sufficient. This migration currently authorizes neither live release nor a PUBLISH_ELIGIBLE run.

## V1 declaration and canonical binding

The JSON Schema is schema/issue311-execution-request-v1.schema.json. It is deliberately strict, has additionalProperties=false at all trust-bearing object levels, and only permits the exact 17 pgextwin extension names. No arbitrary repository, ref, command, Action, workflow name, callback URL, source kind, actor or App selection is supplied by the requester. Fields are:

- schemaVersion=1 and kind=pgextwin-execution-request.
- requestId in the r-YYYYMMDD-... namespace; reusing an ID with different bytes is DENY. The coordinator computes a byte-level SHA256, independently binds it to the committed Git blob and verifies that the PR changed exactly the one allowed path.
- requestedBy is a display claim only, never an authenticated identity.
- mode and purpose; allowFutureUpdates must be false.
- createdAt and expiresAt in RFC3339. The trusted admission verifier checks both dates, a maximum 24-hour initial lifetime, clock skew, that expiry follows creation, and that the same request cannot be revived silently after expiry.
- source.centralMainSha (immutable trusted build coordinator baseline) and source.fleetRegistryBlobSha (exact registered 17-target source list). The coordinator's own trusted workflow SHA, signed provenance and current policy SHA are independently obtained from the GitHub API/event, not from user JSON.
- targets: 1–17 entries of exact allowlisted repository + 40-character lowercase mainSha, no duplicate repositories. Each target's protected main SHA must match the independent live GET at admission; drift is a reasoned stop or explicit new authorization, not a silent scope enlargement.
- limits: bounded parallelism, attempts per stage, operation count and wall clock. Real jobs additionally enforce GitHub maximum job/runtime/cost bounds and may stop earlier.
- approval.scopeText and publicReleaseAuthorized. For AUDIT_ONLY/PREPARE the latter is false and publicationGrants is empty. For PUBLISH_ELIGIBLE a specific releaseTag, exact packaging SHA, candidate SHA and original run IDs must be declared for each grant, but no grant can bypass the existing independent Release authorization and evidence verifier.
- resumeFrom may point to a prior terminal request. A continuation file MUST be separately authenticated and linked to the prior original bytes, unchanged targets/approval and checkpoint source; a string alone never releases locks or opens a Publisher retry.

JSON Schema validates only shape. Its success is neither authenticated GitHub provenance nor sufficient runtime authorization. Runtime admission MUST reject duplicate JSON keys, Unicode/canonical ambiguities, extra members, logically inconsistent date/target/grant combinations and oversized requests. Unknown schema versions fail closed. Store both canonical SHA256 and committed **raw** byte SHA256, with a documented canonical serializer and stable Git blob identity. Reject normalization collisions, mismatched file path/requestId, missing original byte proof or inaccessible GitHub evidence.

## Entry provenance (not a privileged Issue-comment command)

A production request PR must modify exactly .github/execution-requests/<requestId>.json, status added, nothing else. R02 was an isolated nonpublishing bootstrapping canary where workflow and fixture were introduced together; it is NOT a reusable authorization mode. Only code and schema already merged to protected main are executed; never check out or execute script content from the untrusted request PR.

Admit only after independent GitHub REST reads confirm:
1. branch main is protected and its effective required CI rule is verified (UNKNOWN => DENY privilege; the connected plugin currently returns HTTP 403 for administrator protection details);
2. original PR author, human/authorized operator, merged_by, commit parents, exact PR files and immutable blob SHA; a nonbot textual login alone is not sufficient, and the actual event sender/actor must satisfy the existing approved identity policy;
3. exact PR HEAD has all actual applicable required checks from the expected GitHub App, not just a self-reported green badge. The observed build validation App id is 15368, check name resolver; do not hardcode this as a universal 17-repo authorization;
4. the original protected main push event matches the merge SHA, repository, target ref, before/after, changed request file and the same approved actor; no synthetic schedule or workflow_run substitution;
5. one requestId + committed blob + actor + mode + target snapshot is atomically admitted once. A duplicate event with identical bytes is idempotent, a conflicting body is DENY.

The first real R02 proof: PR #312 at head 030bdb81b3e811bb6902e22db09ebfa318a2ad12 passed original App15368 resolver Run40717715045 and merged by ShutenOishi at d9a09ae962b077c4142599daebc6b57746bccf27. Actual push Run40717966364 attempt1 showed actor/sender/triggeringActor ShutenOishi and correct request-byte SHA256, but the job failed because upload-artifact skips dot-prefixed files. This failure is retained; no rerun/waiver. Recovery PR #313 head 96fee41c05b2d8246395b6799b5c8aad0e966f4c passed its own required CI; protected merge 24085fa17eb9e14be5ccb8f66b5c61039e8f54ae triggered successful genuine push Run40718397824 attempt1. Original artifact 12829007351 is 559 bytes, and independent downloaded outer ZIP SHA256 4452a10173d9769955bcfebc7c06d6ebde3dde65479685fd2af32346b7a9d1d1 equals GitHub metadata. Inside original receipt, actor/sender/pusher/triggeringActor=ShutenOishi, event=push, requestId=issue311-r02-20261029-02, request SHA256=a14ae8fddb2b7f21bb1ae3b73e8757f07f861f3675350c7676f842dc92f6f84a, head=24085fa17eb9e14be5ccb8f66b5c61039e8f54ae, before=d9a09ae962b077c4142599daebc6b57746bccf27, publishAuthorized=false. Postmerge validation Run40718397814 succeeded. This proves the connector's merged main push can trigger a Workflow; it does not prove cross-repo dispatch, two-stage continuation, Publisher grant or durability.

## Separate provenance axes

Never conflate:
- entryOrigin: original protected Chat-authored request PR -> human-authenticated merge -> main push;
- executionOrigin: specific workflow file/immutable SHA, runId, runAttempt, genuine GitHub event, actor/App and token capability;
- inputOrigin: original central scan ZIP, actual-byte digest, exact scan event, run/attempt and registry;
- buildOrigin: exact local Windows candidate run, maintained PG14–18 row coverage, package bytes, original signer's OIDC certificate identity and Sigstore;
- admissionOrigin: independent raw-byte verifier and two independent signing auditors;
- publicationOrigin: narrow create-only Publisher App authorization and actual new tag/Release;
- downstreamOrigin: independently verified public Release -> catalog proposal PR -> exact-head protected merge -> CLI/feed -> EN/JA Website smoke.

Existing original-schedule sourceKind is historical and is NOT automatically converted by an event-name OR condition. A new distinct authenticated request-origin type must be enforced in each phase's live policy and adversarial tests. A replayed GET-only observation, inherited 13/17 old receipts, successful no-candidate job or metadata-only hash is not a new original ZIP receipt.

## Durable state and exactly-once side-effect boundaries (R04 design, NOT YET IMPLEMENTED)

Proposed state key: requestId + approved immutable request byte digest. Per-target step key: request digest + repository + main SHA + candidate identity + stage + immutable workflow SHA. Persist stage inputs, SHA256, run/attempt, artifact ID, original ZIP hash, results, lease owner/expiry, retry count, terminal reason and resume pointer.

States: RECEIVED -> AUTHENTICATED -> SNAPSHOTTED -> SCANNED -> TARGET_PREPARED -> SIGNED_AUDITED -> PUBLICATION_ELIGIBILITY_CHECKED -> DOWNSTREAM_CHECKED -> TERMINAL. Each target terminal SUCCESS, NO_UPDATE, FAILED, BLOCKED_APPROVAL or QUARANTINED; an aggregate terminal report lists every outcome and never upgrades partial failure to success.

Require an independently authorized durable compare-and-swap state writer and optimistic version/lease for request and per-release identity. GitHub Issue text, mutable artifact name, untrusted PR file and a GitHub Actions concurrency group are NOT sufficient CAS roots. An immutable original artifact is excellent evidence but not a mutable conflict-free state ledger. Resolve whether the existing approved scoped credential can write to a protected state ref without privilege escalation before implementation; if not, mark R04 BLOCKED_APPROVAL with the exact minimum required permission and security design. Do not repurpose the isolated Publisher credential. A lease timeout never authorizes repeating a write with unknown outcome.

Per-stage successful evidence must be reused; fresh-run attempt identifiers stay separate from verified original evidence. Read-only retries have capped attempts and backoff. Credentialed PR/Release/tag writes first reconcile GitHub's actual committed state by deterministic idempotency key. Ambiguous write/HTTP timeout -> QUARANTINED and explicit recoverable checkpoint, never blind retry. Formal publication remains create-only and no overwrite.

## Coordinator (R05 design, NOT YET IMPLEMENTED)

Prefer a trusted main-side bounded workflow containing needs dependencies and pinned workflow_call, with aggregation jobs that use always() and record child failure/skip. Use no assumed arbitrary-length workflow_run chain: GitHub has a documented multi-level continuation restriction, and new events produced with GITHUB_TOKEN can be suppressed. The genuinely observed connector-merge push is the **first** event only. Every later cross-repository trigger must be independently tested under the permitted App actor and permissions before relying on it. Do not borrow Publisher or Catalog App for this purpose without authorization.

A successful all-target continuation must demonstrate two or more genuine nonpublishing stages and final original aggregate receipt after just the initial request. Accept bounded 429/5xx retry and clear terminal handling for missing events/queue timeouts; if the event transport can permanently lose work, a self-contained queued workflow or another already-authorized durable event is required. No hidden cron, periodic Chat invocation, external scheduler or indefinite long-running polling. If these guarantees cannot be met under existing permissions, terminate with BLOCKED_APPROVAL and a precise resume point; do not assert a working coordinator.

## Publication and downstream gates

Publisher remains denied until all **new** R07 17/17 original receipts and the corresponding R08 identity and double-independent Sigstore audits are accepted. A valid request does not bypass local source/License/export eligibility, each maintained PG major, Windows executable tests, SPDX, Grype, SHA256, OIDC, signed main provenance, replay denial, exact protected main, token isolation/revocation (same live token must return 401), create-only release and original-public-asset verification. No existing tag/Release may be reissued. When every existing gate and the concrete per-release approval are satisfied, R08 may authorize one new Release and R09 may separately start verified Catalog proposal; Catalog scoped App must never be used as a general build Coordinator token.

Website/CLI/feed real E2E must use the same public authenticated Release. R02 test ZIP and legacy HypoPG bytes are not substitute new-release acceptance. #112 independently owns the offline bundle/online-offline CLI trust/bootstrap work and its scheduled audit; avoid modifying or claiming acceptance on #112's behalf. R11 may remove cron only after the replacement is accepted for each affected actor/repo; maintain existing PR/push CI and rollback until then.

## Required negative proofs and stop conditions

R03 schema tests: missing/extra keys, bool-as-int, duplicate repo/grant, unknown actor/App metadata rejected at runtime, bad SHA/ref, expired/oversized grant, unauthorized PUBLISH_ELIGIBLE, request-id/path mismatch, impersonated author/merge, replay and different bytes same ID. R04/R05 tests: duplicate concurrent events, competing requests for same tag, crashed coordinator before/after write, failed/skip child, unavailable token, workflow_run depth, GITHUB_TOKEN event suppression, queue expiry, 429/5xx with finite retry, absent event, external state CAS conflict and unclear Publisher POST. R06–R10 tests: forged scan/local/signing ZIP, partial PG coverage, altered SBOM, wrong OIDC issuer/workflow SHA, failed independent audit, stale snapshot, token reuse and Catalog/Website negative tests.

Stop and record requestId, reason, terminal state, last immutable receipt, writer uncertainty, required permission/action and exact resume point when independently authenticated evidence cannot be obtained. An actual GitHub infrastructure outage can temporarily prevent final notification; preserve recoverable evidence without claiming a guaranteed notification.

## Implementation order and authorization

R01 authenticated inventory and R02 one-step nonpublishing proof completed. R03 records the proposed strictly versioned contract and schema only. R04 durability/CAS needs an explicit trust/permission decision, then R05 event continuation, R06 new scan/local preflight, R07 pilot orafce then remaining 16, R08 independent signer/publisher, R09 Catalog/feed/Website, R10 negative/recovery, R11 cron phase-out, R12 #75 contract replacement. Current code has NO enabled production request handler, no upgraded actor/App privileges and no live release intent; PUBLISH_DENY is maintained.
