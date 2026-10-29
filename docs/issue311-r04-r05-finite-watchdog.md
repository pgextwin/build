# Issue #311 — R04/R05 finite request lifecycle and event-loss boundary

This is an incremental **nonpublishing** component. It does not satisfy full R04/R05 acceptance by itself.

## Decision

A genuine `workflow_run.completed` listener (existing R05 proof) verifies the original Windows source Run and ZIP bytes. A future, *independently push-triggered, bounded* watcher must be launched by the same protected one-shot request. It is not a `workflow_run` descendant and must not depend on delivery of the event being watched. It polls narrowly for the exact original Run and completion bridge, within the request's max wall-clock budget, using GET-only GitHub REST.

On receipt of a verified completion: commit `NO_UPDATE`/failure with the original run/attempt/ZIP digest. If delivery is absent when the finite deadline arrives: after bounded, exhaustive REST listing, record `FAILED` for independently proven missing delivery; when source completion/search cannot be proven, `QUARANTINED`. A delivered-but-malformed event must never be mistaken for missing. Late delivery/replay must not reopen a terminal state.

The pure `issue311-request-lifecycle.py` defines these transitions, operation budget, exact duplicate idempotence, and a publication-denying state. **No argument to this pure module is authenticated**: only an independently audited trusted coordinator with the approved dedicated build-only App may bind run identities, validate source receipts, or persist a transition via original Git Contents CAS in `issue311-state`. Never use Publisher/Catalog credentials or `GITHUB_TOKEN` to write this state.

### Failure ceiling

No design can guarantee terminal delivery when **both** event transport and the separately spawned watcher are never scheduled, or GitHub and the state writer remain unavailable past all runner lifetimes. Preserve immutable protected request + last known checkpoint for explicit safe recovery; do not report a guaranteed unattended terminal in that situation. The watcher must not busy-loop forever, create cron, or retry uncertain write APIs.

### Acceptance still needed

1. Implement exact-request push-triggered watcher and actor/PR/merge trust validation.
2. Use App 5517840, build-only installation 176347451 and approved `issue311-state-writer` environment, without expanding permissions; persist request/target/budget state with CAS.
3. Independently verify genuine original Run and any bridge Run; a running/failed/absent source, API pagination, 429 or 5xx must fail closed.
4. Protected PR, latest-head required `resolver`, postmerge and original real read-only no-delivery terminal proof. Injected missing-listener tests are not evidence of actual lost GitHub events.
5. R04/R05 remain PARTIAL until these live checks and generalized flow are accepted.
