# Issue #75 → Issue #311 v2.1 publication/operation crosswalk (R12-01 candidate)

**Nonpublishing operations document; not a publication authorization.** Owner: [build #311](https://github.com/pgextwin/build/issues/311) canonical immutable 94-branch ledger and v2.1 acceptance. Parent: [build #75](https://github.com/pgextwin/build/issues/75). Date: 2026-10-31 JST. Initial snapshot: **83/94 PASS, 11 pending**, both Issues OPEN. Acceptance of this documentation requires the *latest-head mandatory CI + protected merge + original postmerge*, not merely committing this file. Parent R12 remains PENDING while R09/R10/R11 dependencies or actual public gate are unaccepted.

## Differences that must not be collapsed

1. **Initial request versus Release authority.** A single authenticated Chat instruction may create a narrowly scoped immutable `AUDIT_ONLY` or `PREPARE` request PR. The exact-head protected main push authenticates a finite operation **only**. It is not per-release PUBLISH approval. `PUBLISH_ELIGIBLE` is only a declaration of possible candidacy; the independent existing authorization and Publisher checks remain mandatory.
2. **Windows build / signature versus delivery.** PG14–18 Windows jobs, SPDX/Grype, actual byte SHA256 and independent OIDC/Sigstore audits establish provenance/quality within their scope. They do not cause a Release/tag/asset write and cannot satisfy the future new-stable E2E in R09-02.
3. **Nonpublishing Catalog/CLI/Website versus production.** R09-01 is accepted for nonpublishing native Catalog/CLI/feed/EN+JA same-source-key binding. It preserves a Catalog public-feed guard (NOOP on no public-record change). Website draft #45 is a real PR-only HTTP loopback test, **not** public deployment. Neither means real Release, public catalog/feed update or live EN/JA delivery.
4. **Checkpoint terminal versus approval.** 17 statuses, a CAS revision and keyless independent readback may close a bounded PREPARE request. Success/NO_UPDATE does not imply `publisherAuthorized=true`. Ambiguous public write requires explicit UNKNOWN/QUARANTINED handling; never blind retry.
5. **Prior historical schedule versus the new request.** Preserve old proofs, but never relabel `schedule`/legacy source-kind as new App-signed `PREPARE`. Do not remove schedule dependencies until each migrated alternative has proven authentic success and failure paths. No new cron or recurring ChatGPT tasks.

## Old #75 X/A/D/E/F → new contract evidence and remaining gates

The table is a **migration correspondence**, not an assertion that each historic branch was ever conclusively accepted. The literal original #75 request and its own unchanged public approval constraints still control any release.

| #75 historical part | New #311 contract | Evidence at 2026-10-31 | Remaining before equivalent public end-to-end |
| --- | --- | --- | --- |
| X / X01–X02: existing finite protected-merge, cross-repo source and operator handoff | R01–R06, R07 (17/17) | New v2.1 A–D [audit #6521649490](https://github.com/pgextwin/build/issues/311#issuecomment-6521649490); protected request→main→central→17 App child original/ZIP actual SHA→CAS revision2→independent keyless GET. Legacy X01/X02 remain historical, not substituted as new provenance | No stale source-kind or success rerun; no publication authority flows from X |
| A: read-only inventory, threat model and protected source selection | R01/R02/R03 and R04 immutable request+state/lease | #311 v2.1 and `docs/adr-0311-event-driven-request-v1.md`; source main and original Git blobs verified | Guarded read-only checks must continue at every future privileged action; no weakened ruleset |
| B/C: authenticated Chat intent, explicit per-release gate, single extension pilot | R03/R04, R07-01, R08-02 | 17-App genuine nonpublishing pilot, exact actor and `PUBLISH_DENY`; isolated genuine Publisher App JWT [41080706172](https://github.com/pgextwin/build/actions/runs/41080706172), **no write token** | Future eligible stable and explicit individual Release authorization, original latest-head CI and exact target/tag/candidate binding are still necessary |
| D: Catalog reconciliation and verified one-record update | R09-01 (private) → R09-02 (future public) | Catalog guard PR#180, native shadow PR#179, original feed NOOP [41136175877](https://github.com/pgextwin/catalog/actions/runs/41136175877); proof [#6534563345](https://github.com/pgextwin/build/issues/311#issuecomment-6534563345) | After a **real authorized** Release, re-GET actual release bytes, signatures and provenance, create protected one-record Catalog update and validate public CLI/feed |
| E: extension fleet rollout and operating migration | R07-01/02/03, R10-01/02, R11-01/02 | New R07 17/17 signed/receipt originals accepted; R10 evidence inventory in `docs/issue311-r10-v21-negative-recovery-audit-20261031.md` | R10 durable negative-case report and resumption, then remove migrated schedule dependencies by protected PR. No early cron deletion |
| F: actual formal-release → Catalog → EN/JA E2E acceptance | R08-01/02 + R09-02/parent R09 + R12-02/parent R12 | [R08-01 actual Sigstore acceptance #6525877146](https://github.com/pgextwin/build/issues/311#issuecomment-6525877146), [R08-02 actual Publisher identity deny #6526531530](https://github.com/pgextwin/build/issues/311#issuecomment-6526531530), private R09-01 accepted; Website draft PR#45 only | **PENDING:** newly eligible future stable, explicit approved Release, live Publisher, real public Release bytes, SHA256/Sigstore/Attestation, Catalog/CLI/feed, public EN/JA GET. Never manufacture a test Release |

This matrix preserves the old contract where it is **stricter**, notably the explicit per-candidate publication decision and fail-closed protections. It does **not** loosen #75 due to newer 17-target nonpublic acceptance. Historical 14-repo facts in #75 are not the present 17-target allowlist.

## One-request operator procedure (currently safe and usable in NONPUBLISHING mode)

**Inputs:** exact 17 approved repository names (or explicitly authorized subset), fixed protected-main SHAs fetched afresh, intended purpose, `AUDIT_ONLY` or `PREPARE`, finite expiry, and the instruction `No public Release/Catalog/feed/Website write`. A public-release request is a separate formal event and requires existing per-release authorization.

1. The authenticated GitHub connection GETs #311 and protected current main; freezes target allowlist, time limit and source. Create only a new strict-schema request JSON on a feature branch. Never reuse a previous request ID with different bytes, a successful Run or an old HEAD.
2. Open **one protected PR** for the request, verify latest HEAD required CI, then merge with expected-head enforcement. If stale, reconcile the branch and rerun **new HEAD** checks, not old successful runs.
3. Real protected-main push starts the genuine central PREPARE. Its immutable workflow_run boundary starts the authorized per-repository App dispatch, 17 true child Run/attempt/ZIP SHA256 receipts, then the separate State App CAS. Independent runner without App key GETs the exact checkpoint. A separate finite watchdog terminates missing/failed events; no Chat follow-up, manual rerun or cron is part of a successful request.
4. For each target, record the fixed source/head, run and attempt, original artifact ZIP **actual byte** SHA256, admissible status, cause, CAS blob/revision and safe restart point. `NO_UPDATE` is not a fresh version. Source failure/skip/timeout/verification mismatch is `FAILED` or `QUARANTINED`, not a substituted success.
5. If GitHub/State CAS returns HTTP409, compare exact original; do not blindly repeat PUT. If State PUT acknowledgment disappears, one exact original GET may reconcile; otherwise mark unknown/quarantine. An ambiguous **Release POST** must not be retried on a guessed status.
6. Recovery after infrastructure outage: GET the immutable request and prior CAS blob, validate actor/scope/source/head/expiry/attempt, verify receipts from origin and last accepted checkpoint. Resume only failed or pending permitted work within the original approved scope; never revive an expired request or repeat a completed publish write.
7. Report terminal per-repo table and withheld actions to #311 and summary to #75. Keep #311/#75 OPEN and preserve `runtimeEnabled=false`/`PUBLISH_DENY` until independent full-publication gates are fulfilled.

**Current limitation:** Step 4's per-target detailed reason/ZIP/restart-point is not yet entirely stored within the v1 JSON checkpoint. A reader must join immutable original receipt evidence, and R10-02 is pending an authenticated durable enriched report + keyless independent verification. This document is **not** that report.

## Denial and permanent stop triggers

- Source actor/App/ref/workflow, target allowlist, protected commit, request bytes, signed source certificate, PG matrix, SPDX/Grype, expiration, run attempt or original artifact differs → **DENY / QUARANTINED** with preserved prior evidence.
- No formal release authorization or new eligible stable → `PUBLISH_DENY`, no Publisher token, no tag, no POST, no Catalog public record, no Website deployment.
- Conflicting writers, uncertain GitHub write outcome, expired authorization, inaccessible protected source → no blind write retry or fake success; preserve immutable record, independent GET/reconciliation and explicit human-gated recovery only if necessary.
- Do **not** remove workflows' push/PR CI triggers while removing obsolete schedules. Keep #75 old publication gates as mandatory until actual authorized E2E supersedes them.

## Tracking and closure conditions

- R12-01 can be assessed independently after this crosswalk is **protected-merged** and its original postmerge CI is verified; update #311's R12-01 checkbox only with direct PR/Run/HEAD/merge evidence.
- R12-02 additionally requires evidence-backed one-Chat→17 original nonpublic terminal procedure, a complete operator-facing report and bounded restart semantics.
- Parent R12 requires R12-01+R12-02 and dependency gates R07–R11. R09-02 must remain pending until a future real authorized publication cycle. Parent #75 remains open until old formal public F acceptance is genuinely established.
