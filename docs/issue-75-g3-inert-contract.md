# Issue #75 G3 — Inert future event / receipt / PACKAGE-INFO boundary

**Contract date:** 2026-10-14 JST  
**Status:** Implementation and offline adversarial CI proposed; **NO production PUBLISH authorization**.  
**Source of truth:** [G0–G5 matrix](issue-75-production-readiness.md), [G2 negative-live evidence](https://github.com/pgextwin/build/issues/75#issuecomment-6161778856).

## Boundaries that remain unchanged

- Central `metadata/release-promotion.json.releasePolicy=manual-dispatch`; pilot `config/release-promotion.json.releasePolicy=manual-dispatch`; 14-entry fleet `metadata/automation-fleet.json.releasePolicy=manual-only`.
- No real `.github/release-authorizations/*.json`, authorizing PR, new `push` publisher trigger, publishable receipt, credential change or write token.
- No GitHub Release, tag, `POST git/refs`, Dispatch, publisher call, Secret/App permission/protection changes, automatic Catalog PR or merge. G4/G5 remain separately unauthorised. Candidate PR #29 is never modified.
- `scripts/chat-pr-g3-inert-contract.py` is a **pure, fixture-only contract**, without CLI, network, issuer or publication path; it is NOT a runtime trust anchor, alternative to G2, or a new Release promotion route.

## Source-to-trust mapping

| Future concept | Existing authority / validator reused | G3 proof vs residual gap |
| --- | --- | --- |
| Authorization text vs actual GitHub event | `chat-pr-authorization.verify_approval` validates exactly one squash authorization file/blob, operator, sender, merged_by, PR provenance, parent and required PR-head CI | Synthetic coherence only; authenticated GitHub identities **do not** attest Chat message content |
| Candidate provenance and PR join | `fleet-promotion-gate.verify` and `chat-pr-authorization.bind_verified_receipt` | Candidate PR/head/run/decision and tag must agree, but `DRY_RUN_CONTEXT_ONLY` is **never** a publishable receipt |
| Final JIT, Classic, tag and Release | `chat-pr-phase-d-prepublish.verify_inert_prepublication_recheck`, `classic-composite-protection` | Two complete **synthetic** independent snapshots, unchanged exact main, effective 8-check protection, absent tag/Release, deny stale/read errors. Actual G2 authenticated negative run remains a **separate** bounded proof; positive future JIT is BLOCKED without real authorization |
| Proposed signed build package tuple | `scripts/finalize-package.ps1` fields, `fleet-publish-release.check_assets` checks | On *synthetic* future `release-attested` PG-major package only, require `workflowRun.id/attempt/event/ref`, `source.packagingRepository/packagingCommit`, `package.name`, PG major and immutable upstream commit/ref/version to match a separate candidate source and future run. G3 **does not verify ZIP, SHA256, SPDX, Grype or signature** |
| Typed publisher boundary | `release-authorization.validate_receipt` matches `chat-pr-authorization` + `VERIFIED_CHAT_PR_AUTHORIZATION` + `push` and requires signed independent artifacts | G3 invokes it solely to assert rejection of the inert `DRY_RUN_CONTEXT_ONLY`, `signedArtifactsVerified=false`, `publishingEnabled=false`, `publishableReceipt=false`. G3 returns `DRY_RUN_G3_DEFAULT_DENY_ONLY`, `mutationsEnabled=false`, `publication=DENY` |
| Atomic reservation, replay and recovery | Existing `fleet-publish-release` flow exercised entirely through `test-chat-pr-phase-d-atomic-replay.py` fakes | Simulated one-winner/HTTP 422 loser, occupied tag replay DENY, draft quarantine, immutable Release-ID mismatch DENY. **No real concurrent GitHub tag race or write acceptance** |

## Negative matrix and pass criteria

G3 CI `tests/test-chat-pr-g3-inert-contract.py` must PASS offline with strict manual policies. It rejects unexpected operator/bot, wrong ref/push SHA, wrong parent or extra commit/PR file, failed/missing PR CI, wrong candidate IDs or receipt mode, broken Classic/TOCTOU proof, absent/failed synthetic snapshots, changed JIT tag/Release, source/PG mismatch, wrong PACKAGE-INFO buildMode/run ID/attempt/event/ref, wrong packaging commit, wrong upstream commit/ref/version, skipped/failed future build run and source matrix mismatch. Existing G0/Phase D fixtures separately cover HTTP 401/403/404/429/5xx, timeout and pagination and the simulated atomic reservation/replay.

**PASS** means the future event/receipt/package trust tuple is internally coherent in fixtures **but nonpublishable by construction**. It **never** means future candidate signatures, actual Chat-PUBLISH provenance or release-to-website integration are proven. A failure or any invocation with real untrusted evidence is **DENY/BLOCKED**, not partial acceptance.

## G3 exit and conditional path toward G4

For G3 acceptance: merge a build-only narrowly scoped protected PR after exact-head `resolver` App ID 15368 SUCCESS; validate postmerge `push` CI and preserve unchanged pilot configuration. Attach SHA, run IDs, tests and negative status to Issue #75. Pilot code modifications are unnecessary for this fixture-only stage.

Before even *proposing* G4, separately review and record: (1) least-privilege GET vs future write-token isolation and protection-App scope, (2) GitHub `GITHUB_TOKEN`-generated push event suppression and genuine user event trust, (3) one-tag create-only serialization plus terminal HTTP 422 handling, (4) immutable Release ID and failed/partial Draft quarantine/recovery, (5) complete signed future candidate PG matrix, (6) fresh explicit named human Chat `PUBLISH`, (7) current protection/CI and two genuine *positive* JIT reads, and (8) a **new explicit capability transition decision**. None are activated or proven here. G4/G5 remain NOT AUTHORIZED, and Issue #75 stays OPEN.
