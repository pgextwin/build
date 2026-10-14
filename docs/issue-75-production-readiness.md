# Issue #75 — Production readiness and acceptance matrix (G0–G5)

**Version:** 1.0 (2026-10-14 JST)  
**Status:** G0 **ACCEPTED IN LIMITED SCOPE**; G1 **documentation-only gate**; G2–G5 **NOT ACCEPTED / no production enablement**.  
**Tracker:** [build Issue #75](https://github.com/pgextwin/build/issues/75); authoritative [G0–G5 decision](https://github.com/pgextwin/build/issues/75#issuecomment-6160549857).  
**Related:** [ADR-0075](adr-0075-chat-authorized-publication.md), [Classic auditor contract](issue-75-classic-protection-audit-app.md), [chat-first policy](chat-first-publication.md), [Issue #61](https://github.com/pgextwin/build/issues/61).

This is a **versioned implementation / test / evidence contract**, not a publication instruction. The G0 proofs are deliberately not rerun. A passing documentation PR, an offline test or a historical signed Release **does not** create or authorize a new publishable receipt. Do not treat a future G2 or G3 acceptance as permission to move to G4. Separately approve any capability-changing step.

## 1. Immutable baseline and present policy

Baseline reconciled on 2026-10-14 JST (recheck current GitHub refs when applying a *future* gate):

| Item | Observed state / auditable evidence |
| --- | --- |
| `pgextwin/build` protected main | `765852d7dd9575abe8b002e785e70d6118175615` after [PR #91](https://github.com/pgextwin/build/pull/91); main required context `resolver`, GitHub Actions App ID `15368` |
| Phase D PR exact head | `0618c7b805fafebe3ae320e0a6007f057d409d37`; [PR run #38508401081](https://github.com/pgextwin/build/actions/runs/38508401081) `pull_request`, required resolver **SUCCESS** |
| Phase D postmerge | [main run #38508471848](https://github.com/pgextwin/build/actions/runs/38508471848) `push`, **SUCCESS**; six hostile/offline tests added in #91 |
| Phase D sign-off | [Issue comment #6160501342](https://github.com/pgextwin/build/issues/75#issuecomment-6160501342): **PASS_OFFLINE_SIMULATION_ONLY**, `publishableReceipt=false` |
| Genuine nonpublishing actor/event | [plpgsql_check PR #27 evidence](https://github.com/pgextwin/build/issues/75#issuecomment-6159994062); real protected merge / event / Windows CI; **not** a real publication |
| Historical public signed asset bytes | [PR #90](https://github.com/pgextwin/build/pull/90), [byte-level evidence](https://github.com/pgextwin/build/issues/75#issuecomment-6160343683): already public `plpgsql_check v2.10.14-windows.1`, PG14–18 ZIP/SHA/PACKAGE-INFO, SPDX/Grype and SLSA/SPDX attestations. Historical promotion run #38128142145 ended **FAILURE**; do not report that entire run as successful |
| Unmerged future candidate | [plpgsql_check PR #29](https://github.com/pgextwin/plpgsql_check/pull/29): **OPEN/DRAFT** at reconciliation; ordinary `windows.yml` candidate run is not a signed publisher authorization |
| Central and local modes | `build/metadata/release-promotion.json.releasePolicy=manual-dispatch`; `plpgsql_check/config/release-promotion.json.releasePolicy=manual-dispatch`; `build/metadata/automation-fleet.json.releasePolicy=manual-only` (14 BUILD entries). Maintain these exact values throughout G1–G3 |
| Catalog daily audit | `catalog/.github/workflows/catalog-drift-readonly.yml`, cron `30 0 * * *` (09:30 JST), read-only; first **actual** `schedule` run on 2026-10-14 **NOT ACCEPTED**; see independent track below |

**Scope restrictions:** G1 must touch documentation only. No Release, tag or `git/refs` write, Dispatch, real `.github/release-authorizations/*.json`, live PUBLISH PR, write-capable publication trigger, publishable receipt, policy switch, PR automerge, Secret, GitHub App permissions, or branch protection changes. Issue #75 remains OPEN. The historic Classic auditor design document has some older “credentials not created” status language; defer to newer Issue #75 acceptance evidence for achieved pilot proof, but **always** require fresh, authenticated runtime evidence in a future trusted job.

## 2. Status vocabulary and dependency order

- **PASS (bounded):** the named evidence and exact trust boundary only. `PASS_OFFLINE_SIMULATION_ONLY` does **not** imply live GitHub tag atomicity or future candidate signature verification.
- **DENY:** a negative condition or missing/ambiguous evidence; fail closed, do not generate any publication receipt or privileged write.
- **BLOCKED / NOT ACCEPTED:** prerequisites are not independently proven; prohibition on enabling publication remains.
- **SKIPPED:** a CI job not required in that event; never relabel it SUCCESS.

| Gate | Prerequisite | Current acceptance | Permitted immediate successor |
| --- | --- | --- | --- |
| **G0** Immutable nonpublishing baseline | Existing #61/Phase C/D findings | **ACCEPTED — bounded proofs only** | G1 documentation; no live enablement |
| **G1** Versioned trust/acceptance contract | G0 and latest Issue/main recheck | **Document review / protected docs PR** | G2 only after exact-head resolver and postmerge main CI |
| **G2** Real GET-only JIT negative audit | G1 accepted and isolated trusted-read setup | **NOT ACCEPTED** | G3 inert integration after two genuine snapshots/negative DENY |
| **G3** Future mode/receipt contract, default DENY | G2 acceptance, no policy or trigger switch | **NOT ACCEPTED** | Separate explicit transition decision before any G4 work |
| **G4** Controlled live PR authorization acceptance | G3 + independently authorized production transition + eligible future candidate | **NOT AUTHORIZED / NOT ACCEPTED** | G5 only after event, identity, signing and atomic reservation proofs |
| **G5** Actual future Release → Catalog → Website | G4 independent acceptance + separately approved fresh explicit PUBLISH | **NOT AUTHORIZED / NOT ACCEPTED** | Extension-by-extension opt-in only after proven E2E |

The **Catalog scheduled-audit checkpoint is parallel** to G1–G3 and blocks any 14-extension daily rollout, regardless of G0–G3 status. Do not silently equate a `push` audit run with `event=schedule`.

## 3. Detailed gate contracts

### G0 — Preserve proven, nonpublishing baseline (accepted; DO NOT repeat)

| Field | Contract |
| --- | --- |
| Repositories / verifier | `build` (shared gate and tests), `plpgsql_check` (protected real actor/event and signed historical bytes), `catalog` (separate read-only schedule track); GitHub Actions, Chat GitHub connector, independent read-only audit |
| GitHub events | Actual PR #27 `pull_request` / postmerge `push`; build #90/#91 PR `pull_request` and postmerge `push`; separately historical `workflow_dispatch`-origin signed assets |
| Authentication / permissions | Human connector PR/merge provenance; Classic `Administration:read`/Metadata read-only App and effective REST+GraphQL evidence; signed attestation verification. No publisher write identity inferred |
| SHA / required CI | Exact PR #91 head `0618c7...`, build main `765852...`; build `resolver` app 15368 SUCCESS; pilot `plpgsql_check` protected eight-context baseline (listed in section 5). Real original signed assets' SHA256 checked independently |
| Method / PASS | Preserve #27 actor/event/negative denial proof, #90 already-published byte/SLSA/SPDX signature proof and #91 synthetic one-file approval/JIT/atomic 422/replay/partial-Draft hostile fixtures. **PASS only within each named proof's scope** |
| DENY / not accepted | Bot/unproven identity, wrong head, direct push, missing Classic, stale JIT, tag taken, replay, wrong ID/timeouts. **Never** infer new live PUBLISH intent, live concurrent `POST git/refs` behavior, fresh candidate attestation or a new Release from the G0 results |
| Evidence gap / exit | All future live write/receipt/E2E acceptance absent. Gate exits to G1 only; no additional G0 implementation requested |

Source mapping: `scripts/chat-pr-authorization.py` (`verify_approval`, `bind_verified_receipt`), `scripts/chat-pr-phase-d-github-readonly.py` (`PhaseDGitHubAdapter`), `scripts/chat-pr-phase-d-prepublish.py` (`verify_inert_prepublication_recheck`), `scripts/classic-protection-audit.py`, `scripts/fleet-publish-release.py`; `tests/test-chat-pr-phase-d-atomic-replay.py`; historical fixed-byte verifier `scripts/verify-public-signed-release-readonly.py`. [PR #90](https://github.com/pgextwin/build/pull/90) and [PR #91](https://github.com/pgextwin/build/pull/91) are completed work, not templates for reexecution.

### G1 — This document, implementation-to-evidence traceability (safe now)

| Field | Contract |
| --- | --- |
| Repositories / verifier | `pgextwin/build` **only**; Chat-connected writer and GitHub Actions `resolver` |
| GitHub event | Ordinary **documentation-only** PR `pull_request` and protected `main` `push` after squash; absolutely no authorization pathname or publishing event |
| Authentication / permissions | Current GitHub connector acting as an authenticated contributor; ordinary protected PR+CI, no publisher/App credential |
| SHA / required CI | Branch created from freshly verified build `main`, one document path `docs/issue-75-production-readiness.md`; exact PR head `resolver` SUCCESS from app 15368, expected-head squash; postmerge main run `push` and resolver SUCCESS at resulting main SHA |
| Method / PASS | Each gate documents target repo, trusted verifier, event, principal, fixed SHA/required checks, positive/negative method, evidence not yet obtained and promotion dependencies; PR diff is documentation only |
| DENY | Any change to executable code/policy/triggers/receipts, unresolved CI, wrong head, protection regression or missing postmerge verification → do not declare G1 merged/complete |
| Evidence gap / exit | After protected merge and postmerge CI attach PR/head/main/run/Issue comment. Then G2 is **eligible for planning**, not automatically accepted or enabled |

### G2 — Production-shaped authenticated read-only JIT NEGATIVE audit (future, no authorization)

| Field | Contract |
| --- | --- |
| Repositories / verifier | Trusted protected-main `plpgsql_check` pilot, shared `build` immutable code; separate narrowly installed Classic auditor App; future isolated verifier, not a PR-provided script |
| GitHub event | Audited nonpublishing trusted-main evidence run only; **not** `push`-to-publish, `workflow_dispatch` promotion, or `release-authorizations` file. A real authorization must be absent |
| Authentication / permissions | GET-only evidence token (`contents:read`, `attestations:read`) and distinct `pgextwin-classic-protection-auditor` short-lived installation token restricted to `plpgsql_check` `Administration:read` + `Metadata:read`; zero GitHub writes; no token in candidate checkout/log/artifacts |
| SHA / required CI | Pin reviewed shared runner code and actual `main` SHA, two *fresh genuine* reads of main, protected Classic REST+GraphQL proof, all eight exact-head GitHub Actions app 15368 checks on relevant pilot PR, candidate PR/head/decision run/audit, tag ref, public Release and independently verified signatures |
| Method / PASS | Reuse `PhaseDGitHubAdapter.capture`, Classic composite, `verify_inert_prepublication_recheck` and prior negative probe; exercise authenticated **absence** of actual authorization / unsigned Draft → **DENY**; verify 2 real snapshots, no publisher receipt or write capabilities. Record sanitized HTTP/status/head/run evidence |
| DENY | Missing real auth, Draft/unmerged candidate, unsigned/unknown artifacts, wrong signer/PG/source, occupied/unknown tag, stale main, failed/skipped/missing CI, incomplete pagination, 401/403/404/429/5xx/timeout, changed Classic/bypass, nonmatching snapshots; never accept synthetic fixture as live authorization |
| Evidence gap / exit | No two live complete authenticated snapshots and no future eligible signed candidate proven yet. G2 accepted **only as real read-only negative acceptance**; no positive publication conclusion. Requires separate protected nonpublishing job review before any code is added |

### G3 — Default-DENY integration of future event/receipt/publisher boundaries (future, inert)

| Field | Contract |
| --- | --- |
| Repositories / verifier | Shared `build` gate/publisher/package validators, inert `plpgsql_check` caller fixtures; independent adversarial CI |
| GitHub event | Future `chat-pr-authorization` contract expects trusted protected `main` `push` after exactly one squash-merged authorization JSON PR; present production remains only `manual-dispatch` / `workflow_dispatch` |
| Authentication / permissions | Future human allowlist + authenticated GitHub PR/commit/check evidence, scoped GET/Classic proof; **no enabled publish trigger or write token** at G3 |
| SHA / required CI | Future tuple: actual `push.before=packagingMainSha`, `push.after=authorizationCommit=current main`, exactly one parent, authenticated merged PR/one-file matching blob, exact authorization PR head and eight app-bound required checks, merged candidate SHA/decision/windowed runs, immutable upstream full SHA. Current build changes still require its own exact-head `resolver` |
| Method / PASS | Inert validation of `VERIFIED_CHAT_PR_AUTHORIZATION` + `push` + correctly typed PACKAGE-INFO event + candidate identities; keep `bind_verified_receipt` output nonpublishable; require comprehensive negative tests including actor/bot, direct push, extra file, wrong parent/head/merge, stale candidate, signature, two-read JIT races, timeout/pagination, 422 race, replay, tag/Draft/immutable Release ID and recovery |
| DENY | Any policy remains `manual-dispatch` (as it must during G3), absent genuine authorization/identity/signature proof, unexpected event/receipt tuple or any ambiguous API state ⇒ DENY. No production-capable receipt minted in this gate |
| Evidence gap / exit | Production end-to-end signer-to-receipt-to-write boundary still unproven. G3 exit requires review of least-privilege write-token isolation, event suppression semantics, single-tag serialization, partial-Draft recovery runbook and separately authorized G4 decision; **do not flip any policy automatically** |

Code mapping: `scripts/release-authorization.py:validate_receipt` recognizes strict typed mode/event pairs; `scripts/fleet-promotion-gate.py` handles candidate evidence; `scripts/fleet-publish-release.py` includes tag/Draft/ID-scoped state but active production manual mode remains unchanged. `build-extension-attested.yml` / package finalizer event provenance must agree. No mock should be imported as a trusted runtime publisher.

### G4 — One controlled real authorization transition (future; explicit separate approval mandatory)

| Field | Contract |
| --- | --- |
| Repositories / verifier | Exactly `plpgsql_check` pilot and `build` trusted shared gate; fresh human Chat publication instruction, independent GitHub PR/event/Classic/candidate/signer checks |
| GitHub event | A genuinely new one-file authorization PR, exact-head required `pull_request` CI, expected-head **squash**; actual main `push` trigger proven rather than assumed (GitHub `GITHUB_TOKEN` event suppression matters). No publication from direct push/issue/comment/bot |
| Authentication / permissions | Individually authenticated allowlisted **human**, exact `user.login`, `merged_by.login`, `sender`/`GITHUB_ACTOR` correlation and authentic API provenance; separately approved tightly scoped publication credential, dedicated GET-only Classic App; never use Catalog App as publisher |
| SHA / required CI | Explicit fresh instruction binds exact repo/tag/candidate and literal `PUBLISH`; single committed JSON `releaseTag`, `packagingMainSha`, `candidatePr`, `candidateHeadSha`, `candidateRunId`, `decisionRunId`, `operatorLogin`; live `before`/single-parent squash/`after`, eight required plpgsql_check checks on **exact** head (section 5), source full SHA, signed PG lifecycle matrix, current main and tag/Release double JIT |
| Method / PASS | Only after a separate approved transition, demonstrate future eligible signed candidate, genuine Chat intent + same event/PR/blob identity, current Classic proof, signed attestation, last possible JIT before privileged operation, create-only tag reservation with recorded API outcome, first-use and replay denial. Any isolated real two-writer tag experiment needs **separate explicit isolated-scope authorization**, not accidental production concurrency |
| DENY | Actor/event equality **alone** does not cryptographically prove text typed to Chat; absent fresh unambiguous user PUBLISH for named release, changed SHA/checks, failed evidence, occupied tag, non-atomic GET-only “absence”, unproven write principal or scope, reuse/replay → STOP with no tag or receipt |
| Evidence gap / exit | **No real authorization PR, true future signed candidate publish transition, live `POST git/refs` atomic race, or publishable receipt proof exists.** G4 may not start under this G1 instruction. Separate approval and documented credential boundary required; G5 not implied |

### G5 — Genuine new Release, Catalog proposal, Website verification (future; separately approved)

| Field | Contract |
| --- | --- |
| Repositories / verifier | `plpgsql_check` pilot Release; `build` signer/immutable publisher, independent validator; `catalog` scoped proposer and protected PR, `website` publish verification |
| GitHub events | Authenticated verified `main` authorization `push` → signed builder/Release; Catalog read-only reconciliation `schedule` when accepted, scoped one-record `pull_request` and Chat-reviewed protected merge; Website existing main CI/publication |
| Authentication / permissions | Fresh user-bound PUBLISH, independently gated publish-only credential; Catalog proposal App restricted to Catalog and cannot publish/merge; Chat GitHub connector merges only latest-head CI-passing Catalog PR |
| SHA / required CI | New eligible merged candidate exact head, immutable upstream source SHA, packaging/main/authorization SHA and single unused tag; maintained-PG Windows matrix (PG14 EOL policy evaluated at time of run), package ZIP SHA256, PACKAGE-INFO, SPDX SBOM, Grype **report-only**, signed SLSA+SPDX predicates and signer-workflow, immutable Release ID; exact-head Catalog required CI, Website EN/JA and download SHA |
| Method / PASS | Real create-only reservation and release workflow succeeds; independently re-download / rehash / verify signed new public bytes; quarantine partial failures without overwrite/delete; Catalog independently verifies new public assets, proposes **one** monotonic record PR; Chat merges protected exact-head and checks Website EN/JA, direct ZIP URL, displayed checksums / SBOM / Grype links |
| DENY | Failed Promotion run, unsigned/mismatched bytes, stale PG version, reused/occupied tag, partial Draft, changed Release ID, absent Catalog scheduled-run acceptance, skipped/failed head CI, broken EN/JA or links; never call historical signed bytes a new Release E2E |
| Evidence gap / exit | No future new release-to-Website single-Chat / zero-Work evidence. **Not authorized here.** Successful one-pilot E2E is prerequisite to individually controlled remaining-13 rollout; no unattended Release, auto candidate merge or Catalog auto merge |

## 4. Trust boundary and exact identity mapping

**Chat intention is not GitHub actor authentication.** A logged-in human `actor`, `sender`, `user.login` or `merged_by.login` proves only the authenticated GitHub-side identities/events within its API trust boundary. It cannot cryptographically attest the user's exact natural-language Chat PUBLISH instruction. The operator must separately provide a **fresh, explicit, uniquely target-bound** publication instruction; neither G0 nor a document issue/comment nor a synthetic literal `PUBLISH` supplies it.

**Candidate provenance is not public signed-byte provenance.** A `windows.yml` candidate run, even when successful, is not the signed Release build or a publishable receipt. An old, validly signed public `plpgsql_check v2.10.14-windows.1` ZIP proves those historical bytes only. For a future candidate rebind and independently verify `candidateHeadSha`, merged candidate PR, `candidateRunId`, `decisionRunId`, upstream full SHA, maintained PG matrix and each new ZIP+SBOM+attestation signer/subject; do not recycle a fixed historical signature.

**GET absence is not atomic tag ownership.** Two nontransactional `GET git/ref/tags/<tag>` / `GET releases/tags/<tag>` calls cannot reserve a tag. The PR #91 test makes two fake GETs both “absent”, then uses an **in-memory simulation** of `POST git/refs` create-only: one success and one fake HTTP 422. This proves simulated control-flow fail-closed behavior, **not** GitHub's live concurrency behavior. Any future write must use an actual create-only operation, validate its server result, retain tag/draft-ID recovery evidence, deny replay and never force-update/delete/reuse a tag.

**Main, policy and event binding:**

1. `candidatePr` is the previously audited automation-owned candidate; its *actual merged* `head.sha` must equal `candidateHeadSha`. `candidateRunId` and `decisionRunId` must be actual verified successful independent evidence, not caller-supplied labels.
2. `packagingMainSha` is the exact `main` SHA **before** authorization merge and equals real `push.before`; `authorizationCommit` is the exact single-parent squash result and equals `push.after`, run `GITHUB_SHA` and then-current main. The unique committed authorization JSON blob must match both PR file and commit file SHA; no extra edits/deletions/renames.
3. Authorization PR head `authorizationHeadSha` has exact required CI; PR `merge_commit_sha` matches the push commit; creator, merger, sender and operator identities are authenticated and allowed. A PR body, message or filename alone does not substitute.
4. Both trusted policy files must independently opt in before any future mode can publish, and candidate fleet policy and lifecycle must match. **During G1–G3 no opt-in is permitted**; current `manual-dispatch` and `manual-only` values mandate DENY for Chat-PR publication.
5. Re-fetch mutable main/branch-protection/PR/CI/tag/Release/assets as near as possible to any future privileged write; compare two genuine snapshots and final JIT state. Even same-state GETs cannot guarantee a concurrent administrative change cannot happen after the last read.
6. Typed receipt and PACKAGE-INFO tuple must be independently coherent: legacy `manual-dispatch` → `VERIFIED_MANUAL_DISPATCH` / `workflow_dispatch`; future `chat-pr-authorization` → `VERIFIED_CHAT_PR_AUTHORIZATION` / verified `push`. Current inert helpers deliberately yield `DRY_RUN_CONTEXT_ONLY` or `DRY_RUN_PHASE_D_RECHECK_ONLY`, `publishableReceipt=false`, `signedArtifactsVerified=false`. Never upgrade these statuses by field substitution.

## 5. Exact required CI / protected-branch invariants

The pilot Classic proof pins eight required check names to **GitHub Actions App ID 15368**, presently:

1. `syntax`
2. `windows / Resolve extension and PostgreSQL matrix`
3. `windows / PostgreSQL 15 / Windows x64`
4. `windows / PostgreSQL 16 / Windows x64`
5. `windows / PostgreSQL 17 / Windows x64`
6. `windows / PostgreSQL 18 / Windows x64`
7. `Regression-test immutable Release preflight`
8. `Windows required summary`

Exact PR-head `completed/success` for every required check, enforced `strict=true`, PR-only main, zero required independent approvals, enforced admin protection, no bypass, no force-push/deletion and no silent Rulesets/Classic fallback. Missing/omitted/ambiguous REST fields are not equivalent to explicit empty bypass lists: `scripts/classic-protection-composite.py` and associated verified REST+GraphQL effective-ref proof must independently establish the constraints. Check names/major set are a **point-in-time contract**; PostgreSQL EOL and future matrix changes require a separately reviewed protection/CI migration (PG14 scheduled EOL 2026-11-12), never an implicit waiver. Build documentation PR requires its own required `resolver` at exact head; the eight checks refer to the pilot repository, not build.

## 6. Independent Catalog scheduled-audit and 14-extension rollout track

- **Catalog initial scheduled acceptance: NOT ACCEPTED.** `catalog-drift-readonly.yml` is Active with GitHub Actions enabled, and the cron specifies 09:30 JST / 00:30 UTC. The 2026-10-14 first true `event=schedule` run has **not** been established in the accepted evidence. A `push` SUCCESS is not a schedule SUCCESS; root cause has not been independently proven.
- **Next checkpoint: 2026-10-15 09:30 JST.** Recheck actual workflow run `event=schedule`, head ref/SHA, attempt, job conclusion, two independent live read-only snapshots, no-change or justified drift and API-failure DENY; record a real run URL if present. Never fabricate a schedule run or dispatch it to stand in for one.
- **14-extension daily read-only rollout: HOLD.** Existing 14 BUILD entries and earlier dry-run/no-change successes do not lift the blocked scheduled-event acceptance. Require separately accepted schedule behavior, 14 independent correctly scoped read-only validations, duplicate/no-change and timeout/TOCTOU denials before a rollout decision. No automatic PR creation, Catalog auto-merge, publication or App expansion.
- This schedule gate is **not** G4/G5 authorization. Even when an authentic Catalog scheduled read-only audit passes, future public Release and Catalog proposal still require their own protected/attested evidence and explicit policy gates.

## 7. Evidence ledger and next safe action

| Gate / track | Accepted evidence | Still needed; not implied by G1 |
| --- | --- | --- |
| G0 | [Actor/event #6159994062](https://github.com/pgextwin/build/issues/75#issuecomment-6159994062), [signed historic bytes #6160343683](https://github.com/pgextwin/build/issues/75#issuecomment-6160343683), [offline #6160501342](https://github.com/pgextwin/build/issues/75#issuecomment-6160501342) | Real future intent, fresh signed candidate, live atomic write and E2E |
| G1 | This versioned document (PR/head/CI/main/Issue URLs recorded in separate execution comment) | Protected exact-head docs PR merge and postmerge CI before marking G1 complete |
| G2 | Existing inert reader and negative tests | Actual GET-only scoped two-snapshot trusted-main negative proof and CI URL |
| G3 | Mode/receipt prototypes and hostile fixtures | Same-job independent integration, full CI and proof of default DENY; no enabled trigger |
| G4 | None | Separate approval, genuine new authorized protected PR/push + human explicit PUBLISH + safe atomic reserve |
| G5 | None | Actual new Release → independent new signed bytes → Catalog one-record PR → EN/JA Website |
| Catalog schedule | Workflow is Active / cron configured; `push` evidence separate | Authentic `schedule` run and 14-extension rollout approval |

**Recommended next engineering gate after a fully accepted G1:** G2, narrowly scoped **production-shaped GET-only negative JIT proof** in a trusted protected-main pilot. Reuse the existing read-only adapter and deny fixtures, retain default manual policy and do not introduce any real authorization, tag, Release, Dispatch or write credentials. Track the independent 2026-10-15 Catalog schedule checkpoint separately. Keep Issue #75 OPEN until actual separately authorized G5 acceptance.

## 8. PRE-G4 inert hardening: strict receipt, trust roles and recovery (2026-10-14)

**Authorization:** [Issue #75 decision #6163105169](https://github.com/pgextwin/build/issues/75#issuecomment-6163105169) permits only nonpublishing defensive code, tests and design. **G4/G5 remain NO-GO / NOT AUTHORIZED; Issue #75 OPEN.** This section does not enable a new publisher path.

### Future typed receipt

In scripts/release-authorization.py, future chat-pr-authorization mode requires signedArtifactsVerified, publishingEnabled, and publishableReceipt each to be **literal bool True (is True)**. Missing, null, false, 0, 1, strings, arrays, objects and other truthy stand-ins are denied. Mode/status/event, operator, repository, complete commit SHA and PR/candidate identities are separately checked. Current manual-dispatch semantics are unchanged. The receipt parser cannot certify a signer or the user's actual Chat intent; **no independent issuer or publishable receipt is created here**. Synthetic G3 output is still DENY.

### Actual plpgsql_check manual workflow permission boundary

On pilot protected main 881efc3c170e89ee68fd336f2e224fbd462c1c10, .github/workflows/promote.yml remains **workflow_dispatch only**. The actual executed manual shared-build pin is 455f0ccc667697f600700a6e64bcfd6c57b6a977 (both authorize/publish). The reusable attested builder is pinned to 5756b3c5136a8bf4db710016cfe97555f0a71c6d. **Neither is current build/main 1688d66a5130ea642fdb140e24fb555c31f0dc9a**; CI for main cannot prove those pinned executables passed an equivalent regression.

| Role | Existing permissions | Trust boundary / required later review |
| --- | --- | --- |
| authorize (manual) | contents:read, actions:read, pull-requests:read | Future trusted protected-main GET-only verifier must independently bind human, PR/merge/push, required CI, Classic and double JIT. Never give verifier a publication writer credential. |
| release_build | contents:read, id-token:write, attestations:write, artifact-metadata:write | Bind each maintained PG ZIP, SHA, PACKAGE-INFO, SPDX, Grype and independent signer/attestation to exact upstream/packaging full SHA. Signing role is not a Release writer. |
| publish (manual only) | contents:write, actions:read, attestations:read | Only current manual publisher has Release writer scope. A future new writer needs separate GO and a trusted pinned implementation. Never supply write token to untrusted PR head, arbitrary checkout, or untrusted artifact. |
| catalog_sync | contents:read; scoped Catalog App token (catalog Actions:write) | Catalog dispatch/proposer App cannot become a Release publisher. |
| Classic protection auditor | dedicated Administration:read/Metadata:read scoped App | Strict GET-only Classic/GraphQL bypass-zero audit; no contents:write, separate from signer/publisher/Catalog. |

Before any G4 rollout: independently diff **both exact executed shared pins** and the caller against reviewed build code; verify complete job token boundaries and signing build artifacts. An authenticated GitHub actor/sender/merged_by does not cryptographically prove a target-specific Chat PUBLISH instruction. A GITHUB_TOKEN-origin push normally suppresses subsequent workflows; an actual future human-authorized event must be proven. Do not change these existing pins, events, jobs, token scopes, settings, Secrets or policies in PRE-G4.

### Recovery state gap and read-only design

Current scripts/fleet-publish-release.py:state() writes **schemaVersion=1** with only schemaVersion, state, tag, runId and commit; it does **not** persist git/ref reservation response/status, immutable Release ID or remote asset inventory. Actual control flow already uses GET (non-atomic) → create-only POST git/refs → verify-tag Draft → uniquely resolve immutable Release ID → compare remote asset digest by ID → PATCH only that ID → re-verify published bytes. An ambiguous response or failed state write cannot establish a safe retry. Historic failed [Promotion Run #38128142145](https://github.com/pgextwin/plpgsql_check/actions/runs/38128142145) was FAILURE at DRAFT_STAGED state mismatch; the exact mismatching field was never identified.

**Proposed future durable recovery evidence schema v2 (not emitted or consumed by the actual publisher):**
- schemaVersion=2, state, tag, runId, exact commit SHA.
- reservation: outcome CREATED, HTTP 201, refs/tags/<tag>, confirmed immutable ref target SHA; retain raw response and errors.
- releaseId: exact immutable positive Release ID after staging; no title/tag lookup substitution.
- assetInventory: complete basename → lowercase SHA256 mapping; retain each remotely observed asset ID, upload state, SHA digest, and raw source response.
- Two independently obtained, authenticated, complete GET snapshots (including HTTP status, pagination completeness, observation time and request identity); snapshots must agree.

For TAG_RESERVED, require confirmed reservation and ref SHA with no unexpected Draft. For DRAFT_STAGED and DRAFT_VERIFIED, require matching positive Release ID, tag, target commit, draft=true, all expected assets with valid digests. For PUBLISHED_AUDIT_PENDING and PUBLISHED_VERIFIED, require same ID and draft=false, exact assets, and then a separate genuine signed/public-byte audit. Current v1 recovery artifacts lack essential fields, so always classify as UNKNOWN rather than pretending safe resumption.

Any 422 loser/occupied tag, 429/5xx, timeout/connection reset, lost POST/PATCH response, failed persistence/upload of recovery artifact, incomplete or paginated inventory, two-read disagreement, changed ref SHA or immutable ID, draft state mismatch, missing/duplicate/extra/partial assets, digest mismatch, unexpected Release, replay or missing evidence → **UNKNOWN_QUARANTINE / fail closed**. A tag-lookup 404 must never imply absent Draft. Permitted next step is operator-controlled **GET-only investigation**. Automatic re-POST, retry, PATCH, mutation, deletion, overwrite, tag reuse or publishing is prohibited.

The new scripts/release-recovery-evidence.py classifier is an **offline pure helper not referenced by the current publisher or workflow**. It returns either CONSISTENT_READ_ONLY or UNKNOWN_QUARANTINE, never publish/retry/mutation authorization. The matching classification is evidence consistency only, not proof that synthetic snapshots came from independent authenticated GitHub queries; mock tests cannot establish live one-winner behavior or actual recovery. No executable new publisher write flow is introduced. Only a later separately authorized G4 can address durable persistence and writer operations.

### Scope and residual NO-GO

Central and pilot-local releasePolicy=manual-dispatch, all 14 fleet BUILD/manual-only, candidate PR #29 Draft, and current promote.yml unchanged. The PRE-G4 acceptance gate is exact-head build resolver SUCCESS (App ID 15368), protected expected-head squash merge and postmerge main push CI SUCCESS; test the strict receipt and simulated read-only recovery classifier. **This proves no actual Release capability.**

Remaining G4 blockers: genuinely new eligible candidate (Draft cleared, all required exact-head checks, full SHA/PG lifecycle and real fresh signed assets), fresh human target-bound Chat PUBLISH intent, independently authenticated and protected one-file PR/squash/push event, reviewed fixed executable pins, separate least-privileged GET-only verifier and narrowly scoped writer, independently verified signer/receipt issuer, two genuinely positive live JIT snapshots immediately before privileged action, atomic reservation/race tests under separate authorization, and durable immutable-ID recovery with quarantined ambiguity. A new publisher write flow, policy/trigger transition, real Release and subsequent G5 Catalog/Website E2E **each need separate explicit GO**.

## 9. PRE-G4 fixed-pin / authority-boundary delta acceptance (2026-10-14)

**Decision and scope:** [steering decision #6163635021](https://github.com/pgextwin/build/issues/75#issuecomment-6163635021), following [PR #95 limited acceptance #6163357082](https://github.com/pgextwin/build/issues/75#issuecomment-6163357082). **PASS_PIN_BOUNDARY_DELTA_DOCUMENTATION_ONLY** denotes comparison/design evidence, *not* a deployed executable, operational regression, real signer, publishable receipt or authorization to transition. **G4/G5 NO-GO; Issue #75 OPEN.** This section supersedes older point-in-time G1/G2/G3 status text elsewhere in this document only for the current acceptance state: G0–G3 have individually recorded **limited** PASS, G4/G5 have no GO. Neither live promotion pin nor policy is changed.

### Exact frozen run graph and provenance

| Executed role | Actual caller/immutable SHA | Fact or implication |
| --- | --- | --- |
| Pilot entrypoint | `pgextwin/plpgsql_check/.github/workflows/promote.yml@881efc3c170e89ee68fd336f2e224fbd462c1c10` | `on: workflow_dispatch` only; `github.ref == refs/heads/main` authorize guard; serialized promotion; no Chat push-to-publish trigger. |
| Manual authorize | `pgextwin/build@455f0ccc667697f600700a6e64bcfd6c57b6a977` | Explicit pinned checkout; runs `fleet-promotion-gate.py` and produces `promotion-receipt`. `persist-credentials: false`. |
| Attested Windows builder | reusable `pgextwin/build/.github/workflows/build-extension-attested.yml@5756b3c5136a8bf4db710016cfe97555f0a71c6d` | `job.workflow_sha` checks out that same pinned build source; signs the freshly built PG matrix with scoped attestation permissions. The workflow **blob SHA `93a0a7641253735cf5adb845c768981c79f75b46` equals current main's**; this does **not** make its dependent scripts identical. |
| Manual publish | `pgextwin/build@455f0ccc667697f600700a6e64bcfd6c57b6a977` | Separate pinned checkout; reads receipt + signed run artifacts and uses `fleet-publish-release.py`; `contents:write` in this job only. Current manual publisher is *not* PR #95's implementation. |
| Future reference baseline (not executed) | `pgextwin/build/main@20f1a176db0f95b20b65f9656c7fd3a8f9815403` | PR #95 exact head `8dda394756fbd545d34844b86f2163c8256eef85`; [PR CI #38529209576](https://github.com/pgextwin/build/actions/runs/38529209576) and [push CI #38529324346](https://github.com/pgextwin/build/actions/runs/38529324346) have bounded PASS; no implied equivalence to either fixed executable pin. |

REST compare [authorize/publisher 455f.. → main](https://github.com/pgextwin/build/compare/455f0ccc667697f600700a6e64bcfd6c57b6a977...20f1a176db0f95b20b65f9656c7fd3a8f9815403): **35 ahead, 0 behind, 56 changed files**. [Signer 5756.. → main](https://github.com/pgextwin/build/compare/5756b3c5136a8bf4db710016cfe97555f0a71c6d...20f1a176db0f95b20b65f9656c7fd3a8f9815403): **62 ahead, 0 behind, 64 changed files**. These are commit/file deltas in *build*, not a proposal to deploy all commits. Before any future pin replacement, obtain immutable full-SHA commit/tree and per-file manifest for **each** pinned runner, re-review dependency closure and attestations, and test *the replacement pin's actual code*, never assume `main` tests certify a different pin.

### File-level impact register (455f pin → main, with signer-only deltas)

| Boundary class | Relevant files / concrete delta | Migration risk / pre-G4 acceptance |
| --- | --- | --- |
| Authentication and GitHub provenance | `scripts/chat-pr-authorization.py`, `chat-pr-phase-d-github-readonly.py`, `chat-pr-phase-d-live-deny-probe.py`, `chat-pr-phase-d-prepublish.py`, `chat-pr-g2-live-negative.py`, `chat-pr-g3-inert-contract.py`, `chat-pr-pilot-evidence.py`, `classic-protection-audit.py`, `classic-composite-protection.py`, `classic-graphql-bypass.py` (new); G1/Phase C/D/G3 design docs | New separate **GET-only** and inert proofs; none is called as a trusted live publishable receipt issuer by existing `promote.yml`. Require fresh authenticated API provenance/negative and positive JIT acceptance, exact main/PR/CI/actor/Classic joins and version-pinned entrypoint. |
| Receipt / promotion authorization | `scripts/release-authorization.py` (new), `scripts/fleet-promotion-gate.py` (modified); `tests/test-release-authorization.py`, `test-fleet-promotion-gate.py`, G3/Phase D fixtures | At 455f, the gate is exclusively `manual-dispatch` and emits `VERIFIED_MANUAL_DISPATCH`. Main adds optional `chat-pr-authorization` tuple and `candidateHeadSha`; future typed receipt demands literal `True` for all three `signedArtifactsVerified`, `publishingEnabled`, `publishableReceipt`. This **parser is not a trusted issuer**. Do not relabel a legacy or dry-run receipt as publishable. |
| Publisher and recovery | `scripts/fleet-publish-release.py` (modified), `scripts/release-recovery-evidence.py` (new), `tests/test-fleet-publish-release.py`, `test-release-recovery-evidence.py`, `test-chat-pr-phase-d-atomic-replay.py` | Old publisher hard-requires `workflow_dispatch` / `VERIFIED_MANUAL_DISPATCH`; main routes manual and future typed events, rejects incomplete pagination/duplicate asset names, but still writes **schemaVersion 1** recovery (`state, tag, runId, commit`) and never calls the pure v2 classifier. Any real writer integration and reservation/ID persistence is **BLOCKED pending separate GO**. |
| Attested signing / package | `scripts/finalize-package.ps1` (modified), `scripts/verify-public-signed-release-readonly.py` (new), `schema/package-info.schema.json` (diff since **5756**), signing/package fixtures; reusable `build-extension-attested.yml` **unchanged blob** between 5756 and main | At 5756, finalizer does not yet include the subsequent SQL-only/no-DLL compiler metadata adjustment (present by 455f) or later `release-attested` event/ref guard (main admits only `workflow_dispatch`/`push` on `main`). Package metadata, embedded ZIP bytes, SPDX/Grype, provenance predicates, signer workflow identity and exact `job.workflow_sha` MUST be independently compared and acceptance-tested per proposed immutable signer SHA. No old signatures can prove new candidate bytes. |
| Policy, manifest, fleet | `metadata/release-promotion.json` (allowed repositories expanded 1→14 with same `manual-dispatch`), `metadata/automation-fleet.json` (still 14 BUILD and `manual-only`), `metadata/manual-release-downstream.json` (new), `scripts/unattended-policy.py`, `scripts/candidate-update.py` | Exact repo allowlist and policy tuple must be re-evaluated from trusted commits. No implicit mass Chat-opt-in or fleet migration; local `plpgsql_check/config/release-promotion.json` remains `manual-dispatch`. |
| Workflow and CI | `.github/workflows/validate.yml` (adds negative/inert tests), `tests/test-*` added/modified; **pilot** `.github/workflows/promote.yml` unchanged | New `resolver` on build/main proves selected offline controls only, not an end-to-end execution of original promote pin. Any future caller `on`, `if`, `permissions`, checkout ref, artifact handoff, `needs`, concurrency and effective checks require separate explicit GO and PR review. |
| Documentation / operations | `docs/adr-0075-chat-authorized-publication.md`, `docs/issue-75-*`, `docs/chat-first-publication.md`, `docs/step23-manual-queue.md`, README/architecture | Describes boundaries; does not enact GitHub authorization, isolate writer credentials, or certify a production recovery. |

**Existing manual route compatibility, bounded conclusion.** The caller continues to supply `workflow_dispatch`, manual `PUBLISH` confirmation, `GITHUB_ACTOR`, full candidate and decision evidence, main-only ref, `VERIFIED_MANUAL_DISPATCH` receipt and `PACKAGE-INFO.workflowRun.event=workflow_dispatch`. Old `fleet-promotion-gate.py` and old `fleet-publish-release.py` both require that combination. Main's new optional mode is policy-gated and manual tuple remains recognized, but **source inspection alone is not a regression run** of a hypothetical repinned manual Workflow; compare packaging/PG lifecycle, signed build output, live token provenance, rate/pagination behavior and failure windows before a pin cutover. No production manual Workflow or fixed SHA was changed here.

### Principal separation and event/credential conditions

| Identity / boundary | Effective observed scope or source | Required later acceptance; DENY until demonstrated |
| --- | --- | --- |
| Dedicated Classic audit GitHub App | Earlier authenticated GET-only REST+GraphQL proof; `Administration:read`, `Metadata:read` by design. Current Chat connector's direct Classic endpoint returns 403. | Auditor is **not** a general publication identity. Verify actual installation/repository, read scopes and bypass-zero/effective rules at runtime using dedicated credentials; absent, stale, partial or forbidden GET = DENY. Do not copy the audit key to CI PR-head execution. |
| `authorize` / prospective verifier | `contents:read`, `actions:read`, `pull-requests:read`; no writer credential. | Checkout trusted protected main and immutable shared SHA with `persist-credentials:false`; use API-fetched candidate/head/artifact content as *data only*, prohibit executing scripts/actions from PR head or downloaded artifacts. Validate exact JSON and signed evidence **before** issuing any receipt. |
| `release_build` signer | `contents:read`, `id-token:write`, `attestations:write`, `artifact-metadata:write`. | Isolate OIDC signer workflow/repo/SHA, id-token audience and signed subject/predicate from untrusted PR execution; bind release ZIP+SPDX and PACKAGE-INFO to that exact pinned signing run. No `contents:write` and no implicit publisher approval. |
| `publish` manual writer | `contents:write`, `actions:read`, `attestations:read`; trusted pin, read-only candidate artifacts downloaded. | A verified artifact is **not executable code**; ensure no untrusted path or filename affects interpreter commands or token exposure. Read-only gate job must complete before writer job; writer must reverify source, immutable signer, SHA and receipt without trusting a caller-provided boolean. Minimize live token to the single gated write phase. |
| Catalog App | Minted only after `publish`, scoped to `pgextwin/catalog` and `permission-actions:write` for existing `sync-release.yml` Dispatch; Catalog one-record proposer role is separate. | Never give Catalog App release-writing permissions or use it as signing/auditing identity. Independently verify public Release before Catalog proposal; verify its actual App permissions when later authorized. |

**Trigger and intent separation.** A `GITHUB_TOKEN`-initiated repository push normally does not trigger a second `push` Workflow: success of a connector-triggered PR/merge and success of a synthetic `push` fixture do not prove a future real event will run. Later, without changing anything here, capture the *actual* future event payload/run/actor and its credential type, and reject suppressed/bot/unattributable events rather than substituting `workflow_dispatch` or giving the writer token to a PR. GitHub `actor`, `sender`, `merged_by`, commit author and PR metadata are GitHub-side evidence; none cryptographically proves that the user typed **fresh, uniquely targeted** `PUBLISH` in Chat. The separate explicit intent (repo, candidate PR/head/run, unused tag, packaging SHA) plus independently matched human-connected GitHub PR, exact-head required CI and expected-head squash are all mandatory. `push.before` and single-parent `push.after`, one new authorization blob, and pre-write JIT two snapshots must bind the same trusted tuple. Missing origin, credentials or operator proof => **NO-GO**.

### GO / NO-GO matrix and future rollback/quarantine contract

| Gate | PRE-G4 result | Required proof before any separately approved capability change |
| --- | --- | --- |
| Fixed SHA and dependency closure | **PASS inventory only** | Byte-level review of gate/publisher/builder/finalizer/schema/caller action SHAs; confirm signed commit/tree trust, explicit allowlisted pin transition, test both manual and future mode at *candidate replacement pin*; ensure no untrusted checkout inherits write or OIDC credentials. |
| Current manual behavior | **PASS configuration observation only** | Rehearsal/CI with authentic `workflow_dispatch` tuple, unchanged lifecycle/package/ZIP/SBOM/Grype/attestation, manual first-use and fail-closed error cases. Do not run Dispatch merely to complete this audit. |
| Candidate and Chat authorization | **BLOCKED** | Truly eligible **future** candidate; PR #29 remains OPEN/DRAFT. Fresh target-specific human Chat `PUBLISH`; real matching operator/PR/head/merged_by/push/required CI/protected main; no reuse of earlier signed v2.10.14 assets. |
| Signature and artifact bridge | **BLOCKED** | Verify fresh signed source→packaging→build-run→ZIP SHA256→PACKAGE-INFO→SPDX/Grype→SLSA/SPDX signer identities and full PG lifecycle/matrix with independent authenticated results. |
| Just-in-time state, atomic reservation | **BLOCKED** | Genuine positive independent GET snapshots and last possible trusted recheck of main, CI/Classic, tag/Release, candidate and signer; preserve first-use/422/replay/TOCTOU DENY. A live create-only race or tag write requires separate **isolated explicit authorization**; fake HTTP 201/422 is insufficient. |
| Writer recovery/resumption | **BLOCKED** | Durable atomic reservation result (status/ref SHA), immutable Release ID, state transition, asset IDs/digests, raw complete responses, crash-safe persistence and retained artifact all integrated into *actual* writer and tested for lost POST/PATCH response / partial Draft; current pure classifier never authorizes retry or publish. |
| Event/capability activation | **BLOCKED** | Separate user/steering **GO** for any new writer, trusted event route, token scope/pin/policy change, then independently accepted actual pilot G4; distinct G5 decision before real future Release→Catalog→EN/JA Website. |

**Fail-closed handling and rollback:** preserve `manual-dispatch` in central and local policies, `manual-only` for all 14, old `promote.yml` pins/events/permissions, untouched candidate PR #29, and no new authorization path. A failed pin evaluation is **NO-GO**, not an automatic repin or rollback to unreviewed branch/tag. For an already attempted future write with 422, timeout, 429/5xx, lost API response, mismatched ref/Release ID, incomplete asset inventory, missing durable state, inconsistent dual GET, partial Draft, or recovery artifact loss: mark **UNKNOWN_QUARANTINE**; freeze writes and pin promotion, retain raw immutable evidence, perform only separately authenticated GET-only incident triage. Never retry POST/PATCH, delete/overwrite Draft/tag, force-update ref or reuse a tag based on a 404/absence. Roll back a *future* capability only through an independently approved, protected, exact-head policy/Workflow/pin change; a rollback must not mutate existing tags/Releases or promote an ambiguous candidate.

**This audit makes no implementation of new Publisher write flow.** `release-recovery-evidence.py` stays pure and disconnected; actual `fleet-publish-release.py` v1 state does not save reservation outcome, Release ID or asset inventory. There is no publishable receipt and no G4/G5 acceptance. Next authorized work under this decision is documentation PR + exact-head resolver + expected-head squash + postmerge CI, followed by Issue #75 evidence; **any actual capability enablement needs a new explicit GO**.

### Exact-pin offline manual compatibility replay (Issue #75; 2026-10-14)

**Authorization:** [#6164400912](https://github.com/pgextwin/build/issues/75#issuecomment-6164400912), limited exclusively to write-disabled, offline, nonpublishing fixtures. The production caller, signer, gateway, publisher, SHA pins and release policies are unchanged. **This is not G4/G5 GO.** All three frozen executable snapshots are under `tests/fixtures/issue-75-pre-g4/` for this rehearsal only; `test-fleet-promotion-gate.py`, `test-fleet-publish-release.py` and the existing PowerShell finalizer test use them. No copied publisher `main()` is invoked. Test code stubs subprocess/network and the attestation invocation. A synthetic attestation stub is **not** a cryptographic signature verification.

| Executable / immutable Git blob | Same-input offline comparison | Deliberate limit / remaining DENY |
| --- | --- | --- |
| Manual gate at `build@455f0ccc667697f600700a6e64bcfd6c57b6a977`, blob `6abf79d6a037a9ca5e77d5ce7803d520701e290c` vs main blob `cdcc84862b108758bd5918efd63b1a50bb8ff935` | Same valid manual tuples for plpgsql_check, pg_bigm and per-PG pgaudit; identical `VERIFIED_MANUAL_DISPATCH` data. Wrong PUBLISH, bot, policy, local mode, main SHA, Windows event/run/head, source SHA, audit hash, and expired PG denied in both. Offline fixture asserts actual frozen Git blob SHA-1 and unchanged shared identity helper blob `e8c63f6f7f26a883cf898ca1c3e386d9ed2f1d7c`. | Old function has no `authorization_mode` argument, and no trusted Chat-PR issuer. A synthetic manual receipt must never be repackaged as `publishableReceipt=true`. The gate does not sign bytes. |
| Manual publisher at `build@455f0ccc667697f600700a6e64bcfd6c57b6a977`, blob `85cbe8e6893477210831c6a813fe796f23d7eb08` vs main blob `5b6a514b5038edcb9413c89bab0b41f47fe410c1` | Matching local ZIP/SPDX/Grype 15-asset digest maps over PG14–18; two nominal attestation CLI calls per major, both exact `--signer-workflow` and SPDX 2.3 predicate arguments checked, with execution **mocked**. Wrong receipt status/mode, SHA, repository/operator, PG/source identities, package run/event, PG lifecycle and HTTP 503 deny. | Old publisher does not use typed receipt parser, complete pagination or duplicate asset-name defenses and persists no v2 recovery. **Both versions do not bind `PACKAGE-INFO.workflowRun.attempt` in `check_assets`; a missing/changed attempt in this local synthetic ZIP is accepted by that function. This is a known BLOCKED provenance field, not proof of an authenticated signed run.** Signature mock does not verify real SLSA/SPDX or digest attestations. |
| Attested builder `build@5756b3c5136a8bf4db710016cfe97555f0a71c6d` finalizer blob `7712876c458c6168c06f4181b11d1bb1961210d4` vs main `17232ab1010cd38b8c13224420bd98fdb75cdaec` | Fixed synthetic native-DLL and SQL-only PG18 ZIPs compared for upstream/packaging/build checkout full SHA, `release-attested`, run ID/attempt, `workflow_dispatch`, `refs/heads/main`, embedded JSON. Native `MSVC` semantics match. | SQL-only differs: frozen emits `toolchain.compiler=MSVC`, current emits `not-applicable` with null compilerVersion. Frozen finalizer accepts `release-attested` with `pull_request` or wrong non-main ref, while current explicitly denies. Both deny `BuildCheckoutCommit != BuildCommit`. Frozen schema `schema/package-info.schema.json` requires compiler `MSVC`, while main permits `MSVC` or `not-applicable`. Thus signer workflow blob equality is **not** packaging semantic or event validation equivalence. |

**Signature trust bridge:** the real previously published [plpgsql_check v2.10.14-windows.1](https://github.com/pgextwin/plpgsql_check/releases/tag/v2.10.14-windows.1), immutable Release ID `409572202`, has its **own** independently accepted 16 public bytes / SHA256 / PACKAGE-INFO / standalone SPDX / Grype / SLSA+SPDX signer proof at [PR #90](https://github.com/pgextwin/build/pull/90) and [Issue #75 #6160343683](https://github.com/pgextwin/build/issues/75#issuecomment-6160343683). That is historical `PASS_SIGNED_PUBLIC_BYTES_ONLY`; neither an offline replay nor an old signer workflow file's identical Git blob gives Sigstore authorization or signed byte equivalence for a future build. The frozen code's exact `job.workflow_sha`, builder ref and ZIP/SBOM predicate must be independently joined to actual new run and immutable digest before capability GO. PR #29 remains Draft and is never treated as signed.

**Repin GO checklist (still blocked):** review exact immutable caller/build gate/build publisher/builder/finalizer/schema/helper closure; select and verify a proposed new pin with its own full run of manual and future-mode tests; attest actual new ZIP/PG-major/source+packaging SHA/run ID+attempt/event/ref/signing workflow/predicate; authenticate two live positive GET snapshots immediately before any write; prove separate read-only verifier vs writer/signer credentials; preserve no PR-head execution/token leakage, exact-head protected checks and event delivery; verify immutable ID, atomic reservation, complete recovery v2 and fail-closed race/unknown-response handling. These require new authorization. Current `publishableReceipt=false`, `mutationsEnabled=false`, G4/G5 **NO-GO**, central and local `manual-dispatch`, fleet 14/14 `manual-only`, Issue #75 OPEN.
