# Build history-suite dependency audit (R04, Phase C)

Authority: `REVIEW-VERIFICATION.md` R04 items 1–2, B10/B13. Audited at
`215ef308bd752a5f188a7ffffee8bcee2750c5ac` before changing test selection.

Classification: **(a)** live functional/authorization contract, **(b)** live
policy/proof input, **(c)** historical re-proof. Ambiguous checks stay in normal
CI. No production scripts, signer pins, signature identities, byte-verification,
admission or per-version license implementation changes are proposed.

## B10: retained conservatively

Every candidate file below remains in its existing normal selection (validate,
the additional offline regressions workflow, or its dedicated policy workflow).
A frozen target list/request ID is often the allowlist/key accepted by the reader;
it is not safe to infer retirement from a date or a `pilot` filename. Each file
contains hostile functional checks or enforces an input still consumed by a
workflow. No B10 tests move in this phase.

| Candidate under `tests/` | Class | Contract / reason retained |
| --- | --- | --- |
| `test-issue311-approval-block.py` | (a) | Deterministic OFFLINE approval transition/CAS proof; no real approval claim. Fixed IDs/targets remain reader scope or fixture inputs; no isolated historical-only move. |
| `test-issue311-coordinator-dispatch-pilot.py` | (a) | Offline one-shot real App dispatch policy adversarial fixtures, no credentials. Fixed IDs/targets remain reader scope or fixture inputs; no isolated historical-only move. |
| `test-issue311-coordinator-fleet-original.py` | (a) | Offline fail-closed static and event gate regression for App 17 fleet. Fixed IDs/targets remain reader scope or fixture inputs; no isolated historical-only move. |
| `test-issue311-coordinator-identity.py` | (a) | Offline negative tests for the nonpublishing one-shot Coordinator identity proof. Fixed IDs/targets remain reader scope or fixture inputs; no isolated historical-only move. |
| `test-issue311-coordinator-local-prepare-pilot.py` | (a) | Fail-closed coordinator App one-shot PREPARE request fixture tests. Fixed IDs/targets remain reader scope or fixture inputs; no isolated historical-only move. |
| `test-issue311-lifecycle-store.py` | (a) | R04 generic durable state adapter: CAS, blob and ambiguous write hostile fixtures. Fixed IDs/targets remain reader scope or fixture inputs; no isolated historical-only move. |
| `test-issue311-r04-ambiguous-put.py` | (a) | Hostile Issue311 ambiguous original protected PUT and fail-closed replay tests. Fixed IDs/targets remain reader scope or fixture inputs; no isolated historical-only move. |
| `test-issue311-r04-claim-race.py` | (a) | Hostile, offline R04 independent contender, immutable request and final ZIP tests. Fixed IDs/targets remain reader scope or fixture inputs; no isolated historical-only move. |
| `test-issue311-r04-stopped-run.py` | (a) | R04 separate-run interruption/recovery: hostile, isolated offline regressions. Fixed IDs/targets remain reader scope or fixture inputs; no isolated historical-only move. |
| `test-issue311-r04r05-generic-live.py` | (a) | R04/R05 genuine generic App linkage + hostile independent watcher fixtures. Fixed IDs/targets remain reader scope or fixture inputs; no isolated historical-only move. |
| `test-issue311-r04r05-terminal-recovery.py` | (a) | Original expired 17-target failure reconciliation and hostile recovery tests. Fixed IDs/targets remain reader scope or fixture inputs; no isolated historical-only move. |
| `test-issue311-r05-eventgap17.py` | (a) | Exact-17 controlled no-listener source contract, no GitHub/secret access. Fixed IDs/targets remain reader scope or fixture inputs; no isolated historical-only move. |
| `test-issue311-r05-original-17repo.py` | (a) | R05 read-only 17-target static and hostile terminal contract tests. Fixed IDs/targets remain reader scope or fixture inputs; no isolated historical-only move. |
| `test-issue311-r05-unified17.py` | (a) | Regression: unified 17-target request fails closed on forgery and partial proof. Fixed IDs/targets remain reader scope or fixture inputs; no isolated historical-only move. |
| `test-issue311-r05-watchdog-http-faults.py` | (a) | HTTP 429/503 fault-injection contract only; never a real provider outage claim. Fixed IDs/targets remain reader scope or fixture inputs; no isolated historical-only move. |
| `test-issue311-r05-windows-17.py` | (a) | Issue311 R05 17 original Windows child completion events, ZIP terminal hostile tests. Fixed IDs/targets remain reader scope or fixture inputs; no isolated historical-only move. |
| `test-issue311-r05-windows-completion-bridge.py` | (a) | R05 live completed-event bridge hostile proof: reject absent children, ZIPs and privilege. Fixed IDs/targets remain reader scope or fixture inputs; no isolated historical-only move. |
| `test-issue311-r05-windows-positive.py` | (a) | R05 positive Windows original state transport: hostile fixtures, no tokens. Fixed IDs/targets remain reader scope or fixture inputs; no isolated historical-only move. |
| `test-issue311-r05-windows-probe.py` | (a) | R05 original Windows runner evidence/negative terminal fail-closed fixtures. Fixed IDs/targets remain reader scope or fixture inputs; no isolated historical-only move. |
| `test-issue311-r06-app-fleet-cas-auto.py` | (a) | Offline contract: real workflow_run completed -> independent App CAS; deny forged events. Fixed IDs/targets remain reader scope or fixture inputs; no isolated historical-only move. |
| `test-issue311-r06-app-fleet-cas-terminal.py` | (a) | R06 real 17 App CAS nonpublishing negative guard tests (OFFLINE ONLY). Fixed IDs/targets remain reader scope or fixture inputs; no isolated historical-only move. |
| `test-issue311-r06-child-join-live.py` | (a) | Offline hostile-boundary tests. No claim of genuine Run or live App CAS. Fixed IDs/targets remain reader scope or fixture inputs; no isolated historical-only move. |
| `test-issue311-r06-failed-cas-recovery.py` | (a) | Negative, offline-only tests for genuine failed CAS targeted recovery. Fixed IDs/targets remain reader scope or fixture inputs; no isolated historical-only move. |
| `test-issue311-r06-fleet-local-prepare.py` | (a) | Adversarial contract tests for shared, read-only local PREPARE gate. Fixed IDs/targets remain reader scope or fixture inputs; no isolated historical-only move. |
| `test-issue311-r06-hostile17-live.py` | (a) | R06 hostile source negative unit tests. No GitHub credentials or writes. Fixed IDs/targets remain reader scope or fixture inputs; no isolated historical-only move. |
| `test-issue311-r06-late-event-tombstone.py` | (a) | Fail-closed late-event, original request deadline and ambiguous App PUT regression. Fixed IDs/targets remain reader scope or fixture inputs; no isolated historical-only move. |
| `test-issue311-r06-local-child-join.py` | (a) | R06-05-02-02 negative policy tests. Fixtures do NOT represent real GitHub Runs. Fixed IDs/targets remain reader scope or fixture inputs; no isolated historical-only move. |
| `test-issue311-r06-local-sourcekind.py` | (a) | R06 request source-kind pilot: hostile original-ZIP/local candidate fixtures. Fixed IDs/targets remain reader scope or fixture inputs; no isolated historical-only move. |
| `test-issue311-r06-parallel-cas-original.py` | (a) | R06 original two-runner CAS: pure nonpublishing concurrency contract, no credentials. Fixed IDs/targets remain reader scope or fixture inputs; no isolated historical-only move. |
| `test-issue311-r06-prepare-scan.py` | (a) | Issue 311 R06: PREPARE is separate from AUDIT and genuine schedule; fail closed. Fixed IDs/targets remain reader scope or fixture inputs; no isolated historical-only move. |
| `test-issue311-r06-request-scan.py` | (a) | R06 read-only scan rejects partial, stale, fake and event-kind spoofing. Fixed IDs/targets remain reader scope or fixture inputs; no isolated historical-only move. |
| `test-issue311-r06-unattended-finite-guard.py` | (a) | R06 independent finite event-loss watchdog; OFFLINE negative policy only. Fixed IDs/targets remain reader scope or fixture inputs; no isolated historical-only move. |
| `test-issue311-r06-watchdog-expired-original.py` | (a) | R06: original GitHub Run time is immutable authority across request expiry. Fixed IDs/targets remain reader scope or fixture inputs; no isolated historical-only move. |
| `test-issue311-r08-app-oidc-intent.py` | (a) | R08 v2.1 App OIDC intent adversarial tests (NO CREDENTIALS / NO SIGNATURE). Fixed IDs/targets remain reader scope or fixture inputs; no isolated historical-only move. |
| `test-issue311-r08-app-sigstore.py` | (a) | R08 App-OIDC/dual Sigstore adversarial checks. MOCKS ARE NOT CRYPTOGRAPHY. Fixed IDs/targets remain reader scope or fixture inputs; no isolated historical-only move. |
| `test-issue311-r08-publisher-credential-deny.py` | (a) | Pure hostile R08-02 credentialed Publisher admission tests (NO CREDENTIALS). Fixed IDs/targets remain reader scope or fixture inputs; no isolated historical-only move. |
| `test-issue311-r08-publisher-deny.py` | (a) | R08-02 App -> independent Publisher DENY exhaustive hostile fixtures. Fixed IDs/targets remain reader scope or fixture inputs; no isolated historical-only move. |
| `test-issue311-r09-private-chain.py` | (a) | R09 private evidence key and Catalog/CLI/EN/JA hostile tests (NO PUBLICATION). Fixed IDs/targets remain reader scope or fixture inputs; no isolated historical-only move. |
| `test-issue311-r10-approval-state-original.py` | (a) | R10 genuine approval evidence-gap hostile fixtures; no network or App key. Fixed IDs/targets remain reader scope or fixture inputs; no isolated historical-only move. |
| `test-issue311-r10-dispatch-input-journal.py` | (a) | Offline hostile contract for durable original PRE-WRITE dispatch inputs. Fixed IDs/targets remain reader scope or fixture inputs; no isolated historical-only move. |
| `test-issue311-r10-final-readonly-report.py` | (a) | Offline adversarial R10-02 final-report tests; never network or credentials. Fixed IDs/targets remain reader scope or fixture inputs; no isolated historical-only move. |
| `test-issue311-r10-negative-originals.py` | (a) | Offline hostile guards for R10's negative originals. No network or App key. Fixed IDs/targets remain reader scope or fixture inputs; no isolated historical-only move. |
| `test-issue311-r10-negative-protected.py` | (b) | Pinned archive is still compared with independently recomputed original reports by active R10 proof workflows; keep integrity/count checks as live proof inputs. |
| `test-issue311-r10-protected-report.py` | (b) | Pinned archive is still compared with independently recomputed original reports by active R10 proof workflows; keep integrity/count checks as live proof inputs. |
| `test-issue311-r10-publisher-write-unknown.py` | (a) | R10-01 real formal Publisher code boundary: controlled missing write ACK. Fixed IDs/targets remain reader scope or fixture inputs; no isolated historical-only move. |
| `test-issue311-r10-replay-safe-id.py` | (a) | R10 replay-safe ID hostile tests; pure ID gate is not a live App CAS proof. Fixed IDs/targets remain reader scope or fixture inputs; no isolated historical-only move. |
| `test-issue311-r11-functional-boundaries.py` | (a)/(b) | R11 frozen workflow source and conservative job-boundary checks. Current no-retirement/scope policy; retain exact inventories/pins conservatively. |
| `test-issue311-r11-migration-inventory.py` | (a)/(b) | Hostile offline R11 gate tests. No network and no authority to migrate. Current no-retirement/scope policy; retain exact inventories/pins conservatively. |
| `test-issue311-r11-overlap-preflight.py` | (a)/(b) | Offline hostile input checks for Issue #311 R11 active Run inventory. Current no-retirement/scope policy; retain exact inventories/pins conservatively. |
| `test-issue311-r11-transition-controls.py` | (a)/(b) | R11 hostile regression for writer scope, ACK boundedness, and 20-repo crosswalk. Current no-retirement/scope policy; retain exact inventories/pins conservatively. |
| `test-issue311-request-contract.py` | (a) | Issue #311 R03 inert request contract deny fixtures (NO PUBLISH). Fixed IDs/targets remain reader scope or fixture inputs; no isolated historical-only move. |
| `test-issue311-request-lifecycle.py` | (a) | Hostile R04/R05 general request lifecycle; no App token, no publication. Fixed IDs/targets remain reader scope or fixture inputs; no isolated historical-only move. |
| `test-issue311-state-core.py` | (a) | Issue 311 R04 pure CAS/state denial fixtures (NO RELEASE, NO WRITE). Fixed IDs/targets remain reader scope or fixture inputs; no isolated historical-only move. |
| `test-issue311-state-github.py` | (a) | R04 CAS in-memory storage, hostile lease and ambiguous write regressions. Fixed IDs/targets remain reader scope or fixture inputs; no isolated historical-only move. |
| `test-issue311-v23-effective-approval.py` | (a) | R10 v2.3: prevent reintroduction of a fictitious second human approval gate. Fixed IDs/targets remain reader scope or fixture inputs; no isolated historical-only move. |
| `test-issue311-writer-runtime.py` | (a) | Issue311 dedicated Writer: offline hostile CAS, fencing, claim and scope tests. Fixed IDs/targets remain reader scope or fixture inputs; no isolated historical-only move. |

R10 reader dependency: `issue311-r10-final-readonly-report.yml` runs
`issue311-r10-protected-report.py --verify` in both source and independent
readback jobs. `issue311-r10-negative-protected.py` similarly restores/compares
the negative-original archive. These are not treated as retired ledgers.

## B13 and related workflow tests

| Candidate | Class and disposition |
| --- | --- |
| `test-issue-75-main-publisher-guard.py` (all 10 tests) | (a), stays. `fleet-publish-release.py` imports `issue-75-publisher-preflight.py`; live manual Publisher actor, attempt, signer, source, API/job and TOCTOU denial. Observed unsigned historical dispatch cannot become a signed Publisher. |
| `test-issue-75-attempt-provenance-readonly.py` (all 8 tests) | (a), stays. Synthetic provenance is never cryptographic verification or publication authority; rejects signer/attempt/digest/API mismatches. |
| `test-issue-75-attempt-pin-migration-offline.py` (all 10 tests) | (a), stays. Inert migration never grants publication; verifies scope, per-major identity, stale tag/Release and unknown-write quarantine. PRE-G4 alone does not justify moving it. |
| `test-publication-migration-plan.py`: all six functional tests | (a), stays. Apply templates, preserve signer/detector/source files/required checks and non-authority flags; registered growth and malformed/stale/unsafe inputs. Only the exact `review-templates.json` equality assertion is (c), moved into a separate history test. |
| `test-shared-manual-promotion.py`: job-label check | (a)/(b), stays. `issue-75-publisher-preflight.py` uses these labels as live job selectors. |
| Same: `test_legacy_thirteen_central_source_matches_proven_release_body` | Mixed. Active legacy workflow entrance, concurrency, helper pins, prewrite guard contents and ordering stay (a). Only the whole-job equality to the frozen normalized fixture moves (c). |
| Same: `test_legacy_thirteen_source_parity_snapshot_is_not_a_publish_grant` | Mixed. Fixed 13/4 identities, old commit pins and fixture text move (c). Ledger non-authority declarations stay in `test_historical_shared_shadow_cannot_grant_publication`; current target allowlist/manual gate/signer remain in the existing live workflow tests. |
| Same: `test_legacy_parity_fixture_hostile_removal_would_be_detected` | (c), moves. Mutates only frozen fixture text, with no production reader. |
| Same: `test_two_deployed_shared_pins_are_one_byte_identical_inert_blob` | (c), moves. Past Git blob and old caller-pin equality, archived body/13-vs-4 layout. Current catalog opt-in, target scope, signer and no-authority checks remain normal. |
| Same: all other tests | (a)/(b), stay. Current manual confirmation, exact target authorization, signer, create-only Publisher, catalog opt-in/dependency/permissions and backend contracts. |
| `test-github-actions-security.py`: archived `release-extension.yml` block | (c), moves. Archived create-only body/asset counts/notes. Normal suite explicitly forbids reintroducing retired workflow filenames. All active workflow trust checks remain. |
| Same: version comments/step names | Stays conservatively; broader expression cleanup is outside this historical separation. Active SHA pins, signer, permissions and order semantics are unchanged. |
| `tests/fixtures/historical-workflows/chocolatey-components-benchmark.yml` | (a)/ambiguous, stays in `test-postgresql-component-only.py`; installer-component/runtime contract is out of scope. |
| Other retired Issue75 workflow fixtures | No existing normal body re-proof to move; retain inert archive. Normal suite forbids restoring the retired filenames. |

Dependency search: `promotion-legacy-parity-20261021.json`,
`issue-75-legacy-promotion-normalized.txt` and
`issue-75-historical-shared-promotion.txt` are referenced only in tests/docs,
not production scripts or active workflow readers. The migration snapshot and
observed heads remain test inputs for the functional planner tests; only the
frozen generated output equality moves. `publication_policy_fixtures.py` is a
live test helper, so its manual policy fixture remains a normal-suite input.

## Selection and triggers

History tests live in `tests/history/`, outside the existing root-level
`tests/test-*.py` normal/projection glob. The separate `history` job follows the
existing path-filtered publication-policy projection workflow: PR and main push
paths plus manual dispatch, read-only token, pinned checkout/Python actions.
It runs no online historical proof, signer or Publisher. The normal resolver
job name and required checks are unchanged.

Commands and final counts are recorded after implementation below and in
`../PROGRESS-C.md` in the task workspace.
