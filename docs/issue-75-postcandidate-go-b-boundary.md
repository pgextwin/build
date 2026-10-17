# Issue #75 — v2.10.15 unsigned candidate to GO B boundary

Status: **PASS_UNSIGNED_CANDIDATE_ORIGINAL_BYTES / GO_B_NO_GO / G4_NO_GO / G5_NO_GO** (2026-10-17 JST). This document records an actual *unsigned* candidate and separates it from the deployed signed Publisher path. It is **nonpublishing**: no release, tag, signer, receipt, policy, workflow dispatch, credential or pin mutation is authorized by this record.

## Exact authenticated candidate evidence

- [Work original-byte report](https://github.com/pgextwin/build/issues/75#issuecomment-6232461775), [candidate Run 39021934569](https://github.com/pgextwin/plpgsql_check/actions/runs/39021934569): `workflow_dispatch`, `run_attempt=1`, `completed/success`, 9/9 successful jobs, five PG14–18 Windows artifacts plus one candidate-audit.
- Candidate PR [plpgsql_check #29](https://github.com/pgextwin/plpgsql_check/pull/29) is **OPEN/DRAFT**, latest audited head `4899b5c1da8e2fb681381fff4fa2ab41882cb0bc`, branch `auto-candidate/29d1c1984a1b44a55107`. Protected pilot `main@98452723fcad2aedafb1c02a210f35950f7e8cf2`. A new main/head requires fresh confirmation.
- Candidate-audit artifact ID **12096694791**, API outer artifact `sha256:3f8aaadbf417b749327052a3e5a0a5fbd964bce63bde4d04fb030bc8a3db0c73`; decision Run **38356841007**, decision artifact ID **11792029988**. Work independently downloaded and hashed all six original candidate artifacts and the original decision. This repository's tests **do not** re-download bytes or elevate that report into signature verification.
- Immutable upstream: `okbob/plpgsql_check` version `2.10.15`, ref `v2.10.15`, source full SHA `0ac96adc13b34d071c4be8ba0ec4f73e6e7520f5`; decision candidateId `29d1c1984a1b44a55107`. Each ZIP's PACKAGE-INFO, SPDX and Grype were joined to actual per-major SHA256 and metadata in the original audit. candidate-audit schema has no direct candidateId/version/ref fields; the audit proved those transitively via branch, original inner ZIP digests, PACKAGE-INFO and the decision.
- Inner ZIP SHA256: PG14 `c17fc1a68474452979233a540e704ea376feda3451ce976935b08f01c5a54819`; PG15 `ec3f3884eef34b210564434e7c274198a0d70ba0d37166c122c22868b39a9eff`; PG16 `bfcb3207df8fb88293560f27ff8f0b16f21ca63b85755a77f5ebd78b69cee1de`; PG17 `a7532b0dfbe3d13c2c40bbc1e89074b3e6ed46e6d2897dbac1da6892eecde50e`; PG18 `8b0f7368aa6b764185fdc2780e12095a8c4ea8cac10733ac07d42eb1dbaca106`.
- Candidate audit report step encountered `REPORT_ONLY_403` for its attempted automatic PR comment. The independent artifact was successfully generated and verified; a PR comment success is not claimed. **No second unsigned dispatch is needed.**

## Runtime Publisher delta: current source != deployed executable

Exact `plpgsql_check/main` [promote.yml](https://github.com/pgextwin/plpgsql_check/blob/98452723fcad2aedafb1c02a210f35950f7e8cf2/.github/workflows/promote.yml) still uses `workflow_dispatch` only and checks out common build scripts for *both authorize and publish* at immutable **`455f0ccc667697f600700a6e64bcfd6c57b6a977`**.

| Capability | Currently deployed old pin (Publisher Git Blob `85cbe8e6893477210831c6a813fe796f23d7eb08`) | Newer protected build/main (Publisher Git Blob `0ba9700d9b4472d62bdd7137347e4194438a9e66`) |
| --- | --- | --- |
| PACKAGE-INFO `workflowRun.attempt` and cross-major binding | **Missing** | Implemented |
| `gh attestation verify --signer-digest/--source-digest` | **Missing** | Implemented |
| Independent in-progress attempt-scoped Actions jobs and prewrite TOCTOU checks | **Missing** | Implemented in newer code |
| Persist reservation HTTP/ref result, immutable Release ID, per-asset digest inventory in a crash-safe schema v2 | **Missing** | **Still missing from active Publisher code**; [pure classifier](../scripts/release-recovery-evidence.py) is deliberately not linked to write path |

The reusable signer remains pinned to **`5756b3c5136a8bf4db710016cfe97555f0a71c6d`**. **Never substitute build/main tests for the actual old pin.** Existing [frozen legacy attempt-gap regression](../tests/test-fleet-publish-release.py) demonstrates the discrepancy. The new nonpublishing regression in [test-issue-75-main-publisher-guard.py](../tests/test-issue-75-main-publisher-guard.py) passes the *actual observed* unsigned Run identity through the future Publisher's pure signed preflight and requires strict DENY even if the candidate claims all jobs successful or supplies an invented `VERIFIED` JSON.

## Remaining ordered gates

1. **GO B / positive signed Publisher prewrite:** separately approved, write-isolated, **real attempt-scoped** promoted-main `promote.yml` topology and independently verified ten X.509 SLSA/SPDX signatures; the sign-only canary does not have the Publisher job topology. Existing [GO A canary 39008743613](https://github.com/pgextwin/plpgsql_check/actions/runs/39008743613) remains `completed/failure`; it is not waived or retried.
2. **Publisher pin cutover:** only after independently reviewing the exact new immutable build commit, full dependency closure and permission separation; pilot-only protected PR, App15368 required 8/8 and postmerge checks. A documentation PR or this negative test does **not** authorize repinning or changing publication capability.
3. **Real-state JIT, atomic release creation and fail-closed recovery:** two authenticated positive checks immediately before privileged write, create-only tag conflict/race/422 handling, immutable draft/publication Release ID, asset IDs and verified SHA256, crash-safe recovery with `UNKNOWN_QUARANTINE` for unknown POST/PATCH/GET states. No automatic retry or draft repair from missing evidence.
4. **G4** genuine authorization: separately authorized human target-bound `PUBLISH`, trusted actor/PR/merge semantics and least-privilege writer isolation. Never infer intent from a bot comment, an unsigned candidate or a mocked signed result.
5. **G5** independent fresh successful new promotion, actual ZIP/SPDX/Grype/SLSA+SPDX attestations per PG, create-only `v2.10.15-windows.1`, Catalog verified single-record protected PR and public Website Japanese/English verification. Subsequently run Issue #112's **separate** P1 reassessment rather than automatically crediting five historical rows.

This snapshot preserves central/local `manual-dispatch`, fleet `manual-only`, candidate PR #29 DRAFT, original GO A failure, **GO B/G4/G5 NO-GO**, Issue #112 formal P1 **65/70**, historical source **40/40**, plpgsql_check PG14–18 **five DENY**, publication/distribution **DENY**. No new signed assets, credential, Release, tag or actual Writer call.
