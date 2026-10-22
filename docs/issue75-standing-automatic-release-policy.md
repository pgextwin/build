# Issue #75 — standing owner approval for all verified new stable versions

Status: **Phase 1, read-only automatic-release preflight**; rollout and unattended publication are NOT yet enabled.

## Updated 2026-10-22 owner decision

The operator authorizes prospective Releases for all 17 extensions **without a separate human PUBLISH click for each version**. Existing historical Windows Releases remain immutable and accessible. Approval is conditional on independently verified technical gates: exact upstream full SHA, source/license identity, candidate audit and exact maintained-major Windows CI, real attested build, SLSA/SPDX/Sigstore, ZIP SHA256, protected branch, tag absence and create-only publication. A failed or insufficient candidate never publishes.

## Existing proven reusable components

- 17 extensions share `build/metadata/automation-fleet.json` and common signed Promotion workflow entrypoints. Deployed promotion is still **manual-dispatch** on both central and local protected main, and is retained as rollback.
- build PR #216 (protected merged main `f4e359b4812d435dd72b8e22f9b522cd8bc5b981`) proves authenticated Chat PR with native App15368 required CI, then real signed-off human actor on main/push and a shared nonpublishing 17-extension queue.
- Existing `scripts/chat-pr-authorization.py`, `scripts/fleet-promotion-gate.py`, `scripts/fleet-publish-release.py` and `scripts/release-authorization.py` contain candidate/push policy and signed Publisher checks. Do not create a parallel Publisher or accept mock receipt data.

## Phase 1 deliverable in this PR

`scripts/automatic-release-preflight.py` checks a narrow authenticated candidate-merge *shape*: main push, single parent and single manifest change, allowlisted human merger, bot-authored merged candidate PR, exact-head App15368 Windows required summary and complete matrix, successful candidate/decision/audit identities, and an unused stable release tag. It checks exactly 17 central fleet entries. Invalid/bot/old/partial/duplicate/status-failure fixtures fail closed. The central required `resolver` runs its tests.

**Crucial boundary:** Inputs to this pure module are not independently fetched or cryptographically verified; therefore its successful output is always `publicationAuthorized=false`, `publishableReceipt=false`, `signedArtifactsVerified=false`, `automaticReleaseEnabled=false`. It cannot authorize a Release, even when fixtures pass. No real Release event is added in this PR, no policy flag is switched and no publisher/Signer code is modified.

## Next guarded production stages (sequential)

1. **Trusted push/PR event attestation**: select one safe extension pilot; use the already-proven Chat/GitHub identity and a trusted main-push runner to GET exact GitHub PR+merge metadata, effective protection and App15368 required CI, candidate-decision and candidate-audit artifacts and original SHA. Accept only cryptographically/metadata matched facts. Pilot must be nonpublishing.
2. **Typed automatic promotion receipt**: reuse current shared `fleet-promotion-gate.py` candidate authorization and `fleet-publish-release.py` genuine signed ZIP/SPDX/SLSA checks. Add explicitly guarded `automatic-verified` mode, not an environment override of `workflow_dispatch`, and require the immutable candidate event plus standing owner policy, not an arbitrary schedule or issue comment. A scheduler's existence is not evidence.
3. **Single real Release acceptance**: only when one existing eligible new stable version passes protected PR, CI and postmerge, validate new signed assets, no existing tag/Release overwritten. Keep current manual workflow as fallback until accepted.
4. **17/17 rollout**: same thin caller and config per extension, immutable shared source; no extra App/Secret/reviewer or UI gate, do not duplicate successful CI.
5. **Catalog reconciliation**: reuse existing independent signature+asset verifier and catalog-only proposer App to create **one protected PR per newly published verified Release**. Keep CLI signed feed and Website JA/EN workflows; Chat handles protected Catalog PR merge if required; no publication of unsigned candidate metadata.

The hourly Chat task may monitor, create candidate PRs and handle CI within its permissions. Once stages 1–4 have passed, the standing owner opt-in permits an authenticated scheduled task to prepare narrowly scoped requests for **eligible** versions, but it must not turn observations or failed CI into a signed publication receipt.

Issue #75 stays open until an actual 17/17 supported no-GUI path and Release→Catalog→CLI→JA/EN Website have been independently verified.