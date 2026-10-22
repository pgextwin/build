# Issue #75 — Chat-authored protected-PR push trigger pilot (NON-PUBLISHING)

Date: 2026-10-22 JST. Scope: `pgextwin/build` only, all 17 extension policies unchanged.

## Goal and evidence contract

Prove that the **currently connected normal Chat GitHub identity** can create a same-repository PR, pass the existing protected `resolver` check (GitHub Actions App 15368), squash-merge normally and cause an authentic `main` **push** workflow run. This step cannot sign, create a tag or publish a Release.

This document is the intentionally harmless one-file payload for that first test. It must be merged via the normal protected PR path, not by a direct write to main. The final evidence must identify the PR, exact PR-head SHA, required-check run, merged main SHA, push event/run ID, real GitHub actor and triggering actor, and the absence of any tag/Release creation.

### Conditions to call the probe PASS

1. Authenticated Chat connector creates this one-file PR with expected head and base. The PR is not written by `github-actions[bot]`.
2. The exact PR head receives the existing `resolver` **SUCCESS** from App 15368. Branch protection stays on; no bypass, temporary relaxation, or manual `Approve and run`.
3. The PR is merged using existing branch protection with an expected-head lease, preferably squash. The merged commit must include only this harmless documentation file.
4. A new `Validate build infrastructure` workflow has event=`push`, branch=`main`, head SHA exactly equal to the merged commit and eventually conclusion=`success`; record the actor from GitHub's run metadata, not guesses.
5. There are zero newly-created Release tags, signatures, PUBLISH requests or catalog proposals attributable to this pilot.

If any condition cannot be independently observed, record **NOT VERIFIED**, not success.

## What this proves and what remains

This is an **event delivery and identity** probe, **not** authorization to publish. A Chat-created PR push that runs the existing read-only validation will not by itself establish effective branch-rule provenance, candidate provenance, signed-artifact attestation, or a trusted release authorization receipt.

The follow-on design will reuse existing strict offline `scripts/chat-pr-authorization.py` and `tests/test-chat-pr-authorization.py` plus the current 17-member `metadata/release-promotion.json`. Authorize publication only for a new exact-scope protected authorization PR with independently verified merged-by identity, exact PR-head CI, unique tag, signed candidate/artifact evidence and positive central/local policy. Never treat a GitHub push, schedule, hourly ChatGPT task or ordinary candidate PR as implied permission to publish. Preserve the existing human-dispatched signed Publisher as rollback until a real eligible release demonstrates the complete alternative.

No workflow, secret, permission, GitHub App, policy, CI requirement, extension config or public distribution is changed in this probe.
