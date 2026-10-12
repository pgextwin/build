# ADR-0075: Chat-authorized publication via protected one-record PR

Status: **PROPOSED — DESIGN ONLY; NEVER PUBLISH FROM THIS ADR**
Date: 2026-10-12 JST
Tracking: https://github.com/pgextwin/build/issues/75
Related foundation: https://github.com/pgextwin/build/issues/61
Contract: [chat-first-publication.md](chat-first-publication.md)

## 日本語の決定概要

従来の `workflow_dispatch` 操作を通常Chatから行えずWorkへ引き継ぐ問題を、認証済みGitHub接続の「公開承認PRの作成・厳格な検証・マージ」で解消する。正式Releaseは利用者が通常Chatに対して**対象を指定して明示的に公開依頼した場合に限る**。GitHubのマージ記録がその依頼を暗号学的に証明するわけではない。Chatは承認がない限り公開承認PRを作成・マージしない。候補の自動マージ・正式Releaseの無人公開・Catalogの自動マージは導入しない。

実装初期状態は**無効**。`#61` の13拡張main保護不足を解消し、通常Chatの作成／マージイベントが人間主体としてGitHubに記録される非公開テストを受け入れるまで、公開可能な新トリガーを有効化しない。既存の手動PUBLISH・復旧手順はパイロット期間中のフォールバックとして保持する。

## Verified current implementation, 2026-10-12

- All 14 extension `.github/workflows/promote.yml`: `workflow_dispatch` only, central `fleet-promotion-gate.py`, reusable signed `build-extension-attested.yml`, immutable publisher. None inspected supports new `push` publication.
- Central `metadata/automation-fleet.json`: 14/14 BUILD, manual-only, daily 00:00 UTC. Central `metadata/release-promotion.json` and local `config/release-promotion.json`: `manual-dispatch`.
- `scripts/fleet-promotion-gate.py` explicitly requires `GITHUB_EVENT_NAME=workflow_dispatch`, human/nonbot `GITHUB_ACTOR`, request data and full candidate decision/audit evidence. Its receipt is `VERIFIED_MANUAL_DISPATCH` + `authorizationMode=manual-dispatch`.
- `scripts/fleet-publish-release.py` independently requires the above receipt, `GITHUB_EVENT_NAME=workflow_dispatch` and matching operator. Each ZIP's `PACKAGE-INFO.json` is verified to contain `workflowRun.event=workflow_dispatch`. Merely adding a `push` trigger to `promote.yml` would be rejected. This is a useful existing fail-closed boundary.
- `build-extension-attested.yml` populates `WorkflowEvent` using `github.event_name` via `finalize-package.ps1`, so the new mode must explicitly preserve and verify event provenance through PACKAGE-INFO and receipt.
- `scripts/candidate-update.py` currently invokes `gh workflow run windows.yml --ref <auto-candidate-branch>` from scheduled Actions when required; this GitHub-internal dispatch is permitted and is **not** the Work-only handoff.
- `catalog/.github/workflows/sync-verified-release.yml` is manual-dispatch based; the existing catalog-scoped App can propose a verified single-record PR. E2E wal2json 2.7 -> Catalog PR #54 -> EN/JA Website has been accepted under #61.
- #61 audit reports 13/14 extension `main` branches unprotected; `plpgsql_check` is the exception. Branch protection must be independently reconfirmed when enabling any publisher.

## Proposed architecture and trust boundary

1. **Detection and candidate build:** current scheduled watch, full upstream SHA pin, bot-owned immutable candidate PR and dispatched Windows matrix remain unchanged. Chat independently checks evidence and merges only a valid exact-head candidate. No candidate auto-merge.
2. **Human intent:** user requests publication of an unambiguously named, already verified candidate in a normal Chat. Chat's connected GitHub session is the transaction initiator; a GitHub PR cannot by itself attest what was typed in the chat.
3. **One narrowly scoped authorization PR:** Chat writes exactly one new `.github/release-authorizations/<tag>.json` file in a new branch from the current, validated packaging `main`; opens the PR, checks *the exact PR head* and protected required checks, then merges **squash only** with expected head SHA. This is a public-release authorization, not an extension-code change.
4. **GitHub push-triggered trusted entrypoint:** a minimal extension `authorize-pr-release.yml` may listen to `push` on `main` with the authorization path filter. The filter is ONLY optimization, never sufficient authorization. It executes a shared read-only verifier from an immutable SHA and does not execute untrusted PR scripts.
5. **Gate independent of request text:** before any artifact build or write token, validate the live repo, `main`/event SHA, raw `push.before`, merge-created commit topology, exact one-file change, GitHub PR API's `merged=true`, `merge_commit_sha=GITHUB_SHA`, squash-only operation, repository and base ref, authentic `merged_by` and `GITHUB_ACTOR` identity, currently allowed human operator, approved exact-head CI, one fresh request and currently matching central/local opt-in.
6. **Candidate equivalence:** match the request to merged automation-owned candidate PR, immutable `candidate-decision` run and independently verified full maintained-PG Windows matrix at exact candidate head. `packagingMainSha` must equal the actual pre-authorization `main` commit (`push.before` / single parent). Check absence of unrelated manifest/code changes, stale source refs and tag collisions.
7. **Receipt and publisher:** produce a new typed receipt (for example `VERIFIED_CHAT_PR_AUTHORIZATION`, `authorizationMode=chat-pr-authorization`) containing operator, authorization PR/commit, candidate evidence and exact event type. Shared publisher and PACKAGE-INFO checks must accept **only the matching tuple of receipt mode + event + actor + commit** and must keep manual dispatch mode intact. Never infer successful authentication from literal `PUBLISH` alone.
8. **Signed build/release:** reuse immutable signed builder and current create-only publisher, provenance/SPDX SBOM/Grype(report-only)/SHA256 validation, tag reservation, recovery artifact and concurrency controls. No rewriting/deleting old tags/Releases.
9. **Catalog:** a separate opt-in scheduled reconciler reads trusted public stable Releases and compares each to catalog main, performs the existing independent asset+attestation verifier, then the existing catalog-only App proposes **one** record PR for a monotonic/eligible newer release. No Catalog auto-merge or new broad GitHub App. The Chat still audits and merges Catalog PR; existing Website verification remains unchanged.

### Example authorization JSON — SCHEMA PROPOSAL ONLY

```json
{
  "schemaVersion": 1,
  "type": "pgextwin-chat-authorized-release",
  "repository": "pgextwin/example_extension",
  "releaseTag": "vX.Y.Z-windows.N",
  "packagingMainSha": "<full 40-hex SHA before authorization merge>",
  "candidatePr": 123,
  "candidateHeadSha": "<full 40-hex SHA>",
  "candidateRunId": 123456789,
  "decisionRunId": 123456788,
  "operatorLogin": "<authenticated allowlisted human GitHub login>",
  "confirmRelease": "PUBLISH"
}
```

Schema must reject unknown keys, extra files, paths outside this directory, reused tags/requests, unmerged or bot-merged requests, malformed values and timestamps that cannot be verified. The example is not a valid release request, must not be committed under `.github/release-authorizations/` and authorizes nothing.

## Threat model / fail-closed responses

| Threat / failure | Required mitigation |
| --- | --- |
| Anyone writes `PUBLISH` in a PR/comment, or edits an Issue | Trigger only from trusted protected-main merge; require exact PR/merge/actor/API provenance, not text or Issue events |
| Direct push, unrelated merge, forged Git author, PR body spoof | Verify matching merged PR, exact resulting SHA/parent and one-file diff using live GitHub API; do not trust commit author/PR description |
| GitHub connector authenticates as an unexpected bot or events suppressed | Harmless dry-run PR+merge identity/event probe first; deny if `merged_by` / `GITHUB_ACTOR` cannot prove permitted human; **never weaken to bot-friendly fallback** |
| Stale candidate, source retagging, PG major EOL, license/ABI change | Re-run current upstream/full SHA and candidate decision/audit checks; use latest applicable maintained-PG major matrix and reject drift |
| CI status green on the wrong commit or missing branch protection | Validate required checks at exact PR head and GitHub's effective branch/ruleset enforcement; #61 dependency |
| Race: main advances between review and merge/event | Require authorization's packagingMainSha == actual `push.before` and merge first parent; require current main == event SHA; fail closed if advanced |
| Duplicate, replay, partial Draft, occupied release tag | Verify unique request/tag and no existing tag/Release; atomic create-only semantics, serialized per extension; preserve recovery evidence |
| Privileged `pull_request_target` executes attacker code | Never run untrusted head code with write credentials; trusted base checkout + read-only independent validation first |
| Auth file sneaks a workflow or source change through same PR | Explicitly require the exact single new authorization JSON file, no deletions/renames/multiple files; gate checks full PR/commit diff |
| Secrets/GitHub App token broadened | Avoid new privilege; Catalog App remains scoped only to Catalog contents/PR proposals |
| Auto Catalog reconciler republishes historic or untrusted versions | Independent public Release signature+asset verification, exact tag checks, monotonic guard, existing/prior proposal dedupe; no automatic Catalog merge |

## GitHub event semantics to prove (NOT assumed)

GitHub official documentation: `GITHUB_TOKEN`-initiated push normally suppresses dependent workflow runs; `workflow_dispatch` and `repository_dispatch` are exceptions. PR events created by workflows may require additional approval. An authenticated user/installation token can have different semantics.

Reference: https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/trigger-a-workflow

Required safe experiment:
- In a **non-publishing**, CI-protected context, create a docs-only PR with normal Chat's connected GitHub account, verify `user.login`, exact head and checks. If a harmless merge is authorized, inspect GitHub `merged_by.login`, event `GITHUB_ACTOR`, main push Workflow run creation and event SHA. Verify no bot origin/suppressed event. The experiment cannot use real authorization file names/triggers.
- Existing Catalog #54 was created by `pgextwin-catalog-proposer[bot]` and merged via normal Chat, but the current connector's normalized PR result does not expose `merged_by`. Do not claim operator identity is proven until direct GitHub event/API evidence is obtained.
- If connector-authored PR or merge events cannot be traced to an allowed human, the design remains BLOCKED and alternate narrow authenticated approval mechanisms require a separate security review.

## Proposed implementation work decomposition

1. **Dependency #61:** enforced branch protection + stable required exact-head CI across 13 extension mains, no external reviewer requirement. Handle PG14 end-of-life (2026-11-12) with maintained-major-aware stable aggregate check.
2. **Central mode:** add opt-in schema policy `chat-pr-authorization` while default remains `manual-dispatch`/OBSERVE-DENY; never flip `automaticFormalRelease` to true.
3. **Gate:** refactor `fleet-promotion-gate.py` into shared candidate-evidence verifier plus independent manual/PR authorization paths; emit unambiguous typed receipts; require safe merge-commit topology.
4. **Publisher and package verifier:** update `fleet-publish-release.py` and event checks plus `PACKAGE-INFO` verification to accept the exact new receipt/event tuple; retain all original manual and tag invariants.
5. **Workflow:** add trusted shared reusable entrypoint and thin caller wrapper for one pilot extension, with strict main/path filters, least-privilege jobs and non-publishing dry-run mode. Do NOT enable a live push publisher in Phase A.
6. **Tests:** malformed/unknown schema, wrong actor/bot, direct push, unmerged PR, wrong merge SHA/base/parent, second file, stale main, candidate SHA/run mismatch, tag collision, replay/race, failed/skipped CI, PG matrix/EOL, forged PACKAGE-INFO event, invalid receipt tuple, no secret exposure. Also positive inert fixture proof of exact intended tuple.
7. **Catalog:** separate opt-in scheduled verifier/reconciler using existing catalog-only App and single-record PR with actual rehash/signatures; test no-op on already-catalogued wal2json 2.7 without duplicate proposal.
8. **Pilot and fleet:** after dependencies and inert tests pass, migrate one extension, observe a genuine future eligible publish, then deploy progressively to all 14. Central policy last; publish stays explicitly user-initiated.

## Phase A exit criteria

- [x] 14/14 promoter/central entrypoint inventory and hard-coded manual gate identified.
- [x] PACKAGING metadata + publisher mode coupling identified.
- [x] Current candidate and Catalog dispatch dependencies identified.
- [x] Threat model and negative test inventory documented.
- [ ] Independently demonstrate GitHub-connector-authored user PR, user `merged_by` and real nonpublishing push-event behavior.
- [ ] #61 extension main protection independently completed.
- [ ] Shared design reviewed with exact API contracts and initial test fixtures; no production enabling before then.

**No Release dispatch, tag creation, publishing workflow modification, permission changes, branch-rule changes or App-secret manipulation is authorized by this ADR.**
