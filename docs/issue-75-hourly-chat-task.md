# Issue #75 — hourly ChatGPT task, one shared 17-extension queue

## Delivered in this stage

One scheduled ChatGPT task runs every hour (JST) with the existing connected
GitHub account, subject to that account's app permissions and task approvals.
No additional GitHub App, secret, runner, Release trigger or GUI step is needed.

The existing `fleet-status.py` continues to fetch the live status for the
**same 17 entries** in `metadata/automation-fleet.json`. It now embeds
`hourlyChatQueue` in its JSON output and a nonpublishing task section in its
Markdown. The central queue policy and hostile regression cases live in
`scripts/chat-task-queue.py` and `tests/test-chat-task-queue.py`.

The queue is deterministic triage, NOT a trusted verification receipt:

- `PREPARE_CANDIDATE`: re-fetch protected main/upstream pinned SHA and
  create a candidate PR with the connected human GitHub actor if permitted.
- `REVIEW_CANDIDATE`: independently verify exact PR head, Windows matrix,
  required App check, upstream license/diff and candidate audit **before**
  protected merge; no stale PR run or `action_required` may count as success.
- `INVESTIGATE_CI` / `INVESTIGATE_EVIDENCE`: examine failures and take
  only scoped nonpublishing corrective PR steps.
- No pending action means no notification or redundant rerun.

The task must repeat fresh GitHub GET even if `fleet-status` looks healthy.
No queue item contains `PUBLISH`, operator authorization, a publishable
receipt or permission to create a Release. The separate immutable 17-extension
manual Promotion and signature/attestation/ZIP/SBOM gates remain unchanged.
Catalog/Website are still reconciled from real independently verified
public Releases, never from a candidate-only status.

## Explicit operator publication remains separate

An **hourly schedule is not a per-version human PUBLISH decision**. Never
automatically merge a `.github/release-authorizations/*.json` authorization,
start a signed Publisher or create a new tag merely because an update exists.
A human must name the intended extension and version/tag and authorize that
particular release. This stage retains the working manual `promote.yml`
fallback on all 17 repositories.

`scripts/chat-pr-authorization.py` already has an offline strict-schema
PR parser and hostile tests. It is deliberately *inert*: it cannot be used
as a live signed Publisher receipt. Enabling PR-to-publish would additionally
require protected-main event and real operator identity proof, immutable
candidate/decision evidence, signed artifact verification, exact-head
required CI, one-time create-only tag checks and successful nonpublishing
end-to-end event observation before protected rollout. See Issue #75.

## Scope / acceptance

1. Existing 17/17 published extensions and all successful Windows runs stay
   unchanged; do not reissue formal releases to exercise the task.
2. New authenticated Chat-created protected PR should trigger the existing
   `build/validate.yml` required `resolver` without a Work-only
   `Approve and run`. Observe actual Actions outcome; this is a **pilot**,
   not an assumption about app identity.
3. The queue must fail closed for unknown, duplicated, partial or
   incorrectly scoped snapshots; task decisions must never grant release.
4. Follow-up Issue #75 changes should reuse the existing central schema,
   signer and Publisher; do not add parallel release engines or privilege
   bypasses.

## 日本語での運用

- 毎時：既存17拡張の候補、CI、公開証跡を確認し、非公開作業だけを進める。
- 問題なし：通知・再実行なし。問題あり：対象PR、Run、失敗理由を報告する。
- 正式公開：利用者が**対象拡張とタグ**を明示して認可するまで実施しない。
- Chatの接続で必要な権限が不足・承認待ちなら、無理に迂回しない。
