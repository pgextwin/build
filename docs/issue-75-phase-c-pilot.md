# Issue #75 Phase C — plpgsql_check read-only pilot plan

Status: **DRAFT / NO PUBLICATION AUTHORITY** (2026-10-12 JST)  
Owner: pgextwin/build Issue #75. Depends on Issue #61.  
Phase B shared validators: merged Build PR #77.

## Provisional choice and non-goals

Use **pgextwin/plpgsql_check** only as a *provisional* pilot because GitHub's
`GET /branches/main` reports `protected=true` for this one extension, whereas
the other thirteen extension main branches report `protected=false`.
The standard Chat GitHub connector receives HTTP 403 for the detailed
`/branches/main/protection` endpoint; this **does not establish required CI,
PR-only enforcement, admin/bypass configuration or zero-review policy**.
Effective protection must be independently proven with appropriately scoped
read permissions BEFORE any live path. No other extension is changed here.

**Nothing in this PR creates a publication authorization, runs a workflow,
enables a push publisher, changes a local/central opt-in, produces a signed
publication receipt, writes a tag/Release, edits a secret or broadens GitHub
App permissions.** The existing manual `workflow_dispatch` PUBLISH remains
the only production publisher.

## Safe testable groundwork

- `scripts/chat-pr-pilot-evidence.py` exports `GitHubReadOnly` (REST GET only)
  and `inspect_pilot(api, event, runtime_*, allowed_operators)`. There is
  **no __main__ or Actions workflow entrypoint**: it cannot publish.
- The future trusted runner must bind `event` to GitHub's push payload, the
  runtime values to protected Actions-provided `GITHUB_REPOSITORY`,
  `GITHUB_REF`, `GITHUB_SHA` and `GITHUB_ACTOR` (not PR-provided values),
  and the allowlist to a protected repository-owned central configuration.
- Collector independently reads current main, squash commit, commit-linked
  merged PR, exact one-file PR diff, committed Git blob, branch protection,
  app-bound **exact-head** required check runs, candidate PR, candidate/decision
  run status, and absence of both Release tag and public Release.
- It delegates committed JSON schema, original/main parent/actor/event/CI
  consistency to the merged Phase B `verify_approval`. All missing, failed,
  skipped, duplicated, unprotected, stale or unreadable evidence **DENIES**.
- Success returns `DRY_RUN_CONTEXT_ONLY` and explicit
  `publishingEnabled=false`, `publishableReceipt=false`,
  `candidateArtifactsAndSignatures=NOT_YET_VERIFIED`. This is NOT a publish
  receipt and is not proof of an eligible candidate or live privilege boundary.
- `tests/test-chat-pr-pilot-evidence.py` supplies synthetic, **non-publishing**
  GitHub API responses. Run this as part of Build's existing read-only
  `validate.yml`. Do **not** create a real authorization PR to test the path.

## Before a live Phase C publisher could even be considered

1. **Issue #61 / effective rules:** obtain authenticated read-only effective
   branch rules, required PR/CI checks, zero external approvals, strict
   exact-head conditions, no force/deletion/admin/bypass. Resolve any 403
   rather than fabricate a permissive snapshot. PG14 EOL on 2026-11-12
   requires a stable lifecycle-aware aggregate required check.
2. **Trust source for the dry-run:** implement a main-only, no-write,
   nonpublishing *test* event that injects GitHub-native event/actor/commit
   facts into this collector. No real `.github/release-authorizations/*.json`
   should be created while a publisher trigger or opt-in is inactive.
   Explicitly prove GitHub push event semantics and event re-run denial.
3. **Candidate verifier integration:** use the actual central/local policy,
   exact merged candidate PR/manifest and ancestry, signed Windows per-major
   artifacts, immutable decision + candidate-audit outputs, full upstream
   source SHA, EOL matrix, PACKAGE-INFO event, SPDX SBOM, attestation and
   SHA256 checks **in the same trusted job**. The read-only collector's
   candidate-run metadata checks ALONE cannot authorize a Release.
4. **Concurrency/replay:** add current main check immediately before any
   privileged action, strict one-merge/one-tag idempotency, a fresh
   authorization-request check and create-only tag protection; enforce no
   duplication or stale approval.
5. **No privilege escalation:** future push event path must never execute
   untrusted PR code or accept a user-provided typed receipt as authority.
   Publisher must consume evidence from the trusted job and still independently
   verify actor/event/SHA/ZIP/manifest and GitHub asset attestations.
6. **Zero-workflow live validation:** only after a separate explicit approval,
   a future truly eligible upstream update and Issue #61 closure, consider
   installing a guarded publisher. No such approval is provided by this PR.

## Manual fallback and rollback

Keep `plpgsql_check/.github/workflows/promote.yml` on `workflow_dispatch`,
`confirm_release=PUBLISH`, and both
`build/metadata/release-promotion.json` and
`plpgsql_check/config/release-promotion.json` on `manual-dispatch`.
If any pilot probe is inconclusive, **leave those files unchanged**, remove
only any future *test-only* workflow in its own CI-gated PR, preserve audit
artifacts and Issue #75 OPEN. Never retag, remove assets or amend old Releases.

## Phase C completion criteria

A passing synthetic collector test means **preparation complete**, not live
authentication proven. Phase C rollout approval requires independently fetched
branch rules, genuine no-publish push identity verification, full signed
candidate gate composition, safe run/retry evidence and immutable publisher
guards. Keep all production triggers OFF pending these checks.
