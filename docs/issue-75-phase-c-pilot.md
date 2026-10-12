# Issue #75 Phase C — plpgsql_check read-only pilot plan

Status: **NONPUBLISHING DRY-RUN / NO PUBLICATION AUTHORITY** (2026-10-13 JST)  
Owner: pgextwin/build Issue #75. Issue #61 is CLOSED (extension Classic UI audit).  
Phase B shared validators: merged Build PR #77.

## Provisional choice and non-goals

Use **pgextwin/plpgsql_check** only as a *provisional* pilot. Issue #61's
2026-10-12 final UI audit found Classic protections for all thirteen other
extension mains; its earlier "13 unprotected" snapshot is historical.
`plpgsql_check/main` is also protected, and the fixed
`Windows required summary` job exists, but it is **not yet a required
status check**. `pgextwin/build/main` remains unprotected.
The standard Chat GitHub connector receives HTTP 403 for detailed
`/branches/main/protection`. A UI inspection may confirm an administrator's
configuration, but it is **not** an independently machine-verifiable runtime
authorization proof. On 403, the pilot collector MUST fail closed.
A future publishing path requires separately authorized effective-rule
read evidence (for example a narrowly scoped Administration:read token),
plus exact-head required aggregate CI. No such permission is added here.

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
  A duplicate/ambiguous execution of a required App check (even a previously
  successful run followed by failure or cancellation) DENIES; the collector
  will not infer which attempt is authoritative.
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

1. **Effective rules (Issue #61 UI acceptance is complete):** obtain
   independently machine-readable effective branch rules and required PR/CI
   checks, zero external approvals, strict exact-head conditions, no
   force/deletion/admin/bypass. Resolve any 403 rather than fabricate a
   permissive snapshot. The fixed Windows aggregate job is implemented for
   `plpgsql_check` but must be deliberately required in existing Classic
   protection after successful CI evidence; PG14 EOL on 2026-11-12 must not
   leave obsolete per-major required contexts blocking future merges.
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
