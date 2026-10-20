# Third-wave Chat PR / main-push setup — read-only boundary

Setup date: 2026-10-20 JST. Trackers: [#75](https://github.com/pgextwin/build/issues/75),
[#141](https://github.com/pgextwin/build/issues/141).

## What this change makes usable

The three third-wave repositories can call the same immutable
`chat-publication-readonly.yml` from their existing `windows.yml`. Their existing
required **Windows required summary** also depends on that admission job. The
required check name and GitHub Actions App ID 15368 remain unchanged. No new
review requirement or protection setting is needed. A routine Chat-created PR
and safe squash merge cause genuine PR and main-push runs without Dispatch.

The shared job checks out **only its own full-SHA shared verifier**, with
`persist-credentials:false`. It never checks out or executes caller code. Its
only permissions are contents/actions/pull-requests/checks **read**. It does not
receive a Secret, OIDC signing permission, App key or independent Writer token.

It independently reads GitHub run/event identities and protected-main metadata.
For a push it additionally checks single-parent squash, one merged PR, actual
allowlisted User merger/sender/actor, web-flow verified commit signature, equal
PR/commit file blobs and exact-PR-head App15368 required CI. A second main read
must match. Replayed attempts, unknown actors, direct pushes, unknown/failed/
skipped/duplicate checks, incomplete pagination and changing main fail closed.
These are **authenticated GitHub metadata observations**, not fresh effective
Classic-rule proof, actual candidate artifact signature verification or a
positive independent Publisher admission.

An ordinary PR/push with no authorization file returns `NO_AUTHORIZATION` and
successfully does nothing. Normal Windows manual dispatch is retained and
explicitly classified as **not publication authorization**. A future one-file
authorization must have the existing exact 12-field schema, fresh packaging
base, same-repo author, `auth-release/<tag>` branch, exact added file/blob and
literal `PUBLISH`. UPDATE is a separate candidate action. A well-formed request
returns **VALID_REQUEST_FORMAT_PUBLICATION_DENIED**, never a publishable receipt.
An invalid/unknown/duplicate/renamed/modified request fails required CI.

## Deliberately unresolved production gates

`goB=NO_GO`, `g4=NO_GO`, `g5=NO_GO`, `publication=DENY` and all
`publishableReceipt/publicationAuthorized/catalogProposalAuthorized=false` are
invariant. This change contains **no Publisher connection**, no live authorization
JSON, no new Release/tag, no candidate UPDATE, no token mint or signing. The
central formal 14-extension allowlist and all three disabled local Promotion
policies remain intact. Existing manual-dispatch historical Publisher/Signer
pins, 45 Git Blob custody roots, recovery contract and tests are reused unchanged.

The remaining work cannot be represented by a Boolean enabled flag:

1. Independently authorize and prove an isolated runtime and separately governed
   Reader/Signer/Writer principals, including real short-lived repository-scoped
   Writer issuance/revocation, OIDC/certificate identity, no credential propagation
   and genuinely signed Publisher-positive prewrite/recovery proof. Reusing
   `github.token`, the read-only auditor or catalog-only proposer fails this gate.
2. Establish fresh machine-readable effective Classic/rules proof for each exact
   target at runtime. A GUI checkbox, branch `protected:true` and required-check
   summary are different evidence boundaries and cannot replace it.
3. Obtain eligible actual human-UPDATE candidates, immutable PR/decision/Windows/
   audit IDs and all maintained PG artifacts. Each future named Release still
   needs a separate explicit human PUBLISH. This setup is not that instruction.
4. After the real gates pass, review a protected change joining the existing
   strict approval/signature/JIT/create-only Publisher, and independently accept
   one genuine new signed Release through Catalog proposal, required CI, Chat
   merge and Website JA/EN. Never enable unattended publication or auto-merge.

Until then **CHAT_ONLY_RELEASE_NOT_READY**. Normal Chat can continue code, tests,
protected PR/CI/merge/postmerge and nonpublishing observations without Work.
No public CI success in this setup upgrades GO B/G4/G5.

## Validation and rollout evidence

The shared adversarial test reuses `chat-pr-authorization.py`'s extracted strict
parser. It rejects malformed/extra/duplicate keys, UPDATE-as-PUBLISH, stale SHA,
bot identity, other repository, reused attempt, ambiguous PR, failed/skipped/
wrong-App CI, modified file, blob mismatch, main race, redirect, pagination,
oversize/API errors and credential-bearing exception output. Fixtures are
synthetic only; valid test JSON is not committed as a live authorization.

Exact protected PR, main SHA, App15368 CI, postmerge run and sanitized real job
metadata will be recorded in both tracker Issues. Original successful Windows
runs are not retried; rollout runs validate the changed caller/required-summary
dependency and actual new metadata observer.
