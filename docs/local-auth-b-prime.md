# Local authorization design and rollout

B-prime is the design for pgextwin's local authorization. The 2026-11-23
16:42 JST decision authorizes one switch from DENY to ENFORCE for all 26
repositories in `metadata/automation-fleet.json`. The switch is governed by
`metadata/local-candidate-authority.json` on protected Build main.

## Candidate authority

The existing fleet watch selects genuine stable upstream updates. Build
rechecks the same-run scan, protected Build and extension main, and the
candidate plan. Private issuer main re-derives the plan from the exact
protected commits and verifies that the requesting run is the original
Build schedule. The common matrix resolver yields the required PostgreSQL
major and source version. For each required version, both sides fetch the
license files at exact commits, validate the Git blob bytes and check exact
equality between upstream and packaging copies.

Issuer uses a repository Actions Secret with a pinned Ed25519 public key.
The signer checks that the Secret derives the pinned public key and requires
the system Ed25519 backend for production. The ticket uses the exact LA1
canonical embedded signature. Its signed input digest binds the candidate
plan, all per-major source and license digests, and the Build consumer run.
Tickets last ten minutes. A policy with an unset, expired or revoked
delegation fails closed.

The private issuer repository's own `refs/claims/<requestId>` is the
create-only issuance ledger. After writing the claim, issuer uploads the
ticket, canonical inputs and claim result as one private artifact. Build
uses the run ID returned by the dispatch API, an independently read issuer
main and workflow ID, and the exact run's artifact ID and ZIP digest. LA7
checks the successful first-attempt run, exact claim ref, immutable claim
bytes and ticket digest. Build compares independently recomputed inputs
and policy bindings before the existing dedicated App may use the candidate
proposer. Existing native Windows checks and publication controls still
apply. This ticket authorizes candidate preparation. Its publication field
is false. The requalify operation needs its own signed-run integration.

## Trust decisions

- A private repository Actions Secret replaces the external KMS. The
  verifier keeps the policy-pinned Ed25519 verification. Issuer maintainers
  and workflow editors are trusted to protect the key.
- A create-only Git ref replaces the external CAS database. Its immutable
  commit binds the claim to the ticket digest and issuer run. GitHub admins
  retain the ability to change refs. The private issuer repository
  currently lacks GitHub-enforced main protection on its existing plan.
- Authenticated GitHub run and claim reads replace cross-run OIDC transport.
  The signed inputs bind the exact Build run. This relies on GitHub's API
  record of the run and its repository. It does not carry a job OIDC claim.
- One V1 envelope uses a signed operation and the existing integer-only
  canonical JSON codec. LA1 takes precedence over the earlier proposed
  detached encoding. The separate publication, artifact and license
  checks still apply.
- A finite delegation window, short tickets, exact run association and
  existing candidate CI form the initial operational controls. Expiry,
  changed protected main, stale evidence and ambiguous API outcomes defer
  the proposal. Claim refs are kept after run/artifact expiry.

## Deployment and rollback

Prepare the issuer and Build code under DENY. Build's protected
`fleet-candidate-writer` Environment needs an issuer-only credential
`LOCAL_AUTH_ISSUER_TOKEN` with Actions write and Contents read. The candidate
writer App needs an installation covering the full fleet and its identity
must work with the native candidate audit. Confirm coverage and license
contracts before switching the single policy for all fleet entries. Set a
finite UTC delegation window in that PR and allow the first real candidate
to reach the issuer through the existing scan. Switching policy does not
dispatch a candidate or release.

For rollback, submit a Build PR changing only `mode` to `DENY`. Once
merged, the issuer and Build's local authority reject the live policy
before granting permission. An already-created draft PR, branch or Windows
run stays in the existing audit and review process. Keep issuer claims.
