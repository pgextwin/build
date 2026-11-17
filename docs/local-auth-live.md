# Local authorization live issuer binding

`scripts/local-auth-live.py::verify_live_binding()` calls the unchanged LA1
`verify_ticket()` before any network access. It then checks issuer identity,
current issuer main, the successful issuance run (main, workflow ID/path, run ID,
attempt 1), and the exact claim ref and its immutable `claim.json` contents.
Success means `VERIFIED_LIVE_BINDING_ONLY`, `authorized=false`, `publication=false`.
The existing `authorize()` still rejects DENY and every unimplemented mode.

The inputs to this Python API are the LA1 ticket, canonical input bytes,
**trusted authority policy from `metadata/local-candidate-authority.json`**,
fleet repositories, UTC time, and a required **trusted per-ticket issuance
policy** passed as `issuance_policy`. The latter has exactly these fields:

| Field | Expected value |
| --- | --- |
| `repository` | `pgextwin/local-auth-issuer` |
| `mainSha` | Issuer main commit expected for issuance |
| `workflowPath` | `.github/workflows/issue-ticket.yml` |
| `workflowId` | Issuer workflow's positive integer ID |
| `runId` | Issuance run's positive integer ID |
| `claimCommitSha` | Expected claim commit |
| `requestId` | Ticket request ID |
| `ticketSha256` | SHA-256 of canonical signed ticket bytes |

The caller must supply this policy from an independently trusted issuance
context/receipt or reviewed policy, never copy expectations from the live
responses being checked or an untrusted proposal. It is a separate API argument,
not an addition to the authority JSON schema. This PR does not provision such a
production receipt or connect an execution workflow. Missing context fails closed.
V1 has no issuer SHA, issuance run, or claim commit fields; `centralMainSha` is
the **build** main SHA and must not be repurposed as issuer main. Keeping the
context separate preserves LA1's strict signed ticket format and avoids a circular
ticket digest/claim commit dependency.

The key ID must be `local-auth-prod-1`. LA1 checks the ticket epoch against the
authority policy's epoch (including revocations), verifies with that policy's
public key, and preserves all format, time, fleet and input hash checks. The
checked-in DENY policy has no delegation window, so even evidence verification
cannot succeed with it. Positive tests use only the public RFC 8032 test key and
an injected test delegation window; they do not demonstrate production issuance.

`fetch_live_facts()` uses authenticated `gh api --hostname github.com --method GET`
through `github_get()`. Endpoints are restricted to the fixed issuer repository,
main ref, the expected run/workflow IDs, exact `git/ref/claims/<requestId>` and
`contents/claim.json?ref=<expected claim commit>`. It never uses matching-ref
lists, arbitrary URLs or a mutable ref to read claim contents. Missing refs,
failed GETs, timeouts and malformed responses reject without fallback. The claim
ref must point at the expected commit; canonical claim bytes, Git blob hash and
the ticket digest/request/operation/issuer/run/attempt tuple are checked using
the actual LA5 claim format (run ID and attempt are strings in that record).

Tests inject either a complete `facts` dict or an `api(endpoint)` fixture callback.
Production callers must omit `facts` and use the default fetch layer; cached
facts are not live evidence. GETs are not an atomic snapshot or a distributed
lock. A future execution gate must re-fetch before any write and separately
enforce authorization, target-repository bindings, opt-in, policy freshness,
source semantics and replay rules. This layer neither creates nor consumes a
claim. It does not verify artifact origin/bytes or introduce a signed claim
format. Publication and the issuer's production signing-secret switch remain
outside this PR.

API references: [workflow runs](https://docs.github.com/en/rest/actions/workflow-runs#get-a-workflow-run),
[exact Git refs](https://docs.github.com/en/rest/git/refs#get-a-reference),
[repository contents at a ref](https://docs.github.com/en/rest/repos/contents#get-repository-content).
