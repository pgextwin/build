# Issue #75 / third wave — independent Writer scope and GitHub Actions-only implementation boundary

2026-10-20 JST. **Nonpublishing, unprivileged implementation. No real token mint, Signer invocation, Release/Tag or approval.**

## Fresh source and authenticated metadata checks

- The protected `build/main` was freshly observed at `d5078d474d8356a142c8fb1d63bc68fb3cea0897`, with no open build PR before this change.
- Previous `#146` and read-only main jobs `39351271787` / `39351271846` were COMPLETE/SUCCESS, unchanged. Existing successful Windows jobs remain reused.
- Current connected GitHub App returned **HTTP 403 `Resource not accessible by integration`** when independently GETing the Classic `/branches/main/protection` endpoint on **all three** targets. All three publicly readable `/rulesets?includes_parents=true` collections returned `[]`; this is **not an Administration:read effective-enforcement proof**, and cannot turn the GUI audit into cryptographic proof.
- Prior Work GUI reported no configured protected Environment or eligible existing independent third-wave Release Writer, and no approved new Secret/App/private host. No successful positive principal probe exists. `github.token` and Catalog proposer are not equivalent.

## Implemented, without new permissions

The dormant `scripts/issue-75-private-writer-app-probe.py` previously bound its exact single-repository minted token and authenticated installation-list GET to the historical `pgextwin/plpgsql_check` pilot only. The new explicit allowlist additionally accepts exactly `pgextwin/pgtap`, `pgextwin/pg_variables`, or `pgextwin/pg_store_plans` as an **explicit `repository=` argument**, keeping old callers compatible. It checks *both* GitHub's mint response and the actual minted-token `/installation/repositories` response against the same requested target and independently supplied numeric repository ID, plus strict `contents:write`, selected single-repository scope, issuer/app/installation identity, expiry not exceeding 1 hour and mandatory revocation. Cross-target, Catalog, Website, path-smuggling and spoofed scope are rejected. Added deterministic hostile test coverage in existing required CI; default remains a nonpublishing dormant API.

Tests use synthetic JWTs/tokens and injected API responses. Their success never proves a new Writer exists, that the declared App is independent of Reader/Signer, or that live revocation and job-to-job nonpropagation occurred. A minted-token response lost before capture remains an unresolved remote-state ambiguity; fail closed and quarantine, never retry blindly.

## 2026-10-20 transport-boundary defense-in-depth (nonpublishing)

The dormant `authenticated_call()` now independently validates every installation-token mint POST payload before opening any HTTP transport. Even a future caller accidentally bypassing `probe()` cannot use this helper to POST arbitrary repository IDs (including Catalog/Website/build), multiple targets, bool/coerced IDs, or any permission beyond exactly `{"contents":"write"}`. Only one of the pinned immutable target repository IDs is accepted; `probe()` still binds the ID to the exact target name and authenticates the minted/listed identity and revocation. The historical plpgsql_check pilot target remains allowlisted strictly for backward compatibility and **is not a third-wave release authorization**.

Synthetic adversarial tests prove only this local no-network POST guard, not real GitHub App possession, private custody, actual live mint/revoke, or a durable replay/UNKNOWN quarantine journal. No runner, permissions, App installation, human PUBLISH or Release is enabled. GO B/G4/G5 remain NO_GO; publication remains DENY.

## 2026-10-20 Work GUI App inventory: explicit pre-JWT exclusion, no new rights

User-completed authenticated Work GUI **GET-only** audit reported these existing
pgextwin App principals (not a live independent Writer attestation):

| App ID | Work-observed role | Writer status |
| --- | --- | --- |
| 15368 | GitHub Actions required-check issuer | Not an independent Writer |
| 5295410 | `pgextwin-classic-protection-audit`, installation 170837728, selected `plpgsql_check` only, Administration READ / Metadata READ | Read-only protection auditor; no Contents WRITE |
| 5281285 | `pgextwin-catalog-proposer`, installation 170516730, selected `catalog` only, Contents WRITE / Pull requests WRITE / Metadata READ | Preserve Catalog role; not isolated Wave3 Writer |
| 5250206 | `pgextwin-catalog-dispatcher`, **not installed**, Actions WRITE / Metadata READ, no Contents WRITE | Conditional conversion candidate **only after separate owner authorization** |

The dormant private Writer `probe()` now rejects each known-ineligible App ID
**before any authenticated JWT GET or token-mint POST**. The guard does **not**
approve any other App ID: mocks passing the source contract are not an App
ownership/permission/custody or release proof. A separately approved conversion
of the dormant dispatcher (or a new purpose-built Writer) requires a reviewed
change to this explicit deny baseline **after** actual independently governed
identity, selected installation, minimum permissions, key storage and protected
executor are established. Do not silently treat a changed UI configuration
as permission to mint credentials. The Work report observed no dedicated Writer
Environment across 21 pgextwin repositories; this does not prove external
private-host absence.

The owner-authenticated GUI reported that Classic main rules on
`pgtap` (85048421), `pg_variables` (85048594) and `pg_store_plans`
(85048748) require PR/strict App15368 summary and disallow administrator
bypass/force push/deletion; Rulesets are absent. This is **GUI-observed**
protection, **not** an Administration:read authenticated App GET (the normal
Chat connector still returns HTTP403 for Classic rules). No Secrets,
installation grants, Rulesets, branch rules, environment, runner or Release
were changed.

**GO B/G4/G5 = NO_GO, PUBLISH = DENY, Wave3 formal Releases = 0/3.**

## 2026-10-20 Wave3 Classic effective-rule REST-only readiness (NOT AUTHENTICATED)

New dormant `scripts/issue-75-wave3-classic-readonly.py` reuses the
existing plpgsql_check `classic-protection-audit.py::_validate_snapshot`
without altering the pilot's eight-context default policy. The Wave3-specific
policy requires exactly one `Windows required summary` GitHub Actions
App **15368** check, strict latest-main enforcement, PR required with
zero required approvals, admin enforcement, zero bypass users/teams/apps,
no force push, no deletion, and no actor restriction override.

For each of the exact three pinned repositories (GitHub numeric IDs
1425678353/1425679720/1425680909), the preparatory reader permits **GET**
of only the target's repository identity, protected `branches/main`,
`branches/main/protection` and
`rulesets?includes_parents=true`. It takes two identical four-endpoint
snapshots and requires an empty Ruleset list; stale main SHA, swapped
repository ID, all missing/unknown fields, 403, duplicates, pagination,
mutation, response drift, extra/bypassed status contexts, or forced deletion
**DENY**. Raw credential values are never returned or logged.

This is an intentionally **REST-only, narrow policy contract**. The real
Classic REST endpoint can omit bypass allowance fields; such a response
stays DENY pending a separately reviewed and independently authenticated
effective-ref GraphQL extension. No fixture, owner GUI screenshot or public
`protected=true` claims live App authentication. The existing Work GUI
identified the owner-controlled read-only audit App **5295410**, installation
**170837728**, selected only `plpgsql_check`. It is NOT provisioned on
the three Wave3 repos. `collect()` therefore always reports
`auditorIdentityIndependentlyAuthenticated=false`,
`effectiveRulesAuthenticatedByIndependentApp=false`,
`publicationAuthorized=false` even on passing injected snapshots.
`tests/test-issue-75-wave3-classic-readonly.py` runs only synthetic tests
in existing required CI; no App scope changes, JWT token, Secret, GitHub
credential or privileged job are introduced.

After separate explicit owner approval, an isolated genuine App-issued
Admin READ + Metadata READ installation token scoped to selected target(s)
must independently verify App/installation identity and exact run provenance.
A future trusted nonpublishing job can then perform these reads and any
separately reviewed GraphQL supplement. **No publication authority is
derived from this code or the GUI baseline.** GO B/G4/G5 NO_GO,
PUBLISH DENY, Wave3 formal Releases 0/3.

## Smallest viable authenticated GitHub Actions-only future route (not enabled)

1. **Reader:** retain existing main-only, no-write `issue-75-wave3-actions-readonly.yml`. Job token `contents:read` only, checkout `persist-credentials:false`. Send only trusted run/attempt/source SHA/digest metadata, never a bearer, JWT, OIDC token or key.
2. **Signer:** separate trusted protected workflow/executor; obtain actual GitHub OIDC identity and issued Sigstore X.509 certificate *in the real run*. Independently validate trusted issuer, workflow/ref/SHA/attempt, exact ZIP/SPDX/SLSA original bytes and trust roots. Repair five historical persistent-credential checkout sites through its own protected reviewed SHA update before live proof. No Reader or Writer credentials exposed to this job.
3. **Writer:** separately authorized GitHub App installed on **only the specifically authorized target repositories**; Metadata READ + Contents WRITE as the minimum candidate scope, with owner-governed private key storage and a trusted, access-restricted credential-bearing execution boundary. Never substitute `github.token` or the existing Catalog proposer App. Pass no secrets via jobs/outputs/artifacts/cache/logs and never run attacker-controlled PR code near credentials. Authenticate app/installation/repository IDs, one repository per short-lived installation token, effective permissions, <=3600s TTL, revocation. Verify negative access to Reader/Signer identities in a genuinely isolated runtime.
4. **Publisher:** until signed positive prewrite, protected effective rules, true user PUBLISH, create-only replay safety and a durable external recovery journal are all independently accepted, DO NOT use Writer to create a tag or release. A job-to-job split in public hosted Actions is *not* by itself enough proof of independent credential custody.
5. **Recovery:** preserve `release-recovery-evidence.py` schema-v2 **UNKNOWN_QUARANTINE** on lost POST/422/ambiguous state; a future privileged integration needs durable fsync-backed, access-controlled persisted ID/SHA and separate authenticated two-pass remote GET with no unguarded replay. Existing inert classifier is not a deployed recovery journal.
6. **Admin protection reader:** obtain a specifically authorized Administration:read + Metadata:read authenticated identity on each of the three target repositories, then verify effective Classic REST/GraphQL Rulesets, admin enforcement, bypass, nonforce/nondelete, strict latest-head App15368 checks. 403 is an unmet gate, not a PASS.

## Exact new administrative prerequisites (not requested or provisioned)

An owner must separately authorize a genuine **Release Writer GitHub App**, granting only the chosen extension repositories Contents WRITE + Metadata READ; an independently protected credential store / Actions Environment or truly isolated approved executor with custody separated from the Signer; and a **read-only protection-auditor** scope Administration READ + Metadata READ limited to pgtap, pg_variables and pg_store_plans. Each new credential and Environment requires a separate approved configuration operation. Provisioning/positive token issuance and individual candidate UPDATE / target-specific human PUBLISH are *not* implied by this test-only PR. Do not alter branch protection, billing, required CI or third-party reviewer rules.

## Acceptance retained

This PR adds no publish workflow, permission escalation, CI rerun of already successful Windows, release candidate change, catalog artifact, website change, live credential, GITHUB_TOKEN write privilege or formal PUBLISH instruction.

**GO B/G4/G5=NO_GO; Publisher=DENY; third-wave Releases=0/3; Catalog=14 extensions / 70 ZIP; CLI v0.3.2 verbose preserved. Chat-only unprivileged implementation READY; Chat-only fully authorized formal Release NOT_READY.** Old GO A run 39008743613 remains FAILURE.
