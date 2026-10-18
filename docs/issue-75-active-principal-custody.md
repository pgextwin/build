# Issue #75 — Active pinned Signer/Publisher source custody GET-only (2026-10-18)

## Scope: negative runtime-source observation, never authenticated three-principal acceptance

This change extends the already tested protected-main, read-only Reader job from PR #127. It **does not** invoke the actual Signer, Publisher, Writer or Catalog publisher; cannot create a Tag/Release, cannot mint an App/OIDC token, and does not change scopes, existing secrets, branch protection, production pins or budgets. It does not upload artifacts or publish a credential-bearing trace.

The existing Reader job still first executes issue-75-principal-boundaries.py (4 GET for its own running job and protected build/main), then a second GET-only source witness, sharing **only that Reader step's read-only github.token environment**. The production Publisher repository and current pilot/main SHA are independently GETed twice, and a pinned immutable promote.yml Git Blob is decoded, hashed and checked by the **existing** issue-75-go-b-live-readonly.py workflow_pins proof. No novel HTTP transport, credential persistence or duplicate 32/45-Blob graph. The old Signer source is checked through the existing issue-75-signer-checkout-hardening.py five-checkout Git-Blob proof, in-memory only.

### What actually exists at the pinned current source

- Pilot protected main: pgextwin/plpgsql_check@98452723fcad2aedafb1c02a210f35950f7e8cf2.
- Exact original promote.yml Git Blob 3ae586814b063fefa5c3a554758f13467bb23ea5.
- Old approved Publisher/packaging SHA: 455f0ccc667697f600700a6e64bcfd6c57b6a977.
- Active Signer reusable Workflow pin: 5756b3c5136a8bf4db710016cfe97555f0a71c6d.
- Authorize job: GITHUB_TOKEN via github.token, declared contents:read/actions:read/pull-requests:read, both checkouts persist-credentials:false.
- Reusable Signer build: contents:read, id-token:write, attestations:write, artifact-metadata:write. This declares an OIDC request capability, but does **not prove actual issued OIDC identity, signature, certificate or job isolation**. Its old fixed code still has five checkout steps without persist-credentials:false, so the proposed hardening is NOT deployed.
- Publisher Writer job: contents:write, actions:read, attestations:read, GH_TOKEN from github.token; separately permissioned job, but **not** a distinct independently authenticated Writer installation principal. Its two checkouts do set persist-credentials:false.
- Catalog downstream is the only consumer of the Catalog-limited App token, with repository catalog and action write scope, after publication; that token is NOT the Release Writer credential.

The immutable Blob is a source identity, not a runtime/JWT/OIDC claim. Source static YAML permissions do not attest actual effective runtime scopes or token uniqueness; a short-lived github.token job token is not an independently governed release Writer principal. No token itself is logged, fingerprinted or passed into another job.

### Closed-world acceptance

The new Reader witness verifies two protected pilot/main GET responses and two pinned promote.yml GET source objects using only the pre-existing allowlisted GitHub REST GET transport. Missing/mutated/mismatched source identity, unsigned payload, unexpected pin, permission scope escalation, checkout persistence changes, credential transfer into the build job, alternate Catalog repo, missing/duplicate jobs or missing page/GET -> fail closed (exit nonzero). The hostile tests cover synthetic positives separately and **never upgrade simulated source to actual authenticated principals**.

Passing output is explicitly named ACTIVE_SOURCE_GET4_NEGATIVE_GAPS_CONFIRMED and still has signerOIDCIdentityVerified=false, writerInstallationIdentityVerified=false, writerTokenScopeRuntimeVerified=false, runtimePrincipalSeparation=NOT_PROVEN, releaseAuthorized=false, GO B/G4/G5=NO_GO. A failed Reader step is an actual failure and must be corrected without waiving historical GO A failure.

### Remaining gated work

A genuine independently authenticated, nonpublishing Signer OIDC/certificate subject and Writer installation identity would require **separately authorized trusted credential-bearing infrastructure** and no untrusted PR or public logs with secrets. Neither is silently introduced by this evidence-only PR. Signed Publisher positive prewrite, transitive runtime SHA closure and crash-safe schema-v2 Writer are also NOT_PROVEN.

P1 formal 65/70, independent source 40/40, plpgsql_check PG14–18 five DENY, P1 BLOCKED/P2 NO-GO and Release/distribution DENY persist. Production promote.yml, release policies, old Signer/Publisher pins, plpgsql_check draft PR #29, Secret, permissions and budget are unchanged.
