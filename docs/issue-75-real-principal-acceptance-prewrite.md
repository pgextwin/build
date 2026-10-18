# Issue #75 — Real principal acceptance preflight, immutable negative-only contract

**2026-10-18. Result category: `NEGATIVE_WITNESS_ACCEPTED_REAL_PRINCIPALS_NOT_PROVEN`.** This is an intentionally nonpublishing read-only negative acceptance preflight, NOT a private real Signer/Writer positive experiment or a new trusted cryptographic verifier. It is forbidden to turn a simulated certificate, user-supplied JWT/installation token, source-workflow grant, offline unit-test success, or public GitHub GET into a release receipt.

## Reused evidence, no duplicated observer

The record `evidence/issue-75/real-principal-acceptance-prewrite-deny-20261018.json` anchors the **actual already completed** protected-main source-only negative [Run 39104746046](https://github.com/pgextwin/build/actions/runs/39104746046), attempt 1, head `afdfb07d85608180b472288a3646447dbd4e67dd`, parent SUCCESS. Reader job 117608071252 = SUCCESS with `READER_GET4_NEGATIVE_ONLY` and `ACTIVE_SOURCE_GET4_NEGATIVE_GAPS_CONFIRMED`. Signer inert job 117608071136 and Writer inert job 117608071199 = SUCCESS with `*_UNPROVISIONED_NO_WRITE`. These job-success values prove *only that the negative roles ran*, not that a real privileged Signer/Writer identity was exercised. Historic GO A failure is not waived.

The new `scripts/issue-75-real-principal-acceptance.py` reuses `issue-75-transitive-dependency-delta.py.inspect` and `issue-75-signer-checkout-hardening.py.inspect`, with fixed Git Blob identities for the **32 original + 13 additional blobs**. The older `issue-75-active-principal-custody-readonly.py` pins the actual pilot main `98452723fcad2aedafb1c02a210f35950f7e8cf2`, Publisher source Git Blob `3ae586814b063fefa5c3a554758f13467bb23ea5`, Publisher SHA `455f0ccc667697f600700a6e64bcfd6c57b6a977`, and Signer SHA `5756b3c5136a8bf4db710016cfe97555f0a71c6d`. None of these production references is changed by this work.

## Authorization and custody threat model

| Role | Current known source/runtime limit | Independent acceptance still required |
| --- | --- | --- |
| Reader | Job-scoped GitHub read token; 4+4 bounded GET results in the protected-main source run | Truly effective token scopes and isolated job identity (not inferred solely from publicly accessible GET) |
| Signer | Existing reusable workflow declares `id-token:write`, `attestations:write` and `artifact-metadata:write`, but old five checkout steps retain credential-persistence gap | Cryptographically verified real issued Sigstore/X.509 certificate issuer, OIDC subject and exact signer-workflow, source SHA, run ID and attempt, verified by independent trusted execution; no PR code in credential-bearing job |
| Writer | Production `publish` currently uses `github.token` and declares `contents:write`; the Catalog App token is a separate downstream Catalog-only token, not a Publisher Writer principal | Fresh narrowly scoped *distinct* Writer installation, installation repository/owner/permission identities and token lifetime from authenticated privileged issuer; no raw token in a ledger or public log |
| Job boundaries | Negative Reader/Signer/Writer fixture does not provision real privileged tokens | Credential non-propagation across jobs, both normal/attested checkout `persist-credentials:false`, no credential-bearing artifact, output, cache or untrusted PR path; independent authenticated runtime verification |

**Fail-closed attacker cases**: fake successful Sigstore output, self-asserted `verified=true`, Writer installation ID or token claim, cross-role reused job ID, mixed SHA/attempt, skipped or failed parent/role, mutated pins, extra JSON key, duplicate key, JSON masquerade/oversize, forged GO status, positive publishable receipt, credential injection and truncated/missing evidence. The validator rejects them rather than upgrading acceptance.

## Two intentionally different exit conditions

`python scripts/issue-75-real-principal-acceptance.py --mode static` runs entirely offline in the existing required App15368 `resolver`, verifies the existing 32+13 source records and their checkout hardening gap plus the pinned negative witness, and **returns zero only for successful denial-baseline integrity**. Its JSON says `realPrincipalAcceptance=NOT_PROVEN`, `publicationAuthorized=false`, and GO B/G4/G5 `NO_GO`.

`python scripts/issue-75-real-principal-acceptance.py --mode require-real` **always fails closed (exit code 2)**, including when fed a perfect-looking fabricated positive JSON or an offline mocked verification. This is deliberate: no independently authenticated signer-certificate and installation-token verification pipeline is yet safely available. Future acceptance must implement a *separate*, reviewed, privately isolated verifier that actually checks cryptographic signatures, issuer/subject, installation scope and lifetime against independent authenticated services. It must not simply flip booleans or bypass this command.

No new deployment credential, GitHub Secret/App, permission, branch protection, runner budget, Tag/Release, workflow dispatch, Publisher pin or policy is introduced. Existing `plpgsql_check` PR #29 stays DRAFT. Existing negative GET observer and its real Run remain unchanged. The new script is not an actual credential-bearing job and creates no artifacts.

## Remaining gates

Formal P1 **65/70**, independently accepted source **40/40**, plpgsql_check historical PG14–18 **5 DENY**, P1 BLOCKED/P2 NO-GO, GO B/G4/G5 **NO-GO**, formal Release/distribution **DENY**. A successful required CI or protected merge proves only this nonprivileged denial contract; actual Signer OIDC, Writer separate principal, token non-propagation, signed positive Publisher prewrite and schema-v2 crash-safe Publisher remain **NOT_PROVEN**.

**Next:** independently authorize a genuinely isolated, trusted, credential-bearing *nonpublishing* runtime with appropriate narrow GitHub App scope. Use a true Sigstore/OIDC X.509 verifier and a separate authenticated App-installation provenance/scopes verifier, emitting only scrubbed, immutable negative/JIT evidence. Do not use a real Writer secret in a public PR runner, or grant Release write scope to Reader/Signer.
