# Issue #75 — Protected private Signer/Writer runtime blueprint (NOT DEPLOYED)

This PR adds only dormant libraries and public, synthetic hostile tests. It does not install a GitHub App, provision or access a Secret, adjust permissions/branch protection/budget, or execute a real privileged token mint.

## Trusted isolation, future independently authorized step

**Reader (existing):** Keep the PR #127/#128 protected-main GET-only Reader, the existing immutable 32+13 Blob closure and role negative witnesses. Reader gets only contents:read/actions:read; checkout persist-credentials:false. Transmit only the immutable run/attempt/source/job IDs and SHA-256, never bearer values.

**Signer (new dormant library):** In a separately authorized, isolated trusted runtime, retrieve a SHA-pinned immutable ZIP and SPDX SBOM. Call the real GitHub CLI attestation verify subprocess with repo pgextwin/plpgsql_check, immutable reusable signer workflow path, pinned SHA 5756b3c5136a8bf4db710016cfe97555f0a71c6d, source SHA/ref, default GitHub OIDC issuer, deny-self-hosted-runners and both SLSA and SPDX predicates. Verify both command success and existing issue-75-publisher-preflight.py verified_claims policy for exact certificate/SAN, provenance, source digest, exact invocation/attempt, ZIP hash and SBOM. The gh binary/trusted roots/runner image must themselves be trusted and pinned in a separately approved runtime; the existing Signer checkout credential-persistence gap must be resolved in the actual pinned workflow before claiming custody. This is verification of existing signatures, NOT generation of a fresh OIDC token or live Signer credential-boundary proof.

**Writer (new dormant library):** In a THIRD distinct private executor with no Reader/Signer tokens, authenticate a GitHub App via its JWT; GET /app and GET /app/installations/{id}. Only once an independent user-authorized private credential and environment exist, mint a scoped *test-only* installation token via POST /app/installations/{id}/access_tokens, body limited to repository_ids [one approved repository ID] and permissions contents:write. Verify GitHub's authenticated mint response, scope and expiration <= 1 hour, then GET /installation/repositories with the **new token**, and finally DELETE /installation/token even if assertions fail. Revoke failure is a stop and quarantine condition. Do not use this probe for Release publishing. The existing production Writer using github.token, and the downstream Catalog App credential, do NOT establish this independent Writer principal.

**Across jobs:** Global future workflow permissions should default {}, and every job, checkout and nested workflow should use minimum permissions and checkout persist-credentials:false. Never pass JWT, OIDC bearer, private key, installation token, or their fingerprints through GITHUB_OUTPUT, GITHUB_ENV, artifacts, job summaries, logs, cache, PR input, or untrusted code. Use separate protected environments/private credential stores/runner instances and independent, authenticated policy and JIT access-denial observers to prove real nonpropagation. Token masks or synthetic unit tests are not such proof. A private job may report scrubbed issuer, source SHA, run/attempt, app/installation/repository ID, effective scope class, expiry duration, revoke result and trusted tool SHA only.

**No executable credential workflow is deployed in this PR.** The future isolated executor needs a separate authorization and safe credentials/runner setup. If it is not available, stop only the privileged live test; do not weaken branch protection or widen public CI permissions. Tests run entirely with mocked APIs and synthetic noncredentials.

## Files and test interpretation

- scripts/issue-75-private-signer-verify.py — dormant API, real subprocess-based cryptographic verification path, existing Issue75 verifier reused, no CLI entrypoint or Publisher.
- scripts/issue-75-private-writer-app-probe.py — dormant API, bounded allowlisted GitHub REST, short-lived single repository App token mint/revoke, no CLI entrypoint or release/tag mutation.
- tests/test-issue-75-private-principal-runtime.py — synthetic hostile cases for certificate/CLI arguments and subprocess failure, exact Writer app/installation identity, narrow grants, expiry, unexpected repo, malicious endpoint, failed token revocation, no raw credential output and no privileged public CI wiring.
- Existing scripts/issue-75-real-principal-acceptance.py --mode require-real still intentionally exits 2. Passing tests prove only contract integrity, NOT the live OIDC issued principal, Writer unique credential, job-to-job nonpropagation or genuine signed Publisher positive prewrite.

Protocol references:
https://cli.github.com/manual/gh_attestation_verify
https://docs.github.com/en/rest/apps/apps
https://docs.github.com/en/rest/apps/installations

## Non-negotiable gates

P1 formal 65/70; independent source 40/40; plpgsql_check PG14–18 five historical DENY; old GO A failure not waived; P1 BLOCKED, P2 NO-GO; GO B/G4/G5 NO-GO; formal Release/distribution DENY. Existing Signer/Publisher SHA pins, plpgsql_check PR #29, Secrets, permissions, branch protection, billing, Tags and Releases must not change.
