# Issue #75 — third-wave credentialless three-job isolation and dormant Writer issuance hardening (2026-10-20)

**Safety class: negative-only; independently authenticated release Writer NOT PROVISIONED.** No additional App, Secret, protected Environment, runner, budget, workflow dispatch or Release. No production Publisher or Signer caller changes, and GO B/G4/G5 are NO_GO.

## Reuse, rather than a fourth workflow

The existing protected-main `.github/workflows/issue-75-principal-boundaries.yml` already has three independently scheduled GitHub-hosted jobs:
- `reader`: `contents:read` / `actions:read`; only role permitted to receive a job-local GH_TOKEN for bounded metadata GETs.
- `signer_denied`: `contents:read`, no id-token:write, no signing, no GitHub App key.
- `writer_denied`: `contents:read`, no contents:write, no token mint, no release/tag write.

The existing workflow has `permissions: {}` at the root, no `needs`, no job `outputs`, no cache, no secrets, no artifacts, no GITHUB_OUTPUT or GITHUB_ENV transfer, and each checkout uses `persist-credentials:false`. This change adds a strict **environment-variable-NAME-only** negative observation to the two inert jobs. Reserved GitHub/third-party credential names and suffixes (including even EMPTY variables) cause hard CI failure; no variable values are examined or printed. Synthetic adversarial tests inject many secret-shaped names and verify denial/no output leaks. Success is evidence about only the inert **process environment** of those exact jobs, not proof of all GitHub platform token contexts, host-level isolation or the actual credential-bearing Signer/Writer.

## Dormant independent GitHub App Writer contract

`scripts/issue-75-private-writer-app-probe.py` remains **not wired into Actions** and has no CLI main, Release/Tag API endpoint or live token mint. A later separately authorized, independently protected executor may call its interface once real private App custody is established. The enhanced contract:
1. Preflight rejects GitHub Actions App ID `15368` masquerading as an independent Writer (before any token/JWT use).
2. Requires GitHub-authenticated app and installation identity, selected repo installation and minimally scoped installation permissions (Contents WRITE and optionally Metadata READ; no Issues/Actions/Administration write).
3. Creates at most one per-repository installation token request with an explicit `repository_ids` list and `contents:write` only; verifies exact app installation/owner, requested repository ID and name, minted scope, newly minted token identity inequality, and authenticated token-scoped repository listing.
4. Requires expiry strictly over 30 seconds and at most 3600 seconds from supplied trusted current clock. Expired/oversized/future/ambiguous token lifetimes fail closed.
5. Requires actual API DELETE /installation/token 204 success acknowledgment before returning a nonpublishing classified result, with `scopedTokenRevocation204Observed` only after confirmed result. All results still explicitly `publicationAuthorized=false`, GO B/G4/G5 NO_GO. A lost POST response, revocation ambiguity or invalid scope is a terminal quarantine condition; **do not retry issuance or reuse** after unknown remote effect.
6. Existing hostile FakeApp tests are extended with overgranted App permissions, all/suspended installation, platform ID, 30s/31s/3600s/3601s edges, malformed mint response, revoked-failure, and failed/missing GET. These are synthetic, do not prove actual independence or live revocation.

This is still **not sufficient to certify** real Writer identity or real Signer/Writer separation: actual app owner/private-key custody, target-limited installation, credential non-propagation, authenticated denial of undesired repo access, token TTL and remote revoke must be verified by an independently trusted private execution boundary. An installation token's GET response is evidence of its requested repository scope; it is not an independent assertion about the user's role or human PUBLISH authority. Explicit target-limited human PUBLISH and actual signed positive prewrite remain mandatory.

## Acceptance and follow-up

- **Negative runtime:** the three trusted-main jobs must complete and their raw logs must show `READER_GET4_NEGATIVE_ONLY`, `SIGNER_UNPROVISIONED_NO_WRITE`, `WRITER_UNPROVISIONED_NO_WRITE` with process credential key absence for two inert roles, and all GO flags NO_GO. Main-only path trigger is unchanged; tests prove no cross-job outputs/caches/artifacts/Secrets or credential-bearing permissions.
- **Dormant synthetic:** required App15368 resolver exercises strict App Writer API request/revocation contract and all hostile fixtures. No *real* scoped credential is minted or revoked.
- **Still blocked:** target-scoped separate Release Writer App (Metadata READ + Contents WRITE), secure independently governed private-key storage and protected job/Environment, separate target Administrator READ proof (Classic/GraphQL effective rules), actual pinned Signer OIDC/Sigstore X.509, ZIP/SPDX/SLSA bytes/issuer/run/attempt, durable Publisher recovery and a distinct user-authorized PUBLISH instruction. GitHub-hosted job separation alone cannot satisfy these.
- Preserve legacy GO A Run39008743613 FAILURE, GO B/G4/G5 NO_GO, central 14-extension allowlist, Wave3 Releases 0/3, Catalog 14/70, CLI v0.3.2 verbose and formal DENY.
