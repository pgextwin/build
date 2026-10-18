# Issue #75 — Trusted-main Reader / Signer / Writer principal boundary (nonpublishing)

## Bounded change and unavoidable public-log limit

This is a **protected-main push-only, nonpublishing negative witness** in the
public `pgextwin/build` repository, not a private GitHub runner or
confidential log. It never transfers real Signer/Writer secrets, performs
promotion, emits release receipts, publishes an artifact or mints a Writer
token. **Do not use sensitive credentials in this public workflow.**
PR source runs only static/hostile tests inside the existing read-only
`validate.yml` resolver. The real negative witness is triggered only after
an ordinary protected PR is merged to main, and only when the workflow, its
script or its focused test changes.

## Current fixed credential boundary

| Role | Production state (unchanged) | This witness | What it cannot prove |
| --- | --- | --- | --- |
| Reader | Existing `issue75_reader_probe` PR-only `contents:read`, `actions:read`; transport GET-only | Dedicated protected-main job, `contents:read` + `actions:read`, step-local `github.token`. Two each of allowlisted GET run/main; no Git credential persistence. | Effective token scopes, cryptographic token uniqueness, real signed Publisher prewrite |
| Signer | Existing pinned `build-extension-attested.yml@5756b3c5136a8bf4db710016cfe97555f0a71c6d`, `contents:read` + OIDC/attestation write, five checkout credential-persistence gaps | **Inert role**, `contents:read` only. No OIDC, signing, App token, Secret or publication credential. | Real Signer OIDC principal, signing, runtime closure or deployed checkout fix |
| Writer | Existing `plpgsql_check/promote.yml` has separate `publish` job with `contents:write` after gated Signer | **Inert role**, `contents:read` only. No release tag/ref write, App token or Secret. | True Writer principal and positive authenticated Writer/Signer separation |

The script does not try to introspect `github.token`, dump environment,
fingerprint tokens, write artifacts or probe mutations. The public-job log
only contains fixed-field JSON without token values or HTTP response bodies.
All jobs use full action commit pins and
`actions/checkout` with `persist-credentials: false`.
No `pull_request_target`, `workflow_dispatch` or `workflow_call` on the
new witness; no branch protection, organization permission, secret, budget,
Signer/Publisher pin, production workflow or release policy change.

## Acceptance and failure closure

- Required `resolver` executes hostile synthetic fixture tests on every PR.
  Failure, skip, timeout, unknown context, unexpected role, non-main ref,
  rerun attempt, branch-protection drift, identity conflict, pagination,
  redirect, mismatched or missing GET all **DENY** and return nonzero from
  the trusted witness. The observer never prints exception or HTTP text.
- Protected-main Reader may report `READER_GET4_NEGATIVE_ONLY` only for
  four successful authenticated **request attempts** (two current-run
  identity, two branch identity) with exact main SHA, event, attempt and
  `protected=true`; because the public endpoint may also be readable
  anonymously, this is **not proof of token scope or distinct principals**.
- Inert Signer/Writer roles report `*_UNPROVISIONED_NO_WRITE` when their
  job context is correct and no explicit `GH_TOKEN` or `GITHUB_TOKEN`
  environment is passed into the step. A built-in `github.token` context
  still exists in GitHub Actions and is **not proven absent**; there is no
  privileged credential provisioned or used in this witness.
- Even if all jobs pass, machine-readable
  `authenticationBoundary=NOT_PROVEN`,
  `crossRoleTokenDistinctnessVerified=false`,
  `signerRealIdentityVerified=false`,
  `writerRealIdentityVerified=false`,
  `signedPublisherPositivePrewriteVerified=false`,
  `publicationAuthorized=false`,
  `goB/g4/g5=NO_GO`. Successful static or inert runtime checks must not
  be recast as a real Signer/Writer positive proof.
- Reuse the existing **32 immutable Blob ledger + 13 extra Blob delta +
  credentialBoundaries graph**, Reader probe, Signer hardening proposal,
  sandbox probe, and their hostile fixtures. Do not rewrite those records
  or silently upgrade historical proof categories.

## Separate actual authenticated split gate — NOT PROVEN

An actual separate Signer principal must use a trusted, independently
reviewed, appropriately pinned nonpublishing Signer runtime with OIDC and
attestation identity, in a private or comparably isolated trusted job where
untrusted PR code cannot execute. Writer must be a *different*, narrowly
permissioned short-lived installation principal whose token never crosses
Reader/Signer jobs, and an independently permitted **read-only** witness
must prove the scopes, freshness and provenance without logging secrets.
No credential is authorized or provisioned by this PR; the old active
`plpgsql_check` publisher and Signer pins remain unchanged.

GO A historical FAILURE is not waived. Original P1 = **65/70**,
independent source = **40/40**, historical plpgsql_check PG14–18 = **five
DENY**, GO B/G4/G5 **NO-GO**, P1 BLOCKED/P2 NO-GO and formal
Release/distribution **DENY**. HTTP 403 candidate audit comment remains
unposted. No unsigned dispatch, release, tag or publish authorization.
