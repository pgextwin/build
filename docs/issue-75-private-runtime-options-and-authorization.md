# Issue #75 — Minimum isolated runtime options and authorization contract
Date: 2026-10-18 JST. Scope: **design and negative-only preflight**. No resource, GitHub App, Secret, privileged workflow, budget, Tag or Release is deployed.

## Starting, verified and reported facts

- build/main protected `cbe61b34ade29115d9c359402e8117a9caba3c08`; PR #132 MERGED; postmerge Run 39116480961 push attempt1 SUCCESS; Issue report 6248392031. Existing 32+13 Git Blob source, 45 total, Reader/Signer/Writer negative witness and Work-GUI evidence remain immutable references.
- The 2026-10-18 Work GUI report says the pgextwin organization has **no private repo**, build/plpgsql_check have **no Environment** and no self-hosted Runner; private environments outside those views remain unobserved. GitHub Free, 2000 private minutes included/month as reported in GUI; Actions budget $0/Usage blocked. This is **not** proof that existing public GitHub-hosted workflows cannot run (postmerge success is counterevidence).
- The active pilot Signer declares OIDC capability but does not independently prove a live issued principal and has five deployed checkout credential-persistence gaps. Production Publisher Writer is still `github.token`, not a separately verified GitHub App installation identity. Catalog App does not stand in for Release Writer.
- Source documentation checked 2026-10-18: [GitHub Environments](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments) explains the public/private repository plan restrictions: GitHub Free environments and associated secrets are for **public** repos; private repo Environment features require an eligible paid plan. [Deployment protection](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments) notes that required reviewers on GitHub Free, Pro and Team are restricted to public repositories. [Actions billing](https://docs.github.com/en/billing/concepts/product-billing/github-actions) documents free standard hosted runners on public repos and charging/free allowances for private repos; **do not translate reported $0 UI to actual costs or a guaranteed private CI success**. [GitHub App scoped token](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app) documents installation tokens limited to repositories/permissions and an approximately one-hour expiry; effective app installation scope must be checked separately.

## Architecture selection

| Path | Role boundary | Deployment constraints | Cost classification | Decision |
| --- | --- | --- | --- | --- |
| **A: Public protected Reader+Signer, privately governed external Writer** | Reader stays GET-only in protected GitHub main. Signer uses OIDC/attestations **only in its separately pinned, no Writer key** workflow. Private Writer verifies immutable provenance through an independently trusted tool before any key/token access; a different private Executor/secret store/identity controls Writer | Requires explicit approval and creation/provisioning of an off-GitHub private host or cloud tenancy and a dedicated Release Writer GitHub App; existing environment is NOT_PROVEN. Must prove protected immutable source, no PR untrusted code, precise permissions, separate outputs, credential custody and authenticated JIT evidence | **UNQUOTED**; cannot assume free external hosting, zero maintenance, or that public Actions is all-free after new artifacts/storage | **Preferred design only; NO_GO for execution** |
| **B: GitHub private org repo + protected environment** | Reader/Signer/Writer in distinct jobs/environments, with independent credentials and review barriers | No private repo/env today. GitHub Free org lacks the required private Environment capabilities. Paid-plan upgrade or redesign and permissions review needed; even after upgrade, private repo setup and separate secret custody alone do not prove runtime isolation. Private deployment required-reviewer rules may remain unavailable on Team/Pro | **UNQUOTED**, new plan and private-runner minutes/storage possible. A budget increase is **not authorized** | Conditional; NO_GO |
| **C: Public GitHub Environment + Writer secret** | A separate Environment in a public repo might provide job-level secret gating, but shares the public repo/workflow risk and lacks an independently private credential executor under this threat model | Environment absent; public PR risk, workflow/privileged job tamper/approval bypass must be independently controlled. Do **not** equate secrets-in-public-repo with a private runtime | **UNQUOTED**, no guarantee of protected custody | Reject as the requested private isolation; NO_GO |

**Recommendation:** Path A as a future architectural design only. In particular, an external Writer must **NOT attempt to acquire a GitHub-Actions-scoped OIDC identity itself**. The real GitHub OIDC/Sigstore signer identity is acquired only by an authorized GitHub Actions Signer workflow. The external, isolated Writer checks the *real signed Signer attestation*, exact immutable workflow SHA, ZIP digest, source/ref/run/attempt and a separately authenticated Actions/approval receipt. It cannot infer signer runtime token non-propagation from attestation alone. A distinct independent runtime observer must prove Writer/Signer credential isolation.

## Trust boundaries and exact preconditions

```text
PUBLIC / protected main                                      PRIVATE / not provisioned
GitHub Reader (GET-only)                                      Independent verifier
    | source SHA, run/attempt, SHA256 only                     + SHA-pinned gh binary/trust roots
    | (no bearer/JWT, not a job artifact with token)          + authenticated run evidence
    v                                                         |
GitHub Signer (OIDC & Sigstore, no Writer App key)             |
    | trust-root-bound SLSA+SPDX signed provenance ---------> verify real X509 + ZIP/SBOM
    | five-checkout persist-credentials gap must be fixed     |
    |                                                         v
    X-- NO credential or GITHUB_TOKEN transfer --> private Writer distinct App + vault
                                                              |
                                                      authorized test-only mint
                                                      exact 1-repo contents:write
                                                      API GET scope/TTL, revoke
                                                              |
                                                      scrubbed nonpublishing JIT report
                                                              X no Release/Tag/Publisher
```

Independent security requirements, each separately verified rather than a boolean in public JSON:

1. **Tenancy / source:** approved private host, named owner, dedicated nonpublic storage and key vault, protected immutable source commit and trust anchors, verified private runner image/tool digest, mandatory App15368 resolver on the protected GitHub source ref. Reject fork-PR and `pull_request_target` credential-bearing steps. Signed security policy must be immutable to the untrusted code being checked.
2. **Reader:** no Writer secrets or Signer private key, GET-only app token permissions and no persistent checkout token. Its public GET success is not effective-scope proof.
3. **Signer:** real GitHub-issued OIDC certificate/Sigstore provenance, exact immutable trusted Signer SHA, actual run ID/attempt, source commit/ref and SLSA/SPDX ZIP digest; all checkouts including reusable workflows `persist-credentials:false` deployed and proven in protected workflow; no Writer token.
4. **Writer:** separately registered and authenticated GitHub App installation, explicit app_id/installation_id/owner and repository ID authenticated from GitHub API, minimum `contents:write` to exactly intended repo, test-mint short TTL (max one hour) and reliable `DELETE /installation/token` revocation. No scope derived from a token body or app display name. Existing Writer `github.token` and catalog App do not qualify.
5. **Non-propagation:** separate credentials, runner/OS execution contexts, vault policies and outbound access logs; no GITHUB_OUTPUT, GITHUB_ENV, cache, artifact, build tree, process dumps, traces or logs with bearer data; independent negative access tests from each role and scoped private audit proofs. Synthetic tests do not prove job/runtime isolation.
6. **Release authorization & recovery:** actual JIT signed Publisher positive prewrite, pinned full transitive SHA closure, protected main and mandatory CI, independent credential principal proof, signed schema-v2 recovery and real crash-safe replay. No `GO` until every gate is actually evidenced. Original GO A failed Run remains failed.

## Staged readiness, rollback and cost approval

- **A / Now, zero privilege:** preserve all 32+13 immutable source proofs, PR #127–132 negative only, gate tests. Exit criterion is protected PR + App15368 success + exact-head protected merge + postmerge Validate; this does **not** authorize Writer mint. Rollback by a NEW protected revert PR with the same mandatory checks, never by bypassing branch protection.
- **B / Private host approval:** identify/existing-vs-new private executor, storage, owner, security budget and an explicit maximum spend (no implied permission to upgrade or change $0), audit retention and emergency revocation plan. Test with **no keys** first; if any paid-plan or provisioning change is necessary, obtain the corresponding authorized decision. No private infra is currently observed.
- **C / Private trust and Signer proof:** fix Signer checkout persist-credentials gap in a separately reviewed/pinned protected path before treating it as custody-proven. Hash-pin real gh binary/trust roots/executor image. Verify actual signed ZIP/SBOM and OIDC certificate, run/attempt through existing dormant `issue-75-private-signer-verify.py`, then independent execution-boundary proof. Failure: quarantine artifact, no publication.
- **D / Writer proof with separate authorization:** independent App install and key storage, exact GitHub-authorized scope and test-only issuer validation, one token minted only in approved private executor then immediately revoked using existing dormant `issue-75-private-writer-app-probe.py`. On revocation failure: block further tests, disable/revoke key through approved operation, preserve sanitized JIT log; do not display keys or tokens.
- **E / Future prewrite & recovery:** only once C/D + all GO B/G4/G5 gates and signed schema-v2 evidence are genuinely approved, consider a separately authorized protected Publisher change. Never silently replace production pin or publish while any gate is NO_GO. Rollback retains old immutable pin, freezes Writer key, revokes test tokens and denies all new Release attempts.

For **costs**, current external tenancy = **not discovered**, SKU/usage = **unknown**, App administrative requirements = **unverified**. No estimated dollar amount is accepted as a budget increase; quote a specific vendor, runner duration, storage, artifact retention and reviewer burden before provisioning.

## Machine validation / non-authorizing CLI

`evidence/issue-75/private-runtime-options-contract-20261018.json` records all three alternatives, 15 unresolved controls, 5 staged rollbacks, full old Signer/Publisher pins and every security gate as NO_GO. `scripts/issue-75-private-runtime-options.py --mode static` only verifies consistency with existing GUI/32+13 roots; success means **NONPRIVILEGED_OPTIONS_CONTRACT_PASS_NO_LIVE_APPROVAL**. `--mode require-execution` returns code 2 **unconditionally**. Tests exercise forged plan availability, JWT App claims, self-asserted GO flags, changed budget, phase reordering, deleted rollback, wrong Singer/Publisher pin and missing old evidence. This script does not create private infrastructure, access network/token or add privileged workflow. Passing App15368 CI is not live credential acceptance.

**Permanent safety state:** P1 65/70; independent source 40/40; plpgsql_check PG14–18 historic five DENY; GO B/G4/G5 NO_GO; final Release/distribution DENY; original GO A failure unwaived.
