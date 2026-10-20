# Issue #75 — GitHub-hosted Actions-only third-wave runtime GET witness

2026-10-20. Scope: **live metadata-only negative observation**. This is the next safe engineering step after Work PRs #144/#145, three real Windows #4/#3/#4, Catalog #138/#139, Website #38. No previous successful CI is rerun.

## Actual new capability

On a protected **build/main push only**, the workflow `.github/workflows/issue-75-wave3-actions-readonly.yml` checks out that exact commit with no persistent credentials and a job-scoped `contents:read` token; it double-GETs the actual current protected `main`, the exact-head App15368 Windows required summary and five PG14–18 jobs plus existing nonpublisher admission check, and the first public Release page in each of `pgtap`, `pg_variables` and `pg_store_plans`. It repeats GETs for all three and rejects a changed snapshot, pagination, skipped/failed/missing required checks, non-protected head, wrong App ID, bad JSON, moved SHA and unexpected endpoint.

Each output explicitly reports only `LIVE_THREE_TARGET_METADATA_NEGATIVE_ONLY`. Even if a real Release is later observed, neither its bytes/signatures nor PUBLISH approval are inferred. Inactive/authentication-failed GET causes the Action to fail; a successful run cannot turn a fake witness into a Publisher receipt. The script has a strict HTTPS GitHub GET allowlist and no POST, release, Workflow Dispatch, issuer, JWT, token exchange, environment mutation, tag or PR write.

The old 32+13 Git Blob root ledger, private Signer and Writer dormant verifiers, real-principal acceptance `--mode require-real`, fleet 14-only Publisher, local Promotion disabled, and historical GO A failure are **unchanged**. This new job does *not* repeat cryptographic validation of the 45 blobs; it **reuses** their previous evidence classification.

## 2026-10-20 extension: authenticated exact-HEAD promotion-source negative witness

The existing main/push-only GitHub-hosted read-only Action now performs **two independently fetched GETs per target** of both `config/release-promotion.json?ref=<exact-main-SHA>` and `.github/workflows/promote.yml?ref=<exact-main-SHA>`. Requests are constrained to four additional, SHA-qualified per-target GitHub Contents REST paths only. GitHub REST base64 bytes must decode canonically, match the declared exact file size and independently recomputed Git Blob SHA-1. No new Action permissions, Dispatch, writes, Secret, App or job identities are added.

- The local policy must be the exact `schemaVersion=1`, `enabled=false`, `releasePolicy=manual-dispatch` record; duplicate keys, extra claims, wrong types or enabled promotion DENY.
- The promotion workflow must retain its sole `workflow_dispatch` event and literal operator `PUBLISH`, the legacy reusable Signer pinned to `@5756b3c5136a8bf4db710016cfe97555f0a71c6d`, two publisher-code checkouts at `455f0ccc667697f600700a6e64bcfd6c57b6a977`, and the expected authorize → release_build → publish dependency source pattern. Any relevant drift DENIES this negative-only observation.
- The authenticated **second read** must match both file Blob hashes, while the protected main HEAD and CI checks must also be stable. Missing/malformed/paginated/redirected API responses DENY. The JSON output records observed Blob identities and `disabledManualPromotionPolicyObserved=true` but **always** `independentWriterVerified=false`, `publishableReceipt=false`, `publicationAuthorized=false`, GO B/G4/G5 NO_GO.
- This is a conservative source/text witness, not a complete GitHub YAML event semantics parser, effective Classic/GraphQL administration inspection, real Signer OIDC/Sigstore verification, or independent Writer credential-issued proof. It cannot establish the absence of a separately malicious workflow. It detects drift from this exact previously accepted manual-only configuration in the three current target repositories.

The recent #150 central Signer `main` source hardening is deliberately **not** an active Promotion caller repin: all three existing promote workflows still reference the historic immutable `@5756b3c5...` source. A future positive signed prewrite and controlled repin must have their own accepted real evidence before privilege enablement. No local Promotion is enabled by this test.

### Immutable exact-source acceptance (follow-up)

The preceding source predicates are now **supplemented by three independent literal Git Blob SHA pairs**, recorded from the actual authenticated main/push [Run39359805926](https://github.com/pgextwin/build/actions/runs/39359805926), job 118423070280, after the protected #151 merge. Those *GitHub-returned original bytes* were independently hashed by the observer. No source SHA is accepted merely because its YAML/JSON contains a matching phrase.

| Target | promote.yml Git Blob | release-promotion.json Git Blob |
|---|---|---|
| pgtap | `d8b2ffe43633831cd7f00dcec2135fbed18eb04a` | `fc354ed9c66fe00b539ba02e0b873b9280e42f90` |
| pg_variables | `88b7c3131ddf0a667b4947261cf5cf69bc3fe087` | `fc354ed9c66fe00b539ba02e0b873b9280e42f90` |
| pg_store_plans | `1d4280f7fd1f269a27400b3355feb5845f9ed02b` | `fc354ed9c66fe00b539ba02e0b873b9280e42f90` |

A changed policy or promotion workflow — *including a harmless comment or reformat* — intentionally breaks this negative-only job until a subsequent separately reviewed protected main PR updates the exact accepted baseline. Such breakage is a request for reinspection, not permission to waive a failed run or repin the Publisher. The unit tests use distinct synthetic Blob hashes supplied as a test argument; the production entrypoint always uses these literal real observed baseline pins. The baseline comes from prior read-only attested job logs, **not independent signed authority over effective GitHub administrative protections or Signer/Writer credentials**.

## Current observed permission boundary

From Work's authenticated GUI report at Issue #75 comment 6280683046:

- GitHub-hosted Actions can run the current read-only job without a new App, Secret, runner, plan or budget. Standard separate hosted jobs are useful for process separation but are **not alone proof** of independent credential ownership, cross-job nonpropagation or a privately governed Writer. `github.token` is not a separate Release Writer; Catalog proposer is limited to Catalog and the Classic auditor is limited to plpgsql_check.
- Build, catalog and target extensions have no configured Environment; no independently authorized private credential runtime was proven. No live Signer OIDC or independent GitHub App installation Writer was minted or verified.
- Branch `protected:true` and required check metadata can be observed with public REST GET, but they are **not** a fresh target-by-target effective Classic/GraphQL plus admin-authorized proof. Existing plpgsql_check-only Administration-read auditor cannot be silently reused for the three targets. The per-target strict rules must be independently verified with an appropriately scoped Administration:read principal before any future release privilege is enabled.

## Conditional Actions-only route, *not deployed*

A narrowly scoped, explicitly authorized GitHub App may eventually be installed only on the three selected extension repositories. For a **test-only** independently authenticated Writer, minimum GitHub permissions require Metadata READ plus Contents WRITE on exactly the selected target; a separate private key/credential custody owner and restricted Environment or otherwise genuinely isolated authorized execution is needed. A short-lived installation access token must be independently verified for installation/source/repository identity, actual effective permissions, TTL <= 3600 seconds and reliable revocation. No credential is minted by this PR.

A separate, authorized Signer role must prove genuine issued OIDC Sigstore X.509 workflow/repository/ref/SHA/attempt, actual original signed ZIP + SPDX byte hashes, trust roots and SLSA/SPDX predicates with independently pinned verifiers; the actual pinned signer checkout credential-persistence gaps must be remediated in a separately accepted cutover. The Writer must not receive the Signer OIDC token or untrusted PR code. Establish a real signed Publisher-positive prewrite in a trusted attempt-scoped job plus independently persistent schema-v2 crash-safe tag/asset journal and fail-closed replay/422 handling before considering GO B.

Any GitHub-hosted Actions-only solution must demonstrate custody and separate effective authorization, not merely job isolation by naming separate YAML jobs. If protected Environments, an independent principal, private key storage and effective rules cannot be provided using existing approved resources, stop only the privileged phase and specify the exact new App/Secret/host/plan and approval. No expanded permissions, provisioning or budget has been authorized.

## Remains NOT_READY

- GO B = NO_GO (no independent Writer + signer positive/custody + recovery)
- G4 = NO_GO (no target-bound human PUBLISH, fresh effective protection audit, or eligible candidate receipt)
- G5 = NO_GO (third-wave signed Release 0/3, public ZIPs not attested)
- Publisher = DENY, original 14 allowlist unchanged; Catalog remains actual 14/70 and CLI v0.3.2 verbose remains unchanged.

Future real UPDATE and individual PUBLISH each require their own separate explicit user instruction. The first eligible signed published third-wave Release, Catalog verified protected PR and Japanese/English Website E2E cannot be claimed from this witness.
