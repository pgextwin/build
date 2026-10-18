# Issue #75 — External Private Writer: credentialless preboot execution contract

Status (2026-10-18): **DESIGN ONLY / NOT DEPLOYED**. No privately hosted Writer, registered Release App, Secret, environment, protected private Runner or spend authorization exists as accepted proof. Nothing in this package can authorize publication or a test-token mint.

## Real purpose, not another pretend positive proof

Unlike the previous immutable negative-only acceptance snapshots, `scripts/issue-75-external-writer-preboot.py` can **actually** inspect a local directory's mode/owner and perform reproducible Decimal-based **hypothetical monthly upper-bound calculations** from an operator-supplied, untrusted vendor quote. It also analyzes the credential-free role/data-transfer **proposal**. The trust boundary remains explicit:

- A local POSIX directory with mode 0700 may be safe against basic same-host permission errors, but it is **NOT** proof of an isolated tenancy, trusted hypervisor, host operator, runner image, file-access policy or credential nonpropagation.
- The quote computation is mathematically reproducible, **not** proof that a vendor offered that rate or that an authorized GitHub billing cap was increased.
- A valid source-only flow graph is **not** evidence that live network/process credentials were isolated. No bearer, OIDC claim, scoped App secret, SHA-derived token fingerprint, or unmasked error may appear in the public report.
- The old [32 original plus 13 additional Git Blobs](https://github.com/pgextwin/build/issues/75), prior [GO B architecture contract](issue-75-private-runtime-options-and-authorization.md), original failed GO A and all previous runtime-negative proof are reused; they are not reinterpreted as an actual positive.
- The real [Signer verifier](../scripts/issue-75-private-signer-verify.py) and [Writer test mint/revoke probe](../scripts/issue-75-private-writer-app-probe.py) are **uninvoked**. Their future execution requires protected private runner + independent authorization.

## Architecture and credential flow

```text
  PUBLIC GitHub / already protected source                 PRIVATE external environment / NOT PRESENT
  ┌───────────────────────┐
  │ Reader: GET only      │
  │ No App Writer key     │
  └─────────┬─────────────┘
            │ SOURCE_SHA_AND_RUN_ATTEMPT
            v
  ┌────────────────────────────┐
  │ Signer: GitHub OIDC        │
  │ trust pinned workflow     │
  │ NO Writer App key          │
  └────────────┬───────────────┘
               │ SIGNED_PROVENANCE_NO_BEARER
               └──────────────────────────────────> ┌───────────────────────┐
                                                    │ Private Writer         │
                                                    │ independent App + Vault│
                                                    │ provenance verifier    │
                                                    │ NO Reader/Signer token │
                                                    └──────────┬────────────┘
                                                               │ SCRUBBED_JIT_METADATA
                                                               v
                                                    ┌───────────────────────┐
                                                    │ Independent auditor   │
                                                    │ NO bearer material    │
                                                    └───────────────────────┘

  NEVER: Writer key/token -> Reader, Signer or public job/artifact/cache/log
  NEVER: github.token or Catalog proposer installation = approved Release Writer
  NEVER: real OIDC issuer identity inferred from a mocked or printed JSON field
```

The public Signer acquires its GitHub-issued OIDC identity *inside* GitHub Actions. An external Writer can independently verify the cryptographic Sigstore bundle, X.509 issuer/subject, pinned workflow/source/run/attempt and ZIP/SBOM digest, but **cannot acquire that same GitHub Actions workload OIDC identity**. Actual Signer job token lifetime and checkout credential non-persistence still require separate evidence. The five deployed Signer checkout gaps identified by previous checks must be fixed in a separately reviewed/protected path before acceptance.

## Executable offline checks

Requires Python 3.10+ standard library, no packages, network, privileges or secrets.

| Call | Actual work | Exit 0 means |
| --- | --- | --- |
| `python scripts/issue-75-external-writer-preboot.py --mode static` | Validate immutable role/source graph, prior 15 unproven controls + five rollback phases, exact future JIT metadata allowlist and forbidden credential field names | Proposed policy is internally consistent; **NO private runtime, credential positive, JIT verification, budget approval or publication** |
| `python scripts/issue-75-external-writer-preboot.py --mode local-dir --workspace /absolute/private/path` | In addition to policy: POSIX stat / lstat of existing absolute directory, deny symlinks, require 0700, require current OS owner and resolved unchanged path, refuse repository workspace | Local owner-only filesystem **mode** only; not tenancy, vault, mount, process, cross-job or Secret isolation |
| `python scripts/issue-75-external-writer-preboot.py --mode static --quote path/to/nonsecret-quote.json` | Compute an upper bound from explicit user-supplied yen rates and quantities using exact decimal and ceiling rounding. E.g. 40 hours×15.5 JPY + 10 GB-month×3 + 4 GB×2.25 + fixed 100 = 759 JPY; 20% contingency = ceiling 910.8 = 911 JPY | Arithmetic consistent and **still not a verified vendor quote, approved budget, capped actual bill or buying decision** |
| `python scripts/issue-75-external-writer-preboot.py --mode require-live` | Refuse to treat a manifest/quote/0700 directory as real work authorization | **Always exit 2, DENY** |

The example pricing is deliberately hypothetical; do not present 15.5 JPY/hour as a real product rate. A real vendor estimate must separately include actual region/SKU, bandwidth, SSD/vault/audit-retention and tax/FX as applicable, host uptime, maximum test duration, storage and logging footprint, specific stop/spend cap, responsible payer and an explicit approved maximum spend. A `--quote` file is purely a scratch calculation and is never promoted into the immutable baseline record.

**Quote JSON structure** (supply your own actual vendor figures only when independently sourced; this is a synthetic example):

```json
{
  "currency": "JPY",
  "status": "USER_SUPPLIED_NOT_VERIFIED",
  "rateJPY": {
    "computeHour": "15.5",
    "storageGBMonth": "3.00",
    "egressGB": "2.25",
    "monthlyFixed": "100"
  },
  "limit": {
    "computeHours": 40,
    "storageGBMonths": 10,
    "egressGB": 4
  },
  "bufferPercent": 20,
  "approval": "NOT_APPROVED",
  "reference": "EXAMPLE_NOT_A_REAL_VENDOR_QUOTE"
}
```

Bounds: nonnegative decimal rates, maximum 4 decimal places, up to 10 million JPY per unit, quantities 0–10,000, 0–100% contingency, max bound 1 billion JPY, never accepts bool-as-int, NaN, Inf, scientific notation, negative values, unexpected JSON keys, duplicate keys, credential values or a claimed approved quote. This is **no billing API**, account estimate or effective invoice limit.

## JIT metadata allowlist (future **private**, independently verified)

Accepted *field names* are limited to:

```text
sourceSha, sourceRepo, runId, attempt, signerWorkflowSha,
signedZipSha256, sigstoreRootSha256, toolSha256, writerAppId,
installationId, targetRepositoryId, scopeClass,
tokenTtlSeconds, revoked, independentAuditRef
```

These 15 *keys* are **not** valid evidence unless an authenticated independent verifier signed the corresponding values. Raw app JWT, OIDC bearer, installation token, private key, Authorization header, credential hashes, dump/cache entries, debug traces are forbidden **including in exceptions, stdio, process arguments, artifacts and logs**. Never log candidate raw successful `gh attestation verify` JSON if it may include sensitive content; emit only scrubbed structured results after crypto verification.

Before any real test: resolve the trusted tool hash, protected source SHA, separately authenticated Signer certificate, independent Writer App issuer/installation authorization, exact single-repo scope, token TTL ≤1 h, *revocation confirmed*, job/process isolation and negative access denials, with a separately approved private credential store. An App installation ID/name from Work GUI is not itself an authenticated principal.

## Phased recovery / changes not granted by this PR

| Phase | Preconditions | Reversible stop |
| --- | --- | --- |
| A: nonprivileged design + CI | Existing protected main + App15368 required resolver, immutable 32+13 roots; this script's static tests | Revert only through a *new protected PR* and required CI; do not delete old evidence |
| B: private host / vault | Explicit hosting owner/provider, approved cap and quota, protected immutable source/runner image, vault policy, reader/signer/writer isolation, independent permission audit | Disconnect/disable new executor and do not inject keys |
| C: actual signer crypto | Approved trusted gh tool/bundle root hash, real Sigstore/X.509 identity and 5-checkout remediation, exact run/attempt + source/ZIP/SBOM | Stop, quarantine proof or artifacts, no Writer credential |
| D: Writer scope proof | Real **independent** GitHub App installation + isolated vault, test-only principal, one-repo contents:write, signed approvals | Promptly revoke test token; if revoke uncertain, quarantine and disable App access via separately approved admin operation |
| E: positive prewrite/recovery | Independently signed Publisher positive, fully proven GO B/G4/G5 and schema-v2 crash-safe replay, no missing external SHA closure | NO_GO, retain old production pins and never publish |

**No action in B–E is approved/executed.** The current pgextwin Organization has no observed private repository, Environment or self-hosted runner. GitHub Free organization private Environment and deployment review features have limits; as of this audit, no paid upgrade is approved. GitHub-hosted standard public workflows continue to succeed; $0 Usage blocked in private billing UI does not negate their success.

References:
- [GitHub deployment environments](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments)
- [Actions billed vs free usage](https://docs.github.com/en/billing/concepts/product-billing/github-actions)
- [GitHub App installation token permissions/repository/expiry](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app)

### Postmerge acceptance checklist

New protected PR + full App15368 required resolver SUCCESS; exact-head squash after branch protection confirmed; postmerge push run & required resolver SUCCESS; original failed GO A unchanged; standalone synthetic unit-success and local directory checks **NEVER** a positive credential attestation. Formal P1 remains 65/70, independent source 40/40, five historical plpgsql_check DENY, GO B/G4/G5 NO_GO, formal Release/distribution DENY.
