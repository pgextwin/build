# 17-extension Promotion unification — source-only compatibility stage (2026-10-21)

This is an implementation checkpoint, **not an authorization to publish**. The 17/17
immutable daily-verifier rollout and actual protected Windows PG14–18 postmerge
acceptance have already succeeded and are preserved:
[build #141 evidence](https://github.com/pgextwin/build/issues/141#issuecomment-6313341736),
[build #75 security evidence](https://github.com/pgextwin/build/issues/75#issuecomment-6313350999).
Do not rerun those completed workflows.

## Live architecture inventory

- The 13 legacy-promoter repositories among the original 14 published extensions
  have independent 143-line `.github/workflows/promote.yml` files invoking the
  approved legacy central gate and Publisher source
  `build@455f0ccc667697f600700a6e64bcfd6c57b6a977` and signed builder
  `build-extension-attested.yml@5756b3c5136a8bf4db710016cfe97555f0a71c6d`.
  These 14 existing Release assets and Catalog records remain untouched.
- The remaining original released extension, `plpgsql_check`, and the three
  Wave3 repositories `pgtap`, `pg_variables`, `pg_store_plans` have thin
  `promote.yml` callers pinned to historical shared immutable commits
  (`5425225ea858f8c0165421902c3e66c6c9205f60` and
  `acd6eb28be6d750e89b626fa4ccd4403e1265cd6`, respectively).
- Current central shared `promote-verified-release.yml` is a **source-only**
  compatibility preparation, with caller-independent ZIP artifact glob, and immutable
  signer `5756b3c5136a8bf4db710016cfe97555f0a71c6d`. The newer gate/Publisher
  implementation is pinned to `build@dd4d35186edccfbf39b40d86cecb28380cf210da`.
  It is **not independently accepted as a production runtime** for the current
  Wave3 gates.
- This PR changes only the central *closed caller-identity filter* to all 17 named
  repositories. It does **not** edit any deployed `promote.yml`, the signed builder,
  the fixed Publisher implementation, local release flags, central policy, secrets,
  branch protection, Catalog, Website or published Releases.
- `metadata/release-promotion.json` continues to allow only the original 14
  released repositories. All 3 Wave3 local `config/release-promotion.json`
  retain `enabled=false`, `releasePolicy=manual-dispatch`.
  The shared workflow's identity filter is **not** the publication approval gate.

## Mandatory fail-closed deployment conditions

1. Keep exact per-repository allowlists; a 17-member source filter is **not** the
   17-member production publication allowlist. Preserve literal PUBLISH, user and
   candidate run identities, protected PR required checks, upstream immutable source,
   tag create-only, signed ZIP/SPDX provenance, and independent publisher verification.
2. Obtain effective Classic branch-protection evidence from the independently scoped
   Administration:read auditor for each Wave3 repo. REST `protected=true` or App15368
   CI alone is insufficient. Do not broaden App permissions automatically.
3. Verify the *actual* immutable signer commit and workflow and GitHub OIDC/Sigstore
   X.509 subject on the original ZIP/SBOM/SLSA predicate for the real run/attempt;
   verify separately scoped Writer/Publisher custody, short-lived token, revocation,
   prewrite/partial-Draft recovery, and exact release asset digests.
4. Compare old 14-repository gate/Publisher behavior versus proposed shared runtime
   on adversarial fixtures and an authorized nonpublishing pilot. Do not repin an
   existing working 14-repository release path merely because its caller is listed
   centrally. Do not replace accepted signer SHA without provenance acceptance.
5. After runtime and policy gates are independently accepted, stage each caller
   as a minimal immutable `workflow_call` wrapper, one protected PR per repo,
   with exact-head PG14–18 CI, stable App15368 required summary and main/push
   postmerge. Keep `workflow_dispatch` and `confirm_release=PUBLISH` until
   an independently reviewed chat-authorization PR replaces them safely.
6. Enable Wave3 target-scoped policy **only after** the separate real operator
   authorization and signer/Publisher acceptance; verify a real (not mock) signed,
   attested five-major Release, public bytes/SHA256 and original provenance. Only then
   allow Catalog's independent signed-release verifier to propose a scoped protected PR;
   CLI + EN/JA Website follow verified Catalog. No premature 15th–17th Catalog record.

## Accepted at this source-only stage

Central workflow YAML still requires exact PUBLISH, 14-entry production policy
through `fleet-promotion-gate.py`, local `config/release-promotion.json`,
unchanged signed builder SHA, fixed gate/Publisher SHA, and `needs:
[authorize, release_build]`. The test suite checks **exactly 17 named callers**,
no wildcard, 14 production-approved repositories only, 3 denied Wave3 targets,
and no automatic or unauthenticated publication. No Wave3 formal Release is claimed.

## Operational status

- Scheduled verifier + full Windows postmerge: **17/17 ACCEPTED**.
- Shared Promotion central source caller-compatibility: **17/17 staged**.
- Migrated, validated production Promotion execution: **NOT established** for all
  17; original 14 remain on their known production route.
- Wave3 signed Windows formal Releases: **0/3**. GO B/G4/G5 **NO_GO**,
  PUBLISH **DENY**, no authorized Release/Tag.
- Central 09:00 JST read-only upstream schedule `0 0 * * *` remains unchanged.

Evidence/next action tracker: [build #75](https://github.com/pgextwin/build/issues/75)
for independent runtime authorizations; [build #141](https://github.com/pgextwin/build/issues/141)
for Wave3 formal release verification and public handoff.
