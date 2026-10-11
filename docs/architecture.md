# pgextwin build architecture — current 14-extension operation

## Repository responsibilities and trust boundaries

```text
pgextwin/build (central shared infrastructure)
  ├─ metadata/automation-fleet.json            14 BUILD candidates / daily 00:00 UTC
  ├─ metadata/release-promotion.json            14 operator-only publish entries
  ├─ metadata/unattended-publication.json       OBSERVE / DENY (no auto release)
  ├─ PostgreSQL lifecycle and major-matrix resolution
  ├─ reusable read-only Windows build + Test Contract / PACKAGE-INFO
  ├─ signed Windows build, SPDX SBOM and Grype report-only validation
  ├─ fleet-promotion-gate.py                    verify merged candidate and operator
  ├─ fleet-publish-release.py                   fail-closed create-only Release
  └─ read-only candidate/fleet monitoring

each of the 14 extension repositories
  ├─ config/extension.json, candidate-build.json, release-promotion.json
  ├─ .github/workflows/update-watch.yml         SHA-pinned stable candidate planner
  ├─ .github/workflows/windows.yml              PR/main/candidate read-only Windows CI
  ├─ .github/workflows/promote.yml              MAIN workflow_dispatch + PUBLISH ONLY
  ├─ windows/ci/build.ps1, install.ps1
  └─ windows/ci/smoke-test.ps1, package.ps1

pgextwin/catalog / pgextwin/website
  └─ independently verified signed manual Release → opt-in Catalog PR
     → Catalog CI/merge → Website publish and public verification
```

All **14** extension repositories have `BUILD`, `candidateEnabled=true`, `releasePolicy=manual-only` and a daily 00:00 UTC / 09:00 JST central candidate schedule. This registry enables candidate preparation, **not formal release authorization**. Local `config/candidate-build.json` must also permit candidates. A fresh stable upstream update may generate an immutable-SHA Draft PR; no PR merge or Release follows automatically.

Extension-specific Windows adaptation, exported symbols, preload requirements, SQL and runtime tests remain local. Shared scripts provide the common safety contract, packaging and provenance.

## Normal Windows CI vs formal Release

- The local **`windows.yml`** is `pull_request`, `main` push or explicit `workflow_dispatch`, uses the full-SHA-pinned reusable `build-extension.yml` and only `contents: read`; it does **not** publish.
- The local **`promote.yml`** is exclusively `workflow_dispatch` on `main`. Inputs are `candidate_pr`, `candidate_run_id`, `decision_run_id`, `release_tag`, `confirm_release`. A non-bot operator must type **`PUBLISH`**. Central plus local manual-promotion policy, merged identity-pinned candidate, provenance receipts, correct latest SHA and all supported PG Windows jobs must verify before publishing.
- On authorization, `build-extension-attested.yml` rebuilds supported PG majors with restricted `contents: read`, `id-token: write`, `attestations: write` and `artifact-metadata: write`. ZIP and SPDX attestations must match the original built/validated artifact bytes.
- The local final publish job calls full-SHA-pinned `fleet-publish-release.py`, compares SHA-256, attestation and candidate receipt, and creates a **new Release identity only**. An existing tag or Release must fail closed; partial Draft recovery is evidence, not a license to overwrite assets.

**Important historical distinction:** `release/*` branch pushes are **no longer a publisher trigger** in the current 14 extension callers. The older shared `release-extension.yml` remains for compatibility but does not define current release permission. Never use older `release/*` runbooks as a current operating procedure. Different caller paths may pin **different** approved full 40-character build commits; inspect the exact local workflow refs, rather than assuming all reusable calls use one common ref.

## PostgreSQL lifecycle boundary

`metadata/postgresql.json` defines support and EOL. The shared `scripts/resolve-matrix.ps1` intersects lifecycle with each extension manifest and upstream refs. Normal runs use UTC calendar dates; tests can supply `-EffectiveDate yyyy-MM-dd`. The EOL date is inclusive: PostgreSQL 14 remains in the new build matrix **through 2026-11-12** and is excluded beginning **2026-11-13 UTC**. Historical tags, releases and ZIPs are never deleted at EOL.

## Candidate acceptance vs publication acceptance

A green fleet summary means the observer completed; it **does not** prove every upstream has a new candidate, the candidate is verified, or any Release was published. Verify the current decision run's `candidate-decision`, exact-head Windows job successes, `candidate-audit`, merged PR and source SHA independently.

The default unattended policy is **`OBSERVE / DENY`**, with `automaticCandidateMerge=false`, `automaticFormalRelease=false`, `automaticCatalogMerge=false`. Catalog ingestion after an operator-published Release is a separate signed-asset-verification path. Its GitHub App proposer feature is intentionally opt-in, and a real public-Release → Catalog PR → Website end-to-end acceptance still requires a genuine subsequent manually approved Release.

See the [14-extension queue and release runbook](step23-manual-queue.md), [PostgreSQL lifecycle](postgresql-lifecycle.md), [Artifact Attestations](artifact-attestations.md), and [fleet readiness tracker](https://github.com/pgextwin/build/issues/61).
