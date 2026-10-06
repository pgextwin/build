# GitHub Actions trust and permission policy

This document defines the pgextwin GitHub Actions trust baseline established in Step 5 and the Artifact Attestation permission boundary added in Step 6.

## Scope

The policy covers:

- immutable full-SHA references for remote GitHub Actions,
- immutable full-SHA references from extension repositories to shared reusable workflows,
- identical revision selection for reusable workflow definitions and co-located build scripts/metadata,
- least-privilege `GITHUB_TOKEN` permissions,
- release-only OIDC and Artifact Attestation permissions,
- and regression guards for those trust boundaries.

SBOM generation, PACKAGE-INFO v2, broader dependency locking, upstream source commit expansion, compiler/toolchain provenance, Chocolatey provenance, Catalog/Website attestation visibility, and PostgreSQL 19 production onboarding remain separate work.

## Remote Action pin policy

Every non-local `uses:` dependency committed to this repository must use a full 40-character commit SHA.

GitHub-owned actions also keep a same-line human-readable version comment:

```yaml
uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
```

The SHA must be resolved from the action's official GitHub repository. Do not copy a SHA from a fork or third-party mirror.

The current baseline is:

| Action | Full commit SHA | Version |
| --- | --- | --- |
| `actions/checkout` | `3d3c42e5aac5ba805825da76410c181273ba90b1` | `v7.0.1` |
| `actions/setup-python` | `ece7cb06caefa5fff74198d8649806c4678c61a1` | `v6.3.0` |
| `actions/setup-node` | `249970729cb0ef3589644e2896645e5dc5ba9c38` | `v6.5.0` |
| `actions/upload-artifact` | `043fb46d1a93c77aae656e7c1c64a875d1fc6a0a` | `v7.0.1` |
| `actions/download-artifact` | `3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c` | `v8.0.1` |
| `actions/attest` | `1e69f48acb82d1966a394da916b4c1698aa569d6` | `v4.2.2` |

GitHub Actions Dependabot remains enabled for this repository.

## Reusable workflow self-pin contract

Extension repositories pin all three shared workflows to the same approved build commit SHA:

```yaml
uses: pgextwin/build/.github/workflows/build-extension.yml@<40-character-build-commit-sha>
uses: pgextwin/build/.github/workflows/build-extension-attested.yml@<same-40-character-build-commit-sha>
uses: pgextwin/build/.github/workflows/release-extension.yml@<same-40-character-build-commit-sha>
```

Both build workflows check out their co-located scripts and metadata using:

```yaml
repository: ${{ job.workflow_repository }}
ref: ${{ job.workflow_sha }}
```

The caller SHA therefore fixes the workflow definition, scripts, and metadata to one immutable revision. Mutable `@main` references are forbidden.

## Why normal and attested builds are separate workflows

GitHub reusable-workflow token permissions are monotonic: the called workflow can keep or reduce permissions passed by the caller, but it cannot elevate them. Artifact Attestation also requires the caller and the called workflow to have the necessary attestation/OIDC permissions.

A single reusable workflow that statically requests release-only write scopes cannot also be safely called from a caller granting only `contents: read`; GitHub validates the nested permission contract before build jobs start. Therefore Step 6 uses two build reusable workflows with separate permission contracts:

- `build-extension.yml`: normal PR/main/non-release build; read-only.
- `build-extension-attested.yml`: release build; build/test/package plus provenance generation and verification.
- `release-extension.yml`: publication only; `contents: write`.

This separation preserves the PR trust boundary without granting dormant OIDC or attestation write scopes to ordinary builds.

## Caller permission model

| Path | contents | id-token | attestations | artifact-metadata | Purpose |
| --- | --- | --- | --- | --- | --- |
| PR normal build | read | none | none | none | Build/test/package only |
| main normal build | read | none | none | none | Build/test/package only |
| non-release workflow_dispatch | read | none | none | none | Build/test/package only |
| release build | read | write | write | write | Build/test/package, attest and verify final ZIP |
| release publish | write | none | none | none | Download unchanged ZIPs, create checksums/notes, publish Release |

The current `actions/attest` contract requires `artifact-metadata: write` in addition to `id-token: write` and `attestations: write`. It is therefore granted only to the release build path.

`id-token: write` is used to mint the short-lived OIDC identity used to obtain the Sigstore signing certificate. `attestations: write` persists the attestation. `artifact-metadata: write` permits the artifact storage record used by the current action implementation.

The release publication workflow keeps only:

```yaml
permissions:
  contents: write
```

Do not introduce `pull_request_target`. Fork or pull-request code must never execute with release write or OIDC permissions.

## Artifact Attestation contract

`build-extension-attested.yml` performs, per PostgreSQL-major matrix job:

1. build,
2. install,
3. functional smoke test,
4. final ZIP packaging,
5. `actions/attest` SLSA build provenance generation for `dist/*.zip`,
6. `gh attestation verify` constrained to the caller repository and `pgextwin/build/.github/workflows/build-extension-attested.yml`,
7. upload of the unchanged ZIP.

The publication job later downloads those ZIP bytes, creates `SHA256SUMS.txt`, and publishes the assets without repackaging them.

See [Artifact Attestations and build provenance](artifact-attestations.md).

## Updating the shared build revision

Use this sequence:

1. change `pgextwin/build` on a branch,
2. run and review the build repository CI,
3. merge and record the resulting `main` commit SHA,
4. update all three reusable-workflow references in each extension caller to that exact SHA,
5. run extension Windows CI,
6. merge only after the new shared revision passes.

## Regression guard

`tests/test-github-actions-security.py` rejects:

- remote `uses:` references that are not full 40-character SHAs,
- GitHub-owned action SHA pins without a same-line version comment,
- `permissions: write-all`,
- `pull_request_target`,
- mutable `pgextwin/build@main` source checkout,
- OIDC/attestation permissions or `actions/attest` in the normal build workflow,
- missing release-build attestation permissions,
- an unapproved `actions/attest` pin,
- incorrect package → attest → verify → upload ordering,
- removal of `SHA256SUMS.txt`,
- and OIDC/attestation permissions in the release publication workflow.

Organization-level **Require actions to be pinned to a full-length commit SHA** remains enabled.

## Boundary with later supply-chain steps

Step 6 intentionally does not add:

- SPDX,
- CycloneDX,
- Syft,
- SBOM attestations,
- PACKAGE-INFO v2,
- expanded upstream source commit SHA recording,
- compiler/toolchain provenance fields,
- Python dependency locking,
- Chocolatey package provenance,
- Catalog/Website attestation visibility,
- or PostgreSQL 19 production support.
