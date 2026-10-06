# GitHub Actions trust and permission policy

This document defines the pgextwin GitHub Actions trust baseline established in Step 5 and the Artifact Attestation permission boundary added in Step 6.

## Scope

The policy covers:

- immutable full-SHA references for remote GitHub Actions,
- immutable full-SHA references from extension repositories to the shared reusable workflows,
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

Extension repositories pin both shared reusable workflows to the same approved build commit SHA:

```yaml
uses: pgextwin/build/.github/workflows/build-extension.yml@<40-character-build-commit-sha>
uses: pgextwin/build/.github/workflows/release-extension.yml@<same-40-character-build-commit-sha>
```

Jobs that need co-located build scripts and metadata check out:

```yaml
repository: ${{ job.workflow_repository }}
ref: ${{ job.workflow_sha }}
```

On GitHub.com, `job.workflow_repository` identifies the repository containing the reusable workflow and `job.workflow_sha` identifies the commit of that workflow definition. The caller SHA therefore fixes the workflow definition, scripts, and metadata to one revision.

Mutable `@main` references are forbidden.

## Caller permission model

The extension caller is split into three trust boundaries.

| Path | Shared build | Provenance | Publication |
| --- | --- | --- | --- |
| pull request | `contents: read` | disabled | skipped |
| push to `main` | `contents: read` | disabled | skipped |
| non-release `workflow_dispatch` | `contents: read` | disabled | skipped |
| `release/*` build | `contents: read` + attestation permissions | enabled | not in this job |
| `release/*` publish | not in this job | no OIDC/attestation permission | `contents: write` |

The release build path grants exactly:

```yaml
permissions:
  contents: read
  id-token: write
  attestations: write
  artifact-metadata: write
```

`id-token: write` is used only to obtain the short-lived signing identity required by Sigstore-backed GitHub Artifact Attestations. `attestations: write` persists the attestation, and the current `actions/attest` contract uses `artifact-metadata: write` to create the artifact storage record.

The called reusable build job declares the same permissions because GitHub requires the caller and called workflow to permit reusable-workflow attestation. A reusable workflow cannot elevate permissions beyond the caller, so PR/main/non-release callers that grant only `contents: read` remain read-only.

The release publication workflow keeps only:

```yaml
permissions:
  contents: write
```

It does not receive `id-token: write`, `attestations: write`, or `artifact-metadata: write`.

Do not introduce `pull_request_target`. Fork or pull-request code must never execute with release write or OIDC permissions.

## Artifact Attestation contract

`build-extension.yml` exposes the boolean `attest_provenance` input. Its default is `false`.

When enabled by the release build caller, the matrix job performs:

1. build,
2. install,
3. functional smoke test,
4. final ZIP packaging,
5. `actions/attest` SLSA build provenance generation for `dist/*.zip`,
6. `gh attestation verify` constrained to the caller repository and `pgextwin/build/.github/workflows/build-extension.yml`,
7. upload of the unchanged ZIP.

The publication job later downloads the same ZIP bytes, creates `SHA256SUMS.txt`, and publishes the assets without repackaging.

See [Artifact Attestations and build provenance](artifact-attestations.md).

## Updating the shared build revision

Use this sequence:

1. change `pgextwin/build` on a branch,
2. run and review the build repository CI,
3. merge and record the resulting `main` commit SHA,
4. update both reusable-workflow references in each extension caller to that exact SHA,
5. run extension Windows CI,
6. merge only after the new shared revision passes.

## Regression guard

`tests/test-github-actions-security.py` rejects:

- remote `uses:` references that are not full 40-character SHAs,
- GitHub-owned action SHA pins without a same-line version comment,
- `permissions: write-all`,
- `pull_request_target`,
- mutable `pgextwin/build@main` source checkout,
- missing or unsafe `attest_provenance` defaults,
- an unapproved `actions/attest` pin,
- missing attestation/verification steps,
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
