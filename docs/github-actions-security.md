# GitHub Actions trust and permission policy

This document defines the Step 5 trust baseline for pgextwin GitHub Actions.

## Scope

The baseline covers the GitHub Actions trust chain only:

- immutable references for remote GitHub Actions,
- immutable references from extension repositories to the shared reusable workflow,
- identical revision selection for the reusable workflow and the co-located build scripts/metadata,
- least-privilege `GITHUB_TOKEN` permissions,
- and a small regression guard.

Artifact Attestation, SBOM generation, broader package dependency locking, PACKAGE-INFO/provenance expansion, upstream source commit recording, and organization-level SHA enforcement are separate work.

## Remote Action pin policy

Every non-local `uses:` dependency committed to this repository must use a full 40-character commit SHA.

GitHub-owned actions also keep a same-line human-readable version comment:

```yaml
uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
```

The SHA must be resolved from the action's official GitHub repository. Do not copy a SHA from a fork or third-party mirror.

The Step 5 baseline is:

| Action | Full commit SHA | Version represented by the major tag |
| --- | --- | --- |
| `actions/checkout` | `3d3c42e5aac5ba805825da76410c181273ba90b1` | `v7.0.1` |
| `actions/setup-python` | `ece7cb06caefa5fff74198d8649806c4678c61a1` | `v6.3.0` |
| `actions/setup-node` | `249970729cb0ef3589644e2896645e5dc5ba9c38` | `v6.5.0` |
| `actions/upload-artifact` | `043fb46d1a93c77aae656e7c1c64a875d1fc6a0a` | `v7.0.1` |
| `actions/download-artifact` | `3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c` | `v8.0.1` |

## Reusable workflow self-pin contract

Extension repositories call:

```yaml
uses: pgextwin/build/.github/workflows/build-extension.yml@<40-character-build-commit-sha>
```

The reusable workflow does **not** independently select `pgextwin/build@main` and does not require a duplicated `build_ref` input.

Instead, each job that needs co-located build scripts and metadata checks out:

```yaml
repository: ${{ job.workflow_repository }}
ref: ${{ job.workflow_sha }}
```

On GitHub.com, `job.workflow_repository` identifies the repository containing the reusable workflow and `job.workflow_sha` is the commit SHA of the workflow file defining the current job. Therefore one caller SHA pin determines all three trust inputs:

1. the reusable workflow definition,
2. the build scripts,
3. the PostgreSQL/build metadata.

This is intentionally stronger than a duplicated `uses` + `build_ref` input because the two values cannot drift apart.

## Caller permission model

The initial extension caller workflow has two mutually exclusive reusable-workflow jobs.

| Trigger/path | Caller `contents` permission | Release path |
| --- | --- | --- |
| `pull_request` | `read` | No |
| push to `main` | `read` | No |
| `workflow_dispatch` on a non-`release/*` ref | `read` | No |
| push to `release/*` | `write` | Yes |
| `workflow_dispatch` on a `release/*` ref | `write` | Yes |

The reusable workflow also declares permissions per job:

- matrix resolution: `contents: read`
- build/test/package: `contents: read`
- GitHub Release publication: `contents: write`

A reusable workflow cannot elevate the permissions granted by its caller. The release caller must therefore explicitly grant `contents: write`, while ordinary PR/main builds pass only `contents: read`.

Do not introduce `pull_request_target` for extension builds. Pull-request code must not execute with a write token.

## Updating the shared build revision

The shared build SHA is an explicit dependency of each extension repository.

Use this sequence:

1. change `pgextwin/build` on a branch,
2. run and review the build repository CI,
3. merge the build change and record the resulting `main` commit SHA,
4. update each intended extension caller's reusable-workflow `uses:` reference to that exact SHA,
5. run the extension Windows CI,
6. merge the caller update only after the new shared revision passes.

Because the reusable workflow self-checkout uses `job.workflow_sha`, no second build revision field needs to be updated.

## Dependency updates

Dependabot `github-actions` version updates are enabled only where GitHub-owned Actions are directly referenced. Dependabot understands full-SHA GitHub Action references and same-line version comments.

For the internal `pgextwin/build` reusable-workflow pin, the baseline remains a reviewed manual update contract. Dependabot can update reusable workflow Git references, but following the latest arbitrary build commit is not treated as an automatic trust decision.

## Regression guard

`tests/test-github-actions-security.py` validates the build repository's tracked workflow files. It rejects:

- remote `uses:` references that are not full 40-character SHAs,
- GitHub-owned action SHA pins without a same-line version comment,
- `permissions: write-all`,
- and a mutable `pgextwin/build@main` source checkout.

It also requires the reusable workflow's shared-source checkout to use `job.workflow_repository` and `job.workflow_sha`.

## Boundary with later supply-chain steps

This Step intentionally does not add:

- `actions/attest`,
- `attestations: write`,
- `id-token: write`,
- SBOM/provenance attestation,
- broad Python/package lockfiles or hash pinning,
- PACKAGE-INFO v2/provenance metadata,
- or PostgreSQL 19 production support.

Organization-level **Require actions to be pinned to a full-length commit SHA** should be enabled only after all repositories intended to run under that policy have been verified compatible.
