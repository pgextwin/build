# Artifact Attestations and build provenance

This document defines the pgextwin Step 6 build-provenance contract for Windows ZIP packages.

## What is attested

For release builds, each PostgreSQL-major matrix job creates its final Windows x64 ZIP under `dist/*.zip`. After build, install, functional smoke test, and packaging succeed, `actions/attest` generates a GitHub Artifact Attestation for that ZIP.

The attestation uses the default SLSA build provenance predicate. SBOM attestations and custom predicates are outside Step 6.

The order is intentionally:

1. build,
2. install,
3. functional smoke test,
4. package final ZIP,
5. generate provenance attestation,
6. verify the attestation with GitHub CLI,
7. upload the unchanged ZIP as a GitHub Actions artifact,
8. download the same bytes in the publication job,
9. publish the ZIP as a GitHub Release asset.

The ZIP is not modified after attestation. `SHA256SUMS.txt` is created later by reading the ZIP bytes; the publication job does not repackage the ZIP.

## SHA256SUMS.txt versus Artifact Attestation

`SHA256SUMS.txt` and Artifact Attestation solve different problems and both are retained.

- `SHA256SUMS.txt` lets a user compare the SHA-256 digest of a downloaded file with the digest published with the Release.
- GitHub Artifact Attestation binds the artifact digest to a GitHub Actions build identity and SLSA provenance statement, allowing a user to verify which workflow produced those bytes.

A checksum alone does not establish build identity. An attestation does not replace the convenience of the Release checksum file.

## Signer and caller identity

The caller repository is the extension packaging repository, for example `pgextwin/pg_bigm`.

The signer workflow is the reusable workflow:

`pgextwin/build/.github/workflows/build-extension.yml`

Caller repositories pin that reusable workflow by full 40-character `pgextwin/build` commit SHA. Inside the reusable workflow, co-located scripts and metadata are checked out using `job.workflow_repository` and `job.workflow_sha`, so the workflow definition and shared build implementation are fixed to the same revision.

GitHub stores the attestation with the repository that initiated the caller workflow. When verifying an artifact produced through the cross-repository reusable workflow, verify both the caller repository and the reusable signer workflow identity.

## Permission boundary

Artifact Attestation is opt-in through the boolean reusable-workflow input `attest_provenance`, whose default is `false`.

Normal pull-request, `main`, and non-release manual builds call the reusable workflow with only `contents: read`. They do not grant `id-token: write`, `attestations: write`, or `artifact-metadata: write`.

Only the release build path grants:

```yaml
permissions:
  contents: read
  id-token: write
  attestations: write
  artifact-metadata: write
```

The reusable build job declares the same attestation permissions because GitHub requires both caller and called reusable workflow to permit the operation. Reusable workflows cannot elevate permissions beyond those granted by the caller, so normal builds remain read-only.

The separate release publication job keeps only `contents: write`. It does not receive OIDC or attestation write permissions.

## Verification

After downloading a ZIP from a Step 6-or-later Release, first verify its SHA-256 digest using `SHA256SUMS.txt`, then verify build provenance with GitHub CLI:

```bash
gh attestation verify <zip-file> \
  --repo pgextwin/<extension> \
  --signer-workflow pgextwin/build/.github/workflows/build-extension.yml
```

For example:

```bash
gh attestation verify pg_bigm-<version>-pg16-windows-x64.zip \
  --repo pgextwin/pg_bigm \
  --signer-workflow pgextwin/build/.github/workflows/build-extension.yml
```

The release build workflow runs the same verification immediately after generating each attestation and before uploading the ZIP to the workflow artifact container.

## Historical releases

Artifact Attestation is prospective. Releases created before Step 6 are preserved as historical artifacts and are not rebuilt, re-uploaded, or retroactively represented as attested.

For historical releases, continue to use their published `SHA256SUMS.txt` and package metadata. The absence of a GitHub Artifact Attestation for such a Release is expected.

## Scope boundary

Step 6 covers only SLSA build provenance for the final ZIP.

It does not add:

- SPDX or CycloneDX SBOMs,
- SBOM attestations,
- PACKAGE-INFO v2,
- upstream source commit SHA expansion,
- compiler/toolchain provenance fields inside the package,
- Python dependency locking,
- Chocolatey package provenance,
- Catalog or Website attestation visibility,
- or PostgreSQL 19 production onboarding.
