# Artifact Attestations and build provenance

This document defines the pgextwin Step 6 build-provenance contract for Windows ZIP packages.

## What is attested

For release builds, each PostgreSQL-major matrix job creates its final Windows x64 ZIP under `dist/*.zip`. After build, install, functional smoke test, and packaging succeed, `actions/attest` generates a GitHub Artifact Attestation for that ZIP.

The Step 6 attestation uses the default SLSA build provenance predicate. Step 8 adds a second, separate SPDX 2.3 SBOM Attestation over the same final ZIP subject; it does not replace build provenance. See [Software Bill of Materials (SBOM)](sbom.md).

The order is intentionally:

1. build,
2. install,
3. functional smoke test,
4. package final ZIP,
5. generate and validate the external SPDX 2.3 SBOM from the final ZIP,
6. generate the SLSA build provenance attestation,
7. generate the SPDX 2.3 SBOM Attestation over the same final ZIP,
8. verify both attestations with GitHub CLI and compare the verified SBOM predicate with the generated JSON,
9. upload the unchanged ZIP and external SBOM as GitHub Actions artifacts,
10. publish those same files as future GitHub Release assets.

The ZIP is not modified after attestation. `SHA256SUMS.txt` is created later by reading the ZIP bytes; the publication job does not repackage the ZIP.

## SHA256SUMS.txt versus Artifact Attestation

`SHA256SUMS.txt` and Artifact Attestation solve different problems and both are retained.

- `SHA256SUMS.txt` lets a user compare the SHA-256 digest of a downloaded file with the digest published with the Release.
- GitHub Artifact Attestation binds the artifact digest to a GitHub Actions build identity and SLSA provenance statement, allowing a user to verify which workflow produced those bytes.

A checksum alone does not establish build identity. An attestation does not replace the convenience of the Release checksum file.

## Signer and caller identity

The caller repository is the extension packaging repository, for example `pgextwin/pg_bigm`.

The provenance signer workflow is:

`pgextwin/build/.github/workflows/build-extension-attested.yml`

Normal builds use the separate read-only `build-extension.yml`. Release publication uses `release-extension.yml`. Caller repositories pin all three workflows to the same full 40-character `pgextwin/build` commit SHA.

Inside both build workflows, co-located scripts and metadata are checked out using `job.workflow_repository` and `job.workflow_sha`, so the workflow definition and shared build implementation are fixed to the same revision.

GitHub stores the attestation with the repository that initiated the caller workflow. When verifying an artifact produced through the cross-repository reusable workflow, verify both the caller repository and the reusable signer workflow identity.

## Permission boundary

Normal pull-request, `main`, and non-release manual builds call `build-extension.yml` with only `contents: read`. They do not grant or request `id-token: write`, `attestations: write`, or `artifact-metadata: write`.

Only the release build path calls `build-extension-attested.yml` and grants:

```yaml
permissions:
  contents: read
  id-token: write
  attestations: write
  artifact-metadata: write
```

The attested reusable workflow declares the same permissions because GitHub requires the caller and called reusable workflow to permit Artifact Attestation. Keeping that permission-bearing workflow separate is necessary because reusable workflows cannot elevate permissions passed by their caller and GitHub validates the nested permission contract before build jobs start.

The separate release publication job keeps only `contents: write`. It does not receive OIDC or attestation write permissions.

## Verification

After downloading a ZIP from a Step 6-or-later Release, first verify its SHA-256 digest using `SHA256SUMS.txt`, then verify build provenance with GitHub CLI:

```bash
gh attestation verify <zip-file> \
  --repo pgextwin/<extension> \
  --signer-workflow pgextwin/build/.github/workflows/build-extension-attested.yml
```

For example:

```bash
gh attestation verify pg_bigm-<version>-pg16-windows-x64.zip \
  --repo pgextwin/pg_bigm \
  --signer-workflow pgextwin/build/.github/workflows/build-extension-attested.yml
```

The release build workflow runs the same build-provenance verification and a second SPDX-specific verification using `--predicate-type https://spdx.dev/Document/v2.3`. It also checks that the verified SBOM predicate is semantically identical to the generated standalone SPDX JSON before uploading the ZIP and SBOM to the workflow artifact container.

## Historical releases

Artifact Attestation is prospective. Releases created before Step 6 are preserved as historical artifacts and are not rebuilt, re-uploaded, or retroactively represented as attested.

For historical releases, continue to use their published `SHA256SUMS.txt` and package metadata. The absence of a GitHub Artifact Attestation for such a Release is expected.

## Scope boundary

Step 6 itself covered only SLSA build provenance for the final ZIP. Step 7 added PACKAGE-INFO v2, and Step 8 adds SPDX 2.3 SBOM generation plus SBOM Attestation while preserving the Step 6 provenance statement.

Even after Step 8, this attestation layer does not add:

- vulnerability scanning or a CVE gate,
- dependency or license policy enforcement,
- upstream source commit SHA expansion,
- compiler/toolchain provenance fields inside the package,
- Python dependency locking,
- Chocolatey package provenance,
- Catalog or Website attestation visibility,
- or PostgreSQL 19 production onboarding.
