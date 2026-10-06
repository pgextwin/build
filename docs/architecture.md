# pgextwin build architecture

## Responsibility split

```text
pgextwin/build
  ├─ PostgreSQL maintenance metadata
  ├─ matrix resolution
  ├─ PostgreSQL installation
  ├─ upstream checkout
  ├─ license verification
  ├─ normal read-only build reusable workflow
  ├─ attested release-build reusable workflow
  ├─ GitHub Artifact Attestation verification
  ├─ artifact upload
  ├─ checksums
  └─ GitHub Release publication reusable workflow

extension repository
  ├─ config/extension.json
  ├─ Windows build adaptation
  ├─ windows/ci/build.ps1
  ├─ windows/ci/install.ps1
  ├─ windows/ci/smoke-test.ps1
  └─ windows/ci/package.ps1
```

## Why this boundary

PostgreSQL lifecycle metadata and CI mechanics are common across extensions and should be maintained once. Build commands, exported symbols, preload requirements, files to install, and functional tests differ substantially by extension and remain local.

The reusable workflows are intentionally split by trust boundary:

- `.github/workflows/build-extension.yml` handles PR, main, and non-release manual builds with `contents: read` only.
- `.github/workflows/build-extension-attested.yml` handles release builds with `contents: read`, `id-token: write`, `attestations: write`, and `artifact-metadata: write`.
- `.github/workflows/release-extension.yml` publishes the unchanged ZIPs with `contents: write` only.

All three workflows are pinned by extension callers to the same full `pgextwin/build` commit SHA.

## PostgreSQL lifecycle resolution

`metadata/postgresql.json` is the shared lifecycle source for supported PostgreSQL majors and their EOL dates. `scripts/resolve-matrix.ps1` intersects that metadata with the caller's extension manifest.

Normal runs use the current UTC calendar date. Tests may inject an explicit `-EffectiveDate yyyy-MM-dd` so EOL boundaries are deterministic. The final support date is inclusive: a major remains eligible when `EOL >= effective date` and is excluded beginning the next day.

Lifecycle filtering governs **new normal builds** only. Existing tags, Releases, assets, and checksums remain historical distribution records after a PostgreSQL major reaches EOL. See [PostgreSQL lifecycle policy](postgresql-lifecycle.md).

## Build provenance boundary

Only `release/*` uses the attested build workflow. Each PostgreSQL-major job completes build, install, functional smoke test, and final ZIP packaging before provenance is generated. The final ZIP is the attestation subject.

The workflow then verifies that same ZIP with `gh attestation verify` and only after successful verification uploads it as a GitHub Actions artifact. The publication workflow later downloads the ZIP without repackaging it, reads it to create `SHA256SUMS.txt`, and publishes those same ZIP bytes as GitHub Release assets.

See [Artifact Attestations and build provenance](artifact-attestations.md).

## Release gate

A release is eligible only after every PostgreSQL major in the resolved matrix completes the extension-specific build, install, functional test, packaging, attestation, and in-workflow provenance verification.

`release/*` branches are the publication trigger. Pull requests and normal pushes run the read-only build path only.

## Versioning and immutable dependency contract

Extension callers use full 40-character commit SHAs, not mutable branches or tags, for all `pgextwin/build` reusable workflows. The normal build, attested release build, and release publication references must point to the same approved build commit.

Within each build reusable workflow, co-located scripts and metadata are checked out from `${{ job.workflow_repository }}` at `${{ job.workflow_sha }}`, so the workflow definition and the shared implementation cannot drift to different revisions.
