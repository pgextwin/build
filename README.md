# pgextwin build infrastructure

[日本語](README_ja.md) | English

Shared CI/CD infrastructure for **pgextwin**, a community project that builds and distributes unofficial Windows x64 binaries for PostgreSQL extensions.

This repository contains reusable GitHub Actions workflows, PostgreSQL build metadata, and the hook contract used by extension packaging repositories such as `pgextwin/pg_bigm`.

## Scope

The shared workflow is responsible for:

- resolving maintained PostgreSQL versions,
- installing the matching Windows PostgreSQL distribution,
- checking out the pinned upstream extension source,
- verifying the upstream license when configured,
- invoking extension-specific build/install/test/package hooks,
- generating and verifying release-only GitHub Artifact Attestations for final ZIPs,
- uploading per-PostgreSQL-major artifacts,
- generating SHA-256 checksums,
- and publishing GitHub Releases from `release/*` branches.

Extension-specific source adaptation and functional tests remain in each extension repository.

## Reusable workflows

Caller repositories pin all three shared workflows to the same approved `pgextwin/build` full commit SHA. GitHub does not allow a called reusable workflow to elevate permissions above the caller, and its requested permissions are validated before jobs run. Therefore normal and attested builds use separate reusable workflow files rather than putting release-only write permissions into the normal build workflow.

```yaml
permissions:
  contents: read

jobs:
  windows:
    if: ${{ !startsWith(github.ref, 'refs/heads/release/') }}
    permissions:
      contents: read
    uses: pgextwin/build/.github/workflows/build-extension.yml@<40-character-build-commit-sha>
    with:
      extension_config_path: config/extension.json

  release_build:
    if: ${{ startsWith(github.ref, 'refs/heads/release/') }}
    permissions:
      contents: read
      id-token: write
      attestations: write
      artifact-metadata: write
    uses: pgextwin/build/.github/workflows/build-extension-attested.yml@<same-40-character-build-commit-sha>
    with:
      extension_config_path: config/extension.json

  release:
    if: ${{ startsWith(github.ref, 'refs/heads/release/') }}
    needs: release_build
    permissions:
      contents: write
    uses: pgextwin/build/.github/workflows/release-extension.yml@<same-40-character-build-commit-sha>
    with:
      extension_name: ${{ needs.release_build.outputs.extension_name }}
      upstream_repository: ${{ needs.release_build.outputs.upstream_repository }}
```

`build-extension.yml` is strictly read-only and has no OIDC or attestation capability. `build-extension-attested.yml` performs the same build/install/smoke-test/package sequence, then attests each final `dist/*.zip`, verifies it with `gh attestation verify`, and uploads the unchanged ZIP. `release-extension.yml` only downloads those ZIPs, creates `SHA256SUMS.txt`, and publishes the Release with `contents: write`.

Both build reusable workflows check out co-located scripts and metadata from `${{ job.workflow_repository }}` at `${{ job.workflow_sha }}`. Pinning all three workflows to one build commit therefore fixes the workflow definitions, scripts, metadata, and release implementation to the same revision.

See [Artifact Attestations and build provenance](docs/artifact-attestations.md), [GitHub Actions trust and permission policy](docs/github-actions-security.md), [Hook contract](docs/hook-contract.md), and [Architecture](docs/architecture.md).

## PostgreSQL lifecycle

PostgreSQL lifecycle filtering is centralized in this repository. A major is included in a new normal build only while it is still community-supported, allowed by the extension manifest, and backed by the required upstream ref/version. The official EOL date is inclusive; the major leaves the normal matrix on the following UTC calendar day.

As of 2026-10-06, PostgreSQL 14 is supported through **2026-11-12**. It remains in normal build matrices through that date and is excluded beginning **2026-11-13**. Existing Git tags, GitHub Releases, assets, and checksums are retained after EOL.

See [PostgreSQL lifecycle policy](docs/postgresql-lifecycle.md) for the complete policy and deterministic boundary-test contract.

## Status

- Phase 2 shared build foundation: complete
- Phase 3 pg_bigm pilot: complete — see [Phase 3 pilot report](docs/phase3-pg_bigm-pilot.md)
- Phase 4 second-extension technical pilot: complete — see [pg_cron pilot report](docs/phase4-pg_cron-pilot.md)
- Phase 5 pg_hint_plan technical pilot: complete — see [pg_hint_plan pilot report](docs/phase5-pg_hint_plan-pilot.md)
- Phase 6 pgAudit technical pilot: complete — see [pgAudit pilot report](docs/phase6-pgaudit-pilot.md)
- Phase 7 set_user technical pilot: complete — see [set_user pilot report](docs/phase7-set_user-pilot.md)
- Phase 8 pg_repack technical pilot and productization: complete — see [pg_repack pilot report](docs/phase8-pg_repack-pilot.md)
- Phase 9 pg_ivm technical pilot and productization: complete — see [pg_ivm pilot report](docs/phase9-pg_ivm-pilot.md)
- Phase 10 pg_qualstats technical pilot and productization: complete — see [pg_qualstats pilot report](docs/phase10-pg_qualstats-pilot.md)

**Initial extension roadmap: complete.** All eight initial extensions — `pg_bigm`, `pg_cron`, `pg_hint_plan`, `pgaudit`, `set_user`, `pg_repack`, `pg_ivm`, and `pg_qualstats` — have public PostgreSQL 14–18 Windows x64 Releases and catalog entries. Historical phase numbering is retained for compatibility with the existing pilot reports. See [Extension roadmap](docs/roadmap.md).

## Next platform work

The initial extension roadmap is closed. PostgreSQL lifecycle / PG14 EOL build-foundation readiness (Step 2), catalog and website lifecycle visibility (Step 3), the **PostgreSQL 19 readiness / compatibility audit (Step 4)**, and the **GitHub Actions trust baseline (Step 5)** and **Artifact Attestation / Release Build Provenance (Step 6)** are complete. See [PostgreSQL 19 readiness](docs/postgresql-19-readiness.md) and [GitHub Actions trust policy](docs/github-actions-security.md).

PostgreSQL 19 remains outside the production matrix until the documented GA/Windows/upstream gates are satisfied. Remaining work is intentionally separated into later milestones:

1. PostgreSQL 19 production onboarding after the documented GA/Windows/upstream gates are satisfied
2. SBOM and broader supply-chain provenance work beyond Step 6
3. broader package metadata / catalog improvements
4. website improvements beyond lifecycle visibility
5. upstream update automation
6. second extension wave

## License

The shared build infrastructure is distributed under the PostgreSQL License. See [LICENSE](LICENSE).
