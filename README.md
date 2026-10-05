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
- uploading per-PostgreSQL-major artifacts,
- generating SHA-256 checksums,
- and publishing GitHub Releases from `release/*` branches.

Extension-specific source adaptation and functional tests remain in each extension repository.

## Reusable workflow

Caller repositories use:

```yaml
permissions:
  contents: write

jobs:
  windows:
    uses: pgextwin/build/.github/workflows/build-extension.yml@main
    with:
      extension_config_path: config/extension.json
```

`contents: write` is required only so the reusable workflow can publish or update GitHub Releases from `release/*` branches. Build and test jobs in the reusable workflow run with read-only contents permission.

See [Hook contract](docs/hook-contract.md) and [Architecture](docs/architecture.md).

## Status

- Phase 2 shared build foundation: complete
- Phase 3 pg_bigm pilot: complete — see [Phase 3 pilot report](docs/phase3-pg_bigm-pilot.md)
- Phase 4 second-extension technical pilot: complete — see [pg_cron pilot report](docs/phase4-pg_cron-pilot.md)

The second pilot validates a background-worker extension and the upstream native MSVC/nmake build path beyond the pg_bigm/CMake profile. Productization is pending creation of the public `pgextwin/pg_cron` repository.

## License

The shared build infrastructure is distributed under the PostgreSQL License. See [LICENSE](LICENSE).
