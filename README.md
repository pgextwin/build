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
- Phase 5 pg_hint_plan technical pilot: complete — see [pg_hint_plan pilot report](docs/phase5-pg_hint_plan-pilot.md)
- Phase 6 pgAudit technical pilot: complete — see [pgAudit pilot report](docs/phase6-pgaudit-pilot.md)
- Phase 7 set_user technical pilot: complete — see [set_user pilot report](docs/phase7-set_user-pilot.md)
- Phase 8 pg_repack technical pilot and productization: complete — see [pg_repack pilot report](docs/phase8-pg_repack-pilot.md)
- Phase 9 pg_ivm technical pilot and productization: complete — see [pg_ivm pilot report](docs/phase9-pg_ivm-pilot.md)
- Phase 10 pg_qualstats technical pilot and productization: complete — see [pg_qualstats pilot report](docs/phase10-pg_qualstats-pilot.md)

**Initial extension roadmap: complete.** All eight initial extensions — `pg_bigm`, `pg_cron`, `pg_hint_plan`, `pgaudit`, `set_user`, `pg_repack`, `pg_ivm`, and `pg_qualstats` — have public PostgreSQL 14–18 Windows x64 Releases and catalog entries. Historical phase numbering is retained for compatibility with the existing pilot reports. See [Extension roadmap](docs/roadmap.md).

## Next platform work

The initial extension roadmap is closed. Later work is intentionally tracked as separate platform milestones and is **not implemented by this closure step**:

1. PostgreSQL lifecycle / PG14 EOL
2. PostgreSQL 19 readiness
3. supply-chain hardening
4. package metadata / catalog improvements
5. website improvements
6. upstream update automation
7. second extension wave

## License

The shared build infrastructure is distributed under the PostgreSQL License. See [LICENSE](LICENSE).
