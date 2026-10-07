# Test Contract v2

Test Contract v2 is the machine-readable quality contract for each extension repository's `windows/ci/smoke-test.ps1`.

The shared workflow remains an orchestrator. Extension-specific behavior stays in the extension repository; the contract declares what that smoke test is expected to prove.

## Location and versioning

Each extension repository stores:

```text
config/extension.json
config/test-contract.json
windows/ci/smoke-test.ps1
```

`config/extension.json` remains build-selection/source metadata with its own `schemaVersion`. Test semantics are independently versioned through:

```json
{
  "contractVersion": 2
}
```

The canonical schema is maintained only in `pgextwin/build/schema/test-contract.schema.json`.

## Runtime requirements versus test setup

These are intentionally separate.

`runtimeRequirements` describes upstream-documented user/runtime prerequisites, such as whether preload is required and whether the extension depends on a background worker or packaged client executable.

`testSetup` describes how pgextwin CI starts PostgreSQL for the declared functional scenarios. A shared preload used by CI does not, by itself, mean shared preload is an upstream runtime requirement.

Preload values are intentionally small:

- `none`: no preload requirement.
- `shared`: `shared_preload_libraries` is required.
- `session`: `session_preload_libraries` is required.
- `either`: either shared or session preload satisfies the upstream requirement.
- `optional`: preload is not required for basic activation/use, although it may be a supported deployment mode.
- `unknown`: upstream evidence is not strong enough to make a narrower statement.

`testSetup.preload` is concrete and therefore uses only `none`, `shared`, or `session`.

## Coverage states

Coverage fields use:

- `covered`: the current smoke test contains a direct assertion for the capability.
- `not-covered`: the capability is relevant but the current smoke test does not verify it.
- `not-applicable`: the capability does not apply to this extension/test surface.

In particular, shipped upgrade SQL does not imply upgrade coverage. Upgrade is `covered` only when CI actually exercises an upgrade path.

## Functional scenarios and evidence

Each contract must define at least one stable scenario ID matching:

```text
^[a-z0-9][a-z0-9-]*$
```

Scenarios identify user-visible behavior rather than generic smoke-test phases. Evidence types describe what CI observes, including SQL results, query plans, server logs, background-worker side effects, client execution, physical storage changes, logical decoding, extension upgrades, or backup/restore behavior.

An optional `postgresqlMajors` list marks a scenario that is intentionally limited to specific PostgreSQL majors.

## Validation boundary

Both normal and attested reusable build workflows validate the contract in the matrix job, before Windows compilation begins:

1. the contract file exists,
2. it passes the canonical JSON Schema,
3. `contract.extension` matches `config/extension.json`,
4. the declared smoke-test script exists,
5. scenario IDs are unique,
6. client executable declarations have repository/package-relative paths,
7. preload/background-worker/client coverage declarations are semantically consistent.

The validator does not parse or generate `smoke-test.ps1`. Functional assertions remain ordinary extension-owned PowerShell code and remain reviewable as code.

## Non-goals

Test Contract v2 is not a generic test engine and does not add vulnerability scanning, PostgreSQL 19 production onboarding, catalog schema changes, website UI changes, or retroactive metadata to existing releases.
