# pgextwin build architecture

## Responsibility split

```text
pgextwin/build
  ├─ PostgreSQL maintenance metadata
  ├─ matrix resolution
  ├─ PostgreSQL installation
  ├─ upstream checkout
  ├─ license verification
  ├─ artifact upload
  ├─ checksums
  └─ GitHub Release publication

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

## Release gate

A release is eligible only after every PostgreSQL major in the resolved matrix completes the extension-specific build, install, functional test, and packaging hooks.

`release/*` branches are the publication trigger. Pull requests and normal pushes run validation only.

## Versioning

During Phase 2 callers reference the reusable workflow from `@main`. Before pgextwin v1 is declared stable, the shared workflow must receive a stable version ref so callers can pin infrastructure updates deliberately.
