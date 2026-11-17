# Extension repository template

Copy these files into a new pgextwin extension packaging repository.

Required local files:

```text
.github/workflows/windows.yml
config/extension.json
windows/ci/build.ps1
windows/ci/install.ps1
windows/ci/smoke-test.ps1
windows/ci/package.ps1
README.md
README_ja.md
LICENSE
```

The four PowerShell hook scripts are intentionally not generic templates because build and functional-test behavior is extension-specific. Follow `docs/hook-contract.md`.

For an eligible registered extension's owner-comment signing route, reuse the
minimal caller in [Shared owner-source readiness](../../docs/owner-source-route.md).
Authentication, signed build, independent audit and admission already live in
build; keep only extension configuration and hooks local.
