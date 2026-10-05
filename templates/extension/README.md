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
