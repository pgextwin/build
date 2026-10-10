# HypoPG for Windows — pgextwin technical pilot

Unofficial Windows x64 packaging for [HypoPG](https://github.com/HypoPG/hypopg) 1.4.3, fixed to commit `21d5461ad1868434cc47d9aa656d7afc2b24c464`.

PostgreSQL 15, 16, 17 and 18 are the targets. Build uses the official four C sources (`hypopg.c`, `hypopg_index.c`, `import/hypopg_import.c`, `import/hypopg_import_index.c`) and the MSVC toolchain. The functional smoke test verifies a hypothetical planner index that does not physically exist and then verifies `hypopg_reset()`.

This is an **unvalidated technical pilot**, not an upstream-official distribution. Do not publish a Release or register as implemented until the dedicated Windows CI matrix succeeds and all artifacts (ZIP, SBOM, vulnerability report and checksums) have been verified.
