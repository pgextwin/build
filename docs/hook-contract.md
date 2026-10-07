# Extension hook contract

Each pgextwin extension repository supplies four PowerShell scripts under `windows/ci/`.

The shared reusable workflow owns PostgreSQL selection, PostgreSQL installation, upstream checkout, license verification, Test Contract validation, artifact upload, checksums, and release publication. The extension repository owns extension-specific behavior.

The four PowerShell hook signatures remain the **v1 hook interface**. Step 9 adds **Test Contract v2** as a separate machine-readable quality contract for the smoke-test hook; it does not replace or reinterpret the hook parameters below.

## 1. build.ps1

Required parameters:

```powershell
-PgRoot <PostgreSQL installation root>
-UpstreamDir <checked-out upstream source>
```

Expected result: the extension binary is built successfully.

## 2. install.ps1

Required parameters:

```powershell
-PgRoot <PostgreSQL installation root>
-UpstreamDir <checked-out upstream source>
```

Expected result: files needed for runtime testing are copied into the temporary PostgreSQL installation.

## 3. smoke-test.ps1

Required parameters:

```powershell
-PgRoot <PostgreSQL installation root>
-PgPort <test port>
-PostgreSqlMajor <major version>
```

Expected result: the script starts a temporary PostgreSQL cluster when needed and validates at least:

1. the extension can be loaded,
2. `CREATE EXTENSION` succeeds when applicable,
3. one extension-specific functional scenario succeeds.

The script must clean up processes and temporary resources in a `finally` path.

### Test Contract v2

Each extension repository also provides:

```text
config/test-contract.json
```

The canonical schema lives only in `pgextwin/build/schema/test-contract.schema.json`.

Test Contract v2 declares what the extension-owned smoke test is expected to prove, including runtime prerequisites versus pgextwin test setup, CREATE EXTENSION coverage, background-worker coverage, client-executable coverage, server-log assertions, upgrade coverage, stable functional scenario IDs, and evidence types.

It is validated in both normal and attested reusable workflows before matrix resolution proceeds to Windows compilation. The contract does **not** generate or replace `smoke-test.ps1`; extension-specific test logic remains in each extension repository.

See [Test Contract v2](test-contract-v2.md) for the complete model.

## 4. package.ps1

Required parameters:

```powershell
-UpstreamDir <checked-out upstream source>
-UpstreamRepository <owner/repo>
-UpstreamRef <pinned tag or commit>
-UpstreamVersion <extension version>
-PostgreSqlMajor <major version>
-PostgreSqlMinor <tested minor version>
```

Expected result: exactly one distributable ZIP is written under `dist/`.

The ZIP should use PostgreSQL's installation layout where practical:

```text
lib/
share/extension/
LICENSE
UPSTREAM-README.md
PACKAGE-INFO.txt
```

## Stability

The four hook parameter sets above remain the pgextwin v1 hook interface. New optional hook parameters may be added, but existing required parameters must not be renamed without a versioned workflow change.

Test Contract v2 is versioned independently from both the hook interface and `config/extension.json`'s manifest `schemaVersion`.
