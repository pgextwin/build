# Extension hook contract

Each pgextwin extension repository supplies four PowerShell scripts under `windows/ci/`.

The shared reusable workflow owns PostgreSQL selection, PostgreSQL installation, upstream checkout, license verification, artifact upload, checksums, and release publication. The extension repository owns only extension-specific behavior.

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

The hook parameter names above are the pgextwin v1 contract. New optional parameters may be added, but existing required parameters must not be renamed without a versioned workflow change.
