# Software Bill of Materials (SBOM)

[日本語](#日本語) | English

This document defines the pgextwin Step 8 SBOM contract for Windows ZIP packages.

## Canonical format and generator

pgextwin uses **SPDX 2.3 JSON** as its canonical SBOM format.

The generator is **Anchore Syft 1.54.0**. The workflow invokes the Syft CLI directly and explicitly requests `spdx-json@2.3`; it does not rely on a moving default SPDX version.

Syft is installed on the Windows build runner from the exact official release asset:

`syft_1.54.0_windows_amd64.zip`

The archive version and SHA-256 are fixed in `scripts/install-syft.ps1`. The expected archive SHA-256 is:

`77f4b472779058e819eec9a054753a5071a996aaa40db31a290f8b256748593f`

The installer downloads only that exact release asset, validates the archive SHA-256 before extraction, and verifies the resulting executable reports version 1.54.0. It does not use a floating `latest` URL, `curl | sh`, or a mutable action tag.

The official `anchore/sbom-action/download-syft` path was evaluated. For the Windows path it downloads the requested release asset, but it does not independently verify the release archive checksum. pgextwin therefore uses the smaller direct, version-and-digest-pinned download path instead of adding that Action to the workflow.

## Data flow and scan boundary

The order is:

```text
extension-specific build/test/package
  -> PACKAGE-INFO.json finalization
  -> final ZIP rebuild
  -> PACKAGE-INFO.json validation
  -> Syft scans the final ZIP
  -> <ZIP basename>.spdx.json
  -> SBOM validation
  -> workflow artifact
```

The attested release-build path continues from SBOM validation with two separate attestations:

```text
  -> SLSA Build Provenance Attestation for final ZIP
  -> SPDX 2.3 SBOM Attestation for final ZIP
  -> verify build provenance
  -> verify SBOM attestation
  -> compare verified SBOM predicate with generated SPDX JSON
  -> workflow artifact
```

The scan target is the **final ZIP after PACKAGE-INFO.json finalization**. The build runner filesystem, Visual Studio installation, Git, Python, Chocolatey installation, and the PostgreSQL installation directory are not scanned as package content.

The SBOM is intentionally external to the ZIP. Embedding the SBOM back into the ZIP would change the ZIP digest after the SBOM had been produced and would create a digest cycle.

## Source identity

Syft is invoked with:

- source name = final ZIP basename;
- source version = the manifest/matrix upstream version already used to build the package;
- source supplier = `pgextwin`.

In SPDX 2.3 output this produces a root/source package that identifies the distributed pgextwin Windows ZIP, with `supplier: "Organization: pgextwin"`.

This does **not** claim pgextwin authored the upstream extension. It identifies pgextwin as the supplier/distributor of this Windows package. Upstream repository/ref/version/commit identity remains authoritative in `PACKAGE-INFO.json`.

## Validation

`scripts/validate-sbom.py` performs a deliberately small pgextwin-specific quality gate. It is not a replacement for the complete SPDX specification.

The validator requires:

- parseable JSON;
- `spdxVersion == "SPDX-2.3"`;
- `dataLicense == "CC0-1.0"`;
- `SPDXID == "SPDXRef-DOCUMENT"`;
- a non-empty absolute document namespace;
- creation information containing exactly `Tool: syft-1.54.0`;
- a root/source package named after the final ZIP basename;
- the expected extension version and `Organization: pgextwin` supplier;
- an SPDX document-to-source-package `DESCRIBES` relation (represented by Syft as an `SPDXRef-DOCUMENT` relationship, while the validator also accepts the equivalent `documentDescribes` property);
- a SHA-256 checksum on the source package that equals the actual final ZIP digest;
- consistency between expected extension/version and the embedded `PACKAGE-INFO.json`.

The validator reports the package count, file count, and automatically cataloged package names. It does **not** require an arbitrary “package count > 1”. Native PostgreSQL extension ZIPs may contain meaningful native binaries and SQL files without carrying npm/NuGet-style package manifests. The root/source package and final-ZIP checksum are therefore the minimum meaningful artifact identity.

## PostgreSQL runtime boundary

PostgreSQL server is a compatibility/runtime requirement for these extensions, but ordinary pgextwin ZIPs do not bundle the PostgreSQL installation itself.

Therefore PostgreSQL 14/15/16/17/18 is **not injected into the SBOM as an included component merely because the extension was built or tested against it**.

PostgreSQL compatibility, tested minor version, and Windows installation/toolchain details remain in `PACKAGE-INFO.json`.

## pg_repack and statically linked PostgreSQL frontend support code

`pg_repack` is special. Its Windows client executable `pg_repack.exe` statically links PostgreSQL frontend support code from `libpgport` and `libpgcommon`. The package already preserves `POSTGRESQL-COPYRIGHT` and its package metadata explains this build structure.

Syft primarily catalogs package metadata and recognized package ecosystems. It is not a general-purpose C/C++ object-file provenance reconstructor and may not decompose a PE executable into the source projects whose object code was statically linked into it.

Accordingly:

- pgextwin does not invent a PostgreSQL runtime package entry for ordinary extensions;
- pgextwin does not falsely claim Syft can reconstruct every static C/C++ source contribution;
- the pg_repack probe is used to record what Syft actually discovers;
- the existing `POSTGRESQL-COPYRIGHT` and package/build metadata remain the explicit evidence for the statically linked frontend support code when Syft does not identify it automatically.

Step 8 does not introduce a custom binary-analysis SBOM generator solely for pg_repack.

## Standalone SBOM and Release assets

Each final ZIP has exactly one sibling SBOM:

```text
<zip-basename>.zip
<zip-basename>.spdx.json
```

Future releases publish all ZIPs, their corresponding SPDX JSON files, and `SHA256SUMS.txt`. The checksum file covers both ZIPs and SPDX JSON assets.

Historical releases are preserved unchanged. A historical release created before Step 8 may have no standalone SBOM and no SBOM Attestation.

## Attestation model

Build provenance and SBOM attestations are separate statements over the same final ZIP subject.

Build provenance:

```bash
gh attestation verify <zip-file> \
  --repo pgextwin/<extension> \
  --signer-workflow pgextwin/build/.github/workflows/build-extension-attested.yml
```

SPDX SBOM:

```bash
gh attestation verify <zip-file> \
  --repo pgextwin/<extension> \
  --signer-workflow pgextwin/build/.github/workflows/build-extension-attested.yml \
  --predicate-type https://spdx.dev/Document/v2.3
```

The release build also requests the verified SBOM attestation as JSON and checks that its statement subject matches the final ZIP name/SHA-256 and that its predicate is semantically identical to the generated `*.spdx.json` document. JSON byte-for-byte equality is not required because whitespace and key ordering are not part of the semantic JSON value.

## Evidence roles

| Evidence | Meaning |
| --- | --- |
| `SHA256SUMS.txt` | Download integrity digest for published ZIP and SBOM assets |
| `PACKAGE-INFO.json` | Machine-readable source/build/package identity inside the ZIP |
| Build Provenance Attestation | Signed evidence of which workflow built the final ZIP |
| SPDX SBOM | Materials/components represented for the final ZIP |
| SBOM Attestation | Signed binding between the final ZIP digest and the SPDX SBOM |

---

## 日本語

pgextwin Step 8では、Windows ZIPに対する正規SBOM形式を **SPDX 2.3 JSON** とします。生成器は **Anchore Syft 1.54.0** です。

`scripts/install-syft.ps1` はSyft 1.54.0の公式Windows x64 release assetだけを取得し、固定したSHA-256
`77f4b472779058e819eec9a054753a5071a996aaa40db31a290f8b256748593f`
を照合してから展開します。`latest` URL、`curl | sh`、floating Action tagは使用しません。公式 `anchore/sbom-action/download-syft` も評価しましたが、Windows download path自体はrelease archive checksumを独立検証しないため、pgextwinではより小さな「exact version + exact asset digest」方式を採用します。

SBOMは `PACKAGE-INFO.json` finalization後の **final ZIPそのもの** をSyftでscanして生成します。runner全体、Visual Studio、Git、Python、Chocolatey、PostgreSQL installation directory全体はscan対象ではありません。

SBOMはZIP外部の `<ZIP basename>.spdx.json` とします。SBOMをZIPへ戻すとZIP digestが変化し循環するため、ZIP内部には追加しません。

Syft source identityは、name=final ZIP basename、version=manifest/matrixのupstream version、supplier=`pgextwin` とします。SPDX上では `Organization: pgextwin` となります。これはupstream作者を名乗るものではなく、pgextwin Windows packageの配布者を表します。upstream repository/ref/version/exact commitは引き続き `PACKAGE-INFO.json` が正規情報です。

`scripts/validate-sbom.py` は、SPDX 2.3、dataLicense、document SPDXID/namespace、Syft 1.54.0 creator、final ZIPに対応するroot/source package、version、supplier、documentからsource packageへの `DESCRIBES` 関係（Syft実出力では `SPDXRef-DOCUMENT` relationship）、そしてsource packageのSHA-256と実際のfinal ZIP SHA-256の一致を検証します。Native C Extensionではnpm/NuGetのようなmanifestがないことがあるため、「検出packageが2個以上」のような条件を成功条件にはしません。

PostgreSQL serverはruntime/compatibility要件ですが、通常のExtension ZIPにPostgreSQL installationそのものは同梱しません。そのため、単にPostgreSQL 18.6でbuild/testしたことを理由にPostgreSQLを「SBOM内に含まれるcomponent」として追加しません。互換性・tested minor・build environmentは `PACKAGE-INFO.json` に記録します。

`pg_repack` は例外的に `pg_repack.exe` へPostgreSQL frontend support code（`libpgport` / `libpgcommon`）をstatic linkします。Syftがこのstatic C/C++ codeを自動でsource project単位まで復元できない場合、その限界を明示します。通常ExtensionへPostgreSQL runtimeを偽のincluded componentとして追加したり、pg_repackだけのために巨大な独自binary analyzerを実装したりはしません。既存の `POSTGRESQL-COPYRIGHT` とpackage/build metadataはstatic code由来の明示的evidenceとして維持します。

Release-attested buildでは同じfinal ZIPに対し、SLSA Build Provenance AttestationとSPDX SBOM Attestationを別々に生成します。SBOM Attestationは `https://spdx.dev/Document/v2.3` predicateとして検証し、verified statementのsubject name/SHA-256とpredicateを生成済みSBOMへ意味的に照合します。

今後のReleaseはZIP、対応する `*.spdx.json`、両方を含む `SHA256SUMS.txt` を公開します。Step 8以前の既存Releaseは変更しないため、historical ReleaseにはSBOM/SBOM Attestationが存在しない場合があります。
