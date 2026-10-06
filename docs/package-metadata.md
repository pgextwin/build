# Package metadata contract

[日本語](#日本語) | English

pgextwin packages keep two complementary metadata files inside each ZIP.

- `PACKAGE-INFO.txt` is the human-readable compatibility summary produced by the extension-specific packaging script. It remains the right place for extension-specific notes such as `shared_preload_libraries`, bundled executables, exported headers, and license notices.
- `PACKAGE-INFO.json` is the canonical machine-readable package/source/build metadata contract. It is generated centrally by `pgextwin/build` after the extension-specific package script and before upload or attestation.

The JSON schema is maintained only in this repository at `schema/package-info.schema.json`. Extension repositories do not carry schema copies.

## Contract and versioning

`schemaVersion` starts at **1**. The Step 7 milestone name “PACKAGE-INFO v2” describes the transition from the historical TXT-only package metadata to the next metadata architecture; it is not the JSON schema version.

Schema version changes are required when consumers need a new incompatible JSON contract. Additive evolution should be deliberate because the schema currently rejects unknown properties.

## Metadata identity

`PACKAGE-INFO.json` records:

- package name, Windows platform, x64 architecture, and build mode;
- upstream repository, upstream ref/version, and the exact checked-out upstream commit;
- the packaging repository and the exact checked-out packaging commit;
- `pgextwin/build`, the exact reusable-workflow commit, and reusable-workflow path;
- PostgreSQL major/tested version plus the Chocolatey package name and Chocolatey package version used to install the Windows PostgreSQL build environment;
- the actual MSVC `cl.exe` file version when it can be resolved;
- GitHub Actions run ID, attempt, URL, event, and ref;
- selected runner identity fields.

The packaging and upstream commits are resolved from the checked-out Git repositories, not inferred from mutable branch names. The shared build checkout is resolved from Git and must match `job.workflow_sha`.

`buildMode` is either `normal` or `release-attested`. This value is package metadata only. A package that says `release-attested` does **not** prove that an attestation exists or is authentic.

## Finalization order

Normal builds use:

```text
extension-specific package
  -> common PACKAGE-INFO.json generation
  -> final ZIP rebuild
  -> schema validation
  -> external SPDX 2.3 SBOM generation/validation
  -> upload-artifact
```

Attested release builds use:

```text
extension-specific package
  -> common PACKAGE-INFO.json generation
  -> final ZIP rebuild
  -> schema validation
  -> external SPDX 2.3 SBOM generation/validation
  -> SLSA Build Provenance Attestation
  -> SPDX SBOM Attestation
  -> verify both attestations
  -> upload-artifact
```

The attestation therefore covers the final ZIP bytes that already contain `PACKAGE-INFO.json`.

## Deliberately excluded fields

The package metadata does not contain a wall-clock build timestamp. The workflow run identity already provides execution traceability, while an injected current timestamp would add unnecessary byte-level variability.

The ZIP also does not contain:

- its own final SHA-256;
- GitHub Artifact Attestation IDs or URLs;
- secrets, tokens, credentials, environment dumps, or runner-local absolute paths.

A ZIP cannot safely embed its own final digest without changing the digest. Release asset SHA-256 values remain external in `SHA256SUMS.txt`. Artifact Attestations are also external and bind the final ZIP digest to GitHub/Sigstore-backed provenance.

## Relationship to other supply-chain artifacts

These mechanisms have different roles:

| Mechanism | Role |
| --- | --- |
| `PACKAGE-INFO.txt` | Human-readable package summary and extension-specific operational notes |
| `PACKAGE-INFO.json` | Machine-readable source/build/package identity |
| `SHA256SUMS.txt` | Downloaded release-file digest verification |
| Build Provenance Attestation | Externally verifiable workflow/build provenance for the final ZIP digest |
| SPDX 2.3 SBOM | External materials/components representation generated from the final ZIP |
| SBOM Attestation | Signed binding between the final ZIP digest and its SPDX 2.3 SBOM |

Step 8 consumes the finalized package identity without changing `PACKAGE-INFO.json` afterward. The SBOM remains outside the ZIP, avoiding a digest cycle. See [Software Bill of Materials (SBOM)](sbom.md).

Historical ZIPs are immutable release artifacts. Packages created before Step 7 may therefore contain only `PACKAGE-INFO.txt`; they are not rebuilt solely to add JSON metadata.

---

## 日本語

pgextwinのZIPには、役割の異なる2種類のpackage metadataを保持します。

- `PACKAGE-INFO.txt` は人間向けの互換性・注意事項です。Extension固有の `shared_preload_libraries`、同梱EXE、公開header、license noticeなどは今後もTXT側に残します。
- `PACKAGE-INFO.json` は機械可読なpackage/source/build metadataの正規形式です。Extension固有の `package.ps1` 実行後、uploadやAttestationより前に `pgextwin/build` の共通処理で生成します。

JSON Schemaの正規管理元は `pgextwin/build/schema/package-info.schema.json` だけです。8 Extension repositoryへschemaを複製しません。

`schemaVersion` は初回JSON契約なので **1** です。「PACKAGE-INFO v2」はTXTのみだった従来方式から次世代metadata architectureへ移行するStep名であり、JSON schema versionとは分離しています。

JSONにはupstreamのexact commit、packaging repositoryの実checkout commit、`job.workflow_sha` と一致するshared build commit、PostgreSQL major/tested version、Chocolatey package/version、MSVC `cl.exe` の実ファイルversion、GitHub Actions run identityを記録します。mutable branch名をbuild identityには使いません。

`buildMode=release-attested` は「Attestation用build pathで生成された」という自己申告metadataであり、真正性の証明ではありません。真正性はfinal ZIP digestに対する外部のGitHub Artifact Attestationを `gh attestation verify` で検証します。

現在時刻のtimestamp、final ZIP自身のSHA-256、Attestation ID/URLはZIP内部へ書きません。ZIP自身のdigestは `SHA256SUMS.txt`、build provenanceはGitHub Artifact Attestationが担当します。

Step 8ではStep 7でfinalizeしたZIPを変更せず、そのZIPから外部のSPDX 2.3 SBOMを生成し、別のSBOM Attestationとしてfinal ZIP digestへ結び付けます。SBOM generator identityはSBOM document・workflow・SBOM文書側に置き、`PACKAGE-INFO.json` をSBOM生成後に書き換えません。詳細は [SBOM contract](sbom.md) を参照してください。

既存Releaseはhistorical artifactとして変更しません。そのためStep 7以前のZIPには `PACKAGE-INFO.json` が存在しない場合があります。
