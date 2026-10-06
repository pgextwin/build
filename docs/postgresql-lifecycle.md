# PostgreSQL lifecycle policy

This document defines how pgextwin/build decides whether a PostgreSQL major version belongs in a new Windows build matrix. The PostgreSQL community's [Versioning Policy](https://www.postgresql.org/support/versioning/) is the authoritative source for support and final-release dates.

## Build eligibility

A PostgreSQL major is eligible for a normal new pgextwin build only when all of the following are true:

1. the PostgreSQL community still supports the major on the effective build date,
2. the extension manifest allows that major, and
3. the manifest provides the upstream version/ref needed for that major (either through the uniform upstream mapping or a PostgreSQL-major-specific mapping).

The shared resolver owns the lifecycle filter. Extension repositories do not need to remove an EOL major from their manifests merely to stop normal builds.

## Effective date and EOL boundary

Lifecycle decisions use a **calendar date**, not a time of day.

- Normal workflow execution uses the current UTC date.
- Tests can pass an explicit `-EffectiveDate yyyy-MM-dd` to `scripts/resolve-matrix.ps1`.
- The PostgreSQL final support / EOL date is **inclusive**.
- A major leaves the normal build matrix on the following calendar day.

For PostgreSQL 14, whose official final release date is 2026-11-12:

| Effective date | Normal build status |
|---|---|
| 2026-11-11 | Included when the extension manifest allows PG14 |
| 2026-11-12 | Included when the extension manifest allows PG14 |
| 2026-11-13 | Excluded from new normal build matrices |

The resolver implements this as `EOL >= effective date`.

## Historical availability vs. current maintenance

pgextwin treats these as separate concepts:

- **Current maintenance** controls whether a PostgreSQL major is included in a new normal build matrix.
- **Historical availability** records binaries that were already built and published while that major was supported.

When a PostgreSQL major reaches EOL:

- existing Git tags are retained,
- existing GitHub Releases are retained,
- existing release assets are retained,
- existing `SHA256SUMS.txt` files are retained,
- the PostgreSQL metadata entry may remain so the resolver can make a date-based decision,
- but normal new releases exclude that major beginning the day after EOL.

EOL is therefore not a deletion event.

## Metadata contract

`metadata/postgresql.json` is the shared lifecycle/build metadata source. CI validates that:

- `schemaVersion` is 1,
- every entry contains `major`, `minor`, `chocolateyPackage`, `chocolateyVersion`, `eol`, and `testPort`,
- majors are valid, unique, and ordered ascending,
- `minor` is non-empty and matches its major,
- `eol` uses `yyyy-MM-dd` and is a valid calendar date,
- Chocolatey fields are non-empty,
- and `testPort` is a valid TCP port number.

The Chocolatey package revision is packaging metadata and is not derived from the PostgreSQL Versioning Policy.

## Verified support snapshot: 2026-10-06

The following values were checked against the PostgreSQL Versioning Policy on 2026-10-06:

| Major | Current minor | Final release / EOL |
|---:|---:|---|
| 14 | 14.24 | 2026-11-12 |
| 15 | 15.19 | 2027-11-11 |
| 16 | 16.15 | 2028-11-09 |
| 17 | 17.11 | 2029-11-08 |
| 18 | 18.6 | 2030-11-14 |

PostgreSQL 14 remains a normal build target through 2026-11-12. It must not be removed early from `metadata/postgresql.json` or extension manifests solely because its EOL is approaching.

PostgreSQL 19 is outside this milestone and is not added to metadata or build matrices here.

## Catalog and website boundary

Catalog schema v1 currently uses `postgresql.<major>.available` primarily to describe whether a published asset exists. That is not the same as current community maintenance.

This lifecycle foundation does **not** add `maintained` or EOL fields to catalog schema v1 and does not change the website lifecycle UI. Catalog/website lifecycle representation is a separate follow-up milestone.

---

# PostgreSQL ライフサイクルポリシー

この文書は、pgextwin/build がPostgreSQLの各メジャーバージョンを新規Windows build matrixへ含めるかどうかを判定するルールを定義します。サポート期間とFinal Release日については、PostgreSQLコミュニティの [Versioning Policy](https://www.postgresql.org/support/versioning/) を一次情報とします。

## Build対象となる条件

PostgreSQL majorを通常の新規pgextwin build対象にするには、次のすべてを満たす必要があります。

1. effective date時点でPostgreSQLコミュニティのサポート期間内であること
2. Extension manifestがそのmajorを許可していること
3. そのmajorのbuildに必要なupstream version/refがmanifestに存在すること（共通refまたはPostgreSQL major別mapping）

Lifecycle filterは共通resolverが担当します。EOLになったmajorを通常buildから外すためだけに、各Extension repositoryのmanifestから直ちに削除する必要はありません。

## Effective dateとEOL境界

Lifecycle判定は時刻ではなく**日付**で行います。

- 通常のworkflow実行ではUTCの現在日付を使用します。
- テストでは `scripts/resolve-matrix.ps1` に `-EffectiveDate yyyy-MM-dd` を明示できます。
- PostgreSQL公式のFinal Release / EOL日は**その日を含めて有効**です。
- 通常build matrixから除外するのはEOL日の翌日からです。

PostgreSQL 14の公式Final Release日は2026-11-12なので、次の扱いになります。

| Effective date | 通常buildでの扱い |
|---|---|
| 2026-11-11 | Extension manifestがPG14を許可していれば含める |
| 2026-11-12 | Extension manifestがPG14を許可していれば含める |
| 2026-11-13 | 新規の通常build matrixから除外 |

resolverでは `EOL >= effective date` として実装します。

## Historical availability と Current maintenance

pgextwinでは次の2つを別概念として扱います。

- **Current maintenance**: 新規の通常build matrixへ含めるかどうか
- **Historical availability**: サポート期間中にすでにbuild・公開した過去の配布物が存在すること

PostgreSQL majorがEOLになっても、

- 既存Git tagは削除しない
- 既存GitHub Releaseは削除しない
- 既存Release assetは削除しない
- 既存の `SHA256SUMS.txt` は保持する
- resolverが日付判定できるようPostgreSQL metadata entryは残してよい
- ただしEOL翌日以降の通常の新規Releaseではそのmajorをbuild対象にしない

という方針です。EOLは既存配布物の削除イベントではありません。

## Metadata contract

`metadata/postgresql.json` を共通のLifecycle/build metadata sourceとし、CIでは次を検証します。

- `schemaVersion` が1
- 各entryに `major`、`minor`、`chocolateyPackage`、`chocolateyVersion`、`eol`、`testPort` が存在
- majorが妥当・一意・昇順
- `minor` が空ではなくmajorと整合
- `eol` が `yyyy-MM-dd` 形式で実在する日付
- Chocolatey関連フィールドが空でない
- `testPort` が有効なTCP port番号

Chocolatey package revisionはPostgreSQL公式Versioning Policyから導出する値ではなく、Windows package側のmetadataとして扱います。

## 2026-10-06時点の公式照合

| Major | Current minor | Final Release / EOL |
|---:|---:|---|
| 14 | 14.24 | 2026-11-12 |
| 15 | 15.19 | 2027-11-11 |
| 16 | 16.15 | 2028-11-09 |
| 17 | 17.11 | 2029-11-08 |
| 18 | 18.6 | 2030-11-14 |

PostgreSQL 14は2026年11月12日まで通常のbuild対象とし、翌日以降は新規build matrixから除外します。既存Releaseは保持します。EOL日が近いという理由だけで、期日前に `metadata/postgresql.json` やExtension manifestからPG14を削除してはいけません。

PostgreSQL 19はこのmilestoneの対象外であり、metadataやbuild matrixには追加しません。

## Catalog / Websiteとの境界

Catalog schema v1の `postgresql.<major>.available` は主として公開済みassetの存在を表しており、PostgreSQLコミュニティによる現在のmaintenance状態とは別概念です。

このLifecycle Foundationではschema v1へ `maintained` やEOL情報を追加せず、WebsiteのLifecycle表示も変更しません。Catalog / Website上のLifecycle表現は後続milestoneで扱います。
