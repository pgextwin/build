# pgextwin 共通ビルド基盤

[English](README.md) | **日本語**

このリポジトリは **pgextwin** の共通CI/CD基盤です。pgextwinは、PostgreSQL拡張機能について、通常のWindows版PostgreSQLへ導入できる非公式Windows x64バイナリをビルド・検証・配布するコミュニティプロジェクトです。

このリポジトリでは、各拡張機能リポジトリから利用するReusable Workflow、PostgreSQL対応バージョン情報、共通hook仕様を管理します。

## 現在の運用：14拡張の候補キューと手動の検証済みRelease

**全14拡張**で、上流の安定版更新検出（UTC 00:00 / JST 09:00）、コミットSHA固定の**Draft候補PR**、Windows CI、機械可読な候補検証を共通化しました。中央 `metadata/automation-fleet.json` は **14件とも `BUILD` / `candidateEnabled=true`** です。候補準備は自動実行できますが、**候補のマージと正式Releaseは別々の明示的な操作**です。

正式公開は全14拡張とも、`release/*` のpush公開ではなく、**main限定の `promote.yml` `workflow_dispatch`** を使用します。マージ済みの正規候補、候補の正確なhead SHAに対応するWindows CI全対象メジャー成功、候補監査、正規の担当者、未使用タグ、`confirm_release=PUBLISH` が必須です。中央 `metadata/release-promotion.json` の手動公開許可リストも14件になりました。不完全なDraft Releaseのタグを再利用したり、独断で再公開したりしません。

無人公開ポリシーは `OBSERVE / DENY` のままです。候補PRの自動マージ、正式Releaseの自動公開、Catalogの自動マージは無効です。Catalogの署名付きRelease取り込みは別途opt-inであり、GitHub App設定や新Releaseからの実運用E2E検証まで完了したことを意味しません。詳しくは[14拡張手動キュー手順](docs/step23-manual-queue.md)、[Architecture](docs/architecture.md)、[運用受入Issue #61](https://github.com/pgextwin/build/issues/61)を参照してください。

## 共通基盤が担当する処理

- メンテナンス対象PostgreSQLバージョンの解決
- Windows版PostgreSQLの導入
- 固定されたupstreamソースのcheckout
- 設定された場合のupstream LICENSE照合
- 各Extensionのmachine-readableなTest Contract v2をコンパイル前に検証
- Extension固有のbuild/install/test/package hook呼び出し
- final ZIPを信頼対象にする前の共通 `PACKAGE-INFO.json` source/build metadata生成・検証
- final ZIPからのSPDX 2.3 JSON SBOM生成とartifact identity検証
- 検証済みSPDX SBOMをchecksum固定Grypeでreport-only scanし、point-in-time vulnerability reportを検証
- Release buildでの最終ZIPに対するBuild Provenance / SBOM GitHub Artifact Attestation生成・検証
- PostgreSQLメジャーバージョン別artifactのアップロード
- SHA-256チェックサム生成
- mainでの検証済み手動 `PUBLISH` に限定した、署名付き新規GitHub Releaseの公開

拡張機能固有のWindows対応、ビルド方法、機能テストは各Extension repository側で管理します。

## Reusable Workflowと信頼境界

各拡張は、共通Workflowとスクリプトを個別に承認された**40文字の固定コミットSHA**で参照します。read-onlyの `windows.yml` は `pgextwin/build/.github/workflows/build-extension.yml` を呼び、PR・main push・明示的な候補CIを実行します。この経路はReleaseを公開しません。

正式公開は、各拡張の `.github/workflows/promote.yml` を**mainの `workflow_dispatch`** から手動起動し、次の入力を渡す方式です。

- `candidate_pr`：既にマージされた不変の上流候補PR
- `candidate_run_id`：候補の正確なhead SHAで成功したWindows CI
- `decision_run_id`：`candidate-decision` 成果物がある検出run
- `release_tag`：過去に使用していない新しいWindows Releaseタグ
- `confirm_release`：文字列 `PUBLISH`

認可jobは中央・各拡張のポリシーを照合し、`promotion-receipt` を記録します。その後だけ、署名付きbuildのReusable Workflowで対象PostgreSQLの再ビルド、ZIP・SPDXのAttestation作成・検証を行います。最後にlocal `publish` jobが共通 `fleet-publish-release.py` を呼び、ZIP整合性・SHA-256・署名・未使用Release IDを検証して公開します。部分失敗時は復旧記録を残し、既存タグ・Release・assetを変更しません。

`release-extension.yml` は過去との互換性のため共通Build内に残っていますが、**現在の14拡張の正式公開経路ではありません**。過去の `release/*` 手順を現行操作に用いず、拡張ごとに実際にpinされたWorkflowのSHAを確認してください。

詳細は [Test Contract v2](docs/test-contract-v2.md)、[Package metadata contract](docs/package-metadata.md)、[SBOM contract](docs/sbom.md)、[Vulnerability policy baseline](docs/vulnerability-policy.md)、[Artifact Attestations / build provenance](docs/artifact-attestations.md)、[GitHub Actions trust / permission policy](docs/github-actions-security.md)、[Hook contract](docs/hook-contract.md)、[Architecture](docs/architecture.md) を参照してください。

## PostgreSQL Lifecycle

PostgreSQLのLifecycle filterはこのrepositoryで一元管理します。通常の新規build対象になるのは、PostgreSQLコミュニティのサポート期間内で、Extension manifestが許可し、必要なupstream ref/versionが存在するmajorだけです。公式EOL日はその日を含めて有効とし、翌UTC日から通常のbuild matrixから除外します。

2026-10-06時点でPostgreSQL 14は **2026-11-12** までサポート対象です。その日までは通常build対象のままとし、**2026-11-13** から新規build matrixから除外します。EOL後も既存Git tag、GitHub Release、asset、checksumは保持します。

詳細なルールと決定論的な境界テスト仕様は [PostgreSQL lifecycle policy](docs/postgresql-lifecycle.md) を参照してください。

## 現在の位置づけ

- Phase 2 共通ビルド基盤: 完了
- Phase 3 pg_bigm pilot: 完了 — [Phase 3 pilot report](docs/phase3-pg_bigm-pilot.md)
- Phase 4 第2Extension技術pilot: 完了 — [pg_cron pilot report](docs/phase4-pg_cron-pilot.md)
- Phase 5 pg_hint_plan 技術pilot: 完了 — [pg_hint_plan pilot report](docs/phase5-pg_hint_plan-pilot.md)
- Phase 6 pgAudit 技術pilot: 完了 — [pgAudit pilot report](docs/phase6-pgaudit-pilot.md)
- Phase 7 set_user 技術pilot: 完了 — [set_user pilot report](docs/phase7-set_user-pilot.md)
- Phase 8 pg_repack 技術pilot・正式公開: 完了 — [pg_repack pilot report](docs/phase8-pg_repack-pilot.md)
- Phase 9 pg_ivm 技術pilot・正式公開: 完了 — [pg_ivm pilot report](docs/phase9-pg_ivm-pilot.md)
- Phase 10 pg_qualstats 技術pilot・正式公開: 完了 — [pg_qualstats pilot report](docs/phase10-pg_qualstats-pilot.md)

**Initial extension roadmap: 完了。** 初期8 Extensionである `pg_bigm`、`pg_cron`、`pg_hint_plan`、`pgaudit`、`set_user`、`pg_repack`、`pg_ivm`、`pg_qualstats` は、すべてPostgreSQL 14〜18向けWindows x64 Release公開とcatalog登録まで完了しています。既存pilot reportとの互換性を保つため、Phase番号は履歴として維持します。詳細は [Extension roadmap](docs/roadmap.md) を参照してください。

## 次のplatform作業

初期Extensionロードマップは完了済みです。PostgreSQL lifecycle / PG14 EOLのbuild基盤（Step 2）、Catalog / WebsiteのLifecycle表示（Step 3）、**PostgreSQL 19 Readiness / Compatibility Audit（Step 4）**、**GitHub Actions Trust Baseline（Step 5）**、**Artifact Attestation / Release Build Provenance（Step 6）**、**PACKAGE-INFO v2（Step 7）**、**SBOM Generation & SBOM Attestation（Step 8）**、**Test Contract v2 / Runtime Capability & Functional Validation Contract（Step 9）**、**Vulnerability / Dependency Policy Baseline（Step 10）**まで完了しました。詳細は [PostgreSQL 19 readiness](docs/postgresql-19-readiness.md) と [GitHub Actions trust policy](docs/github-actions-security.md) を参照してください。

PostgreSQL 19は、文書化したGA / Windows配布 / upstream gateを満たすまではproduction matrixへ追加しません。後続作業は別milestoneとして扱います。

1. 文書化したGA / Windows配布 / upstream gateを満たした後のPostgreSQL 19正式オンボーディング
2. 将来のhard vulnerability gate、VEX / exception管理、Dependency Submission / Review、SARIF / Security tab統合、license policy、PostgreSQL runtime vulnerability policy
3. 現行metadataを越えたCatalog / Website provenance・security visibility
4. Python dependency lockingとより広いbuild-tool provenance
5. 記録済みChocolatey identityを越えたPostgreSQL package provenance
6. second extension wave


## 上流更新検出

**Step 13** は初期8拡張のIssue型安定版検出を実装した履歴です。現在は**全14拡張**が、検出と独立したSHA固定の候補作成・Windows CI・候補監査を使用します。workflowファイル変更のmain pushではwatcher/plannerのdry-run受入を実行し、本番scheduleは**毎日09:00 JST**です。検出・候補作成から正式Releaseが自動公開されることはありません。

PostgreSQL公式ライフサイクル監視は継続し、検知だけでは成果物を変更しません。現行操作は[14拡張手動キュー](docs/step23-manual-queue.md)、当初のIssue検出仕様は[Step 13設計](docs/update-automation.md)を参照してください。

## ライセンス

共通ビルド基盤はPostgreSQL Licenseで配布します。[LICENSE](LICENSE) を参照してください。
