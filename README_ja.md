# pgextwin 共通ビルド基盤

[English](README.md) | **日本語**

このリポジトリは **pgextwin** の共通CI/CD基盤です。pgextwinは、PostgreSQL拡張機能について、通常のWindows版PostgreSQLへ導入できる非公式Windows x64バイナリをビルド・検証・配布するコミュニティプロジェクトです。

このリポジトリでは、各拡張機能リポジトリから利用するReusable Workflow、PostgreSQL対応バージョン情報、共通hook仕様を管理します。

## 共通基盤が担当する処理

- メンテナンス対象PostgreSQLバージョンの解決
- Windows版PostgreSQLの導入
- 固定されたupstreamソースのcheckout
- 設定された場合のupstream LICENSE照合
- Extension固有のbuild/install/test/package hook呼び出し
- PostgreSQLメジャーバージョン別artifactのアップロード
- SHA-256チェックサム生成
- `release/*` ブランチからのGitHub Release公開

拡張機能固有のWindows対応、ビルド方法、機能テストは各Extension repository側で管理します。

## Reusable Workflow

呼び出し側は次のように利用します。

```yaml
permissions:
  contents: write

jobs:
  windows:
    uses: pgextwin/build/.github/workflows/build-extension.yml@main
    with:
      extension_config_path: config/extension.json
```

`contents: write` は、`release/*` ブランチからGitHub Releaseを作成・更新するために必要です。Reusable Workflow内の通常のビルド・テストジョブはread-only権限で実行します。

詳細は [Hook contract](docs/hook-contract.md) と [Architecture](docs/architecture.md) を参照してください。

## 現在の位置づけ

- Phase 2 共通ビルド基盤: 完了
- Phase 3 pg_bigm pilot: 完了 — [Phase 3 pilot report](docs/phase3-pg_bigm-pilot.md)
- Phase 4 第2Extension技術pilot: 完了 — [pg_cron pilot report](docs/phase4-pg_cron-pilot.md)
- Phase 5 pg_hint_plan 技術pilot: 完了 — [pg_hint_plan pilot report](docs/phase5-pg_hint_plan-pilot.md)

pg_hint_plan pilotではさらに、PostgreSQLメジャー別upstream release、メジャー別license notice、Flex scanner生成、公式PostgreSQL sourceからのquery-jumble互換object再生成を検証しました。`pg_bigm` と `pg_cron` はPostgreSQL 14〜18向けReleaseとcatalog登録まで完了しています。`pg_hint_plan` はPostgreSQL 14〜18で技術検証完了済みで、正式なOrganization repository作成後にproductizationへ進みます。

## ライセンス

共通ビルド基盤はPostgreSQL Licenseで配布します。[LICENSE](LICENSE) を参照してください。
