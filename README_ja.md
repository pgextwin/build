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
jobs:
  windows:
    uses: pgextwin/build/.github/workflows/build-extension.yml@main
    with:
      extension_config_path: config/extension.json
```

詳細は [Hook contract](docs/hook-contract.md) と [Architecture](docs/architecture.md) を参照してください。

## 現在の位置づけ

pgextwin Phase 2の共通ビルド基盤です。最初のpilot extensionとしてpg_bigmを使用します。

## ライセンス

共通ビルド基盤はPostgreSQL Licenseで配布します。[LICENSE](LICENSE) を参照してください。
