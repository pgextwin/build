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
- Phase 6 pgAudit 技術pilot: 完了 — [pgAudit pilot report](docs/phase6-pgaudit-pilot.md)
- Phase 7 set_user 技術pilot: 完了 — [set_user pilot report](docs/phase7-set_user-pilot.md)
- Phase 8 pg_repack 技術pilot・正式公開: 完了 — [pg_repack pilot report](docs/phase8-pg_repack-pilot.md)
- Phase 9 pg_ivm 技術pilot・正式公開: 完了 — [pg_ivm pilot report](docs/phase9-pg_ivm-pilot.md)
- Phase 10 pg_qualstats 技術pilot・正式公開: 完了 — [pg_qualstats pilot report](docs/phase10-pg_qualstats-pilot.md)

**Initial extension roadmap: 完了。** 初期8 Extensionである `pg_bigm`、`pg_cron`、`pg_hint_plan`、`pgaudit`、`set_user`、`pg_repack`、`pg_ivm`、`pg_qualstats` は、すべてPostgreSQL 14〜18向けWindows x64 Release公開とcatalog登録まで完了しています。既存pilot reportとの互換性を保つため、Phase番号は履歴として維持します。詳細は [Extension roadmap](docs/roadmap.md) を参照してください。

## 次のplatform作業

初期Extensionロードマップはここで完了です。以下は後続の独立したplatform milestoneとして扱い、**このclosure stepでは実装しません**。

1. PostgreSQL lifecycle / PG14 EOL
2. PostgreSQL 19 readiness
3. supply-chain hardening
4. package metadata / catalog improvements
5. website improvements
6. upstream update automation
7. second extension wave

## ライセンス

共通ビルド基盤はPostgreSQL Licenseで配布します。[LICENSE](LICENSE) を参照してください。
