# Phase 3 pilot completion: pg_bigm

## Result

The pg_bigm pilot is complete.

The pilot proved that the shared pgextwin build architecture can separate common Windows CI/CD mechanics from extension-specific build and functional-test logic.

## Repositories

- Shared infrastructure: `pgextwin/build`
- Pilot packaging repository: `pgextwin/pg_bigm`
- Upstream: `pgbigm/pg_bigm`

The packaging repository has been transferred to the `pgextwin` Organization. The existing Release assets were preserved, post-transfer documentation links were corrected, and the full PostgreSQL 14–18 matrix was revalidated successfully after the transfer.

## Verified architecture

The caller repository now contains only:

- `config/extension.json`
- extension-specific Windows build adaptation,
- `windows/ci/build.ps1`,
- `windows/ci/install.ps1`,
- `windows/ci/smoke-test.ps1`,
- `windows/ci/package.ps1`,
- a small caller workflow.

The reusable workflow in `pgextwin/build` owns:

- maintained PostgreSQL version resolution,
- PostgreSQL Windows installation,
- pinned upstream checkout,
- upstream-license verification,
- hook invocation,
- artifact upload,
- checksum generation,
- bilingual Release publication.

## Validation

The final pull-request validation and the post-merge `main` validation both passed for:

- PostgreSQL 14
- PostgreSQL 15
- PostgreSQL 16
- PostgreSQL 17
- PostgreSQL 18

Each PostgreSQL major completed:

```text
matrix resolution
→ upstream checkout
→ license verification
→ PostgreSQL installation
→ build hook
→ install hook
→ CREATE EXTENSION / functional smoke test
→ package hook
→ artifact upload
```

The pg_bigm functional test creates the extension, creates a GIN index using `gin_bigm_ops`, and verifies a real search result.

## Phase 3 acceptance criteria

| Criterion | Result |
|---|---|
| Reusable cross-repository workflow works | PASS |
| Central PostgreSQL lifecycle metadata works | PASS |
| Extension manifest controls compatibility range | PASS |
| Upstream source remains pinned | PASS |
| Upstream license verification works | PASS |
| Extension-specific hooks remain local | PASS |
| PG14–18 build successfully | PASS |
| Functional test succeeds on every target | PASS |
| Per-major Windows x64 artifacts are produced | PASS |
| English/Japanese documentation updated | PASS |

## Productization status

Productization is complete.

- Repository: `pgextwin/pg_bigm`
- Release: `v1.2-20250903-windows.1`
- PostgreSQL 14–18 assets plus `SHA256SUMS.txt`
- Public catalog entry: published
- Post-transfer full-matrix CI: PASS

---

# Phase 3 pilot完了: pg_bigm

## 結果

pg_bigmを使用したpilot検証は完了しました。

共通Windows CI/CD処理を `pgextwin/build` に集約し、Extension固有のビルド・機能テストのみを各Extension repositoryに残す構成が実際に成立することを確認しました。

## 検証済みPostgreSQL

PostgreSQL 14 / 15 / 16 / 17 / 18 の全5世代で、ビルドだけでなく `CREATE EXTENSION`、GINインデックス作成、実検索、ZIP package、artifact uploadまで成功しています。

## Phase 3完了判定

Reusable Workflow、中央PostgreSQL metadata、Extension manifest、LICENSE照合、Extension固有hook、5世代の実機能テスト、Windows x64 artifact生成、英日ドキュメントをすべて確認済みです。

その後、repositoryは `pgextwin/pg_bigm` へ移管済みです。既存Release assetを保持したまま、移管後のドキュメント修正とPostgreSQL 14〜18の再検証も完了し、catalogへ公開済みです。
