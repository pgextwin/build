# Chat-first minimal Release operation (14 extensions)

> **2026-10-20 third-wave setup:** [read-only Chat PR / main-push admission](issue-75-chat-only-readonly-setup.md)
> removes Dispatch from **nonpublishing validation** for pgtap / pg_variables /
> pg_store_plans. It does not replace the historical manual Release route or
> enable a push Publisher. GO B/G4/G5 remain NO-GO; **Chat-only formal Release
> NOT_READY** until the real independent Writer, effective-rule, signed-Publisher
> and per-Release human PUBLISH gates are independently accepted.

> Active product-scope decision, 2026-10-12. Detailed validation and recovery instructions remain in [step23-manual-queue.md](step23-manual-queue.md); acceptance evidence is tracked in [build issue #61](https://github.com/pgextwin/build/issues/61). This document narrows *routine operator work*; it does not relax security or declare unproven automations complete.

## 日本語: ふだんは「公開して」の一度の指示を目指す

**目的:** 安定版の検出、固定SHAの候補作成、Windows x64のビルド・検証を自動で行い、**正式Releaseだけを利用者の明示的なChatGPT指示で確定**する。その後は署名済みReleaseの検証、Catalog反映、Website公開確認まで、既存のGitHub ActionsとChatGPTが分担する。独立した第三者レビュー・二重承認は求めない。

| 段階 | 担当 | 現在の実装状態 |
| --- | --- | --- |
| 14拡張の安定版更新検出、固定SHA候補Draft PR、候補Windows CI | GitHub Actions | 実装済み。スケジュールは毎日00:00 UTC予定（開始時刻は保証されない） |
| 候補監査、最新head CIと証跡照合、マージ | ChatGPT＋GitHub接続 | GitHub接続によるPR操作が可能。**候補自動マージは導入しない** |
| 正式公開の意思決定 | 利用者 | **「検証済み候補を公開して」**という明示的な依頼を必須にする |
| `main` の `promote.yml` 起動 | GitHub Actions UI / Work | 全14拡張の `workflow_dispatch` 実装済み。**通常ChatのGitHub接続には新規Dispatch起動機能がないため、現状はWork/ブラウザーへの操作引き継ぎが必要** |
| 署名付き新規Release、ZIP・SBOM・Grype・Attestation検証 | GitHub Actions | 実装済み。正式公開は `confirm_release=PUBLISH`、正確な候補証跡と未使用タグが必須 |
| 公開後のCatalog候補レコードを1件だけ提案 | Catalogの `sync-verified-release.yml` ＋専用App | 検証コード実装済み。App設定・有効化と新Release E2Eは未受入。**正式Release自体のブロッカーにはしない** |
| Catalog PRの最新head CI確認・マージ | ChatGPT＋GitHub接続 | **自動マージAppの追加導入は当面不要**。既存のブランチ保護・必須CIは維持 |
| Website反映・公開EN/JAとダウンロード検証 | 既存CI＋ChatGPT | Catalog main pushのWebsite公開監査Workflowは実装済み。次の実Releaseで一気通貫の受入が必要 |

### 依頼文とChatGPTが実行すること

> pgextwinで公開可能な、検証済みの新しい安定版候補を確認して。適格な候補を正式公開し、CatalogとWebsiteの反映まで進めて。CI・証跡が不一致なら公開しないで。

1. ChatGPTは14件の実候補を調べる。**更新なし**、監査未完了、失敗、SHA移動、タグ衝突、ライセンス・ABI懸念は公開せず理由を報告する。複数候補があっても、依頼から対象が明らかでなければ勝手に全件を公開しない。
2. 適格な候補だけ、固定upstream full SHA、`candidate-decision`、候補PRの正確なhead、最新PG別CI・監査・署名証跡を検証し、保護されたPRをマージする。独立した人間レビューは不要。
3. `candidate_pr`、`candidate_run_id`、`decision_run_id`、**新規未使用**の`release_tag`をChatGPTが確認する。利用者の明示的な公開指示を受けて、**人間の認証済みセッション**から対象拡張の`main`に`confirm_release=PUBLISH`を渡す。GitHub bot主体による起動や認証制限の回避はしない。
4. 新しいPromotion runがSUCCESSとなり、本当に公開されたタグ、SHA256、ZIP/SBOM/Grype、Attestationと対象PGメジャーを確認する。失敗・部分Draftは停止して復旧証跡を報告し、既存タグ・Releaseを上書きしない。
5. Catalog側では署名済みの公開成果物を独立に再取得・再ハッシュし、**その拡張のJSONレコード1件のみ**をPR提案する。専用App未設定の場合は「Release公開済み／Catalog保留」と区別して記録する。App・Workflowの実行権限はUI側で別途一度だけ設定する。
6. Catalog PRの必須CI成功を最新headで確認してChatGPTがマージし、Websiteの公開日本語・英語、直DL、SHA256と証跡表示を検査する。実証されない部分をSUCCESS扱いしない。

### ここから先は実装しない（別途の新要望がある場合を除く）

- 完全無人の正式Release、定期的な自動Release、`automaticFormalRelease` の有効化。
- 候補PRの自動マージや追加の第三者承認フロー。
- Catalog自動マージのための**別の**GitHub App、複数の権限・管理画面・独自の承認ダッシュボード。
- ChatコマンドをGitHub Issueコメントから特権Workflowへ直接変換する新しい認証経路（セキュリティ範囲を広げるため）。
- Releaseを伴わないCatalog変更への自動マージの横展開、検証実績のない全機能の一斉有効化。

**引き続き必須:** main-only、認証済み非botの明示的PUBLISH、中央・ローカル許可、full SHA、最新headの全対象PG CI、ライセンス/ソース/ABI監査、成果物SHA256、SPDX SBOM、署名・Attestation、未使用タグ、冪等で安全な停止、PR保護。Grypeは**report-only**であり安全性の合格判定そのものではない。PostgreSQL EOL・上流未対応PGは除外する。

### 残りの受入項目（最小限）

1. **一度限りの管理UI作業:** Catalog専用の**PR提案Appだけ**をcatalogリポジトリに限定してインストールし、Actions variableと秘密鍵が適切に設定されたことを確かめる。漏洩・権限過大なら有効化しない。Catalog自動マージのAppは不要。
2. **次の本物の安定版更新時:** 候補 → 人間の明示的PUBLISH → 成功した署名付きRelease → 独立検証 → Catalog PRの必須CI・ChatGPTマージ → Websiteの公開確認を1件実証する。**テストのためだけに新Releaseを捏造しない。**
3. **現時点の操作上の隙間:** 通常ChatのGitHub接続単体では新しいWorkflow Dispatchを起動できない。WorkのGitHub Cloud Browserへの最小限の引き継ぎを当面使う。接続機能が増えたらこの隙間だけ置き換える。

## English summary

Keep automatic stable upstream detection, immutable candidate PRs, Windows CI, mandatory provenance, SBOM, digest and attestation verification for all 14 extensions. Treat the user's **single explicit ChatGPT publication instruction** as the only routine release decision. ChatGPT may inspect and merge a fully verified candidate; the existing human-authorized, main-only `PUBLISH` workflow creates the signed Release. The current Chat GitHub connector cannot initiate a new Actions workflow dispatch; use a minimal authenticated Work/browser handoff rather than building a new privileged command endpoint. After success, use the already implemented independent Catalog verifier and opt-in, repository-scoped **proposal-only** GitHub App; have ChatGPT merge its one-record PR only after mandatory checks. Reuse Website CI. **Do not implement autonomous Releases, candidate auto-merging, or Catalog auto-merge infrastructure.** Keep issue #61 open until the first genuine signed new-Release-to-Website end-to-end acceptance.
