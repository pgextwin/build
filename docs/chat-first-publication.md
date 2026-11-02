# Chat一指示 → 適格な正式公開（17拡張共通）

> 現行の優先運用契約（2026-11-02）。正本: [build #311](https://github.com/pgextwin/build/issues/311)、公開経路: [#75](https://github.com/pgextwin/build/issues/75)。
> この文書は2026-10の14拡張・手動PUBLISH前提の記述を上書きする。既存の独立した公開ゲートは変更しない。

## 一指示の意味と権限境界

所有者が通常Chatで **「pgextwinを更新して」** と依頼した場合、その依頼に含まれる登録済み拡張の真正な安定版更新について、**更新検出・実装・検証・保護マージから、条件を満たした正式Release、Catalog、Website公開まで行うことを明示的に承認したもの**と扱う。途中で「公開して」「継続して」と改めて確認しない。特定拡張の指定があればその範囲に限定し、無指定なら保護Fleetの登録済み全拡張を対象とする。

この**自然言語での所有者意思表示は、GitHub内の検証済みPUBLISH receipt・署名・App token・正規eventを代替しない**。共通Publisherのcronは撤去し、既存の保護された署名付き公開policyを満たす対象について、所有者本人による正規の `workflow_dispatch` または build Issue #311 への本人認証済み `/pgextwin publish pgextwin/<extension>` コメントの真正 `issue_comment.created` を用いる。手動Runには別途、保護された中央の `metadata/owner-dispatch-publication.json` による許可も必要で、GitHubが返すactorとtriggering_actorのログイン・IDを照合し、scheduleになりすまさない。上流検出を含めた全工程のcron撤去は別途必要である。

**更新なし**は `NO_UPDATE` で正常終了する。複数拡張のうち更新可能なものは独立して完了し、別の拡張の不成立を理由に一括停止しない。既存Releaseのタグ・資産は上書きしない。

## Chat主体で一貫して実行する標準手順

1. **現状の認証済みGET**: Fleet登録/中央・各repo保護main、公開Release/Catalog、重複候補PR、先行成功Run、上流stableと固定SHAを照合。成功済みのCI・署名Runを再実行しない。
2. **本物の変更がある拡張だけ**: 既存の自動候補・検証を再利用し、必要な最小実装と真正native Windows CI（PG対応メジャー、機能テスト）を進める。GitHubの `action_required` で正規の実行承認が必須な場合に限りWorkのGUIへ引き継ぎ、それ以外をChatで進める。成功/失敗/SKIPPEDと真正PR run/dispatch runを混同しない。
3. **保護マージ**: 最新HEAD・必須CI・既存保護設定が成立した場合にのみマージ。独立第三者レビューを新要件として加えないが既存保護設定は維持。
4. **署名済み原本**: マージ済み保護mainから生じた正規 `push`/OIDC署名Run、ZIP/SPDX/Grype、Build Provenance・SBOM Attestation、原本と別RunnerのSigstore実バイト独立照合を要求。コード成功と署名真正性を区別。
5. **独立Publisher**: 中央 `publisher-candidate-intake.yml` を所有者本人が起動した真正 `workflow_dispatch`、正確な原本Run/attempt、現在の保護main、中央・ローカルの署名付き公開policy、専用Publisher App/Environment、Grypeブロック、live verify、未使用タグ、create-only/失効を再確認。手動Runは所有者のログインと数値IDをRunのGitHub GETで照合し、対象は指定された登録済みリポジトリ1件に限定し、別種のreceiptとして記録する。dry-runが既定であり、公開には明示的に解除する。単なるChat同意、`push`、他人のDispatch、静的policy、古い別Run成功は発行権限ではない。
6. **本当の公開物**: Releaseの公開タグ・PG別ZIP/SPDX/Grypeと `SHA256SUMS.txt`、公開バイトのSHA256、公開署名・Attestationを独立GETで検証。候補Artifactのハッシュを公開物のハッシュの代用にしない。
7. **Catalog・Website**: 正式に公開されたReleaseに限定して専用Catalog検証でレコード単位PRを作る。必須CI→保護マージ後、Website日本語・英語、実ダウンロード、SHA256を確認。未公開候補でCatalogを先に進めない。
8. **監査**: [#311](https://github.com/pgextwin/build/issues/311)に、完成したもの・未完了・阻害原因・必要なら最小のWork操作を簡潔に記録。公開済みと候補のみを明確に分け、歴史的85/94等の台帳を成功なしに加算しない。

## 完成の判定（再確認を要求しない）

| 完了状態 | 意味 |
| --- | --- |
| `NO_UPDATE` | 上流差分なし、既存公開資産維持 |
| `CANDIDATE_ONLY` | 更新実装・CI等は済んだが正式Releaseなし |
| `SIGNED_NONPUBLISHING` | 署名候補と独立監査まで成立、Publisher認可/Release未成立 |
| `RELEASE_PUBLISHED` | 実公開ReleaseのSHA256・署名・Attestationの検証成功、Catalog/Websiteは別管理 |
| `PUBLIC_COMPLETE` | Release + Catalog保護main + Website JA/EN + 公開DLの実検証すべて成功 |
| `BLOCKED` | 実在する必要ゲート、権限、CI、安全上の不成立。偽承認・保護緩和は禁止 |


## Workを使わない本人コメント起動

1. ChatのGitHub接続から build Issue #311 に **対象1件だけ** `/pgextwin publish pgextwin/hypopg` のような形式でコメントを追加。通常の監査コメントは公開要求ではない。
2. 本物の `issue_comment.created` Runのactor/triggering_actorのログイン・数値ID、GitHubイベントJSON、元Issue・編集されていないコメント・Run表示名に固定されたコメントIDを照合する。
3. 署名付きsource main/push原本、別RunnerのZIP/SPDX/Grype/Sigstore、最新保護main、既存Publisher App/Environmentとcreate-only tagを再検証し、条件不成立は公開しない。
4. CatalogもReleaseの出所を独立GETし、コメントID・対象・実Runを照合する。公開後はCatalog保護PR、必須CI、Website日英公開証跡まで更新する。

元の `workflow_dispatch` と別の正規eventとして記録し、schedule偽装・成功Run再実行・コメント編集による権限変更を禁止する。

## Workでしかできない最小作業

通常ChatのGitHub接続で行える調査、コード変更、PR、CI確認、保護マージ、Issue記録はChat側で完結させる。Workは**GitHub公式画面だけが実行できる** `Approve and run`、必要なActions/Environment/App管理GUI等の具体的な障害時だけ使用する。Workに渡す場合は、対象URL・唯一必要な操作・期待HEAD/Run・検証条件・禁止事項を含む、短い実行プロンプトを用意する。

公開の意思表示は**毎回の「pgextwinを更新して」で既に成立**しており、Workへ渡す作業を公開の再承認にしてはならない。GitHubの独立した権限・実行承認を必要とする場合は、それを正式な操作上の障害として扱う。

## 安全維持

ブランチ保護、必須CI、固定上流SHA、ライセンス・PG対応、実Windows機能試験、GitHub original event/Run/attempt、Grypeブロック、SPDX、SHA256、署名、Attestation、独立Publisher Appの最小権限・token失効、tag create-only、有限回復・曖昧状態隔離、Catalog保護、Website公開実証を維持。旧成功Run再実行、偽の更新、未検証公開、手動のみ経路への無条件切替、追加Secret/権限拡大はしない。

## English summary

A single authenticated Chat request **“pgextwinを更新して”** is the owner's instruction to perform the registered fleet update through **eligible formal publication and public Catalog/Website verification**, without asking for a second publication consent. It does *not* replace independently enforced GitHub Actions, signed-source, authentic event, scoped Publisher, release, Catalog or Website gates. Owner-triggered `workflow_dispatch` and `schedule` have distinct authenticated provenance. Use connected Chat for supported GitHub work and the official Actions UI when dispatch is unavailable. Record `NO_UPDATE`, partial, blocked and fully public outcomes distinctly.
