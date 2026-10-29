# R06依存ゲートと17repo起動権限の具体案

2026-10-30 JST。正本はIssue #311、親は#75。提案JSONは`metadata/proposals/issue311-prepare-coordinator-app.json`。この文書・JSONは設定案であり、実装から読み込まれる有効な認可設定ではない。App、インストール、Environment、Secretを作成せず、既存Appの権限も変更しない。

## 今回受入できた範囲

R06-05-02-02-02の同一cycle統合は、実原本と永続状態で成立した。中央原本Run40962984014、Artifact12935853174、ZIP SHA256 `15040c5aac00282255417ff9b5668b02b4a236e3e36db1b0ebb1428515821a70`に17実ローカルRunを結合。全17保護PR、各Windows original postmerge PG14〜18/Summary、計102ジョブを独立確認した。ローカル原本ZIPは16個。実SKIPPEDジョブ1件はartifact不在を確認し、架空のreceiptを作らない。

集約要求PR#413のprotected merge `c4a7992045c1c2c95e963b6fb4ae1896c1243c7d`により、Source40970909757、独立watchdog/readback40970910085が追加操作なしで成功。App原本Git blobはrevision1 `74027bf1712c84824746dec82f379008df95cd66`からrevision2 `93ffecb3606b93f2098181779a037dfa42974eff`へ進み、13 NO_UPDATE・4 QUARANTINED。source/terminal/readbackの実ZIPも独立取得・provider SHA256照合した。4件は意図したfailure、実skip、実1分step timeout、原本bundleからの制御completion欠落であり、自然なGitHub障害を主張しない。source-kind/attempt/expiryのコピー負例と、実App永続terminal後のreplay拒否を区別する。

## R06-06で残った実際の依存

中央PREPARE workflow/scriptは原本scanまでを行い、17repoの起動を発行しない。今回もChat接続が17個の要求PRを作成・保護マージし、別の集約要求PR#413を作成した。この実証を「最初の中央要求以降、GitHubだけで17repoを起動した」とは読み替えない。

ADR-0311のCoordinatorは設計段階のままである。R04/R05の既存限定証明と今回の異常系統合を再利用できるが、中央要求から17repoへ無人起動するR05の要件は未受入。R06-06、R04/R05/R06の全体、R07〜R12を、この証拠だけで完了扱いにしない。

## 最小の追加権限案

| 主体 | 許可範囲 | 用途 |
|---|---|---|
| 既存state App5517840 | buildだけ・Contents write | 既存のCAS/lease/永続終端。変更しない |
| 新しい専用App案 | 選択した17拡張だけ・Actions write、Metadata read | 非公開PREPARE用Workflowのプログラム起動 |
| Publisher / Catalog | 既存の各専用範囲 | 起動用には転用しない |

新AppはContents、Workflows、PR、Administration、Secrets等の権限を要求しない。直接のRelease作成に必要なContents writeを持たせず、既存Publisherの認可を維持する。build/catalog/websiteはインストール対象に含めない。App名は候補であり、使用可能なslug・実App ID/installation ID/bot user IDは作成時に確認してから保護PRで固定する。

GitHubのApp権限は特定の1WorkflowだけにActions writeを限定できない。Actions writeにはWorkflowの停止・再実行等も含まれるため、新しい権限の承認が必要である。実装側で対象repo、Workflow、ref、実App actor、モード、入力、API endpointを固定し、専用Environmentをmainに限定する。既存Publisher/Signerへの未知bot・新source-kind拒否を維持する。

公式根拠: [Workflow dispatchの必要権限](https://docs.github.com/en/rest/actions/workflows#create-a-workflow-dispatch-event)、[Release作成の必要権限](https://docs.github.com/en/rest/releases/releases#create-a-release)。前者はGitHub App installation tokenとActions writeに対応する。2026-03-10 APIのRun ID付き応答はpilotで実証してから採用し、不明なPOST結果を無条件再送しない。

## 承認後に行う具体的な作業

1. private Appを作成し、提案JSONの正確な17repoだけにインストールする。webhook・外部サーバ・ユーザーOAuth認可は使わない。
2. buildに専用Environment `issue311-prepare-coordinator`とSecret `ISSUE311_PREPARE_COORDINATOR_PRIVATE_KEY`を作り、mainの信頼された起動Jobだけで使用する。鍵・tokenをChatや証跡に出さず、既存state/Publisher/Catalog keyをコピーしない。
3. 実App/installation/bot ID、権限、選択repoを独立確認し、固定policyと起動adapterを保護PR・必須CI・postmergeで導入する。未設定IDや不一致はDENY。新Appを人間ShutenOishiと偽装しない。
4. orafceで実`workflow_dispatch`起点の非公開pilotを実証する。現在のmain-push receiptを新eventの合格証明に流用しない。人間が保護マージした元要求・中央ZIP・local protected SHA・実App actor・原本Run/ZIPを結合し、公開権限なしを保つ。
5. 1repoに限定した短命tokenを単一dispatch後に失効し、同じlive tokenの401を確認する。最大4並列、既存CAS/lease、原本Run ID、有限timeout/曖昧POST終端を結合する。正常完了済み工程は再実行しない。
6. 保護条件を維持して残16repoへ展開し、初回中央要求後に追加Chatなしで17子起動・集約・永続終端する実原本を受入する。その後R05/R06-06を再判定し、成立分のみR07以降へ進む。旧cronは代替受入後のR11まで変更しない。

この案の承認はApp作成・選択17repoへのインストール・専用Environment/Secretの保存・非公開起動実装に限定する。Release、署名、Publisher/Catalogの権限拡張・資格情報転用・正式公開の承認を含まない。現在は`runtimeEnabled=false`、IDはnull、未作成・未インストールである。
