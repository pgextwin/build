# #311 残作業の実行契約 v2.2（2026-10-31 JST）

この文書はユーザーの「タスクを明確化し、再現可能な手順と受入条件を計画して実施する」という指示に対応する。#311 v2.1、94枝番、過去の原本、85受入/9未受入を維持する。公開認可や実証条件を自動的に成立させない。

機械可読の正本は `metadata/issue311-remaining-work-v22.json`。各作業に inputs / procedure / passWhen / failWhen / nextAction / accepted を持たせた。これら7作業は既存94枝番の作業分解であり、新しい受入件数ではない。

## 停滞原因と今回の修正

1. 承認待ちStateの有無の再監査を繰り返しても、原本は発生しない。さらに共通 `record_completion` は NO_UPDATE/FAILED/QUARANTINED だけを受け付け、既存enumの BLOCKED_APPROVAL に対応する専用共通遷移が存在しなかった。今回 `record_approval_block` を追加した。**既存の実承認lookupを呼び出す認証adapterはまだない。この変更だけで実運用経路が完成したとはしない。**
2. 17対象PREPAREのNO_UPDATE証明は、旧scheduleが担う候補作成・署名再評価・Catalog照合等の全機能の代替証明ではない。対象workflowごとの機能と入出力を先に固定する。
3. 旧/新Writerの偶発競合を待つ計画には有限の完了条件がない。共有する書込資源を特定し、実コード・真正event・隔離Stateによる制御試験を設計する。一般CASの実409を旧/新Writer競合と読み替えない。
4. 実行前に止まったSKIPPEDには子ZIPが存在しない場合がある。必須証拠はその段階に対応させ、認証済みartifact不在を記録する。ただし元dispatch入力との結合不足は不在証明で代用しない。

## 作業順・合否

| 作業 | 入力・実施内容 | 合格条件 / 未達時の具体工程 |
|---|---|---|
| W10-A 共通承認停止 | bound original State + 固定policy + 認証済み承認不足の観測。専用遷移と既存CAS adapterの制御試験 | 17対象BLOCKED_APPROVAL、理由/再開点のevent hash結合、成功不変、stale/ACK喪失拒否。**コード/制御試験限定**。live合格はW10-C |
| W10-B 異常原本の結合 | 既存2正常×17、4異常×17、32子ZIPとorafce skip/timeout | 原本入力→子Run/attempt/head→存在するZIPまたは真の不在→State→理由/再開点を結合。orafce POST入力が回収不能ならUNRECOVERABLE_INPUT_BINDINGと記録し、次の限定負例に先立ち入力receipt保存を実装 |
| W10-C 実承認gate adapter | 実在する**有効な**PREPARE policy・適格要求・真正source | 条件分岐：承認が実際に必須かつ不足→`BLOCKED_APPROVAL`原本、承認不要→`NOT_REQUIRED`原本＋正常な安全終端。いずれも実State App CAS→revoke401→別Runner鍵なしGET→元ZIP実SHAと17対象の理由/復旧点を照合。承認不足の捏造禁止 |
| W11-A schedule機能の代替 | 17拡張、build6/catalog4/website1、hypopg追加回復を別区分 | 各機能の非公開正常/異常original受入→その対象だけ保護PR撤去→postmerge→20repo再監査。先にorafce pilot。棚卸しだけのPRを反復しない |
| W11-B 旧/新書込の排他 | 実コードSHAと書込namespaceの対応表 | 共有Writerは実旧/新コード・真正event・隔離資源で実409/PUT1回ずつ/失効/有限再開を証明。共有しない組合せはnamespaceと書込allowlistの非交差を証明しN/Aを明示。これは実409の代替証拠ではない。旧Run不在の観測だけでは不可 |
| W12-A 非公開最終要求 | R10/R11前提成立、固定17対象の1要求 | 保護PR→CI→期待HEAD merge→真正中央/17子→有限終端CAS→独立読取。理由/最終成功/安全再開/Run/ZIP実SHA/Stateを報告。親依存は別途すべて照合 |
| W09-A 実公開 | 将来適格stable + 特定候補への正式PUBLISH | 正規公開原本→Catalog→CLI/feed→EN/JAを独立照合。外部条件未成立なら待機。試験Release/tag作成禁止 |

親R10はR10-01/02、親R11はR11-01/02、親R09はR09-01/02の両成立後のみ。R12-02と親R12を混同せず、親R12はv2.1のR07〜11前提を別途満たす。#75は全公開ゲート成立前に閉じない。外部条件の未成立と実装の未完成を分ける。

## 再現手順（無資格情報・非公開）

```bash
python tests/test-issue311-request-lifecycle.py
python tests/test-issue311-lifecycle-store.py
python tests/test-issue311-approval-block.py --receipt issue311-r10-reproducible-boundary.json
```

同じcheckoutで最後のコマンドをもう一度実行するとreceipt実バイト一致を検証する。正常17対象、要求/HEAD/Run/対象差替、policy欠落、期限切れ、承認十分、PUBLISH_DENY誤用、終端再開、成功上書き、stale CAS、PUT ACK喪失後GETを決定的に検査する。テストtransportはIN-MEMORYであり、GitHubの実409・実App・実承認の証明ではない。

保護PRのrequired resolverでも上記新テストを実施する。新workflowはread-onlyで、original main pushに対するテストreceiptをuploadし、別Runnerが実ZIPを取得してCRC/provider digest/内部JSON/再実行結果のバイト一致を検査する。ここで再実行するのは決定的なofflineテストであり、成功Actions Runのrerunや過去の本物の要求の再起動ではない。

## 共通関数の契約と安全な再開

`record_approval_block` は**pure関数**で、ネットワーク認証や実承認lookupを行わない。呼出元は原本request、source attempt1、policyのGit blob、実際の人間承認不足を独立した認証GETで先に照合する。caller提供booleanのみで実承認証明を作ってはならない。policyModeはPREPARE限定で、PUBLISH_DENY/AUDIT_ONLY/失敗/隔離を承認不足へ改名しない。

元request/HEAD/sourceRun/17対象が一致し、未期限切れで全対象PENDINGかつsource登録済みの場合だけ、BLOCKED_APPROVALを新revisionへ遷移させる。元の成功・失敗・隔離・承認停止terminalは不変。理由HUMAN_PREPARE_APPROVAL_MISSING、最終成功SOURCE_BOUND、再開RECHECK_ORIGINAL_APPROVAL_WITH_NEW_AUTHORIZATIONを含む原本観測JSON全体のSHA256をState eventへ結合する。観測JSON自体はoriginal receiptとして保全する。

BLOCKED_APPROVALを自動的にSUCCESSへ書き戻す機能は追加しない。後日の承認時は元の停止を再読取し、既存の明示的再開認可と新たな観測で新処理を開始する。そのlive再開adapterも今回未実装であり、R10-02の受入時に必要範囲を別途証明する。

## 反復監査を止める規則

未変更の原本を再取得するだけのPRを作らない。次の条件が成立するときだけ再確認する：policy/要求/原本の変更、実装修正、既存証拠の有効期限切れ、受入に必要な新証拠の発生。外部待機は再開条件を1回記録し、独立したIMPLEMENT作業へ進む。保護PR・required CI・postmerge・実バイト照合なしで受入件数を増やさない。

不変条件：runtimeEnabled=false / PUBLISH_DENY / 全保護・必須CI / 原本保全 / 成功Run rerun禁止 / 新cron・Chat定期タスク・外部worker禁止 / 偽actor・source-kind・schedule禁止 / Secret転用・権限緩和・未認可公開禁止。Website Draft #45は未マージ。


## v2.3 R10 有効承認policyの条件分岐（旧v2.2表現を補正）

**単一ユーザー運用で人間の承認不足を人工的に作ることは受入条件ではない。** まず実際のpolicy Git blob/Environment設定・request/source attempt1を認証済みの原本で固定し、以下の**排他的な実際の分岐**に従う。マシン可読正本は `metadata/issue311-remaining-work-v22.json` の W10-A/W10-C `passWhen` とする。

- **REQUIRED_AND_MISSING:** 実際にPREPARE承認が必要で、かつ現に不足している時だけ `record_approval_block` を呼ぶ。17対象 `BLOCKED_APPROVAL`、reason/lastSuccess/resume、original observation hash、App CASと独立鍵なしreadbackを要求する。
- **NOT_REQUIRED:** 認証済み実policyで承認不要の場合、`NOT_REQUIRED` の原本を保持する。`record_approval_block` を**呼ばず**、17対象の実際の正常/異常terminalと有限State CAS・revoke401・元ZIP実SHA・別Runner鍵なしreadbackを検証する。
- policyが不明・不一致・期限切れ・実source不在・State書込ACK不明の場合はPENDING/QUARANTINEDとし、どちらにも偽分類しない。形式的第二human承認や追加intentを要求しない。

共通の W10-B 元dispatch入力/ZIP有無の結合、W10-A controlled hostile、真正AppのPUT回数・原本Run/attempt1・17対象レポート・安全な再開条件は、どちらの分岐でも別途必要。**この契約補正は実原本の受入そのものではなく、85/94の正式チェックを変更しない。**

## v2.3 単一ユーザー移行

[単一ユーザー実行契約](issue311-single-user-v23.md) を将来判定に適用する。追加human intentを必要とせず、実在policyの承認不要を承認不足と偽らない。隔離された実GitHub統合試験と正式公開E2Eを分離する。85/94は不変。
