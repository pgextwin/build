# 単一ユーザー実行契約 v2.3

## 2026-10-31 単一ユーザー移行（今回の明示指示を適用）

本節は上記の任意の「別human intent」「第二人間」「追加Work操作」条件を置き換える。ShutenOishi本人の一回のChat要求を、認証済みGitHub操作で固定する。同じrequestIdの許可scope内のPREPARE・Issue調停・Draft候補・native CI・検証・記録は追加human要求なしで進める。実際のGitHub actor/author/merged_by/Runは独立GETし、Botを人間と呼ばない。

**実行可能工程:** immutable request（対象・scope・requestId・source SHA・expected HEAD・expiry・replay key）→hostile試験→保護PR→必須App15368 CI→期待HEAD保護マージ→original postmerge→必要な実ZIP/State独立GET。既存成功Runを再実行しない。
**受入条件:** 上記原本が同じ要求へ結合し、無権限・scope外・改ざん・期限切れ・replayをfail closed。追加の人間操作なしで許可範囲が完走した場合のみ本機能の完了。正式85/94は変更しない。
**原本証跡:** PR/HEAD、真正author/merged_by/actor、Run/attempt1、request blob、必要なZIP実SHA256/CRC/署名/Attestation、State revision、独立readback URLを記録。
**外部条件:** GitHub自身の実在する保護/承認規則、サービスquota、真正upstream、特定候補のPUBLISHのみ。有限timeout/retry・単発write/不明応答GET-only・最小権限は維持する。任意件数上限は理由と適用箇所を監査し、無条件に無制限化しない。
**再開条件:** 具体的な未成立の外部事実、または未実装adapter/検証工程を示す。不在監査だけを反復しない。

非公開統合試験は実在するupstream tag/full commitを使い、隔離資源・実GitHub API・実workflowで行う。新stableの偽造は不可。CONTROLLED_INTEGRATIONと将来真正stableのPUBLIC_E2Eを別判定し、正式契約の判定変更は保護PRのマージ・postmerge後に適用する。旧scheduleは代替受入まで維持。

R10は実policyと実承認状態を確認し、存在しないPREPARE承認不足を捏造しない。policyが承認を要求しない場合は「不足なし」を原本付きで記録し、任意の第二人間待ちを作らず、適用判定の契約改訂へ進む。実在する不足時のみBLOCKED_APPROVALを実証する。

本要求は非公開実装・契約変更の認可。PUBLISH_DENY/runtimeEnabled=falseを維持。正式公開は実在する特定候補への本人一回の明示PUBLISHと全既存公開ゲートが必要。


## 管理画面の確認原本

2026-10-31 JST。build classic branch rule 84707241: PR必須=true、Require approvals=false、Code Owners=false、most recent push approval=false、required checks=true、up-to-date=true、resolver/App15368、admin bypass不可=true。変更なし。
PREPARE Environment 25744043853: Required reviewers=false、Wait timer=false、selected branch=mainのみ。変更なし。API branch protectionは403であり、上記は認証済み管理UI観測。

## 適用と未完了

この契約は保護マージ・original postmerge後にv2.2の任意の人的待機条件に優先する。94枝番・85受入・9未受入は不変。R10の実policy非該当は自動受入せず、policy原本と適用判定を残す。非公開統合試験はR11機能の証拠にできるが、R09公開E2Eの証拠にはならない。

実装は既存orafce event-sourceの単一modeをscope配列/同一sourceへ接続し、exact SHA/expiry/replayの検証と実GitHub原本を追加する必要がある。現行runtimeを契約文だけで有効化しない。
