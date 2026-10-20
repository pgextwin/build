# pgextwin 第3弾 — 通常Chatへの実行引き継ぎ（2026-10-20）

あなたは通常Chat＋GitHub接続＋GitHub Actionsの継続担当です。初回WorkのGUI監査と認可不要の経路実装は実施済みです。以下を最新GitHub GETで確認し、成功済み工程を再実装・再実行せず、既存権限で進められる残工程を完了してください。

最初に読むもの：
- https://github.com/pgextwin/build/issues/75
- https://github.com/pgextwin/build/issues/141
- https://github.com/pgextwin/build/blob/main/docs/issue-75-work-chat-migration-20261020.md
- https://github.com/pgextwin/build/blob/main/docs/issue-75-chat-only-readonly-setup.md
- https://github.com/pgextwin/catalog/blob/main/docs/chat-public-release-request.md

既存成果（必ずGETで現在との差分を確認）：
- build PR #144 MERGED。共有read-only admission pin = 3df403c22aeb220ebc75632b25a25550a863519c。PR resolver Run39347165087、exact-main postmerge39347218488 SUCCESS。
- pgtap PR #4 MERGED、main 35e1f76a14eb4b962e3478d6359ccd39afc33aa5。PR Run39347365687、postmerge Run39348173513。
- pg_variables PR #3 MERGED、main 6f9547521df2de9df295d9d6fabd916ffcc63a73。PR Run39347374602、postmerge Run39348179617。
- pg_store_plans PR #4 MERGED、main f895d8e7d7b8d632eecbc2f74f2c22f659fae85c。PR Run39347384135、postmerge Run39348184925。
- 各PRのPG14〜18 15/15とApp15368必須summary SUCCESS。各実main observerもSUCCESS：actor/PR author/merged_by=ShutenOishi(User)、web-flowの検証済み署名、exact PR HEAD CI、実push発火を確認。NO_AUTHORIZATION / publication=DENY。全3件の親postmergeもattempt1 COMPLETED/SUCCESS、Windows15/15・native summary3/3 SUCCESS。
- Catalog PR #138 MERGED、main 004dbea7fd503ff615b152c76a98a8c519516450。PR Run39348250791のvalidateとWindows CLI smoke SUCCESS。postmerge Validate39348440990、NO_CATALOG_REQUEST bootstrap39348440982 SUCCESS。Python全391テストPASS。Website audit Run39348441311は旧CLI v0.3.1検証残存によりFAILUREで保持。後述の修正と新Runを使用。
- Website PR #38 MERGED、main54c06a57aa16d0687e9e2dc6710732db1ce2237c。64テストとPR Run39349060753、postmergeValidate39349133783 SUCCESS。CLI v0.3.2の実公開SHA256に監査を揃え、旧ラベルを修正し、再利用監査をjob.workflow_shaへ自己固定。Pages deploy39349133690、公開JA/EN・CLI v0.3.2/hash/verbose・14件70ZIP実監査39349133807 SUCCESS。
- Catalog PR #139でWebsite監査参照を上記full SHAへ固定。PR Run39349194003必須validate/Windows CLI SUCCESS、MERGED main c0dba8d3ee907b9f6602aafabd4545950e651ed2。exact-main Validate39349427737とcross-repo公開監査39349428002はいずれもattempt1 COMPLETED/SUCCESS。
- read-only経路はWork Dispatch不要。これは正式Publisherへの接続・公開認可の成立ではない。

維持する現状：
- 第3弾3拡張のcandidate enabled=true/manual-only、local Promotion enabled=false、中央正式Publisher allowlist=既存14件。
- 第3弾正式Release 0/3、実Catalog14件/70ZIP。CLI v0.3.2 verboseと厳格な14→17受入を保持。
- GO B/G4/G5 NO_GO、正式公開DENY。45 Git Blob証跡・既存否定テスト・create-only/復旧を再利用。
- 元GO A Run39008743613のFAILUREを変更・免除せず、過去の署名技術証拠だけで全体PASSへ加算しない。
- 本引き継ぎ指示は候補UPDATEでも個別PUBLISHでもない。架空認可JSON、タグ、Releaseを作らない。

次の仕事：
1. 上記Issue/報告/main/Runと未完了PRをGETで照合。既存実装・CI成功を再利用し、差分・失敗がある場合だけ原因を修正し、保護PR→必須CI→expected-head merge→postmerge→両Issue記録まで自律実行。
2. 正式公開の残障害は、認可済みの隔離実行環境、独立した短命・最小権限Writer、Reader/Signer/Writer認証分離、真正OIDC/証明書、実Publisherの署名済みpositive prewrite、永続復旧、および対象ごとのfresh effective rules。既存Catalog専用App、plpgsql_check専用read-only監査App、github.tokenを独立Writerへ読み替えない。GUIスクリーンショットを機械可読runtime証拠へ変換しない。
3. GitHub Actionsだけで既存安全条件を満たす隔離方式を優先して検証し、外部ホスト・新App・課金が不可欠とは未検証のまま断定しない。新たな権限、Secret/鍵設定、費用が必要なら、その特権工程だけ具体的な対象・最小権限・費用・検証条件を示して保留。通常Chatで進む作業をWorkへ戻さない。
4. 将来、利用者から明示的な候補UPDATEや対象限定PUBLISHが別途出た場合だけ、その指示の範囲を候補PR/full SHA/decision/Windows/audit/未使用tagへ厳格に束縛。共有read-only observerが通っても、本番Publisherの全ゲートが真正に成立するまで公開しない。
5. 実際の署名済み正式Release公開・独立検証後は、Catalogの既存署名検証を使う。通常Chatはcatalog-verify/<extension>-<tag>から、厳格な8キーの単一Catalog verification JSONを保護PRで追加できる。VERIFY_PUBLIC_RELEASEはPUBLISHとは別。実Release ID/全SHAを固定し、main pushのread-only検証が本当に成功した後だけverified-catalog-chat-request Artifactを取得。その原本レコードを通常の単一拡張Catalog PR（初回のみ許可済みindex更新）へ反映し、必須CI→マージ→Website日本語/英語・DL・SHA256・証跡を確認する。Dispatchや新Appは前提にしない。

禁止：成功済みRunの無意味な再実行、保護/必須CI緩和、第三者レビュー義務の新設、Secret/鍵/トークン出力、無承認課金、失敗免除、模擬GO、無人正式公開、個別PUBLISH省略、候補ZIPの正式Catalog収載。

終了時は正確なSHA/PR/Run URL、実証範囲と未実証境界、GO B/G4/G5、3拡張状態、Chat-only READY/NOT_READYを両Issueへ記録。正式公開の完全移行が未成立ならNOT_READYを明記する。
