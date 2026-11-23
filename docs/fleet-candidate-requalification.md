# 中央候補生成と署名付き再評価の移行

## pg_ivm の候補生成

`fleet-upstream-watch.yml` の `readonly-fleet` が公開する同一 Run の artifact ID を候補選定に渡す。選定は初回の真正な `schedule` のみで動き、GitHub API で中央 Run、成功済みの `readonly-fleet`、保護された中央 main とスキャンのコード blob、鮮度と全台帳の網羅性、対象の保護 main を照合する。更新なしは選定ジョブの要約に記録する。更新を検出したパイロットだけ対象コミットを checkout し、既存の候補計画で安定タグとコミットを解決する。ジョブの成否は、監視結果や他のジョブを参照する既存の監査に混入させない。

書き込みの有効化には、専用 `pgextwin-fleet-candidate` GitHub App を対象拡張のみにインストールし、対象ごとの短命トークンに `Contents: write`、`Pull requests: write`、`Actions: write` を付与する必要がある。保護された main に限定する Build Environment `fleet-candidate-writer` に `fleet_candidate_app_private_key` を保管し、Build の `PGEXTWIN_FLEET_CANDIDATE_APP_CLIENT_ID` を設定する。ブランチ保護の迂回許可は不要。既存の Publisher、Catalog、汎用接続のトークンはこの用途と権限範囲が異なる。

既存の native PR 検証、マージ観測、原本監査には `github-actions[bot]` で作者を固定する箇所がある。専用 App が作った PR は App の bot が作者になる。稼働前に、対象リポジトリ・App の数値 ID と bot の数値 ID、中央 Run/attempt と候補決定、PR の正確な head と出所を既存の利用側で照合する切替をレビューする。既存の作者と証拠に対する検査も維持する。PR の作者名やマーカーだけで新経路を認可できるようにはしない。

writer は新規 PR に候補決定のコピーを含め、作成直後に GitHub API から PR を読み直す。対象リポジトリの数値 ID、App と bot の数値 ID、中央 Run/attempt と候補決定 artifact ID、対象の保護 main SHA、正確な head と manifest blob を記録する。PR 番号を加えた正規化 JSON を `candidate-origin-<extension>-<sha256>` として同じ Run に保存する。既存 PR の再利用時は出所を新しい Run に付け替えない。

| 合格条件 | 証拠成果物 | 評価経路 |
| --- | --- | --- |
| 登録された対象と App/bot の数値 ID が一致し、中央の保護 main 由来の初回 schedule でスキャンと対象 writer が成功している | GitHub の App、PR、Run/attempt、ジョブとステップのメタデータ | native PR 監査、中央 native 回復、マージ観測、原本決定の照合、fleet 状況表示で同一の verifier を実行する |
| 同一 Run の候補決定と出所 artifact が一意かつ有効で、writer の実行中に作られた PR と一致する | `candidate-decision-<extension>`、`candidate-origin-<extension>-<sha256>`、PR 本文の証拠コピーと GitHub の PR 番号 | verifier は PR から計算した SHA-256 を中央の artifact 名と照合し、Run・SHA・時刻も確認する。拡張の読み取りジョブは公開 REST メタデータを使う |
| 候補 head は保護 main を唯一の親とし、変更した manifest blob のタグ・版・コミットが決定と一致する。マージ済みの場合はマージコミットの親と manifest blob も一致する | GitHub の保護ブランチ、対象 PR、コミット、head の `config/extension.json` | verifier の合格後も各監査は従来の Windows 必須チェックと原本照合を行う。native とマージ観測の成果物は App の出所識別子も記録する |

pg_ivm の `update-watch.yml` は `verify-native-pr-candidate.yml` と `automatic-postmerge-audit-readonly.yml` をそれぞれ固定 SHA で呼ぶ。Build のレビュー済み変更を取り込んだ SHA にこの 2 参照を移し、真正な schedule の後段を観測してから切り替える。既存の中央 native 回復スケジュールは Build の保護 main から直接動く。

以上の設定と監査側の準備を確認してから `PGEXTWIN_FLEET_CANDIDATE_WRITES=enabled` を設定する。設定待ちの検出は候補決定を保存し、書き込み延期を要約に記録する。中央で管理する対象は `scripts/fleet-candidate.py` の `PILOTS`。中央 writer は元の保護 main を親とする候補ブランチを使う。既存の拡張ローカル bot 候補や、ベース同期で変化したブランチがある場合は旧経路で解決してから切り替える。

旧ローカルの `operator-update-auto.yml` はスキャンのコード blob を固定 SHA と照合する。旧経路を維持するリポジトリでは、Build のスキャン更新を含む互換 pin への移行が必要になる。B2 着地後にも旧 pin での blob 不一致が発生している。

## 署名付き再評価の中央移行案

対象は `metadata/merged-candidate-requalification.json` に登録済みの orafce、pg_hint_plan、pg_ivm、plpgsql_check。起点を拡張の毎時 Run から Build の真正な定期実行へ移す。候補生成とはジョブを分け、古い候補の再評価に使う入力は、登録済みの元 PR と同一スキャンの最新状態を満たす行とする。

1. 専用の読み取りジョブで、新規候補の有無と独立に、中央 schedule の Run/attempt、成功したスキャン artifact、対象の現在の保護 main と `up-to-date` 行を照合する。対象が登録済み原本条件を満たさない場合は、その対象をスキップした理由を記録する。
2. `verify-merged-candidate-requalification.py` が要求する、元の bot PR、マージ SHA・祖先関係、manifest の Git blob と SHA ピン、元の native `pull_request` Run/attempt、App 15368 の正確な head の必須チェックを引き続き照合する。リポジトリ、対象ソース SHA と manifest blob、中央 Run/attempt、元 PR/Run を含む用途限定の intent を生成する。読み取りジョブに署名権限は付けない。
3. 署名を移す別 PR では、中央の保護ワークフローから対象リポジトリの正確な保護 SHA を取得し、検証済み intent から対象を再確認する。source repository/SHA を中央ワークフローの実行 repository/SHA と別に記録する。既存の署名と監査はローカル `schedule` の repository・workflow・SHA に依存するため、中央 OIDC の issuer、`repository_id`、`job_workflow_ref`、保護 ref と対象ソースの両方を検証する新しい出所種別の設計・承認が先に必要になる。中央の環境変数を拡張側の値に置き換える手法ではこの証明が成立しない。
4. 二つの独立ジョブで署名 ZIP/SPDX/Grype を改めてダウンロードし、対象の PG 系列、ソース・ライセンス原本と配布バイト、Sigstore の出所を照合する。二つの証跡が一致した時点で再評価完了とする。Publisher が受理する出所種別、admission、Release 作成権限は従来の設定を維持する。
5. まず fixture と読み取り Run で、誤ったトリガー、古いスキャン、対象 main の移動、候補の head と manifest の取り違え、署名者の相違が処理を止めることを確認する。将来の署名実証は別途承認を得て行う。対象ごとに移行を確認してから拡張側の `merged_candidate_scheduled_oidc` とその起動経路を外す。候補生成のみを先に切り替えるときはローカルの `schedule` と `authorize` から再評価につながる条件を維持する。
