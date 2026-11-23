# R06の実ローカル原本集約と有限App CAS終端

この経路は非公開の検証専用である。署名、候補作成、Publisher、Release、Catalog、dispatch、cronの権限を持たない。GITHUB_TOKENは原本のGET専用、既存の専用Appはbuildのrequest-lifecycle stateに限定する。独立再読取ジョブにはAppキーを渡さない。

## 起動と原本

既存の中央PREPARE原本を同一cycleの17ローカル要求へ結合し、すべての子RunとWindows main push Runが終わってから、新しい`pgextwin-r06-original-child-join`要求を保護PRで追加する。要求は元中央Run/HEAD/Artifact/ZIP SHA256、17対象のlocal Run/request ID、AUDIT_ONLY、公開不可、最大30分の期限を固定する。各子の真正なpush/main/actor/attempt1、原本親commit、request-only保護マージと最新HEADのApp15368 PG14〜18/SummaryをGETで再検証する。

## Windows CI の代替証拠

- 合格条件は、同一リポジトリの保護 main にマージされた PR の最終 HEAD に対応する `windows.yml` の `pull_request` 第1試行が成功し、従来の PG14〜18 各ジョブと `Windows required summary` もすべて成功すること。共有 Build の入力記録と GitHub Commits で、PR の実 checkout と保護 main のマージツリー、解決済み Build SHA、固定の上流コミットを含む全ビルド入力が一致することを求める。通常の unsigned CI のみを対象とする。
- 記録は既存の `issue311-r06-child-join-original` に追加する。`windowsEvidence` に証拠種別、PR 番号、Run ID と試行番号、必須ジョブ結果を出力する。PR 証拠には実 checkout と main の SHA・tree、Build SHA、main の入力記録を取得した Run ID も含める。証拠に採用した PR Run は `windowsPrRunId`、push Run は `windowsPostmergeRunId` に記録する。`issue311-r06-child-join-independent-readback` は原本を再取得して一致した結果を残す。
- 既存の source／watchdog／独立 readback が同じ判定を実行する。GitHub PR・Commits・Actions の原本を GET し、PR と main push の matrix ジョブに残った入力記録を `scripts/windows-main-reuse.py` の照合で比較する。PR の証拠が欠けるか一致しない場合は、従来どおり push で必須ジョブすべての成功が必要になる。実際の main push 実行が監査対象の子には、要求に `"requireWindowsPostmerge": true` を付ける。pg_hint_plan #60 の PG17 復旧確認も push を必須とする。

実ビルドを必要とする PR は、対象 PR のマージ前に `metadata/main-reuse.json` の `requireOriginalPush` にリポジトリと PR 番号を登録し、caller が使用する `windows-ci` に反映する。同じ設定を R06 と main push の matrix 解決ステップが読む。通常の unsigned main push は、同一リポジトリの PR の第1試行、checkout、固定入力、共有 Build SHA、解決済みマトリクスの全 Windows ジョブと summary を照合できたときだけ Windows ジョブを省略できる。push Run には `PGEXTWIN_INPUT_RECORD` と、再利用した PR Run を示す `Windows CI reused from a successful PR` ステップサマリーが残る。

元のZIPはAPIで再取得し、provider digestと実圧縮バイトSHA256、単一エントリ、中央要求および17 SHAとの結合を独立検証する。実skipped jobには架空のreceiptを作らず、元jobのSKIPPEDとartifact不在を保存する。実failureはexit17、timeoutは原本workflowのtimeout-minutes:1、実stepのfailure、60秒以上の実時間とGitHub timeoutログを照合する。workflowの結論がfailureでも、実step timeoutをworkflow-level timed_outと偽称しない。

検証ステップの表示名は各原本Workflowの固定コマンドと`ff551bd2`完全SHA pinから対応付け、実ジョブの同名ステップSUCCESSを照合する。リポジトリ名から表示名を推測しない。原本のコマンド・pin・環境・表示名が変わった場合は拒否する。

## 制御したcompletion欠落と独立終端

Source workflowは実16件のcompletion bundleを作り、orafceの1件だけを意図的に含めない。このprovider ZIPからの欠落が今回の制御した障害であり、GitHub自然障害の発生を主張しない。別のpushで同時起動する有限watchdogはsourceを最大36回・5秒間隔で観測し、元ZIPの16件と独立した17子原本の再GETを照合する。orafceの元local要求の実期限後だけmissing completionを確定する。

Sourceが専用App CAS revision0をcreate-onlyで作成し、元source Runをrevision1へ結合する。Watchdogが原本を再照合してからrevision2へ終端化し、Git blob実バイトとstateを再GETする。正常NO_UPDATEを維持し、failure/skip/timeout/missing completionはQUARANTINEDにする。UPDATE_PRESENT_NOT_AUTHORIZEDも公開せずQUARANTINEDにする。成功と異常を同一の成功結果に読み替えない。

別ジョブはAppキーなしで中央・17子・Source/Terminal ZIPと永続stateを再取得する。元Git blobとrevision/対象/Run/権限の一致、永続terminal後のreplay拒否、PUTなしを確認する。source-kind/attempt2/期限の負例は実原本のコピーに対するメモリ内試験として明記し、実ネットワーク異常の証明と混同しない。App tokenは各Writerジョブで同じlive tokenを失効しHTTP401を確認する。

## 期限切れcycle

期限切れの既存PREPARE要求を延命・再実行しない。既存の実異常と成功Runは歴史原本として保全する。未完のcycleがある場合は、その欠落を未受入として記録し、新しい入力を固定する別の限定PREPARE要求を使う。この文書やoffline試験、コードPRのCIだけではR06統合受入にならない。
