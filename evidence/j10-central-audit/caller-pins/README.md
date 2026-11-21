# J10 中央監査の caller pin 更新

更新先の build SHA は `7788623fa49e56b1301090bea4f023ea86405657`。`pgextwin` の既定ブランチを読み取り、対象は全26リポジトリの `.github/workflows/update-watch.yml` であることを確認した。対象は build の `BUILD` かつ `candidateEnabled=true` の登録と一致した。

各パッチは次の3行を更新する。

- `operator-update-auto.yml` とその `detector_sha` の2行。従来の SHA は両方とも `73ab3248aa6e15fc150d86f1e118ca1cc036e020`。スキャンのコード照合には `.github/workflows/fleet-upstream-watch.yml` も含まれる。
- `automatic-postmerge-audit-readonly.yml` の1行。従来の SHA は hypopg が `dbf7365ae702ddc19e094205f8343ec555125d9c`、他の25件が `9ec4dde0b6defabc10cf3527c06cb69c13e5a7ff`。

orafce、pg_hint_plan、pg_ivm、plpgsql_check の `requalify-merged-candidate-signed.yml@12e9c809d963c82735e23680ac1838693a6de356` は、現在の保護 build/main のスキャンを取得し、ローカル署名意図の検証で `validate_merged()` を直接呼ぶ。

build 実装 SHA が GitHub で参照できる段階で、各対象リポジトリのレビュー用ブランチに同名のパッチを適用する。例は hypopg の場合。

```sh
git apply --check /path/to/build/evidence/j10-central-audit/caller-pins/hypopg.patch
git apply /path/to/build/evidence/j10-central-audit/caller-pins/hypopg.patch
```

全26件で、GitHub の下表の元 blob に対する `git apply --check --index` と適用後の3行差分をローカルで検証した。

| リポジトリ | 更新前の workflow blob |
| --- | --- |
| hypopg | `7dbee67f61fd74e33c1de66e4944473fe1d8978a` |
| odbc_fdw | `bea45d9536ed9970ec4583468bd6d915155d6d55` |
| orafce | `2573fbdf1582a7fa9bc2d56cf316d956e9519d08` |
| pg_bigm | `e714057561d5778b06e2cbecf053954388fd9f46` |
| pg_cron | `ae10d897b212f87c42a5bb24e1798aff387d0e50` |
| pg_failover_slots | `aacfcababa24dcd6d5b3c847c633439aa65e2062` |
| pg_hint_plan | `00dce5bf4b2d5ad07d57b54ea742cba989ca1fe9` |
| pg_ivm | `276c279d8d6f7d5f2d956aa577dc0ea469904aa0` |
| pg_partman | `e1066335c2bc7341add10849fb1e983aaf72c4ea` |
| pg_permissions | `f756ad7c2ff862c456d2c69f07a35224898fc393` |
| pg_profile | `255034d05c7c0b289911f6b05b7a502bb857608f` |
| pg_qualstats | `f67229ca01dd780464fdd89810277b8df9ea1674` |
| pg_repack | `f9916ea4e70f416fddd827f31c0c3da522482d40` |
| pg_show_plans | `f46a757aa0f01d42258bbdc65462c2ec3b831436` |
| pg_squeeze | `aacfcababa24dcd6d5b3c847c633439aa65e2062` |
| pg_stat_monitor | `bc50731bca9622074ac6906d35f372f4a4514189` |
| pg_store_plans | `f07356a2eba273537614f0d78a9d8b993b45df02` |
| pg_track_settings | `f756ad7c2ff862c456d2c69f07a35224898fc393` |
| pg_variables | `83eeb0d7652b57dd8b8469c5b2d03dc37f84fcf6` |
| pg_wait_sampling | `255034d05c7c0b289911f6b05b7a502bb857608f` |
| pgaudit | `d66feec9f42961fbc62241ef25d55d09e6332163` |
| pgtap | `29612fc43efe056003a7c61f2310c669642ccc49` |
| pldebugger | `df4de0c8001dd87064cff7929df7a445a2d0f842` |
| plpgsql_check | `8318610e59d1280a18ba4ab8ef0c9950001df917` |
| set_user | `f9916ea4e70f416fddd827f31c0c3da522482d40` |
| wal2json | `e1066335c2bc7341add10849fb1e983aaf72c4ea` |
