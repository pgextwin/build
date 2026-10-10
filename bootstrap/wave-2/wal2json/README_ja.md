# wal2json Windows x64（pgextwin技術パイロット）

PostgreSQL 15〜18向けの論理デコード出力プラグインwal2json 2.6を上流SHAに固定し、MSVCでビルドする非公式実装です。

本プラグインはCREATE EXTENSIONではなく、論理レプリケーションスロットから利用します。INSERT・UPDATE・DELETEをコミットし、出力されたJSONを検証する機能テストを実施します。

**PostgreSQL 18は必須の互換性判定ゲートです。** さらにPostgreSQL 18.6などのセキュリティ更新後は、`output_plugin_libraries`の許可リストに`wal2json`を追加する必要があります。

専用リポジトリのWindows CIでPG15〜18がすべて成功するまで、正式リリースとCatalog登録は禁止します。
