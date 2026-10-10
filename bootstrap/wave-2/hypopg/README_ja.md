# HypoPG Windows x64 技術パイロット

PostgreSQL 15〜18の標準Windows x64環境向けに、HypoPG 1.4.3を上流commit `21d5461ad1868434cc47d9aa656d7afc2b24c464`からビルドする非公式プロジェクトです。

仮想インデックスの作成、EXPLAINによる利用確認、物理インデックスが存在しないことの確認、resetによる元の実行計画への復帰を機能試験で検証します。

**未検証の実装候補です。** PostgreSQL 15〜18のWindows CIと成果物検証を通過するまで、正式なReleaseやCatalog登録は行いません。
