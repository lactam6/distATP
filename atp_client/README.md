# ATP Client

FinanceATP API のGUIクライアントアプリケーション

## インストール

```bash
# パッケージをインストール
pip install .

# または開発モード（編集可能インストール）
pip install -e .
```

## 起動方法

### コマンドで起動

```bash
atp-client
```

### Pythonモジュールとして起動

```bash
python -m atp_client
```

### 直接実行

```bash
python atp_client.py
```

## 依存関係

- Python 3.8以上
- requests

## 機能

- API接続設定 (Base URL, API Key)
- ヘルスチェック
- ユーザー管理 (作成・取得・更新・削除)
- 残高照会
- 送金実行
- ATP発行 (Mint)
- ATP焼却 (Burn)
- イベントログ参照
- APIキー管理

## ライセンス

MIT
