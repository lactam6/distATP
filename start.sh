#!/bin/bash
# financeATP - ワンクリック起動スクリプト (Mac/Linux)
# 使用方法: ./start.sh

set -e

# --------------------------------------------------
# 設定
# --------------------------------------------------
MAX_RETRIES=30        # 最大待機回数 (30回 * 3秒 = 90秒)
HEALTH_URL="http://localhost:3000/health"
# --------------------------------------------------

echo ""
echo "============================================"
echo "  financeATP 起動中..."
echo "============================================"
echo ""

# 0. 必要なコマンドのチェック (curl)
if ! command -v curl &> /dev/null; then
    echo "[エラー] 'curl' コマンドが見つかりません。インストールしてください。"
    exit 1
fi

# 1. Docker コマンドの判定 (docker-compose vs docker compose)
if command -v docker-compose &> /dev/null; then
    DOCKER_COMPOSE_CMD="docker-compose"
elif docker compose version &> /dev/null; then
    DOCKER_COMPOSE_CMD="docker compose"
else
    echo "[エラー] Docker Compose が見つかりません。"
    exit 1
fi

# 2. Docker デーモンの確認 (権限チェック含む)
if ! docker info &> /dev/null 2>&1; then
    echo "[エラー] Docker が起動していないか、権限がありません。"
    echo "Linuxの場合: 'sudo' が必要か、ユーザーを 'docker' グループに追加してください。"
    exit 1
fi

# 3. コンテナを起動
echo "[1/3] コンテナを起動しています... (使用コマンド: $DOCKER_COMPOSE_CMD)"
$DOCKER_COMPOSE_CMD up -d

# 4. 起動待機 (タイムアウト付き)
echo "[2/3] サービスの起動を待機しています..."
sleep 5 # 初期待機

echo "[3/3] 接続を確認しています..."
count=0
until curl -s "$HEALTH_URL" > /dev/null 2>&1; do
    count=$((count+1))
    if [ "$count" -ge "$MAX_RETRIES" ]; then
        echo ""
        echo "[エラー] タイムアウトしました。コンテナログを確認してください。"
        echo "確認コマンド: $DOCKER_COMPOSE_CMD logs"
        exit 1
    fi
    echo "  まだ起動中... ($count/$MAX_RETRIES)"
    sleep 3
done

echo ""
echo "============================================"
echo "  起動完了！"
echo "============================================"
echo ""
echo "  API: http://localhost:3000"
echo ""
echo "  停止するには: $DOCKER_COMPOSE_CMD down"
echo ""
