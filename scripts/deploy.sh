#!/usr/bin/env bash
# 将本地代码同步到远程服务器，在服务器上构建镜像并滚动重启。
#
# 用法:
#   ./scripts/deploy.sh              # 同步 + 构建 + 重启
#   ./scripts/deploy.sh --sync-only  # 仅同步代码
#   ./scripts/deploy.sh --restart    # 不重建，仅重启容器
#
# 可用环境变量（也可写在项目根目录 deploy.env，已被 gitignore）:
#   DEPLOY_HOST=38.58.59.228
#   DEPLOY_USER=root
#   DEPLOY_PATH=/opt/grok2api
#   DEPLOY_PORT=22
#   GROK2API_PORT=8000

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ -f "$ROOT_DIR/deploy.env" ]]; then
  # shellcheck disable=SC1091
  source "$ROOT_DIR/deploy.env"
fi

DEPLOY_HOST="${DEPLOY_HOST:-38.58.59.228}"
DEPLOY_USER="${DEPLOY_USER:-root}"
DEPLOY_PATH="${DEPLOY_PATH:-/opt/grok2api}"
DEPLOY_PORT="${DEPLOY_PORT:-22}"
GROK2API_PORT="${GROK2API_PORT:-8000}"
REMOTE="${DEPLOY_USER}@${DEPLOY_HOST}"

SSH=(ssh -p "$DEPLOY_PORT" -o StrictHostKeyChecking=accept-new "$REMOTE")
RSYNC_SSH="ssh -p ${DEPLOY_PORT} -o StrictHostKeyChecking=accept-new"

MODE="full"
for arg in "$@"; do
  case "$arg" in
    --sync-only) MODE="sync" ;;
    --restart) MODE="restart" ;;
    -h|--help)
      sed -n '2,16p' "$0"
      exit 0
      ;;
    *)
      echo "未知参数: $arg" >&2
      exit 1
      ;;
  esac
done

log() { printf '\n==> %s\n' "$*"; }

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "缺少命令: $1" >&2
    exit 1
  }
}

require_cmd rsync
require_cmd ssh

sync_code() {
  log "同步代码 -> ${REMOTE}:${DEPLOY_PATH}"
  "${SSH[@]}" "mkdir -p '${DEPLOY_PATH}' && chmod 700 '${DEPLOY_PATH}'"

  rsync -az --delete \
    -e "$RSYNC_SSH" \
    --exclude '.git/' \
    --exclude '.github/' \
    --exclude '.DS_Store' \
    --exclude '.idea/' \
    --exclude '.vscode/' \
    --exclude 'deploy.env' \
    --exclude 'config.yaml' \
    --exclude 'config.local.yaml' \
    --exclude 'config.*.local.yaml' \
    --exclude '.env' \
    --exclude '.env.*' \
    --exclude 'data/' \
    --exclude 'backend/data/' \
    --exclude 'backend/grok2api' \
    --exclude 'backend/coverage.out' \
    --exclude '.gocache/' \
    --exclude '.gocache-*/' \
    --exclude 'frontend/node_modules/' \
    --exclude 'frontend/dist/' \
    --exclude 'frontend/.cache/' \
    --exclude '.pnpm-store/' \
    --exclude 'release/' \
    --exclude '.tmp/' \
    --exclude 'tmp/' \
    --exclude '*.log' \
    --exclude '*.test' \
    --exclude '*.coverprofile' \
    ./ "${REMOTE}:${DEPLOY_PATH}/"

  # 生产 compose：强制用本地构建镜像，避免误拉官方 latest 覆盖本地改动
  "${SSH[@]}" "cat > '${DEPLOY_PATH}/docker-compose.yml' <<'EOF'
name: grok2api

services:
  grok2api:
    container_name: grok2api
    build:
      context: .
      dockerfile: Dockerfile
    image: grok2api:local
    ports:
      - \"\${GROK2API_PORT:-8000}:8000\"
    environment:
      TZ: Asia/Shanghai
    volumes:
      - ./config.yaml:/run/grok2api/config.yaml:ro
      - grok2api-data:/app/data
    restart: unless-stopped
    init: true
    stop_grace_period: 30s
    security_opt:
      - no-new-privileges:true

volumes:
  grok2api-data:
EOF"

  # 首次部署：若远端没有 config.yaml，从 example 生成并提示改密钥
  "${SSH[@]}" bash -s -- "$DEPLOY_PATH" <<'REMOTE_CFG'
set -euo pipefail
DEPLOY_PATH="$1"
if [[ ! -f "${DEPLOY_PATH}/config.yaml" ]]; then
  if [[ -f "${DEPLOY_PATH}/config.example.yaml" ]]; then
    cp "${DEPLOY_PATH}/config.example.yaml" "${DEPLOY_PATH}/config.yaml"
    chmod 600 "${DEPLOY_PATH}/config.yaml"
    echo "已从 config.example.yaml 生成 config.yaml，请先编辑 secrets/bootstrapAdmin 后再启动。"
    exit 2
  fi
  echo "远端缺少 config.yaml 与 config.example.yaml" >&2
  exit 1
fi
chmod 600 "${DEPLOY_PATH}/config.yaml"
REMOTE_CFG
}

ensure_swap() {
  # 3~4G 内存机器构建 Node+Go 多阶段镜像容易 OOM，没有 swap 时临时补 2G
  "${SSH[@]}" bash -s <<'REMOTE_SWAP'
set -euo pipefail
if free -b | awk '/^Mem:/{exit !($2 < 5000000000)}'; then
  if [[ ! -f /swapfile ]] && ! swapon --show | grep -q .; then
    echo "内存偏小，创建临时 2G swap 以支撑镜像构建..."
    fallocate -l 2G /swapfile || dd if=/dev/zero of=/swapfile bs=1M count=2048
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
  elif [[ -f /swapfile ]] && ! swapon --show | grep -q /swapfile; then
    swapon /swapfile || true
  fi
fi
free -h
REMOTE_SWAP
}

remote_build_and_up() {
  log "远端构建并启动"
  ensure_swap
  "${SSH[@]}" bash -s -- "$DEPLOY_PATH" "$GROK2API_PORT" <<'REMOTE_BUILD'
set -euo pipefail
DEPLOY_PATH="$1"
export GROK2API_PORT="$2"
cd "$DEPLOY_PATH"

if ! command -v docker >/dev/null 2>&1; then
  echo "远端未安装 docker" >&2
  exit 1
fi

export DOCKER_BUILDKIT=1
export COMPOSE_DOCKER_CLI_BUILD=1

echo "构建镜像 grok2api:local ..."
docker compose build --pull

echo "启动容器..."
docker compose up -d --remove-orphans

echo "等待健康检查..."
ok=0
for i in $(seq 1 60); do
  status="$(docker inspect --format='{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' grok2api 2>/dev/null || true)"
  if [[ "$status" == "healthy" ]] || [[ "$status" == "running" ]]; then
    if curl -fsS "http://127.0.0.1:${GROK2API_PORT}/healthz" >/dev/null 2>&1; then
      ok=1
      break
    fi
  fi
  sleep 2
done

docker compose ps
docker compose logs --tail 40 grok2api

if [[ "$ok" -ne 1 ]]; then
  echo "健康检查未通过，请查看上方日志" >&2
  exit 1
fi

echo "发布成功: http://$(hostname -I | awk '{print $1}'):${GROK2API_PORT}/"
REMOTE_BUILD
}

remote_restart() {
  log "远端仅重启容器"
  "${SSH[@]}" bash -s -- "$DEPLOY_PATH" "$GROK2API_PORT" <<'REMOTE_RESTART'
set -euo pipefail
cd "$1"
export GROK2API_PORT="$2"
docker compose up -d
sleep 2
curl -fsS "http://127.0.0.1:${GROK2API_PORT}/healthz"
echo
docker compose ps
REMOTE_RESTART
}

case "$MODE" in
  sync)
    sync_code
    log "仅同步完成（未构建）"
    ;;
  restart)
    remote_restart
    ;;
  full)
    sync_code
    remote_build_and_up
    ;;
esac

log "完成"
echo "  地址: http://${DEPLOY_HOST}:${GROK2API_PORT}"
echo "  远端: ${REMOTE}:${DEPLOY_PATH}"
echo "  说明: 远端 config.yaml 不会被覆盖，改配置请 SSH 编辑后 ./scripts/deploy.sh --restart"
