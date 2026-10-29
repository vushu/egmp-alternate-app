#!/usr/bin/env bash
# Deploy Bluewink to your server: build locally, rsync dist/, restart service.
#
# Usage:
#   ./scripts/deploy.sh                          # uses BLUEWINK_DEPLOY_TARGET
#   BLUEWINK_DEPLOY_TARGET=root@1.2.3.4 ./scripts/deploy.sh
#
# Env vars:
#   BLUEWINK_DEPLOY_TARGET  [user@]host[:port][/remote/path]
#                           Defaults: user=root, port=22, path=/opt/egmp-alternate-app
#   BLUEWINK_BASE_PATH      Web base path to build with (default: /)
#                           Must match what the server runs with.
#
# Neither value is hardcoded — this is a public repo.

set -euo pipefail

TARGET="${BLUEWINK_DEPLOY_TARGET:-}"
if [ -z "$TARGET" ]; then
  echo "Error: set BLUEWINK_DEPLOY_TARGET, e.g.:"
  echo "  BLUEWINK_DEPLOY_TARGET=root@1.2.3.4 ./scripts/deploy.sh"
  exit 1
fi

BASE_PATH="${BLUEWINK_BASE_PATH:-/}"

# Parse [user@]host[:port][/path]
REMOTE_PATH="/opt/egmp-alternate-app"
SSH_PORT=22
if [[ "$TARGET" == */* ]]; then
  REMOTE_PATH="${TARGET#*/}"
  TARGET="${TARGET%%/*}"
fi
if [[ "$TARGET" == *:* ]]; then
  SSH_PORT="${TARGET##*:}"
  TARGET="${TARGET%:*}"
fi
SSH_TARGET="$TARGET"

echo "==> Building web bundle (base path: $BASE_PATH)..."
BLUEWINK_BASE_PATH="$BASE_PATH" npx expo export --platform web

echo "==> Syncing dist/ to ${SSH_TARGET}:${REMOTE_PATH}/dist/ ..."
rsync -avz --delete -e "ssh -p $SSH_PORT" dist/ "${SSH_TARGET}:${REMOTE_PATH}/dist/"

echo "==> Restarting bluewink service (with BLUEWINK_BASE_PATH=$BASE_PATH)..."
ssh -p "$SSH_PORT" "$SSH_TARGET" "sudo systemctl restart bluewink && systemctl is-active bluewink"

echo ""
echo "Deployed with base path: $BASE_PATH"
