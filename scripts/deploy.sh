#!/usr/bin/env bash
# Deploy Bluewink to your server: build locally, rsync dist/, restart service.
#
# Usage:
#   ./scripts/deploy.sh                          # uses BLUEWINK_DEPLOY_TARGET
#   BLUEWINK_DEPLOY_TARGET=root@1.2.3.4 ./scripts/deploy.sh
#
# Target format: [user@]host[:port][/remote/path]
#   Defaults: user=root, port=22, path=/opt/egmp-alternate-app
#
# The target is intentionally NOT hardcoded — this is a public repo.

set -euo pipefail

TARGET="${BLUEWINK_DEPLOY_TARGET:-}"
if [ -z "$TARGET" ]; then
  echo "Error: set BLUEWINK_DEPLOY_TARGET, e.g.:"
  echo "  BLUEWINK_DEPLOY_TARGET=root@1.2.3.4 ./scripts/deploy.sh"
  exit 1
fi

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

echo "==> Building web bundle (with /bil/kona base path)..."
npx expo export --platform web

echo "==> Syncing dist/ to ${SSH_TARGET}:${REMOTE_PATH}/dist/ ..."
rsync -avz --delete -e "ssh -p $SSH_PORT" dist/ "${SSH_TARGET}:${REMOTE_PATH}/dist/"

echo "==> Restarting bluewink service..."
ssh -p "$SSH_PORT" "$SSH_TARGET" "sudo systemctl restart bluewink && systemctl is-active bluewink"

echo ""
echo "Deployed. Verify: https://your-domain.dk/bil/kona"
