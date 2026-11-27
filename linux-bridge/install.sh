#!/usr/bin/env bash
set -euo pipefail

# One-command installer for FF Linux Bridge v3 (Level 2)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/ff-linux-bridge"
SECRET_FILE="$CONFIG_DIR/rpc-secret.txt"
ENV_FILE="$CONFIG_DIR/bridge.env"
SYSTEMD_USER_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
PORT="${FF_LINUX_PORT:-39073}"
DEVICE_NAME="${FF_DEVICE_NAME:-$(hostname | tr -cd 'A-Za-z0-9_-' | cut -c1-64)}"

echo "[ff-linux-bridge] Checking Python 3.10+..."
python3 - <<'PY'
import sys
if sys.version_info < (3, 10):
    raise SystemExit(f"Python 3.10+ required, found {sys.version}")
print(f"  OK: Python {sys.version.split()[0]}")
PY

mkdir -p "$CONFIG_DIR"
chmod 700 "$CONFIG_DIR"

if [[ ! -s "$SECRET_FILE" ]]; then
  python3 -c 'import secrets; print(secrets.token_urlsafe(36))' > "$SECRET_FILE"
  chmod 600 "$SECRET_FILE"
  echo "[ff-linux-bridge] Generated RPC secret (mode 0600): $SECRET_FILE"
else
  chmod 600 "$SECRET_FILE"
  echo "[ff-linux-bridge] Reusing existing RPC secret: $SECRET_FILE"
fi

if [[ ! -f "$ENV_FILE" ]]; then
  cat > "$ENV_FILE" <<EOF
FF_LINUX_HOST=127.0.0.1
FF_LINUX_PORT=$PORT
FF_DEVICE_NAME=$DEVICE_NAME
FF_RPC_SECRET_FILE=$SECRET_FILE
# Optional: restrict file operations to a single workspace directory:
# FF_LINUX_WORKSPACE_ROOT=$HOME/workspace
# Optional: explicit Chromium/Chrome binary path:
# FF_LINUX_BROWSER_BIN=/usr/bin/chromium
EOF
  chmod 600 "$ENV_FILE"
  echo "[ff-linux-bridge] Created env file: $ENV_FILE"
fi

echo "[ff-linux-bridge] Checking Chromium/Chrome availability (optional for Level 2 browser ops)..."
if command -v chromium >/dev/null 2>&1 || command -v chromium-browser >/dev/null 2>&1 || command -v google-chrome >/dev/null 2>&1; then
  echo "  OK: Browser binary found in PATH."
else
  echo "  NOTE: No chromium/google-chrome found yet. Install with e.g. 'sudo apt install chromium' for browser_* ops."
fi

if command -v systemctl >/dev/null 2>&1 && systemctl --user status >/dev/null 2>&1; then
  mkdir -p "$SYSTEMD_USER_DIR"
  sed "s|__BRIDGE_DIR__|$SCRIPT_DIR|g; s|__ENV_FILE__|$ENV_FILE|g" \
    "$SCRIPT_DIR/systemd/ff-linux-bridge.service" > "$SYSTEMD_USER_DIR/ff-linux-bridge.service"
  systemctl --user daemon-reload
  systemctl --user enable --now ff-linux-bridge.service
  echo "[ff-linux-bridge] Installed & started systemd user service: ff-linux-bridge.service"
  echo "  Check status: systemctl --user status ff-linux-bridge.service"
  echo "  Health check: curl -s http://127.0.0.1:$PORT/health"
else
  echo "[ff-linux-bridge] systemd --user not active in this shell. Start manually with:"
  echo "  PYTHONPATH=\"$SCRIPT_DIR\" python3 -m ff_linux_bridge.server --secret-file \"$SECRET_FILE\" --port $PORT"
fi
