#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"

CERT_DIR=${CERT_DIR:-$PROJECT_ROOT/certs}
SECRETS_DIR=${SECRETS_DIR:-$PROJECT_ROOT/secrets}
CERT_FILE=${CERT_FILE:-$CERT_DIR/server.crt}
KEY_FILE=${KEY_FILE:-$CERT_DIR/server.key}
PSK_FILE=${PSK_FILE:-$SECRETS_DIR/chat.psk}
HOST=${HOST:-127.0.0.1}
PORT=${PORT:-54321}
PYTHON_BIN=${PYTHON_BIN:-python3}
LOG_DIR=${LOG_DIR:-$PROJECT_ROOT/tmp}

mkdir -p "$LOG_DIR"

echo "[smoke] Ensuring TLS assets and PSK exist..."
"$SCRIPT_DIR/bootstrap.sh"

pushd "$PROJECT_ROOT" > /dev/null

echo "[smoke] Starting server in background..."
$PYTHON_BIN server.py \
  --host "$HOST" \
  --port "$PORT" \
  --certfile "$CERT_FILE" \
  --keyfile "$KEY_FILE" \
  --psk-file "$PSK_FILE" \
  > "$LOG_DIR/server.log" 2>&1 &
SERVER_PID=$!

cleanup() {
  if kill -0 "$SERVER_PID" >/dev/null 2>&1; then
    kill "$SERVER_PID" >/dev/null 2>&1 || true
    wait "$SERVER_PID" >/dev/null 2>&1 || true
  fi
  popd > /dev/null
}
trap cleanup EXIT

READY=0
for _ in {1..20}; do
  if grep -q "Server listening" "$LOG_DIR/server.log" 2>/dev/null; then
    READY=1
    break
  fi
  if ! kill -0 "$SERVER_PID" >/dev/null 2>&1; then
    echo "[smoke] Server process exited unexpectedly."
    tail -n 50 "$LOG_DIR/server.log" || true
    exit 1
  fi
  sleep 0.5
done

if [[ "$READY" -ne 1 ]]; then
  echo "[smoke] Timed out waiting for server readiness."
  tail -n 50 "$LOG_DIR/server.log" || true
  exit 1
fi

ACTUAL_PORT=$($PYTHON_BIN - "$LOG_DIR/server.log" <<'PY'
import re
import sys

pattern = re.compile(r"\('([^']+)', (\d+)\)")
log_path = sys.argv[1]
with open(log_path, encoding="utf-8") as fh:
    lines = fh.readlines()
for line in reversed(lines):
    if "Server listening" not in line:
        continue
    match = pattern.search(line)
    if match:
        print(match.group(2))
        break
else:
    raise SystemExit("Unable to determine server port from log.")
PY
)
echo "[smoke] Using $HOST:$ACTUAL_PORT"

echo "[smoke] Running scripted client interaction..."
printf "Alice\nHello from the smoke test!\n/quit\n" | \
  $PYTHON_BIN client.py \
    --host "$HOST" \
    --port "$ACTUAL_PORT" \
    --cafile "$CERT_FILE" \
    --psk-file "$PSK_FILE" \
    --server-hostname localhost

echo "[smoke] Client finished, stopping server..."
kill "$SERVER_PID" >/dev/null 2>&1 || true
wait "$SERVER_PID" >/dev/null 2>&1 || true

echo "[smoke] Smoke test completed successfully."
