#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"

HOST=${HOST:-127.0.0.1}
PORT=${PORT:-54321}
PYTHON_BIN=${PYTHON_BIN:-python3}
LOG_DIR=${LOG_DIR:-$PROJECT_ROOT/tmp}

mkdir -p "$LOG_DIR"

echo "[smoke] Ensuring prerequisites..."
"$SCRIPT_DIR/bootstrap.sh"

pushd "$PROJECT_ROOT" > /dev/null

echo "[smoke] Starting server in background..."
$PYTHON_BIN pychat_server.py \
  --host "$HOST" \
  --port "$PORT" \
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
SESSION_KEY=""
for _ in {1..40}; do
  if [[ -z "$SESSION_KEY" && -f "$LOG_DIR/server.log" ]]; then
    SESSION_KEY=$(
      {
        grep -oE "Session pre-shared key: [0-9a-fA-F]+" "$LOG_DIR/server.log" 2>/dev/null | tail -n 1 | awk '{print $NF}'
      } || true
    )
  fi
  if grep -q "Server listening" "$LOG_DIR/server.log" 2>/dev/null; then
    READY=1
    if [[ -n "$SESSION_KEY" ]]; then
      break
    fi
  fi
  if ! kill -0 "$SERVER_PID" >/dev/null 2>&1; then
    echo "[smoke] Server process exited unexpectedly."
    tail -n 50 "$LOG_DIR/server.log" || true
    exit 1
  fi
  sleep 0.5
done

if [[ "$READY" -ne 1 || -z "$SESSION_KEY" ]]; then
  echo "[smoke] Timed out waiting for server readiness."
  tail -n 50 "$LOG_DIR/server.log" || true
  exit 1
fi

echo "[smoke] Using $HOST:$PORT with session key $SESSION_KEY"

echo "[smoke] Running scripted client interaction..."
printf "Alice\nHello from the smoke test!\n/quit\n" | \
  $PYTHON_BIN pychat_client.py \
    --host "$HOST" \
    --port "$PORT" \
    --psk "$SESSION_KEY"

echo "[smoke] Client finished, stopping server..."
kill "$SERVER_PID" >/dev/null 2>&1 || true
wait "$SERVER_PID" >/dev/null 2>&1 || true

echo "[smoke] Smoke test completed successfully."
