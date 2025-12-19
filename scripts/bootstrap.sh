#!/usr/bin/env bash
set -euo pipefail

CERT_DIR=${CERT_DIR:-certs}
SECRETS_DIR=${SECRETS_DIR:-secrets}
CERT_FILE=${CERT_FILE:-$CERT_DIR/server.crt}
KEY_FILE=${KEY_FILE:-$CERT_DIR/server.key}
PSK_FILE=${PSK_FILE:-$SECRETS_DIR/chat.psk}
COMMON_NAME=${COMMON_NAME:-localhost}

mkdir -p "$CERT_DIR"
install -m 700 -d "$SECRETS_DIR"

if [[ ! -f "$CERT_FILE" || ! -f "$KEY_FILE" ]]; then
  echo "[bootstrap] Generating self-signed certificate for CN=$COMMON_NAME"
  openssl req -x509 -newkey rsa:4096 \
    -keyout "$KEY_FILE" \
    -out "$CERT_FILE" \
    -days 365 \
    -nodes \
    -subj "/CN=$COMMON_NAME"
else
  echo "[bootstrap] Certificate already exists, skipping."
fi

if [[ ! -f "$PSK_FILE" ]]; then
  echo "[bootstrap] Generating random pre-shared key at $PSK_FILE"
  openssl rand -hex 32 > "$PSK_FILE"
  chmod 600 "$PSK_FILE"
else
  echo "[bootstrap] Pre-shared key already exists, skipping."
fi

echo "[bootstrap] TLS and PSK assets ready."
