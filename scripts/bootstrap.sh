#!/usr/bin/env bash
set -euo pipefail

echo "[bootstrap] Checking for GnuPG..."
if ! command -v gpg >/dev/null 2>&1; then
  echo "[bootstrap] gpg executable not found. Please install GnuPG." >&2
  exit 1
fi

gpg --version | head -n 1
echo "[bootstrap] GnuPG is available. No further setup required."
