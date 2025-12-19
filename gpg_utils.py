"""Lightweight helpers for invoking GnuPG symmetrically."""

from __future__ import annotations

import base64
import shutil
import subprocess
from typing import Final


class GPGError(RuntimeError):
    """Raised when encryption or decryption fails."""


GPG_COMMAND: Final = "gpg"


def ensure_gpg_available() -> None:
    if shutil.which(GPG_COMMAND) is None:
        raise SystemExit("gpg executable not found. Please install GnuPG to continue.")


def encrypt_message(message: str, passphrase: str) -> str:
    """Encrypts plaintext with GPG symmetric AES256 and returns base64."""
    ensure_gpg_available()
    proc = subprocess.run(
        [
            GPG_COMMAND,
            "--batch",
            "--yes",
            "--symmetric",
            "--cipher-algo",
            "AES256",
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            passphrase,
        ],
        input=message.encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        raise GPGError(proc.stderr.decode("utf-8", errors="ignore").strip() or "GPG encryption failed.")
    return base64.b64encode(proc.stdout).decode("ascii")


def decrypt_message(token: str, passphrase: str) -> str:
    """Decrypts base64-wrapped GPG ciphertext."""
    ensure_gpg_available()
    try:
        payload = base64.b64decode(token.encode("ascii"), validate=True)
    except Exception as exc:
        raise GPGError("Invalid ciphertext encoding.") from exc

    proc = subprocess.run(
        [
            GPG_COMMAND,
            "--batch",
            "--yes",
            "--decrypt",
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            passphrase,
        ],
        input=payload,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        raise GPGError(proc.stderr.decode("utf-8", errors="ignore").strip() or "GPG decryption failed.")
    return proc.stdout.decode("utf-8")
