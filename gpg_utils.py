"""Lightweight helpers for invoking GnuPG symmetrically."""

from __future__ import annotations

import base64
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Final, Optional


class GPGError(RuntimeError):
    """Raised when encryption or decryption fails."""


GPG_COMMAND: Final = "gpg"
_GPG_HOME_CACHE: Optional[str] = None


def _gpg_env() -> dict[str, str]:
    env = os.environ.copy()
    gpg_home = _resolve_gpg_home()
    if gpg_home:
        env["GNUPGHOME"] = gpg_home
    return env


def _resolve_gpg_home() -> Optional[str]:
    global _GPG_HOME_CACHE
    if _GPG_HOME_CACHE is not None:
        return _GPG_HOME_CACHE

    candidates: list[Path] = []
    env_home = os.environ.get("GNUPGHOME")
    if env_home:
        candidates.append(Path(env_home).expanduser())
    candidates.append(Path.home() / ".gnupg")
    candidates.append(Path.home() / ".pychat_gnupg")
    candidates.append(Path(tempfile.gettempdir()) / "pychat_gnupg")

    for candidate in candidates:
        try:
            candidate.mkdir(mode=0o700, parents=True, exist_ok=True)
        except Exception:
            continue
        if _is_writable_dir(candidate):
            _GPG_HOME_CACHE = str(candidate)
            return _GPG_HOME_CACHE

    _GPG_HOME_CACHE = None
    return None


def _is_writable_dir(path: Path) -> bool:
    if not path.is_dir():
        return False
    if not os.access(path, os.R_OK | os.W_OK | os.X_OK):
        return False
    try:
        with tempfile.NamedTemporaryFile(dir=path):
            pass
    except Exception:
        return False
    return True


def ensure_gpg_available() -> None:
    if shutil.which(GPG_COMMAND) is None:
        raise SystemExit("gpg executable not found. Please install GnuPG to continue.")
    if _resolve_gpg_home() is None:
        raise SystemExit(
            "Unable to find a writable GPG home directory. "
            "Set GNUPGHOME to a writable location and try again."
        )


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
        env=_gpg_env(),
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
        env=_gpg_env(),
        check=False,
    )
    if proc.returncode != 0:
        raise GPGError(proc.stderr.decode("utf-8", errors="ignore").strip() or "GPG decryption failed.")
    return proc.stdout.decode("utf-8")
