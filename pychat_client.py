#!/usr/bin/env python3
"""Interactive GPG-encrypted chat client."""

from __future__ import annotations

import argparse
import asyncio
import sys

from gpg_utils import GPGError, decrypt_message, encrypt_message, ensure_gpg_available


async def _forward_stdin(writer: asyncio.StreamWriter, psk: str) -> None:
    loop = asyncio.get_running_loop()
    while True:
        line = await loop.run_in_executor(None, sys.stdin.readline)
        if not line:
            break
        plaintext = line.rstrip("\n")
        try:
            payload = encrypt_message(plaintext, psk)
        except GPGError as exc:
            print(f"Encryption failed: {exc}", file=sys.stderr)
            continue
        writer.write(f"{payload}\n".encode("utf-8"))
        await writer.drain()
        if line.strip() == "/quit":
            break


async def _forward_server(reader: asyncio.StreamReader, psk: str) -> None:
    while True:
        data = await reader.readline()
        if not data:
            print("\nServer closed the connection.")
            break
        payload = data.decode("utf-8", errors="ignore").rstrip("\r\n")
        if not payload:
            continue
        try:
            message = decrypt_message(payload, psk)
        except GPGError as exc:
            print(f"[decryption failed] {exc}", file=sys.stderr)
            continue
        print(message)


async def _run_client(
    host: str,
    port: int,
    psk: str,
) -> None:
    reader, writer = await asyncio.open_connection(host, port)
    await _perform_psk_handshake(reader, writer, psk)
    print(f"Connected to {host}:{port}. Press Ctrl+C or type /quit to exit.")

    stdin_task = asyncio.create_task(_forward_stdin(writer, psk))
    server_task = asyncio.create_task(_forward_server(reader, psk))

    done, pending = await asyncio.wait(
        {stdin_task, server_task},
        return_when=asyncio.FIRST_COMPLETED,
    )
    if server_task in pending:
        pending.remove(server_task)
        try:
            await asyncio.wait_for(server_task, timeout=5)
        except asyncio.TimeoutError:
            server_task.cancel()
            await asyncio.gather(server_task, return_exceptions=True)
    if stdin_task in pending:
        pending.remove(stdin_task)
        stdin_task.cancel()
        await asyncio.gather(stdin_task, return_exceptions=True)

    for task in (stdin_task, server_task):
        if task.cancelled():
            continue
        if exception := task.exception():
            raise exception

    writer.close()
    await writer.wait_closed()


async def _perform_psk_handshake(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, psk: str) -> None:
    prompt = await reader.readline()
    if not prompt:
        raise ConnectionError("Server closed connection before PSK prompt.")
    prompt_text = prompt.decode("utf-8", errors="ignore")
    print(prompt_text, end="")
    writer.write(f"{psk}\n".encode("utf-8"))
    await writer.drain()

    response = await reader.readline()
    if not response:
        raise ConnectionError("Server closed connection during PSK negotiation.")
    response_text = response.decode("utf-8", errors="ignore")
    print(response_text, end="")
    if "accepted" not in response_text.lower():
        raise PermissionError(response_text.strip() or "Pre-shared key rejected by server.")


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="GPG-encrypted asyncio chat client.")
    parser.add_argument("--host", default="127.0.0.1", help="Chat server host/IP (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5000, help="Chat server port (default: 5000)")
    parser.add_argument(
        "--psk",
        required=True,
        help="Pre-shared key announced by the server at startup.",
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    ensure_gpg_available()
    psk = args.psk.strip()
    if not psk:
        raise SystemExit("Pre-shared key cannot be empty.")
    try:
        asyncio.run(_run_client(args.host, args.port, psk))
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
    except PermissionError as exc:
        print(f"Authentication failed: {exc}", file=sys.stderr)
    except ConnectionError as exc:
        print(f"Connection error: {exc}", file=sys.stderr)


if __name__ == "__main__":
    main()
