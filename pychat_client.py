#!/usr/bin/env python3
"""Interactive TLS-enabled chat client."""

from __future__ import annotations

import argparse
import asyncio
import ssl
import sys
from pathlib import Path
from typing import Optional


async def _forward_stdin(writer: asyncio.StreamWriter) -> None:
    loop = asyncio.get_running_loop()
    while True:
        line = await loop.run_in_executor(None, sys.stdin.readline)
        if not line:
            break
        writer.write(line.encode("utf-8"))
        await writer.drain()
        if line.strip() == "/quit":
            break


async def _forward_server(reader: asyncio.StreamReader) -> None:
    while True:
        data = await reader.readline()
        if not data:
            print("\nServer closed the connection.")
            break
        print(data.decode("utf-8", errors="ignore"), end="")


def _build_ssl_context(cafile: str | None, insecure: bool) -> ssl.SSLContext:
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=cafile)
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


async def _run_client(
    host: str,
    port: int,
    server_hostname: str,
    cafile: str | None,
    insecure: bool,
    psk: str,
) -> None:
    ssl_context = _build_ssl_context(cafile, insecure)
    reader, writer = await asyncio.open_connection(host, port, ssl=ssl_context, server_hostname=server_hostname)
    await _perform_psk_handshake(reader, writer, psk)
    print(f"Connected to {host}:{port}. Press Ctrl+C or type /quit to exit.")

    stdin_task = asyncio.create_task(_forward_stdin(writer))
    server_task = asyncio.create_task(_forward_server(reader))

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
    parser = argparse.ArgumentParser(description="Secure asyncio chat client.")
    parser.add_argument("--host", default="127.0.0.1", help="Chat server host/IP (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5000, help="Chat server port (default: 5000)")
    parser.add_argument(
        "--server-hostname",
        default=None,
        help="Override TLS SNI/hostname verification (defaults to --host).",
    )
    parser.add_argument(
        "--cafile",
        default=None,
        help="Path to a PEM file containing trusted CA certificates (required for self-signed certs).",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable certificate verification (NOT recommended).",
    )
    parser.add_argument(
        "--psk",
        help="Pre-shared key expected by the server (best supplied via env var).",
    )
    parser.add_argument(
        "--psk-file",
        help="Path to a file containing the pre-shared key (alternative to --psk).",
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    server_hostname = args.server_hostname or args.host
    if args.insecure:
        print("Warning: running in insecure mode; TLS certificates are not verified.", file=sys.stderr)
    try:
        psk = _resolve_psk(args.psk, args.psk_file)
        asyncio.run(_run_client(args.host, args.port, server_hostname, args.cafile, args.insecure, psk))
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
    except PermissionError as exc:
        print(f"Authentication failed: {exc}", file=sys.stderr)
    except ConnectionError as exc:
        print(f"Connection error: {exc}", file=sys.stderr)


def _resolve_psk(psk: Optional[str], psk_file: Optional[str]) -> str:
    if psk:
        value = psk.strip()
        if not value:
            raise SystemExit("Pre-shared key provided via --psk cannot be empty.")
        return value
    if psk_file:
        path = Path(psk_file)
        try:
            value = path.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise SystemExit(f"Unable to read pre-shared key file: {exc}") from exc
        if not value:
            raise SystemExit("Pre-shared key file is empty.")
        return value
    raise SystemExit("A pre-shared key is required. Provide --psk or --psk-file.")


if __name__ == "__main__":
    main()
