#!/usr/bin/env python3
"""TLS-enabled multi-client chat server."""

from __future__ import annotations

import argparse
import asyncio
import hmac
import logging
import signal
import ssl
from pathlib import Path
from typing import Optional

MAX_MESSAGE_LENGTH = 2048
MAX_NICKNAME_LENGTH = 32


class ClientSession:
    """Lightweight container for a connected client."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.reader = reader
        self.writer = writer
        self.address = writer.get_extra_info("peername")
        self.name: Optional[str] = None

    def __hash__(self) -> int:  # pragma: no cover - relying on object identity
        return id(self)

    def label(self) -> str:
        if self.name:
            return f"{self.name} {self.address}"
        return str(self.address)


class ChatServer:
    """Holds shared state and per-client coroutines."""

    def __init__(self, psk: str) -> None:
        self.clients: set[ClientSession] = set()
        self._lock = asyncio.Lock()
        self._psk = psk

    async def register(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        client = ClientSession(reader, writer)
        logging.info("New connection from %s", client.address)
        async with self._lock:
            self.clients.add(client)

        try:
            await self._authenticate(client)
            await self._send_line(client, "Welcome to the secure chat server.")
            client.name = await self._negotiate_name(client)
            await self._send_line(
                client,
                "Type messages and press enter to chat. Use /quit to leave. Change nickname anytime with /name NEW_NAME.",
            )
            await self.broadcast(f"* {client.name} joined the chat *", skip=client)
            await self._handle_messages(client)
        except ConnectionError:
            logging.info("Client %s disconnected during handshake", client.address)
        except PermissionError:
            logging.warning("Client %s failed PSK authentication", client.address)
        except asyncio.CancelledError:
            raise
        except Exception:
            logging.exception("Unhandled error while serving %s", client.label())
        finally:
            await self._drop_client(client)

    async def _authenticate(self, client: ClientSession) -> None:
        await self._send_line(client, "Pre-shared key required:")
        data = await client.reader.readline()
        if not data:
            raise ConnectionError("Client disconnected before providing a pre-shared key.")
        provided = data.decode("utf-8", errors="ignore").strip()
        if not hmac.compare_digest(provided, self._psk):
            await self._send_line(client, "Invalid pre-shared key. Disconnecting.")
            raise PermissionError("Invalid pre-shared key.")
        await self._send_line(client, "Pre-shared key accepted.")

    async def _handle_messages(self, client: ClientSession) -> None:
        assert client.name, "Client should have a nickname before messaging"
        while True:
            data = await client.reader.readline()
            if not data:
                logging.info("Client %s closed the connection", client.label())
                break

            message = data.decode("utf-8", errors="ignore").rstrip("\r\n")
            if not message:
                continue
            if len(message) > MAX_MESSAGE_LENGTH:
                await self._send_line(client, f"Message too long (max {MAX_MESSAGE_LENGTH} characters).")
                continue
            if message == "/quit":
                await self._send_line(client, "Goodbye!")
                break
            if message.startswith("/name"):
                parts = message.split(maxsplit=1)
                if len(parts) == 1 or not parts[1].strip():
                    await self._send_line(client, "Usage: /name NEW_NICKNAME")
                    continue
                new_name = parts[1].strip()
                old_name = client.name
                error = await self._set_nickname(client, new_name)
                if error:
                    await self._send_line(client, f"Name change failed: {error}")
                else:
                    assert old_name
                    await self.broadcast(f"* {old_name} is now known as {client.name} *")
                continue

            await self.broadcast(f"[{client.name}] {message}", skip=client)

    async def _negotiate_name(self, client: ClientSession) -> str:
        await self._send_line(client, "Choose a nickname:")
        while True:
            data = await client.reader.readline()
            if not data:
                raise ConnectionError("Client disconnected before selecting a nickname.")
            desired = data.decode("utf-8", errors="ignore").strip()
            error = await self._set_nickname(client, desired)
            if error:
                await self._send_line(client, f"{error} Try again:")
                continue
            assert client.name
            return client.name

    async def broadcast(self, message: str, *, skip: Optional[ClientSession] = None) -> None:
        recipients = [c for c in self.clients if c is not skip]
        if not recipients:
            return

        # Normalize newline handling so every client gets one per message.
        payload = message if message.endswith("\n") else f"{message}\n"
        data = payload.encode("utf-8")
        for client in recipients:
            try:
                client.writer.write(data)
            except ConnectionResetError:
                logging.warning("Dropping client %s due to write failure", client.label())
        await asyncio.gather(*(c.writer.drain() for c in recipients), return_exceptions=True)

    async def _send_line(self, client: ClientSession, message: str) -> None:
        payload = message if message.endswith("\n") else f"{message}\n"
        client.writer.write(payload.encode("utf-8"))
        await client.writer.drain()

    async def _drop_client(self, client: ClientSession) -> None:
        remove = False
        async with self._lock:
            if client in self.clients:
                self.clients.remove(client)
                remove = True

        if client.writer.can_write_eof():
            try:
                client.writer.write_eof()
            except Exception:
                pass
        try:
            client.writer.close()
            await client.writer.wait_closed()
        except Exception:
            pass
        if remove and client.name:
            await self.broadcast(f"* {client.name} left the chat *", skip=client)

    async def close_all(self) -> None:
        for client in list(self.clients):
            try:
                await self._send_line(client, "Server is shutting down.")
            except Exception:
                pass
            await self._drop_client(client)

    async def _set_nickname(self, client: ClientSession, desired: str) -> Optional[str]:
        desired = desired.strip()
        if not desired:
            return "Nickname cannot be empty."
        if len(desired) > MAX_NICKNAME_LENGTH:
            return f"Nickname must be <= {MAX_NICKNAME_LENGTH} characters."
        if client.name and desired == client.name:
            return "You already have that nickname."

        async with self._lock:
            if any(other is not client and other.name == desired for other in self.clients):
                return "That nickname is already in use."
            client.name = desired
        return None


async def _run_server(host: str, port: int, certfile: str, keyfile: str, psk: str) -> None:
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
    ssl_context.load_cert_chain(certfile, keyfile=keyfile)

    chat_server = ChatServer(psk)
    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()

    def _request_shutdown() -> None:
        if not stop_event.is_set():
            stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _request_shutdown)
        except NotImplementedError:
            # Windows falls back to default signal behavior.
            signal.signal(sig, lambda *_: _request_shutdown())

    server = await asyncio.start_server(chat_server.register, host, port, ssl=ssl_context)
    sockets = ", ".join(str(sock.getsockname()) for sock in server.sockets or [])
    logging.info("Server listening on %s", sockets)

    async with server:
        await stop_event.wait()
        logging.info("Shutdown requested, closing server...")
    await chat_server.close_all()
    logging.info("Server stopped.")


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Secure asyncio chat server.")
    parser.add_argument("--host", default="127.0.0.1", help="Host/IP to bind (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5000, help="TCP port to bind (default: 5000)")
    parser.add_argument("--certfile", required=True, help="Path to PEM-encoded TLS certificate")
    parser.add_argument("--keyfile", required=True, help="Path to PEM-encoded private key")
    parser.add_argument(
        "--psk",
        help="Pre-shared key required of all clients (best supplied via env var).",
    )
    parser.add_argument(
        "--psk-file",
        help="Path to a file containing the pre-shared key (alternative to --psk).",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Verbosity of log output",
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    psk = _resolve_psk(args.psk, args.psk_file)
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(message)s",
    )
    try:
        asyncio.run(_run_server(args.host, args.port, args.certfile, args.keyfile, psk))
    except KeyboardInterrupt:
        pass


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
