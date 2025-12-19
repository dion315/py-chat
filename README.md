## Secure Python Chat

This repository contains a lightweight TLS-enabled chat server and matching client. Multiple users can connect simultaneously, exchange messages, and disconnect safely. Everything is implemented with Python's `asyncio` and `ssl` modules—no external dependencies are required.

### Requirements

- Python 3.11+ (tested with CPython, but PyPy should also work)
- A TLS certificate and private key pair hosted on the server

### Generating a Self-Signed Certificate (development only)

You can use OpenSSL to generate a throwaway certificate for local testing:

```bash
mkdir -p certs
openssl req -x509 -newkey rsa:4096 -keyout certs/server.key -out certs/server.crt -days 365 -nodes -subj "/CN=localhost"
```

Copy the resulting `server.crt` to any client machines so they can verify the server's identity.

### Running the Server

```bash
python pychat_server.py --host 0.0.0.0 --port 5000 \
  --certfile certs/server.crt --keyfile certs/server.key \
  --psk-file secrets/chat.psk
```

By default, the server listens on `127.0.0.1:5000`. Press `Ctrl+C` to shut it down gracefully.

### Running the Client

```bash
python pychat_client.py --host YOUR_SERVER_IP --port 5000 \
  --cafile certs/server.crt --psk-file secrets/chat.psk
```

- Each client is prompted for a nickname.
- Type `/quit` to exit cleanly.
- Provide the same pre-shared key (`--psk` or `--psk-file`) that the server expects.
- Use `--server-hostname` if the TLS certificate's common name differs from the `--host` value (e.g., connecting via IP).
- Development-only: pass `--insecure` to skip certificate verification, though this sacrifices the security benefits of TLS.
- Change your nickname later with `/name NEW_NICKNAME`.

### Pre-Shared Key

- Set a strong random value (for example `openssl rand -hex 32 > secrets/chat.psk`) and point both server and client to it.
- You can pass the key inline with `--psk`, but supplying it via a file (or environment variable that you read yourself) is more secure because it avoids exposing the secret in process listings.

### Automation Helpers

- `scripts/bootstrap.sh` generates a self-signed certificate and random PSK under `certs/` and `secrets/`.
- `scripts/smoke_test.sh` launches the server and a scripted client to verify TLS + PSK end-to-end.

### Features

- TLS-secured sockets to prevent eavesdropping and tampering.
- Broadcast of join/leave events and chat messages to all connected peers.
- Basic keep-alive logic and graceful shutdown handling.

### Development Notes

The networking logic lives directly in `pychat_server.py` and `pychat_client.py`. Feel free to extend them with persistence, authentication, or richer chat commands.
