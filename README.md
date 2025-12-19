## Secure Python Chat

This repository contains a lightweight asyncio chat server and matching client secured with GnuPG-based symmetric encryption. The server generates a fresh pre-shared key at startup, displays it on the console, and every connected client encrypts/decrypts their traffic with that key. Multiple users can connect simultaneously, exchange messages (including `/name NEW_NAME` for renames), and disconnect safely.

### Requirements

- Python 3.11+
- `gpg` available on the system `PATH`

### Running the Server

```bash
python pychat_server.py --host 0.0.0.0 --port 5000
```

- On launch, the server prints a line like `Session pre-shared key: abc123...`. Copy/paste it to your users.
- Use `--psk YOUR_KEY` if you prefer to reuse a known key instead of generating a new one each run.
- Press `Ctrl+C` to shut it down gracefully.

### Running the Client

```bash
python pychat_client.py --host YOUR_SERVER_IP --port 5000 --psk COPIED_KEY
```

- Each client is prompted for a nickname, and can later type `/name NEW_NICKNAME` to change it.
- Type `/quit` to exit cleanly.
- The `--psk` flag is required and must match the key printed by the server.

### Pre-Shared Key Details

- Keys default to a fresh random 32-hex-character value every time the server starts.
- Pass `--psk VALUE` when starting the server to supply your own static key (helpful for automation).
- Clients always receive the key out-of-band—share it however you prefer (copy/paste, secure messenger, etc.).

### Automation Helpers

- `scripts/bootstrap.sh` simply verifies that `gpg` is installed before you start hacking.
- `scripts/smoke_test.sh` launches the server, captures the announced key, runs a scripted client session, and tears everything down again.

### Features

- GPG-encrypted message payloads over simple TCP sockets—no TLS certificates required.
- Server-enforced nickname uniqueness plus `/name` to change identities mid-session.
- Graceful shutdown of all sockets and a `scripts/smoke_test.sh` check to ensure things keep working.

### Development Notes

All networking and encryption glue lives in `pychat_server.py`, `pychat_client.py`, and `gpg_utils.py`. Feel free to extend them with authentication, persistence, or richer chat commands.
