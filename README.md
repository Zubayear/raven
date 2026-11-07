# Raven

Raven is a small mail server written in Zig.
It currently provides SMTP, IMAP, filesystem-backed storage, tenant-aware routing, and optional TLS.

![Zig](https://img.shields.io/badge/Zig-0.17-%23f7a41d)
![License](https://img.shields.io/badge/License-MIT-blue)
![TLS](https://img.shields.io/badge/TLS-OpenSSL-2d7ff9)

## Features

- SMTP receiving per RFC 5321: `SIZE`, `8BITMIME`, `ENHANCEDSTATUSCODES`, `PIPELINING`, enforced line and recipient limits
- IMAP4rev1 for real clients: literals, UIDs, full FETCH (ENVELOPE, BODYSTRUCTURE, sections), STORE, folders with special-use (Sent, Drafts, Trash, Junk), APPEND, COPY/MOVE, STATUS
- Maildir storage: atomic delivery, flags in file names, safe across restarts
- Multi-tenant routing: only hosted domains and known users are accepted (no open relay), with aliases and `user+tag` plus-addressing
- Accounts with argon2id password hashes (`raven passwd`)
- TLS via OpenSSL: SMTP `STARTTLS` and implicit-TLS SMTPS; authentication only over TLS
- Concurrent sessions with idle timeouts (SMTP 5 min, IMAP 30 min) and a connection cap
- Graceful shutdown on signal

## Requirements

- Zig 0.17
- OpenSSL 3 or newer, discoverable through `pkg-config`
  - macOS: `brew install openssl pkg-config`
  - Debian/Ubuntu: `apt install libssl-dev pkg-config`
- Python 3 and the `openssl` CLI for the smoke test

## Build

```bash
zig build
zig build test
```

## Run

```bash
zig build run -- \
  --listen-address 127.0.0.1 \
  --listen-port 5882 \
  --imap-port 1143 \
  --hostname localhost \
  --data-dir data
```

On first run, Raven creates its filesystem layout under `--data-dir`.

## TLS

Generate a short-lived local certificate:

```bash
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout key.pem -out cert.pem -days 1 \
  -subj "/CN=localhost"
```

Start Raven with TLS enabled:

```bash
zig build run -- \
  --listen-address 127.0.0.1 \
  --listen-port 5882 \
  --smtps-port 5465 \
  --imap-port 1143 \
  --hostname localhost \
  --data-dir data \
  --tls-cert cert.pem \
  --tls-key key.pem
```

With a certificate configured:

- the SMTP port offers `STARTTLS` (RFC 3207); `AUTH` is only offered and accepted after it
- `--smtps-port` (usually 465) serves SMTP over implicit TLS
- the IMAP port uses implicit TLS (IMAP `STARTTLS` is tracked in #19)

`--tls-cert` accepts a full chain (e.g. Let's Encrypt `fullchain.pem`).
For local testing without TLS, `--allow-plaintext-auth` lets `AUTH` through on a plaintext connection; never use it in production.

Connect with `openssl s_client`:

```bash
openssl s_client -starttls smtp -connect 127.0.0.1:5882 -quiet -CAfile cert.pem
openssl s_client -connect 127.0.0.1:5465 -quiet -CAfile cert.pem
openssl s_client -connect 127.0.0.1:1143 -quiet -CAfile cert.pem
```

## Configuration

Raven accepts configuration from:

- CLI flags
- Environment variables
- `key = value` config files

Common options:

- `--config`
- `--listen-address`
- `--listen-port`
- `--imap-port`
- `--hostname`
- `--data-dir`
- `--tls-cert`
- `--tls-key`
- `--max-connections` (per listener, default 100)
- `--max-message-size` (bytes, default 26214400; advertised with SMTP `SIZE`)
- `--smtps-port` (implicit-TLS SMTP; off by default)
- `--allow-plaintext-auth` (testing only)

Environment variables use the `RAVEN_` prefix:

- `RAVEN_CONFIG`
- `RAVEN_LISTEN_ADDRESS`
- `RAVEN_LISTEN_PORT`
- `RAVEN_IMAP_PORT`
- `RAVEN_HOSTNAME`
- `RAVEN_DATA_DIR`
- `RAVEN_TLS_CERT`
- `RAVEN_TLS_KEY`
- `RAVEN_MAX_CONNECTIONS`
- `RAVEN_MAX_MESSAGE_SIZE`
- `RAVEN_SMTPS_PORT`
- `RAVEN_ALLOW_PLAINTEXT_AUTH`

Example config file:

```text
listen_address = 127.0.0.1
listen_port = 5882
imap_port = 1143
hostname = localhost
data_dir = data
tls_cert_file = cert.pem
tls_key_file = key.pem
max_connections = 100
max_message_size = 26214400
```

## Accounts

Host a domain by adding its tenant to `data/tenants/index.txt` (read at startup):

```text
tenant acme example.com
```

Create an account; `raven passwd` reads the password from stdin (without echo on a terminal) and prints an argon2id hash:

```bash
mkdir -p data/tenants/acme/domains/example.com
echo "alice $(zig-out/bin/raven passwd)" >> data/tenants/acme/domains/example.com/accounts.txt
echo "sales alice" >> data/tenants/acme/domains/example.com/aliases.txt   # optional alias
```

Accounts and aliases are read on every login and delivery, so no restart is needed. Only argon2id hashes are accepted.

## Data layout

```text
data/tenants/index.txt                                  tenant <name> <domain>...
data/tenants/<tenant>/domains/<domain>/accounts.txt     <user> <argon2id hash>
data/tenants/<tenant>/domains/<domain>/aliases.txt      <alias> <user>
data/tenants/<tenant>/domains/<domain>/users/<user>/Maildir/{tmp,new,cur}   INBOX
data/tenants/<tenant>/domains/<domain>/users/<user>/Maildir/.Sent/...       folders (Maildir++)
```

Each domain belongs to exactly one tenant. Domains and local parts match case-insensitively; mail for `user+tag@domain` is delivered to `user`.

Mailboxes are standard Maildirs: delivery writes to `tmp/`, syncs, then renames into `new/`; IMAP moves mail to `cur/` and stores flags in the file name (`:2,FS`), so tools like mutt can read them directly.

## Testing

- `zig build test` runs the unit tests, including SMTP and IMAP session transcripts.
- `zig build smoke` starts the real binary (plain and TLS), delivers a message over SMTP, and reads it back over IMAP.

## Architecture

- `src/main.zig` wires configuration, startup, TLS, and shutdown.
- `src/server.zig` handles SMTP sessions and inbound delivery.
- `src/imap.zig` handles mailbox access and IMAP commands.
- `src/storage.zig` manages the filesystem layout and message files.
- `src/config.zig` loads CLI, environment, and config-file settings.
- `src/conn.zig` runs the accept loop and gives each connection socket I/O with an idle timeout.
- `src/tls.zig` wraps OpenSSL for server-side TLS on top of that socket I/O.
- `src/address.zig` validates mail addresses before they reach the filesystem.
- `src/tenant_index.zig`, `src/alias_index.zig`, and `src/account_index.zig` provide routing and identity lookup.

## Contributing

- Keep changes small and focused.
- Run `zig build` and `zig build test` before opening a PR.
- If you touch startup, TLS, or storage behavior, add or update tests.
- Prefer minimal changes that preserve the current architecture.

## License

MIT
