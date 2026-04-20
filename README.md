# Raven

Raven is a small mail server written in Zig.
It currently provides SMTP, IMAP, filesystem-backed storage, tenant-aware routing, and optional TLS.

![Zig](https://img.shields.io/badge/Zig-0.16-%23f7a41d)
![License](https://img.shields.io/badge/License-MIT-blue)
![TLS](https://img.shields.io/badge/TLS-OpenSSL-2d7ff9)

## Features

- SMTP listener with inbound delivery
- IMAP listener with mailbox access
- Filesystem-backed mail storage
- Tenant/domain routing and alias lookup
- Account authentication from local storage
- Optional TLS via OpenSSL
- Graceful shutdown on signal

## Requirements

- Zig 0.16
- OpenSSL 3
- macOS build support currently expects Homebrew OpenSSL at `/opt/homebrew/opt/openssl@3`

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
  --imap-port 1143 \
  --hostname localhost \
  --data-dir data \
  --tls-cert cert.pem \
  --tls-key key.pem
```

Connect with `openssl s_client`:

```bash
openssl s_client -connect 127.0.0.1:5882 -quiet -CAfile cert.pem
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

Environment variables use the `RAVEN_` prefix:

- `RAVEN_CONFIG`
- `RAVEN_LISTEN_ADDRESS`
- `RAVEN_LISTEN_PORT`
- `RAVEN_IMAP_PORT`
- `RAVEN_HOSTNAME`
- `RAVEN_DATA_DIR`
- `RAVEN_TLS_CERT`
- `RAVEN_TLS_KEY`

Example config file:

```text
listen_address = 127.0.0.1
listen_port = 5882
imap_port = 1143
hostname = localhost
data_dir = data
tls_cert_file = cert.pem
tls_key_file = key.pem
```

## Testing

- `zig build test` runs the unit test suite.
- For a manual smoke test, connect to the SMTP and IMAP ports and verify the greeting banners.

## Architecture

- `src/main.zig` wires configuration, startup, TLS, and shutdown.
- `src/server.zig` handles SMTP sessions and inbound delivery.
- `src/imap.zig` handles mailbox access and IMAP commands.
- `src/storage.zig` manages the filesystem layout and message files.
- `src/config.zig` loads CLI, environment, and config-file settings.
- `src/tls.zig` wraps OpenSSL for server-side TLS.
- `src/tenant_index.zig`, `src/alias_index.zig`, and `src/account_index.zig` provide routing and identity lookup.

## Contributing

- Keep changes small and focused.
- Run `zig build` and `zig build test` before opening a PR.
- If you touch startup, TLS, or storage behavior, add or update tests.
- Prefer minimal changes that preserve the current architecture.

## License

MIT
