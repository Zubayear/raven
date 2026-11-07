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
- TLS via OpenSSL: `STARTTLS` for SMTP and IMAP, implicit-TLS SMTPS/IMAPS; passwords only over TLS
- Outbound delivery for authenticated users: durable queue, MX lookup, opportunistic STARTTLS, DKIM signing, retries with backoff for 5 days, DSN bounces
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
  --imaps-port 5993 \
  --hostname localhost \
  --data-dir data \
  --tls-cert cert.pem \
  --tls-key key.pem
```

With a certificate configured:

- the SMTP port offers `STARTTLS` (RFC 3207); `AUTH` is only offered and accepted after it
- `--smtps-port` (usually 465) serves SMTP over implicit TLS
- the IMAP port offers `STARTTLS` and advertises `LOGINDISABLED` until it is used
- `--imaps-port` (usually 993) serves IMAP over implicit TLS

`--tls-cert` accepts a full chain (e.g. Let's Encrypt `fullchain.pem`).
For local testing without TLS, `--allow-plaintext-auth` accepts SMTP `AUTH` and IMAP `LOGIN`/`AUTHENTICATE` on plaintext connections; never use it in production.

Connect with `openssl s_client`:

```bash
openssl s_client -starttls smtp -connect 127.0.0.1:5882 -quiet -CAfile cert.pem
openssl s_client -connect 127.0.0.1:5465 -quiet -CAfile cert.pem
openssl s_client -starttls imap -connect 127.0.0.1:1143 -quiet -CAfile cert.pem
openssl s_client -connect 127.0.0.1:5993 -quiet -CAfile cert.pem
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
- `--imaps-port` (implicit-TLS IMAP; off by default)
- `--submission-port` (mail submission, RFC 6409; AUTH required; off by default)
- `--relay-host`, `--relay-port` (send outbound mail through a smarthost instead of MX lookup)
- `--log-level` (`err`, `warn`, `info` or `debug`; default `info`)
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
- `RAVEN_IMAPS_PORT`
- `RAVEN_SUBMISSION_PORT`
- `RAVEN_RELAY_HOST`, `RAVEN_RELAY_PORT`
- `RAVEN_LOG_LEVEL`
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

## Logging

Raven logs one line per event to stderr, tagged with its level and protocol. Lines about a connection carry its number and the client's address, so `grep '#42 '` follows one session:

```text
info(smtp): listening on 127.0.0.1:5882
debug(smtp): #1 127.0.0.1:63625: connected
warning(smtp): #1 127.0.0.1:63625: authentication failed
info(smtp): #2 127.0.0.1:63631: authenticated as alice@example.com
info(queue): 1794050302.M963224R...: delivered to bob@remote.test
```

`--log-level` sets the least severe level shown; `debug` adds connects and disconnects. Passwords and AUTH payloads are never logged, and failed logins record only the client's address.

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

## DKIM

Mail that authenticated users send to other domains is DKIM-signed (RFC 6376, `rsa-sha256`, relaxed/relaxed) when their domain has a key. The key's file name is the selector:

```bash
mkdir -p data/tenants/acme/domains/example.com/dkim
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
  -out data/tenants/acme/domains/example.com/dkim/mail2026.pem
chmod 600 data/tenants/acme/domains/example.com/dkim/mail2026.pem
```

Publish the public key as a TXT record at `<selector>._domainkey.<domain>`:

```bash
echo "mail2026._domainkey.example.com. TXT \"v=DKIM1; k=rsa; p=$(openssl pkey \
  -in data/tenants/acme/domains/example.com/dkim/mail2026.pem -pubout -outform DER | base64 | tr -d '\n')\""
```

In a zone file, split values longer than 255 characters into several quoted strings; most DNS providers do this for you.

Keys are read for every message, and the alphabetically last `<selector>.pem` signs: to rotate, add the new key and its DNS record, then remove the old key (and later its record). Without a key, or if signing fails, mail goes out unsigned.

## Data layout

```text
data/tenants/index.txt                                  tenant <name> <domain>...
data/tenants/<tenant>/domains/<domain>/accounts.txt     <user> <argon2id hash>
data/tenants/<tenant>/domains/<domain>/aliases.txt      <alias> <user>
data/tenants/<tenant>/domains/<domain>/dkim/<selector>.pem   DKIM signing key
data/tenants/<tenant>/domains/<domain>/users/<user>/Maildir/{tmp,new,cur}   INBOX
data/tenants/<tenant>/domains/<domain>/users/<user>/Maildir/.Sent/...       folders (Maildir++)
data/queue/outbound/<id>.eml + <id>.env                                    outbound queue
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
- `src/dkim.zig` DKIM-signs mail leaving through the queue.
- `src/address.zig` validates mail addresses before they reach the filesystem.
- `src/tenant_index.zig`, `src/alias_index.zig`, and `src/account_index.zig` provide routing and identity lookup.

## Contributing

- Keep changes small and focused.
- Run `zig build` and `zig build test` before opening a PR.
- If you touch startup, TLS, or storage behavior, add or update tests.
- Prefer minimal changes that preserve the current architecture.

## License

MIT
