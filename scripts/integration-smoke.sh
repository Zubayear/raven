#!/usr/bin/env bash
set -euo pipefail

BIN=${RAVEN_BIN:-zig-out/bin/raven}

if [[ ! -x "$BIN" ]]; then
  echo "missing raven binary: $BIN" >&2
  exit 1
fi

TMPDIR_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/raven-smoke.XXXXXX")
trap 'rm -rf "$TMPDIR_ROOT"' EXIT

SMTP_PORT=2525
IMAP_PORT=2143

wait_for_port() {
  local port=$1
  local attempts=0
  until python3 -c 'import socket, sys; s = socket.socket(); s.settimeout(0.2); sys.exit(0 if s.connect_ex(("127.0.0.1", int(sys.argv[1]))) == 0 else 1)' "$port" >/dev/null 2>&1; do
    attempts=$((attempts + 1))
    if [[ $attempts -gt 100 ]]; then
      echo "timed out waiting for port $port" >&2
      return 1
    fi
    sleep 0.1
  done
}

capture_plain() {
  local host=$1
  local port=$2
  local marker=$3
  python3 -c '
import socket
import sys
import time

host = sys.argv[1]
port = int(sys.argv[2])
marker = sys.argv[3].encode()

with socket.create_connection((host, port), timeout=5) as sock:
    payload = sys.stdin.buffer.read()
    sock.sendall(payload)
    sock.shutdown(socket.SHUT_WR)
    sock.settimeout(0.5)

    chunks = []
    deadline = time.monotonic() + 10
    while True:
        if time.monotonic() > deadline:
            raise TimeoutError("timed out waiting for marker")
        try:
            data = sock.recv(4096)
        except socket.timeout:
            continue
        if not data:
            break
        chunks.append(data)
        if marker in b"".join(chunks):
            break

sys.stdout.buffer.write(b"".join(chunks))
' "$host" "$port" "$marker"
}

capture_tls() {
  local host=$1
  local port=$2
  local cafile=$3
  local marker=$4
  python3 -c '
import socket
import ssl
import sys
import time

host = sys.argv[1]
port = int(sys.argv[2])
cafile = sys.argv[3]
marker = sys.argv[4].encode()

ctx = ssl.create_default_context(cafile=cafile)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_REQUIRED

with socket.create_connection((host, port), timeout=5) as raw_sock:
    with ctx.wrap_socket(raw_sock, server_hostname="localhost") as sock:
        payload = sys.stdin.buffer.read()
        sock.sendall(payload)
        sock.shutdown(socket.SHUT_WR)
        sock.settimeout(0.5)

        chunks = []
        deadline = time.monotonic() + 10
        while True:
            if time.monotonic() > deadline:
                raise TimeoutError("timed out waiting for marker")
            try:
                data = sock.recv(4096)
            except socket.timeout:
                continue
            if not data:
                break
            chunks.append(data)
            if marker in b"".join(chunks):
                break

sys.stdout.buffer.write(b"".join(chunks))
' "$host" "$port" "$cafile" "$marker"
}

start_server() {
  local name=$1
  shift
  local log_file="$TMPDIR_ROOT/$name.log"
  "$BIN" \
    --listen-address 127.0.0.1 \
    --listen-port "$SMTP_PORT" \
    --imap-port "$IMAP_PORT" \
    --hostname localhost \
    --data-dir "$TMPDIR_ROOT/data" \
    "$@" >"$log_file" 2>&1 &
  echo $!
}

assert_contains() {
  local haystack=$1
  local needle=$2
  if [[ "$haystack" != *"$needle"* ]]; then
    echo "expected output to contain: $needle" >&2
    echo "actual output:" >&2
    printf '%s\n' "$haystack" >&2
    exit 1
  fi
}

SMTP_PID=$(start_server plain)
cleanup_plain() {
  kill "$SMTP_PID" >/dev/null 2>&1 || true
  wait "$SMTP_PID" >/dev/null 2>&1 || true
}
trap cleanup_plain EXIT

wait_for_port "$SMTP_PORT"
wait_for_port "$IMAP_PORT"

plain_smtp=$(printf '' | capture_plain 127.0.0.1 "$SMTP_PORT" "220 localhost ESMTP raven ready")
assert_contains "$plain_smtp" "220 localhost"

plain_imap=$(printf '' | capture_plain 127.0.0.1 "$IMAP_PORT" "* OK IMAP4rev1 raven ready")
assert_contains "$plain_imap" "* OK IMAP4rev1 raven ready"

cleanup_plain
trap - EXIT

cert_file="$TMPDIR_ROOT/cert.pem"
key_file="$TMPDIR_ROOT/key.pem"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$key_file" -out "$cert_file" -days 1 -subj "/CN=localhost" >/dev/null 2>&1

SMTP_PID=$(start_server tls --tls-cert "$cert_file" --tls-key "$key_file")
cleanup_tls() {
  kill "$SMTP_PID" >/dev/null 2>&1 || true
  wait "$SMTP_PID" >/dev/null 2>&1 || true
}
trap cleanup_tls EXIT

wait_for_port "$SMTP_PORT"
wait_for_port "$IMAP_PORT"

tls_smtp=$(printf '' | capture_tls 127.0.0.1 "$SMTP_PORT" "$cert_file" "220 localhost ESMTP raven ready")
assert_contains "$tls_smtp" "220 localhost"

tls_imap=$(printf '' | capture_tls 127.0.0.1 "$IMAP_PORT" "$cert_file" "* OK IMAP4rev1 raven ready")
assert_contains "$tls_imap" "* OK IMAP4rev1 raven ready"

cleanup_tls
trap - EXIT

if "$BIN" --listen-address 127.0.0.1 --listen-port "$SMTP_PORT" --imap-port "$IMAP_PORT" --hostname localhost --data-dir "$TMPDIR_ROOT/invalid" --tls-cert "$cert_file" >/dev/null 2>&1; then
  echo "expected invalid TLS config to fail" >&2
  exit 1
fi

echo "smoke test passed"
