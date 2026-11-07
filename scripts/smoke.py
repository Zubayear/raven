#!/usr/bin/env python3
"""End-to-end smoke test against a real raven binary. Run with `zig build smoke`."""
import hashlib
import imaplib
import os
import smtplib
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from pathlib import Path

BIN = os.environ.get("RAVEN_BIN", "zig-out/bin/raven")
HOST, SMTP_PORT, IMAP_PORT = "127.0.0.1", 2525, 2143


class Raven:
    def __init__(self, data_dir, *extra):
        self.args = [BIN, "--listen-address", HOST, "--listen-port", str(SMTP_PORT),
                     "--imap-port", str(IMAP_PORT), "--hostname", "localhost",
                     "--data-dir", str(data_dir), *extra]

    def __enter__(self):
        self.proc = subprocess.Popen(self.args, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        for port in (SMTP_PORT, IMAP_PORT):
            deadline = time.monotonic() + 10
            while True:
                if self.proc.poll() is not None:
                    sys.exit(f"raven exited early:\n{self.proc.stderr.read().decode()}")
                with socket.socket() as s:
                    if s.connect_ex((HOST, port)) == 0:
                        break
                if time.monotonic() > deadline:
                    sys.exit(f"timed out waiting for port {port}")
                time.sleep(0.05)
        return self

    def __exit__(self, *exc):
        self.proc.terminate()
        self.proc.wait(timeout=10)


class Imap:
    """Raw IMAP client: imaplib quotes LOGIN arguments, which raven can't parse yet (#12)."""

    def __init__(self, sock):
        self.file = sock.makefile("rwb")
        self.tag = 0
        line = self.file.readline()
        assert line.startswith(b"* OK"), line

    def cmd(self, text):
        self.tag += 1
        tag = b"t%d" % self.tag
        self.file.write(tag + b" " + text.encode() + b"\r\n")
        self.file.flush()
        out = b""
        while True:
            line = self.file.readline()
            if not line:
                raise AssertionError(f"connection closed during {text!r}: {out!r}")
            out += line
            if line.startswith(tag + b" "):
                assert line.startswith(tag + b" OK"), out
                return out


def setup_accounts(root):
    domain = root / "tenants/acme/domains/example.com"
    domain.mkdir(parents=True)
    (root / "tenants/index.txt").write_text("tenant acme example.com\n")
    (domain / "accounts.txt").write_text(f"alice {hashlib.sha256(b'secret').hexdigest()}\n")


def check_delivery(smtp, imap_sock):
    smtp.sendmail("bob@external.test", ["alice@example.com"], "Subject: smoke\r\n\r\nhello raven\r\n")
    smtp.quit()

    imap = Imap(imap_sock)
    imap.cmd("LOGIN alice@example.com secret")
    assert b"* 1 EXISTS" in imap.cmd("SELECT INBOX")
    assert b"hello raven" in imap.cmd("FETCH 1 BODY[]")
    imap.cmd("LOGOUT")


def main():
    with tempfile.TemporaryDirectory(prefix="raven-smoke.") as tmp:
        tmp = Path(tmp)

        data = tmp / "plain"
        setup_accounts(data)
        with Raven(data):
            # Silent clients must not block anyone else (#5).
            idle = [socket.create_connection((HOST, port), timeout=5) for port in (SMTP_PORT, IMAP_PORT)]
            check_delivery(smtplib.SMTP(HOST, SMTP_PORT, timeout=5),
                           socket.create_connection((HOST, IMAP_PORT), timeout=5))
            for s in idle:
                s.close()

        with Raven(tmp / "busy", "--max-connections", "1"):
            # The readiness probe's session may still hold the only slot briefly.
            for _ in range(50):
                first = socket.create_connection((HOST, SMTP_PORT), timeout=5)
                if first.recv(64).startswith(b"220 "):
                    break
                first.close()
                time.sleep(0.05)
            else:
                sys.exit("first client was never served")
            with socket.create_connection((HOST, SMTP_PORT), timeout=5) as second:
                assert second.recv(64).startswith(b"421 "), "second client should be turned away"
            first.close()

        cert, key = tmp / "cert.pem", tmp / "key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key,
                        "-out", cert, "-days", "1", "-subj", "/CN=localhost"],
                       check=True, capture_output=True)
        ctx = ssl.create_default_context(cafile=cert)
        ctx.check_hostname = False  # cert has no SAN; the chain is still verified

        data = tmp / "tls"
        setup_accounts(data)
        with Raven(data, "--tls-cert", str(cert), "--tls-key", str(key)):
            check_delivery(smtplib.SMTP_SSL(HOST, SMTP_PORT, timeout=5, context=ctx),
                           ctx.wrap_socket(socket.create_connection((HOST, IMAP_PORT), timeout=5)))
            # Left open across shutdown: SIGTERM must still stop raven promptly.
            idle_tls = ctx.wrap_socket(socket.create_connection((HOST, IMAP_PORT), timeout=5))
            assert idle_tls.recv(64).startswith(b"* OK")
        idle_tls.close()

        bad = subprocess.run([BIN, "--data-dir", str(tmp / "bad"), "--tls-cert", str(cert)],
                             capture_output=True, timeout=10)
        assert bad.returncode != 0, "a cert without a key must be rejected"

    print("smoke test passed")


if __name__ == "__main__":
    main()
