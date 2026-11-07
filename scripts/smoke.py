#!/usr/bin/env python3
"""End-to-end smoke test against a real raven binary. Run with `zig build smoke`."""
import base64
import imaplib
import mailbox
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
HOST, SMTP_PORT, IMAP_PORT, SMTPS_PORT = "127.0.0.1", 2525, 2143, 2465


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


PASSWORD = "correct horse"  # the space exercises IMAP quoting (#12)
PASSWORD_HASH = None


def setup_accounts(root):
    global PASSWORD_HASH
    if PASSWORD_HASH is None:  # argon2id is deliberately slow: hash once
        PASSWORD_HASH = subprocess.run([BIN, "passwd"], input=PASSWORD.encode() + b"\n", capture_output=True,
                                       check=True).stdout.decode().strip()
        assert PASSWORD_HASH.startswith("$argon2id$"), PASSWORD_HASH
    domain = root / "tenants/acme/domains/example.com"
    domain.mkdir(parents=True)
    (root / "tenants/index.txt").write_text("tenant acme example.com\n")
    (domain / "accounts.txt").write_text(f"alice {PASSWORD_HASH}\n")


def check_delivery(smtp, imap, expected=1, sender="bob@external.test"):
    smtp.sendmail(sender, ["alice+smoke@example.com"], f"Subject: smoke {expected}\r\n\r\nhello raven\r\n")
    smtp.quit()

    imap.login("alice@example.com", PASSWORD)
    assert imap.select("INBOX") == ("OK", [b"%d" % expected])
    fetched = imap.fetch(str(expected), "(BODY[])")[1][0][1]
    assert b"Subject: smoke %d" % expected in fetched
    assert b"Return-Path: <%s>" % sender.encode() in fetched and b"([127.0.0.1])" in fetched, fetched  # #11
    imap.logout()


def imap_plain():
    return imaplib.IMAP4(HOST, IMAP_PORT, timeout=5)


def main():
    with tempfile.TemporaryDirectory(prefix="raven-smoke.") as tmp:
        tmp = Path(tmp)

        data = tmp / "plain"
        setup_accounts(data)
        with Raven(data):
            # Silent clients must not block anyone else (#5).
            idle = [socket.create_connection((HOST, port), timeout=5) for port in (SMTP_PORT, IMAP_PORT)]
            check_delivery(smtplib.SMTP(HOST, SMTP_PORT, timeout=5), imap_plain())
            for s in idle:
                s.close()

        with Raven(data):  # delivery after a restart must not collide with existing files (#6)
            check_delivery(smtplib.SMTP(HOST, SMTP_PORT, timeout=5), imap_plain(), expected=2)
            imap = imap_plain()
            imap.login("alice@example.com", PASSWORD)
            imap.select("INBOX")
            assert imap.store("1", "+FLAGS", "(\\Seen)")[0] == "OK"
            imap.logout()
        # Any standard Maildir reader must see both messages and the flag.
        maildir = mailbox.Maildir(data / "tenants/acme/domains/example.com/users/alice/Maildir", create=False)
        assert sorted(m.get_flags() for m in maildir) == ["", "S"], [m.get_flags() for m in maildir]

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
        with Raven(data, "--tls-cert", str(cert), "--tls-key", str(key), "--smtps-port", str(SMTPS_PORT)):
            # Passwords never travel in the clear: no AUTH before STARTTLS (#9).
            smtp = smtplib.SMTP(HOST, SMTP_PORT, timeout=5)
            smtp.ehlo()
            assert smtp.has_extn("starttls") and not smtp.has_extn("auth"), smtp.esmtp_features
            credentials = base64.b64encode(b"\0alice@example.com\0" + PASSWORD.encode()).decode()
            assert smtp.docmd("AUTH", "PLAIN " + credentials)[0] == 538
            smtp.starttls(context=ctx)
            smtp.login("alice@example.com", PASSWORD)
            check_delivery(smtp, imaplib.IMAP4_SSL(HOST, IMAP_PORT, ssl_context=ctx, timeout=5), sender="alice@example.com")

            smtps = smtplib.SMTP_SSL(HOST, SMTPS_PORT, timeout=5, context=ctx)
            smtps.login("alice@example.com", PASSWORD)
            check_delivery(smtps, imaplib.IMAP4_SSL(HOST, IMAP_PORT, ssl_context=ctx, timeout=5), expected=2,
                           sender="alice@example.com")

            s_client = subprocess.run(["openssl", "s_client", "-starttls", "smtp", "-connect", f"{HOST}:{SMTP_PORT}",
                                       "-CAfile", cert, "-quiet"], input=b"EHLO client\r\nQUIT\r\n",
                                      capture_output=True, timeout=10)
            assert b"250-AUTH PLAIN" in s_client.stdout, s_client.stdout + s_client.stderr
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
