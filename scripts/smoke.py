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
HOST, SMTP_PORT, IMAP_PORT, SMTPS_PORT, IMAPS_PORT, SUBMISSION_PORT = "127.0.0.1", 2525, 2143, 2465, 2993, 2587


class Raven:
    def __init__(self, data_dir, *extra, ports=(SMTP_PORT, IMAP_PORT), hostname="localhost"):
        if "--tls-cert" not in extra:
            extra += ("--allow-plaintext-auth",)  # no TLS in these runs, so IMAP LOGIN needs the opt-out
        self.ports = ports
        self.args = [BIN, "--listen-address", HOST, "--listen-port", str(ports[0]),
                     "--imap-port", str(ports[1]), "--hostname", hostname,
                     "--data-dir", str(data_dir), *extra]

    def __enter__(self):
        self.proc = subprocess.Popen(self.args, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        for port in self.ports:
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
    fetched = imap.fetch(str(expected), "(BODY.PEEK[])")[1][0][1]
    assert b"Subject: smoke %d" % expected in fetched
    assert b"Return-Path: <%s>" % sender.encode() in fetched and b"([127.0.0.1])" in fetched, fetched  # #11
    assert imap.search(None, "SUBJECT", '"smoke %d"' % expected)[1][0] == b"%d" % expected  # #17
    summary = imap.fetch(str(expected), "(FLAGS ENVELOPE BODYSTRUCTURE)")[1][0]  # #14
    assert b'"smoke %d"' % expected in summary and b'BODYSTRUCTURE ("text" "plain"' in summary, summary
    # Nothing is expunged in these runs, so the newest message has UID == count (#13).
    assert b"UID %d " % expected in imap.uid("FETCH", str(expected), "(BODY.PEEK[])")[1][0][0]
    validity = imap.response("UIDVALIDITY")[1][0]
    imap.logout()
    return validity


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
            validity = check_delivery(smtplib.SMTP(HOST, SMTP_PORT, timeout=5), imap_plain())
            for s in idle:
                s.close()

        with Raven(data):  # delivery after a restart must not collide with existing files (#6)
            assert check_delivery(smtplib.SMTP(HOST, SMTP_PORT, timeout=5), imap_plain(), expected=2) == validity
            imap = imap_plain()
            imap.login("alice@example.com", PASSWORD)
            imap.select("INBOX")
            assert imap.store("1", "+FLAGS", "(\\Seen)")[0] == "OK"
            imap.logout()
        # Any standard Maildir reader must see both messages and the flag.
        maildir = mailbox.Maildir(data / "tenants/acme/domains/example.com/users/alice/Maildir", create=False)
        assert sorted(m.get_flags() for m in maildir) == ["", "S"], [m.get_flags() for m in maildir]

        data = tmp / "folders"
        setup_accounts(data)
        with Raven(data):  # #16
            smtplib.SMTP(HOST, SMTP_PORT, timeout=5).sendmail("bob@external.test", ["alice@example.com"], "Subject: hi\r\n\r\nx\r\n")
            imap = imap_plain()
            imap.login("alice@example.com", PASSWORD)
            assert imap.create("Projects")[0] == "OK"
            assert imap.append("Projects", "(\\Seen)", None, b"Subject: appended\r\n\r\nhi\r\n")[0] == "OK"
            imap.select("INBOX")
            imaplib.Commands.setdefault("MOVE", ("SELECTED",))
            assert imap._simple_command("MOVE", "1", "Projects")[0] == "OK"
            assert imap.status("Projects", "(MESSAGES UNSEEN)")[1][0] == b'"Projects" (MESSAGES 2 UNSEEN 1)'
            assert b"\\Sent" in b"".join(imap.list()[1])
            imap.logout()

        data = tmp / "idle"
        setup_accounts(data)
        with Raven(data):  # #18: a delivery shows up while the client IDLEs
            imap = imap_plain()
            imap.login("alice@example.com", PASSWORD)
            imap.select("INBOX")
            tag = imap._new_tag()
            imap.send(tag + b" IDLE\r\n")
            assert imap.readline().startswith(b"+"), "IDLE not accepted"
            started = time.monotonic()
            smtplib.SMTP(HOST, SMTP_PORT, timeout=5).sendmail("bob@external.test", ["alice@example.com"], "Subject: ping\r\n\r\n")
            assert imap.readline() == b"* 1 EXISTS\r\n"
            assert time.monotonic() - started < 5
            assert imap.readline() == b"* 1 RECENT\r\n"
            imap.send(b"DONE\r\n")
            assert imap.readline().startswith(tag + b" OK")
            imap.logout()

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
        # A second Raven hosting remote.test receives what the first one relays.
        remote = tmp / "remote"
        (remote / "tenants/beta/domains/remote.test").mkdir(parents=True)
        (remote / "tenants/index.txt").write_text("tenant beta remote.test\n")
        (remote / "tenants/beta/domains/remote.test/accounts.txt").write_text(f"bob {PASSWORD_HASH}\n")
        with Raven(remote, "--tls-cert", str(cert), "--tls-key", str(key), ports=(3525, 3143), hostname="mx.remote.test"), \
                Raven(data, "--tls-cert", str(cert), "--tls-key", str(key), "--smtps-port", str(SMTPS_PORT),
                      "--imaps-port", str(IMAPS_PORT), "--submission-port", str(SUBMISSION_PORT),
                      "--relay-host", HOST, "--relay-port", "3525"):
            # Submission: AUTH first, then remote recipients go to the queue (#20).
            sub = smtplib.SMTP(HOST, SUBMISSION_PORT, timeout=5)
            sub.starttls(context=ctx)
            try:
                sub.sendmail("alice@example.com", ["bob@remote.test"], "Subject: out\r\n\r\nhi\r\n")
                sys.exit("submission without AUTH must fail")
            except smtplib.SMTPSenderRefused as err:
                assert err.smtp_code == 530, err
            sub.login("alice@example.com", PASSWORD)
            sub.sendmail("alice@example.com", ["bob@remote.test"], "Subject: out\r\n\r\nhi\r\n")
            sub.quit()

            # The queue runner relays it to the other Raven over STARTTLS (#22, #23).
            bob = remote / "tenants/beta/domains/remote.test/users/bob/Maildir/new"
            deadline = time.monotonic() + 20
            while not (bob.exists() and any(bob.iterdir())):
                assert time.monotonic() < deadline, "relayed mail never arrived"
                time.sleep(0.2)
            relayed = next(bob.iterdir()).read_bytes()
            assert b"with ESMTPS" in relayed and b"Subject: out" in relayed, relayed
            deadline = time.monotonic() + 5
            while list((data / "queue/outbound").glob("*.env")):
                assert time.monotonic() < deadline, "queue entry was not removed after delivery"
                time.sleep(0.1)

            # IMAP refuses passwords before STARTTLS, then accepts them (#19).
            imap = imaplib.IMAP4(HOST, IMAP_PORT, timeout=5)
            assert "LOGINDISABLED" in imap.capabilities and "STARTTLS" in imap.capabilities, imap.capabilities
            try:
                imap.login("alice@example.com", PASSWORD)
                sys.exit("LOGIN before STARTTLS must fail")
            except imaplib.IMAP4.error as err:
                assert "PRIVACYREQUIRED" in str(err), err
            imap.starttls(ssl_context=ctx)
            imap.login("alice@example.com", PASSWORD)
            imap.logout()

            # Passwords never travel in the clear: no AUTH before STARTTLS (#9).
            smtp = smtplib.SMTP(HOST, SMTP_PORT, timeout=5)
            smtp.ehlo()
            assert smtp.has_extn("starttls") and not smtp.has_extn("auth"), smtp.esmtp_features
            credentials = base64.b64encode(b"\0alice@example.com\0" + PASSWORD.encode()).decode()
            assert smtp.docmd("AUTH", "PLAIN " + credentials)[0] == 538
            smtp.starttls(context=ctx)
            smtp.login("alice@example.com", PASSWORD)
            check_delivery(smtp, imaplib.IMAP4_SSL(HOST, IMAPS_PORT, ssl_context=ctx, timeout=5), sender="alice@example.com")

            smtps = smtplib.SMTP_SSL(HOST, SMTPS_PORT, timeout=5, context=ctx)
            smtps.login("alice@example.com", PASSWORD)
            check_delivery(smtps, imaplib.IMAP4_SSL(HOST, IMAPS_PORT, ssl_context=ctx, timeout=5), expected=2,
                           sender="alice@example.com")

            # IDLE over TLS: poll timeouts must not break the TLS session (#18).
            imap = imaplib.IMAP4_SSL(HOST, IMAPS_PORT, ssl_context=ctx, timeout=10)
            imap.login("alice@example.com", PASSWORD)
            imap.select("INBOX")
            tag = imap._new_tag()
            imap.send(tag + b" IDLE\r\n")
            assert imap.readline().startswith(b"+")
            time.sleep(2.5)  # at least one poll timeout inside TLS before the delivery
            smtplib.SMTP(HOST, SMTP_PORT, timeout=5).sendmail("bob@external.test", ["alice@example.com"], "Subject: ping\r\n\r\n")
            assert imap.readline() == b"* 3 EXISTS\r\n"
            imap.readline()
            imap.send(b"DONE\r\n")
            assert imap.readline().startswith(tag + b" OK")
            imap.logout()

            s_client = subprocess.run(["openssl", "s_client", "-starttls", "smtp", "-connect", f"{HOST}:{SMTP_PORT}",
                                       "-CAfile", cert, "-quiet"], input=b"EHLO client\r\nQUIT\r\n",
                                      capture_output=True, timeout=10)
            assert b"250-AUTH PLAIN" in s_client.stdout, s_client.stdout + s_client.stderr
            s_client = subprocess.run(["openssl", "s_client", "-starttls", "imap", "-connect", f"{HOST}:{IMAP_PORT}",
                                       "-CAfile", cert, "-quiet"], input=b"a CAPABILITY\r\nb LOGOUT\r\n",
                                      capture_output=True, timeout=10)
            assert b"AUTH=PLAIN" in s_client.stdout and b"LOGINDISABLED" not in s_client.stdout, s_client.stdout + s_client.stderr
            # Left open across shutdown: SIGTERM must still stop raven promptly.
            idle_tls = ctx.wrap_socket(socket.create_connection((HOST, IMAPS_PORT), timeout=5))
            assert idle_tls.recv(64).startswith(b"* OK")
        idle_tls.close()

        bad = subprocess.run([BIN, "--data-dir", str(tmp / "bad"), "--tls-cert", str(cert)],
                             capture_output=True, timeout=10)
        assert bad.returncode != 0, "a cert without a key must be rejected"

    print("smoke test passed")


if __name__ == "__main__":
    main()
