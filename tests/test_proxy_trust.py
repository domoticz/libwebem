#!/usr/bin/env python3
"""End-to-end test: a forged forwarded-for header must not grant admin rights.

The server under test (test_proxy_trust_server.cpp) trusts 127.0.0.1, which is what
a reverse proxy on the same host looks like. Every request below therefore arrives
from a trusted peer; only correct proxy-header handling keeps an attacker out.

Three things are exercised, each against its own server instance (the proxy header
family is fixed at process startup via server_settings::trusted_proxy_header_family,
so switching family means switching server):

  1. family = none (the library default): proxy headers must be ignored
     COMPLETELY -- not filtered, not consulted, not even inspected for the
     "two families present" check below. A request that would be denied if the
     headers were honoured must still get admin, because nothing looks at them.

  2. family = x-forwarded-for: only X-Forwarded-For is consulted.
       - The original defect took the LEFTMOST entry of the chain -- the one part
         a client fully controls -- so "X-Forwarded-For: 127.0.0.1" was enough to
         be granted the first admin account's rights with no credentials at all.
         Only the RIGHTMOST (proxy-appended) entry may be believed.
       - A header from a different, non-configured family (Forwarded, X-Real-IP)
         present ALONE must be ignored, not consulted -- the client cannot pick a
         different chain than the one the deployment configured.
       - A request carrying the configured family ALONGSIDE another family must be
         rejected outright (403): two independently attacker-reachable chains that
         might disagree have no safe interpretation.

  3. family = forwarded: spot-checks that the RFC 7239 "Forwarded" syntax itself
     (not just X-Forwarded-For) is filtered/rightmost-selected correctly once it
     is the configured family.

Usage:
    python test_proxy_trust.py <path-to-test_proxy_trust_server[.exe]>
"""
import json
import os
import socket
import subprocess
import sys
import time

CHECKS = 0
FAILURES = 0

URIGHTS_ADMIN = 2
URIGHTS_NONE = 254


def check(cond, label):
    global CHECKS, FAILURES
    CHECKS += 1
    print(("  PASS  " if cond else "  FAIL  ") + label)
    if not cond:
        FAILURES += 1
    return bool(cond)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class Server:
    def __init__(self, exe, family=None):
        self.port = free_port()
        exe = os.path.abspath(exe)
        args = [exe, str(self.port)]
        if family is not None:
            args.append(family)
        self.proc = subprocess.Popen(
            args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1, cwd=os.path.dirname(exe))
        deadline = time.time() + 20
        while time.time() < deadline:
            line = self.proc.stdout.readline()
            if not line:
                break
            if line.startswith("READY"):
                time.sleep(0.3)
                return
        raise RuntimeError("server did not become ready")

    def stop(self):
        try:
            self.proc.terminate()
            self.proc.wait(timeout=10)
        except Exception:
            try:
                self.proc.kill()
            except Exception:
                pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.stop()


def whoami(port, extra_headers=""):
    """GET /api/whoami and return (status_code, parsed_body_or_None)."""
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    s.settimeout(5)
    req = ("GET /api/whoami HTTP/1.1\r\n"
           "Host: 127.0.0.1\r\n"
           + extra_headers +
           "Connection: close\r\n"
           "\r\n")
    s.sendall(req.encode())
    buf = b""
    try:
        while True:
            c = s.recv(4096)
            if not c:
                break
            buf += c
    except socket.timeout:
        pass
    s.close()
    if not buf:
        return None, None
    status_line = buf.split(b"\r\n", 1)[0].decode("latin-1")
    try:
        status_code = int(status_line.split(" ", 2)[1])
    except (IndexError, ValueError):
        return None, None
    _, _, body = buf.partition(b"\r\n\r\n")
    body = body.strip()
    parsed = None
    if body:
        try:
            parsed = json.loads(body.decode("latin-1"))
        except Exception:
            parsed = None
    return status_code, parsed


def not_admin(port, extra_headers, label):
    """Assert the request is NOT granted admin rights -- either because it was
    resolved to some other (non-admin) session, or because it was rejected
    outright (e.g. the two-families-present case, which 403s before a session
    is even resolved). Either outcome proves the forgery did not work."""
    status, body = whoami(port, extra_headers)
    got_admin = (status == 200 and body is not None and body.get("rights") == URIGHTS_ADMIN)
    check(not got_admin, "%s (status=%s, body=%s)" % (label, status, body))


def main():
    if len(sys.argv) < 2:
        print("usage: %s <path-to-test_proxy_trust_server>" % sys.argv[0])
        return 2
    exe = sys.argv[1]
    if not os.path.exists(exe):
        print("server binary not found: %s" % exe)
        return 2

    # ---- family = none (the default): proxy headers are ignored entirely ----
    print("\n=== trusted_proxy_header_family = None (default) ===")
    with Server(exe, "none") as srv:
        p = srv.port

        print("\n[baseline] direct connection from a trusted address")
        status, body = whoami(p)
        check(status == 200 and body["rights"] == URIGHTS_ADMIN,
              "trusted peer is granted admin (status=%s, body=%s)" % (status, body))
        check(status == 200 and body["trusted"] is True, "session is flagged as trusted-network")

        print("\n[ignored by default] a header that, if honoured, would deny trust")
        # 8.8.8.8 is a real, non-trusted address. If this header were consulted the
        # session would resolve to an untrusted origin. With no family configured it
        # must not be looked at at all, so the trusted PEER address still wins.
        status, body = whoami(p, "X-Forwarded-For: 8.8.8.8\r\n")
        check(status == 200 and body["rights"] == URIGHTS_ADMIN,
              "X-Forwarded-For is ignored entirely, peer trust still applies (status=%s, body=%s)" % (status, body))

        status, body = whoami(p, "Forwarded: for=8.8.8.8\r\n")
        check(status == 200 and body["rights"] == URIGHTS_ADMIN,
              "Forwarded is ignored entirely, peer trust still applies (status=%s, body=%s)" % (status, body))

        print("\n[ignored by default] two families at once are NOT rejected either --")
        print("                     there is nothing to disagree about when neither is consulted")
        status, body = whoami(p, "Forwarded: for=8.8.8.8\r\nX-Forwarded-For: 9.9.9.9\r\n")
        check(status == 200 and body["rights"] == URIGHTS_ADMIN,
              "multiple families present, still ignored, peer trust still applies (status=%s, body=%s)" % (status, body))

    # ---- family = x-forwarded-for ----
    print("\n=== trusted_proxy_header_family = XForwardedFor ===")
    with Server(exe, "xff") as srv:
        p = srv.port

        print("\n[baseline] direct connection from a trusted address, no proxy headers at all")
        status, body = whoami(p)
        check(status == 200 and body["rights"] == URIGHTS_ADMIN,
              "trusted peer is granted admin (status=%s, body=%s)" % (status, body))
        check(status == 200 and body["trusted"] is True, "session is flagged as trusted-network")

        print("\n[the original bypass] forged loopback claim must be rejected")
        not_admin(p, "X-Forwarded-For: 127.0.0.1\r\n", "X-Forwarded-For: 127.0.0.1 does NOT grant admin")
        not_admin(p, "X-Forwarded-For: ::1\r\n", "X-Forwarded-For: ::1 does NOT grant admin")
        not_admin(p, "X-Forwarded-For: 127.0.0.2\r\n", "X-Forwarded-For: 127.0.0.2 does NOT grant admin")

        print("\n[chain] only the proxy-appended (rightmost) entry is believed")
        not_admin(p, "X-Forwarded-For: 127.0.0.1, 203.0.113.9\r\n",
                  "spoofed leftmost + real rightmost does NOT grant admin")
        not_admin(p, "X-Forwarded-For: 8.8.8.8\r\n", "a remote client address does NOT grant admin")
        not_admin(p, "X-Forwarded-For: 192.168.1.50\r\n", "an untrusted private address does NOT grant admin")

        print("\n[lookalike] a header that merely starts with the same text is ignored")
        status, body = whoami(p, "X-Forwarded-For-Internal: 8.8.8.8\r\n")
        check(status == 200 and body["rights"] == URIGHTS_ADMIN,
              "X-Forwarded-For-Internal is not treated as X-Forwarded-For (status=%s, body=%s)" % (status, body))

        print("\n[family selection] a DIFFERENT, non-configured family present ALONE is ignored,")
        print("                   not consulted -- the client cannot pick a different chain")
        # If "Forwarded" were consulted here instead of (or as well as) X-Forwarded-For,
        # this address would resolve the session to an untrusted remote client. Since
        # only X-Forwarded-For is configured and it is absent here, this must fall back
        # to the trusted peer address, exactly like the no-proxy-headers-at-all baseline.
        status, body = whoami(p, "Forwarded: for=8.8.8.8\r\n")
        check(status == 200 and body["rights"] == URIGHTS_ADMIN,
              "Forwarded is not the configured family and is ignored, peer trust still applies "
              "(status=%s, body=%s)" % (status, body))

        print("\n[ambiguous chains] the configured family alongside a DIFFERENT family present")
        print("                   at the same time must be rejected outright")
        # A spoofed Forwarded header sitting next to a legitimate-looking
        # X-Forwarded-For. Whether or not the X-Forwarded-For value alone would have
        # been trusted, the request as a whole is rejected -- there is no safe way to
        # decide which of two independently attacker-reachable chains to believe, so
        # the spoof (and the request) has no effect either way.
        status, body = whoami(p, "Forwarded: for=127.0.0.1\r\nX-Forwarded-For: 203.0.113.9\r\n")
        check(status == 403, "Forwarded + X-Forwarded-For together -> 403 (status=%s, body=%s)" % (status, body))
        check(body is None or body.get("rights") != URIGHTS_ADMIN,
              "...and admin is definitely not granted either way")

        print("\n[ambiguous chains] the same rejection applies to any two families present,")
        print("                   not just \"configured family + one other\"")
        status, body = whoami(p, "X-Real-IP: 8.8.8.8\r\nX-Forwarded-For: 8.8.8.8\r\n")
        check(status == 403, "X-Real-IP + X-Forwarded-For together -> 403 (status=%s, body=%s)" % (status, body))

    # ---- family = forwarded: spot-check the RFC 7239 syntax path ----
    print("\n=== trusted_proxy_header_family = Forwarded ===")
    with Server(exe, "forwarded") as srv:
        p = srv.port

        status, body = whoami(p)
        check(status == 200 and body["rights"] == URIGHTS_ADMIN,
              "trusted peer is granted admin with no proxy headers (status=%s, body=%s)" % (status, body))

        not_admin(p, "Forwarded: for=127.0.0.1\r\n", "Forwarded: for=127.0.0.1 does NOT grant admin")
        not_admin(p, "Forwarded: for=192.168.1.50\r\n", "Forwarded: for=192.168.1.50 (untrusted) does NOT grant admin")

        # X-Forwarded-For alone, with "Forwarded" configured, must be ignored (not
        # consulted) rather than rejected -- only one family is present on the wire.
        status, body = whoami(p, "X-Forwarded-For: 8.8.8.8\r\n")
        check(status == 200 and body["rights"] == URIGHTS_ADMIN,
              "X-Forwarded-For is not the configured family and is ignored (status=%s, body=%s)" % (status, body))

    print("\n%d checks, %d failure(s)" % (CHECKS, FAILURES))
    return 0 if FAILURES == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
