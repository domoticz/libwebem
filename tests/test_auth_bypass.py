#!/usr/bin/env python3
"""End-to-end test: the API command whitelist must be judged on the parsed
parameters the page handler dispatches on, never on a raw-URI substring search.

CheckAuthByPass used to find the command with uri.find("?param=") /
uri.find("&param="), while CheckForPageOverride tokenised the query string into
request::parameters and the handler dispatched on findValue("param"). Any input
that makes those two disagree lets an unauthenticated caller run a command that
is not on the whitelist, e.g.

    /json.htm?foo=?param=logincheck&type=command&param=getsettings

The raw search found "logincheck" inside foo's VALUE and granted the bypass; the
tokeniser handed the handler param=getsettings.

Every case below sends one request and checks the status plus, for a 200, the
"param" the handler actually dispatched on and the session user it ran as. A
non-whitelisted "param" served with an empty user is the bug.

Usage:
    python test_auth_bypass.py <path-to-test_auth_bypass_server[.exe]>
"""
import base64
import json
import os
import socket
import subprocess
import sys
import time

CHECKS = 0
FAILURES = 0

WHITELISTED = "logincheck"
PROTECTED = "getsettings"
ADMIN_BASIC = "Authorization: Basic %s\r\n" % base64.b64encode(b"admin:test").decode()


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
    def __init__(self, exe):
        self.port = free_port()
        exe = os.path.abspath(exe)
        self.proc = subprocess.Popen(
            [exe, str(self.port)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1, cwd=os.path.dirname(exe))
        deadline = time.time() + 20
        while time.time() < deadline:
            line = self.proc.stdout.readline()
            if not line:
                break
            if line.strip().startswith("READY"):
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


def request(port, path, method="GET", body=None, content_type=None, extra_headers="", timeout=5):
    """Send one request and return (status_code, body_dict_or_None). Any
    socket-level failure is surfaced as status_code None."""
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    except OSError:
        return None, None
    s.settimeout(timeout)
    data = body.encode() if body is not None else b""
    head = "%s %s HTTP/1.1\r\nHost: 127.0.0.1\r\n%s" % (method, path, extra_headers)
    if content_type:
        head += "Content-Type: %s\r\n" % content_type
    if body is not None:
        head += "Content-Length: %d\r\n" % len(data)
    head += "Connection: close\r\n\r\n"
    try:
        s.sendall(head.encode() + data)
        buf = b""
        while True:
            c = s.recv(4096)
            if not c:
                break
            buf += c
    except socket.timeout:
        s.close()
        return None, None
    s.close()
    if not buf:
        return None, None
    status_line = buf.split(b"\r\n", 1)[0].decode("latin-1")
    try:
        status_code = int(status_line.split(" ", 2)[1])
    except (IndexError, ValueError):
        return None, None
    _, _, payload = buf.partition(b"\r\n\r\n")
    payload = payload.strip()
    parsed = None
    if payload:
        try:
            parsed = json.loads(payload.decode("latin-1"))
        except Exception:
            parsed = None
    return status_code, parsed


def expect_denied(port, path, label, **kw):
    status, body = request(port, path, **kw)
    check(status == 401, "%s -> 401 (status=%s body=%s)" % (label, status, body))


def expect_served(port, path, label, param, user="", **kw):
    status, body = request(port, path, **kw)
    check(status == 200, "%s -> 200 (status=%s)" % (label, status))
    check(bool(body) and body.get("param") == param,
          "%s: handler dispatched on param=%s (body=%s)" % (label, param, body))
    check(bool(body) and body.get("user") == user,
          "%s: ran as user '%s' (body=%s)" % (label, user, body))


def main():
    if len(sys.argv) < 2:
        print("usage: %s <path-to-test_auth_bypass_server>" % sys.argv[0])
        return 2
    exe = sys.argv[1]
    if not os.path.exists(exe):
        print("server binary not found: %s" % exe)
        return 2

    with Server(exe) as srv:
        p = srv.port

        print("\n[baseline] the whitelist itself still works, and nothing else gets in for free")
        expect_served(p, "/json.htm?type=command&param=%s" % WHITELISTED,
                      "whitelisted command, no credentials", WHITELISTED)
        expect_denied(p, "/json.htm?type=command&param=%s" % PROTECTED,
                      "protected command, no credentials")
        expect_denied(p, "/json.htm?param=%s" % WHITELISTED,
                      "whitelisted command without type=command")
        expect_denied(p, "/json.htm?type=command",
                      "type=command with no param at all")
        expect_served(p, "/json.htm?type=command&param=%s" % PROTECTED,
                      "protected command with valid Basic credentials", PROTECTED, user="admin",
                      extra_headers=ADMIN_BASIC)

        print("\n[reported bypass] '?param=<whitelisted>' hidden inside another parameter's value")
        # Verbatim from the report: the raw-URI search found "?param=logincheck"
        # inside foo's value, the tokeniser dispatched param=getsettings.
        expect_denied(p, "/json.htm?foo=?param=%s&type=command&param=%s" % (WHITELISTED, PROTECTED),
                      "foo=?param=<whitelisted> then real param=<protected>")
        expect_denied(p, "/json.htm?type=command&foo=?param=%s&param=%s" % (WHITELISTED, PROTECTED),
                      "same, type first")
        expect_denied(p, "/json.htm?type=command&param=%s&foo=?param=%s" % (PROTECTED, WHITELISTED),
                      "real param=<protected> first, decoy in a later value")
        # The decoy spelled with the other separator the raw search looked for.
        expect_denied(p, "/json.htm?foo=bar%%26param=%s&type=command&param=%s" % (WHITELISTED, PROTECTED),
                      "decoy '&param=' url-encoded inside a value")

        print("\n[original report] a bare segment in front of the whitelisted command")
        # The first PoC for GHSA-gwf6-ff7h-484q: with '=' found before '&', the
        # bare "foo" segment swallowed the next name ("foo&param"=logincheck), so
        # the raw search saw logincheck while the dispatcher saw only getsettings.
        expect_denied(p, "/json.htm?type=command&foo&param=%s&param=%s" % (WHITELISTED, PROTECTED),
                      "&foo&param=<whitelisted>&param=<protected>")
        expect_denied(p, "/json.htm?type=command&foo&param=%s" % PROTECTED,
                      "&foo&param=<protected>")
        expect_served(p, "/json.htm?type=command&foo&param=%s" % WHITELISTED,
                      "&foo&param=<whitelisted>", WHITELISTED)

        print("\n[duplicate param] a request naming both a whitelisted and a protected command")
        # Whichever duplicate a multimap lookup happens to return, the bypass is
        # granted for the request as a whole, so every value must be whitelisted.
        expect_denied(p, "/json.htm?type=command&param=%s&param=%s" % (WHITELISTED, PROTECTED),
                      "param=<whitelisted>&param=<protected>")
        expect_denied(p, "/json.htm?type=command&param=%s&param=%s" % (PROTECTED, WHITELISTED),
                      "param=<protected>&param=<whitelisted>")
        expect_served(p, "/json.htm?type=command&param=%s&param=%s" % (WHITELISTED, WHITELISTED),
                      "param=<whitelisted> twice", WHITELISTED)

        print("\n[exact match] regression for the prefix-match fix (GHSA-gwf6-ff7h-484q)")
        expect_denied(p, "/json.htm?type=command&param=%sextra" % WHITELISTED,
                      "whitelisted command name as a prefix of a longer name")
        expect_denied(p, "/json.htm?type=command&param=%s" % WHITELISTED.upper(),
                      "whitelisted command name in a different case")

        print("\n[consistency] the bypass sees the same decoded values the handler does")
        # "%6c" decodes to "l": the handler dispatches logincheck, so the bypass
        # must agree (the old raw search would have said 'not whitelisted').
        expect_served(p, "/json.htm?type=command&param=%6cogincheck",
                      "url-encoded whitelisted command", WHITELISTED)
        expect_denied(p, "/json.htm?type=command&param=%67etsettings",
                      "url-encoded protected command")
        # A '+' in the value becomes a blank before matching.
        expect_denied(p, "/json.htm?type=command&param=%s+" % WHITELISTED,
                      "whitelisted command followed by an encoded blank")

        print("\n[POST body] form-encoded parameters are part of the same parsed set")
        # The bypass is decided on the query string before the body is parsed
        # (the body stays behind authentication), and re-checked on the completed
        # set afterwards. So a body can never EARN the bypass, but it can lose it.
        form = "application/x-www-form-urlencoded"
        expect_denied(p, "/json.htm?type=command",
                      "whitelisted command supplied only in the POST body",
                      method="POST", body="param=%s" % WHITELISTED, content_type=form)
        expect_denied(p, "/json.htm?type=command",
                      "protected command supplied only in the POST body",
                      method="POST", body="param=%s" % PROTECTED, content_type=form)
        expect_denied(p, "/json.htm?type=command&param=%s" % WHITELISTED,
                      "whitelisted in the URI, protected in the POST body",
                      method="POST", body="param=%s" % PROTECTED, content_type=form)
        expect_denied(p, "/json.htm?type=command&param=%s" % PROTECTED,
                      "protected in the URI, whitelisted in the POST body",
                      method="POST", body="param=%s" % WHITELISTED, content_type=form)
        expect_denied(p, "/json.htm?foo=?param=%s" % WHITELISTED,
                      "decoy in the URI, real type/param in the POST body",
                      method="POST", body="type=command&param=%s" % PROTECTED, content_type=form)

        print("\n[liveness] the server still answers a plain request afterwards")
        status, _ = request(p, "/json.htm?type=command&param=%s" % WHITELISTED)
        check(status == 200, "server alive (status=%s)" % status)

    print("\n%d checks, %d failure(s)" % (CHECKS, FAILURES))
    return 0 if FAILURES == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
