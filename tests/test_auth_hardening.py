#!/usr/bin/env python3
"""End-to-end test: a malformed Authorization header must not kill the server.

parse_auth_header()'s JWT branch used to call jwt::decode() (and several claim
accessors) with nothing catching what they throw on malformed input, and
separately dereferenced the "aud" claim's audience set without checking it was
non-empty. Both were reachable pre-authentication, from a single request, and
both used to take the whole webserver thread down (or invoke undefined
behaviour) rather than simply rejecting the request.

Every case below sends one bad request, then immediately sends a normal request
and requires a normal response -- that second request is the actual assertion.
A dead or wedged server would fail it (connection refused/reset, or a timeout).

Usage:
    python test_auth_hardening.py <path-to-test_auth_hardening_server[.exe]>
"""
import base64
import hashlib
import hmac
import json
import os
import socket
import subprocess
import sys
import time

CHECKS = 0
FAILURES = 0


def check(cond, label):
    global CHECKS, FAILURES
    CHECKS += 1
    print(("  PASS  " if cond else "  FAIL  ") + label)
    if not cond:
        FAILURES += 1
    return bool(cond)


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class Server:
    def __init__(self, exe):
        self.port = free_port()
        self.token = None
        exe = os.path.abspath(exe)
        self.proc = subprocess.Popen(
            [exe, str(self.port)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1, cwd=os.path.dirname(exe))
        deadline = time.time() + 20
        while time.time() < deadline:
            line = self.proc.stdout.readline()
            if not line:
                break
            line = line.strip()
            if line.startswith("TOKEN "):
                self.token = line[len("TOKEN "):]
            elif line.startswith("READY"):
                if self.token is None:
                    raise RuntimeError("server became ready without printing a TOKEN line")
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


def request(port, path="/api/whoami", extra_headers="", timeout=5):
    """Send a single GET and return (status_code, body_dict_or_None). Any socket-level
    failure (refused, reset, timeout) is surfaced as status_code None, which the
    caller treats as "server did not respond" -- exactly the failure mode a crash
    or a hang would produce."""
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    except OSError:
        return None, None
    s.settimeout(timeout)
    req = ("GET %s HTTP/1.1\r\n"
           "Host: 127.0.0.1\r\n"
           "%s"
           "Connection: close\r\n"
           "\r\n") % (path, extra_headers)
    try:
        s.sendall(req.encode())
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
    _, _, body = buf.partition(b"\r\n\r\n")
    body = body.strip()
    parsed = None
    if body:
        try:
            parsed = json.loads(body.decode("latin-1"))
        except Exception:
            parsed = None
    return status_code, parsed


def forge_hs256_empty_key(payload_obj, kid):
    """Build a syntactically valid HS256 JWT, signed with an EMPTY HMAC key --
    exactly what jwt::algorithm::hs256{signingsecret} constructs when
    signingsecret is "". OpenSSL's HMAC() accepts a zero-length key without
    complaint, so this signature is something any attacker can compute; nothing
    about it is hard to forge. It exists purely to prove the server-side fix
    refuses to verify HS256 against a ClientID that has no HMAC secret
    registered, not to demonstrate any cryptographic weakness in HMAC itself.

    "kid" is a JOSE HEADER parameter (set via jwt::builder::set_key_id() on the
    genuine-token path), not a payload claim -- it has to go in the header here
    too, or has_key_id()/get_key_id() never see it."""
    header = b64u(json.dumps({"alg": "HS256", "typ": "JWT", "kid": kid}).encode())
    payload = b64u(json.dumps(payload_obj).encode())
    signing_input = ("%s.%s" % (header, payload)).encode()
    sig = hmac.new(b"", signing_input, hashlib.sha256).digest()
    return "%s.%s.%s" % (header, payload, b64u(sig))


def assert_survives(port, bad_auth_header, label):
    """Send the malformed Authorization header, then require the server to still
    answer a completely ordinary follow-up request. That follow-up response -- not
    the malformed request's own response -- is what proves the server is alive."""
    status, _ = request(port, extra_headers=bad_auth_header)
    check(status is not None, "%s: server responded to the malformed request (status=%s)" % (label, status))

    status, _ = request(port, path="/api/ping")
    check(status == 200, "%s: server still serves normal requests afterwards (status=%s)" % (label, status))


def main():
    if len(sys.argv) < 2:
        print("usage: %s <path-to-test_auth_hardening_server>" % sys.argv[0])
        return 2
    exe = sys.argv[1]
    if not os.path.exists(exe):
        print("server binary not found: %s" % exe)
        return 2

    with Server(exe) as srv:
        p = srv.port

        print("\n[regression] a request with no Authorization header at all")
        status, _ = request(p)
        check(status == 401, "no Authorization header -> 401 (status=%s)" % status)

        print("\n[regression] a genuinely valid, correctly signed JWT still authenticates")
        status, body = request(p, extra_headers="Authorization: Bearer %s\r\n" % srv.token)
        check(status == 200, "valid JWT -> 200 (status=%s)" % status)
        check(bool(body) and body.get("user") == "alice",
              "valid JWT resolves to the expected user (body=%s)" % body)
        check(bool(body) and body.get("rights") == 0,
              "valid JWT resolves to the expected rights (URIGHTS_VIEWER) (body=%s)" % body)

        print("\n[Finding #3] jwt::decode() throws on a token with too few segments")
        # From the vulnerability report verbatim: the header segment decodes to
        # {"alg":"HS256","typ":"JWT"}, so parse_auth_header enters the JWT branch,
        # and the token has only one dot, so jwt::decode() throws std::invalid_argument.
        assert_survives(p, "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.x\r\n",
                         "two-segment token")

        print("\n[Finding #3] a well-formed three-segment token with a non-JSON payload")
        header = b64u(b'{"alg":"HS256","typ":"JWT"}')
        payload = b64u(b"this is not json")
        token = "%s.%s.garbagesignature" % (header, payload)
        assert_survives(p, "Authorization: Bearer %s\r\n" % token, "non-JSON payload")

        print("\n[Finding #10] a token whose \"aud\" claim is present but empty")
        # has_audience() only checks the claim exists; "aud": [] leaves it present
        # but empty, so a naive cbegin()->... dereferences the end iterator.
        header = b64u(b'{"alg":"HS256","typ":"JWT"}')
        payload = b64u(b'{"iss":"https://127.0.0.1/","aud":[],"sub":"alice"}')
        token = "%s.%s.garbagesignature" % (header, payload)
        assert_survives(p, "Authorization: Bearer %s\r\n" % token, "empty aud array")

        print("\n[not a crash, but must still be rejected] syntactically valid, wrong signature")
        header = b64u(b'{"alg":"HS256","typ":"JWT"}')
        payload = b64u(json.dumps({
            "iss": "https://127.0.0.1/", "aud": "myclient", "sub": "alice",
            "exp": 9999999999, "nbf": 0, "iat": 0, "kid": "2",
        }).encode())
        token = "%s.%s.%s" % (header, payload, b64u(b"not-the-real-signature"))
        status, _ = request(p, extra_headers="Authorization: Bearer %s\r\n" % token)
        check(status == 401, "wrong signature -> 401, not 200 (status=%s)" % status)
        status, _ = request(p, path="/api/ping")
        check(status == 200, "server still serves normal requests afterwards (status=%s)" % status)

        print("\n[Critical] JWT algorithm/key confusion: HS256 forged with an empty HMAC key")
        print("           against a ClientID registered only for asymmetric (PS256) tokens")
        # "pubclient" is registered with a PubKey and NO SigningSecret (see
        # test_auth_hardening_server.cpp). Before the fix, the guard that decided
        # whether a ClientID could be used at all only required "SigningSecret OR
        # PubKey non-empty" -- so this ClientID passed it -- and the token's own
        # "alg" header, HS256 here, was then trusted to pick
        # jwt::algorithm::hs256{signingsecret} with signingsecret == "". That is
        # forgeable by anyone, and "root_admin" is a real admin account, so this
        # token used to buy full administrative rights with no credentials at all.
        now = int(time.time())
        forged = forge_hs256_empty_key({
            "iss": "https://127.0.0.1/",
            "aud": "pubclient",
            "sub": "root_admin",
            "exp": now + 3600,
            "nbf": now - 60,
            "iat": now - 60,
        }, kid="3")
        status, body = request(p, extra_headers="Authorization: Bearer %s\r\n" % forged)
        check(status == 401,
              "empty-HMAC-key HS256 token naming an admin subject -> 401, not 200 (status=%s, body=%s)" % (status, body))
        check(not (body and body.get("rights") == 2),
              "...and admin rights (URIGHTS_ADMIN) are never granted either way (body=%s)" % body)
        status, _ = request(p, path="/api/ping")
        check(status == 200, "server still serves normal requests afterwards (status=%s)" % status)

        print("\n[baseline] the malformed-token requests above were actually rejected, not")
        print("           silently authenticated as some other user")
        # Re-confirms the no-header case still 401s after everything above, i.e. none
        # of the malformed tokens left the server in a state where it started
        # authenticating requests it shouldn't.
        status, _ = request(p)
        check(status == 401, "no Authorization header still -> 401 at the end of the run (status=%s)" % status)

    print("\n%d checks, %d failure(s)" % (CHECKS, FAILURES))
    return 0 if FAILURES == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
