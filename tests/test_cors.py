#!/usr/bin/env python3
"""End-to-end test: CORS headers must not turn the trusted-network auth bypass
into cross-origin data exfiltration, and WebSocket upgrades must validate Origin
for trusted-network-authenticated sessions.

The server under test (test_cors_server.cpp) trusts 127.0.0.1, exactly like
test_proxy_trust_server.cpp: every request below arrives already carrying admin
rights with no cookie at all (docs/INTEGRATION.md, "Trusted Networks"). Before
this fix, every API/page response also carried an unconditional
"Access-Control-Allow-Origin: *", which would let ANY website the user's browser
visited read that response. This test proves:

  - API/page responses (e.g. /json.htm) carry no CORS header by default;
  - an unlisted Origin still gets nothing;
  - a configured allow-list origin is echoed back exactly, with Vary: Origin;
  - static assets are unaffected (still unconditional ACAO: *);
  - a WebSocket upgrade from a foreign Origin is rejected for a trusted-network
    session, while a same-origin or allow-listed upgrade is accepted;
  - the same-origin check normalises the scheme's default port, so it matches
    whether the Host header elides ":80" or spells it out explicitly;
  - the policy is runtime-switchable via cWebem::SetCorsPolicy(): a "*" entry
    echoes any Origin (never a literal "*"), cors_allow_trusted_networks echoes
    IP-literal origins inside trusted ranges (hostnames never resolved), and
    tightening the policy again takes effect immediately.

Usage:
    python test_cors.py <path-to-test_cors_server[.exe]>
"""
import base64
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


def _recv_until_headers(s, deadline):
    buf = b""
    while time.time() < deadline:
        try:
            c = s.recv(4096)
        except socket.timeout:
            break
        if not c:
            break
        buf += c
        if b"\r\n\r\n" in buf:
            break
    return buf


def parse_response(buf):
    head, _, body = buf.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    status_line = lines[0].decode("latin-1") if lines and lines[0] else ""
    headers = {}
    for line in lines[1:]:
        if b":" in line:
            k, _, v = line.partition(b":")
            headers[k.decode("latin-1").strip().lower()] = v.decode("latin-1").strip()
    return status_line, headers, body


def http_get(port, path, origin=None):
    """Plain GET, optionally with an Origin header. Returns (status_line, headers)."""
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    s.settimeout(5)
    lines = ["GET %s HTTP/1.1" % path, "Host: 127.0.0.1:%d" % port]
    if origin is not None:
        lines.append("Origin: %s" % origin)
    lines.append("Connection: close")
    req = "\r\n".join(lines) + "\r\n\r\n"
    s.sendall(req.encode())
    buf = _recv_until_headers(s, time.time() + 5)
    # Drain whatever's left of the body (best effort; not needed for header checks).
    try:
        while True:
            c = s.recv(4096)
            if not c:
                break
            buf += c
    except socket.timeout:
        pass
    s.close()
    status_line, headers, _ = parse_response(buf)
    return status_line, headers


def ws_handshake_status(port, path, origin, host_header=None):
    """Send a WebSocket upgrade handshake with the given Origin (or none, if
    origin is None) and return just the HTTP status line of the response --
    "101 Switching Protocols" on success, something else (400/403) on rejection.

    host_header overrides the Host header sent, independent of the socket's
    actual port -- OriginMatchesRequestHost compares Origin against the Host
    header's text, not the real endpoint, so this is what lets the port-
    normalisation checks below exercise it without needing a real listener
    on port 80.
    """
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    s.settimeout(5)
    key = base64.b64encode(os.urandom(16)).decode()
    lines = [
        "GET %s HTTP/1.1" % path,
        "Host: %s" % (host_header if host_header is not None else "127.0.0.1:%d" % port),
        "Connection: Upgrade",
        "Upgrade: websocket",
    ]
    if origin is not None:
        lines.append("Origin: %s" % origin)
    lines.append("Sec-WebSocket-Version: 13")
    lines.append("Sec-WebSocket-Key: %s" % key)
    req = "\r\n".join(lines) + "\r\n\r\n"
    s.sendall(req.encode())
    buf = _recv_until_headers(s, time.time() + 5)
    s.close()
    status_line, _, _ = parse_response(buf)
    return status_line


def main():
    if len(sys.argv) < 2:
        print("usage: %s <path-to-test_cors_server>" % sys.argv[0])
        return 2
    exe = sys.argv[1]
    if not os.path.exists(exe):
        print("server binary not found: %s" % exe)
        return 2

    with Server(exe) as srv:
        p = srv.port
        api_path = "/json.htm?type=command&param=getsettings"

        print("\n[baseline] /json.htm with no Origin header carries no CORS header")
        status, headers = http_get(p, api_path)
        check(status.startswith("HTTP/1.1 200"), "baseline /json.htm succeeds (status=%r)" % status)
        check("access-control-allow-origin" not in headers,
              "no Origin header -> no Access-Control-Allow-Origin on /json.htm")

        print("\n[unlisted origin] cross-origin GET to /json.htm gets no CORS header")
        status, headers = http_get(p, api_path, origin="https://evil.com")
        check(status.startswith("HTTP/1.1 200"), "request still succeeds (status=%r)" % status)
        check("access-control-allow-origin" not in headers,
              "unlisted Origin (evil.com) does NOT get Access-Control-Allow-Origin")

        print("\n[allow-listed origin] listed origin is echoed exactly, with Vary: Origin")
        status, headers = http_get(p, api_path, origin="https://allowed.example.com")
        check(headers.get("access-control-allow-origin") == "https://allowed.example.com",
              "listed Origin is echoed exactly (got %r)" % headers.get("access-control-allow-origin"))
        check(headers.get("vary") == "Origin",
              "Vary: Origin is present (got %r)" % headers.get("vary"))

        print("\n[static asset] unaffected: still served with Access-Control-Allow-Origin: *")
        status, headers = http_get(p, "/asset.txt", origin="https://evil.com")
        check(status.startswith("HTTP/1.1 200"), "static asset request succeeds (status=%r)" % status)
        check(headers.get("access-control-allow-origin") == "*",
              "static asset still carries ACAO: * (got %r)" % headers.get("access-control-allow-origin"))

        print("\n[websocket] same-origin upgrade on a trusted-network session is accepted")
        status = ws_handshake_status(p, "/ws/echo", "http://127.0.0.1:%d" % p)
        check(status.startswith("HTTP/1.1 101"), "same-origin upgrade accepted (status=%r)" % status)

        print("\n[websocket] foreign-origin upgrade on a trusted-network session is rejected")
        status = ws_handshake_status(p, "/ws/echo", "https://evil.com")
        check(not status.startswith("HTTP/1.1 101"),
              "cross-origin upgrade from an unlisted origin is rejected (status=%r)" % status)

        print("\n[websocket] allow-listed cross-origin upgrade is accepted")
        status = ws_handshake_status(p, "/ws/echo", "https://allowed.example.com")
        check(status.startswith("HTTP/1.1 101"),
              "cross-origin upgrade from an allow-listed origin is accepted (status=%r)" % status)

        print("\n[websocket] same-origin upgrade matches when the Host header elides "
              "the default port (Host: example.com, Origin: http://example.com)")
        status = ws_handshake_status(p, "/ws/echo", "http://example.com", host_header="example.com")
        check(status.startswith("HTTP/1.1 101"),
              "elided-port Host still matches Origin with no port (status=%r)" % status)

        print("\n[websocket] same-origin upgrade matches when the Host header spells "
              "out the default port explicitly (Host: example.com:80, Origin: "
              "http://example.com)")
        status = ws_handshake_status(p, "/ws/echo", "http://example.com", host_header="example.com:80")
        check(status.startswith("HTTP/1.1 101"),
              "explicit ':80' Host still matches Origin with the port elided (status=%r)" % status)

        # ---- runtime policy switches (cWebem::SetCorsPolicy) ----------------

        def set_policy(origins, trusted):
            s, _ = http_get(p, "/setcors.htm?origins=%s&trusted=%d" % (origins, trusted))
            if not s.startswith("HTTP/1.1 200"):
                raise RuntimeError("setcors failed: %r" % s)

        print("\n['*' opt-out] a single '*' entry echoes ANY Origin (never a literal '*')")
        set_policy("*", 0)
        status, headers = http_get(p, api_path, origin="https://evil.com")
        check(headers.get("access-control-allow-origin") == "https://evil.com",
              "'*' policy echoes the request Origin exactly (got %r)" % headers.get("access-control-allow-origin"))
        check(headers.get("vary") == "Origin",
              "'*' policy still sends Vary: Origin (got %r)" % headers.get("vary"))
        status = ws_handshake_status(p, "/ws/echo", "https://evil.com")
        check(status.startswith("HTTP/1.1 101"),
              "'*' policy also admits the cross-origin WebSocket upgrade (status=%r)" % status)

        print("\n[trusted-network origins] IP-literal origin inside a trusted range is echoed")
        set_policy("", 1)
        status, headers = http_get(p, api_path, origin="http://127.0.0.1:8082")
        check(headers.get("access-control-allow-origin") == "http://127.0.0.1:8082",
              "origin with a trusted-range IP host is echoed (got %r)" % headers.get("access-control-allow-origin"))
        check(headers.get("vary") == "Origin",
              "trusted-network echo sends Vary: Origin (got %r)" % headers.get("vary"))
        status, headers = http_get(p, api_path, origin="http://192.168.1.5:8082")
        check("access-control-allow-origin" not in headers,
              "IP origin outside the trusted ranges gets no CORS header")
        status, headers = http_get(p, api_path, origin="http://localhost:8082")
        check("access-control-allow-origin" not in headers,
              "hostname origin is never resolved against trusted ranges, so no CORS header")
        status = ws_handshake_status(p, "/ws/echo", "http://127.0.0.1:8082",
                                     host_header="127.0.0.1:%d" % p)
        check(status.startswith("HTTP/1.1 101"),
              "trusted-range origin also admits the WebSocket upgrade (status=%r)" % status)

        print("\n[policy restore] tightening the policy again takes effect immediately")
        set_policy("https://allowed.example.com", 0)
        status, headers = http_get(p, api_path, origin="https://evil.com")
        check("access-control-allow-origin" not in headers,
              "after restore, an unlisted Origin gets no CORS header again")
        status, headers = http_get(p, api_path, origin="https://allowed.example.com")
        check(headers.get("access-control-allow-origin") == "https://allowed.example.com",
              "after restore, the listed Origin is still echoed (got %r)" % headers.get("access-control-allow-origin"))

    print("\n%d checks, %d failure(s)" % (CHECKS, FAILURES))
    return 0 if FAILURES == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
