#!/usr/bin/env python3
"""End-to-end test: server_settings::allowed_hosts must close DNS rebinding
against the WebSocket trusted-network same-origin check.

The server under test (test_dns_rebinding_server.cpp) trusts 127.0.0.1 (the
same reverse-proxy-on-localhost deployment shape as test_cors_server.cpp) and
configures allowed_hosts = ["127.0.0.1", "legit.example.com"].

Before this fix, the WebSocket same-origin check just compared the
handshake's Origin header against the request's own (otherwise unvalidated,
on a plain-HTTP listener with no vhostname) Host header -- which always agree
for a genuine browser request, but agree just as trivially for a hostname an
attacker controls: serve a page from a short-TTL DNS name, wait for a
trusted-network browser to load and cache it, then re-point that name at this
server's LAN address. The next request the browser makes carries Origin ==
Host == the attacker's chosen hostname.

This test simulates that by sending requests with an explicit Host header
independent of the real destination (exactly what DNS rebinding achieves for
a real browser, and the same technique test_cors.py's ws_handshake_status
helper uses) naming a hostname NOT in allowed_hosts, and checks it is
rejected -- both for a plain request (Host validated by cWebem::CheckVHost on
every request, not just WebSocket upgrades) and for the WebSocket upgrade
itself.

Usage:
    python test_dns_rebinding.py <path-to-test_dns_rebinding_server[.exe]>
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


def parse_status(buf):
    head, _, _ = buf.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    return lines[0].decode("latin-1") if lines and lines[0] else ""


def http_get_status(port, path, host_header):
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    s.settimeout(5)
    req = "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % (path, host_header)
    s.sendall(req.encode())
    buf = _recv_until_headers(s, time.time() + 5)
    s.close()
    return parse_status(buf)


def ws_handshake_status(port, path, origin, host_header):
    """Send a WebSocket upgrade handshake with an explicit Host header,
    independent of the socket's real destination -- exactly what DNS
    rebinding achieves for a real browser -- and return the HTTP status
    line: "101 Switching Protocols" on success, something else on rejection.
    """
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    s.settimeout(5)
    key = base64.b64encode(os.urandom(16)).decode()
    lines = [
        "GET %s HTTP/1.1" % path,
        "Host: %s" % host_header,
        "Connection: Upgrade",
        "Upgrade: websocket",
        "Origin: %s" % origin,
        "Sec-WebSocket-Version: 13",
        "Sec-WebSocket-Key: %s" % key,
    ]
    req = "\r\n".join(lines) + "\r\n\r\n"
    s.sendall(req.encode())
    buf = _recv_until_headers(s, time.time() + 5)
    s.close()
    return parse_status(buf)


def main():
    if len(sys.argv) < 2:
        print("usage: %s <path-to-test_dns_rebinding_server>" % sys.argv[0])
        return 2
    exe = sys.argv[1]
    if not os.path.exists(exe):
        print("server binary not found: %s" % exe)
        return 2

    with Server(exe) as srv:
        p = srv.port
        api_path = "/json.htm?type=command&param=getsettings"

        print("\n[baseline] plain request with an allow-listed Host succeeds")
        status = http_get_status(p, api_path, "127.0.0.1:%d" % p)
        check(status.startswith("HTTP/1.1 200"), "allow-listed Host succeeds (status=%r)" % status)

        print("\n[DNS rebinding, plain request] an unlisted Host is rejected on EVERY "
              "request, not just WebSocket upgrades")
        status = http_get_status(p, api_path, "rebind.evil.com")
        check(status.startswith("HTTP/1.1 400"),
              "unlisted Host is rejected with 400 (status=%r)" % status)

        print("\n[baseline] same-origin WebSocket upgrade with an allow-listed "
              "Host/Origin pair is accepted")
        status = ws_handshake_status(p, "/ws/echo", "http://127.0.0.1:%d" % p, "127.0.0.1:%d" % p)
        check(status.startswith("HTTP/1.1 101"), "allow-listed upgrade accepted (status=%r)" % status)

        print("\n[DNS rebinding, WebSocket] Host and Origin both reading the attacker's "
              "chosen (unlisted) hostname must NOT be treated as same-origin")
        status = ws_handshake_status(p, "/ws/echo", "http://rebind.evil.com", "rebind.evil.com")
        check(not status.startswith("HTTP/1.1 101"),
              "rebinding attempt (Host==Origin==unlisted hostname) is rejected, not "
              "granted a trusted-network WebSocket (status=%r)" % status)
        check(status.startswith("HTTP/1.1 400"),
              "rejected specifically by the Host allow-list check (400), before "
              "authentication (and the WebSocket Origin check) is even reached "
              "(status=%r)" % status)

    print("\n%d checks, %d failure(s)" % (CHECKS, FAILURES))
    return 0 if FAILURES == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
