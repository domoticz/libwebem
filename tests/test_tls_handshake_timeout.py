#!/usr/bin/env python3
"""End-to-end test: a client that opens a TCP connection to an HTTPS listener
but never completes (or never starts) the TLS handshake must be dropped after
tls_handshake_timeout, not held open indefinitely.

Before tls_handshake_timeout existed, a connection that completed the TCP
three-way handshake and then went silent was bound only by the 20-minute
abandoned-connection timeout -- a modest flood of clients doing exactly that
could pin a socket, an SSL stream and several timers each for a very long
time. This drives a real listener over loopback TCP, connects without ever
sending a TLS ClientHello, and asserts the server actually closes the
connection close to the configured (short, test-only) timeout: neither
immediately (which would suggest something else killed it) nor left hanging
well past it (which would mean the timeout did nothing and the 20-minute
abandoned timer is the only backstop again).

Usage:
    python test_tls_handshake_timeout.py <path-to-test_tls_handshake_timeout_server[.exe]> <cert_file> <key_file>
"""
import os
import socket
import ssl
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
    def __init__(self, exe, timeout_secs, cert_file, key_file):
        self.port = free_port()
        exe = os.path.abspath(exe)
        self.proc = subprocess.Popen(
            [exe, str(self.port), str(timeout_secs), cert_file, key_file],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1, cwd=os.path.dirname(exe))
        deadline = time.time() + 20
        while time.time() < deadline:
            line = self.proc.stdout.readline()
            if not line:
                break
            if line.startswith("READY"):
                time.sleep(0.3)   # let the acceptor arm
                return
        raise RuntimeError("server did not become ready")

    def alive(self):
        return self.proc.poll() is None

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


def tls_ping(port, timeout=5.0):
    """A real TLS handshake plus one HTTP request. True if the server answered 200."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname="127.0.0.1") as s:
                s.settimeout(timeout)
                s.sendall(b"GET /api/ping HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
                buf = b""
                while b"\r\n\r\n" not in buf:
                    c = s.recv(4096)
                    if not c:
                        break
                    buf += c
                return buf.startswith(b"HTTP/1.1 200")
    except Exception:
        return False


def test_silent_connection_dropped_at_timeout(exe, cert_file, key_file):
    print("\n[tls handshake timeout] a connection that never sends a ClientHello "
          "must be dropped near the configured timeout")
    TIMEOUT_SECS = 2
    # Generous windows around the configured timeout: must survive at least a
    # little while (proves it isn't some unrelated, immediate rejection) and
    # must not survive much longer (proves the bound is actually enforced,
    # not just accepted as a setting and ignored).
    MIN_SURVIVAL = TIMEOUT_SECS * 0.4
    MAX_SURVIVAL = TIMEOUT_SECS + 8.0

    with Server(exe, TIMEOUT_SECS, cert_file, key_file) as srv:
        check(tls_ping(srv.port), "baseline HTTPS request succeeds before the test")

        s = socket.create_connection(("127.0.0.1", srv.port), timeout=MAX_SURVIVAL + 5)
        s.settimeout(MAX_SURVIVAL + 5)
        started = time.time()
        # Deliberately send nothing -- not even a partial TLS record -- and
        # just wait for the server to give up on us.
        closed_after = None
        try:
            data = s.recv(4096)
            if data == b"":
                closed_after = time.time() - started
        except (socket.timeout, ConnectionResetError, OSError):
            closed_after = time.time() - started
        finally:
            s.close()

        check(closed_after is not None,
              "server closed the silent connection instead of holding it open (no data ever sent)")
        if closed_after is not None:
            check(closed_after >= MIN_SURVIVAL,
                  "connection survived at least %.1fs before being dropped (got %.2fs) -- "
                  "too fast would mean something else killed it" % (MIN_SURVIVAL, closed_after))
            check(closed_after <= MAX_SURVIVAL,
                  "connection was dropped within %.1fs of the %ds timeout (got %.2fs) -- "
                  "too slow would mean the timeout isn't actually enforced" %
                  (MAX_SURVIVAL, TIMEOUT_SECS, closed_after))

        check(srv.alive(), "server process is still running")
        check(tls_ping(srv.port), "server still serves real HTTPS requests after the timeout fired")
        # A well-behaved client that completes the handshake promptly must
        # never be affected by the same bound.
        ok = all(tls_ping(srv.port) for _ in range(5))
        check(ok, "5 consecutive well-behaved HTTPS requests all succeed")


def main():
    if len(sys.argv) < 4:
        print("usage: %s <path-to-test_tls_handshake_timeout_server> <cert_file> <key_file>" % sys.argv[0])
        return 2
    exe, cert_file, key_file = sys.argv[1], sys.argv[2], sys.argv[3]
    if not os.path.exists(exe):
        print("server binary not found: %s" % exe)
        return 2
    if not os.path.exists(cert_file) or not os.path.exists(key_file):
        print("cert/key file not found: %s / %s" % (cert_file, key_file))
        return 2

    test_silent_connection_dropped_at_timeout(exe, cert_file, key_file)

    print("\n%d checks, %d failure(s)" % (CHECKS, FAILURES))
    return 0 if FAILURES == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
