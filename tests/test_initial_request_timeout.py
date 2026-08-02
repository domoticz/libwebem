#!/usr/bin/env python3
"""End-to-end test: a connection that never completes its first HTTP request
must be dropped near server_settings::initial_request_timeout, not held open
for the life of read_timeout (fixed at 20s) or the 20-minute
abandoned-connection timeout.

Before initial_request_timeout existed, a connection was bound only by
read_timeout -- reset by EVERY byte received, complete request or not -- so a
client trickling a single byte slightly more often than read_timeout could
hold a global connection slot (see server_settings::max_connections)
indefinitely without ever completing a request: the slowloris pattern.
initial_request_timeout closes that: started once reading begins, and never
reset by individual bytes -- only by a request actually completing.

This drives a real listener over loopback TCP and checks two connections:
  - one that sends nothing at all
  - one that trickles a single byte at a time, slowly enough that it never
    completes a request, but fast enough that it would keep resetting
    read_timeout indefinitely if that were the only bound in play
Both must be dropped close to the configured (short, test-only)
initial_request_timeout, not near read_timeout or later.

Usage:
    python test_initial_request_timeout.py <path-to-test_initial_request_timeout_server[.exe]>
"""
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
    def __init__(self, exe, timeout_secs):
        self.port = free_port()
        exe = os.path.abspath(exe)
        self.proc = subprocess.Popen(
            [exe, str(self.port), str(timeout_secs)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1, cwd=os.path.dirname(exe))
        deadline = time.time() + 20
        while time.time() < deadline:
            line = self.proc.stdout.readline()
            if not line:
                break
            if line.startswith("READY"):
                time.sleep(0.3)  # let the acceptor arm
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


def http_ping(port, timeout=5.0):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout) as s:
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


def _wait_for_close(sock, max_wait):
    """Seconds elapsed until the peer closes, or None if still open after max_wait."""
    started = time.time()
    sock.settimeout(max_wait + 2)
    try:
        data = sock.recv(4096)
        if data == b"":
            return time.time() - started
    except (socket.timeout, ConnectionResetError, OSError):
        return time.time() - started
    return None


def test_silent_connection_dropped_near_timeout(exe):
    print("\n[initial request timeout] a connection that never sends anything must be "
          "dropped near the configured timeout, not near read_timeout (fixed at 20s)")
    TIMEOUT_SECS = 3
    # Generous windows around the configured timeout: must survive at least a
    # little while (proves it isn't some unrelated, immediate rejection) and
    # must not survive much longer -- in particular must stay comfortably
    # under read_timeout's fixed 20s, or this cannot tell "the new timer
    # fired" apart from "the old one eventually did, same as always".
    MIN_SURVIVAL = TIMEOUT_SECS * 0.4
    MAX_SURVIVAL = TIMEOUT_SECS + 8.0

    with Server(exe, TIMEOUT_SECS) as srv:
        check(http_ping(srv.port), "baseline request succeeds before the test")

        s = socket.create_connection(("127.0.0.1", srv.port), timeout=MAX_SURVIVAL + 5)
        closed_after = _wait_for_close(s, MAX_SURVIVAL)
        s.close()

        check(closed_after is not None,
              "server closed the silent connection instead of holding it open")
        if closed_after is not None:
            check(closed_after >= MIN_SURVIVAL,
                  "connection survived at least %.1fs before being dropped (got %.2fs) -- "
                  "too fast would mean something else killed it" % (MIN_SURVIVAL, closed_after))
            check(closed_after <= MAX_SURVIVAL,
                  "connection was dropped within %.1fs of the %ds timeout (got %.2fs) -- "
                  "too slow means read_timeout (20s) or the abandoned timeout is what "
                  "actually closed it, not the fix under test" %
                  (MAX_SURVIVAL, TIMEOUT_SECS, closed_after))

        check(srv.alive(), "server process is still running")
        check(http_ping(srv.port), "server still serves real requests after the timeout fired")


def test_slow_trickle_still_dropped_near_timeout(exe):
    print("\n[initial request timeout] a connection trickling bytes one at a time (never "
          "completing a request) must still be dropped near the configured timeout -- "
          "proving the new timer, unlike read_timeout, is NOT reset by individual bytes")
    TIMEOUT_SECS = 3
    MAX_SURVIVAL = TIMEOUT_SECS + 8.0

    with Server(exe, TIMEOUT_SECS) as srv:
        s = socket.create_connection(("127.0.0.1", srv.port), timeout=MAX_SURVIVAL + 5)
        s.settimeout(MAX_SURVIVAL + 5)
        started = time.time()
        closed_after = None
        # Trickle a single request-line byte roughly once a second: activity
        # that would keep resetting read_timeout (20s) indefinitely if that
        # were the only bound in play, but never completes a request (the
        # request line alone is never terminated by \r\n).
        try:
            for ch in b"GET / HTTP/1.1\r\n":
                if time.time() - started > MAX_SURVIVAL:
                    break
                s.sendall(bytes([ch]))
                time.sleep(1.0)
        except (BrokenPipeError, ConnectionResetError, OSError):
            closed_after = time.time() - started

        if closed_after is None:
            remaining = MAX_SURVIVAL - (time.time() - started)
            closed_after = _wait_for_close(s, max(remaining, 0.5))
        s.close()

        check(closed_after is not None,
              "server closed the trickling connection instead of holding it open")
        if closed_after is not None:
            check(closed_after <= MAX_SURVIVAL,
                  "trickling connection was dropped within %.1fs of the %ds timeout "
                  "(got %.2fs) -- too slow means byte-by-byte activity kept it alive "
                  "past initial_request_timeout, defeating the fix" %
                  (MAX_SURVIVAL, TIMEOUT_SECS, closed_after))

        check(srv.alive(), "server process is still running")
        check(http_ping(srv.port), "server still serves real requests after the timeout fired")


def main():
    if len(sys.argv) < 2:
        print("usage: %s <path-to-test_initial_request_timeout_server>" % sys.argv[0])
        return 2
    exe = sys.argv[1]
    if not os.path.exists(exe):
        print("server binary not found: %s" % exe)
        return 2

    test_silent_connection_dropped_near_timeout(exe)
    test_slow_trickle_still_dropped_near_timeout(exe)

    print("\n%d checks, %d failure(s)" % (CHECKS, FAILURES))
    return 0 if FAILURES == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
