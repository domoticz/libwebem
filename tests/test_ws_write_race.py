#!/usr/bin/env python3
"""Stress test for the WS_Write-vs-connection::stop() socket race.

Background: WS_Write()/WS_WriteBinary()/MyWrite() are, by design, callable from
arbitrary application threads (the writer-callback pattern documented on the
public API and demonstrated in examples/03_websocket). Before the fix in
connection.h/connection.cpp (the strand_ member), those calls reached
boost::asio::async_write on the raw socket directly from whichever thread
called them -- with nothing to stop that racing connection::stop(), which the
io thread runs (closing the very same socket) whenever a connection drops,
e.g. because the client reset the TCP connection.

The server under test (test_ws_write_race_server.cpp) runs a background
thread that hammers WS_Write() on every live WebSocket connection as fast as
it can, completely independently of any connection's own io -- exactly the
"arbitrary application thread" scenario. This script opens many WebSocket
connections and aborts each one with a TCP RST (SO_LINGER 0, not a clean
FIN close) immediately after the upgrade completes, from several threads at
once, so the io thread is doing teardown while the pusher thread is very
likely mid-write on the same connection.

CAVEAT: MSVC has no ThreadSanitizer. A clean run here demonstrates "no
crash/hang under sustained concurrent load", not "the race is provably
closed" -- there is no way to prove absence of a data race from outside the
process without a sanitizer or a formal model. Treat this as a stress
regression test, not a correctness proof.

Usage:
    python test_ws_write_race.py <path-to-test_ws_write_race_server[.exe]>
"""
import base64
import concurrent.futures
import os
import socket
import struct
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


def ws_upgrade_request():
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    return (
        "GET /ws/push HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\n"
        "Connection: Upgrade\r\n"
        "Upgrade: websocket\r\n"
        "Origin: http://127.0.0.1\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "Sec-WebSocket-Key: %s\r\n"
        "\r\n" % key
    ).encode("ascii")


def ping(port, timeout=5.0):
    """One complete plain-HTTP request/response. True if the server answered."""
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        s.settimeout(timeout)
        s.sendall(b"GET /api/ping HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        buf = b""
        while b"\r\n\r\n" not in buf:
            c = s.recv(4096)
            if not c:
                break
            buf += c
        s.close()
        return buf.startswith(b"HTTP/1.1 200")
    except Exception:
        return False


def ws_connect_then_rst(port):
    """Upgrade to WebSocket, then abort with a TCP RST while the server-side
    pusher thread is (very likely) mid-write on this connection.

    SO_LINGER with a zero timeout makes close() emit RST instead of the
    normal FIN, so the io thread lands in handle_read's/handle_write's error
    branch -> connection_manager_.stop() -> connection::stop() -> socket
    close, exactly the teardown path the finding is about.
    """
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=3.0)
        s.settimeout(3.0)
        s.sendall(ws_upgrade_request())
        buf = b""
        while b"\r\n\r\n" not in buf and len(buf) < 4096:
            c = s.recv(4096)
            if not c:
                break
            buf += c
        # Don't bother validating the 101 here -- the point is to abort while
        # the connection is live, not to be a conformance test. Give the
        # pusher thread a moment to actually get a write in flight before we
        # pull the socket out from under it.
        time.sleep(0.001)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        s.close()
        return buf.startswith(b"HTTP/1.1 101")
    except Exception:
        return False


def ws_clean_round_trip(port, timeout=5.0):
    """Upgrade, confirm the server actually pushes data, then close cleanly."""
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        s.settimeout(timeout)
        s.sendall(ws_upgrade_request())
        buf = b""
        while b"\r\n\r\n" not in buf and len(buf) < 4096:
            c = s.recv(4096)
            if not c:
                return False
            buf += c
        if not buf.startswith(b"HTTP/1.1 101"):
            return False
        # The pusher thread sends every ~200us; a pushed frame should already
        # be waiting (or arrive within the timeout).
        pushed = s.recv(4096)
        s.close()
        return len(pushed) > 0
    except Exception:
        return False


def test_ws_write_race_storm(exe):
    print("\n[ws write race] hammer WS_Write from an application thread while "
          "aborting connections with RST")
    ROUNDS = 400
    WORKERS = 24
    with Server(exe) as srv:
        check(ping(srv.port), "baseline HTTP request succeeds before the storm")
        check(ws_clean_round_trip(srv.port), "baseline WebSocket round trip succeeds before the storm")

        upgraded = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as pool:
            results = list(pool.map(lambda _: ws_connect_then_rst(srv.port), range(ROUNDS)))
        upgraded = sum(1 for r in results if r)

        # Not every attempt has to reach 101 (this is a storm, some connects
        # can be refused/racy by design) but most should, or the storm isn't
        # actually exercising the WebSocket push path.
        check(upgraded > ROUNDS // 2,
              "most of the %d connections completed the WebSocket upgrade (got %d)" %
              (ROUNDS, upgraded))

        time.sleep(0.5)   # let any in-flight teardown/backoff settle

        check(srv.alive(), "server process is still running after the storm")
        check(ping(srv.port), "server still answers plain HTTP after the storm")
        check(ws_clean_round_trip(srv.port), "server still serves WebSocket connections after the storm")
        # Not a one-off: repeat to make sure the server didn't just limp back
        # for a single request.
        ok = all(ping(srv.port) for _ in range(10))
        check(ok, "10 consecutive HTTP requests all succeed after the storm")


def main():
    if len(sys.argv) < 2:
        print("usage: %s <path-to-test_ws_write_race_server>" % sys.argv[0])
        return 2
    exe = sys.argv[1]
    if not os.path.exists(exe):
        print("server binary not found: %s" % exe)
        return 2

    test_ws_write_race_storm(exe)

    print("\n%d checks, %d failure(s)" % (CHECKS, FAILURES))
    return 0 if FAILURES == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
