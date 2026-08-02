#!/usr/bin/env python3
"""The listener must survive accept-time errors and keep accepting.

The accept loop used to re-arm itself only on the SUCCESS path, so a single accept
error left the server permanently unable to accept new connections -- silently. The
process stayed alive (its heartbeat timer keeps io_context::run() busy) and existing
connections kept working, so it looked healthy while being unreachable. Recovery
needed a restart.

The two realistic triggers are fd exhaustion (EMFILE) and a client that resets the
connection before it is accepted (ECONNABORTED). Reset storms are the one an
unprivileged remote attacker can drive at will, so that is what this exercises.

Reuses the configurable server from test_connection_limits_server.cpp for its
/api/ping endpoint; nothing here depends on the limits it takes on argv.

Usage:
    python test_accept_resilience.py <path-to-test_connection_limits_server[.exe]>
"""
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
    def __init__(self, exe, max_conn=1000, max_reqs=100000):
        self.port = free_port()
        exe = os.path.abspath(exe)
        self.proc = subprocess.Popen(
            [exe, str(self.port), str(max_conn), str(max_reqs), str(8 << 20), "10"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
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


def ping(port, timeout=5.0):
    """One complete request/response. True if the server answered."""
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


def abortive_connect(port):
    """Connect then send RST, the way a client aborting mid-handshake does.

    SO_LINGER with a zero timeout makes close() emit RST instead of FIN, which is
    what provokes ECONNABORTED on the server's accept().

    CAVEAT: this is reliable on Linux/BSD but NOT on Windows, where the stack may
    report a different error or none at all. On Windows this test therefore proves
    only that the listener survives the storm, not that the error branch was taken.
    test_survives_repeated_cap_refusals below is the platform-independent companion:
    it drives the accept loop through hundreds of accept/refuse cycles regardless.
    """
    try:
        s = socket.socket()
        s.settimeout(2.0)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        s.connect(("127.0.0.1", port))
        s.close()
    except Exception:
        pass


def test_survives_reset_storm(exe):
    print("\n[reset storm] 300 abortive connections, then the server must still serve")
    with Server(exe) as srv:
        check(ping(srv.port), "baseline request succeeds before the storm")

        for _ in range(300):
            abortive_connect(srv.port)
        time.sleep(1.0)   # let any backoff retry elapse

        check(srv.alive(), "server process is still running")
        check(ping(srv.port), "server still accepts new connections after the storm")
        # Not a one-off: the loop must keep going, not survive exactly once.
        ok = all(ping(srv.port) for _ in range(10))
        check(ok, "10 consecutive requests all succeed after the storm")


def test_survives_repeated_cap_refusals(exe):
    """Hitting the connection cap must not disturb the accept loop either."""
    print("\n[cap churn] repeatedly exceed a tiny connection cap, then serve normally")
    CAP = 3
    with Server(exe, max_conn=CAP) as srv:
        for _ in range(20):
            held = []
            for _ in range(CAP + 3):     # 3 accepted, 3 refused, every round
                try:
                    held.append(socket.create_connection(("127.0.0.1", srv.port), timeout=2))
                except Exception:
                    pass
            for s in held:
                try:
                    s.close()
                except Exception:
                    pass
            time.sleep(0.02)

        time.sleep(0.5)
        check(srv.alive(), "server process is still running")
        check(ping(srv.port), "server still serves after 20 rounds of cap refusals")


def main():
    if len(sys.argv) < 2:
        print("usage: %s <path-to-test_connection_limits_server>" % sys.argv[0])
        return 2
    exe = sys.argv[1]
    if not os.path.exists(exe):
        print("server binary not found: %s" % exe)
        return 2

    test_survives_reset_storm(exe)
    test_survives_repeated_cap_refusals(exe)

    print("\n%d checks, %d failure(s)" % (CHECKS, FAILURES))
    return 0 if FAILURES == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
