#!/usr/bin/env python3
"""Integration tests for the connection resource limits.

Covers: global connection cap, per-address cap (and its disabled-by-default
behaviour), the per-connection HTTP request budget, the write-queue bound
that drops a client which stops reading a push feed, and a POST body
delivered across many separate, delayed TCP writes (see
test_post_body_dribbled_across_reads).

Drives the real server binary (tests/test_connection_limits_server.cpp) over
loopback TCP. Unlike the unit tests in test_security.cpp, these exercise the full
connection lifecycle: accept -> request budget -> teardown.

Usage:
    python test_connection_limits.py <path-to-test_connection_limits_server[.exe]>
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
    if cond:
        print("  PASS  %s" % label)
    else:
        FAILURES += 1
        print("  FAIL  %s" % label)
    return bool(cond)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class Server:
    """Launch the test server and wait for its READY line."""

    def __init__(self, exe, max_conn, max_reqs, max_wq, tls_to):
        self.port = free_port()
        exe = os.path.abspath(exe)   # cwd is changed below, so this must be absolute
        self.proc = subprocess.Popen(
            [exe, str(self.port), str(max_conn), str(max_reqs), str(max_wq), str(tls_to)],
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


def connect(port, timeout=5.0):
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    s.settimeout(timeout)
    return s


GET = ("GET /api/ping HTTP/1.1\r\n"
       "Host: 127.0.0.1\r\n"
       "Connection: Keep-Alive\r\n"
       "\r\n")


def read_one_response(sock):
    """Read exactly one HTTP response (headers + Content-Length body)."""
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            return None
        buf += chunk
    head, _, rest = buf.partition(b"\r\n\r\n")
    clen = 0
    for line in head.split(b"\r\n")[1:]:
        if line.lower().startswith(b"content-length:"):
            clen = int(line.split(b":", 1)[1].strip())
    while len(rest) < clen:
        chunk = sock.recv(4096)
        if not chunk:
            break
        rest += chunk
    return head.decode("latin-1")


def read_full_response(sock, timeout):
    """Like read_one_response(), but also hands back the body bytes.

    read_one_response() above only returns the headers, which is all the
    other tests in this file need; test_post_body_dribbled_across_reads()
    below needs to verify the body it gets back is byte-for-byte what it
    sent, so it uses this instead.
    """
    sock.settimeout(timeout)
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(65536)
        if not chunk:
            return None, None
        buf += chunk
    head, _, rest = buf.partition(b"\r\n\r\n")
    clen = 0
    for line in head.split(b"\r\n")[1:]:
        if line.lower().startswith(b"content-length:"):
            clen = int(line.split(b":", 1)[1].strip())
    while len(rest) < clen:
        chunk = sock.recv(65536)
        if not chunk:
            break
        rest += chunk
    return head.decode("latin-1"), rest[:clen]


# ---------------------------------------------------------------------------


def test_request_budget(exe):
    """max_requests_per_connection must close the keep-alive connection."""
    print("\n[request budget] max_requests_per_connection = 5")
    BUDGET = 5
    with Server(exe, 100, BUDGET, 8 << 20, 10) as srv:
        s = connect(srv.port)
        served = 0
        advertised = None
        try:
            for _ in range(BUDGET + 3):
                s.sendall(GET.encode())
                head = read_one_response(s)
                if head is None:
                    break
                served += 1
                for line in head.split("\r\n"):
                    if line.lower().startswith("keep-alive:"):
                        # Header looks like "Keep-Alive: max=5, timeout=20"
                        for part in line.split(":", 1)[1].split(","):
                            k, _, v = part.strip().partition("=")
                            if k == "max":
                                advertised = v.strip()
        except (socket.timeout, ConnectionResetError, BrokenPipeError, OSError):
            pass
        finally:
            s.close()

        check(served == BUDGET,
              "served exactly %d requests then closed (got %d)" % (BUDGET, served))
        check(advertised == str(BUDGET),
              "advertised 'Keep-Alive: max=%d' (got %r)" % (BUDGET, advertised))


def test_global_connection_cap(exe):
    """max_connections must refuse the excess, and recover once slots free."""
    print("\n[global cap] max_connections = 5")
    CAP = 5
    with Server(exe, CAP, 1000, 8 << 20, 10) as srv:
        live, refused = [], 0
        for _ in range(CAP + 4):
            try:
                s = connect(srv.port, timeout=3.0)
                s.sendall(GET.encode())
                head = read_one_response(s)
                if head and head.startswith("HTTP/1.1 200"):
                    live.append(s)
                else:
                    refused += 1
                    s.close()
            except (socket.timeout, ConnectionResetError, OSError):
                refused += 1

        check(len(live) == CAP, "exactly %d connections served (got %d)" % (CAP, len(live)))
        check(refused == 4, "the 4 excess connections were refused (got %d)" % refused)

        # Free one slot; a new connection must now be admitted.
        live.pop().close()
        time.sleep(0.5)
        ok = False
        try:
            s = connect(srv.port, timeout=3.0)
            s.sendall(GET.encode())
            head = read_one_response(s)
            ok = bool(head and head.startswith("HTTP/1.1 200"))
            s.close()
        except Exception:
            ok = False
        check(ok, "a slot freed by a closed connection is reusable")

        for s in live:
            s.close()


def test_per_ip_disabled_by_default(exe):
    """The shipped default (0) must NOT throttle many connections from one address.

    This is the reverse-proxy regression: every connection through a proxy shares
    the proxy's address, so a non-zero default would cap the whole server.
    """
    print("\n[per-IP default] max_connections_per_ip = 0 (shipped default)")
    N = 25
    with Server(exe, 1000, 1000, 8 << 20, 10) as srv:
        live = []
        for _ in range(N):
            try:
                s = connect(srv.port, timeout=3.0)
                s.sendall(GET.encode())
                head = read_one_response(s)
                if head and head.startswith("HTTP/1.1 200"):
                    live.append(s)
                else:
                    s.close()
            except Exception:
                pass
        check(len(live) == N,
              "all %d connections from one address were served (got %d)" % (N, len(live)))
        for s in live:
            s.close()


def test_write_queue_bound(exe):
    """A client that stops reading a push feed must be dropped, not buffered."""
    print("\n[write queue] max_write_queue_bytes = 256 KiB, client stops reading")
    with Server(exe, 100, 1000, 256 * 1024, 10) as srv:
        s = connect(srv.port, timeout=10.0)
        s.sendall(("GET /api/flood HTTP/1.1\r\n"
                   "Host: 127.0.0.1\r\n"
                   "Connection: Keep-Alive\r\n"
                   "\r\n").encode())
        # Read only the SSE headers, then deliberately stop reading so the socket
        # receive window closes and the server's write queue starts growing.
        buf = b""
        try:
            while b"\r\n\r\n" not in buf:
                c = s.recv(1024)
                if not c:
                    break
                buf += c
        except socket.timeout:
            pass
        check(b"text/event-stream" in buf.lower(), "SSE stream established")

        # Shrink our receive buffer so the window closes quickly, then idle.
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        except OSError:
            pass
        time.sleep(6.0)

        # The server should have hit the bound and closed. Drain whatever was
        # buffered locally; EOF within the timeout means the server dropped us.
        closed = False
        s.settimeout(8.0)
        try:
            while True:
                c = s.recv(65536)
                if not c:
                    closed = True
                    break
        except socket.timeout:
            closed = False
        except (ConnectionResetError, OSError):
            closed = True
        s.close()
        check(closed, "server closed the connection instead of buffering without limit")


def test_post_body_dribbled_across_reads(exe):
    """A POST body delivered in many small, delayed TCP writes must still be
    parsed completely and correctly -- not hang until the read-idle timeout,
    and not come back truncated or corrupted.

    Regression test for the incremental-parsing resumption path: a parser
    state that fast-forwards past body bytes it has not actually extracted,
    whenever a body does not arrive within a single handle_read callback,
    throws away the parser's only record of where the body started. Every
    request whose body spans more than one read -- routine for anything
    beyond a single TCP segment, not just a contrived edge case -- would then
    hang indefinitely instead of ever completing. Unit tests that feed the
    parser its whole input in one call (and the other checks in this file,
    whose bodies are small enough to always arrive in a single read) cannot
    see that; this test drives a real socket and deliberately dribbles the
    body across dozens of delayed writes to force it across several separate
    handle_read callbacks, the way a real client on a slow or congested link
    routinely would.
    """
    print("\n[body framing] POST body dribbled across many delayed TCP writes")
    CHUNK_BYTES = 250
    DELAY_SECS = 0.015
    body = os.urandom(20000)  # comfortably more than one TCP segment / read chunk

    with Server(exe, 100, 1000, 8 << 20, 10) as srv:
        s = connect(srv.port, timeout=10.0)
        try:
            # Disabling Nagle makes each small write go out as its own
            # segment instead of being coalesced, maximising the chance the
            # server sees the body split across several reads.
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass

        headers = ("POST /api/echo HTTP/1.1\r\n"
                   "Host: 127.0.0.1\r\n"
                   "Connection: Keep-Alive\r\n"
                   "Content-Length: %d\r\n"
                   "\r\n" % len(body)).encode()

        head, received = None, None
        try:
            s.sendall(headers)
            for i in range(0, len(body), CHUNK_BYTES):
                s.sendall(body[i:i + CHUNK_BYTES])
                time.sleep(DELAY_SECS)
            # Comfortably under the server's 20s read-idle timeout, but short
            # enough that a regression (the request never completing) fails
            # this test in seconds rather than tens of seconds.
            head, received = read_full_response(s, timeout=10.0)
        except (socket.timeout, ConnectionResetError, BrokenPipeError, OSError):
            pass
        finally:
            s.close()

    check(head is not None and head.startswith("HTTP/1.1 200"),
          "server responded instead of hanging until the read timeout (got %r)" %
          (head.split("\r\n")[0] if head else head))
    check(received == body,
          "echoed body matches exactly what was sent (%d bytes sent, %s bytes back)" %
          (len(body), "none" if received is None else len(received)))


def main():
    if len(sys.argv) < 2:
        print("usage: %s <path-to-test_connection_limits_server>" % sys.argv[0])
        return 2
    exe = sys.argv[1]
    if not os.path.exists(exe):
        print("server binary not found: %s" % exe)
        return 2

    test_request_budget(exe)
    test_global_connection_cap(exe)
    test_per_ip_disabled_by_default(exe)
    test_write_queue_bound(exe)
    test_post_body_dribbled_across_reads(exe)

    print("\n%d checks, %d failure(s)" % (CHECKS, FAILURES))
    return 0 if FAILURES == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
