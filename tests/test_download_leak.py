#!/usr/bin/env python3
"""Deterministic regression test for the connection::handle_write_file leak.

Finding: send_buffer_ (a 16 KB std::unique_ptr<std::array<...>>) was released
via send_buffer_.release() instead of .reset() on every path out of
handle_write_file -- normal completion AND an aborted transfer both hit the
same line. release() relinquishes ownership without freeing, so every single
reply::download_file response leaked FILE_SEND_BUFFER_SIZE (16 KB), forever.

This drives many real download requests -- both to completion and aborted
partway through a multi-chunk transfer, matching the plan's own verification
recipe -- against a real server process and checks its own working-set
memory before and after. An unfixed build leaks roughly
(requests * 16 KB): thousands of requests make that tens of MB, which is
easily distinguished from ordinary allocator/connection-object churn (a few
MB at most). This is the "assert bounded memory" style of check; it does not
instrument individual new/delete pairs (there is no allocation hook exposed
across the process boundary this test drives the server over), so treat it as
strong evidence, not a formal proof that not a single byte leaks.

NOT covered here: the second half of the same finding, the bare `return;` on
a 0-byte read that isn't EOF (handle_write_file's old `bread <= 0` branch),
which used to skip connection_manager_.stop() entirely and strand the
connection until the 20-minute abandoned timer. Reproducing "the file becomes
unreadable mid-transfer without hitting EOF" deterministically from outside
the process would need OS-level trickery (e.g. racily truncating a file out
from under an open read handle), which is racy and platform-specific enough
that it isn't a reliable automated test. That fix was verified by inspection
instead: the code now falls through to the same close-and-stop cleanup used
by every other exit from handle_write_file, rather than returning bare.

Usage:
    python test_download_leak.py <path-to-test_download_leak_server[.exe]>
"""
import ctypes
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


def get_rss_bytes(pid):
    """Current resident/working-set memory of `pid`, in bytes."""
    if os.name == "nt":
        from ctypes import wintypes

        class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD),
                ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        PROCESS_QUERY_INFORMATION = 0x0400
        PROCESS_VM_READ = 0x0010
        handle = ctypes.windll.kernel32.OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
        if not handle:
            raise OSError("OpenProcess failed for pid %d" % pid)
        try:
            counters = PROCESS_MEMORY_COUNTERS()
            counters.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS)
            ok = ctypes.windll.psapi.GetProcessMemoryInfo(
                handle, ctypes.byref(counters), counters.cb)
            if not ok:
                raise OSError("GetProcessMemoryInfo failed for pid %d" % pid)
            # PagefileUsage (private/committed bytes -- what Task Manager
            # calls "Commit Size") rather than WorkingSetSize: Windows can
            # trim genuinely leaked-but-idle heap pages out of the working
            # set under its own memory pressure, which makes WorkingSetSize
            # an unreliable leak signal here. Committed bytes only grow when
            # the process actually holds memory it hasn't freed.
            return int(counters.PagefileUsage)
        finally:
            ctypes.windll.kernel32.CloseHandle(handle)
    else:
        with open("/proc/%d/status" % pid) as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) * 1024
        raise OSError("VmRSS not found for pid %d" % pid)


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


REQUEST = (
    b"GET /api/download HTTP/1.1\r\n"
    b"Host: 127.0.0.1\r\n"
    b"Connection: close\r\n"
    b"\r\n"
)


def download_to_completion(port, timeout=5.0):
    """One full download: read until the server closes the connection.

    Exercises the normal-completion exit of handle_write_file, i.e. the
    unconditional send_buffer_.release() at the very end of the function.
    """
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    s.settimeout(timeout)
    try:
        s.sendall(REQUEST)
        total = 0
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            total += len(chunk)
        return total
    finally:
        s.close()


def download_and_abort(port, timeout=5.0):
    """Read the header plus one body chunk, then abort with an RST.

    This is the plan's own verification recipe: "aborting each after the
    first chunk". The abort path reaches the exact same
    send_buffer_.release() as normal completion (it is the only exit out of
    handle_write_file other than the early "keep reading" branch), so it
    leaks identically on an unfixed build.
    """
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    s.settimeout(timeout)
    try:
        s.sendall(REQUEST)
        buf = b""
        while b"\r\n\r\n" not in buf and len(buf) < 65536:
            chunk = s.recv(4096)
            if not chunk:
                return
            buf += chunk
        # One more read: guarantees at least one FILE_SEND_BUFFER_SIZE chunk
        # of the body was actually sent (and send_buffer_ allocated) before
        # we pull the socket out from under the transfer.
        s.recv(4096)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    finally:
        s.close()


def ping_download(port):
    try:
        return download_to_completion(port) > 0
    except Exception:
        return False


def test_download_buffer_not_leaked(exe):
    print("\n[download leak] many downloads, completed and aborted, must not "
          "grow the server's working set")
    WARMUP = 100
    FULL = 1500
    ABORTED = 500
    # An unfixed build leaks ~16 KB per request regardless of which path it
    # took, so FULL+ABORTED requests would leak roughly
    # (FULL+ABORTED)*16KB =~ 31 MB. Ordinary allocator/connection-object
    # churn is nowhere near that; a few MB is generous headroom above it.
    GROWTH_LIMIT_BYTES = 12 * 1024 * 1024

    with Server(exe) as srv:
        check(ping_download(srv.port), "baseline download succeeds")

        # Let the allocator/heap settle into steady state before measuring,
        # so the baseline isn't artificially low from one-time first-touch
        # growth unrelated to any leak.
        for _ in range(WARMUP):
            download_to_completion(srv.port)

        rss_before = get_rss_bytes(srv.proc.pid)

        for _ in range(FULL):
            download_to_completion(srv.port)
        for _ in range(ABORTED):
            download_and_abort(srv.port)

        # Give the io thread a moment to finish tearing down the last few
        # connections (each abort's RST still has to be processed) before
        # taking the final measurement.
        time.sleep(0.5)
        rss_after = get_rss_bytes(srv.proc.pid)

        growth = rss_after - rss_before
        total_requests = FULL + ABORTED
        print("    RSS before: %.1f MB, after: %.1f MB, growth: %.1f MB "
              "(%d requests, unfixed-leak estimate ~%.1f MB)" %
              (rss_before / 1048576.0, rss_after / 1048576.0, growth / 1048576.0,
               total_requests, total_requests * 16 * 1024 / 1048576.0))

        check(growth < GROWTH_LIMIT_BYTES,
              "working set grew %.1f MB after %d downloads, under the %.1f MB bound" %
              (growth / 1048576.0, total_requests, GROWTH_LIMIT_BYTES / 1048576.0))

        check(srv.alive(), "server process is still running")
        check(ping_download(srv.port), "server still serves downloads afterwards")


def request_raw(port, path, timeout=5.0):
    """Send a bare GET for `path` and read the response until the server
    closes the connection (every request here uses Connection: close)."""
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    s.settimeout(timeout)
    try:
        s.sendall(
            b"GET " + path.encode("ascii") + b" HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Connection: close\r\n"
            b"\r\n"
        )
        data = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
        return data
    finally:
        s.close()


def test_bad_attachment_name_rejected(exe):
    print("\n[download bad attachment] a control-character attachment name "
          "must not produce a header-less (or split) download")

    with Server(exe) as srv:
        response = request_raw(srv.port, "/api/download-bad-attachment")
        header_end = response.find(b"\r\n\r\n")
        check(header_end != -1, "response has a complete header block")
        headers = response[:header_end] if header_end != -1 else response
        body = response[header_end + 4:] if header_end != -1 else b""

        status_line = headers.split(b"\r\n", 1)[0]
        # attachment_name failing validation is an application-supplied bad
        # value, not something the client did wrong, so the fixed code must
        # reject it as a server error (500) rather than stream the file
        # anyway with no Content-Disposition header (which is what the
        # unfixed code does, silently, while still returning 200).
        check(status_line == b"HTTP/1.1 500 Internal Server Error",
              "status line is 500 Internal Server Error, got %r" % status_line)

        # The injected header/value must never reach the wire, however the
        # request is handled.
        check(b"X-Injected" not in response, "no injected header anywhere in the response")
        check(b"Content-Disposition" not in headers, "no Content-Disposition header at all")

        # The unfixed code streams the real payload file (128 * 4096 = 512 KB
        # of 'x' bytes) alongside the missing header; the fixed code sends the
        # small stock 500 body instead. Checking the body is short (and is
        # not the payload) is what actually distinguishes "rejected" from
        # "silently served without a Content-Disposition header".
        check(len(body) < 4096, "body is the short stock error page, not the 512 KB payload (got %d bytes)" % len(body))
        check(not body.startswith(b"xxxx"), "body is not the payload file's content")

        check(srv.alive(), "server process is still running")
        check(ping_download(srv.port), "server still serves ordinary downloads afterwards")


def main():
    if len(sys.argv) < 2:
        print("usage: %s <path-to-test_download_leak_server>" % sys.argv[0])
        return 2
    exe = sys.argv[1]
    if not os.path.exists(exe):
        print("server binary not found: %s" % exe)
        return 2

    test_download_buffer_not_leaked(exe)
    test_bad_attachment_name_rejected(exe)

    print("\n%d checks, %d failure(s)" % (CHECKS, FAILURES))
    return 0 if FAILURES == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
