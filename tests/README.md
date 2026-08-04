# libwebem test suite

This directory holds two kinds of tests:

- **Unit tests** (`webem_tests`, `webem_test_http_framing`, `webem_test_session_lifetime`,
  `webem_test_hash_and_reply`, `webem_test_response_headers`) — standalone executables,
  each with its own `main()` and a lightweight `CHECK()` macro harness (no external test
  framework). They exercise the library in-process: parsing, framing, hashing, session
  bookkeeping, header/CORS primitives.
- **Integration tests** (`test_*.py`) — Python drivers that launch a small purpose-built
  server binary (`test_*_server`, built from the matching `.cpp` file) and exercise it from
  outside the process over real loopback TCP sockets. These cover what an in-process unit
  test structurally cannot: accept()/socket teardown races, actual process memory growth,
  TCP-level framing across many small reads, and concurrent access from independent threads.

## What each suite covers

| Suite | What it proves |
|---|---|
| `webem_tests` | Secure token generation, constant-time comparison, SHA-256/MD5 hashing, control-character/NUL-injection rejection in paths and URL decoding, strict `Content-Length` parsing, WebSocket frame bounds checks, connection resource limits (global/per-address caps, defaults), proxy header trust (`X-Forwarded-For`/`Forwarded` resolution and filtering). |
| `webem_test_http_framing` | `Content-Length` is honoured for every HTTP method (not just POST), so a declared body can't be left in the buffer to be reparsed as a smuggled second request; `Transfer-Encoding` is rejected; disagreeing duplicate `Content-Length` headers are rejected; pipelined requests are parsed correctly and in order; request-line/header-count/header-size/total-size limits reject oversized input; incremental parsing across many small chunks consumes each byte exactly once (no re-walking from byte 0). |
| `webem_test_session_lifetime` | Sessions are handed out by value, never by pointer into the locked map (no use-after-free under concurrent read/renew/clear); `TouchSessionExpiry`'s renewal thresholds; the per-instance, locked, size-capped remote-client tracking map (bounded inline, not only after a periodic sweep, and evicted oldest-by-last-seen rather than by map key). |
| `webem_test_hash_and_reply` | `request::print()` returns each request's own parameters rather than a cached first result; `ConstantTimeEquals` never treats two empty inputs as equal; hash functions match known vectors; `reply::set_content_from_file` succeeds on a real file and fails cleanly (no throw) on a missing one. |
| `webem_test_response_headers` | `reply::add_header`/`add_header_attachment`/`set_download_file` reject embedded control characters (CRLF header injection, including via a user-supplied download attachment name) instead of emitting them; `add_cors_headers` never echoes an unlisted Origin or emits a bare `*`, and adds `Vary: Origin` only when it does echo one. |
| `test_connection_limits.py` | End-to-end: the per-connection request budget closes a keep-alive connection at the configured count and advertises it honestly; the global connection cap refuses excess connections and frees slots on close; the per-address cap is disabled by default (so a reverse-proxy deployment isn't throttled) and enforced when configured; a client that stops reading a push feed is dropped once the write-queue bound is hit; a POST body dribbled across many small, delayed TCP writes still parses completely and correctly. |
| `test_proxy_trust.py` | The rightmost entry in a forwarded-header chain is trusted, never the leftmost (the client-controlled end); a forged loopback/link-local/unspecified address is filtered out of the chain rather than falling back to the trusted proxy's own address; private-range addresses are not filtered (they're legitimate LAN clients); `Forwarded:` header parsing handles RFC 7239 forms including the `for=` precedence case. |
| `test_accept_resilience.py` | The accept loop keeps re-arming itself after accept-time errors (a connection reset before accept, or exceeding the connection cap) instead of silently dying and leaving the listener unreachable until a restart. |
| `test_auth_hardening.py` | A malformed `Authorization` header (too few JWT segments, non-JSON payload, an empty `"aud"` array) is rejected without taking the server thread down or hitting undefined behaviour; a validly signed token still authenticates; a wrong signature is rejected. |
| `test_download_leak.py` | Many completed and aborted `download_file` responses do not grow the server's committed memory (the per-download 16 KB buffer leak); an attachment name containing control characters is rejected as a 500 rather than silently streaming the file with no `Content-Disposition` header. |
| `test_cors.py` | API/page responses carry no CORS header by default; an unlisted Origin gets nothing; an allow-listed Origin is echoed exactly with `Vary: Origin`; static assets are unaffected (still unconditional `*`); a WebSocket upgrade from a foreign Origin is rejected for a trusted-network-authenticated session, including same-origin default-port normalisation. The policy is runtime-switchable via `cWebem::SetCorsPolicy()`: a `*` entry echoes any Origin (never a literal `*`), `cors_allow_trusted_networks` echoes IP-literal origins inside trusted ranges (hostnames never resolved), and both apply to WebSocket upgrades too. |
| `test_ws_write_race.py` | `WS_Write()` called from an independent application thread while the io thread is tearing a connection down (client RST) does not crash or hang the server under sustained load. This is a stress test, not a proof — MSVC has no ThreadSanitizer, so a clean run demonstrates survival under load, not the absence of a data race. |
| `test_tls_handshake_timeout.py` | A client that completes the TCP handshake but never sends a TLS ClientHello is dropped near the configured `tls_handshake_timeout` instead of being held open indefinitely (previously bounded only by the 20-minute abandoned-connection timeout). Needs `openssl` at configure time to generate a throwaway self-signed certificate; see below. |

## Running everything

```
cmake -S . -B build -DWEBEM_BUILD_TESTS=ON ...
cmake --build build
ctest --test-dir build --output-on-failure
```

All twelve unit-test and Python-driven suites are registered with `add_test`, so `ctest` is
the one command that runs the whole thing — nobody needs to know which server binary pairs
with which Python driver. Python-driven tests are skipped at configure time (with a
`message(STATUS ...)` explaining why, not a hard failure) if no Python 3 interpreter is
found; `test_tls_handshake_timeout` is additionally skipped if no `openssl` executable is
found, or if `WEBEM_ENABLE_SSL` is off.

Expected check counts as of this suite — every unit binary and Python driver prints
`N checks, M failure(s)` on exit, so a drop in any of these numbers (with `ctest` still
reporting the suite as "Passed") is a regression worth investigating even though `ctest`
itself only checks the process exit code, not the count:

| Suite | Checks |
|---|---|
| `webem_tests` | 248 |
| `webem_test_http_framing` | 131 |
| `webem_test_session_lifetime` | 36 |
| `webem_test_hash_and_reply` | 26 |
| `webem_test_response_headers` | 36 |
| `test_connection_limits.py` | 10 |
| `test_proxy_trust.py` | 11 |
| `test_accept_resilience.py` | 6 |
| `test_auth_hardening.py` | 13 |
| `test_download_leak.py` | 12 |
| `test_cors.py` | 23 |
| `test_ws_write_race.py` | 7 |
| `test_tls_handshake_timeout.py` | 7 |

**556 checks across 13 suites, 0 failures**, on a clean build.

## Running one suite manually

Unit test binaries take no arguments and print `N checks, M failure(s)` on exit:

```
build/tests/webem_tests
```

Python drivers take the path to their server binary (built alongside them in
`build/tests/`):

```
python tests/test_connection_limits.py  build/tests/test_connection_limits_server
python tests/test_proxy_trust.py        build/tests/test_proxy_trust_server
python tests/test_accept_resilience.py  build/tests/test_connection_limits_server
python tests/test_auth_hardening.py     build/tests/test_auth_hardening_server
python tests/test_download_leak.py      build/tests/test_download_leak_server
python tests/test_cors.py               build/tests/test_cors_server
python tests/test_ws_write_race.py      build/tests/test_ws_write_race_server
python tests/test_tls_handshake_timeout.py build/tests/test_tls_handshake_timeout_server <cert> <key>
```

(`.exe` suffix on Windows.) `test_tls_handshake_timeout.py` additionally needs a
certificate/key pair; when driven through `ctest`, CMake generates a throwaway self-signed
one at configure time into `<build>/tests/tls_handshake_timeout_certs/`. To run it by hand,
either point it at that pair or generate your own with
`openssl req -new -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 3650 -nodes -subj "/CN=127.0.0.1"`.

## AddressSanitizer

`WEBEM_ENABLE_ASAN` (default `OFF`) builds the library and every test binary with
`/fsanitize=address` (MSVC) or `-fsanitize=address` (everything else):

```
cmake -S . -B build-asan -DWEBEM_BUILD_TESTS=ON -DWEBEM_ENABLE_ASAN=ON ...
cmake --build build-asan
ctest --test-dir build-asan --output-on-failure
```

**On MSVC, the built binaries will not start unless the ASan runtime DLL is on `PATH`.**
`clang_rt.asan_dynamic-x86_64.dll` ships with the MSVC toolchain itself (it is not copied
next to the executables), at:

```
<Visual Studio install>\VC\Tools\MSVC\<version>\bin\Hostx64\x64\
```

A shell that has already run `vcvars64.bat` (or the equivalent Developer Command Prompt)
has this directory on `PATH` automatically — it's the same directory `cl.exe` lives in — so
building and running from that same shell works with no extra step. A *different* shell, a
CI runner that never sourced `vcvars64.bat`, or launching the binary directly (double-click,
a debugger, a service) will fail at process start with `STATUS_DLL_NOT_FOUND`
(`0xC0000135`) instead of a useful error message. If that happens, add the directory above
to `PATH` for whatever launched the process.

MSVC has supported `/fsanitize=address` since VS 16.9 but has no ThreadSanitizer
equivalent; data races around shared connection state (see `test_ws_write_race.py`) are
only checkable with TSan on a non-MSVC toolchain (gcc/clang with `-fsanitize=thread`).

`WEBEM_ENABLE_ASAN` is not on by default and this document does not claim a full ASan
build/run was exercised as part of this change — treat enabling it as its own verification
step, not something implied by the option existing.

## Known pre-existing breakage: `webem.vcxproj` Release|x64

Not caused by anything in this test suite. `webem.vcxproj` builds the library only (it has
no test target). `Debug|x64` builds clean — it resolves vcpkg packages against the
`x64-windows` triplet. `Release|x64` sets `VcpkgTriplet` to `x64-windows-static`, and that
triplet on this machine is missing the `boost-logic` package specifically: the include
directory has most of Boost but not `boost/logic/tribool.hpp`, so `Release|x64` fails with
`C1083: Cannot open include file: 'boost/logic/tribool.hpp'` in every translation unit that
(transitively) includes `request_parser.h` or `Websockets.h`. Installing `boost-logic` for
`x64-windows-static` (`vcpkg install boost-logic:x64-windows-static`) would resolve it; this
has not been done here since it changes machine-wide vcpkg state outside this repository.
