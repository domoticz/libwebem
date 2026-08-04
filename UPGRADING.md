# Upgrading libwebem

## From the 2026-07 security remediation

Most of this release is additive: new `server_settings` fields with safe
defaults, new checks, no source change required. Three public symbols did change
incompatibly, and a handful of behaviours changed at runtime without changing
any signature.

In the one real-world integration this was validated against (Domoticz), exactly
**one** symbol broke — `m_remote_web_clients`. The other two breaking changes are
listed because they are public API, not because they were hit in practice.

---

### Breaking: source changes required

#### 1. `m_remote_web_clients` is no longer a global

```cpp
// before -- reached from the integrator via an extern declaration
extern std::map<std::string, connection::_tRemoteClients> m_remote_web_clients;
for (const auto &it : m_remote_web_clients) { ... }

// after
for (const auto &rc : webem.GetRemoteClients()) { ... }
```

It was a namespace-scope global, written from the io thread and read from
application threads with no synchronisation, and never pruned. It is now a
private, mutex-guarded member of `cWebem` with an LRU bound.

`GetRemoteClients()` returns a **snapshot by value**, taken under the lock. That
is deliberate: handing back a reference or iterator would reintroduce exactly the
race being fixed. Note the map is now per-`cWebem`, so an application running
both a plain and a secure server has two of them and must combine the results —
see `CWebServerHelper::GetRemoteClients()` in Domoticz for the pattern.

Symptom if missed: `LNK2001: unresolved external symbol m_remote_web_clients`.

#### 2. `cWebem::GetSession()` returns a copy, not a pointer

```cpp
// before
WebEmSession *s = webem.GetSession(sid);
if (s) { use(s->username); }          // pointer outlived the lock

// after
WebEmSession s;
if (webem.GetSession(sid, s)) { use(s.username); }
```

The old signature *was* the bug: the pointer was taken under `m_sessionsMutex`
and returned after the lock was dropped, so another thread expiring or replacing
that session freed it under the caller. There is no way to keep a
pointer-returning overload and also fix this, so it was removed rather than
deprecated.

If you only need to refresh a session's expiry, use `TouchSessionExpiry(sid, out)`
instead of reading, mutating and writing back.

#### 3. `reply::add_cors_headers()` takes an origin and an allow-list

```cpp
// before -- unconditionally emitted "Access-Control-Allow-Origin: *"
reply::add_cors_headers(&rep);

// after
reply::add_cors_headers(&rep, GetRequestOrigin(req), settings.allowed_cors_origins);
```

The wildcard combined with IP-based trusted-network authentication meant any
website could read authenticated responses from a server that trusts the local
network. The new form echoes the request's origin only when it exactly matches
an entry in `allowed_cors_origins`, and adds `Vary: Origin` when it does.

`allowed_cors_origins` is empty by default, so **no** CORS headers are emitted
unless you configure it. If you relied on the wildcard, that is the setting to
populate — and worth re-examining before you do.

Hosting applications that surface this to end users have three knobs, all
runtime-switchable via `cWebem::SetCorsPolicy(origins, allowTrustedNetworks)`
(no restart; in-flight requests see either the old or the new policy, never a
mix):

- exact origins in `allowed_cors_origins`;
- a single `"*"` entry in that list as an explicit allow-any opt-out (the
  request's Origin is echoed, never a literal `*`);
- `cors_allow_trusted_networks`, which echoes Origins whose host is an
  IP literal inside an `AddTrustedNetworks()` range (hostnames are never
  resolved). See the field comments in `server_settings.h` for the risk each
  one carries.

The same policy also admits cookie-less WebSocket upgrade origins (see
"WebSocket upgrades are authenticated when users exist" below).

---

### Source-compatible, but worth acting on

- **`reply::add_header_attachment()` now returns `bool`.** Existing callers that
  ignore it still compile. They should not: it returns `false` when the
  attachment name contains CR/LF (a response-splitting attempt), and ignoring
  that sends the response anyway. `connection::send_file()` now checks it and
  replies 500.
- **`reply::status_type` gained `payload_too_large` (413) and `uri_too_long`
  (414).** Only affects an exhaustive `switch` over the enum.
- **`server_settings` gained many fields.** Assigning members is fine;
  aggregate-initialising the struct positionally (`server_settings s = {...}`)
  is not, and never was advisable.
- **`AddTrustedNetworks()` now takes `const std::string&`.** No caller change.
- **`IWebsocketHandler` is unchanged.** WebSocket handlers do not need edits.
  `CWebsocketFrame::Parse()` did change, but it is an internal frame parser.

---

### Behavioural changes (no signature change)

These need no code edit but will be visible at runtime.

| Change | Effect |
|---|---|
| **HTTP/1.1 keep-alive now defaults on** | Persistence previously required an explicit `Connection: Keep-Alive`, contrary to RFC 9112 §9.3, so clients relying on the default got one request per connection. They now reuse it — and `max_requests_per_connection` (100), formerly unreachable for those clients, now applies. Connections are also held between requests rather than freed immediately. |
| **Size limits return specific statuses** | Previously every size breach returned `431`. Now: `414` for an over-long URI, `413` for an oversized body, `431` for the header block, and `503` (retryable) when the server-wide in-flight budget is momentarily full. |
| **WebSocket upgrades are authenticated when users exist** | With no user accounts configured the upgrade is allowed unauthenticated, matching HTTP on such a server. The same-origin check is **not** relaxed with it — WebSocket is not subject to CORS, so a cookie-less upgrade from a foreign origin is refused either way. |
| **New limits are enforced by default** | Request line 8 KiB, single header 8 KiB, 100 headers, 64 KiB header block, 100 MB body, 128 MB bodies in flight, 512 connections, 10 s TLS handshake, 30 s to first request. All configurable; see `docs/INTEGRATION.md`. |
| **Malformed-request logging moved to Debug** | It was `Error` level and unthrottled, so any client could fill the log by sending junk. |

---

### Settings that ship inert

Three protections default to off so that upgrading changes no behaviour. They do
nothing until configured:

- `trusted_proxy_header_family` — **required** if you sit behind a reverse proxy.
  Until set, no `X-Forwarded-For` / `Forwarded` / `X-Real-IP` header is consulted
  at all, and the peer address is used. Setting it wrong is worse than leaving it
  unset: it names which header your proxy actually writes, and everything else is
  ignored — including when several families arrive on the same request, which is
  normal (nginx Proxy Manager writes `X-Forwarded-For` and `X-Real-IP` together).
- `allowed_hosts` — validates the `Host` header on every request. Without it,
  DNS rebinding against a trusted-network deployment is not blocked.
- `max_connections_per_ip` — 0 (disabled), because behind a proxy every client
  shares one address and a non-zero value would throttle the whole server. If you
  enable it, list the proxy in `trusted_proxy_addresses` to exempt it.
