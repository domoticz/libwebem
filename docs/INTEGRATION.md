# Integrating libwebem into Your Project

This guide covers how to add libwebem to your build system and explains the core API concepts.

## 1. Adding to Your Build

### As a CMake subdirectory

The simplest approach for projects that include the webserver source directly:

```cmake
add_subdirectory(path/to/webserver)
target_link_libraries(myapp PRIVATE webem::webem)
```

CMake will propagate all required include paths and link dependencies automatically.

### As an installed package (find_package)

After building and installing libwebem:

```bash
cmake ../webserver -DCMAKE_INSTALL_PREFIX=/usr/local
make install
```

Then in your project:

```cmake
find_package(webem REQUIRED)
target_link_libraries(myapp PRIVATE webem::webem)
```

### Controlling optional features

Pass these options when configuring libwebem:

```cmake
add_subdirectory(webserver)
# or on the cmake command line:
#   -DWEBEM_ENABLE_SSL=ON
#   -DWEBEM_ENABLE_ZIP=OFF
#   -DWEBEM_ENABLE_FASTCGI=OFF
#   -DWEBEM_ENABLE_GZIP=OFF    # disable GZip compression; removes the zlib dependency
#   -DWEBEM_BUILD_EXAMPLES=ON
```

---

## 2. Core Concepts

### Server Setup

The entry point is `http::server::cWebem`. Construction requires a `server_settings` struct and a document root path.

```cpp
#include <libwebem/cWebem.h>

http::server::server_settings settings;
settings.listening_address = "::";      // "::" = all interfaces (IPv4+IPv6)
settings.listening_port    = "8080";
settings.server_name       = "MyApp/1.0"; // optional Server: header

http::server::cWebem server(settings, "/var/www/myapp");

// Optional: heartbeat callbacks for watchdog integration
settings.on_heartbeat        = [](const std::string& name) { /* alive */ };
settings.on_heartbeat_remove = [](const std::string& name) { /* stopped */ };
```

Call `Run()` to start the server (blocking). Call `Stop()` from another thread to shut it down cleanly.

```cpp
std::thread server_thread([&server]{ server.Run(); });
// ... later ...
server.Stop();
server_thread.join();
```

---

### Serving Static Files

Files under the document root are served automatically. The URL path maps directly to the filesystem:

```
GET /index.html  ->  /var/www/myapp/index.html
GET /css/app.css ->  /var/www/myapp/css/app.css
```

GZip compression behaviour is controlled with `SetWebCompressionMode()`:

```cpp
// Dynamic gzip (default): compress responses on the fly
server.SetWebCompressionMode(http::server::WWW_USE_GZIP);

// Serve pre-compressed .gz files alongside originals
server.SetWebCompressionMode(http::server::WWW_USE_STATIC_GZ_FILES);

// Disable all compression
server.SetWebCompressionMode(http::server::WWW_FORCE_NO_GZIP_SUPPORT);
```

---

### Registering Request Handlers

Use `RegisterPageCode` to handle GET and POST requests at a specific URL:

```cpp
server.RegisterPageCode("/api/status",
    [](http::server::WebEmSession& session,
       const http::server::request& req,
       http::server::reply& rep)
    {
        rep.status  = http::server::reply::ok;
        rep.content = R"({"status":"running"})";
        http::server::reply::add_header(&rep, "Content-Type", "application/json");
    });
```

The third parameter `bypassAuthentication` (default `false`) allows a handler to be reachable without credentials:

```cpp
server.RegisterPageCode("/api/health", handler, /*bypassAuthentication=*/true);
```

Use `RegisterActionCode` for form-submission actions that redirect after processing:

```cpp
server.RegisterActionCode("/action/save",
    [](http::server::WebEmSession& session,
       const http::server::request& req,
       std::string& redirecturi)
    {
        // process req.content / query parameters
        redirecturi = "/settings?saved=1";
    });
```

---

### WebSocket Endpoints

Register one or more WebSocket endpoints, each with its own factory and optional sub-protocol name.

```cpp
#include <libwebem/IWebsocketHandler.h>

class MyHandler : public http::server::IWebsocketHandler {
public:
    MyHandler(http::server::cWebem* webem,
              std::function<void(const std::string&)> writer)
        : m_writer(std::move(writer)) {}

    // Called for every received (inbound) message.
    // outbound=false for received messages, true for sent ones (rarely needed).
    bool Handle(const std::string& data, bool outbound) override {
        m_writer("echo: " + data);  // send reply to client
        return true;
    }

    void Start() override { /* connection opened */ }
    void Stop()  override { /* connection closed */ }

    // Store session cookie / auth info from the upgrade HTTP handshake
    void store_session_id(const http::server::request& req,
                          const http::server::reply& rep) override {}

private:
    std::function<void(const std::string&)> m_writer;
};

// Register the endpoint — one factory call per new connection
server.RegisterWebsocketEndpoint("/ws/echo",
    [](http::server::cWebem* webem,
       std::function<void(const std::string&)> writer)
    {
        return std::make_shared<MyHandler>(webem, std::move(writer));
    },
    "echo"  // WebSocket sub-protocol (sent in Sec-WebSocket-Protocol header)
);
```

Multiple endpoints can coexist on different paths. Clients connect using the standard WebSocket URL: `ws://host:port/ws/echo`.

---

### Authentication

Two authentication methods are available:

```cpp
// Form-based login (default): users POST credentials to a login page
server.SetAuthenticationMethod(http::server::AUTH_LOGIN);

// HTTP Basic/Digest authentication
server.SetAuthenticationMethod(http::server::AUTH_BASIC);
```

Add users with `AddUserPassword`:

```cpp
// ID, username, hashed_password, mfatoken, passkeys, rights, active_tabs
server.AddUserPassword(1, "admin",  "sha256_hash", "", "",
                       http::server::URIGHTS_ADMIN,   0xFF);
server.AddUserPassword(2, "viewer", "sha256_hash", "", "",
                       http::server::URIGHTS_VIEWER,  0xFF);
```

Available rights levels:

| Value | Meaning |
|-------|---------|
| `URIGHTS_VIEWER` | Read-only access |
| `URIGHTS_SWITCHER` | Can control switches |
| `URIGHTS_ADMIN` | Full administrative access |

Plain HTTP Basic Auth can be explicitly allowed or denied:

```cpp
server.SetAllowPlainBasicAuth(false);  // require HTTPS for Basic auth
```

Set the digest authentication realm:

```cpp
server.SetDigistRealm("MyApplication");
```

---

### Trusted Networks

Requests from trusted IP ranges bypass authentication entirely — a request from a
trusted address is served with the rights of the first admin user, with no credentials:

```cpp
server.AddTrustedNetworks("192.168.1.0/24");  // local LAN
server.AddTrustedNetworks("::1/128");          // IPv6 loopback
```

Clear all trusted networks:

```cpp
server.ClearTrustedNetworks();
```

> **Do not add your reverse proxy's own address to this list.**
>
> If libwebem sits behind nginx/Apache on the same host and you trust `127.0.0.1/32`,
> then *every* request arriving through that proxy comes from a trusted address, and
> every visitor — including from the public internet — is granted administrative
> access. The proxy's address is the address of the proxy, not of the client.
>
> When a proxy is in front, either leave the trusted-network list empty, or populate it
> only with the *client* ranges you actually mean to trust.

#### How forwarded client addresses are resolved

**Proxy headers are ignored unless you explicitly opt in.** `Forwarded` (RFC 7239),
`X-Forwarded-For` and `X-Real-IP` are three independent, unauthenticated header
families. A real reverse proxy populates exactly one of them; the other two arrive on
the wire as whatever the client chose to send, completely unmodified. If libwebem
consulted all three, the client — not your proxy — would decide which chain gets
believed: configure nginx the recommended way below (which writes `X-Forwarded-For`
and leaves `Forwarded` untouched) and a remote attacker can still buy trusted-network
admin rights simply by sending a `Forwarded` header instead, because nothing strips or
overwrites it on the way through.

So by default, `session.remote_host` is never overridden from any of these headers,
regardless of trusted-network configuration. To opt in, tell libwebem which single
family your proxy actually writes:

```cpp
settings.trusted_proxy_header_family = http::server::ProxyHeaderFamily::XForwardedFor;
```

Once set, **only that family is consulted**; the other two are ignored completely,
even when present. A request carrying several families at once is *not* rejected —
the families you did not configure are never read, so they cannot change the outcome.
This matters in practice: nginx Proxy Manager writes `X-Forwarded-For` and `X-Real-IP`
on every request by default, and plenty of hand-written nginx configs do the same.
Presence of more than one family is logged at Debug level under the `Auth` category.

When the connecting peer is in a trusted network and the configured family is present,
libwebem recovers the originating client from it and uses that address for the
trusted-network decision. Two further rules make this safe:

- **Only the last entry in the chain is believed.** A proxy *appends* the address of
  whoever connected to it, so the rightmost entry is the one your proxy wrote.
  Everything to its left was supplied by the client and is forgeable.
- **Non-routable addresses are discarded** — loopback (`127.0.0.0/8`, `::1`),
  link-local (`169.254.0.0/16`, `fe80::/10`) and the unspecified address. These can
  never legitimately identify a *forwarded* client, so their presence indicates either
  a forged header or a proxy misconfigured to pass the client's header through instead
  of appending to it.

If the configured family's header is present but no usable address survives those
rules, the request is treated as coming from an **untrusted** origin: it does not
inherit the trust that the connecting proxy's own address would otherwise confer.
Configure your proxy to append rather than overwrite (nginx: `proxy_set_header
X-Forwarded-For $proxy_add_x_forwarded_for;`).

#### CORS and trusted networks — read this together

A trusted-network request is granted the first admin user's rights with **no
credentials at all**. That has a direct consequence for any browser sitting on a
trusted network: a page on `evil.com` can `fetch('http://domoticz.lan:8080/json.htm?...')`
and the server will happily execute it with admin rights, because the request simply
arrived from a trusted address. Whether `evil.com`'s JavaScript can then *read* the
response is entirely down to CORS headers — so on a deployment with trusted networks
configured, CORS is doing real access control, not just enabling convenience
integrations.

For that reason API/page responses (registered via `RegisterPageCode`, e.g.
`/json.htm`) carry **no** `Access-Control-Allow-Origin` header by default. This is
safe for the bundled web UI: same-origin requests never consult that header at all,
so leaving it off breaks nothing for normal use. Static assets under `www_root` are
unaffected by this and continue to be served with `Access-Control-Allow-Origin: *`,
since they are meant to be publicly cacheable and carry no session-derived content.

If a separate site legitimately needs to call this API from client-side JavaScript,
opt it in explicitly:

```cpp
settings.allowed_cors_origins.push_back("https://dashboard.example.com");
```

Only an exact match of the request's `Origin` header is echoed back (with `Vary:
Origin`); nothing is ever echoed unvalidated. **Adding an origin here grants that
site the same trusted-network rights that any browser on the trusted network already
has** — treat this list with the same care as `AddTrustedNetworks()`.

Two deliberate opt-outs exist beyond exact origins, both off by default (see the
field comments in `server_settings.h` for the exposure each one accepts):

- a single `"*"` entry in `allowed_cors_origins` echoes **any** Origin (still never
  a literal `*`, so responses stay per-origin cacheable) — the pre-hardening
  behaviour, restored only by explicit choice;
- `cors_allow_trusted_networks` echoes an Origin whose host is an IP literal inside
  an `AddTrustedNetworks()` range — for dashboards served from another port or
  machine inside the trusted network. Hostname origins are never resolved for this
  check; list those explicitly.

The whole policy can be replaced at runtime with
`cWebem::SetCorsPolicy(origins, allowTrustedNetworks)`, e.g. from a settings page,
without restarting the server.

The same policy gates WebSocket upgrades: a same-origin upgrade (Origin matching
this server's own scheme+host) is always allowed, but a cross-origin upgrade is only
accepted for a trusted-network-authenticated session when its Origin passes
`IsCorsOriginAllowed()`. Cookie-authenticated upgrades don't need this check —
`SameSite=strict` already keeps a foreign site's browser from attaching the session
cookie in the first place.

#### DNS rebinding — validate Host, don't just compare it to Origin

"Same-origin" above (Origin matching this server's own scheme+host) is implemented by
comparing the WebSocket handshake's `Origin` header against the request's own `Host`
header. For a genuine browser request both are derived from the same URL, so they
agree — but they agree just as trivially for **any** hostname an attacker controls,
because nothing validates that `Host` names this server in the first place (a
plain-HTTP listener with no `vhostname` configured, which is the common case, does not
check `Host` at all otherwise).

Concretely: an attacker serves a page from a short-TTL DNS name they control, waits for
a browser on your trusted network (see `AddTrustedNetworks()` above) to load it, then
re-points that DNS name at this server's LAN address. The victim's browser — still
holding the cached page, on the trusted network — opens `ws://that-name:8080/`. Both
`Origin` and `Host` read the attacker's hostname, "match" perfectly, and the attacker
gets a bidirectional WebSocket with the first admin user's rights, with the added twist
over a plain forged request that they can **read** the responses too.

Close this by configuring an allow-list of the hostnames/addresses real clients
actually use to reach this server:

```cpp
settings.allowed_hosts = { "domoticz.lan", "192.168.1.10" };
```

Once set, two things change together: `Host` is validated against this list on *every*
request (not just WebSocket upgrades, and not only when using a TLS listener with
`vhostname` — a request with an unrecognised `Host` is rejected with 400 before
authentication is even reached), and the WebSocket same-origin check compares `Origin`
against this list instead of against the request's own `Host` header. An attacker's
rebinding domain is never in the list, so it fails both checks.

`allowed_hosts` **defaults to empty**, which preserves the pre-fix behaviour exactly, so
upgrading does not by itself break an existing deployment. But leaving it unset leaves
DNS rebinding open on any deployment using `AddTrustedNetworks()` — set it if you use
trusted networks at all.

---

### Session Management

Sessions are stored in memory by default. Implement the `session_store` interface to persist sessions in a database or cache:

```cpp
#include <libwebem/session_store.h>

class MySessionStore : public http::server::session_store {
public:
    http::server::WebEmStoredSession GetSession(const std::string& id) override {
        // load from database
    }
    void StoreSession(const http::server::WebEmStoredSession& s) override {
        // save to database
    }
    void RemoveSession(const std::string& id) override {
        // delete from database
    }
    void CleanSessions() override {
        // purge expired sessions from database
    }
};

MySessionStore store;
server.SetSessionStore(&store);
```

Access the current session from within a handler via the `WebEmSession` parameter:

```cpp
session.id            // session identifier
session.username      // authenticated username
session.rights        // _eUserRights value
session.istrustednetwork  // true if request came from a trusted IP
session.auth_token    // JWT auth token
```

---

### JWT Tokens

Generate JWT tokens for API authentication:

```cpp
std::string token;
Json::Value payload;
payload["custom_claim"] = "value";

bool ok = server.GenerateJwtToken(
    token,
    "client-id",     // sub claim
    "admin",         // username
    3600,            // expiry in seconds
    payload,         // additional claims (optional)
    "MyApp"          // issuer (optional)
);
```

#### Verifying incoming bearer tokens

When a client presents a JWT (`Authorization: Bearer ...`), it is only accepted for a
ClientID that is registered with matching key material for the algorithm the token
itself claims: `HS*` requires a non-empty `signingsecret` (`AddUserPassword`'s
`signingsecret` parameter), `RS*`/`PS*` requires a non-empty public key
(`AddUserPassword`'s `pubkey` parameter). A ClientID registered asymmetrically (public
key only) cannot be satisfied by an HS256 token, no matter what key that token claims
to be signed with -- an empty signing secret is never treated as "any HS256 signature
is acceptable".

The token's `iss` (issuer) claim is checked against `settings.jwt_expected_issuer` when
set. **Leaving it unset is not a neutral default**: the expected issuer then falls back
to being derived from the request's own `Host` header, which the client controls, so
the check verifies little beyond "the token names an issuer that resembles this
request's URL". Set it to the server's real, fixed external URL for a meaningful check:

```cpp
settings.jwt_expected_issuer = "https://myhost.example.com/";
```

---

### Logging

Provide a custom logger by implementing `IWebServerLogger`:

```cpp
#include <libwebem/IWebServerLogger.h>

class MyLogger : public http::server::IWebServerLogger {
public:
    void Log(http::server::LogLevel level, const char* fmt, ...) override {
        char buf[2048];
        va_list args;
        va_start(args, fmt);
        vsnprintf(buf, sizeof(buf), fmt, args);
        va_end(args);
        // write to your logging system
    }

    void Debug(http::server::DebugCategory cat, const char* fmt, ...) override {
        // called for verbose debug messages
    }

    // Access logging (Apache Combined Log Format) — opt in
    bool IsAccessLogEnabled() override { return true; }
    void AccessLog(const char* fmt, ...) override {
        // write to access log file
    }
};

auto logger = std::make_shared<MyLogger>();
http::server::cWebem server(settings, "./www", logger);
```

Log levels: `LogLevel::Error`, `LogLevel::Status`, `LogLevel::Debug`.
Debug categories: `DebugCategory::WebServer`, `DebugCategory::Auth`.

If no logger is provided, all output is silently discarded.

---

### Heartbeat / Health Monitoring

Set callbacks on `server_settings` before construction to receive periodic heartbeat signals (approximately every 4 seconds):

```cpp
settings.on_heartbeat = [](const std::string& name) {
    watchdog_kick();  // signal external watchdog
};
settings.on_heartbeat_remove = [](const std::string& name) {
    watchdog_stop();  // server is shutting down
};
```

The `name` parameter identifies the server instance (useful when running multiple instances).

---

### HTTPS / SSL

Use `ssl_server_settings` instead of `server_settings` when SSL support is compiled in (`WEBEM_ENABLE_SSL=ON`):

```cpp
#include <libwebem/server_settings.h>

http::server::ssl_server_settings ssl_settings;
ssl_settings.listening_address            = "::";
ssl_settings.listening_port               = "8443";
ssl_settings.cert_file_path               = "/etc/myapp/server.crt";
ssl_settings.private_key_file_path        = "/etc/myapp/server.key";
ssl_settings.certificate_chain_file_path  = "/etc/myapp/chain.crt";
ssl_settings.tmp_dh_file_path             = "/etc/myapp/dhparam.pem";
ssl_settings.ssl_options = "default_workarounds,no_sslv2,no_sslv3,single_dh_use";

http::server::cWebem server(ssl_settings, "./www");
```

`cWebem` accepts both `server_settings` and `ssl_server_settings` — the correct server type is selected automatically based on `settings.is_secure()`.

#### Supported ssl_options values

`default_workarounds`, `single_dh_use`, `no_sslv2`, `no_sslv3`, `no_tlsv1`, `no_tlsv1_1`, `no_tlsv1_2`, `no_compression`

#### Certificate hot-reloading

SSL certificates and DH parameters are checked for modification on each new incoming connection. Updated certificates are loaded automatically without restarting the server.

---

### No-Cache Patterns

Force cache-control headers for specific URI patterns (useful for API endpoints):

```cpp
server.RegisterNoCachePattern("/api/");
server.RegisterNoCachePattern("/json.htm");
```

Any request whose URI contains the registered substring receives `Cache-Control: no-cache,must-revalidate`.

---

### Whitelist (Authentication Bypass by URL)

Register URL substrings that bypass authentication checks entirely (supplements `bypassAuthentication` on individual handlers):

```cpp
server.RegisterWhitelistURLString("/public/");
server.RegisterWhitelistCommandsString("getversion");
```

---

### Request Size Limits and File Uploads

`server_settings` bounds how much a client can make the server allocate:

| Setting | Default | Bounds |
|---|---|---|
| `max_request_body_size` | 100 MB | One request's declared `Content-Length` |
| `max_body_bytes_in_flight` | 128 MB | All request bodies being received at once, server-wide |
| `min_request_body_rate` | 64 KiB/s | Throughput floor a body must beat (see below) |

The defaults are deliberately generous so that **restoring a database backup
works out of the box** — a database with a few years of history reaches 75 MB,
and a restore that fails until the operator discovers an undocumented setting
is a worse outcome than a tighter memory bound. Deployments that never accept
uploads should lower `max_request_body_size`: it is the single most effective
knob for bounding what one connection can make the server allocate.

**If you change one, check the other.** `reserve_body_bytes()` refuses any
single request larger than the entire `max_body_bytes_in_flight` budget, so a
budget below the per-request cap silently makes the larger setting unreachable:

```cpp
settings.max_request_body_size    = 64u * 1024 * 1024;   // tighten per request
settings.max_body_bytes_in_flight = 128u * 1024 * 1024;  // keep >= the above
```

Neither may exceed `request_parser::kMaxContentLength` (100 MB), which is
compiled in rather than configurable because the receive buffer is sized from
it. `max_request_body_size` defaults to exactly that ceiling.

#### Timeouts on large uploads

`initial_request_timeout` (30 s) is a one-shot deadline that is deliberately
never reset by arriving bytes — that is what stops a slow-trickle client from
holding a connection slot indefinitely. Applied unchanged to a large upload it
would also kill a healthy one: 75 MB inside 30 s demands 2.5 MB/s.

So once a body is admitted, the deadline is extended by
`content_length / min_request_body_rate`. A genuine upload gets time
proportional to its size; a trickler still cannot hold the connection forever,
because the extension is finite and computed from a length the client committed
to up front. Set `min_request_body_rate` to 0 to drop the time bound on the
body phase entirely.

#### Memory cost

The whole body is buffered in memory before the handler runs, and it is copied
once more into `request::content`, so a body of size N costs roughly 2N at peak
— more if your handler extracts a multipart field into another string. libwebem
does not currently stream request bodies to disk the way nginx does with
`client_body_buffer_size`. Size `max_request_body_size` with that in mind on
small hardware: 100 MB is comfortable on a Raspberry Pi 4, but not on a device
with 512 MB of RAM.

Responses have no such cost — `set_download_file()` streams from disk in 16 KB
chunks, so serving a backup of any size up to `MAX_REPLY_FILE_SIZE` (512 MiB)
is not memory-bound.

A request rejected for size is answered with the status naming what was
actually breached, so the client can act on it:

| Condition | Status |
|---|---|
| URI longer than `max_request_line_length` | `414 URI Too Long` |
| Header block, header count, or single header too large | `431 Request Header Fields Too Large` |
| Declared body over `max_request_body_size` / `kMaxContentLength` | `413 Payload Too Large` |
| Server-wide `max_body_bytes_in_flight` momentarily exhausted | `503 Service Unavailable` |

The 503 is the only one of these worth retrying: the body would have fit, the
server just had no room for it at that moment.
