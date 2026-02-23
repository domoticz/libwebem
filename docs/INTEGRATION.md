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

Requests from trusted IP ranges bypass authentication entirely:

```cpp
server.AddTrustedNetworks("127.0.0.1/32");    // localhost only
server.AddTrustedNetworks("192.168.1.0/24");  // local LAN
server.AddTrustedNetworks("::1/128");          // IPv6 loopback
```

Clear all trusted networks:

```cpp
server.ClearTrustedNetworks();
```

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
