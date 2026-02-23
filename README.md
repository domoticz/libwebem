# libwebem

A lightweight, embeddable C++17 HTTP/HTTPS/WebSocket server library built on Boost.Asio.

## Features

- **HTTP/1.1** server with static file serving from a configurable document root
- **HTTPS/TLS** support via OpenSSL (optional, enabled at compile time)
- **WebSocket** support (RFC 6455) with multiple endpoint routing on different URL paths
- **Session management** with a pluggable session store interface (in-memory by default)
- **Authentication** — Login-form-based and HTTP Basic/Digest methods
- **JWT token** generation and validation (via jwt-cpp)
- **GZip compression** — dynamic, pre-compressed static files, or disabled
- **ZIP archive** file serving with optional password protection (optional, requires minizip)
- **FastCGI** support for PHP scripting (optional)
- **Trusted networks** — bypass authentication for configured IP ranges
- **Pluggable logging** interface (`IWebServerLogger`) — zero-overhead when no logger is provided
- **Heartbeat callbacks** for watchdog/health-monitor integration
- **Virtual host** support via configurable hostname checking
- **Cross-platform** — Linux, Windows, macOS, BSD, and embedded devices

## Dependencies

| Library | Required | Purpose | Resolution |
|---------|----------|---------|------------|
| Boost 1.69+ | Yes | Async networking, threading | System (find_package) |
| zlib | Optional | GZip compression (`WEBEM_ENABLE_GZIP`) | System (find_package) |
| jsoncpp | Yes | JSON parsing for WebSocket protocol messages | find_package or auto-fetched via FetchContent |
| jwt-cpp (header-only) | Yes | JWT token authentication | find_package or auto-fetched via FetchContent |
| OpenSSL | Yes | HTTPS/TLS support (`WEBEM_ENABLE_SSL`) and JWT signing | System (find_package) |
| minizip | Optional | ZIP archive file serving (`WEBEM_ENABLE_ZIP`) | System only; ZIP disabled if not found |

## Building

### CMake (Linux / macOS / Windows)

```bash
mkdir build && cd build
cmake ../webserver
make -j$(nproc)
```

#### Common CMake options

| Option | Default | Description |
|--------|---------|-------------|
| `WEBEM_ENABLE_SSL` | `ON` | Enable HTTPS/TLS support (requires OpenSSL) |
| `WEBEM_ENABLE_ZIP` | `ON` | Enable ZIP archive serving (requires minizip) |
| `WEBEM_ENABLE_FASTCGI` | `ON` | Enable FastCGI/PHP support |
| `WEBEM_ENABLE_GZIP` | `ON` | Enable GZip compression (requires zlib) |
| `WEBEM_BUILD_EXAMPLES` | `OFF` | Build the example applications |

> **Note:** jsoncpp and jwt-cpp are resolved automatically — via `find_package` if available on the system,
> or fetched and built from source via CMake `FetchContent` as a fallback. No manual path variables are needed.

#### Build with examples

```bash
cmake ../webserver -DWEBEM_BUILD_EXAMPLES=ON
make -j$(nproc)
```

### Visual Studio (Windows)

For Windows builds, use CMake with vcpkg (recommended) or open `webem.vcxproj` directly in Visual Studio:

```bash
vcpkg install boost jsoncpp jwt-cpp openssl zlib minizip
cmake -S webserver -B build -DCMAKE_TOOLCHAIN_FILE=[vcpkg-root]/scripts/buildsystems/vcpkg.cmake
cmake --build build
```

### Using as a CMake subdirectory (recommended)

```cmake
add_subdirectory(webserver)
target_link_libraries(myapp PRIVATE webem::webem)
```

### Using as an installed package

```cmake
find_package(webem REQUIRED)
target_link_libraries(myapp PRIVATE webem::webem)
```

## Quick Start

```cpp
#include <libwebem/cWebem.h>
#include <iostream>

int main() {
    http::server::server_settings settings;
    settings.listening_address = "::";   // all interfaces, IPv4 + IPv6
    settings.listening_port    = "8080";

    http::server::cWebem server(settings, "./www");

    // Register a JSON API endpoint
    server.RegisterPageCode("/api/hello",
        [](http::server::WebEmSession& session,
           const http::server::request& req,
           http::server::reply& rep) {
            rep.status  = http::server::reply::ok;
            rep.content = R"({"message":"Hello, World!"})";
            http::server::reply::add_header(&rep, "Content-Type", "application/json");
        });

    std::cout << "Listening on http://localhost:8080\n";
    server.Run();  // blocks until Stop() is called
}
```

See the [examples/](examples/) directory for complete, buildable applications covering HTTPS, WebSocket endpoints, authentication, and custom logging.

## Documentation

- [Integration guide](docs/INTEGRATION.md) — CMake integration, core concepts, and API reference
- [examples/](examples/) — Five progressive example applications

## License

BSD 3-Clause — see [LICENSE](LICENSE) file.

Portions based on the Boost.Asio HTTP server example by Christopher M. Kohlhoff (Boost Software License 1.0).
