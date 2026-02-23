// Example 01 — Minimal HTTP server
//
// Demonstrates:
//   - Creating a server_settings struct
//   - Constructing cWebem with a document root
//   - Registering a JSON API endpoint with RegisterPageCode()
//   - Setting response status, content, and headers
//   - Starting the server with Run()
//
// Build (after installing libwebem):
//   cmake -S . -B build -Dwebem_DIR=<prefix>/lib/cmake/webem
//   cmake --build build
//
// Run:
//   ./simple_http
//   curl http://localhost:8080/api/hello
//   open http://localhost:8080/            (serves www/index.html)

#include <libwebem/cWebem.h>
#include <iostream>
#include <csignal>

static http::server::cWebem* g_server = nullptr;

static void signal_handler(int /*sig*/)
{
    if (g_server)
        g_server->Stop();
}

int main()
{
    // ------------------------------------------------------------------
    // 1. Configure server settings
    // ------------------------------------------------------------------
    http::server::server_settings settings;
    settings.listening_address = "::";    // all interfaces (IPv4 and IPv6)
    settings.listening_port    = "8080";
    settings.server_name       = "libwebem-example/1.0";

    // ------------------------------------------------------------------
    // 2. Create the server, pointing it at the www/ directory
    // ------------------------------------------------------------------
    http::server::cWebem server(settings, "./www");
    g_server = &server;

    // Graceful shutdown on Ctrl+C
    std::signal(SIGINT,  signal_handler);
    std::signal(SIGTERM, signal_handler);

    // ------------------------------------------------------------------
    // 3. Register a JSON API endpoint
    // ------------------------------------------------------------------
    server.RegisterPageCode("/api/hello",
        [](http::server::WebEmSession& /*session*/,
           const http::server::request& /*req*/,
           http::server::reply& rep)
        {
            rep.status  = http::server::reply::ok;
            rep.content = R"({"message":"Hello, World!","library":"libwebem"})";
            http::server::reply::add_header(&rep, "Content-Type", "application/json");
        },
        /*bypassAuthentication=*/true);

    // A second endpoint that echoes the request URI back to the caller
    server.RegisterPageCode("/api/echo",
        [](http::server::WebEmSession& /*session*/,
           const http::server::request& req,
           http::server::reply& rep)
        {
            rep.status  = http::server::reply::ok;
            rep.content = R"({"uri":")" + req.uri + R"("})";
            http::server::reply::add_header(&rep, "Content-Type", "application/json");
        },
        /*bypassAuthentication=*/true);

    // ------------------------------------------------------------------
    // 4. Start the server (blocks until Stop() is called)
    // ------------------------------------------------------------------
    std::cout << "Simple HTTP server running on http://localhost:8080\n";
    std::cout << "  Static files: http://localhost:8080/\n";
    std::cout << "  JSON hello:   http://localhost:8080/api/hello\n";
    std::cout << "  JSON echo:    http://localhost:8080/api/echo?foo=bar\n";
    std::cout << "Press Ctrl+C to stop.\n";

    server.Run();

    std::cout << "Server stopped.\n";
    return 0;
}
