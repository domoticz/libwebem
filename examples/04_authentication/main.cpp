// Example 04 — Authentication and session management
//
// Demonstrates:
//   - SetAuthenticationMethod() — form-based login vs. HTTP Basic
//   - AddUserPassword() — registering users with different rights levels
//   - AddTrustedNetworks() — bypassing auth for specific IP ranges
//   - bypassAuthentication flag — public endpoints that skip auth checks
//   - Reading session information (username, rights, trusted network) in handlers
//   - RegisterWhitelistURLString() — additional auth-bypass by URL pattern
//
// Run:
//   ./auth_server
//   open http://localhost:8080/
//   curl http://localhost:8080/api/public
//   curl http://127.0.0.1:8080/api/whoami      # trusted network — no login required
//   curl -u admin:secret http://localhost:8080/api/whoami  (Basic auth only if allowed)

#include <libwebem/cWebem.h>
#include <iostream>
#include <csignal>
#include <string>

static http::server::cWebem* g_server = nullptr;

static void signal_handler(int /*sig*/)
{
    if (g_server)
        g_server->Stop();
}

// Simple helper: build a JSON response with status 200
static void json_ok(http::server::reply& rep, const std::string& body)
{
    rep.status  = http::server::reply::ok;
    rep.content = body;
    http::server::reply::add_header(&rep, "Content-Type", "application/json");
}

int main()
{
    http::server::server_settings settings;
    settings.listening_address = "::";
    settings.listening_port    = "8080";

    http::server::cWebem server(settings, "./www");
    g_server = &server;

    std::signal(SIGINT,  signal_handler);
    std::signal(SIGTERM, signal_handler);

    // ------------------------------------------------------------------
    // 1. Authentication configuration
    // ------------------------------------------------------------------

    // Use form-based login (the default): clients POST credentials to the
    // login page; the server creates a session cookie.
    // Switch to AUTH_BASIC for HTTP Basic/Digest authentication instead.
    server.SetAuthenticationMethod(http::server::AUTH_LOGIN);

    // Set the Digest auth realm (used when AUTH_BASIC is active)
    server.SetDigistRealm("libwebem Example");

    // Reject plain (unencrypted) HTTP Basic auth — require HTTPS
    server.SetAllowPlainBasicAuth(false);

    // ------------------------------------------------------------------
    // 2. Register users
    //
    // In production, passwords should be stored and compared as SHA-256
    // (or stronger) hashes.  Here we use plain strings for clarity.
    // Parameters: ID, username, password, mfatoken, passkeys,
    //             rights, active_tabs
    // ------------------------------------------------------------------
    server.AddUserPassword(1, "admin",  "secret",      "", "",
                           http::server::URIGHTS_ADMIN,   0xFF);
    server.AddUserPassword(2, "viewer", "viewerpass",  "", "",
                           http::server::URIGHTS_VIEWER,  0x0F);

    // ------------------------------------------------------------------
    // 3. Trusted networks — these addresses bypass authentication entirely
    // ------------------------------------------------------------------
    server.AddTrustedNetworks("127.0.0.1/32");   // IPv4 loopback
    server.AddTrustedNetworks("::1/128");          // IPv6 loopback

    // ------------------------------------------------------------------
    // 4. URL whitelist — patterns that bypass auth (all methods)
    // ------------------------------------------------------------------
    server.RegisterWhitelistURLString("/api/public");

    // ------------------------------------------------------------------
    // 5. Register endpoints
    // ------------------------------------------------------------------

    // Public endpoint — bypassAuthentication=true means no login required
    // regardless of the authentication method configured above.
    server.RegisterPageCode("/api/public",
        [](http::server::WebEmSession& /*session*/,
           const http::server::request& /*req*/,
           http::server::reply& rep)
        {
            json_ok(rep, R"({"endpoint":"public","auth":"not required"})");
        },
        /*bypassAuthentication=*/true);

    // Protected endpoint — returns information about the authenticated session
    server.RegisterPageCode("/api/whoami",
        [](http::server::WebEmSession& session,
           const http::server::request& /*req*/,
           http::server::reply& rep)
        {
            std::string rights_str;
            switch (session.rights) {
                case http::server::URIGHTS_VIEWER:   rights_str = "viewer";   break;
                case http::server::URIGHTS_SWITCHER: rights_str = "switcher"; break;
                case http::server::URIGHTS_ADMIN:    rights_str = "admin";    break;
                default:                             rights_str = "unknown";  break;
            }

            std::string body =
                R"({"username":")" + session.username + R"(",)"
                R"("rights":")"   + rights_str        + R"(",)"
                R"("session":")"  + session.id         + R"(",)"
                R"("trusted":)"   + (session.istrustednetwork ? "true" : "false") +
                R"(})";

            json_ok(rep, body);
        });

    // Admin-only endpoint — handler checks rights and returns 403 if insufficient
    server.RegisterPageCode("/api/admin",
        [](http::server::WebEmSession& session,
           const http::server::request& /*req*/,
           http::server::reply& rep)
        {
            if (session.rights != http::server::URIGHTS_ADMIN)
            {
                rep.status  = http::server::reply::forbidden;
                rep.content = R"({"error":"admin rights required"})";
                http::server::reply::add_header(&rep, "Content-Type", "application/json");
                return;
            }
            json_ok(rep, R"({"message":"Welcome, admin!","access":"full"})");
        });

    // ------------------------------------------------------------------
    // 6. Start the server
    // ------------------------------------------------------------------
    std::cout << "Authentication server running on http://localhost:8080\n";
    std::cout << "  Public:   http://localhost:8080/api/public    (no auth)\n";
    std::cout << "  Whoami:   http://localhost:8080/api/whoami    (auth required)\n";
    std::cout << "  Admin:    http://localhost:8080/api/admin     (admin rights)\n";
    std::cout << "\n";
    std::cout << "  Users:    admin / secret   (admin)\n";
    std::cout << "            viewer / viewerpass (viewer)\n";
    std::cout << "\n";
    std::cout << "  Trusted:  127.0.0.1 and ::1 — no login required from localhost\n";
    std::cout << "Press Ctrl+C to stop.\n";

    server.Run();

    std::cout << "Server stopped.\n";
    return 0;
}
