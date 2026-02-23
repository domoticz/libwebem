// Example 02 — HTTPS server with TLS
//
// Demonstrates:
//   - Using ssl_server_settings for HTTPS
//   - Configuring certificate, private key, and DH parameters
//   - Certificate hot-reloading (files are re-read on each new connection
//     if they have changed on disk — no restart required)
//
// Prerequisites:
//   - Build libwebem with WEBEM_ENABLE_SSL=ON (the default)
//   - Generate test certificates:  bash generate_certs.sh
//
// Run:
//   ./https_server
//   curl -k https://localhost:8443/api/secure
//   open https://localhost:8443/

#include <libwebem/cWebem.h>

// ssl_server_settings is only available when SSL support is compiled in.
#ifndef WWW_ENABLE_SSL
#  error "This example requires libwebem to be built with WEBEM_ENABLE_SSL=ON"
#endif

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
    // 1. Configure HTTPS settings
    //    Run generate_certs.sh to produce the required files.
    // ------------------------------------------------------------------
    http::server::ssl_server_settings settings;
    settings.listening_address           = "::";
    settings.listening_port              = "8443";
    settings.server_name                 = "libwebem-example/1.0";

    // Certificate files (paths relative to the working directory)
    settings.cert_file_path              = "server.crt";
    settings.private_key_file_path       = "server.key";
    settings.certificate_chain_file_path = "server.crt";  // same file for self-signed
    settings.tmp_dh_file_path            = "dhparam.pem";

    // TLS options (comma-separated list)
    settings.ssl_options = "default_workarounds,no_sslv2,no_sslv3,single_dh_use";

    // Optional: require client certificate
    // settings.verify_peer                    = true;
    // settings.verify_fail_if_no_peer_cert    = true;
    // settings.ca_cert_file_path              = "ca.crt";

    // ------------------------------------------------------------------
    // 2. Create the server
    // ------------------------------------------------------------------
    http::server::cWebem server(settings, "./www");
    g_server = &server;

    std::signal(SIGINT,  signal_handler);
    std::signal(SIGTERM, signal_handler);

    // ------------------------------------------------------------------
    // 3. Register endpoints
    // ------------------------------------------------------------------
    server.RegisterPageCode("/api/secure",
        [](http::server::WebEmSession& /*session*/,
           const http::server::request& /*req*/,
           http::server::reply& rep)
        {
            rep.status  = http::server::reply::ok;
            rep.content = R"({"secure":true,"tls":"active"})";
            http::server::reply::add_header(&rep, "Content-Type", "application/json");
        },
        /*bypassAuthentication=*/true);

    // ------------------------------------------------------------------
    // 4. Start the server
    // ------------------------------------------------------------------
    std::cout << "HTTPS server running on https://localhost:8443\n";
    std::cout << "  (use -k with curl to accept the self-signed certificate)\n";
    std::cout << "  curl -k https://localhost:8443/api/secure\n";
    std::cout << "Press Ctrl+C to stop.\n";

    server.Run();

    std::cout << "Server stopped.\n";
    return 0;
}
