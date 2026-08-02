//
// test_tls_handshake_timeout_server.cpp
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// Server used by test_tls_handshake_timeout.py.
//
// The finding: an HTTPS listener used to hold a connection's socket, SSL
// socket and timers open indefinitely if a client completed the TCP
// handshake but never sent (or never finished) its TLS ClientHello -- the
// only backstop was the 20-minute abandoned-connection timeout, so a modest
// number of clients that connect and go silent could pin that many
// half-open connections for a very long time. tls_handshake_timeout bounds
// that separately and much lower (connection::set_handshake_timeout() /
// handle_handshake_timeout() in connection.cpp).
//
//   test_tls_handshake_timeout_server <port> <tls_handshake_timeout_seconds>
//       <cert_file> <key_file>
//
// Endpoints:
//   /api/ping  -> 200, tiny JSON body, reachable over a real completed TLS
//                 handshake, so the driver can confirm the listener still
//                 works normally after (and independently of) the timeout.
//
// Prints "READY <port>" on stdout once listening.
//
#include <libwebem/cWebem.h>

#ifndef WWW_ENABLE_SSL
#  error "test_tls_handshake_timeout_server requires libwebem built with WEBEM_ENABLE_SSL=ON"
#endif

#include <cstdio>
#include <cstdlib>
#include <string>

using namespace http::server;

int main(int argc, char **argv)
{
	if (argc < 5)
	{
		std::fprintf(stderr, "usage: %s <port> <tls_handshake_timeout_seconds> <cert_file> <key_file>\n", argv[0]);
		return 2;
	}

	ssl_server_settings settings;
	settings.listening_address = "127.0.0.1";
	settings.listening_port = argv[1];
	settings.server_name = "libwebem-tls-handshake-timeout-test/1.0";
	settings.tls_handshake_timeout = static_cast<int>(std::strtol(argv[2], nullptr, 10));

	// Self-signed test certificate; no DH params needed (tmp_dh_file_path
	// left empty is a supported, logged-but-non-fatal configuration -- see
	// ssl_server::init() in server.cpp) since nothing here negotiates a
	// DHE cipher suite deliberately.
	settings.cert_file_path = argv[3];
	settings.certificate_chain_file_path = argv[3];
	settings.private_key_file_path = argv[4];

	cWebem server(settings, "./www");

	// CheckAuthentication fails closed when the user table is empty, so
	// register one even though every endpoint below bypasses it anyway.
	server.AddUserPassword(1, "test", "098f6bcd4621d373cade4e832627b4f6", "", "",
			       URIGHTS_ADMIN, 0);

	server.RegisterPageCode(
		"/api/ping",
		[](WebEmSession &, const request &, reply &rep) {
			rep.status = reply::ok;
			rep.content = R"({"ok":true})";
			reply::add_header(&rep, "Content-Type", "application/json");
		},
		/*bypassAuthentication=*/true);

	std::printf("READY %s\n", settings.listening_port.c_str());
	std::fflush(stdout);

	server.Run();
	return 0;
}
