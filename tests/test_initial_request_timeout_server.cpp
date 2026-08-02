//
// test_initial_request_timeout_server.cpp
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// Server used by test_initial_request_timeout.py.
//
// The finding: a connection that never completes its first HTTP request was
// bounded only by read_timeout -- reset by EVERY byte received, complete
// request or not -- and, past that, the 20-minute abandoned-connection
// timeout. A client trickling a single byte slightly more often than
// read_timeout could hold a global connection slot (see
// server_settings::max_connections) for the full 20 minutes without ever
// completing a request: the slowloris pattern. initial_request_timeout
// bounds that separately: started once reading begins and, unlike
// read_timeout, never reset by individual bytes arriving -- only by a
// request actually completing (see connection::set_initial_request_timeout()
// / handle_initial_request_timeout() in connection.cpp).
//
//   test_initial_request_timeout_server <port> <initial_request_timeout_secs>
//
// read_timeout itself is fixed at 20s (server_base's hardcoded default) and
// is not exposed as a setting, so every configured initial_request_timeout
// here must stay well below that for the distinction this test exists to
// prove -- a silent or slow-trickling connection dropped near
// initial_request_timeout, not near the unrelated, much longer read_timeout
// -- to be visible at all.
//
// Endpoints:
//   /api/ping  -> 200, tiny JSON body, so the driver can confirm the
//                 listener still serves real requests normally, both before
//                 and after the timeout fires on an unrelated connection.
//
// Prints "READY <port>" on stdout once listening.
//
#include <libwebem/cWebem.h>

#include <cstdio>
#include <cstdlib>
#include <string>

using namespace http::server;

int main(int argc, char **argv)
{
	if (argc < 3)
	{
		std::fprintf(stderr, "usage: %s <port> <initial_request_timeout_secs>\n", argv[0]);
		return 2;
	}

	server_settings settings;
	settings.listening_address = "127.0.0.1";
	settings.listening_port = argv[1];
	settings.server_name = "libwebem-initial-request-timeout-test/1.0";
	settings.initial_request_timeout = static_cast<int>(std::strtol(argv[2], nullptr, 10));

	cWebem server(settings, "./www");

	// CheckAuthentication fails closed when the user table is empty, so
	// register one even though the endpoint below bypasses it anyway.
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
