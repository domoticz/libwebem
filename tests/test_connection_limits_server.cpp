//
// test_connection_limits_server.cpp
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// A small, fully-configurable libwebem server used by test_connection_limits.py to
// exercise the connection resource limits end to end. Every limit is settable
// from argv so the Python driver can pick values small enough to trip in seconds
// rather than the production defaults.
//
//   test_connection_limits_server <port> <max_connections> <max_requests_per_connection>
//                   <max_write_queue_bytes> <tls_handshake_timeout>
//
// Endpoints:
//   /api/ping   -> 200, tiny JSON body (drives keep-alive / request-budget tests)
//   /api/flood  -> SSE stream that pushes hard, so a client that stops reading
//                  makes the write queue grow and trip max_write_queue_bytes
//   /api/echo   -> 200, echoes the request body back verbatim. Used to prove a
//                  POST body delivered across several TCP segments (and
//                  therefore several handle_read callbacks) is still parsed
//                  completely and correctly, rather than hanging or being
//                  truncated/corrupted by the incremental parser.
//
// Prints "READY <port>" on stdout once listening, so the driver can synchronise
// without polling blindly.
//
#include <libwebem/cWebem.h>
#include <libwebem/ISseHandler.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>
#include <thread>

using namespace http::server;

namespace {

// Pushes SSE events continuously until stopped. The point is to outrun a client
// that refuses to read, so connection::MyWrite keeps queueing and eventually
// exceeds max_write_queue_bytes.
class flood_handler : public ISseHandler
{
public:
	explicit flood_handler(std::function<void(const std::string &)> writer)
		: writer_(std::move(writer))
	{
	}

	~flood_handler() override { stop_flag_ = true; if (th_.joinable()) th_.join(); }

	void Start() override
	{
		th_ = std::thread([this] {
			// ~4 KB per event; at this rate an unread socket fills its window fast.
			const std::string payload(4000, 'x');
			while (!stop_flag_)
			{
				writer_("data: " + payload + "\n\n");
				std::this_thread::sleep_for(std::chrono::milliseconds(2));
			}
		});
	}

	void Stop() override
	{
		stop_flag_ = true;
		if (th_.joinable())
			th_.join();
	}

	bool IsAlive() const override { return !stop_flag_; }

private:
	std::function<void(const std::string &)> writer_;
	std::thread th_;
	std::atomic<bool> stop_flag_{ false };
};

cWebem *g_server = nullptr;

} // namespace

int main(int argc, char **argv)
{
	if (argc < 6)
	{
		std::fprintf(stderr,
			     "usage: %s <port> <max_connections> <max_requests_per_connection>"
			     " <max_write_queue_bytes> <tls_handshake_timeout>\n",
			     argv[0]);
		return 2;
	}

	server_settings settings;
	settings.listening_address = "127.0.0.1";
	settings.listening_port = argv[1];
	settings.server_name = "libwebem-conn-limits-test/1.0";
	settings.max_connections = static_cast<size_t>(std::strtoull(argv[2], nullptr, 10));
	settings.max_requests_per_connection = static_cast<unsigned int>(std::strtoul(argv[3], nullptr, 10));
	settings.max_write_queue_bytes = static_cast<size_t>(std::strtoull(argv[4], nullptr, 10));
	settings.tls_handshake_timeout = static_cast<int>(std::strtol(argv[5], nullptr, 10));
	// Left at its shipped default (0 = disabled) on purpose: the driver asserts that
	// many connections from one address are all admitted.
	settings.max_connections_per_ip = 0;

	cWebem server(settings, "./www");
	g_server = &server;

	// CheckAuthentication fails closed when the user table is empty (every request
	// would 500), so register one user. Password is the MD5 of "test".
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

	server.RegisterPageCode(
		"/api/echo",
		[](WebEmSession &, const request &req, reply &rep) {
			rep.status = reply::ok;
			rep.content = req.content;
			reply::add_header(&rep, "Content-Type", "application/octet-stream");
		},
		/*bypassAuthentication=*/true);

	server.RegisterPageCode(
		"/api/flood",
		[](WebEmSession &session, const request &, reply &rep) {
			rep.status = reply::sse_stream;
			rep.sse_session = session;
		},
		/*bypassAuthentication=*/true);

	server.RegisterSseEndpoint("/api/flood",
				   [](std::function<void(const std::string &)> writer,
				      const WebEmSession &, const std::string &) {
					   return std::make_shared<flood_handler>(std::move(writer));
				   });

	std::printf("READY %s\n", settings.listening_port.c_str());
	std::fflush(stdout);

	server.Run();
	return 0;
}
