//
// test_ws_write_race_server.cpp
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// Stress server for test_ws_write_race.py.
//
// The finding this exercises: WS_Write() is called, by design, from
// arbitrary application threads (the writer-callback pattern in
// examples/03_websocket), and used to reach boost::asio::async_write on the
// raw socket directly from whatever thread called it. Meanwhile the io
// thread can be inside connection::stop() closing that same socket (e.g.
// because the client reset the TCP connection). Both touching the socket at
// once is undefined behaviour as far as Asio is concerned.
//
// A background thread here (PusherThreadMain) hammers WS_Write() on every
// live connection as fast as it can, completely independently of any
// connection's own io. test_ws_write_race.py opens many WebSocket
// connections and aborts each one with a TCP RST (not a clean close) shortly
// after the upgrade completes, so the io thread is very likely to be mid-
// teardown while the pusher thread is mid-write on the same connection.
//
// This is a stress test, not a proof: MSVC has no ThreadSanitizer, so a
// clean run here demonstrates "no crash/hang under sustained concurrent
// load", not "the race is provably closed". See the accompanying .py driver.
//
#include <libwebem/cWebem.h>
#include <libwebem/IWebsocketHandler.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

using namespace http::server;

namespace {

// The registry holds weak_ptrs only, never shared_ptrs. The sole strong
// owner of a handler is CWebsocket::m_handler (see Websockets.h/.cpp), which
// lives exactly as long as the connection's websocket_parser does and is
// released via connection::stop() -> DetachHandler() -> ... -> Stop() ->
// shared_ptr destroyed. If this registry held shared_ptrs instead, it would
// keep every handler alive for as long as it stayed registered, which
// creates a lifetime trap: getting it back out again needs a shared_ptr to
// erase, and the only place that's naturally available from inside the
// handler itself is shared_from_this() -- which is undefined behaviour when
// called from ~PushHandler() (the control block is already gone, so it
// throws std::bad_weak_ptr, and throwing out of an implicitly-noexcept
// destructor calls std::terminate()).
//
// weak_ptr sidesteps all of that: PusherThreadMain's lock() either yields a
// shared_ptr that keeps the handler alive for exactly the duration of one
// Push() call, or observes the weak_ptr already expired and prunes it.
// Nothing in this registry ever keeps a handler alive on its own.
std::mutex g_handlers_mutex;
std::set<std::weak_ptr<class PushHandler>, std::owner_less<std::weak_ptr<class PushHandler>>> g_handlers;

// One instance per live WebSocket connection. Registration happens in the
// factory below, where std::make_shared first produces this handler's
// shared_ptr -- the only place its control block is naturally at hand --
// rather than inside Start()/Stop(), which only ever see a raw
// IWebsocketHandler*, or in the destructor, where shared_from_this() would
// be unsafe (see the comment above g_handlers).
class PushHandler : public IWebsocketHandler
{
public:
	explicit PushHandler(std::function<void(const std::string &)> text_writer)
		: writer_(std::move(text_writer))
	{
	}

	bool Handle(const std::string &, bool /*outbound*/) override { return true; }

	// Registry membership doesn't depend on the Start()/Stop() lifecycle at
	// all (see the factory below), so these have nothing to do.
	void Start() override {}
	void Stop() override {}

	// Called from PusherThreadMain, i.e. a thread with no relationship
	// whatsoever to this connection's io -- exactly the "arbitrary
	// application thread" the writer-callback contract promises to support.
	void Push(const std::string &payload) { writer_(payload); }

private:
	std::function<void(const std::string &)> writer_;
};

std::atomic<bool> g_running{ true };

void PusherThreadMain()
{
	const std::string payload(64, 'x');
	while (g_running)
	{
		std::vector<std::shared_ptr<PushHandler>> snapshot;
		{
			std::lock_guard<std::mutex> lock(g_handlers_mutex);
			for (auto it = g_handlers.begin(); it != g_handlers.end();)
			{
				// lock() atomically yields either a live shared_ptr (handler
				// still alive; keeps it alive for the Push() call below even
				// if the io thread destroys the connection a moment later)
				// or an empty one (handler already gone). Either way there
				// is no window where a freed PushHandler gets dereferenced.
				if (auto sp = it->lock())
				{
					snapshot.push_back(std::move(sp));
					++it;
				}
				else
				{
					it = g_handlers.erase(it);
				}
			}
		}
		for (auto &h : snapshot)
		{
			h->Push(payload);
		}
		std::this_thread::sleep_for(std::chrono::microseconds(200));
	}
}

} // namespace

int main(int argc, char **argv)
{
	if (argc < 2)
	{
		std::fprintf(stderr, "usage: %s <port>\n", argv[0]);
		return 2;
	}

	server_settings settings;
	settings.listening_address = "127.0.0.1";
	settings.listening_port = argv[1];
	settings.server_name = "libwebem-ws-write-race-test/1.0";

	cWebem server(settings, "./www");

	// CheckAuthentication fails closed when the user table is empty (every
	// request would 500 before it even gets to the bypass-authentication
	// check below), so register one user. Password is the MD5 of "test".
	server.AddUserPassword(1, "test", "098f6bcd4621d373cade4e832627b4f6", "", "",
			       URIGHTS_ADMIN, 0);

	// No sub-protocol requirement, and whitelisted so the upgrade handshake
	// does not need a logged-in session -- this test is only about the
	// socket-level race, not authentication.
	server.RegisterPageCode(
		"/ws/push",
		[](WebEmSession &, const request &, reply &) {},
		/*bypassAuthentication=*/true);

	server.RegisterWebsocketEndpoint(
		"/ws/push",
		[](cWebem *,
		   std::function<void(const std::string &)> text_writer,
		   std::function<void(const std::string &)> /*binary_writer*/,
		   const WebEmSession &) {
			auto handler = std::make_shared<PushHandler>(std::move(text_writer));
			{
				std::lock_guard<std::mutex> lock(g_handlers_mutex);
				g_handlers.insert(handler);
			}
			return handler;
		},
		/*protocol=*/"");

	server.RegisterPageCode(
		"/api/ping",
		[](WebEmSession &, const request &, reply &rep) {
			rep.status = reply::ok;
			rep.content = R"({"ok":true})";
			reply::add_header(&rep, "Content-Type", "application/json");
		},
		/*bypassAuthentication=*/true);

	std::thread pusher(PusherThreadMain);

	std::printf("READY %s\n", settings.listening_port.c_str());
	std::fflush(stdout);

	server.Run();

	g_running = false;
	pusher.join();
	return 0;
}
