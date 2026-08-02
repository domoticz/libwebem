//
// test_dns_rebinding_server.cpp
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// Server used by test_dns_rebinding.py to exercise server_settings::allowed_hosts
// (see docs/INTEGRATION.md, "DNS rebinding -- validate Host, don't just compare
// it to Origin").
//
// Loopback is trusted here, the same deployment shape as test_cors_server.cpp /
// test_proxy_trust_server.cpp: every request below already carries admin rights
// with no cookie at all. Without allowed_hosts, an attacker who gets a victim's
// browser on the trusted network to resolve a hostname they control to this
// server's address (DNS rebinding) is granted a WebSocket with those rights,
// because the WebSocket same-origin check just compares Origin against the
// request's own Host header -- which both read the attacker's chosen hostname
// and so "match" each other trivially. allowed_hosts closes that: Host is
// validated against a fixed list on every request, and Origin is compared
// against that same list instead of against Host.
//
//   test_dns_rebinding_server <port>
//
#include <libwebem/cWebem.h>
#include <libwebem/IWebsocketHandler.h>

#include <cstdio>
#include <memory>
#include <string>

using namespace http::server;

namespace {

// Minimal echo handler, only used to prove an upgrade completed.
class EchoWsHandler : public IWebsocketHandler
{
public:
	explicit EchoWsHandler(std::function<void(const std::string &)> writer)
		: writer_(std::move(writer))
	{
	}
	bool Handle(const std::string &data, bool /*outbound*/) override
	{
		writer_("echo: " + data);
		return true;
	}
	void Start() override {}
	void Stop() override {}

private:
	std::function<void(const std::string &)> writer_;
};

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
	settings.server_name = "libwebem-dns-rebinding-test/1.0";
	// The only hostnames this server considers itself known as. The driver's
	// baseline requests use "127.0.0.1" (the loopback address it actually
	// connects to); the simulated DNS-rebinding attack uses a hostname that
	// is deliberately NOT in this list, via an explicit Host header
	// independent of where the TCP connection actually goes -- exactly what
	// DNS rebinding achieves for a real browser.
	settings.allowed_hosts = { "127.0.0.1", "legit.example.com" };

	cWebem server(settings, "./www");

	// Loopback is trusted -- same deployment shape as test_cors_server.cpp.
	server.AddTrustedNetworks("127.0.0.1/32");

	// CheckAuthentication fails closed when the user table is empty, so an
	// admin must exist even though every endpoint below bypasses it anyway.
	server.AddUserPassword(1, "admin", "098f6bcd4621d373cade4e832627b4f6", "", "",
			       URIGHTS_ADMIN, 0);

	server.RegisterPageCode(
		"/json.htm",
		[](WebEmSession &, const request &, reply &rep) {
			rep.status = reply::ok;
			rep.content = R"({"ok":true})";
		},
		/*bypassAuthentication=*/true);

	server.RegisterWebsocketEndpoint(
		"/ws/echo",
		[](cWebem *,
		   std::function<void(const std::string &)> text_writer,
		   std::function<void(const std::string &)> /*binary_writer*/,
		   const WebEmSession &) {
			return std::make_shared<EchoWsHandler>(std::move(text_writer));
		},
		/*protocol=*/"");

	std::printf("READY %s\n", settings.listening_port.c_str());
	std::fflush(stdout);

	server.Run();
	return 0;
}
