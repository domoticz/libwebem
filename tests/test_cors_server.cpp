//
// test_cors_server.cpp
// ~~~~~~~~~~~~~~~~~~~~~
//
// Server used by test_cors.py to exercise the CORS/Origin hardening around the
// trusted-network authentication bypass (see docs/INTEGRATION.md, "CORS and
// trusted networks -- read this together").
//
// Loopback is configured as a trusted network here, exactly like
// test_proxy_trust_server.cpp: it reproduces the reverse-proxy-on-localhost
// deployment shape, so every request the driver sends below already carries
// admin rights with NO cookie at all. Whether a foreign website's JavaScript
// can read the response, or open a WebSocket with those rights, is entirely
// down to the CORS/Origin handling this test proves.
//
//   test_cors_server <port>
//
#include <libwebem/cWebem.h>
#include <libwebem/IWebsocketHandler.h>

#include <cstdio>
#include <filesystem>
#include <fstream>
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

	// A real static asset under www_root, so the "static assets are unaffected"
	// assertion exercises the actual request_handler.cpp file-serving path
	// (Access-Control-Allow-Origin: * is still sent there, unconditionally --
	// that behaviour is deliberately untouched) rather than a stand-in for it.
	std::filesystem::create_directories("www");
	{
		std::ofstream f("www/asset.txt", std::ios::binary | std::ios::trunc);
		f << "static asset content";
	}

	server_settings settings;
	settings.listening_address = "127.0.0.1";
	settings.listening_port = argv[1];
	settings.server_name = "libwebem-cors-test/1.0";
	// The one origin allowed to read cross-origin API responses / open a
	// cross-origin WebSocket against this trusted-network deployment.
	settings.allowed_cors_origins.push_back("https://allowed.example.com");

	cWebem server(settings, "./www");

	// Loopback is trusted -- the same deployment shape as
	// test_proxy_trust_server.cpp (a reverse proxy on the same host).
	server.AddTrustedNetworks("127.0.0.1/32");

	// CheckAuthentication fails closed when the user table is empty, so an admin
	// must exist even though every endpoint below bypasses authentication.
	server.AddUserPassword(1, "admin", "098f6bcd4621d373cade4e832627b4f6", "", "",
			       URIGHTS_ADMIN, 0);

	// Registered via RegisterPageCode with a "/json.htm?" URI, exactly the path
	// cWebem::CheckForPageOverride uses to sniff the "json" extension and decide
	// this response is API/page content (not an image) -- the same code path
	// Domoticz's own /json.htm goes through, and the one that used to call
	// reply::add_cors_headers() with an unconditional "*".
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
