//
// test_proxy_trust_server.cpp
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// Server used by test_proxy_trust.py to prove that a forged forwarded-for header
// cannot buy trusted-network rights.
//
// It reproduces the vulnerable deployment shape exactly: the loopback address is a
// TRUSTED network, which is what a reverse proxy running on the same host looks
// like to libwebem (and is what docs/INTEGRATION.md recommends configuring). Every
// request the driver sends therefore arrives from a trusted peer, and the only
// thing standing between the caller and administrative access is the correctness
// of the proxy-header handling.
//
//   test_proxy_trust_server <port> [family]
//
// <family> selects server_settings::trusted_proxy_header_family and defaults to
// "none" (the library default) when omitted:
//   none      -> ProxyHeaderFamily::None          (proxy headers ignored entirely)
//   forwarded -> ProxyHeaderFamily::Forwarded      ("Forwarded", RFC 7239)
//   xff       -> ProxyHeaderFamily::XForwardedFor  ("X-Forwarded-For")
//   xri       -> ProxyHeaderFamily::XRealIP        ("X-Real-IP")
//
// /api/whoami reports the session the server resolved, so the driver can assert on
// the rights actually granted rather than on a proxy for them.
//
#include <libwebem/cWebem.h>

#include <cstdio>
#include <cstring>
#include <string>

using namespace http::server;

int main(int argc, char **argv)
{
	if (argc < 2)
	{
		std::fprintf(stderr, "usage: %s <port> [none|forwarded|xff|xri]\n", argv[0]);
		return 2;
	}

	server_settings settings;
	settings.listening_address = "127.0.0.1";
	settings.listening_port = argv[1];
	settings.server_name = "libwebem-proxy-trust-test/1.0";

	std::string family = (argc >= 3) ? argv[2] : "none";
	if (family == "none")
	{
		settings.trusted_proxy_header_family = ProxyHeaderFamily::None;
	}
	else if (family == "forwarded")
	{
		settings.trusted_proxy_header_family = ProxyHeaderFamily::Forwarded;
	}
	else if (family == "xff")
	{
		settings.trusted_proxy_header_family = ProxyHeaderFamily::XForwardedFor;
	}
	else if (family == "xri")
	{
		settings.trusted_proxy_header_family = ProxyHeaderFamily::XRealIP;
	}
	else
	{
		std::fprintf(stderr, "unknown family '%s' (expected none|forwarded|xff|xri)\n", family.c_str());
		return 2;
	}

	cWebem server(settings, "./www");

	// The deployment under test: our own peer address is trusted, exactly as it
	// would be with a reverse proxy on localhost.
	server.AddTrustedNetworks("127.0.0.1/32");

	// An admin must exist, otherwise CheckAuthentication fails closed for every
	// request and the test could not tell "denied" from "misconfigured".
	server.AddUserPassword(1, "admin", "098f6bcd4621d373cade4e832627b4f6", "", "",
			       URIGHTS_ADMIN, 0);

	server.RegisterPageCode(
		"/api/whoami",
		[](WebEmSession &session, const request &, reply &rep) {
			rep.status = reply::ok;
			rep.content = std::string("{\"user\":\"") + session.username +
				      "\",\"rights\":" + std::to_string(static_cast<int>(session.rights)) +
				      ",\"trusted\":" + (session.istrustednetwork ? "true" : "false") + "}";
			reply::add_header(&rep, "Content-Type", "application/json");
		},
		/*bypassAuthentication=*/true);

	std::printf("READY %s\n", settings.listening_port.c_str());
	std::fflush(stdout);

	server.Run();
	return 0;
}
