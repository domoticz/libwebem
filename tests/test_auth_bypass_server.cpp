//
// test_auth_bypass_server.cpp
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// Server used by test_auth_bypass.py to prove that the authentication bypass
// whitelist for API commands is decided on the SAME parsed parameter set the
// page handler dispatches on.
//
// CheckAuthByPass used to locate the command by searching the raw URI for
// "?param=" / "&param=", while the page handler tokenised the query string into
// request::parameters and dispatched on request::findValue("param"). The two
// disagreed whenever the substring "?param=<whitelisted>" appeared INSIDE the
// value of another parameter:
//
//   /json.htm?foo=?param=logincheck&type=command&param=getsettings
//
// The raw search saw "logincheck" (whitelisted, bypass granted); the tokeniser
// handed the handler param=getsettings, which then ran without authentication.
//
//   test_auth_bypass_server <port>
//
// The server mirrors the Domoticz shape: a single protected page "/json.htm"
// (RegisterPageCode without bypass) whose handler echoes the "type" and "param"
// values it dispatched on plus the resolved session user, and a whitelisted
// command "logincheck" (RegisterWhitelistCommandsString) that may be called
// without credentials. Plain Basic auth is enabled so the driver can also show
// that a properly authenticated caller still reaches non-whitelisted commands.
//
// Prints "READY <port>" once listening.
//
#include <libwebem/cWebem.h>

#include <cstdio>
#include <string>

using namespace http::server;

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
	settings.server_name = "libwebem-auth-bypass-test/1.0";

	cWebem server(settings, "./www");

	// No trusted network: every request is judged on its own credentials, so an
	// unauthenticated request can only reach a page through the bypass whitelist.

	// Password is the MD5 of "test", the form AddUserPassword expects.
	server.AddUserPassword(1, "admin", "098f6bcd4621d373cade4e832627b4f6", "", "", URIGHTS_ADMIN, 0);

	// Basic auth over plain HTTP is normally refused; allow it here so the driver
	// can send "Authorization: Basic" without setting up TLS.
	server.SetAllowPlainBasicAuth(true);

	// The Domoticz API page. Deliberately NOT bypassAuthentication: only the
	// command whitelist below may let an unauthenticated request through.
	server.RegisterPageCode(
		"/json.htm",
		[](WebEmSession &session, const request &req, reply &rep) {
			// Echo exactly what a real dispatcher would act on: findValue() over
			// the parsed parameter set. If the bypass decision and this dispatch
			// ever disagree, the driver sees a non-whitelisted "param" served
			// with an empty user.
			rep.status = reply::ok;
			rep.content = std::string("{\"type\":\"") + request::findValue(&req, "type") +
				      "\",\"param\":\"" + request::findValue(&req, "param") +
				      "\",\"user\":\"" + session.username + "\"}";
			reply::add_header(&rep, "Content-Type", "application/json");
		},
		/*bypassAuthentication=*/false);

	// The one command an unauthenticated caller may run.
	server.RegisterWhitelistCommandsString("logincheck");

	std::printf("READY %s\n", settings.listening_port.c_str());
	std::fflush(stdout);

	server.Run();
	return 0;
}
