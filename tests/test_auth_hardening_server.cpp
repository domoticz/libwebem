//
// test_auth_hardening_server.cpp
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// Server used by test_auth_hardening.py to prove that a malformed Authorization
// header can no longer take the webserver thread down.
//
// parse_auth_header()'s JWT branch used to call jwt::decode() and several claim
// accessors with nothing catching the exceptions they throw on malformed input
// (wrong segment count, non-JSON payload, ...), and separately dereferenced the
// audience set without checking it was non-empty. Both were reachable from a
// single unauthenticated request. This server registers a real ClientID/user pair
// so the driver can also confirm that a genuinely valid token still authenticates
// -- the hardening must reject bad input without breaking the good path.
//
// It also registers an ASYMMETRIC ClientID ("pubclient": PubKey set, SigningSecret
// deliberately empty) and a separate admin account ("root_admin"), so the driver
// can prove the algorithm/key-confusion fix: an HS256 token forged with an empty
// HMAC key, naming "pubclient" as audience and "root_admin" as subject, must be
// rejected rather than accepted on the strength of an empty-string HMAC key.
//
//   test_auth_hardening_server <port>
//
// Endpoints:
//   /api/whoami   -> requires authentication; reports the resolved session so the
//                    driver can tell "rejected" (401) from "accepted" (200, with
//                    the expected user/rights) rather than just "didn't crash".
//   /api/ping     -> bypasses authentication; used purely as a liveness probe.
//
// Prints "READY <port>" once listening, and "TOKEN <jwt>" with a valid JWT for the
// registered user, so the driver does not have to reimplement JWT signing.
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
	settings.server_name = "libwebem-auth-hardening-test/1.0";

	cWebem server(settings, "./www");

	// Deliberately no trusted network is configured: every request below must be
	// judged purely on the Authorization header it carries, exactly like a
	// deployment reachable from the open internet.

	// The ClientID user a JWT's "aud" claim must name, and the key its signature
	// is checked against.
	server.AddUserPassword(2, "myclient", "", "", "", URIGHTS_CLIENTID, /*activetabs=*/0,
			       "", "", 0, "test-signing-secret-for-hardening-tests");

	// The real user a valid token's "sub" claim names. The Password value is never
	// consulted on the JWT path (CheckAuthentication resolves the session directly
	// from the token once it verifies), so a placeholder is fine.
	server.AddUserPassword(1, "alice", "unused", "", "", URIGHTS_VIEWER, 0);

	// A ClientID registered ASYMMETRICALLY: activetabs is truthy (the same flag
	// GenerateJwtToken checks to decide whether to sign with PS256+PrivKey rather
	// than HS256+SigningSecret) and PubKey is set, but SigningSecret is
	// deliberately left EMPTY -- exactly the shape produced by a real deployment
	// registering a public-key client. Before the fix, an HS256 token was still
	// accepted for this ClientID because the guard only required "SigningSecret OR
	// PubKey non-empty", and jwt::algorithm::hs256{""} (an empty HMAC key) is
	// something OpenSSL's HMAC() happily accepts and anyone can forge.
	server.AddUserPassword(3, "pubclient", "", "", "", URIGHTS_CLIENTID, /*activetabs=*/1,
			       "", "dummy-placeholder-public-key-never-used-by-the-hs256-attack", 0, "");

	// The admin account the forged token's "sub" claim will try to impersonate.
	server.AddUserPassword(4, "root_admin", "unused", "", "", URIGHTS_ADMIN, 0);

	server.RegisterPageCode(
		"/api/whoami",
		[](WebEmSession &session, const request &, reply &rep) {
			rep.status = reply::ok;
			rep.content = std::string("{\"user\":\"") + session.username +
				      "\",\"rights\":" + std::to_string(static_cast<int>(session.rights)) + "}";
			reply::add_header(&rep, "Content-Type", "application/json");
		},
		/*bypassAuthentication=*/false);

	server.RegisterPageCode(
		"/api/ping",
		[](WebEmSession &, const request &, reply &rep) {
			rep.status = reply::ok;
			rep.content = R"({"ok":true})";
			reply::add_header(&rep, "Content-Type", "application/json");
		},
		/*bypassAuthentication=*/true);

	// Issue a token the driver can send back verbatim to prove a real, correctly
	// signed JWT still authenticates after the hardening changes. The issuer is
	// pinned to match the Host header the driver sends ("127.0.0.1"), since
	// parse_auth_header derives the expected issuer from that header.
	std::string token;
	if (!server.GenerateJwtToken(token, "myclient", "alice", /*exptime=*/3600, Json::Value(), "https://127.0.0.1/"))
	{
		std::fprintf(stderr, "failed to generate test JWT\n");
		return 2;
	}
	std::printf("TOKEN %s\n", token.c_str());

	std::printf("READY %s\n", settings.listening_port.c_str());
	std::fflush(stdout);

	server.Run();
	return 0;
}
