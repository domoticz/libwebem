//
// test_httpoxy.cpp
// ~~~~~~~~~~~~~~~~
//
// Regression test for the httpoxy class of bugs (CVE-2016-5385): a client-supplied
// "Proxy:" request header must not become HTTP_PROXY in the PHP/CGI child's
// environment. libcurl, PHP streams and most HTTP clients treat HTTP_PROXY as "route
// my outbound requests through this proxy" -- since php_cgi_path is reachable by any
// unauthenticated client, sending a single extra header would otherwise let an
// attacker redirect every outbound request a PHP script makes through a server of
// their choosing.
//
// fastcgi_parser::handlePHP() builds the CGI child's environment map directly from
// the request's headers (src/fastcgi.cpp) and is exercised here directly -- no HTTP
// server needed -- against a real request carrying a "Proxy" header. In place of a
// real php-cgi binary (which the machine running these tests is not guaranteed to
// have installed), settings.php_cgi_path points at test_httpoxy_helper, a tiny
// stand-in interpreter built alongside this test that reports back exactly which
// environment variables it saw. That proves what the CHILD's actual environment
// contains, not merely what fastcgi.cpp intended to pass.
//
// Usage:
//     test_httpoxy <path-to-test_httpoxy_helper[.exe]>
//
#include "fastcgi.h"
#include <libwebem/request.h>
#include <libwebem/reply.h>
#include <libwebem/server_settings.h>

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>

static int g_failures = 0;
static int g_checks = 0;

#define CHECK(cond)                                                        \
    do {                                                                   \
        ++g_checks;                                                        \
        if (!(cond)) {                                                     \
            ++g_failures;                                                  \
            std::printf("FAIL: %s (line %d)\n", #cond, __LINE__);          \
        }                                                                  \
    } while (0)

using namespace http::server;

int main(int argc, char **argv)
{
	if (argc < 2)
	{
		std::fprintf(stderr, "usage: %s <path-to-test_httpoxy_helper[.exe]>\n", argv[0]);
		return 2;
	}

	// handlePHP() only checks that the target script exists on disk (interpretation
	// is delegated entirely to php_cgi_path, the stand-in helper here) -- its content
	// is never read or executed, so an empty placeholder file is enough.
	std::filesystem::path wwwRoot = std::filesystem::current_path() / "httpoxy_test_www";
	std::filesystem::create_directories(wwwRoot);
	{
		std::ofstream placeholder((wwwRoot / "test.php").string());
	}

	server_settings settings;
	settings.www_root = wwwRoot.string();
	settings.php_cgi_path = argv[1];
	settings.server_name = "webem-httpoxy-test";

	request req;
	req.method = "GET";
	req.uri = "/test.php";
	req.http_version_major = 1;
	req.http_version_minor = 1;
	req.headers.push_back({"Host", "127.0.0.1"});
	// The attack: an ordinary, unauthenticated client can set this on any request.
	req.headers.push_back({"Proxy", "http://attacker.example:8080"});
	// An ordinary header, to prove headers reach the child's environment at all --
	// otherwise "HTTP_PROXY is unset" could just mean nothing gets through.
	req.headers.push_back({"X-Custom-Test", "expected-value"});
	// A lookalike header name: only an exact "Proxy" match should be excluded.
	req.headers.push_back({"Proxy-Something", "keep-me"});

	reply rep;
	modify_info mInfo{};
	bool ok = fastcgi_parser::handlePHP(settings, "/test.php", req, rep, mInfo, nullptr);
	CHECK(ok);

	std::printf("---- helper response body ----\n%s\n-------------------------------\n", rep.content.c_str());

	CHECK(rep.content.find("HTTP_PROXY=(unset)") != std::string::npos);
	CHECK(rep.content.find("HTTP_X_CUSTOM_TEST=expected-value") != std::string::npos);
	CHECK(rep.content.find("HTTP_PROXY_SOMETHING=keep-me") != std::string::npos);

	std::printf("\n%d checks, %d failure(s)\n", g_checks, g_failures);
	return g_failures == 0 ? 0 : 1;
}
