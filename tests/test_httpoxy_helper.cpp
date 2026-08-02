//
// test_httpoxy_helper.cpp
// ~~~~~~~~~~~~~~~~~~~~~~~
//
// Minimal stand-in for a php-cgi interpreter, used only by webem_test_httpoxy
// (test_httpoxy.cpp) in place of a real php-cgi binary, which the machine
// running the tests is not guaranteed to have installed.
//
// fastcgi_parser::handlePHP() invokes settings.php_cgi_path as a child process
// with the request's headers turned into HTTP_* environment variables (see
// src/fastcgi.cpp). This helper ignores its argv (the script path a real
// interpreter would read and execute) and instead reports back, in the raw CGI
// response format handlePHP() parses (headers, blank line, body), whether two
// specific environment variables were present in ITS OWN environment when it
// ran -- HTTP_PROXY (which must never arrive, see CVE-2016-5385/httpoxy) and
// HTTP_X_CUSTOM_TEST (an ordinary header, included so the test can tell "the
// exclusion works" apart from "no headers reach the child at all").
//
#include <cstdio>
#include <cstdlib>

static const char *envOrUnset(const char *name)
{
	const char *v = std::getenv(name);
	return (v != nullptr) ? v : "(unset)";
}

int main()
{
	std::printf("Content-Type: text/plain\n");
	std::printf("\n");
	std::printf("HTTP_PROXY=%s\n", envOrUnset("HTTP_PROXY"));
	std::printf("HTTP_X_CUSTOM_TEST=%s\n", envOrUnset("HTTP_X_CUSTOM_TEST"));
	// A header that merely starts with "Proxy" (rather than being an exact,
	// case-insensitive match) must still pass through -- the fix targets the
	// literal "Proxy" header name only, not a prefix.
	std::printf("HTTP_PROXY_SOMETHING=%s\n", envOrUnset("HTTP_PROXY_SOMETHING"));
	std::fflush(stdout);
	return 0;
}
