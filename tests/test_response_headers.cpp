//
// test_response_headers.cpp
// ~~~~~~~~~~~~~~~~~~~~~~~~~
//
// Standalone regression tests (own main(), no external test framework) for the
// reply-level parts of the response-header/CORS hardening:
//
//   - reply::add_header() must reject a name/value containing a control
//     character (in particular CR/LF, which would otherwise split the
//     response into an injected extra header) instead of emitting it verbatim.
//   - reply::add_header_attachment() and reply::set_download_file() must apply
//     the same check to the attachment name, at the point the application
//     supplies it, and must otherwise behave exactly as before for ordinary
//     filenames.
//   - reply::add_cors_headers() must never echo an Origin that isn't an exact
//     match for an entry in the allow-list, must add "Vary: Origin" only when
//     it does echo, and must add nothing at all when the allow-list is empty
//     or the Origin header was absent.
//
// The CORS *response-dispatch* behaviour (which of cWebem's call sites get no
// header vs. an echoed one, and the WebSocket-upgrade Origin check) is covered
// end-to-end by test_cors.py / test_cors_server.cpp, which exercise a real
// listening server; this file only tests the reply:: primitives in isolation.
//
// Lightweight harness (same style as test_hash_and_reply.cpp): each check
// increments a global counter and the process exits non-zero if anything
// failed.
//

#include <libwebem/reply.h>

#include <boost/algorithm/string.hpp>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>
#include <vector>

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

// Returns the header value for the (case-insensitive) name, or an empty
// optional-substitute ("\x01" sentinel would be overkill here) -- callers that
// care about "is it present at all" use header_present() instead.
static bool header_present(const reply &rep, const std::string &name)
{
    for (const auto &h : rep.headers)
    {
        if (boost::iequals(h.name, name))
            return true;
    }
    return false;
}

static std::string header_value(const reply &rep, const std::string &name)
{
    for (const auto &h : rep.headers)
    {
        if (boost::iequals(h.name, name))
            return h.value;
    }
    return {};
}

// Finding #16: a CRLF embedded in a header name or value must not reach the
// wire. add_header() must reject it outright (no header added at all) rather
// than emit a mangled/truncated line, and header_to_string() must not contain
// the injected "Y: 1" anywhere in its output.
static void test_add_header_rejects_crlf()
{
    reply rep;
    rep.status = reply::ok;

    reply::add_header(&rep, "X-Legit", "fine-value");
    CHECK(header_present(rep, "X-Legit"));
    CHECK(header_value(rep, "X-Legit") == "fine-value");

    size_t before = rep.headers.size();
    reply::add_header(&rep, "X", "a\r\nY: 1");
    CHECK(rep.headers.size() == before); // nothing was added
    CHECK(!header_present(rep, "X"));

    std::string wire = rep.header_to_string();
    CHECK(wire.find("Y: 1") == std::string::npos);
    CHECK(wire.find("a\r\nY") == std::string::npos);

    // A control character in the *name* must be rejected the same way.
    before = rep.headers.size();
    reply::add_header(&rep, "X-Bad\r\nInjected", "value");
    CHECK(rep.headers.size() == before);
    wire = rep.header_to_string();
    CHECK(wire.find("Injected") == std::string::npos);

    // The legitimate header from before must still be present and unharmed.
    CHECK(header_value(rep, "X-Legit") == "fine-value");
}

// A bare NUL or other C0 control character must be rejected too, not just \r\n.
static void test_add_header_rejects_other_control_chars()
{
    reply rep;
    size_t before = rep.headers.size();
    reply::add_header(&rep, "X-Test", std::string("bad\x01value", 9));
    CHECK(rep.headers.size() == before);
}

// Finding #16: add_header_attachment() must reject a CRLF-laden attachment
// name (the one live sink identified: an application deriving a download name
// from user input) and leave no Content-Disposition header behind, but must
// keep working normally for an ordinary filename.
static void test_add_header_attachment()
{
    reply rep;
    bool ok = reply::add_header_attachment(&rep, "report.csv");
    CHECK(ok);
    CHECK(header_value(rep, "Content-Disposition") == "attachment; filename=report.csv");

    reply rep2;
    ok = reply::add_header_attachment(&rep2, "a\r\nX-Injected: 1");
    CHECK(!ok);
    CHECK(!header_present(rep2, "Content-Disposition"));
    std::string wire = rep2.header_to_string();
    CHECK(wire.find("X-Injected") == std::string::npos);
}

// Finding #16: set_download_file() joins file_path and attachment with an
// internal "\r\n" delimiter that connection.cpp later splits back apart; a
// CRLF embedded in either value must be rejected here, at the point the
// application supplies it, rather than silently smuggling a second delimiter
// through. Ordinary filenames must be entirely unaffected.
static void test_set_download_file()
{
    reply rep;
    bool ok = reply::set_download_file(&rep, "/tmp/report.csv", "report.csv");
    CHECK(ok);
    CHECK(rep.status == reply::status_type::download_file);
    CHECK(rep.content == "/tmp/report.csv\r\nreport.csv");

    reply rep2;
    ok = reply::set_download_file(&rep2, "f.txt", "a\r\nX-Injected: 1");
    CHECK(!ok);
    // reset() is only called after validation succeeds, so a failed call must
    // not have mutated rep2 into a download_file reply at all.
    CHECK(rep2.status != reply::status_type::download_file);

    reply rep3;
    ok = reply::set_download_file(&rep3, "/tmp/re\r\nport.csv", "report.csv");
    CHECK(!ok);

    reply rep4;
    ok = reply::set_download_file(&rep4, "", "report.csv");
    CHECK(!ok); // empty file_path was already rejected before this change

    reply rep5;
    ok = reply::set_download_file(&rep5, "/tmp/report.csv", "");
    CHECK(!ok); // empty attachment was already rejected before this change
}

// set_content_from_file(..., attachment, ...) must propagate an attachment
// rejection as an overall failure instead of silently proceeding with a
// missing Content-Disposition header.
static void test_set_content_from_file_with_bad_attachment()
{
    const std::string path = "test_response_headers_tmpfile.bin";
    {
        std::ofstream out(path.c_str(), std::ios::out | std::ios::binary | std::ios::trunc);
        out << "payload";
    }

    reply rep;
    bool ok = reply::set_content_from_file(&rep, path, "snapshot.jpg", true);
    CHECK(ok);
    CHECK(header_value(rep, "Content-Disposition") == "attachment; filename=snapshot.jpg");

    reply rep2;
    ok = reply::set_content_from_file(&rep2, path, "a\r\nX-Injected: 1", true);
    CHECK(!ok);
    CHECK(!header_present(rep2, "Content-Disposition"));

    std::remove(path.c_str());
}

// Finding #15: add_cors_headers() must never send a bare "*", must only echo
// an Origin that is an exact match for an allow-list entry (adding
// "Vary: Origin" alongside it), and must add nothing at all otherwise --
// including when the Origin header was absent, or the allow-list is empty
// (the default, matching server_settings::allowed_cors_origins).
static void test_add_cors_headers()
{
    const std::vector<std::string> allowed = { "https://allowed.example.com" };

    // No Origin header at all (the request never sent one): nothing added.
    {
        reply rep;
        reply::add_cors_headers(&rep, "", allowed);
        CHECK(!header_present(rep, "Access-Control-Allow-Origin"));
        CHECK(!header_present(rep, "Vary"));
    }

    // Empty allow-list (the shipped default): nothing added, regardless of Origin.
    {
        reply rep;
        reply::add_cors_headers(&rep, "https://allowed.example.com", {});
        CHECK(!header_present(rep, "Access-Control-Allow-Origin"));
    }

    // Origin present but not on the allow-list: nothing added. In particular,
    // the origin string must never be echoed unvalidated.
    {
        reply rep;
        reply::add_cors_headers(&rep, "https://evil.com", allowed);
        CHECK(!header_present(rep, "Access-Control-Allow-Origin"));
        CHECK(!header_present(rep, "Vary"));
    }

    // Exact match: echoed verbatim (never "*"), with Vary: Origin alongside it.
    {
        reply rep;
        reply::add_cors_headers(&rep, "https://allowed.example.com", allowed);
        CHECK(header_value(rep, "Access-Control-Allow-Origin") == "https://allowed.example.com");
        CHECK(header_value(rep, "Access-Control-Allow-Origin") != "*");
        CHECK(header_value(rep, "Vary") == "Origin");
    }

    // A prefix/suffix match is not a match: the comparison must be exact.
    {
        reply rep;
        reply::add_cors_headers(&rep, "https://allowed.example.com.evil.com", allowed);
        CHECK(!header_present(rep, "Access-Control-Allow-Origin"));
    }
}

int main()
{
    test_add_header_rejects_crlf();
    test_add_header_rejects_other_control_chars();
    test_add_header_attachment();
    test_set_download_file();
    test_set_content_from_file_with_bad_attachment();
    test_add_cors_headers();

    std::printf("\n%d checks, %d failure(s)\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
