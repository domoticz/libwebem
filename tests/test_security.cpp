//
// test_security.cpp
// ~~~~~~~~~~~~~~~~~
//
// Unit tests covering the security hardening in libwebem:
//   - cryptographically secure token generation
//   - constant-time comparison
//   - SHA-256 / MD5 hashing
//   - control-character (incl. embedded NUL) detection in request paths
//   - URL decoding + NUL-injection rejection logic
//   - strict Content-Length parsing (negative / malformed / oversized)
//   - WebSocket frame parsing bounds checks
//
// Lightweight harness (no external test framework): each check increments a
// global counter and the process exits non-zero if anything fails.
//

#include <libwebem/webem_utils.h>
#include <libwebem/request.h>
#include <libwebem/request_parser.h>
#include <libwebem/request_handler.h>
#include <libwebem/Websockets.h>

#include <boost/logic/tribool.hpp>

#include <cstdio>
#include <string>
#include <set>

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

static void test_secure_token()
{
    std::string a = utils::GenerateSecureToken(32);
    std::string b = utils::GenerateSecureToken(32);
    CHECK(a.size() == 64);                 // 32 bytes -> 64 hex chars
    CHECK(b.size() == 64);
    CHECK(a != b);                         // must not repeat
    // hex only
    bool hexOnly = true;
    for (char c : a)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            hexOnly = false;
    CHECK(hexOnly);
    // no cookie-delimiter characters ('_' or '.') that would corrupt parsing
    CHECK(a.find('_') == std::string::npos);
    CHECK(a.find('.') == std::string::npos);

    // reasonable uniqueness across many draws
    std::set<std::string> seen;
    for (int i = 0; i < 200; ++i)
        seen.insert(utils::GenerateSecureToken(16));
    CHECK(seen.size() == 200);
}

static void test_constant_time_equals()
{
    CHECK(utils::ConstantTimeEquals("", ""));
    CHECK(utils::ConstantTimeEquals("abcdef", "abcdef"));
    CHECK(!utils::ConstantTimeEquals("abcdef", "abcdeg"));
    CHECK(!utils::ConstantTimeEquals("abc", "abcd"));     // different length
    CHECK(!utils::ConstantTimeEquals("abcd", "abc"));
    CHECK(!utils::ConstantTimeEquals("", "a"));
}

static void test_hashes()
{
    // Known SHA-256 vectors
    CHECK(utils::GenerateSHA256Hash("") ==
          "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    CHECK(utils::GenerateSHA256Hash("abc") ==
          "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    // Salt is concatenated
    CHECK(utils::GenerateSHA256Hash("a", "bc") == utils::GenerateSHA256Hash("abc"));
    // Known MD5 vector (retained for backwards compatibility)
    CHECK(utils::GenerateMD5Hash("abc") == "900150983cd24fb0d6963f7d28e17f72");
}

static void test_control_chars()
{
    CHECK(!utils::contains_control_chars("/index.html"));
    CHECK(!utils::contains_control_chars("/a/b/c.js?x=1"));
    CHECK(utils::contains_control_chars(std::string("/a\0b", 4)));  // embedded NUL
    CHECK(utils::contains_control_chars("/a\nb"));                  // newline
    CHECK(utils::contains_control_chars("/a\x7f" "b"));            // DEL
    CHECK(utils::contains_control_chars(std::string("\x01", 1)));
}

static void test_url_decode_nul_injection()
{
    std::string out;
    // Normal decoding still works
    CHECK(request_handler::url_decode("%41%42C", out));
    CHECK(out == "ABC");
    CHECK(request_handler::url_decode("a+b", out));
    CHECK(out == "a b");
    CHECK(request_handler::url_decode("%2e%2e%2f", out));
    CHECK(out == "../");
    // Malformed escapes are rejected
    CHECK(!request_handler::url_decode("%zz", out));
    CHECK(!request_handler::url_decode("%4", out));       // truncated
    // A "%00" decodes to an embedded NUL, which path validation must catch
    CHECK(request_handler::url_decode("/x.php%00.js", out));
    CHECK(utils::contains_control_chars(out));            // -> IsBadRequestPath rejects it
}

static boost::tribool parse_request(const std::string &raw, request &req)
{
    request_parser parser;
    const char *begin = raw.data();
    const char *end = raw.data() + raw.size();
    auto result = parser.parse(req, begin, end);
    return result.template get<0>();
}

static void test_content_length_parsing()
{
    // Valid POST with a body is accepted and content is captured
    {
        request req;
        boost::tribool r = parse_request(
            "POST /x HTTP/1.1\r\nContent-Length: 5\r\n\r\nHELLO", req);
        CHECK(bool(r) == true);
        CHECK(req.content == "HELLO");
    }
    // Negative Content-Length is rejected (previously caused a crash)
    {
        request req;
        boost::tribool r = parse_request(
            "POST /x HTTP/1.1\r\nContent-Length: -1\r\n\r\n", req);
        CHECK(bool(!r) == true);   // invalid
    }
    // Non-numeric Content-Length is rejected
    {
        request req;
        boost::tribool r = parse_request(
            "POST /x HTTP/1.1\r\nContent-Length: abc\r\n\r\n", req);
        CHECK(bool(!r) == true);
    }
    // Oversized Content-Length is rejected (> 100 MB)
    {
        request req;
        boost::tribool r = parse_request(
            "POST /x HTTP/1.1\r\nContent-Length: 209715200\r\n\r\n", req);
        CHECK(bool(!r) == true);
    }
    // Trailing garbage after digits is rejected
    {
        request req;
        boost::tribool r = parse_request(
            "POST /x HTTP/1.1\r\nContent-Length: 5x\r\n\r\nHELLO", req);
        CHECK(bool(!r) == true);
    }
}

static void test_websocket_frame_bounds()
{
    // Too short to hold a header
    {
        CWebsocketFrame f;
        uint8_t b[1] = { 0x00 };
        CHECK(f.Parse(b, 1) == false);
    }
    // Valid unmasked text frame "abc"
    {
        CWebsocketFrame f;
        uint8_t b[5] = { 0x81, 0x03, 'a', 'b', 'c' };
        CHECK(f.Parse(b, sizeof(b)) == true);
        CHECK(f.Payload() == "abc");
        CHECK(f.Consumed() == 5);
        CHECK(f.isFinal() == true);
    }
    // Extended length (126) announced but not enough bytes present
    {
        CWebsocketFrame f;
        uint8_t b[3] = { 0x81, 0x7E, 0x00 };
        CHECK(f.Parse(b, sizeof(b)) == false);
    }
    // Announced payload longer than available data
    {
        CWebsocketFrame f;
        uint8_t b[4] = { 0x81, 0x05, 'a', 'b' }; // says 5, only 2 present
        CHECK(f.Parse(b, sizeof(b)) == false);
    }
    // Create (unmasked) -> Parse round trip
    {
        std::string frame = CWebsocketFrame::Create(opcode_text, "hello", false);
        CWebsocketFrame f;
        CHECK(f.Parse(reinterpret_cast<const uint8_t *>(frame.data()), frame.size()) == true);
        CHECK(f.Payload() == "hello");
    }
}

int main()
{
    test_secure_token();
    test_constant_time_equals();
    test_hashes();
    test_control_chars();
    test_url_decode_nul_injection();
    test_content_length_parsing();
    test_websocket_frame_bounds();

    std::printf("\n%d checks, %d failure(s)\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
