//
// test_http_framing.cpp
// ~~~~~~~~~~~~~~~~~~~~~
//
// Unit tests for HTTP request framing / request-smuggling defences in
// request_parser:
//   - Content-Length is honoured for every method, not just POST, so a
//     declared body is consumed rather than left in the connection buffer
//     to be re-parsed as a second, attacker-smuggled request.
//   - reading_content advances past exactly content_length bytes, so a
//     pipelined request immediately following a body is preserved rather
//     than discarded.
//   - Transfer-Encoding is rejected (501: chunked decoding is not
//     implemented), Transfer-Encoding combined with Content-Length is
//     rejected (400: the two canonical desync primitives), and duplicate
//     Content-Length headers that disagree are rejected (400), while
//     duplicate headers that agree are accepted.
//   - obs-fold (a header continuation line introduced by leading
//     whitespace, RFC 7230 SS3.2.4) is rejected outright rather than
//     silently folded onto the previous header's value with no separator --
//     the third request-smuggling primitive alongside CL.CL and TE above.
//   - Request-line, header-length, header-count and total header-block size
//     limits reject an oversized request instead of letting it grow the
//     connection's receive buffer without bound, and incremental parsing
//     (resuming a partially-received request instead of re-parsing it from
//     byte 0 on every read) processes each byte exactly once and produces a
//     correctly-parsed request regardless of where the chunk boundaries
//     fall, while reset() leaves no state behind for the next request
//     parsed by the same parser instance to inherit.
//
// Lightweight harness (no external test framework): each check increments a
// global counter and the process exits non-zero if anything fails. Standalone
// executable with its own main(), in the style of test_security.cpp.
//

#include <libwebem/request.h>
#include <libwebem/request_parser.h>
#include <libwebem/webem_utils.h>

#include <boost/logic/tribool.hpp>

#include <algorithm>
#include <cstdio>
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

// Parses exactly one request out of [pos, end), advancing pos past whatever
// was consumed -- mirroring how connection::handle_read feeds the leftover
// buffer back through a fresh request_parser/request pair for each request
// on a keep-alive connection.
static boost::tribool parse_one(request &req, const char *&pos, const char *end)
{
    request_parser parser;
    auto result = parser.parse(req, pos, end);
    return result.template get<0>();
}

// Same as parse_one(), but hands back the reject reason too, for the tests
// that need to tell a 400 apart from a 501.
static boost::tribool parse_one(request &req, const char *&pos, const char *end,
                                 request_parser::reject_reason &reason)
{
    request_parser parser;
    auto result = parser.parse(req, pos, end);
    reason = parser.last_reject_reason();
    return result.template get<0>();
}

static void test_normal_get_no_body()
{
    std::string raw = "GET /index.html HTTP/1.1\r\nHost: x\r\n\r\n";
    const char *pos = raw.data();
    const char *end = raw.data() + raw.size();

    request req;
    boost::tribool r = parse_one(req, pos, end);
    CHECK(bool(r) == true);
    CHECK(req.content.empty());
    CHECK(req.content_length == 0);
    CHECK(pos == end);          // nothing left dangling in the buffer
}

static void test_normal_post_with_body()
{
    std::string raw = "POST /submit HTTP/1.1\r\nContent-Length: 5\r\n\r\nHELLO";
    const char *pos = raw.data();
    const char *end = raw.data() + raw.size();

    request req;
    boost::tribool r = parse_one(req, pos, end);
    CHECK(bool(r) == true);
    CHECK(req.content == "HELLO");
    CHECK(pos == end);
}

// A GET carrying a body must consume that body, not leave it to be
// misparsed as the start of a second request.
static void test_get_with_content_length_body_is_consumed()
{
    std::string body(62, 'A');
    std::string raw =
        "GET /json.htm?type=command&param=getversion HTTP/1.1\r\n"
        "Host: victim\r\n"
        "Content-Length: " + std::to_string(body.size()) + "\r\n"
        "\r\n" + body;
    // A pipelined request immediately follows the body on the same connection.
    raw += "GET /second HTTP/1.1\r\nHost: victim\r\n\r\n";

    const char *pos = raw.data();
    const char *end = raw.data() + raw.size();

    request req1;
    boost::tribool r1 = parse_one(req1, pos, end);
    CHECK(bool(r1) == true);
    CHECK(req1.method == "GET");
    CHECK(req1.content == body);              // body captured as data ...
    CHECK(req1.content_length == (int)body.size());

    // ... and pos now sits exactly at the start of the pipelined request:
    // the body bytes were not left behind to be reinterpreted as framing.
    request req2;
    boost::tribool r2 = parse_one(req2, pos, end);
    CHECK(bool(r2) == true);
    CHECK(req2.method == "GET");
    CHECK(req2.uri == "/second");
    CHECK(pos == end);
}

// The canonical request-smuggling payload: a GET with Content-Length whose
// body is itself a full HTTP request. Before Content-Length was honoured for
// every method, the parser stopped at the end of the GET's headers (method !=
// POST), leaving the "POST /json.htm?smuggled ..." bytes in the connection
// buffer to be parsed as a second, attacker-controlled request that would
// then capture the next pipelined victim request as its body.
static void test_smuggling_payload_produces_no_second_request()
{
    std::string smuggled =
        "POST /json.htm?smuggled HTTP/1.1\r\n"
        "Content-Length: 500\r\n"
        "\r\n";
    std::string raw =
        "GET /json.htm?type=command&param=getversion HTTP/1.1\r\n"
        "Host: victim\r\n"
        "Connection: Keep-Alive\r\n"
        "Content-Length: " + std::to_string(smuggled.size()) + "\r\n"
        "\r\n" + smuggled;

    const char *pos = raw.data();
    const char *end = raw.data() + raw.size();

    request req;
    boost::tribool r = parse_one(req, pos, end);
    CHECK(bool(r) == true);
    CHECK(req.method == "GET");               // never reinterpreted as the smuggled POST
    CHECK(req.content == smuggled);            // captured verbatim as opaque body data
    CHECK(pos == end);                         // nothing left over to parse as request #2

    // Feeding whatever is left (nothing) into a fresh parse cannot produce a
    // complete second request -- there is no synthesised request to answer.
    request req2;
    boost::tribool r2 = parse_one(req2, pos, end);
    CHECK(boost::indeterminate(r2));
}

static void test_transfer_encoding_chunked_rejected()
{
    std::string raw = "GET /x HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n";
    const char *pos = raw.data();
    const char *end = raw.data() + raw.size();

    request req;
    request_parser::reject_reason reason;
    boost::tribool r = parse_one(req, pos, end, reason);
    CHECK(bool(!r) == true);
    CHECK(reason == request_parser::reject_reason::not_implemented);
}

static void test_transfer_encoding_with_content_length_rejected()
{
    std::string raw =
        "POST /x HTTP/1.1\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Content-Length: 10\r\n"
        "\r\n0123456789";
    const char *pos = raw.data();
    const char *end = raw.data() + raw.size();

    request req;
    request_parser::reject_reason reason;
    boost::tribool r = parse_one(req, pos, end, reason);
    CHECK(bool(!r) == true);
    CHECK(reason == request_parser::reject_reason::bad_request);
}

static void test_disagreeing_duplicate_content_length_rejected()
{
    std::string raw =
        "POST /x HTTP/1.1\r\n"
        "Content-Length: 5\r\n"
        "Content-Length: 10\r\n"
        "\r\nHELLOHELLO";
    const char *pos = raw.data();
    const char *end = raw.data() + raw.size();

    request req;
    request_parser::reject_reason reason;
    boost::tribool r = parse_one(req, pos, end, reason);
    CHECK(bool(!r) == true);
    CHECK(reason == request_parser::reject_reason::bad_request);
}

// Must not over-reject: two Content-Length headers that agree are legal
// (some clients/proxies duplicate the header) and must be accepted normally.
static void test_agreeing_duplicate_content_length_accepted()
{
    std::string raw =
        "POST /x HTTP/1.1\r\n"
        "Content-Length: 5\r\n"
        "Content-Length: 5\r\n"
        "\r\nHELLO";
    const char *pos = raw.data();
    const char *end = raw.data() + raw.size();

    request req;
    boost::tribool r = parse_one(req, pos, end);
    CHECK(bool(r) == true);
    CHECK(req.content == "HELLO");
    CHECK(pos == end);
}

// RFC 7230 SS3.2.4: obs-fold -- a header continuation line introduced by
// leading whitespace -- must be rejected outright rather than silently
// concatenated onto the previous header's value with no separator inserted.
// The concrete desync this closes: "Content-Length: 1\r\n 0\r\n" used to fold
// into value "1" then "0" with nothing between them, i.e. "10" -- a value no
// conforming intermediary would derive from the same bytes, and the third
// request-smuggling primitive alongside the CL.CL and TE cases covered
// above. If this rejection regresses, the parser would instead accept the
// request with content_length == 10 rather than failing to parse it at all.
static void test_obs_fold_rejected()
{
    std::string raw =
        "POST /x HTTP/1.1\r\n"
        "Content-Length: 1\r\n"
        " 0\r\n"
        "\r\n0";
    const char *pos = raw.data();
    const char *end = raw.data() + raw.size();

    request req;
    request_parser::reject_reason reason;
    boost::tribool r = parse_one(req, pos, end, reason);
    CHECK(bool(!r) == true);
    CHECK(reason == request_parser::reject_reason::bad_request);
    // Specifically must not have derived a folded value of "10": that is the
    // desync this test exists to catch.
    CHECK(req.content_length != 10);
}

// obs-fold on a header's very first line (before any header has been seen)
// cannot be a continuation of anything, so it takes the ordinary
// bad-request path through header_line_start regardless -- included for
// completeness alongside the continuation case above.
static void test_leading_whitespace_before_any_header_rejected()
{
    std::string raw = "GET /x HTTP/1.1\r\n \r\n\r\n";
    const char *pos = raw.data();
    const char *end = raw.data() + raw.size();

    request req;
    request_parser::reject_reason reason;
    boost::tribool r = parse_one(req, pos, end, reason);
    CHECK(bool(!r) == true);
    CHECK(reason == request_parser::reject_reason::bad_request);
}

// server_settings::max_request_body_size -- the configurable, tighter cap
// that sits below the fixed kMaxContentLength ceiling (100 MB elsewhere in
// this file). This is the knob that closes "100 MB of unauthenticated
// request body buffered per connection": kMaxContentLength alone is far too
// generous a per-connection bound for a constrained deployment. Exercised
// with a tiny configured limit so the test does not need to construct
// anywhere near a real body.
static void test_configurable_body_size_cap_rejected()
{
    std::string raw = "POST /x HTTP/1.1\r\nContent-Length: 101\r\n\r\n";
    const char *pos = raw.data();
    const char *end = raw.data() + raw.size();

    request_parser parser;
    parser.set_max_request_body_size(100); // tiny cap for the test
    request req;
    boost::tribool r;
    boost::tie(r, boost::tuples::ignore) = parser.parse(req, pos, end);
    CHECK(bool(!r) == true);
    // Specifically body_too_large, not merely "some size breach": this is what
    // makes the connection layer answer 413 rather than 431, and a client that
    // is told its headers are too large after uploading an oversized file has
    // no way to act on that.
    CHECK(parser.last_reject_reason() == request_parser::reject_reason::body_too_large);
}

// A database restore must work on the SHIPPED defaults, with no configuration.
// A Domoticz database with a few years of history reaches 75 MB, and the whole
// point of the default chosen in server_settings is that such a restore is not
// rejected out of the box. This drives a real 75 MB body through the parser --
// not a declared length with no bytes behind it -- so it also proves the body
// is actually consumed rather than merely admitted.
static void test_seventy_five_megabyte_upload_accepted_on_defaults()
{
    const size_t body_size = 75u * 1024 * 1024;
    std::string raw = "POST /json.htm?param=restoredatabase HTTP/1.1\r\n"
                      "Content-Type: application/octet-stream\r\n"
                      "Content-Length: " + std::to_string(body_size) + "\r\n\r\n";
    const size_t header_len = raw.size();
    raw.append(body_size, 'D');

    const char *pos = raw.data();
    const char *end = raw.data() + raw.size();

    // A default-constructed parser carries the shipped defaults -- no
    // set_max_request_body_size() call here, deliberately: configuring it would
    // defeat the point of the test.
    request_parser parser;
    request req;
    boost::tribool r;
    boost::tie(r, boost::tuples::ignore) = parser.parse(req, pos, end);

    CHECK(bool(r) == true);
    CHECK(req.content_length == static_cast<int>(body_size));
    CHECK(req.content.size() == body_size);
    // The entire request was consumed: header block plus every body byte.
    CHECK((size_t)(pos - raw.data()) == header_len + body_size);
}

// The absolute ceiling still applies above the (now generous) configurable cap:
// kMaxContentLength is 100 MB and no setting can raise it.
static void test_body_over_fixed_ceiling_still_rejected()
{
    const long over = request_parser::kMaxContentLength + 1;
    std::string raw = "POST /x HTTP/1.1\r\nContent-Length: "
                      + std::to_string(over) + "\r\n\r\n";
    const char *pos = raw.data();
    const char *end = raw.data() + raw.size();

    request_parser parser;
    request req;
    boost::tribool r;
    boost::tie(r, boost::tuples::ignore) = parser.parse(req, pos, end);
    CHECK(bool(!r) == true);
    CHECK(parser.last_reject_reason() == request_parser::reject_reason::body_too_large);
}

// A body at (not over) the configured cap must still be accepted normally --
// this must not over-reject.
static void test_configurable_body_size_cap_accepts_at_limit()
{
    std::string body(100, 'x');
    std::string raw = "POST /x HTTP/1.1\r\nContent-Length: 100\r\n\r\n" + body;
    const char *pos = raw.data();
    const char *end = raw.data() + raw.size();

    request_parser parser;
    parser.set_max_request_body_size(100);
    request req;
    boost::tribool r;
    boost::tie(r, boost::tuples::ignore) = parser.parse(req, pos, end);
    CHECK(bool(r) == true);
    CHECK(req.content == body);
}

// server_settings::max_body_bytes_in_flight -- the server-wide budget shared
// across all connections, which is what actually bounds the aggregate that
// N connections can buffer at once (a per-connection cap alone cannot: N
// connections each within max_request_body_size can still sum to N times
// that). request_parser has no notion of "other connections" itself; it
// only guarantees its body-admission callback is invoked exactly once per
// request that declares a body, with the declared length, before any of
// that body is read. This exercises that contract directly, standing in for
// connection_manager's real reserve_body_bytes()/release_body_bytes() pair
// (covered with a real connection_manager, at the same reduced scale, in
// test_security.cpp's test_body_budget_reserve_and_release) without needing
// a live socket or an actual multi-megabyte body -- per the note above, the
// aggregate-budget path as a whole is therefore tested at reduced scale,
// never with anything approaching a real 100 MB body.
static void test_body_admission_check_invoked_once_before_reading_content()
{
    std::string body = "HELLO";
    std::string raw = "POST /x HTTP/1.1\r\nContent-Length: 5\r\n\r\n" + body;
    const char *pos = raw.data();
    const char *end = raw.data() + raw.size();

    request_parser parser;
    int calls = 0;
    long seen_length = -1;
    parser.set_body_admission_check([&](long content_length) {
        ++calls;
        seen_length = content_length;
        return true; // admit
    });
    request req;
    boost::tribool r;
    boost::tie(r, boost::tuples::ignore) = parser.parse(req, pos, end);
    CHECK(bool(r) == true);
    CHECK(calls == 1);
    CHECK(seen_length == 5);
}

// The rejection path: a callback that refuses (standing in for
// connection_manager finding the server-wide budget exhausted) fails the
// request instead of proceeding to buffer any of the body.
static void test_body_admission_check_rejection_fails_request()
{
    std::string raw = "POST /x HTTP/1.1\r\nContent-Length: 5\r\n\r\nHELLO";
    const char *pos = raw.data();
    const char *end = raw.data() + raw.size();

    request_parser parser;
    parser.set_body_admission_check([](long) { return false; });
    request req;
    boost::tribool r;
    boost::tie(r, boost::tuples::ignore) = parser.parse(req, pos, end);
    CHECK(bool(!r) == true);
    // Distinct from body_too_large: the body would have fit, the server just
    // had no room for it right now. That maps to a retryable 503, so a client
    // backing off and retrying succeeds instead of giving up on a 413.
    CHECK(parser.last_reject_reason() == request_parser::reject_reason::body_budget_exhausted);
}

// A zero-length body must not consult the admission check at all -- there is
// nothing to admit, and the request completes on the "Content-Length: 0"
// path without ever entering reading_content.
static void test_body_admission_check_not_invoked_for_empty_body()
{
    std::string raw = "GET /x HTTP/1.1\r\nContent-Length: 0\r\n\r\n";
    const char *pos = raw.data();
    const char *end = raw.data() + raw.size();

    request_parser parser;
    bool invoked = false;
    parser.set_body_admission_check([&](long) { invoked = true; return false; });
    request req;
    boost::tribool r;
    boost::tie(r, boost::tuples::ignore) = parser.parse(req, pos, end);
    CHECK(bool(r) == true);
    CHECK(invoked == false);
}

static void test_pipelined_post_then_get()
{
    std::string raw =
        "POST /a HTTP/1.1\r\nContent-Length: 4\r\n\r\nBODY"
        "GET /b HTTP/1.1\r\nHost: x\r\n\r\n";
    const char *pos = raw.data();
    const char *end = raw.data() + raw.size();

    request req1;
    boost::tribool r1 = parse_one(req1, pos, end);
    CHECK(bool(r1) == true);
    CHECK(req1.method == "POST");
    CHECK(req1.content == "BODY");

    request req2;
    boost::tribool r2 = parse_one(req2, pos, end);
    CHECK(bool(r2) == true);
    CHECK(req2.method == "GET");
    CHECK(req2.uri == "/b");
    CHECK(pos == end);
}

// A flood of header lines that never reaches a terminating blank line -- the
// unbounded-memory / quadratic-CPU attack request_parser's size limits exist
// to stop: without max_request_size, a client sending "GET / HTTP/1.1\r\n"
// followed by an endless stream of header lines would grow the connection's
// receive buffer (and the cost of re-scanning it) without bound.
static void test_header_flood_rejected_without_reading_it_all()
{
    std::string raw = "GET / HTTP/1.1\r\n";
    const std::string one_header = "A: " + std::string(4000, 'B') + "\r\n";
    while (raw.size() < 100u * 1024 * 1024)
        raw += one_header;

    const char *pos = raw.data();
    const char *end = raw.data() + raw.size();

    request req;
    request_parser::reject_reason reason;
    boost::tribool r = parse_one(req, pos, end, reason);
    CHECK(bool(!r) == true);
    CHECK(reason == request_parser::reject_reason::header_too_large);
    // Rejected at the configured header-block limit (default 64 KiB), not
    // after scanning the full 100 MB -- proves the flood is never buffered
    // or processed in its entirety.
    CHECK((size_t)(pos - raw.data()) < 128u * 1024);
}

static void test_too_many_headers_rejected()
{
    std::string raw = "GET / HTTP/1.1\r\n";
    // Default max_header_count is 100; 150 short headers comfortably exceeds it
    // while staying well under the header-block size limit, isolating this
    // check from test_header_flood_rejected_without_reading_it_all() above.
    for (int i = 0; i < 150; ++i)
        raw += "X" + std::to_string(i) + ": v\r\n";
    raw += "\r\n";

    const char *pos = raw.data();
    const char *end = raw.data() + raw.size();

    request req;
    request_parser::reject_reason reason;
    boost::tribool r = parse_one(req, pos, end, reason);
    CHECK(bool(!r) == true);
    CHECK(reason == request_parser::reject_reason::header_too_large);
}

static void test_single_header_too_long_rejected()
{
    std::string raw = "GET / HTTP/1.1\r\n";
    // Default max_header_length is 8 KiB (name + value combined).
    raw += "X: " + std::string(9000, 'v') + "\r\n\r\n";

    const char *pos = raw.data();
    const char *end = raw.data() + raw.size();

    request req;
    request_parser::reject_reason reason;
    boost::tribool r = parse_one(req, pos, end, reason);
    CHECK(bool(!r) == true);
    CHECK(reason == request_parser::reject_reason::header_too_large);
}

static void test_request_line_too_long_rejected()
{
    // Default max_request_line_length is 8 KiB, checked against the URI.
    std::string raw = "GET /" + std::string(9000, 'a') + " HTTP/1.1\r\n\r\n";

    const char *pos = raw.data();
    const char *end = raw.data() + raw.size();

    request req;
    request_parser::reject_reason reason;
    boost::tribool r = parse_one(req, pos, end, reason);
    CHECK(bool(!r) == true);
    // An over-long URI is a 414, not a 431: nothing is wrong with this
    // request's headers, and telling the client otherwise sends it looking in
    // the wrong place.
    CHECK(reason == request_parser::reject_reason::uri_too_long);
}

// Regression test for the O(n^2) parsing bug that made a single connection
// able to stall the whole (single-threaded) server: connection::handle_read
// used to call request_parser::reset() and re-parse a fresh local `request`
// from byte 0 of the *entire* accumulated buffer on every read callback, so
// a request that arrived over many small TCP segments was re-walked in full
// on every one of them. request_parser and request are now connection
// members that persist across callbacks, so parsing resumes exactly where
// the previous callback left off.
//
// This exercises that resumption pattern directly against the parser: the
// same parser and request object are reused across many tiny chunks, with
// each chunk's [begin, end) spanning only the newly-arrived bytes -- exactly
// what connection::handle_read now does via its buf_parsed_offset_ member --
// and reset() is never called between chunks. Some of the chunk boundaries
// below are placed at deliberately awkward points -- between a header's CR
// and LF, mid-header-name, mid-header-value, and mid-body -- because a
// state-machine bug that forgot which sub-state it was in across a callback
// (as opposed to one that merely miscounted bytes) would only show up at
// exactly those points. A pure byte-counter check cannot catch that class of
// bug, so this also verifies the fully-parsed request's method, URI,
// headers and body are correct, not just that parsing completed.
static void test_incremental_parsing_processes_each_byte_once()
{
    const std::string body = "HELLOWORLD!";
    std::string raw =
        "POST /json.htm?type=command&param=setsetpoint HTTP/1.1\r\n"
        "Host: victim.example\r\n"
        "User-Agent: test-agent/1.0\r\n"
        "Accept: application/json\r\n"
        "Authorization: Bearer abcdef123456\r\n"
        "Content-Length: 11\r\n"
        "\r\n" + body;
    const size_t header_block_size = raw.size() - body.size();

    // Located by content rather than hardcoded offsets so these stay correct
    // if the headers above are ever edited.
    size_t split_crlf = raw.find("\r\n", raw.find("Host:")) + 1;       // between \r and \n
    size_t split_mid_header_name = raw.find("User-Agent:") + 7;        // inside "User-Ag|ent:"
    size_t split_mid_header_value = raw.find("application/json") + 6;  // inside "applic|ation/json"
    size_t split_mid_body = raw.find(body) + 5;                        // inside "HELLO|WORLD!"

    // Merge those four with plain small-step chunking (as the previous
    // version of this test used) so parsing is still exercised across many
    // tiny reads in general, not only at the points singled out above.
    std::vector<size_t> boundaries = {
        split_crlf, split_mid_header_name, split_mid_header_value, split_mid_body
    };
    for (size_t i = 4; i < raw.size(); i += 4)
        boundaries.push_back(i);
    boundaries.push_back(raw.size());
    std::sort(boundaries.begin(), boundaries.end());
    boundaries.erase(std::unique(boundaries.begin(), boundaries.end()), boundaries.end());

    request_parser parser;
    request req;
    const char *base = raw.data();
    size_t fed = 0;
    boost::tribool result = boost::indeterminate;

    for (size_t boundary : boundaries)
    {
        CHECK(boost::indeterminate(result));  // must not have finished (or failed) early
        const char *pos = base + fed;
        // No reset() between chunks -- resuming without restarting is
        // exactly the behaviour under test.
        boost::tie(result, boost::tuples::ignore) = parser.parse(req, pos, base + boundary);
        fed = (size_t)(pos - base);
    }

    CHECK(bool(result) == true);
    CHECK(fed == raw.size());
    // bytes_consumed_ only counts bytes seen while state_ != reading_content
    // (see its doc comment), so once a body is involved it equals the
    // header-block size, not the whole request; if parsing ever re-walked
    // bytes it had already processed (the old restart-from-byte-0
    // behaviour), this count would exceed that instead of matching it.
    CHECK(parser.bytes_consumed() == header_block_size);

    CHECK(req.method == "POST");
    CHECK(req.uri == "/json.htm?type=command&param=setsetpoint");
    CHECK(req.content == body);
    CHECK(req.content_length == (int)body.size());
    CHECK(req.headers.size() == 5);

    struct { const char *name; const char *value; } expected_headers[] = {
        { "Host", "victim.example" },
        { "User-Agent", "test-agent/1.0" },
        { "Accept", "application/json" },
        { "Authorization", "Bearer abcdef123456" },
        { "Content-Length", "11" },
    };
    for (const auto &eh : expected_headers)
    {
        const char *v = request::get_req_header(&req, eh.name);
        CHECK(v != nullptr);
        if (v != nullptr)
            CHECK(std::string(v) == eh.value);
    }
}

// Companion to the resumption test above: proves reset() genuinely clears
// the parser's own state rather than just rewinding it, so nothing from one
// request can leak into the next request parsed by the same parser
// instance. Request A carries an Authorization header, a Content-Length
// body and a query string; request B carries none of those, and must come
// out showing none of A's values -- if reset() missed a field (state_,
// bytes_consumed_, ...), B would inherit it.
static void test_reset_clears_state_between_requests()
{
    std::string raw_a =
        "POST /json.htm?type=command&param=setsetpoint HTTP/1.1\r\n"
        "Authorization: Bearer secret-token-A\r\n"
        "Content-Length: 4\r\n"
        "\r\n"
        "BODY";
    std::string raw_b = "GET /status HTTP/1.1\r\n\r\n";

    request_parser parser;

    request req_a;
    const char *pos_a = raw_a.data();
    const char *end_a = raw_a.data() + raw_a.size();
    boost::tribool r_a;
    boost::tie(r_a, boost::tuples::ignore) = parser.parse(req_a, pos_a, end_a);
    CHECK(bool(r_a) == true);
    CHECK(req_a.uri == "/json.htm?type=command&param=setsetpoint");
    CHECK(req_a.content == "BODY");
    CHECK(request::get_req_header(&req_a, "Authorization") != nullptr);
    CHECK(pos_a == end_a);

    parser.reset();

    request req_b;
    const char *pos_b = raw_b.data();
    const char *end_b = raw_b.data() + raw_b.size();
    boost::tribool r_b;
    boost::tie(r_b, boost::tuples::ignore) = parser.parse(req_b, pos_b, end_b);
    CHECK(bool(r_b) == true);
    CHECK(req_b.method == "GET");
    CHECK(req_b.uri == "/status");
    CHECK(req_b.content.empty());
    CHECK(req_b.content_length == 0);
    CHECK(req_b.headers.empty());
    CHECK(request::get_req_header(&req_b, "Authorization") == nullptr);
    CHECK(pos_b == end_b);
    // raw_b has no body, so every byte of it is header-block: this being
    // exactly raw_b.size() (rather than raw_b.size() plus some leftover
    // count from request A) confirms bytes_consumed_ was actually zeroed by
    // reset(), not just the parser state machine.
    CHECK(parser.bytes_consumed() == raw_b.size());
}

// --------------------------------------------------------------------------
// Connection-header token parsing, which decides whether a connection is
// persistent. HTTP/1.1 is persistent by default and closes only on
// "Connection: close"; the value is a comma-separated token list, so matching
// the header as one string both misses "close" inside "TE, close" and matches
// "keep-alive" inside a longer token like "no-keep-alive".
// --------------------------------------------------------------------------
static void test_connection_header_token_matching()
{
    using http::server::utils::header_has_token;

    // exact, case-insensitive
    CHECK(header_has_token("close", "close") == true);
    CHECK(header_has_token("Close", "close") == true);
    CHECK(header_has_token("CLOSE", "close") == true);
    CHECK(header_has_token("keep-alive", "keep-alive") == true);
    CHECK(header_has_token("Keep-Alive", "keep-alive") == true);

    // token inside a list, with and without spaces
    CHECK(header_has_token("TE, close", "close") == true);
    CHECK(header_has_token("close,TE", "close") == true);
    CHECK(header_has_token("keep-alive, Upgrade", "keep-alive") == true);
    CHECK(header_has_token("Upgrade,  keep-alive  ", "keep-alive") == true);
    CHECK(header_has_token("\tclose\t", "close") == true);

    // must NOT match a substring of a longer token -- the whole point of
    // comparing elements entire rather than searching the raw string
    CHECK(header_has_token("no-keep-alive", "keep-alive") == false);
    CHECK(header_has_token("keep-alive-ish", "keep-alive") == false);
    CHECK(header_has_token("closed", "close") == false);
    CHECK(header_has_token("disclose", "close") == false);

    // absent
    CHECK(header_has_token("Upgrade", "close") == false);
    CHECK(header_has_token("", "close") == false);
    CHECK(header_has_token(",", "close") == false);
}

int main()
{
    test_connection_header_token_matching();
    test_normal_get_no_body();
    test_normal_post_with_body();
    test_get_with_content_length_body_is_consumed();
    test_smuggling_payload_produces_no_second_request();
    test_transfer_encoding_chunked_rejected();
    test_transfer_encoding_with_content_length_rejected();
    test_disagreeing_duplicate_content_length_rejected();
    test_agreeing_duplicate_content_length_accepted();
    test_obs_fold_rejected();
    test_leading_whitespace_before_any_header_rejected();
    test_configurable_body_size_cap_rejected();
    test_configurable_body_size_cap_accepts_at_limit();
    test_seventy_five_megabyte_upload_accepted_on_defaults();
    test_body_over_fixed_ceiling_still_rejected();
    test_body_admission_check_invoked_once_before_reading_content();
    test_body_admission_check_rejection_fails_request();
    test_body_admission_check_not_invoked_for_empty_body();
    test_pipelined_post_then_get();
    test_header_flood_rejected_without_reading_it_all();
    test_too_many_headers_rejected();
    test_single_header_too_long_rejected();
    test_request_line_too_long_rejected();
    test_incremental_parsing_processes_each_byte_once();
    test_reset_clears_state_between_requests();

    std::printf("\n%d checks, %d failure(s)\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
