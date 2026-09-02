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
//   - connection resource limits (global cap, per-address cap, defaults)
//   - proxy header trust (X-Forwarded-For / Forwarded resolution and filtering)
//
// End-to-end coverage of the connection limits lives in test_connection_limits.py,
// which drives a real listening server.
//
// Lightweight harness (no external test framework): each check increments a
// global counter and the process exits non-zero if anything fails.
//

#include <libwebem/webem_utils.h>
#include <libwebem/request.h>
#include <libwebem/request_parser.h>
#include <libwebem/request_handler.h>
#include <libwebem/Websockets.h>
#include <libwebem/connection.h>
#include <libwebem/connection_manager.h>
#include <libwebem/server_settings.h>
#include <libwebem/cWebem.h>

#include <boost/logic/tribool.hpp>
#include <boost/asio.hpp>

#include <cstdint>
#include <cstdio>
#include <memory>
#include <string>
#include <set>
#include <vector>
#include <utility>

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
    // An empty hash means digest generation failed (e.g. an unavailable EVP
    // algorithm); two empty secrets must never be treated as authenticating.
    CHECK(!utils::ConstantTimeEquals("", ""));
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

// Hand-build a WebSocket frame so tests can control bits CWebsocketFrame::Create
// doesn't expose (FIN=0 fragments, out-of-spec control frames, arbitrary
// reserved opcodes, ...). mask_key is fixed rather than random: RFC 6455 only
// requires a mask be present for a client frame, not that it be unpredictable
// from this parser's point of view, and a fixed key keeps the tests
// deterministic.
static std::string build_frame(opcodes opc, const std::string &payload, bool fin, bool masked)
{
    static const uint8_t mask_key[4] = { 0x12, 0x34, 0x56, 0x78 };
    std::string out;
    out += (char)((fin ? 0x80 : 0x00) | (uint8_t)opc);
    size_t len = payload.size();
    uint8_t b1 = masked ? 0x80 : 0x00;
    if (len < 126) {
        out += (char)(b1 | (uint8_t)len);
    }
    else if (len <= 0xffff) {
        out += (char)(b1 | 126);
        out += (char)((len >> 8) & 0xff);
        out += (char)(len & 0xff);
    }
    else {
        out += (char)(b1 | 127);
        for (int shift = 56; shift >= 0; shift -= 8)
            out += (char)((uint64_t(len) >> shift) & 0xff);
    }
    if (masked) {
        for (uint8_t k : mask_key)
            out += (char)k;
        for (size_t i = 0; i < len; ++i)
            out += (char)((uint8_t)payload[i] ^ mask_key[i % 4]);
    }
    else {
        out += payload;
    }
    return out;
}

// Captures every message CWebsocket dispatches, so tests can tell "rejected"
// apart from "accepted but not yet delivered".
class TestCaptureHandler : public IWebsocketHandler
{
public:
    std::vector<std::string> received;
    bool Handle(const std::string &packet_data, bool outbound) override
    {
        if (!outbound)
            received.push_back(packet_data);
        return true;
    }
    void Start() override {}
    void Stop() override {}
};

static void test_websocket_frame_bounds()
{
    // Too short to hold a header
    {
        CWebsocketFrame f;
        uint8_t b[1] = { 0x00 };
        CHECK(f.Parse(b, 1, 0) == frame_parse_result::need_more_data);
    }
    // Valid masked text frame "abc"
    {
        CWebsocketFrame f;
        std::string frame = build_frame(opcode_text, "abc", true, true);
        CHECK(f.Parse(reinterpret_cast<const uint8_t *>(frame.data()), frame.size(), 0) == frame_parse_result::ok);
        CHECK(f.Payload() == "abc");
        CHECK(f.Consumed() == frame.size());
        CHECK(f.isFinal() == true);
    }
    // Extended length (126) announced but not enough bytes present
    {
        CWebsocketFrame f;
        uint8_t b[3] = { 0x81, 0xFE, 0x00 }; // masked, len marker 126, only 1 of 2 length bytes
        CHECK(f.Parse(b, sizeof(b), 0) == frame_parse_result::need_more_data);
    }
    // Announced payload longer than available data
    {
        CWebsocketFrame f;
        // masked, header says 5 bytes of payload; mask key present but no payload bytes yet
        uint8_t b[6] = { 0x81, 0x85, 0x12, 0x34, 0x56, 0x78 };
        CHECK(f.Parse(b, sizeof(b), 0) == frame_parse_result::need_more_data);
    }
    // Create (masked) -> Parse round trip
    {
        std::string frame = CWebsocketFrame::Create(opcode_text, "hello", true);
        CWebsocketFrame f;
        CHECK(f.Parse(reinterpret_cast<const uint8_t *>(frame.data()), frame.size(), 0) == frame_parse_result::ok);
        CHECK(f.Payload() == "hello");
    }
}

// RFC 6455 SS5.1: every frame sent from client to server must be masked.
// The masking bit used to be read and never checked.
static void test_websocket_unmasked_rejected()
{
    CWebsocketFrame f;
    uint8_t b[5] = { 0x81, 0x03, 'a', 'b', 'c' }; // FIN+text, masking bit NOT set
    CHECK(f.Parse(b, sizeof(b), 0) == frame_parse_result::protocol_error);
}

// RFC 6455 SS5.5: control frames must never be fragmented and must carry at
// most 125 bytes of payload. Neither was enforced.
static void test_websocket_control_frame_rules()
{
    // Fragmented ping (FIN=0, opcode=ping)
    {
        CWebsocketFrame f;
        std::string frame = build_frame(opcode_ping, "", false, true);
        CHECK(f.Parse(reinterpret_cast<const uint8_t *>(frame.data()), frame.size(), 0) == frame_parse_result::protocol_error);
    }
    // Ping with a 200-byte payload (> 125)
    {
        CWebsocketFrame f;
        std::string frame = build_frame(opcode_ping, std::string(200, 'x'), true, true);
        CHECK(f.Parse(reinterpret_cast<const uint8_t *>(frame.data()), frame.size(), 0) == frame_parse_result::protocol_error);
    }
    // A 125-byte ping is exactly at the limit and must still be accepted
    {
        CWebsocketFrame f;
        std::string frame = build_frame(opcode_ping, std::string(125, 'x'), true, true);
        CHECK(f.Parse(reinterpret_cast<const uint8_t *>(frame.data()), frame.size(), 0) == frame_parse_result::ok);
    }
}

// A frame declaring a payload far beyond any sane limit must be rejected the
// moment the length is decoded -- distinctly from "need more data" -- so the
// connection is failed instead of buffering 4 KB at a time toward a length it
// will never be allowed to reach.
static void test_websocket_oversized_frame_rejected()
{
    // FIN=1 (opcode irrelevant here), masked, 64-bit length field = 4 GiB.
    // No mask key or payload bytes are supplied: rejection must happen from
    // the length prefix alone, before the parser asks for more bytes.
    uint8_t b[10] = { 0x82, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 };
    {
        CWebsocketFrame f;
        auto r = f.Parse(b, sizeof(b), 1 * 1024 * 1024 /* ws_max_frame_size */);
        CHECK(r == frame_parse_result::protocol_error);
        CHECK(f.Consumed() == 0); // nothing credited toward the connection
    }
    // Distinctness check: the same declared length, but with the 64-bit
    // length field itself not fully arrived yet, must read as "need more
    // data", not "protocol error" -- these are genuinely different outcomes.
    {
        CWebsocketFrame f;
        CHECK(f.Parse(b, 6, 1 * 1024 * 1024) == frame_parse_result::need_more_data);
    }
    // End-to-end through CWebsocket::parse: the connection must be failed
    // (keep_alive cleared) rather than the frame being buffered.
    {
        CWebsocket ws([](const std::string &) {}, [](const std::string &) {});
        size_t consumed = 12345; // poisoned, must be reset to 0 on rejection
        bool keep_alive = true;
        boost::tribool r = ws.parse(b, sizeof(b), consumed, keep_alive);
        CHECK(bool(!r) == true);
        CHECK(consumed == 0);
        CHECK(keep_alive == false);
    }
}

// Parse()'s per-frame limit does nothing to stop a chain of small
// continuation frames from reassembling into an oversized message; that is
// bounded separately by ws_max_message_size in CWebsocket::parse.
static void test_websocket_message_size_cap()
{
    CWebsocket ws([](const std::string &) {}, [](const std::string &) {});
    ws.SetLimits(1000 /* ws_max_frame_size */, 2000 /* ws_max_message_size */);

    std::string frame1 = build_frame(opcode_text, std::string(700, 'a'), false, true);
    std::string frame2 = build_frame(opcode_continuation, std::string(700, 'b'), false, true);
    std::string frame3 = build_frame(opcode_continuation, std::string(700, 'c'), false, true);

    size_t consumed = 0;
    bool keep_alive = true;

    // 700 bytes: under the 2000-byte cap.
    ws.parse(reinterpret_cast<const uint8_t *>(frame1.data()), frame1.size(), consumed, keep_alive);
    CHECK(consumed == frame1.size());
    CHECK(keep_alive == true);

    // 1400 bytes: still under the cap.
    ws.parse(reinterpret_cast<const uint8_t *>(frame2.data()), frame2.size(), consumed, keep_alive);
    CHECK(consumed == frame2.size());
    CHECK(keep_alive == true);

    // 2100 bytes: crosses the 2000-byte cap -> connection failed at the limit.
    boost::tribool r = ws.parse(reinterpret_cast<const uint8_t *>(frame3.data()), frame3.size(), consumed, keep_alive);
    CHECK(bool(!r) == true);
    CHECK(consumed == 0);
    CHECK(keep_alive == false);
}

// The original bug: a single reserved-opcode frame set last_opcode to a value
// the dispatch switch had no case for. Because there was no default: case,
// execution fell out of the switch into the "wait for more fragments" path,
// which reset start_new_packet back to false -- packet_data was then never
// cleared again and nothing was ever dispatched again, for the life of the
// connection. Confirm the connection is failed instead, and -- the actual
// point of the fix -- that it does not silently swallow whatever comes next.
static void test_websocket_reserved_opcode_wedge()
{
    // The literal attack frame from the report: FIN=1, opcode=3 (reserved),
    // unmasked, zero-length. It is now rejected for being unmasked before
    // the reserved opcode is ever inspected, which is fine -- either reason
    // is a protocol error and either way the connection must be failed.
    {
        CWebsocketFrame f;
        uint8_t b[2] = { 0x83, 0x00 };
        CHECK(f.Parse(b, sizeof(b), 0) == frame_parse_result::protocol_error);
    }

    // Exercise the switch's default: case directly with an otherwise
    // well-formed (masked) reserved-opcode frame.
    auto handler = std::make_shared<TestCaptureHandler>();
    CWebsocket ws([](const std::string &) {}, [](const std::string &) {});
    ws.SetHandler(handler);

    std::string reserved_frame = build_frame((opcodes)3, "", true, true);
    size_t consumed = 0;
    bool keep_alive = true;
    boost::tribool r = ws.parse(reinterpret_cast<const uint8_t *>(reserved_frame.data()), reserved_frame.size(), consumed, keep_alive);
    CHECK(bool(!r) == true);
    CHECK(keep_alive == false);        // connection must be failed, not wedged
    CHECK(handler->received.empty());  // nothing was dispatched for the bad frame

    // The actual bug: a subsequent valid text frame must still be dispatched
    // correctly (parsed independently here, as it would be if a caller
    // mistakenly kept driving the parser), not silently absorbed into
    // leftover state from the reserved-opcode frame.
    std::string text_frame = build_frame(opcode_text, "hello", true, true);
    keep_alive = true;
    boost::tribool r2 = ws.parse(reinterpret_cast<const uint8_t *>(text_frame.data()), text_frame.size(), consumed, keep_alive);
    CHECK(bool(r2) == true);
    CHECK(keep_alive == true);
    CHECK(handler->received.size() == 1);
    CHECK(handler->received[0] == "hello");
}

// Reserved RSV1-3 bits are parsed but no extension is ever negotiated, so a
// client setting any of them is violating the protocol.
static void test_websocket_reserved_bits_rejected()
{
    CWebsocketFrame f;
    std::string frame = build_frame(opcode_text, "abc", true, true);
    // Set RSV1 (0x40) on byte 0 without disturbing FIN/opcode.
    std::vector<uint8_t> b(frame.begin(), frame.end());
    b[0] |= 0x40;
    CHECK(f.Parse(b.data(), b.size(), 0) == frame_parse_result::protocol_error);
}

// Create()/Parse() round trip at a size that exercises the 8-byte extended
// length path (> 64 KB), on both ends: Create must emit a correct 8-byte
// length and Parse must decode it back to the same value. This is the path
// F17's shift-UB fix touches on both sides.
static void test_websocket_large_length_roundtrip()
{
    std::string payload(70000, 'z'); // > 0xffff, forces the 127/8-byte length form
    std::string frame = CWebsocketFrame::Create(opcode_binary, payload, true);

    CWebsocketFrame f;
    CHECK(f.Parse(reinterpret_cast<const uint8_t *>(frame.data()), frame.size(), 0) == frame_parse_result::ok);
    CHECK(f.Payload().size() == payload.size());
    CHECK(f.Payload() == payload);
    CHECK(f.Consumed() == frame.size());
}

// Normal traffic (small masked text messages, one frame each) must be
// entirely unaffected by any of the above.
static void test_websocket_normal_traffic_unaffected()
{
    auto handler = std::make_shared<TestCaptureHandler>();
    CWebsocket ws([](const std::string &) {}, [](const std::string &) {});
    ws.SetHandler(handler);

    for (const std::string &msg : { std::string("hello"), std::string("{\"event\":\"subscribe\"}"), std::string("") })
    {
        std::string frame = build_frame(opcode_text, msg, true, true);
        size_t consumed = 0;
        bool keep_alive = true;
        boost::tribool r = ws.parse(reinterpret_cast<const uint8_t *>(frame.data()), frame.size(), consumed, keep_alive);
        CHECK(bool(r) == true);
        CHECK(keep_alive == true);
        CHECK(consumed == frame.size());
    }
    CHECK(handler->received.size() == 3);
    CHECK(handler->received[0] == "hello");
    CHECK(handler->received[1] == "{\"event\":\"subscribe\"}");
    CHECK(handler->received[2] == "");
}

// ---------------------------------------------------------------------------
// Connection resource limits
// ---------------------------------------------------------------------------

// The defaults are load-bearing: max_connections_per_ip MUST default to 0
// (disabled), because behind a reverse proxy every connection appears to come
// from the proxy's address and any non-zero value would throttle the whole
// server down to that single per-IP limit instead of protecting it.
static void test_connection_limit_defaults()
{
    server_settings s;
    CHECK(s.max_connections == 512);
    CHECK(s.max_connections_per_ip == 0);          // MUST be 0 - proxy safety
    CHECK(s.max_write_queue_bytes == 8 * 1024 * 1024);
    CHECK(s.tls_handshake_timeout == 10);
    CHECK(s.max_requests_per_connection == 100);
    // 100 MB / 128 MB: sized so a database restore works on the shipped
    // defaults. A Domoticz database with a few years of history reaches 75 MB,
    // and a restore that fails until the operator discovers an undocumented
    // setting is a worse outcome than the memory bound a smaller cap buys.
    CHECK(s.max_request_body_size == 100u * 1024 * 1024);
    CHECK(s.max_body_bytes_in_flight == 128u * 1024 * 1024);
    // The aggregate budget must never sit below the per-request cap:
    // reserve_body_bytes() refuses any single request larger than the whole
    // budget, which would silently make the larger setting unreachable.
    CHECK(s.max_body_bytes_in_flight >= s.max_request_body_size);
    // The configurable cap must stay within the fixed ceiling.
    CHECK(static_cast<long>(s.max_request_body_size) <= request_parser::kMaxContentLength);
    // Server default and parser default must agree; when they drifted, a body
    // the server accepted was rejected by a default-constructed parser.
    CHECK(s.max_request_body_size == request_parser::kDefaultMaxRequestBodySize);
    CHECK(s.min_request_body_rate == 64u * 1024);
    CHECK(s.ws_max_frame_size == 1 * 1024 * 1024);
    CHECK(s.ws_max_message_size == 4 * 1024 * 1024);

    // to_string() must not throw and must surface the new fields
    std::string desc = s.to_string();
    CHECK(desc.find("max_connections=512") != std::string::npos);
    CHECK(desc.find("max_connections_per_ip=0") != std::string::npos);
    CHECK(desc.find("max_request_body_size=104857600") != std::string::npos);
    CHECK(desc.find("max_body_bytes_in_flight=134217728") != std::string::npos);
    CHECK(desc.find("ws_max_frame_size=1048576") != std::string::npos);
    CHECK(desc.find("ws_max_message_size=4194304") != std::string::npos);
}

// Harness that hands connection_manager genuinely connected sockets, so the
// remote_endpoint() lookup in connection_manager::start() behaves as it does in
// production. The io_context is deliberately never run: start() arms async reads
// and timers, but no handler needs to fire for these assertions.
namespace {

class cm_fixture
{
public:
    cm_fixture()
        : acceptor_(io_)
        , handler_("./", nullptr, nullptr)
    {
        boost::asio::ip::tcp::endpoint ep(
            boost::asio::ip::make_address("127.0.0.1"), 0);
        acceptor_.open(ep.protocol());
        acceptor_.bind(ep);
        acceptor_.listen();
        port_ = acceptor_.local_endpoint().port();
    }

    ~cm_fixture()
    {
        mgr_.stop_all();
        boost::system::error_code ec;
        for (auto &c : clients_)
            c->close(ec);
        acceptor_.close(ec);
    }

    // Establish one real loopback connection and offer it to the manager.
    void offer(const server_settings &settings)
    {
        auto client = std::make_shared<boost::asio::ip::tcp::socket>(io_);
        boost::system::error_code ec;
        client->connect(
            boost::asio::ip::tcp::endpoint(
                boost::asio::ip::make_address("127.0.0.1"), port_), ec);
        CHECK(!ec);
        clients_.push_back(client);

        auto conn = std::make_shared<connection>(io_, mgr_, handler_, 20, settings, nullptr);
        acceptor_.accept(conn->socket(), ec);
        CHECK(!ec);
        conns_.push_back(conn);
        mgr_.start(conn);
    }

    connection_manager &mgr() { return mgr_; }
    connection_ptr at(size_t i) { return conns_.at(i); }

private:
    boost::asio::io_context io_;
    boost::asio::ip::tcp::acceptor acceptor_;
    request_handler handler_;
    connection_manager mgr_;
    unsigned short port_ = 0;
    std::vector<std::shared_ptr<boost::asio::ip::tcp::socket>> clients_;
    std::vector<connection_ptr> conns_;
};

} // namespace

static void test_global_connection_cap()
{
    cm_fixture fx;
    server_settings s;
    fx.mgr().configure(/*max_connections=*/3, /*max_connections_per_ip=*/0,
                       /*max_body_bytes_in_flight=*/0, nullptr);

    for (int i = 0; i < 3; ++i)
        fx.offer(s);
    CHECK(fx.mgr().count() == 3);

    // The 4th must be refused, and must NOT be admitted to the manager.
    fx.offer(s);
    CHECK(fx.mgr().count() == 3);

    // Releasing one frees a slot again.
    fx.mgr().stop(fx.at(0));
    CHECK(fx.mgr().count() == 2);
    fx.offer(s);
    CHECK(fx.mgr().count() == 3);
}

// The regression that matters most: with the shipped default, many connections
// from one address (i.e. every proxied deployment) must all be admitted.
static void test_per_ip_disabled_by_default()
{
    cm_fixture fx;
    server_settings s;
    CHECK(s.max_connections_per_ip == 0);
    fx.mgr().configure(s.max_connections, s.max_connections_per_ip, s.max_body_bytes_in_flight, nullptr);

    for (int i = 0; i < 30; ++i)   // all from 127.0.0.1
        fx.offer(s);
    CHECK(fx.mgr().count() == 30);
}

static void test_per_ip_cap_when_enabled()
{
    cm_fixture fx;
    server_settings s;
    fx.mgr().configure(/*max_connections=*/0, /*max_connections_per_ip=*/4,
                       /*max_body_bytes_in_flight=*/0, nullptr);

    for (int i = 0; i < 4; ++i)
        fx.offer(s);
    CHECK(fx.mgr().count() == 4);

    fx.offer(s);                       // 5th from the same address
    CHECK(fx.mgr().count() == 4);

    // Bookkeeping must be released on stop, so a slot frees up.
    fx.mgr().stop(fx.at(0));
    CHECK(fx.mgr().count() == 3);
    fx.offer(s);
    CHECK(fx.mgr().count() == 4);
}

// stop() must be idempotent: a second call cannot double-decrement the per-address
// counter, which would otherwise let the cap drift upward over time.
// The per-address cap must not throttle a configured, trusted reverse proxy:
// every real client behind it funnels through the proxy's own address, so a
// non-zero max_connections_per_ip would otherwise refuse the proxy itself
// (and, with it, every client behind it) once enough of them are connected
// at once. server_settings::trusted_proxy_addresses exempts specific
// addresses from this cap so it can be safely enabled at all in that
// deployment shape.
static void test_per_ip_cap_trusted_proxy_exemption()
{
    cm_fixture fx;
    server_settings s;
    fx.mgr().configure(/*max_connections=*/0, /*max_connections_per_ip=*/4,
                       /*max_body_bytes_in_flight=*/0, nullptr);
    // Every offer() connection in this fixture originates from 127.0.0.1
    // (see its doc comment), so exempting that address stands in for
    // exempting a real reverse proxy's own address.
    fx.mgr().set_trusted_proxy_addresses({ "127.0.0.1" });

    // Comfortably more than max_connections_per_ip: without the exemption,
    // the 5th of these alone would already be refused (see
    // test_per_ip_cap_when_enabled, which proves exactly that with the same
    // limit and no exemption configured).
    for (int i = 0; i < 10; ++i)
        fx.offer(s);
    CHECK(fx.mgr().count() == 10);
}

// An exemption list that does NOT name the connecting address must change
// nothing -- the cap still applies in full. Guards against an
// implementation that accidentally disables the per-IP cap entirely instead
// of exempting only the listed addresses.
static void test_per_ip_cap_unaffected_by_unrelated_exemption()
{
    cm_fixture fx;
    server_settings s;
    fx.mgr().configure(/*max_connections=*/0, /*max_connections_per_ip=*/4,
                       /*max_body_bytes_in_flight=*/0, nullptr);
    fx.mgr().set_trusted_proxy_addresses({ "203.0.113.9" }); // not 127.0.0.1

    for (int i = 0; i < 4; ++i)
        fx.offer(s);
    CHECK(fx.mgr().count() == 4);

    fx.offer(s);                       // 5th from 127.0.0.1, still capped
    CHECK(fx.mgr().count() == 4);
}

static void test_double_stop_is_safe()
{
    cm_fixture fx;
    server_settings s;
    fx.mgr().configure(0, 2, /*max_body_bytes_in_flight=*/0, nullptr);

    fx.offer(s);
    fx.offer(s);
    CHECK(fx.mgr().count() == 2);

    connection_ptr first = fx.at(0);
    fx.mgr().stop(first);
    fx.mgr().stop(first);              // second stop must be a no-op
    CHECK(fx.mgr().count() == 1);

    // Only one slot was actually released, so exactly one more may be admitted.
    fx.offer(s);
    CHECK(fx.mgr().count() == 2);
    fx.offer(s);
    CHECK(fx.mgr().count() == 2);      // still capped
}

// ---------------------------------------------------------------------------
// Server-wide in-flight request-body budget
// ---------------------------------------------------------------------------
//
// Exercises connection_manager::reserve_body_bytes()/release_body_bytes()
// directly, with a small configured budget standing in for the real default
// (64 MiB) so this does not need to allocate anywhere near that much. This
// is what bounds the AGGREGATE a flood of connections can buffer at once --
// server_settings::max_request_body_size alone only bounds one connection,
// so N connections each within that individual cap can still sum to N times
// it. The request_parser <-> connection wiring that calls these (via the
// body-admission callback installed in connection's constructor, and
// released in connection::stop()/handle_read) is covered separately in
// test_http_framing.cpp; together the two cover the aggregate-budget path
// end to end, but always at this reduced scale -- never with anything
// approaching a real 100 MB body.
static void test_body_budget_reserve_and_release()
{
    connection_manager mgr;
    mgr.configure(/*max_connections=*/0, /*max_connections_per_ip=*/0,
                  /*max_body_bytes_in_flight=*/100, nullptr);
    CHECK(mgr.body_bytes_in_flight() == 0);

    CHECK(mgr.reserve_body_bytes(60, "1.2.3.4") == true);
    CHECK(mgr.body_bytes_in_flight() == 60);

    // A second connection's request would push the aggregate over budget,
    // even though nothing about this request individually exceeds any
    // per-connection cap -- exactly the check a per-connection limit alone
    // cannot express.
    CHECK(mgr.reserve_body_bytes(50, "5.6.7.8") == false);
    CHECK(mgr.body_bytes_in_flight() == 60);   // rejection reserves nothing

    // Releasing the first frees room for the second.
    mgr.release_body_bytes(60);
    CHECK(mgr.body_bytes_in_flight() == 0);
    CHECK(mgr.reserve_body_bytes(50, "5.6.7.8") == true);
    CHECK(mgr.body_bytes_in_flight() == 50);
}

// 0 (the "disabled" convention used throughout this class) must skip the
// check entirely and never track anything -- matching every other 0=unlimited
// resource limit here.
static void test_body_budget_disabled_when_zero()
{
    connection_manager mgr;
    mgr.configure(0, 0, /*max_body_bytes_in_flight=*/0, nullptr);
    CHECK(mgr.reserve_body_bytes(1000000, "1.2.3.4") == true);
    CHECK(mgr.body_bytes_in_flight() == 0);
}

// ---------------------------------------------------------------------------
// Proxy header trust
// ---------------------------------------------------------------------------

static unsigned short free_tcp_port()
{
    boost::asio::io_context io;
    boost::asio::ip::tcp::acceptor a(io);
    boost::asio::ip::tcp::endpoint ep(boost::asio::ip::make_address("127.0.0.1"), 0);
    a.open(ep.protocol());
    a.bind(ep);
    unsigned short p = a.local_endpoint().port();
    a.close();
    return p;
}

static request make_request(std::initializer_list<std::pair<std::string, std::string>> hdrs)
{
    request req;
    for (const auto &h : hdrs)
    {
        header hh;
        hh.name = h.first;
        hh.value = h.second;
        req.headers.push_back(hh);
    }
    return req;
}

// The client-supplied end of an X-Forwarded-For chain must never be believed: a proxy
// APPENDS the address of whoever connected to it, so only the rightmost entry carries
// any authority. Taking the leftmost let a remote attacker send
// "X-Forwarded-For: 127.0.0.1" and be handed trusted-network admin rights.
//
// Also covers the family-precedence bypass: with three independent, unauthenticated
// header families (Forwarded, X-Forwarded-For, X-Real-IP), a client could simply pick
// whichever one the deployment's proxy did NOT overwrite. Proxy headers are therefore
// ignored entirely unless m_settings.trusted_proxy_header_family names exactly one
// family to trust; below, that field is mutated directly between blocks (it is a
// public member of cWebem) to exercise each family and the "none configured" default
// against the same web instance.
static void test_proxy_header_resolution()
{
    server_settings s;
    s.listening_address = "127.0.0.1";
    s.listening_port = std::to_string(free_tcp_port());
    cWebem web(s, "./www");

    std::string host;
    bool present = false;

    auto resolve = [&](const request &req) {
        host.clear();
        present = false;
        return web.findRealHostBehindProxies(req, host, present);
    };

    // ---- No family configured (the default): proxy headers are ignored completely,
    // not merely filtered -- a header that would otherwise resolve cleanly must still
    // leave nothing resolved and nothing flagged, and two families present together
    // must NOT be rejected (there is nothing to disagree about when neither is read).
    CHECK(web.m_settings.trusted_proxy_header_family == ProxyHeaderFamily::None);
    CHECK(resolve(make_request({{"Host", "x"}})) == true);
    CHECK(host.empty());
    CHECK(present == false);
    CHECK(resolve(make_request({{"X-Forwarded-For", "8.8.8.8"}})) == true);
    CHECK(host.empty());
    CHECK(present == false);
    CHECK(resolve(make_request({{"Forwarded", "for=8.8.8.8"}, {"X-Forwarded-For", "9.9.9.9"}})) == true);
    CHECK(host.empty());
    CHECK(present == false);

    // ---- family = X-Forwarded-For ----
    web.m_settings.trusted_proxy_header_family = ProxyHeaderFamily::XForwardedFor;

    // No proxy headers at all -> nothing resolved, nothing flagged.
    CHECK(resolve(make_request({{"Host", "x"}})) == true);
    CHECK(host.empty());
    CHECK(present == false);

    // Single hop: that entry is what the proxy wrote.
    CHECK(resolve(make_request({{"X-Forwarded-For", "8.8.8.8"}})) == true);
    CHECK(host == "8.8.8.8");
    CHECK(present == true);

    // THE BYPASS REGRESSION: rightmost wins, not leftmost.
    CHECK(resolve(make_request({{"X-Forwarded-For", "10.0.0.5, 203.0.113.9"}})) == true);
    CHECK(host == "203.0.113.9");

    // A forged loopback claim is discarded, and the caller is told headers were present
    // so it can refuse to fall back to the peer's own trust.
    CHECK(resolve(make_request({{"X-Forwarded-For", "127.0.0.1"}})) == true);
    CHECK(host.empty());
    CHECK(present == true);

    // ... and it is discarded even when mixed with a real client address.
    CHECK(resolve(make_request({{"X-Forwarded-For", "127.0.0.1, 203.0.113.9"}})) == true);
    CHECK(host == "203.0.113.9");

    // Other non-routable forms that cannot identify a forwarded client.
    CHECK(resolve(make_request({{"X-Forwarded-For", "::1"}})) == true);
    CHECK(host.empty());
    CHECK(resolve(make_request({{"X-Forwarded-For", "127.0.0.2"}})) == true);
    CHECK(host.empty());                       // whole 127.0.0.0/8, not just .1
    CHECK(resolve(make_request({{"X-Forwarded-For", "169.254.1.1"}})) == true);
    CHECK(host.empty());
    CHECK(resolve(make_request({{"X-Forwarded-For", "0.0.0.0"}})) == true);
    CHECK(host.empty());
    CHECK(resolve(make_request({{"X-Forwarded-For", "fe80::1"}})) == true);
    CHECK(host.empty());

    // Private ranges are legitimate forwarded clients and must NOT be filtered.
    CHECK(resolve(make_request({{"X-Forwarded-For", "192.168.1.50"}})) == true);
    CHECK(host == "192.168.1.50");
    CHECK(resolve(make_request({{"X-Forwarded-For", "10.1.2.3"}})) == true);
    CHECK(host == "10.1.2.3");

    // Header matching is exact: a lookalike header is not a forwarding header.
    CHECK(resolve(make_request({{"X-Forwarded-For-Internal", "127.0.0.1"}})) == true);
    CHECK(host.empty());
    CHECK(present == false);

    // A different, non-configured family present ALONE is ignored, not consulted.
    CHECK(resolve(make_request({{"Forwarded", "for=8.8.8.8"}})) == true);
    CHECK(host.empty());
    CHECK(present == false);

    // Several families present at once is NOT a rejection: only the configured
    // family is ever parsed, so the others cannot change the answer. Rejecting
    // here made every request through nginx Proxy Manager, which writes
    // X-Forwarded-For and X-Real-IP together, fail with 403
    // (domoticz/domoticz#6939). In both cases the configured family decides and
    // the value from the non-configured one is nowhere to be seen.
    CHECK(resolve(make_request({{"Forwarded", "for=8.8.8.8"}, {"X-Forwarded-For", "9.9.9.9"}})) == true);
    CHECK(host == "9.9.9.9");
    CHECK(present == true);
    CHECK(resolve(make_request({{"X-Real-IP", "8.8.8.8"}, {"X-Forwarded-For", "9.9.9.9"}})) == true);
    CHECK(host == "9.9.9.9");
    CHECK(present == true);

    // Two non-configured families together are likewise inert: neither is read,
    // so this is indistinguishable from a request carrying no proxy headers.
    CHECK(resolve(make_request({{"Forwarded", "for=8.8.8.8"}, {"X-Real-IP", "7.7.7.7"}})) == true);
    CHECK(host.empty());
    CHECK(present == false);

    // ---- family = Forwarded: RFC 7239 syntax, including the operator-precedence
    // regression (the value was only ever parsed when "for=" sat at offset 0).
    web.m_settings.trusted_proxy_header_family = ProxyHeaderFamily::Forwarded;

    CHECK(resolve(make_request({{"Forwarded", "for=1.2.3.4"}})) == true);
    CHECK(host == "1.2.3.4");
    CHECK(resolve(make_request({{"Forwarded", "proto=https;for=1.2.3.4"}})) == true);
    CHECK(host == "1.2.3.4");
    CHECK(resolve(make_request({{"Forwarded", "for=1.2.3.4;proto=https"}})) == true);
    CHECK(host == "1.2.3.4");
    CHECK(resolve(make_request({{"Forwarded", "for=\"[2001:db8::1]:443\""}})) == true);
    CHECK(host == "2001:db8::1");
    CHECK(resolve(make_request({{"Forwarded", "for=1.2.3.4:5678"}})) == true);
    CHECK(host == "1.2.3.4");                  // IPv4 port stripped

    // X-Forwarded-For present alone, with "Forwarded" configured, is ignored.
    CHECK(resolve(make_request({{"X-Forwarded-For", "8.8.8.8"}})) == true);
    CHECK(host.empty());
    CHECK(present == false);

    // ---- family = X-Real-IP ----
    web.m_settings.trusted_proxy_header_family = ProxyHeaderFamily::XRealIP;

    CHECK(resolve(make_request({{"X-Real-IP", "198.51.100.7"}})) == true);
    CHECK(host == "198.51.100.7");

    web.Stop();
}

// ---------------------------------------------------------------------------
// Host allow-list (DNS-rebinding defence)
// ---------------------------------------------------------------------------
//
// cWebem::CheckVHost is called for every request (see handle_request's step
// 1, before authentication is even reached) and is the piece that closes DNS
// rebinding against the WebSocket trusted-network same-origin check: without
// it, a plain-HTTP listener with no vhostname configured never validates
// Host at all, so an attacker who gets a victim's browser to resolve a
// hostname they control to this server's address gets a request where
// Origin and Host both read that hostname and "match" trivially. The
// Origin-vs-allowed_hosts half of the fix (OriginMatchesRequestHost in
// cWebem.cpp) is `static`/file-local and not reachable from a unit test;
// it is covered end to end, together with this Host check, by
// test_dns_rebinding.py driving a real listener.
static void test_allowed_hosts_check()
{
    server_settings s;
    s.listening_address = "127.0.0.1";
    s.listening_port = std::to_string(free_tcp_port());

    // ---- Default (empty allowed_hosts): pre-fix behaviour preserved --
    // CheckVHost only ever validates Host for a TLS listener with vhostname
    // set (neither is true for `s` here), so ANY Host passes, including one
    // an attacker chose via DNS rebinding. This is deliberately still true
    // after the fix -- allowed_hosts is opt-in -- and documents exactly what
    // "leaving it unset leaves rebinding open" (server_settings.h) means in
    // practice.
    {
        cWebem web(s, "./www");
        CHECK(web.CheckVHost(make_request({{"Host", "rebind.evil.com"}})) == true);
        CHECK(web.CheckVHost(make_request({})) == true);   // no Host header at all
        web.Stop();
    }

    // ---- allowed_hosts configured: validated on every request ----
    server_settings s2 = s;
    s2.listening_port = std::to_string(free_tcp_port());
    s2.allowed_hosts = { "legit.example.com", "192.168.1.10" };
    {
        cWebem web(s2, "./www");

        // The attack this exists to stop: an unlisted (attacker-controlled)
        // hostname must now be rejected outright.
        CHECK(web.CheckVHost(make_request({{"Host", "rebind.evil.com"}})) == false);

        // A listed hostname is accepted...
        CHECK(web.CheckVHost(make_request({{"Host", "legit.example.com"}})) == true);
        // ...case-insensitively, matching how browsers/DNS treat hostnames...
        CHECK(web.CheckVHost(make_request({{"Host", "LEGIT.EXAMPLE.COM"}})) == true);
        // ...and with a port suffix stripped before comparing, same as the
        // legacy vhostname check already did.
        CHECK(web.CheckVHost(make_request({{"Host", "legit.example.com:8080"}})) == true);
        CHECK(web.CheckVHost(make_request({{"Host", "192.168.1.10"}})) == true);

        // A request with no Host header at all cannot be validated against
        // the list and must not be let through by default-ing to "allowed".
        CHECK(web.CheckVHost(make_request({})) == false);

        // Still rejected even when it looks superficially close to a listed
        // entry (must be an exact hostname match, not a substring/suffix).
        CHECK(web.CheckVHost(make_request({{"Host", "evil-legit.example.com"}})) == false);
        CHECK(web.CheckVHost(make_request({{"Host", "notlegit.example.com"}})) == false);

        web.Stop();
    }
}

// The API command whitelist (CheckAuthByPass) and the page dispatch both read
// request::parameters, and cWebem::ParseUrlEncodedParameters is the one
// tokeniser that fills it. These pin down the tokeniser's answer for the inputs
// the old raw-URI substring search got wrong, so any future "quick" search over
// the URI can be compared against what the dispatcher will actually see.
static void test_parameter_parsing_consistency()
{
    using http::server::cWebem;
    using http::server::request;

    // The reported bypass: "?param=logincheck" lives inside foo's VALUE. The
    // dispatcher sees exactly one "param", and it is getsettings.
    {
        std::multimap<std::string, std::string> p;
        cWebem::ParseUrlEncodedParameters("foo=?param=logincheck&type=command&param=getsettings", p);
        CHECK(p.count("param") == 1);
        CHECK(request::findValue(&p, "param") == "getsettings");
        CHECK(request::findValue(&p, "type") == "command");
        CHECK(request::findValue(&p, "foo") == "?param=logincheck");
    }

    // A url-encoded separator inside a value stays part of the value: values
    // are decoded individually, after tokenising.
    {
        std::multimap<std::string, std::string> p;
        cWebem::ParseUrlEncodedParameters("foo=bar%26param%3Dlogincheck&type=command&param=getsettings", p);
        CHECK(p.count("param") == 1);
        CHECK(request::findValue(&p, "param") == "getsettings");
        CHECK(request::findValue(&p, "foo") == "bar&param=logincheck");
    }

    // Duplicates are all kept (multimap), so a bypass check can insist that
    // every value is whitelisted rather than trusting whichever one find() returns.
    {
        std::multimap<std::string, std::string> p;
        cWebem::ParseUrlEncodedParameters("type=command&param=logincheck&param=getsettings", p);
        CHECK(p.count("param") == 2);
    }

    // The original report (GHSA-gwf6-ff7h-484q): a bare segment must become an
    // empty-valued parameter, not swallow the next pair's name. Splitting on '='
    // first turned "&foo&param=logincheck" into a parameter named "foo&param".
    {
        std::multimap<std::string, std::string> p;
        cWebem::ParseUrlEncodedParameters("type=command&foo&param=logincheck&param=getsettings", p);
        CHECK(p.count("foo") == 1);
        CHECK(request::findValue(&p, "foo").empty());
        CHECK(p.count("foo&param") == 0);
        CHECK(p.count("param") == 2);
        CHECK(request::findValue(&p, "param") == "logincheck");
    }

    // Empty segments ("&&", a trailing '&') are skipped, not turned into
    // empty-named parameters.
    {
        std::multimap<std::string, std::string> p;
        cWebem::ParseUrlEncodedParameters("&&type=command&&param=x&", p);
        CHECK(p.size() == 2);
        CHECK(request::findValue(&p, "param") == "x");
    }

    // '%xx' in a value is decoded and '+' becomes a blank -- the dispatcher
    // matches on the decoded form, so the bypass must too.
    {
        std::multimap<std::string, std::string> p;
        cWebem::ParseUrlEncodedParameters("param=%6cogincheck&x=a+b", p);
        CHECK(request::findValue(&p, "param") == "logincheck");
        CHECK(request::findValue(&p, "x") == "a b");
    }

    // ParseRequestParameters merges the query string and a form-encoded POST
    // body into one set (query first), and starts from a clean slate each call.
    {
        server_settings s;
        s.listening_address = "127.0.0.1";
        s.listening_port = std::to_string(free_tcp_port());
        cWebem web(s, "./www");

        request req;
        req.method = "POST";
        req.uri = "/json.htm?type=command&param=logincheck";
        req.headers.push_back({"Content-Type", "application/x-www-form-urlencoded"});
        req.content = "param=getsettings";
        req.content_length = static_cast<int>(req.content.size());
        req.parameters.insert({"stale", "value"});

        CHECK(web.ParseRequestParameters(req) == true);
        CHECK(req.parameters.count("stale") == 0);
        CHECK(req.parameters.count("param") == 2);
        CHECK(request::findValue(&req, "type") == "command");

        // handle_request parses the query string alone before authentication
        // (bIncludeBody=false) and appends the body afterwards (ParseRequestBody).
        CHECK(web.ParseRequestParameters(req, /*bIncludeBody=*/false) == true);
        CHECK(req.parameters.count("param") == 1);
        CHECK(web.ParseRequestBody(req) == true);
        CHECK(req.parameters.count("param") == 2);

        // A GET carries only its query string, even if content was left behind.
        req.method = "GET";
        CHECK(web.ParseRequestParameters(req) == true);
        CHECK(req.parameters.count("param") == 1);
        CHECK(request::findValue(&req, "param") == "logincheck");

        web.Stop();
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
    test_websocket_unmasked_rejected();
    test_websocket_control_frame_rules();
    test_websocket_oversized_frame_rejected();
    test_websocket_message_size_cap();
    test_websocket_reserved_opcode_wedge();
    test_websocket_reserved_bits_rejected();
    test_websocket_large_length_roundtrip();
    test_websocket_normal_traffic_unaffected();

    // connection resource limits
    test_connection_limit_defaults();
    test_global_connection_cap();
    test_per_ip_disabled_by_default();
    test_per_ip_cap_when_enabled();
    test_per_ip_cap_trusted_proxy_exemption();
    test_per_ip_cap_unaffected_by_unrelated_exemption();
    test_double_stop_is_safe();

    // server-wide in-flight request-body budget
    test_body_budget_reserve_and_release();
    test_body_budget_disabled_when_zero();

    // proxy header trust
    test_proxy_header_resolution();

    // Host allow-list (DNS-rebinding defence)
    test_allowed_hosts_check();

    // one tokeniser behind request::parameters (auth bypass vs. dispatch)
    test_parameter_parsing_consistency();

    std::printf("\n%d checks, %d failure(s)\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
