/*
 * server_settings.h
 *
 *  Created on: 15 févr. 2016
 *      Author: gaudryc
 */
#pragma once
#ifndef WEBSERVER_SERVER_SETTINGS_H_
#define WEBSERVER_SERVER_SETTINGS_H_

#include <cstddef>
#include <functional>
#include <string>
#include <vector>
// For request_parser::kDefaultMaxRequestBodySize, shared with the setting
// below so the parser default and the server default cannot disagree.
#include <libwebem/request_parser.h>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/algorithm/string.hpp>

namespace http {
namespace server {

/// Which family of proxy-forwarded-client-address header (if any) libwebem is
/// permitted to trust when resolving the real client behind a reverse proxy.
/// See server_settings::trusted_proxy_header_family for the reasoning.
///
/// The numeric values are persisted by consumers (Domoticz stores this as a
/// user preference) and range-checked as [None, XRealIP], so keep None first
/// and XRealIP last, and do not renumber: a new family goes before XRealIP or
/// the consumer's bounds check has to be updated with it.
enum class ProxyHeaderFamily {
	None = 0,	// Proxy headers are not consulted at all (default).
	Forwarded,	// RFC 7239 "Forwarded"
	XForwardedFor,	// "X-Forwarded-For"
	XRealIP		// "X-Real-IP"
};

struct server_settings {
public:
  server_settings() = default;
  server_settings(const server_settings &s) = default;
  virtual ~server_settings() = default;
  server_settings &operator=(const server_settings &s) = default;
  bool is_secure() const
  {
	  return is_secure_;
  }
	bool is_enabled() const {
		return ((listening_port != "0") && (!listening_port.empty()));
	}
	bool is_php_enabled() const {
		return !php_cgi_path.empty();
	}
	/**
	 * Set relevant values
	 */
	virtual void set(const server_settings & settings) {
		www_root = get_valid_value(listening_address, settings.www_root);
		listening_address = get_valid_value(listening_address, settings.listening_address);
		listening_port = get_valid_value(listening_port, settings.listening_port);
		vhostname = get_valid_value(vhostname, settings.vhostname);
		php_cgi_path = get_valid_value(php_cgi_path, settings.php_cgi_path);
		server_name = get_valid_value(server_name, settings.server_name);
		if (listening_port == "0") {
			listening_port.clear();// server NOT enabled
		}
	}

	virtual std::string to_string() const {
		return std::string("'server_settings[is_secure_=") + (is_secure_ == true ? "true" : "false") +
			", www_root='" + www_root + "'" +
			", listening_address='" + listening_address + "'" +
			", listening_port='" + listening_port + "'" +
			", vhostname='" + vhostname + "'" +
			", php_cgi_path='" + php_cgi_path + "'" +
			", server_name='" + server_name + "'" +
			", allowed_hosts_count=" + std::to_string(allowed_hosts.size()) +
			", allowed_cors_origins_count=" + std::to_string(allowed_cors_origins.size()) +
			", max_connections=" + std::to_string(max_connections) +
			", max_connections_per_ip=" + std::to_string(max_connections_per_ip) +
			", trusted_proxy_addresses_count=" + std::to_string(trusted_proxy_addresses.size()) +
			", max_write_queue_bytes=" + std::to_string(max_write_queue_bytes) +
			", tls_handshake_timeout=" + std::to_string(tls_handshake_timeout) +
			", initial_request_timeout=" + std::to_string(initial_request_timeout) +
			", max_requests_per_connection=" + std::to_string(max_requests_per_connection) +
			", max_request_line_length=" + std::to_string(max_request_line_length) +
			", max_header_length=" + std::to_string(max_header_length) +
			", max_header_count=" + std::to_string(max_header_count) +
			", max_request_size=" + std::to_string(max_request_size) +
			", max_request_body_size=" + std::to_string(max_request_body_size) +
			", max_body_bytes_in_flight=" + std::to_string(max_body_bytes_in_flight) +
			", min_request_body_rate=" + std::to_string(min_request_body_rate) +
			", ws_max_frame_size=" + std::to_string(ws_max_frame_size) +
			", ws_max_message_size=" + std::to_string(ws_max_message_size) +
			", trusted_proxy_header_family=" + std::to_string(static_cast<int>(trusted_proxy_header_family)) +
			", jwt_expected_issuer='" + jwt_expected_issuer + "'" +
			"]'";
	}

protected:
	explicit server_settings(bool is_secure) :
		is_secure_(is_secure) {}
	std::string get_valid_value(const std::string & old_value, const std::string & new_value) {
		if ((!new_value.empty()) && (new_value != old_value))
		{
			return new_value;
		}
		return old_value;
	}
public:
	std::string www_root;
	std::string vhostname;
	std::string listening_address;
	std::string listening_port;

	std::string php_cgi_path; //if not empty, php files are handled

	/// Server identification string sent in the "Server" HTTP response header.
	/// Defaults to empty (no Server header sent). Set to e.g. "MyApp/1.0".
	std::string server_name;

	/// Allow-list of hostnames (or addresses) this server considers itself
	/// known as. Compared against the request's Host header -- name only,
	/// any port ignored, case-insensitive -- on EVERY request when non-empty
	/// (see cWebem::CheckVHost), not only for a TLS listener with vhostname
	/// set the way the older, narrower vhostname check above works.
	///
	/// This closes a DNS-rebinding attack on the WebSocket trusted-network
	/// same-origin check (see OriginMatchesRequestHost in cWebem.cpp): that
	/// check compares the handshake's Origin header against the request's
	/// own Host header, which agree for a genuine same-origin browser
	/// request because both derive from the same URL -- but they agree just
	/// as trivially for ANY hostname an attacker controls. Concretely: an
	/// attacker serves a page from a short-TTL DNS name, waits for a
	/// browser on the trusted network (see AddTrustedNetworks()) to load it
	/// and cache the name, then re-points that name at this server's LAN
	/// address. The next request the victim's browser makes to it carries
	/// Origin == Host == the attacker's hostname, "matching" perfectly, and
	/// istrustednetwork grants the WebSocket a bidirectional admin channel
	/// with no credentials at all.
	///
	/// With this configured, that attacker hostname fails the Host check
	/// (400) before authentication is even reached, and -- defence in depth
	/// -- the Origin comparison itself is validated against this list
	/// rather than against the request's own (in that scenario, equally
	/// attacker-influenced) Host header. See OriginMatchesRequestHost.
	///
	/// DEFAULTS TO EMPTY, which preserves pre-fix behaviour exactly: Host is
	/// otherwise validated only by the narrower vhostname check (TLS +
	/// vhostname set), and Origin is compared to the request's own Host.
	/// LEAVING THIS UNSET LEAVES DNS REBINDING OPEN on any deployment using
	/// AddTrustedNetworks() -- set it to every hostname/address real clients
	/// use to reach this server (e.g. "domoticz.lan", "192.168.1.10") if
	/// trusted networks are in use. See docs/INTEGRATION.md.
	std::vector<std::string> allowed_hosts;

	/// Origins allowed to read cross-origin API responses, via
	/// Access-Control-Allow-Origin. When the request's Origin header exactly
	/// matches an entry here, that origin is echoed back (never "*") together with
	/// "Vary: Origin"; otherwise no CORS headers are sent on API/page responses at
	/// all -- registered page handlers (RegisterPageCode, e.g. /json.htm) and the
	/// authentication-failure paths all consult this list.
	///
	/// Entries here are compared for an exact string match against the request's
	/// Origin header, which browsers always serialise without the scheme's
	/// default port (https://fetch.spec.whatwg.org/#concept-origin) -- so list
	/// "https://example.com", never "https://example.com:443" (and likewise
	/// "http://example.com", never "http://example.com:80"); the latter form
	/// would never match a real browser's Origin header and so would silently
	/// never grant the access it looks like it grants.
	///
	/// Defaults to empty, meaning API responses carry no CORS headers by default.
	/// This is safe for same-origin use: a same-origin request never consults this
	/// header, so the bundled web UI's own requests are unaffected either way.
	/// Static assets (served from www_root) are unaffected by this setting and
	/// continue to be sent with Access-Control-Allow-Origin: * -- they are meant to
	/// be publicly cacheable/embeddable and carry no session-derived content.
	///
	/// Read this together with AddTrustedNetworks(): a request from a trusted IP
	/// range is granted the first admin user's rights with NO credentials at all
	/// (see docs/INTEGRATION.md, "Trusted Networks"). Listing an origin here grants
	/// that website exactly the same rights, for every browser that happens to be
	/// on the trusted network -- do not add an origin here unless you deliberately
	/// intend a separate site to be able to call this API from client-side
	/// JavaScript.
	std::vector<std::string> allowed_cors_origins;

	/// Which proxy-forwarded-client-address header family libwebem is allowed to
	/// trust for AreWeInTrustedNetwork() / session.remote_host resolution.
	///
	/// DISABLED BY DEFAULT (ProxyHeaderFamily::None), and that default is
	/// deliberate: "Forwarded" (RFC 7239), "X-Forwarded-For" and "X-Real-IP" are
	/// three independent, unauthenticated header families, and a reverse proxy
	/// deployment typically writes only ONE of them -- the others arrive on the
	/// wire completely unmodified, which means an attacker who simply picks a
	/// different family than the one the proxy uses controls what libwebem
	/// believes the client address is. See docs/INTEGRATION.md, "How forwarded
	/// client addresses are resolved" for the concrete attack this closes.
	///
	/// Once set, ONLY the named family is consulted -- the other two are ignored
	/// completely, even when present. If more than one family is present on a
	/// single request, the request is rejected outright: two independently
	/// attacker-influenced chains that might disagree have no safe
	/// interpretation, exactly like a request carrying two disagreeing
	/// Content-Length headers.
	///
	/// Leave this at None unless libwebem is genuinely deployed behind a proxy
	/// that overwrites (not appends to) exactly one of these headers.
	ProxyHeaderFamily trusted_proxy_header_family{ ProxyHeaderFamily::None };

	/// Expected "iss" (issuer) claim for JWT bearer-token authentication.
	///
	/// When empty (the default), the expected issuer is derived from the
	/// request's own "Host" header, which is attacker-controlled -- a client can
	/// simply send whatever Host it likes, so that fallback verifies nothing
	/// beyond "the token names some issuer resembling this request's URL". It is
	/// kept only so existing deployments that have not set this explicitly keep
	/// working unchanged; relying on it weakens issuer validation to effectively
	/// no validation at all. Set this to the fixed, real external URL of the
	/// server (e.g. "https://myhost.example.com/") to get a meaningful check.
	std::string jwt_expected_issuer;

	//feature
	//std::string fastcgi_php_server; (like nginx)

	// ---- Connection resource limits (DoS mitigation) ----------------------
	// These bound what a single client, or a flood of clients, can make the
	// server allocate. All are configurable because deployments range from a
	// Raspberry Pi to a server; 0 disables the limit unless noted otherwise.
	//
	// max_request_line_length, max_header_length, max_header_count and
	// max_request_size below all bound the header block only -- the request
	// line plus all header lines, up to and including the blank line that
	// terminates them. None of them constrain the body of a POST/PUT/PATCH;
	// a large but legitimate request body is governed separately by the
	// parser's own MAX_CONTENT_LENGTH.

	/// Maximum number of simultaneously open connections, across all clients.
	/// Chosen to stay well below a typical 1024 file-descriptor limit so that
	/// accept() never fails with EMFILE. 0 = unlimited (not recommended).
	size_t max_connections{ 512 };

	/// Maximum simultaneous connections from a single remote address.
	///
	/// DISABLED BY DEFAULT (0), and that default is deliberate: behind a reverse
	/// proxy every connection originates from the proxy's address, so any non-zero
	/// value would throttle the entire server to that number of connections.
	/// Only enable this when libwebem is directly exposed to clients.
	///
	/// If libwebem IS behind a reverse proxy and this is enabled anyway (e.g.
	/// because some clients also connect directly), list the proxy's own
	/// address(es) in trusted_proxy_addresses below so its connections are
	/// exempted from this cap instead of starving every other client behind
	/// it once the proxy itself reaches the limit.
	size_t max_connections_per_ip{ 0 };

	/// Addresses exempted from max_connections_per_ip -- typically the reverse
	/// proxy(s) libwebem sits behind, whose connections would otherwise all be
	/// counted against a single address and eventually refused once enough
	/// distinct clients are using the proxy at once. Compared as an exact
	/// string match against connection_manager's resolved peer address (the
	/// same value max_connections_per_ip itself is keyed by), so list it in
	/// the form the connection actually arrives in -- typically the plain
	/// dotted/colon form (e.g. "127.0.0.1", "::1"); note this comparison does
	/// NOT strip an IPv4-mapped IPv6 prefix the way request-level Host
	/// resolution elsewhere in this library does, so a dual-stack listener
	/// that observes proxy connections as "::ffff:127.0.0.1" needs that exact
	/// form listed instead.
	///
	/// This is unrelated to AddTrustedNetworks()/trusted_proxy_header_family:
	/// it exists only to keep the per-IP connection cap usable when a proxy is
	/// present, and confers no authentication bypass or forwarded-address
	/// trust by itself. Has no effect while max_connections_per_ip is 0 (the
	/// default) -- there is nothing to exempt anything from. Defaults to
	/// empty; do not add a client range here, only infrastructure you
	/// control.
	std::vector<std::string> trusted_proxy_addresses;

	/// Maximum number of bytes that may sit queued for a single connection while
	/// a write is already in flight. A client that stops reading (zero TCP window)
	/// otherwise causes unbounded server-side buffering. 0 = unlimited.
	size_t max_write_queue_bytes{ 8 * 1024 * 1024 };

	/// Seconds allowed to complete the TLS handshake. Without this a client can
	/// hold a socket, an ssl_socket and several timers for the full 20-minute
	/// abandoned timeout at no cost. 0 = no handshake timeout.
	int tls_handshake_timeout{ 10 };

	/// Seconds allowed for a connection to complete its FIRST HTTP request,
	/// counted from when it starts being read (after the TLS handshake, for a
	/// secure listener) rather than reset by every byte received, unlike the
	/// ordinary read timeout below. Without this, a connection that trickles
	/// one byte every read_timeout-minus-a-bit seconds never triggers the read
	/// timeout, so it can occupy a global connection slot (see max_connections)
	/// for the full 20-minute abandoned-connection timeout while never
	/// completing a request -- a single host sustaining this at ~27 bytes/sec
	/// per connection can eventually refuse every OTHER client, including a
	/// legitimate reverse proxy, once max_connections is exhausted. This
	/// bounds that exposure to initial_request_timeout regardless of how the
	/// attacker paces their bytes.
	///
	/// Cancelled the moment the first request on the connection completes (or
	/// is rejected as malformed -- either way, real progress was made); a
	/// keep-alive connection's second and later requests are governed by
	/// read_timeout / max_requests_per_connection / the abandoned timeout
	/// instead, none of which this replaces.
	///
	/// nginx's equivalent (client_header_timeout) defaults to 60s; this
	/// defaults to half that. A real client, even a slow mobile one, finishes
	/// sending request headers in well under a second once it starts; 30s is
	/// generous headroom above that while keeping the worst-case exposure per
	/// connection slot an order of magnitude below the 20-minute abandoned
	/// timeout it used to be bounded by. 0 disables this check (pre-fix
	/// behaviour: no bound beyond the abandoned timeout).
	int initial_request_timeout{ 30 };

	/// Maximum number of HTTP requests served on one keep-alive connection before
	/// it is closed. This makes the already-advertised "Keep-Alive: max=" header
	/// honest. Does not apply to WebSocket or SSE connections, which are
	/// long-lived by design. 0 = unlimited.
	unsigned int max_requests_per_connection{ 100 };

	/// Maximum length, in bytes, of the URI in the request line. Bounds the
	/// only part of the request line that has no other natural limit (method
	/// and HTTP version are already constrained by the parser's state
	/// machine). 0 = unlimited.
	size_t max_request_line_length{ 8 * 1024 };

	/// Maximum length, in bytes, of a single header's name plus value. 0 = unlimited.
	///
	/// 8 KiB matches nginx's `large_client_header_buffers` default, so this is
	/// a well-precedented bound rather than an arbitrary one, not a value
	/// picked to fit some specific client. A single header -- e.g. an
	/// Authorization bearer token or a large JWT -- large enough to breach it
	/// would be unusual. Deployments that genuinely need more can raise this;
	/// doing so trades memory bound for compatibility.
	size_t max_header_length{ 8 * 1024 };

	/// Maximum number of headers accepted on a single request. 0 = unlimited.
	size_t max_header_count{ 100 };

	/// Maximum total size, in bytes, of the header block: the request line
	/// plus all header lines, up to and including the blank line that ends
	/// them. The body is bounded separately by request_parser's own
	/// Content-Length cap. 0 = unlimited.
	///
	/// These four limits exist because boost::asio::streambuf's receive
	/// buffer is otherwise unbounded (default max_size is SIZE_MAX) and
	/// nothing is consumed from it until a complete request has been parsed:
	/// without them, a client that sends headers and never terminates them
	/// grows server memory without bound, and -- more damaging on a
	/// single-threaded io_context -- makes every read callback re-scan
	/// everything buffered so far, which is quadratic in the number of bytes
	/// sent. Defaults are sized for a Raspberry Pi deployment.
	size_t max_request_size{ 64 * 1024 };

	/// Maximum size, in bytes, of a single request's body (Content-Length),
	/// checked against the declared length before any of the body is read.
	/// This is the knob a deployment actually tunes day to day; request_parser's
	/// own kMaxContentLength (100 MB) stays fixed as the absolute ceiling no
	/// setting here can raise -- see its doc comment in request_parser.h.
	///
	/// The default is deliberately generous rather than nginx-conservative
	/// (client_max_body_size defaults to 1 MiB there). The governing use case
	/// is restoring a database backup, which must work OUT OF THE BOX: a
	/// Domoticz database with a few years of history reaches 75 MB and beyond,
	/// and a restore that fails with "413 Payload Too Large" until the operator
	/// finds an undocumented setting is a worse outcome than the memory bound
	/// this buys. Smaller uploads -- floorplan and camera images, custom device
	/// icons, plugin packages -- fit comfortably inside it.
	///
	/// Set to kMaxContentLength so the configurable cap does not sit below the
	/// fixed ceiling and reject what the library is otherwise willing to carry.
	/// Deployments that never accept uploads should lower this: it is the
	/// single most effective knob for bounding what one connection can make the
	/// server allocate. 0 = unlimited (falls back to kMaxContentLength alone),
	/// consistent with every other limit here.
	///
	/// Note the whole body is buffered in memory before the handler runs, and
	/// request_parser copies it once more into request::content, so a body of
	/// size N costs roughly 2N at peak. Budget accordingly on small hardware.
	///
	/// Shares its default with request_parser's own member default via the
	/// named constant, so the value a real server pushes into the parser and
	/// the value a default-constructed parser enforces cannot drift apart.
	size_t max_request_body_size{ request_parser::kDefaultMaxRequestBodySize };

	/// Server-wide budget, in bytes, of request-body data currently being
	/// received across ALL connections at once. max_request_body_size above
	/// only bounds a single connection; nothing previously stopped N
	/// connections from each buffering up to that amount simultaneously, so
	/// the aggregate was bounded only by kMaxContentLength * max_connections
	/// -- on the default settings, up to 100 MB * 512 connections, enough to
	/// exhaust memory on a Raspberry Pi (1-2 GB) with as few as 15-20
	/// concurrent unauthenticated connections slow-streaming a body each.
	///
	/// Checked (and, on success, reserved) once per request, at the moment
	/// its Content-Length has been validated and before any of the declared
	/// body has been read for it; released once that request's body has been
	/// fully received or its connection is torn down first. See
	/// connection_manager::reserve_body_bytes / release_body_bytes.
	///
	/// MUST be >= max_request_body_size, or a single request at the per-request
	/// cap is refused by this check instead: reserve_body_bytes() rejects any
	/// request larger than the whole budget outright, so a budget below the
	/// per-request cap silently makes the larger setting unreachable. Raising
	/// one without the other is the mistake this comment exists to prevent.
	///
	/// The default leaves one full-size upload (100 MB, above) able to proceed
	/// with headroom for ordinary API traffic alongside it. Uploads beyond that
	/// are not refused outright -- they get a retryable 503 until the in-flight
	/// one finishes.
	///
	/// 0 = unlimited (the aggregate is then bounded only by
	/// max_connections * kMaxContentLength, i.e. pre-fix behaviour).
	size_t max_body_bytes_in_flight{ 128u * 1024 * 1024 };

	/// Floor, in bytes per second, at which a request body is considered to be
	/// making real progress. 0 disables the check.
	///
	/// This exists because initial_request_timeout (above) is a ONE-SHOT
	/// deadline that is deliberately never reset by arriving bytes -- that is
	/// what stops a slowloris client from holding a connection slot forever by
	/// trickling just fast enough to dodge read_timeout. Applied unchanged to a
	/// large upload, though, it also kills a perfectly healthy one: a 75 MB
	/// database restore cannot complete inside a 30 second deadline unless the
	/// client sustains 2.5 MB/s, so restores would fail on any link slower than
	/// a fast LAN.
	///
	/// So once a body has been admitted -- Content-Length validated, size
	/// accepted, budget reserved -- the deadline is extended by
	/// content_length / min_request_body_rate. The connection still cannot be
	/// held indefinitely (the extension is finite and computed from a length
	/// the client committed to up front), but a genuine upload gets time
	/// proportional to its size instead of a flat 30 seconds.
	///
	/// 64 KiB/s (512 kbit/s) is the floor a client must beat. That gives a
	/// 100 MB upload ~27 minutes, and is a low bar for any device on a LAN
	/// while still bounding how long a deliberate trickler can squat on the
	/// body budget. Raise it to be stricter, lower it for genuinely slow links.
	size_t min_request_body_rate{ 64u * 1024 };

	// ---- WebSocket resource limits (DoS mitigation) ------------------------
	// Once a connection is upgraded, request_parser_ and the four limits above
	// no longer apply -- the WebSocket frame parser has no size bound of its
	// own otherwise. A client can declare an arbitrary 64-bit payload length,
	// and fragments of a single logical message accumulate with no cap, so
	// both a single frame and the reassembled message need their own limit.
	// 0 = unlimited, consistent with the HTTP limits above.

	/// Maximum size, in bytes, of a single WebSocket frame's payload. Checked
	/// as soon as the frame's length prefix is decoded, before the frame is
	/// buffered, so an oversized frame is rejected instead of accumulating
	/// 4 KB at a time toward a length it will never be allowed to reach.
	size_t ws_max_frame_size{ 1 * 1024 * 1024 };

	/// Maximum total size, in bytes, of a reassembled WebSocket message
	/// (a text/binary frame plus every continuation frame that completes
	/// it). Bounds fragment accumulation independently of ws_max_frame_size,
	/// since a message can be split into arbitrarily many frames that each
	/// individually stay under that limit.
	size_t ws_max_message_size{ 4 * 1024 * 1024 };

	// Optional heartbeat callbacks (set by the application)
	std::function<void(const std::string& name)> on_heartbeat;
	std::function<void(const std::string& name)> on_heartbeat_remove;
private:
  bool is_secure_{ false };
};

#ifdef WWW_ENABLE_SSL

struct ssl_server_settings : public server_settings {
public:
	std::string ssl_method;
	std::string certificate_chain_file_path;
	std::string ca_cert_file_path;
	std::string cert_file_path;

	std::string private_key_file_path;
	std::string private_key_pass_phrase;

	std::string ssl_options;
	std::string tmp_dh_file_path;

	bool verify_peer{ false };
	bool verify_fail_if_no_peer_cert{ false };
	std::string verify_file_path;
	std::string cipher_list;

	ssl_server_settings()
		: server_settings(true)
		, ssl_method("tls")
		, ssl_options("default_workarounds,no_sslv2,no_sslv3,no_tlsv1,no_tlsv1_1,single_dh_use")
		, cipher_list(
			"ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
			"ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
			"ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
			"DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384")
	{
	}
	ssl_server_settings(const ssl_server_settings &s) = default;
	~ssl_server_settings() override = default;
	ssl_server_settings &operator=(const ssl_server_settings &s) = default;

	boost::asio::ssl::context::method get_ssl_method() const {
		boost::asio::ssl::context::method method;
		if (ssl_method == "tlsv1")
		{
			method = boost::asio::ssl::context::tlsv1;
		}
		else if (ssl_method == "tlsv1_server")
		{
			method = boost::asio::ssl::context::tlsv1_server;
		}
		else if (ssl_method == "sslv23")
		{
			method = boost::asio::ssl::context::sslv23;
		}
		else if (ssl_method == "sslv23_server")
		{
			method = boost::asio::ssl::context::sslv23_server;
		}
		else if (ssl_method == "tlsv11")
		{
			method = boost::asio::ssl::context::tlsv11;
		}
		else if (ssl_method == "tlsv11_server")
		{
			method = boost::asio::ssl::context::tlsv11_server;
		}
		else if (ssl_method == "tlsv12")
		{
			method = boost::asio::ssl::context::tlsv12;
		}
		else if (ssl_method == "tlsv12_server")
		{
			method = boost::asio::ssl::context::tlsv12_server;
		}
		else if (ssl_method == "tlsv13")
		{
			method = boost::asio::ssl::context::tlsv13;
		}
		else if (ssl_method == "tlsv13_server")
		{
			method = boost::asio::ssl::context::tlsv13_server;
		}
		else if (ssl_method == "tls")
		{
			method = boost::asio::ssl::context::tls;
		}
		else if (ssl_method == "tls_server")
		{
			method = boost::asio::ssl::context::tls_server;
		}
		else
		{
			std::string error_message("invalid SSL method ");
			error_message.append("'").append(ssl_method).append("'");
			throw std::invalid_argument(error_message);
		}
		return method;
	}

	boost::asio::ssl::context::options get_ssl_options() const {
		boost::asio::ssl::context::options opts(0x0L);

		if (ssl_options.empty())
			return opts;

		std::string error_message;

		std::vector<std::string> options_array;
		boost::split(options_array, ssl_options, boost::is_any_of(","), boost::token_compress_on);
		for (const auto &option : options_array)
		{
			if (option == "default_workarounds")
			{
				update_options(opts, boost::asio::ssl::context::default_workarounds);
			}
			else if (option == "single_dh_use")
			{
				update_options(opts, boost::asio::ssl::context::single_dh_use);
			}
			else if (option == "no_sslv2")
			{
				update_options(opts, boost::asio::ssl::context::no_sslv2);
			}
			else if (option == "no_sslv3")
			{
				update_options(opts, boost::asio::ssl::context::no_sslv3);
			}
			else if (option == "no_tlsv1")
			{
				update_options(opts, boost::asio::ssl::context::no_tlsv1);
			}
			else if (option == "no_tlsv1_1")
			{
				update_options(opts, boost::asio::ssl::context::no_tlsv1_1);
			}
			else if (option == "no_tlsv1_2")
			{
				update_options(opts, boost::asio::ssl::context::no_tlsv1_2);
			}
			else if (option == "no_compression")
			{
				update_options(opts, boost::asio::ssl::context::no_compression);
			}
			else
			{
				if (error_message.empty()) {
					error_message.append("unknown SSL option(s) : ");
				}
				if (error_message.find('\'') != std::string::npos)
				{
					error_message.append(", ");
				}
				error_message.append("'").append(option).append("'");
			}
		}
		if (!error_message.empty()) {
			throw std::invalid_argument(error_message);
		}
		return opts;
	}

	/**
	 * Set relevant values
	 */
	using http::server::server_settings::set;
	virtual void set(const ssl_server_settings & ssl_settings) {
		server_settings::set(ssl_settings);

		ssl_method = server_settings::get_valid_value(ssl_method, ssl_settings.ssl_method);

		std::string path = server_settings::get_valid_value(cert_file_path, ssl_settings.cert_file_path);
		bool update_cert = path == ssl_settings.cert_file_path;
		if (update_cert) {
			cert_file_path = ssl_settings.cert_file_path;
			// use certificate file for all usage by default
			certificate_chain_file_path = ssl_settings.cert_file_path;
			ca_cert_file_path = ssl_settings.cert_file_path;
			private_key_file_path = ssl_settings.private_key_file_path;
			tmp_dh_file_path = ssl_settings.cert_file_path;
			verify_file_path = ssl_settings.cert_file_path;
		}

		certificate_chain_file_path = server_settings::get_valid_value(certificate_chain_file_path, ssl_settings.certificate_chain_file_path);
		ca_cert_file_path = server_settings::get_valid_value(ca_cert_file_path, ssl_settings.ca_cert_file_path);
		private_key_file_path = server_settings::get_valid_value(private_key_file_path, ssl_settings.private_key_file_path);
		private_key_pass_phrase = server_settings::get_valid_value(private_key_pass_phrase, ssl_settings.private_key_pass_phrase);

		ssl_options = server_settings::get_valid_value(ssl_options, ssl_settings.ssl_options);
		tmp_dh_file_path = server_settings::get_valid_value(tmp_dh_file_path, ssl_settings.tmp_dh_file_path);

		verify_peer = ssl_settings.verify_peer;
		verify_fail_if_no_peer_cert = ssl_settings.verify_fail_if_no_peer_cert;
		verify_file_path = server_settings::get_valid_value(verify_file_path, ssl_settings.verify_file_path);
	}

	std::string to_string() const override
	{
		return std::string("ssl_server_settings[") + server_settings::to_string() +
				", ssl_method='" + ssl_method + "'" +
				", certificate_chain_file_path='" + certificate_chain_file_path + "'" +
				", ca_cert_file_path='" + ca_cert_file_path + "'" +
				", cert_file_path=" + cert_file_path + "'" +
				", private_key_file_path='" + private_key_file_path + "'" +
				", private_key_pass_phrase='" + private_key_pass_phrase + "'" +
				", ssl_options='" + ssl_options + "'" +
				", tmp_dh_file_path='" + tmp_dh_file_path + "'" +
				", verify_peer=" + (verify_peer == true ? "true" : "false") +
				", verify_fail_if_no_peer_cert=" + (verify_fail_if_no_peer_cert == true ? "true" : "false") +
				", verify_file_path='" + verify_file_path + "'" +
				"]";
	}

protected:
	void update_options(boost::asio::ssl::context::options & opts, boost::asio::ssl::context::options option) const {
		if (opts != 0x0L) {
			opts |= option;
		} else {
			opts = option;
		}
	}
};

#endif //#ifdef WWW_ENABLE_SSL

} // namespace server
} // namespace http

#endif /* WEBSERVER_SERVER_SETTINGS_H_ */
