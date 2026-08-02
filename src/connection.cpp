//
// connection.cpp
// ~~~~~~~~~~~~~~
//
// Copyright (c) 2003-2008 Christopher M. Kohlhoff (chris at kohlhoff dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
#include "webem_stdafx.h"
#include <libwebem/connection.h>
#include <boost/algorithm/string.hpp>
#include <iomanip>
#include <set>
#include <sstream>
#include <libwebem/connection_manager.h>
#include <libwebem/request_handler.h>
#include "mime_types.h"
#include <libwebem/cWebem.h>
#include <libwebem/webem_utils.h>
#include <limits>
#include <optional>

namespace http {
	namespace server {

		namespace {
			// Matches the size passed to _buf.prepare() in read_more(). Named so the
			// slack term in compute_buf_max_size() below documents itself.
			constexpr std::size_t kReadChunkBytes = 4096;

			/// Upper bound for _buf, the connection's receive buffer.
			///
			/// A default-constructed boost::asio::streambuf has max_size() ==
			/// SIZE_MAX; nothing is consumed from it until a complete request has
			/// been parsed, so without an explicit bound a client that never
			/// finishes a request grows it without limit. request_parser_ enforces
			/// settings.max_request_size on the header block byte by byte, so it
			/// always rejects a header-only attack long before _buf could approach
			/// this bound. This is the hard backstop for the rest: it still has to
			/// be big enough to hold one entire legitimate request -- header block
			/// plus a body up to request_parser::kMaxContentLength -- because _buf
			/// isn't drained until the whole request has been parsed. settings.
			/// max_request_size == 0 (unlimited header block, an explicit opt-out
			/// like the other settings that use that convention) is honoured as
			/// max_size() == SIZE_MAX, matching pre-fix behaviour.
			///
			/// _buf is reused after a connection is upgraded to WebSocket, so the
			/// bound also has to cover one legitimate WebSocket frame: header (up
			/// to 14 bytes for the extended-length + masking-key form) plus a
			/// payload up to ws_max_frame_size. The HTTP-derived bound above is
			/// normally far bigger than that (it embeds the 100 MB body limit),
			/// so this only changes anything for a deployment that raises
			/// ws_max_frame_size past it; getting this wrong would silently drop
			/// otherwise-legitimate large WebSocket frames at the streambuf
			/// level, before Parse() ever saw them.
			std::size_t compute_buf_max_size(const server_settings& settings)
			{
				constexpr std::size_t kMaxFrameHeaderBytes = 14;

				const bool http_unlimited = (settings.max_request_size == 0);
				const bool ws_unlimited = (settings.ws_max_frame_size == 0);
				if (http_unlimited && ws_unlimited)
					return (std::numeric_limits<std::size_t>::max)();

				const std::size_t http_bound = http_unlimited
					? (std::numeric_limits<std::size_t>::max)()
					: settings.max_request_size
						+ static_cast<std::size_t>(request_parser::kMaxContentLength)
						+ kReadChunkBytes;
				const std::size_t ws_bound = ws_unlimited
					? (std::numeric_limits<std::size_t>::max)()
					: settings.ws_max_frame_size + kMaxFrameHeaderBytes + kReadChunkBytes;

				return (std::max)(http_bound, ws_bound);
			}
		}

		// this is the constructor for plain connections
		connection::connection(boost::asio::io_context &io_context, connection_manager &manager, request_handler &handler, int read_timeout, const server_settings &settings, WebServerLogger logger)
			: m_logger(std::move(logger))
			, send_buffer_(nullptr)
			, writeQ_bytes_(0)
			, max_write_queue_bytes_(settings.max_write_queue_bytes)
			, strand_(io_context.get_executor())
			, read_timeout_(read_timeout)
			, read_timer_(io_context, std::chrono::seconds(read_timeout))
			, default_abandoned_timeout_(20 * 60)
			// 20mn before stopping abandoned connection
			, abandoned_timer_(io_context, std::chrono::seconds(default_abandoned_timeout_))
			, tls_handshake_timeout_(settings.tls_handshake_timeout)
			, handshake_timer_(io_context)
			, initial_request_timeout_(settings.initial_request_timeout)
			, initial_request_timer_(io_context)
			, min_request_body_rate_(settings.min_request_body_rate)
			, ws_session_renewal_timer_(io_context)
			, connection_manager_(manager)
			, request_handler_(handler)
			, _buf(compute_buf_max_size(settings))
			, buf_parsed_offset_(0)
			, status_(INITIALIZING)
			, default_max_requests_(20)
			, max_requests_per_connection_(settings.max_requests_per_connection)
			, request_count_(0)
			// The lambdas capture `this` but are only stored; the parser invokes them
			// when it processes data, which cannot happen before construction ends.
			, websocket_parser([this](auto &&r) { MyWrite(r); }, [this](auto &&r) { WS_Write(r); })
		{
			secure_ = false;
			keepalive_ = false;
			write_in_progress = false;
			connection_type = ConnectionType::connection_http;
			// Advertise the limit we actually enforce, so "Keep-Alive: max=" is honest.
			if (max_requests_per_connection_ > 0)
				default_max_requests_ = max_requests_per_connection_;
			request_parser_.set_limits(settings.max_request_line_length, settings.max_header_length,
				settings.max_header_count, settings.max_request_size);
			request_parser_.set_max_request_body_size(settings.max_request_body_size);
			// Wire the parser's per-request body admission check to
			// connection_manager's server-wide budget. Captures `this` (safe: the
			// parser is a member with the same lifetime as the connection it
			// belongs to, and is never invoked after destruction). On success the
			// granted amount is remembered in body_bytes_reserved_ so handle_read
			// (normal completion) or stop() (connection torn down mid-body) can
			// release exactly that much later -- see body_bytes_reserved_'s doc
			// comment in connection.h.
			request_parser_.set_body_admission_check([this](long content_length) {
				const size_t n = static_cast<size_t>(content_length);
				if (!connection_manager_.reserve_body_bytes(n, host_remote_endpoint_address_))
					return false;
				body_bytes_reserved_ = n;
				// The body has been admitted, so the flat initial-request deadline
				// is now the wrong bound: it was sized for a client that has not
				// yet produced a complete request at all, and a large legitimate
				// upload cannot finish inside it (see min_request_body_rate).
				// Give this request time proportional to the length it committed
				// to, so the connection still cannot be held open indefinitely.
				extend_initial_request_timeout_for_body(n);
				return true;
			});
			websocket_parser.SetLimits(settings.ws_max_frame_size, settings.ws_max_message_size);
			socket_ = std::make_unique<boost::asio::ip::tcp::socket>(io_context);
		}

#ifdef WWW_ENABLE_SSL
		// this is the constructor for secure connections
		connection::connection(boost::asio::io_context &io_context, connection_manager &manager, request_handler &handler, int read_timeout, boost::asio::ssl::context &context, const server_settings &settings, WebServerLogger logger)
			: m_logger(std::move(logger))
			, send_buffer_(nullptr)
			, writeQ_bytes_(0)
			, max_write_queue_bytes_(settings.max_write_queue_bytes)
			, strand_(io_context.get_executor())
			, read_timeout_(read_timeout)
			, read_timer_(io_context, std::chrono::seconds(read_timeout))
			, default_abandoned_timeout_(20 * 60)
			// 20mn before stopping abandoned connection
			, abandoned_timer_(io_context, std::chrono::seconds(default_abandoned_timeout_))
			, tls_handshake_timeout_(settings.tls_handshake_timeout)
			, handshake_timer_(io_context)
			, initial_request_timeout_(settings.initial_request_timeout)
			, initial_request_timer_(io_context)
			, min_request_body_rate_(settings.min_request_body_rate)
			, ws_session_renewal_timer_(io_context)
			, connection_manager_(manager)
			, request_handler_(handler)
			, _buf(compute_buf_max_size(settings))
			, buf_parsed_offset_(0)
			, status_(INITIALIZING)
			, default_max_requests_(20)
			, max_requests_per_connection_(settings.max_requests_per_connection)
			, request_count_(0)
			// The lambdas capture `this` but are only stored; the parser invokes them
			// when it processes data, which cannot happen before construction ends.
			, websocket_parser([this](auto &&r) { MyWrite(r); }, [this](auto &&r) { WS_Write(r); })
		{
			secure_ = true;
			keepalive_ = false;
			write_in_progress = false;
			connection_type = ConnectionType::connection_http;
			// Advertise the limit we actually enforce, so "Keep-Alive: max=" is honest.
			if (max_requests_per_connection_ > 0)
				default_max_requests_ = max_requests_per_connection_;
			request_parser_.set_limits(settings.max_request_line_length, settings.max_header_length,
				settings.max_header_count, settings.max_request_size);
			request_parser_.set_max_request_body_size(settings.max_request_body_size);
			// Wire the parser's per-request body admission check to
			// connection_manager's server-wide budget. Captures `this` (safe: the
			// parser is a member with the same lifetime as the connection it
			// belongs to, and is never invoked after destruction). On success the
			// granted amount is remembered in body_bytes_reserved_ so handle_read
			// (normal completion) or stop() (connection torn down mid-body) can
			// release exactly that much later -- see body_bytes_reserved_'s doc
			// comment in connection.h.
			request_parser_.set_body_admission_check([this](long content_length) {
				const size_t n = static_cast<size_t>(content_length);
				if (!connection_manager_.reserve_body_bytes(n, host_remote_endpoint_address_))
					return false;
				body_bytes_reserved_ = n;
				// The body has been admitted, so the flat initial-request deadline
				// is now the wrong bound: it was sized for a client that has not
				// yet produced a complete request at all, and a large legitimate
				// upload cannot finish inside it (see min_request_body_rate).
				// Give this request time proportional to the length it committed
				// to, so the connection still cannot be held open indefinitely.
				extend_initial_request_timeout_for_body(n);
				return true;
			});
			websocket_parser.SetLimits(settings.ws_max_frame_size, settings.ws_max_message_size);
			socket_ = nullptr;
			sslsocket_ = std::make_unique<ssl_socket>(io_context, context);
		}
#endif

#ifdef WWW_ENABLE_SSL
		// get the attached client socket of this connection
		ssl_socket::lowest_layer_type& connection::socket()
		{
			if (secure_) {
				return sslsocket_->lowest_layer();
			}
			return socket_->lowest_layer();
		}
#else
		// alternative: get the attached client socket of this connection if ssl is not compiled in
		boost::asio::ip::tcp::socket& connection::socket()
		{
			return *socket_;
		}
#endif

		void connection::start()
		{
			boost::system::error_code ec;
			boost::asio::ip::tcp::endpoint remote_endpoint = socket().remote_endpoint(ec);
			if (ec) {
				// Prevent the exception to be thrown to run to avoid the server to be locked (still listening but no more connection or stop).
				// If the exception returns to WebServer to also create a exception loop.
				if (m_logger) m_logger->Log(LogLevel::Error, "Getting error '%s' while getting remote_endpoint in connection::start", ec.message().c_str());
				connection_manager_.stop(shared_from_this());
				return;
			}
			host_remote_endpoint_address_ = remote_endpoint.address().to_string();
			host_remote_endpoint_port_ = std::to_string(remote_endpoint.port());

			boost::asio::ip::tcp::endpoint local_endpoint = socket().local_endpoint(ec);
			if (ec) {
				// Prevent the exception to be thrown to run to avoid the server to be locked (still listening but no more connection or stop).
				// If the exception returns to WebServer to also create a exception loop.
				if (m_logger) m_logger->Log(LogLevel::Error, "Getting error '%s' while getting local_endpoint in connection::start", ec.message().c_str());
				connection_manager_.stop(shared_from_this());
				return;
			}
			host_local_endpoint_address_ = local_endpoint.address().to_string();
			host_local_endpoint_port_ = std::to_string(local_endpoint.port());

			set_abandoned_timeout();

			if (secure_) {
#ifdef WWW_ENABLE_SSL
				status_ = WAITING_HANDSHAKE;
				// A client that connects and then stays silent would otherwise hold this
				// connection (socket + ssl_socket + timers) for the full 20-minute
				// abandoned timeout, so bound the handshake separately.
				set_handshake_timeout();
				// with ssl, we first need to complete the handshake before reading
				sslsocket_->async_handshake(boost::asio::ssl::stream_base::server, [self = shared_from_this()](auto &&err) { self->handle_handshake(err); });
#endif
			}
			else {
				// start reading data
				set_initial_request_timeout();
				read_more();
			}
		}

		// Precondition: must only be called from the io thread. Unlike WS_Write/
		// MyWrite, stop() reads connection_type directly instead of going through
		// strand_ -- safe today because every call site is either an async
		// completion handler or something already posted onto the io_context
		// (post_stop(), handle_timeout, ...), never an application thread. If that
		// ever changes, this read races the same connection_type writes strand_
		// exists to protect against; route the call through post_stop() rather
		// than calling stop() directly from outside the io thread.
		void connection::stop()
		{
			switch (connection_type) {
			case ConnectionType::connection_websocket:
			case ConnectionType::connection_websocket_closing:
			{
				auto handler = websocket_parser.DetachHandler();
				if (handler) {
					auto* webem = request_handler_.Get_myWebem();
					if (webem) {
						// This hands the handler off to cWebem's own m_io_context, a
						// separate io_context from this connection's. Handler::Stop() may
						// synchronously call the writer callback it was constructed with
						// (WS_Write/WS_WriteBinary), which posts onto strand_ same as any
						// other call -- even though the socket here has already been shut
						// down and closed just below. That is expected and harmless: the
						// connection is kept alive by shared_from_this() in the posted
						// task, and asio reports the closed socket as a write error to
						// handle_write rather than crashing.
						webem->ScheduleHandlerCleanup(std::move(handler));
					} else {
						if (m_logger) m_logger->Log(LogLevel::Error, "WebSocket: webem unavailable, falling back to inline handler cleanup");
						try { handler->Stop(); } catch (...) {}
					}
				}
				break;
			}
			case ConnectionType::connection_sse:
			{
				if (sse_handler_)
				{
					auto* webem = request_handler_.Get_myWebem();
					if (webem)
					{
						webem->ScheduleSseHandlerCleanup(std::move(sse_handler_));
					}
					else
					{
						try { sse_handler_->Stop(); } catch (...) {}
					}
					sse_handler_.reset();
				}
				break;
			}
			}
			// Cancel timers
			cancel_ws_session_renewal();
			cancel_abandoned_timeout();
			cancel_read_timeout();
			cancel_handshake_timeout();
			cancel_initial_request_timeout();

			// Release any body-budget reservation still outstanding: the request
			// that reserved it never finished (the connection is being torn down
			// mid-body -- a timeout, a client disconnect, an error), so the normal
			// release point in handle_read was never reached. Without this, a
			// client that opens a connection, declares a large Content-Length and
			// then never sends the body would permanently remove that many bytes
			// from the server-wide budget for the life of the process.
			if (body_bytes_reserved_ > 0) {
				connection_manager_.release_body_bytes(body_bytes_reserved_);
				body_bytes_reserved_ = 0;
			}

			// Initiate graceful connection closure.
			boost::system::error_code ignored_ec;
			socket().shutdown(boost::asio::ip::tcp::socket::shutdown_both, ignored_ec); // @note For portable behaviour with respect to graceful closure of a
																						// connected socket, call shutdown() before closing the socket.
			// stop() is reached from every async handler (timeouts, errors, normal
			// completion, ...), so -- like handle_timeout below -- it must not use the
			// throwing close() overload: an already-broken socket (e.g. ECONNRESET
			// racing this call) would otherwise unwind out of the async completion
			// handler and take the whole server thread down.
			socket().close(ignored_ec);
		}

		void connection::handle_timeout(const boost::system::error_code& error)
		{
			if (error != boost::asio::error::operation_aborted) {
				switch (connection_type) {
				case ConnectionType::connection_http:
					// Timers should be cancelled before stopping to remove tasks from the io_context.
					// The io_context will stop naturally when every tasks are removed.
					// If timers are not cancelled, the exception ERROR_ABANDONED_WAIT_0 is thrown up to the io_context::run() caller.
					cancel_abandoned_timeout();
					cancel_read_timeout();

					try {
						// Initiate graceful connection closure.
						boost::system::error_code ignored_ec;
						socket().shutdown(boost::asio::ip::tcp::socket::shutdown_both, ignored_ec); // @note For portable behaviour with respect to graceful closure of a
																									// connected socket, call shutdown() before closing the socket.
						socket().close(ignored_ec);
					}
					catch (...) {
						if (m_logger) m_logger->Log(LogLevel::Error, "%s -> exception thrown while stopping connection", host_remote_endpoint_address_.c_str());
					}
					break;
				case ConnectionType::connection_websocket:
					websocket_parser.SendPing();
					break;
				}
			}
		}

#ifdef WWW_ENABLE_SSL
		void connection::handle_handshake(const boost::system::error_code& error)
		{
			status_ = ENDING_HANDSHAKE;
			// The handshake finished (successfully or not); stop the handshake watchdog
			// before it can fire and stop an already-progressing connection.
			cancel_handshake_timeout();
			if (secure_) { // assert
				if (!error)
				{
					// handshake completed, start reading
					set_initial_request_timeout();
					read_more();
				}
				else
				{
					if (m_logger) m_logger->Debug(DebugCategory::WebServer, "connection::handle_handshake Error: %s", error.message().c_str());
					connection_manager_.stop(shared_from_this());
				}
			}
		}
#endif

		void connection::read_more()
		{
			status_ = WAITING_READ;

			// read chunks of max 4 KB
			// optional because mutable_buffers_type is mutable_buffers_1 in older
			// Boost, which has no default constructor
			std::optional<boost::asio::streambuf::mutable_buffers_type> buf;
			try
			{
				buf.emplace(_buf.prepare(kReadChunkBytes));
			}
			catch (const std::exception&)
			{
				// _buf hit the bound set in compute_buf_max_size(). request_parser_
				// checks settings.max_request_size on every byte of the header block,
				// so it should always reject a request that would grow this large
				// long before prepare() ever gets here; reaching this catch means
				// those limits were disabled (max_request_size == 0) or a legitimate
				// request plus its body genuinely exceeds the bound. Either way, drop
				// the connection instead of letting prepare()'s exception unwind into
				// io_context::run() and take the whole server down with it.
				if (m_logger) m_logger->Log(LogLevel::Status,
					"%s -> receive buffer exceeded its bound, dropping connection",
					host_remote_endpoint_address_.c_str());
				connection_manager_.stop(shared_from_this());
				return;
			}

			// set timeout timer
			reset_read_timeout();

			if (secure_) {
#ifdef WWW_ENABLE_SSL
				// Perform secure read
				sslsocket_->async_read_some(*buf, [self = shared_from_this()](auto &&err, auto bytes) { self->handle_read(err, bytes); });
#endif
			}
			else {
				// Perform plain read
				socket_->async_read_some(*buf, [self = shared_from_this()](auto &&err, auto bytes) { self->handle_read(err, bytes); });
			}
		}

		void connection::SocketWrite(const std::string& buf)
		{
			// do not call directly, use MyWrite()
			if (write_in_progress) {
				// something went wrong, this shouldnt happen
			}
			write_in_progress = true;
			write_buffer = buf;
			if (secure_) {
#ifdef WWW_ENABLE_SSL
				boost::asio::async_write(*sslsocket_, boost::asio::buffer(write_buffer), [self = shared_from_this()](auto &&err, auto bytes) { self->handle_write(err, bytes); });
#endif
			}
			else {
				boost::asio::async_write(*socket_, boost::asio::buffer(write_buffer), [self = shared_from_this()](auto &&err, auto bytes) { self->handle_write(err, bytes); });
			}

		}

		/// Queue a frame that was produced before the HTTP 101 response went out.
		///
		/// The handler's Start() may call WS_Write/WS_WriteBinary immediately, while
		/// connection_type is still connection_http, so those frames have to wait here
		/// until the handshake response has been written. This path bypasses MyWrite,
		/// so it must maintain writeQ_bytes_ itself - otherwise handle_write would
		/// decrement for bytes that were never counted and the bound would drift.
		void connection::QueuePreUpgradeFrame(const std::string& frame)
		{
			bool queue_overflow = false;
			{
				std::unique_lock<std::mutex> lock(writeMutex);
				// Same overflow-safe comparison as MyWrite: never form the sum.
				const size_t sz = frame.size();
				if ((max_write_queue_bytes_ > 0)
				    && ((sz > max_write_queue_bytes_) || (writeQ_bytes_ > (max_write_queue_bytes_ - sz)))) {
					queue_overflow = true;
				}
				else {
					writeQ.push_back(frame);
					writeQ_bytes_ += sz;
				}
			}
			if (queue_overflow) {
				if (m_logger) m_logger->Log(LogLevel::Status,
					"%s -> pre-upgrade write queue exceeded %zu bytes; dropping connection",
					host_remote_endpoint_address_.c_str(), max_write_queue_bytes_);
				post_stop();
			}
		}

		void connection::WS_Write(const std::string& resp)
		{
			// Called, by design, from arbitrary application threads (the writer
			// callback handed to WebSocket handlers -- see examples/03_websocket).
			// Post the whole decision, including the connection_type read, onto
			// strand_ instead of making it here: asio sockets are not safe for
			// concurrent use, and reading connection_type off the io thread would
			// itself be a race.
			boost::asio::post(strand_, [self = shared_from_this(), resp]() {
				if (self->connection_type == ConnectionType::connection_websocket) {
					self->MyWriteOnStrand(CWebsocketFrame::Create(opcode_text, resp, false));
				}
				else {
					// socket connection not set up yet, add to queue
					self->QueuePreUpgradeFrame(CWebsocketFrame::Create(opcode_text, resp, false));
				}
			});
		}

		void connection::WS_WriteBinary(const std::string& data)
		{
			// See WS_Write above -- same reasoning, same strand.
			boost::asio::post(strand_, [self = shared_from_this(), data]() {
				if (self->connection_type == ConnectionType::connection_websocket) {
					self->MyWriteOnStrand(CWebsocketFrame::Create(opcode_binary, data, false));
				}
				else {
					// socket connection not set up yet, add to queue
					self->QueuePreUpgradeFrame(CWebsocketFrame::Create(opcode_binary, data, false));
				}
			});
		}

		void connection::MyWrite(const std::string& buf)
		{
			// Also called from arbitrary application threads (the SSE writer
			// callback, and internally the same WebSocket writer WS_Write posts
			// through). Defer the actual work to MyWriteOnStrand so it always runs
			// on the io thread, whether this call came from there already (e.g.
			// handle_read building an HTTP response) or from a handler's own
			// thread. Posting unconditionally -- rather than only when the caller
			// is off the io thread -- keeps this in the same relative order as any
			// WS_Write call already queued ahead of it, and the connection_type
			// flips in handle_read, which go through the same strand for exactly
			// that reason (see WriteThenSetConnectionType below).
			boost::asio::post(strand_, [self = shared_from_this(), buf]() { self->MyWriteOnStrand(buf); });
		}

		void connection::MyWriteOnStrand(const std::string& buf)
		{
			switch (connection_type) {
			case ConnectionType::connection_http:
			case ConnectionType::connection_websocket:
			case ConnectionType::connection_sse:
				// we dont send data anymore in websocket closing state
				{
					bool queue_overflow = false;
					size_t queued_bytes = 0;
					{
						std::unique_lock<std::mutex> lock(writeMutex);
						// For SSE (HTTP/1.1 streaming), wrap payload in HTTP chunked encoding.
						const std::string* sendPtr = &buf;
						std::string chunked;
						if (connection_type == ConnectionType::connection_sse) {
							char hex[24];
							snprintf(hex, sizeof(hex), "%zx", buf.size());
							chunked = std::string(hex) + "\r\n" + buf + "\r\n";
							sendPtr = &chunked;
						}
						if (write_in_progress) {
							// A write is already in flight. async_write only completes once the
							// whole buffer has gone out, so a client that has stopped reading
							// (zero TCP window) leaves write_in_progress set indefinitely while
							// everything we push piles up here. Bound it: a client that cannot
							// keep up with the feed must be dropped, not buffered forever.
							// Compare without ever forming writeQ_bytes_ + size, which could wrap.
							const size_t sz = sendPtr->size();
							if ((max_write_queue_bytes_ > 0)
							    && ((sz > max_write_queue_bytes_) || (writeQ_bytes_ > (max_write_queue_bytes_ - sz)))) {
								queue_overflow = true;
								queued_bytes = writeQ_bytes_;
							}
							else {
								writeQ.push_back(*sendPtr);
								writeQ_bytes_ += sendPtr->size();
							}
						}
						else {
							SocketWrite(*sendPtr);
						}
					}
					// Stop outside the lock. post_stop() defers to the io thread, so this is
					// safe even when MyWrite was called from an application thread.
					if (queue_overflow) {
						if (m_logger) m_logger->Log(LogLevel::Status,
							"%s -> write queue exceeded %zu bytes (%zu queued), client is not reading; dropping connection",
							host_remote_endpoint_address_.c_str(), max_write_queue_bytes_, queued_bytes);
						post_stop();
					}
				}
				break;
			}
		}

		void connection::WriteThenSetConnectionType(const std::string& buf, ConnectionType new_type)
		{
			boost::asio::post(strand_, [self = shared_from_this(), buf, new_type]() {
				self->MyWriteOnStrand(buf);
				self->connection_type = new_type;
			});
		}

		void connection::handle_write_file(const boost::system::error_code& error, size_t bytes_transferred)
		{
			if (!error && sendfile_.is_open() && !sendfile_.eof())
			{
				if (!send_buffer_)
					send_buffer_ = std::make_unique<std::array<uint8_t, FILE_SEND_BUFFER_SIZE>>();
				size_t bread = static_cast<size_t>(sendfile_.read((char *)send_buffer_->data(), FILE_SEND_BUFFER_SIZE).gcount());
				if (bread > 0)
				{
					if (secure_) {
#ifdef WWW_ENABLE_SSL
						boost::asio::async_write(*sslsocket_, boost::asio::buffer(*send_buffer_, bread),
									 [self = shared_from_this()](auto &&err, auto bytes) { self->handle_write_file(err, bytes); });
#endif
					}
					else {
						boost::asio::async_write(*socket_, boost::asio::buffer(*send_buffer_, bread),
									 [self = shared_from_this()](auto &&err, auto bytes) { self->handle_write_file(err, bytes); });
					}
					return;
				}
				// bread == 0: a read error, not EOF (that is caught by sendfile_.eof()
				// above, and a short-of-buffer read still returns bread > 0). Fall
				// through to the same cleanup as a normal completion instead of
				// returning bare -- a bare return here used to leave sendfile_ open
				// and send_buffer_ allocated with no outstanding async operation, so
				// the connection was neither readable nor reapable until the
				// 20-minute abandoned timer caught it.
			}

			// Reaching here -- whether normal EOF, a read error, or the error branch
			// above -- means no further async_write for this transfer is in flight,
			// so it is safe to close sendfile_ and free send_buffer_ now: every
			// async_write callback above captures shared_from_this(), so this
			// connection object (and therefore sendfile_/send_buffer_) could not
			// have been destroyed while a write was still outstanding.
			if (sendfile_.is_open())
				sendfile_.close();

			// reset(), not release(): release() relinquishes ownership without
			// freeing, leaking FILE_SEND_BUFFER_SIZE (16 KB) on every completed and
			// every aborted download.
			send_buffer_.reset();
			connection_manager_.stop(shared_from_this());
		}

		bool connection::send_file(const std::string& filename, std::string& attachment_name, reply& rep)
		{
			boost::system::error_code write_error;

			rep = reply::stock_reply(reply::ok);

			sendfile_.open(filename.c_str(), std::ios::in | std::ios::binary); //we open this file
			if (!sendfile_.is_open())
			{
				//File not found!
				rep = reply::stock_reply(reply::not_found);
				return false;
			}
			time_t ftime = last_write_time(filename, m_logger);

			sendfile_.seekg(0, std::ios::end);
			std::streamsize total_size = sendfile_.tellg();
			sendfile_.seekg(0, std::ios::beg);

			reply::add_header(&rep, "Cache-Control", "max-age=0, private");
			reply::add_header(&rep, "Accept-Ranges", "bytes");
			reply::add_header(&rep, "Date", utils::make_web_time(time(nullptr)));
			reply::add_header(&rep, "Last-Modified", utils::make_web_time(ftime));
			// Use the configured server name if set, otherwise omit the Server header.
			{
				auto* webem = request_handler_.Get_myWebem();
				if (webem && !webem->m_settings.server_name.empty())
					reply::add_header(&rep, "Server", webem->m_settings.server_name);
			}

			std::size_t last_dot_pos = filename.find_last_of('.');
			if (last_dot_pos != std::string::npos) {
				std::string file_extension = filename.substr(last_dot_pos + 1);
				std::string mime_type = mime_types::extension_to_type(file_extension);
				reply::add_header_content_type(&rep, mime_type);
			}
			if (!reply::add_header_attachment(&rep, attachment_name))
			{
				// attachment_name failed control-character validation (most likely an
				// embedded CR/LF, which would otherwise split the response into forged
				// headers). It is application-supplied, not something the client sent,
				// so this is a server-side fault, not a client error -- 500, matching
				// the other internal-invariant violation this function's caller maps
				// to internal_server_error (the malformed download_file sentinel in
				// handle_read()). Bail out here rather than falling through to stream
				// the file with no Content-Disposition header at all.
				sendfile_.close();
				rep = reply::stock_reply(reply::internal_server_error);
				return false;
			}
			reply::add_header(&rep, "Content-Length", std::to_string(total_size));

			//write headers
			std::string headers = rep.to_string("GET");
			write_buffer = headers;

			if (secure_) {
#ifdef WWW_ENABLE_SSL
				boost::asio::async_write(*sslsocket_, boost::asio::buffer(write_buffer), [self = shared_from_this()](auto &&err, auto bytes) { self->handle_write_file(err, bytes); });
#endif
			}
			else {
				boost::asio::async_write(*socket_, boost::asio::buffer(write_buffer), [self = shared_from_this()](auto &&err, auto bytes) { self->handle_write_file(err, bytes); });
			}
			return true;
		}

		void connection::handle_read(const boost::system::error_code& error, std::size_t bytes_transferred)
		{
			status_ = READING;

			// data read, no need for timeouts (RK, note: race condition)
			cancel_read_timeout();

			if (!error && bytes_transferred > 0)
			{
				// ensure written bytes in the buffer
				_buf.commit(bytes_transferred);
				boost::tribool result;

				// http variables
				/// our response
				reply reply_;
				const char* begin;
				// websocket variables
				size_t bytes_consumed;

				switch (connection_type)
				{
				case ConnectionType::connection_http:
					begin = static_cast<const char*>(_buf.data().data());
					{
						// Resume from wherever the previous callback left off instead of
						// re-parsing everything buffered so far: request_parser_ and
						// request_ are connection members precisely so this can pick up
						// mid-request, rather than restarting from byte 0 (and re-running
						// every state-machine transition already done) on every read --
						// which is what made a large request's total parsing cost
						// quadratic in the number of read callbacks it arrived over.
						const char* parse_pos = begin + buf_parsed_offset_;
						const char* parse_end = begin + _buf.size();
						try
						{
							boost::tie(result, boost::tuples::ignore) = request_parser_.parse(
								request_, parse_pos, parse_end);
						}
						catch (...)
						{
							if (m_logger) m_logger->Log(LogLevel::Error, "Exception parsing HTTP. Address: %s", host_remote_endpoint_address_.c_str());
							// A parse exception is treated as a rejected request, same as
							// the parser returning false. Set that outcome explicitly
							// instead of relying on boost::tribool's default-false state,
							// and rewind parse_pos to where this call started rather than
							// leaving it wherever parse() had advanced to when it threw:
							// the rejection branch below zeroes buf_parsed_offset_ anyway,
							// but neither of those facts should be what keeps a
							// partially-advanced pointer from being stored as the resume
							// offset.
							result = false;
							parse_pos = begin + buf_parsed_offset_;
						}
						// How far into _buf's unconsumed region parsing has now
						// progressed, whether or not the request is complete yet.
						buf_parsed_offset_ = static_cast<size_t>(parse_pos - begin);
					}

					if (result) {
						// A request has now completed on this connection -- this is the
						// first one if none had before, and a no-op (cancelling an
						// already-inactive timer is harmless) on every one after that.
						// Real progress was made, so the slow-trickle exposure
						// initial_request_timeout exists to bound is over; read_timeout_ /
						// max_requests_per_connection / the abandoned timeout govern the
						// connection from here.
						cancel_initial_request_timeout();

						struct timeval tv;
						std::time_t newt;

						if(m_logger && m_logger->IsAccessLogEnabled())
						{
							// Record timestamp (with milliseconds) before starting to process
						#ifdef CLOCK_REALTIME
							struct timespec ts;
							if (!clock_gettime(CLOCK_REALTIME, &ts))
							{
								tv.tv_sec = ts.tv_sec;
								tv.tv_usec = ts.tv_nsec / 1000;
							}
							else
						#endif
								utils::get_timeofday(&tv);
							newt = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
						}

						_buf.consume(buf_parsed_offset_);
						// The parser's job for this request is done; reset it immediately
						// so it is ready for the next one. request_ (the parsed data) is
						// still needed below to build and log the response, so it is reset
						// separately at each point further down where this request's
						// processing actually finishes.
						request_parser_.reset();
						buf_parsed_offset_ = 0;
						// This request's body (if any) has been fully received, so release
						// its reservation back to connection_manager's server-wide budget.
						// Balances the reserve_body_bytes() call made from the body-admission
						// callback set up in the constructor -- see body_bytes_reserved_'s
						// doc comment in connection.h. A no-op when the request had no body
						// (body_bytes_reserved_ stays 0 in that case).
						if (body_bytes_reserved_ > 0) {
							connection_manager_.release_body_bytes(body_bytes_reserved_);
							body_bytes_reserved_ = 0;
						}
						reply_.reset();
						// Persistence follows the protocol version, not the mere presence of
						// a "Connection: Keep-Alive" header. HTTP/1.1 connections are
						// persistent by DEFAULT (RFC 9112 s9.3) and close only when the
						// client says "Connection: close"; HTTP/1.0 is the other way round.
						//
						// Requiring the header explicitly -- as this did -- meant any
						// HTTP/1.1 client that relies on the default (Python's http.client,
						// curl, most API clients and libraries) got its connection closed
						// after a single request, silently turning every call into a fresh
						// TCP handshake. Browsers send the header explicitly, which is why
						// this went unnoticed for so long: the web UI was never affected.
						//
						// The header is a comma-separated list of tokens ("keep-alive,
						// Upgrade"), so it is searched token-wise rather than compared whole;
						// an exact compare misses "close" in "TE, close" and would leave the
						// connection open against the client's wishes.
						const char* pConnection = request_.get_req_header(&request_, "Connection");
						const bool is_http_1_1 = (request_.http_version_major > 1)
							|| ((request_.http_version_major == 1) && (request_.http_version_minor >= 1));
						keepalive_ = is_http_1_1;
						if (pConnection != nullptr)
						{
							if (utils::header_has_token(pConnection, "close"))
								keepalive_ = false;
							else if (utils::header_has_token(pConnection, "keep-alive"))
								keepalive_ = true;
							// Any other token (e.g. "TE") leaves the version default standing.
						}
						request_.keep_alive = keepalive_;
						// Enforce the request budget that we advertise in "Keep-Alive: max=".
						// Without it, a client can hold a keep-alive connection open forever by
						// sending one request just inside the read timeout, and each completed
						// write pushes the 20-minute abandoned timer out again.
						//
						// This deliberately runs before the upgrade handling further down.
						// WebSocket and SSE connections are long-lived by design and do not use
						// HTTP keep-alive, so they must not be subject to the budget: the upgrade
						// branch below unconditionally sets keepalive_ = true again, which leaves
						// them exempt even when the budget is exhausted on the upgrade request.
						++request_count_;
						if ((max_requests_per_connection_ > 0) && (request_count_ >= max_requests_per_connection_)) {
							if (m_logger) m_logger->Debug(DebugCategory::WebServer,
								"%s -> request budget of %u reached, closing keep-alive connection",
								host_remote_endpoint_address_.c_str(), max_requests_per_connection_);
							keepalive_ = false;
							request_.keep_alive = false;
						}
						request_.host_remote_address = host_remote_endpoint_address_;
						request_.host_local_address = host_local_endpoint_address_;
						if (request_.host_remote_address.substr(0, 7) == "::ffff:") {
							request_.host_remote_address = request_.host_remote_address.substr(7);
						}
						if (request_.host_local_address.substr(0, 7) == "::ffff:") {
							request_.host_local_address = request_.host_local_address.substr(7);
						}
						request_.host_remote_port = host_remote_endpoint_port_;
						request_.host_local_port = host_local_endpoint_port_;
						host_last_request_uri_ = request_.uri;
						// Last line of defence: request_handler_ has its own guards (e.g. the
						// try/catch around the JWT branch in parse_auth_header), but this
						// catches anything those miss -- a page handler, an unexpected library
						// exception, whatever -- and turns it into a 500 instead of letting it
						// unwind out of this async completion handler and take the whole
						// server thread down. reply_ is fully overwritten here, so it does not
						// matter whether handle_request had partially filled it in before
						// throwing.
						try
						{
							request_handler_.handle_request(request_, reply_);
						}
						catch (const std::exception &e)
						{
							if (m_logger) m_logger->Log(LogLevel::Error, "%s -> exception handling request: %s",
								host_remote_endpoint_address_.c_str(), e.what());
							reply_ = reply::stock_reply(reply::internal_server_error);
						}
						catch (...)
						{
							if (m_logger) m_logger->Log(LogLevel::Error, "%s -> unknown exception handling request",
								host_remote_endpoint_address_.c_str());
							reply_ = reply::stock_reply(reply::internal_server_error);
						}

						if(m_logger && m_logger->IsAccessLogEnabled())	// Only do this if we are gonna use it, otherwise don't spend the compute power
						{
							// Generate webserver logentry
							std::string wlHost = (reply_.originHost.empty()) ? request_.host_remote_address : reply_.originHost;
							std::string wlUser = "-";	// Maybe we can fill this sometime? Or maybe not so we don't expose sensitive data?
							std::string wlReqUri = request_.method + " " + request_.uri + " HTTP/" + std::to_string(request_.http_version_major) + (request_.http_version_minor ? "." + std::to_string(request_.http_version_minor): "");
							std::string wlReqRef = "-";
							if (request_.get_req_header(&request_, "Referer") != nullptr)
							{
								std::string shdr = request_.get_req_header(&request_, "Referer");
								wlReqRef = "\"" + shdr + "\"";
							}
							std::string wlBrowser = "-";
							if (request_.get_req_header(&request_, "User-Agent") != nullptr)
							{
								std::string shdr = request_.get_req_header(&request_, "User-Agent");
								wlBrowser = "\"" + shdr + "\"";
							}
							int wlResCode = (int)reply_.status;
							int wlContentSize = (int)reply_.content.length();

							std::stringstream sstr;
							sstr << std::setw(3) << std::setfill('0') << ((int)tv.tv_usec / 1000);
							std::string wlReqTimeMs = sstr.str();

							char wlReqTime[32];
							struct tm ltm{};
							utils::safe_localtime(&newt, &ltm);
							std::strftime(wlReqTime, sizeof(wlReqTime), "%d/%b/%Y:%H:%M:%S", &ltm);
							wlReqTime[sizeof(wlReqTime) - 1] = '\0';

							char wlReqTimeZone[16];
							std::strftime(wlReqTimeZone, sizeof(wlReqTimeZone), "%z", &ltm);
							wlReqTimeZone[sizeof(wlReqTimeZone) - 1] = '\0';

							if (m_logger) m_logger->AccessLog("%s - %s [%s.%s %s] \"%s\" %d %d %s %s", wlHost.c_str(), wlUser.c_str(), wlReqTime, wlReqTimeMs.c_str(), wlReqTimeZone, wlReqUri.c_str(), wlResCode, wlContentSize, wlReqRef.c_str(), wlBrowser.c_str());
						}

						if (reply_.status == reply::switching_protocols) {
							// this was an upgrade request
							// Do NOT set connection_type = connection_websocket here.
							// The handler's Start() may call WS_Write/WS_WriteBinary to send data
							// immediately. Those writes must be queued (writeQ) and delivered only
							// after the HTTP 101 response below. Setting connection_type to
							// connection_websocket here causes WS_Write/WS_WriteBinary to write
							// directly to the socket before the 101, corrupting the handshake.
							// connection_type is set to connection_websocket by
							// WriteThenSetConnectionType, further down, only after the 101 write
							// has been posted to strand_ -- see the comment there.
							// from now on we are a persistant connection
							keepalive_ = true;
							// Create the handler via factory for this request path
							{
								auto* webem = request_handler_.Get_myWebem();
								if (webem)
								{
									std::string req_path = webem->ExtractRequestPath(request_.uri);
									auto factory = webem->GetWebsocketFactory(req_path);
									if (factory)
									{
										// Capture weak_ptr instead of raw this so the writer
										// lambdas safely no-op after the connection is destroyed.
										// This prevents use-after-free when async handler cleanup
										// runs after the connection has already been torn down.
										std::weak_ptr<connection> weak_self = shared_from_this();
										auto ws_handler = factory(
											webem,
											[weak_self](const std::string& data) {
												if (auto self = weak_self.lock())
													self->WS_Write(data);
											},
											[weak_self](const std::string& data) {
												if (auto self = weak_self.lock())
													self->WS_WriteBinary(data);
											},
											reply_.ws_session);
										websocket_parser.SetHandler(ws_handler);
										webem->RegisterWebsocketHandler(ws_handler);
									}
								}
							}
							m_ws_session_id = reply_.ws_session.id;
							start_ws_session_renewal();
							websocket_parser.Start();
							// todo: check if multiple connection from the same client in CONNECTING state?
						}
						else if (reply_.status == reply::sse_stream) {
							// Send plain HTTP 200 SSE headers -- sse_stream is an internal sentinel
							// and must never be serialised as a real HTTP status code.
							// Build SSE headers, including any extra headers set on the reply (e.g. CORS).
							// Deduplicate against the fixed headers above, and guard against CRLF injection.
							std::string sse_headers =
								"HTTP/1.1 200 OK\r\n"
								"Content-Type: text/event-stream\r\n"
								"Transfer-Encoding: chunked\r\n"
								"Cache-Control: no-cache\r\n"
								"Connection: keep-alive\r\n"
								"X-Accel-Buffering: no\r\n";
							std::set<std::string> emitted_headers = {
								"content-type", "cache-control", "connection",
								"transfer-encoding", "x-accel-buffering",
								"content-length"  // SSE has no fixed body length; suppress any Content-Length added by page handlers
							};
							for (const auto& h : reply_.headers)
							{
								if (h.name.find_first_of("\r\n") != std::string::npos ||
									h.value.find_first_of("\r\n") != std::string::npos)
									continue;
								std::string lower_name = boost::to_lower_copy(h.name);
								if (emitted_headers.insert(lower_name).second)
									sse_headers += h.name + ": " + h.value + "\r\n";
							}
							sse_headers += "\r\n";
							// Write the header block and flip connection_type in one strand task
							// (WriteThenSetConnectionType) rather than assigning connection_type
							// here directly: MyWrite now defers, so an unguarded assignment right
							// here would let a later-executing header write observe
							// connection_sse too early and wrongly chunk-encode the header block
							// itself instead of only the body writes that follow it.
							WriteThenSetConnectionType(sse_headers, ConnectionType::connection_sse);
							keepalive_ = true;

							auto* webem = request_handler_.Get_myWebem();
							if (webem)
							{
								std::string req_path = webem->ExtractRequestPath(request_.uri);
								auto factory = webem->GetSseFactory(req_path);
								if (factory)
								{
									std::weak_ptr<connection> weak_self = shared_from_this();
									auto writer = [weak_self](const std::string& data) {
										if (auto self = weak_self.lock())
											self->MyWrite(data);
									};
									sse_handler_ = factory(writer, reply_.sse_session, reply_.sse_context);
									webem->RegisterSseHandler(sse_handler_);
									sse_handler_->Start();
								}
							}
							// Do NOT call read_more() -- SSE is server-to-client only.
							// request_ is not needed again on this connection (the http
							// case above is never reached once connection_type has moved
							// to connection_sse), but clear it anyway so it does not sit
							// around holding the last request's headers.
							request_ = request();
							return;
						}
						else if (reply_.status == reply::download_file) {
							std::string filename_attachment = reply_.content;
							size_t npos = filename_attachment.find("\r\n");
							if (npos == std::string::npos)
							{
								reply_ = reply::stock_reply(reply::internal_server_error);
							}
							else
							{
								std::string filename = filename_attachment.substr(0, npos);
								std::string attachment = filename_attachment.substr(npos + 2);
								if (!send_file(filename, attachment, reply_))
								{
									// send_file() failed (file not found, or attachment_name rejected
									// control-character validation). Either way it has already
									// overwritten reply_ with a stock error reply before returning
									// false -- reply_.status is guaranteed not to still be
									// download_file (102, an internal sentinel that must never be
									// serialised to the wire) -- so falling through to the ordinary
									// reply-writing path below is safe and sends that error reply.
								}
								else
								{
									// send_file() takes over writing the response; request_ has
									// no further use here, and this bypasses the reset below.
									request_ = request();
									return;
								}
							}
						}

						if (request_.keep_alive && ((reply_.status == reply::ok) || (reply_.status == reply::no_content) || (reply_.status == reply::not_modified))) {
							// Allows request handler to override the header (but it should not)
							reply::add_header_if_absent(&reply_, "Connection", "Keep-Alive");
							std::stringstream ss;
							ss << "max=" << default_max_requests_ << ", timeout=" << read_timeout_;
							reply::add_header_if_absent(&reply_, "Keep-Alive", ss.str());
						}
						else if (!keepalive_ && (reply_.status != reply::switching_protocols)) {
							// We really are going to close (keepalive_ is what read_more()
							// below tests), so say so. An HTTP/1.1 client is entitled to
							// assume the connection stays open unless told otherwise, and a
							// silent close leaves it to find out by having its next request
							// fail -- which, on a non-idempotent request it then retries, is
							// worse than a wasted round trip.
							//
							// Keyed on keepalive_ rather than on the status test above: a 404
							// or 500 on an otherwise healthy keep-alive connection is still
							// reused (read_more() is still called), and announcing "close"
							// there would throw away a perfectly good connection on every
							// missing favicon.
							//
							// Excluded for 101, where "Connection: Upgrade" is already set and
							// the connection very much continues.
							reply::add_header_if_absent(&reply_, "Connection", "close");
						}

						if (reply_.status == reply::switching_protocols) {
							// Write the 101 response and flip connection_type in one strand task
							// (WriteThenSetConnectionType), not a plain MyWrite() followed by an
							// unguarded assignment here: MyWrite now defers its work onto
							// strand_, so assigning connection_type here, synchronously, would
							// let it run before the queued 101 write and any pre-upgrade frames
							// already queued ahead of it (from the handler's Start(), above) --
							// exactly the ordering the comment there warns against.
							WriteThenSetConnectionType(reply_.to_string(request_.method), ConnectionType::connection_websocket);
						}
						else {
							MyWrite(reply_.to_string(request_.method));
						}

						if (keepalive_) {
							read_more();
						}
						status_ = WAITING_WRITE;
						// This request's processing is finished; request_ has no further
						// use (the websocket-upgrade case above has already switched
						// connection_type, so the http case will not read it again either).
						// Clear it now rather than leaving it to be overwritten byte-by-byte
						// by the next request's parse, so a shorter next request cannot
						// inherit stale headers or a stale URI from this one.
						request_ = request();
					}
					else if (!result)
					{
						// A malformed first request still ends the slow-trickle exposure
						// initial_request_timeout guards against just as a well-formed one
						// does -- the connection is about to be dropped anyway (keepalive_
						// is forced false just below), so there is nothing left for that
						// timer to usefully bound. Harmless no-op on a later request.
						cancel_initial_request_timeout();

						keepalive_ = false;
						// Transfer-Encoding is the one rejection that isn't just a malformed
						// request: chunked decoding is not implemented, so it is a 501 rather
						// than a 400. Each size limit maps to the status that names the part
						// actually breached -- a client told "431 Request Header Fields Too
						// Large" after uploading an oversized file would go looking at its
						// headers -- and the server-wide budget maps to 503 because it is
						// transient and worth retrying, unlike the per-request cap.
						// Everything else the parser refuses (bad framing, disagreeing
						// Content-Length headers, ...) is a plain bad request. This is a
						// switch rather than a ternary, and deliberately has no default
						// label, so that adding a new reject_reason without also adding a
						// case here is a compiler warning instead of a silent fall into
						// "everything maps to bad_request".
						reply::status_type reject_status = reply::bad_request;
						switch (request_parser_.last_reject_reason())
						{
						case request_parser::reject_reason::not_implemented:
							reject_status = reply::not_implemented;
							break;
						case request_parser::reject_reason::header_too_large:
							reject_status = reply::request_header_fields_too_large;
							break;
						case request_parser::reject_reason::uri_too_long:
							reject_status = reply::uri_too_long;
							break;
						case request_parser::reject_reason::body_too_large:
							reject_status = reply::payload_too_large;
							break;
						case request_parser::reject_reason::body_budget_exhausted:
							reject_status = reply::service_unavailable;
							break;
						case request_parser::reject_reason::bad_request:
						case request_parser::reject_reason::none:
							reject_status = reply::bad_request;
							break;
						}

						// Debug, not Error: every input that reaches here is chosen by
						// the client, so an Error-level line per malformed request lets
						// anyone fill an operator's log by sending junk -- the same
						// amplification the refusal logging in connection_manager is
						// throttled to avoid. Nothing has gone wrong on this side; a
						// bad request was correctly rejected.
						//
						// The previous wording ("Error parsing http request address")
						// also misread: the peer address parsed fine and is only context
						// here. What failed is the request, and the reason -- which is
						// what an operator chasing a limit that is set too low actually
						// needs -- was not reported at all.
						if (m_logger) m_logger->Debug(DebugCategory::WebServer,
							"%s -> rejected malformed or oversized request, replying %d",
							host_remote_endpoint_address_.c_str(),
							static_cast<int>(reject_status));
						reply_ = reply::stock_reply(reject_status);
						MyWrite(reply_.to_string(request_.method));
						if (keepalive_) {
							read_more();
						}
						// The connection is being dropped (keepalive_ was just forced
						// false above), so nothing will parse another request on it, but
						// reset defensively rather than leave a rejected request's partial
						// state lying around on the connection object.
						request_parser_.reset();
						request_ = request();
						buf_parsed_offset_ = 0;
					}
					else
					{
						// Request is incomplete (indeterminate tribool), not rejected.
						// buf_parsed_offset_ is deliberately left as parsing just set it
						// above rather than reset to 0 here: that is exactly what lets
						// the next handle_read callback resume parsing where this one
						// left off instead of restarting from byte 0 of _buf.
						read_more();
					}
					break;
				case ConnectionType::connection_websocket:
				case ConnectionType::connection_websocket_closing:
					// Drain all complete frames from the buffer before yielding back to
					// the async read loop. Without this loop, bursts of frames that all
					// arrive in a single async_read_some callback leave frames 2..N stuck
					// in _buf until the next byte arrives from the network.
					do {
						begin = static_cast<const char*>(_buf.data().data());
						result = websocket_parser.parse((const unsigned char*)begin, _buf.size(), bytes_consumed, keepalive_);
						_buf.consume(bytes_consumed);
					} while (keepalive_ && bytes_consumed > 0 && _buf.size() > 0);

					if (keepalive_) {
						read_more();
					}
					else {
						// a connection close control packet was received
						// todo: wait for writeQ to flush?
						connection_type = ConnectionType::connection_websocket_closing;
					}
					break;
				}
			}
			else if (error == boost::asio::error::eof)
			{
				connection_manager_.stop(shared_from_this());
			}
			else if (error != boost::asio::error::operation_aborted)
			{
				connection_manager_.stop(shared_from_this());
			}
		}

		void connection::handle_write(const boost::system::error_code& error, size_t bytes_transferred)
		{
			std::unique_lock<std::mutex> lock(writeMutex);
			write_buffer.clear();
			write_in_progress = false;
			bool stopConnection = false;
			if (!error && !writeQ.empty())
			{
				std::string buf = writeQ.front();
				writeQ.pop_front();
				// Keep the queued-byte accounting in step with the deque itself.
				// Under normal operation writeQ_bytes_ is exactly the sum of the element
				// sizes, so the guard below never trips. It exists so that a hypothetical
				// accounting drift degrades into a clamp rather than an unsigned wrap that
				// would instantly exceed the bound and kill healthy connections. Drift is
				// a bug, so say so loudly rather than hiding it.
				if (writeQ_bytes_ < buf.size()) {
					if (m_logger) m_logger->Log(LogLevel::Error,
						"%s -> write queue accounting drift (%zu < %zu); please report",
						host_remote_endpoint_address_.c_str(), writeQ_bytes_, buf.size());
					writeQ_bytes_ = 0;
				}
				else {
					writeQ_bytes_ -= buf.size();
				}
				SocketWrite(buf);
				if (keepalive_)
				{
					reset_abandoned_timeout();
				}
				return;
			}

			// Stop needs to be outside the lock to avoid potential deadlocks.
			lock.unlock();

			if (error == boost::asio::error::operation_aborted)
			{
				connection_manager_.stop(shared_from_this());
			}
			else if (error)
			{
					if (connection_type == ConnectionType::connection_sse && sse_handler_)
					{
						auto* webem = request_handler_.Get_myWebem();
						if (webem)
							webem->ScheduleSseHandlerCleanup(std::move(sse_handler_));
						else
							try { sse_handler_->Stop(); } catch (...) {}
						sse_handler_.reset();
					}
					connection_manager_.stop(shared_from_this());
			}
			else if (keepalive_)
			{
				status_ = ENDING_WRITE;
				reset_abandoned_timeout();
			}
			else
			{
				//Everything has been send. Closing connection.
				connection_manager_.stop(shared_from_this());
			}
		}

		/// Close this connection from any thread.
		///
		/// MyWrite() may be called by application threads (the documented WebSocket/SSE
		/// writer-callback pattern), but connection_manager is only safe to touch from the
		/// io thread. Posting through the timer's executor guarantees the stop runs there.
		void connection::post_stop() {
			boost::asio::post(read_timer_.get_executor(), [self = shared_from_this()]() {
				self->connection_manager_.stop(self);
			});
		}

		/// schedule the TLS handshake timeout
		void connection::set_handshake_timeout() {
			if (tls_handshake_timeout_ <= 0)
				return; // disabled
			handshake_timer_.expires_after(std::chrono::seconds(tls_handshake_timeout_));
			handshake_timer_.async_wait([self = shared_from_this()](auto &&err) { self->handle_handshake_timeout(err); });
		}

		/// cancel the TLS handshake timeout
		void connection::cancel_handshake_timeout() {
			try {
				handshake_timer_.cancel();
			}
			catch (...) {
				if (m_logger) m_logger->Log(LogLevel::Error, "%s -> exception thrown while canceling handshake timeout", host_remote_endpoint_address_.c_str());
			}
		}

		/// drop a connection that never completed its TLS handshake
		void connection::handle_handshake_timeout(const boost::system::error_code& error) {
			if (error == boost::asio::error::operation_aborted)
				return; // handshake completed, timer cancelled
			if (error)
				return;
			if (status_ != WAITING_HANDSHAKE)
				return; // already progressed; nothing to do
			if (m_logger) m_logger->Log(LogLevel::Status, "%s -> TLS handshake not completed within %d seconds, dropping connection",
						    host_remote_endpoint_address_.c_str(), tls_handshake_timeout_);
			connection_manager_.stop(shared_from_this());
		}

		/// schedule the initial-request timeout (see server_settings::initial_request_timeout)
		void connection::set_initial_request_timeout() {
			if (initial_request_timeout_ <= 0)
				return; // disabled
			initial_request_timer_.expires_after(std::chrono::seconds(initial_request_timeout_));
			initial_request_timer_.async_wait([self = shared_from_this()](auto &&err) { self->handle_initial_request_timeout(err); });
		}

		void connection::extend_initial_request_timeout_for_body(size_t content_length) {
			if (initial_request_timeout_ <= 0)
				return; // deadline disabled entirely; nothing to extend
			if (min_request_body_rate_ == 0)
			{
				// Rate floor disabled: the operator has opted out of bounding the
				// body phase by time, so the flat deadline must not apply to it
				// either -- leaving it armed would reintroduce exactly the failure
				// this function exists to prevent.
				cancel_initial_request_timeout();
				return;
			}

			// Seconds this body is allowed, at the configured floor throughput.
			// Computed in 64-bit and clamped: content_length is already bounded by
			// max_request_body_size / kMaxContentLength, but the clamp keeps the
			// arithmetic obviously safe if either is ever raised.
			const uint64_t allowance = static_cast<uint64_t>(content_length)
				/ static_cast<uint64_t>(min_request_body_rate_);
			constexpr uint64_t kMaxExtensionSeconds = 24ULL * 60 * 60;
			const uint64_t seconds = (std::min)(
				static_cast<uint64_t>(initial_request_timeout_) + allowance,
				kMaxExtensionSeconds);

			if (m_logger) m_logger->Debug(DebugCategory::WebServer,
				"%s -> body of %zu bytes admitted, initial-request deadline extended to %llu seconds",
				host_remote_endpoint_address_.c_str(), content_length,
				static_cast<unsigned long long>(seconds));

			// expires_after() on an already-pending timer cancels the outstanding
			// wait; handle_initial_request_timeout() returns early on
			// operation_aborted, so the superseded handler is a no-op.
			initial_request_timer_.expires_after(std::chrono::seconds(seconds));
			initial_request_timer_.async_wait([self = shared_from_this()](auto &&err) { self->handle_initial_request_timeout(err); });
		}

		/// cancel the initial-request timeout
		void connection::cancel_initial_request_timeout() {
			try {
				initial_request_timer_.cancel();
			}
			catch (...) {
				if (m_logger) m_logger->Log(LogLevel::Error, "%s -> exception thrown while canceling initial-request timeout", host_remote_endpoint_address_.c_str());
			}
		}

		/// Drop a connection that has not completed its first HTTP request within
		/// initial_request_timeout seconds of when reading began -- unlike
		/// read_timer_, this is never reset by individual bytes arriving, so a
		/// client trickling data slowly enough to keep dodging the per-read
		/// timeout cannot use that to hold a global connection slot (see
		/// max_connections) indefinitely without ever completing a request.
		void connection::handle_initial_request_timeout(const boost::system::error_code& error) {
			if (error == boost::asio::error::operation_aborted)
				return; // first request completed (or connection already stopping), timer cancelled
			if (error)
				return;
			if (m_logger) m_logger->Log(LogLevel::Status, "%s -> no complete request within %d seconds of connecting, dropping connection",
						    host_remote_endpoint_address_.c_str(), initial_request_timeout_);
			connection_manager_.stop(shared_from_this());
		}

		// schedule read timeout timer
		void connection::set_read_timeout() {
			read_timer_.expires_after(std::chrono::seconds(read_timeout_));
			read_timer_.async_wait([self = shared_from_this()](auto &&err) { self->handle_read_timeout(err); });
		}

		/// simply cancel read timeout timer
		void connection::cancel_read_timeout() {
			try {
				read_timer_.cancel();
			}
			catch (...) {
				if (m_logger) m_logger->Log(LogLevel::Error, "%s -> exception thrown while canceling read timeout", host_remote_endpoint_address_.c_str());
			}
		}

		/// reschedule read timeout timer
		void connection::reset_read_timeout() {
			cancel_read_timeout();
			set_read_timeout();
		}

		/// stop connection on read timeout
		void connection::handle_read_timeout(const boost::system::error_code& error) {
			if (!error && keepalive_ && (connection_type == ConnectionType::connection_websocket)) {
				// For WebSockets that requested keep-alive, use a Server side Ping
				websocket_parser.SendPing();
			}
			else if (!error && keepalive_ && (connection_type == ConnectionType::connection_sse)) {
				// SSE clients never send data, so the read timer must not close the connection.
				// Send a comment line as a keepalive and reschedule the timer. This handler
				// only ever runs on the io thread, so reset_read_timeout() below is not racing
				// anything; MyWrite() itself now just posts the write onto strand_ and returns.
				MyWrite(": keepalive\n\n");
				reset_read_timeout();
			}
			else if (!error)
			{
				connection_manager_.stop(shared_from_this());
			}
			else if (error != boost::asio::error::operation_aborted)
			{
				if (m_logger) m_logger->Log(LogLevel::Error, "connection::handle_read_timeout Error: %s", error.message().c_str());
				connection_manager_.stop(shared_from_this());
			}
		}

		/// schedule abandoned timeout timer
		void connection::set_abandoned_timeout() {
			abandoned_timer_.expires_after(std::chrono::seconds(default_abandoned_timeout_));
			abandoned_timer_.async_wait([self = shared_from_this()](auto &&err) { self->handle_abandoned_timeout(err); });
		}

		/// simply cancel abandoned timeout timer
		void connection::cancel_abandoned_timeout() {
			try {
				abandoned_timer_.cancel();
			}
			catch (...) {
				if (m_logger) m_logger->Log(LogLevel::Error, "%s -> exception thrown while canceling abandoned timeout", host_remote_endpoint_address_.c_str());
			}
		}

		/// reschedule abandoned timeout timer
		void connection::reset_abandoned_timeout() {
			cancel_abandoned_timeout();
			set_abandoned_timeout();
		}

		/// stop connection on abandoned timeout
		void connection::handle_abandoned_timeout(const boost::system::error_code& error) {
			if (error != boost::asio::error::operation_aborted) {
				if (m_logger) m_logger->Log(LogLevel::Status, "%s -> handle abandoned timeout (status=%d)", host_remote_endpoint_address_.c_str(), status_);
				connection_manager_.stop(shared_from_this());
			}
		}

		// Interval at which the WebSocket session renewal timer fires.
		// Must be shorter than SHORT_SESSION_TIMEOUT/2 (defined in cWebem.cpp) so that
		// RenewSessionIfNeeded() reliably catches the renewal window before expiry.
		static constexpr int kWsSessionRenewalInterval = 60; // seconds

		/// Start periodic session renewal timer for an authenticated WebSocket connection.
		/// Fires every kWsSessionRenewalInterval seconds so the session stays alive
		/// even when the client sends no HTTP requests (e.g. passive dashboard pages).
		void connection::start_ws_session_renewal() {
			if (m_ws_session_id.empty())
				return;
			ws_session_renewal_timer_.expires_after(std::chrono::seconds(kWsSessionRenewalInterval));
			ws_session_renewal_timer_.async_wait([self = shared_from_this()](const boost::system::error_code& err) {
				self->handle_ws_session_renewal(err);
			});
		}

		void connection::cancel_ws_session_renewal() {
			try {
				ws_session_renewal_timer_.cancel();
			}
			catch (...) {}
		}

		void connection::handle_ws_session_renewal(const boost::system::error_code& error) {
			if (error == boost::asio::error::operation_aborted)
				return;
			if (connection_type != ConnectionType::connection_websocket)
				return;
			auto* webem = request_handler_.Get_myWebem();
			if (webem && !m_ws_session_id.empty())
				webem->RenewSessionIfNeeded(m_ws_session_id);
			start_ws_session_renewal();
		}

	} // namespace server
} // namespace http
