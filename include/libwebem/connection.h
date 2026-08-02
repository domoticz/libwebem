//
// connection.h
// ~~~~~~~~~~~~~~
//
// Copyright (c) 2003-2008 Christopher M. Kohlhoff (chris at kohlhoff dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
#pragma once
#ifndef HTTP_CONNECTION_H
#define HTTP_CONNECTION_H

#include <boost/asio.hpp>
#include <deque>
#include <fstream>
#include "reply.h"
#include "request.h"
#include "request_handler.h"
#include "request_parser.h"
#include "Websockets.h"
#include "IWebServerLogger.h"
#include "ISseHandler.h"
#include "server_settings.h"
#ifdef WWW_ENABLE_SSL
#include <boost/asio/ssl.hpp>
typedef boost::asio::ssl::stream<boost::asio::ip::tcp::socket> ssl_socket;
#endif

namespace http {
	namespace server {

		class connection_manager;
		class CWebsocket;

		/// Represents a single connection from a client.
		class connection
			: public std::enable_shared_from_this<connection>
		{
		public:
			connection(const connection&) = delete;
			connection& operator=(const connection&) = delete;

			struct _tRemoteClients
			{
				time_t last_seen = 0;
				std::string host_remote_endpoint_address_;
				std::string host_local_endpoint_port_;
				std::string host_last_request_uri_;
			};
			/// Construct a connection with the given io_context.
			/// The resource limits are copied out of `settings` by value; no reference
			/// to the settings object is retained, so its lifetime does not matter here.
			explicit connection(boost::asio::io_context& io_context,
				connection_manager& manager, request_handler& handler, int timeout,
				const server_settings& settings,
				WebServerLogger logger = nullptr);
#ifdef WWW_ENABLE_SSL
			explicit connection(boost::asio::io_context& io_context,
				connection_manager& manager, request_handler& handler, int timeout, boost::asio::ssl::context& context,
				const server_settings& settings,
				WebServerLogger logger = nullptr);
#endif
			~connection() = default;

			/// Get the socket associated with the connection.
#ifdef WWW_ENABLE_SSL
			ssl_socket::lowest_layer_type& socket();
#else
			boost::asio::ip::tcp::socket& socket();
#endif

			/// Start the first asynchronous operation for the connection.
			void start();

			/// Stop all asynchronous operations associated with the connection.
			void stop();

			// send packet over websocket
			void WS_Write(const std::string& packet_data);
			// send binary packet over websocket
			void WS_WriteBinary(const std::string& data);
			/// Add content to write buffer
			void MyWrite(const std::string& buf);
			/// Timer handlers
			void handle_timeout(const boost::system::error_code& error);

			/// Timer handlers
			void handle_read_timeout(const boost::system::error_code& error);
			void handle_abandoned_timeout(const boost::system::error_code& error);
			void handle_ws_session_renewal(const boost::system::error_code& error);

		private:
			/// Handle completion of a read operation.
			void handle_read(const boost::system::error_code& e, std::size_t bytes_transferred);
			void read_more();

			/// Handle completion of a write operation.
			void handle_write(const boost::system::error_code& e, size_t bytes_transferred);
			/// Protect the write queue
			std::mutex writeMutex;
			/// Is protected by writeMutex
			std::deque<std::string> writeQ;
			/// Total bytes currently sitting in writeQ (excludes the in-flight write).
			/// Is protected by writeMutex.
			size_t writeQ_bytes_;
			/// Upper bound for writeQ_bytes_; 0 disables the check.
			size_t max_write_queue_bytes_;
			/// indicates if we are currently writing
			bool write_in_progress;
			void SocketWrite(const std::string& buf);
			/// The body of MyWrite(), run only on strand_ (see below). Split out so
			/// WS_Write/WS_WriteBinary can reach it without bouncing through a second
			/// post() of their own -- they post once, and from inside that single
			/// posted task decide whether to call this or QueuePreUpgradeFrame.
			void MyWriteOnStrand(const std::string& buf);
			/// Queue a WebSocket frame produced before the HTTP 101 response was written.
			/// Keeps writeQ_bytes_ in step, which the raw writeQ.push_back it replaces did not.
			void QueuePreUpgradeFrame(const std::string& frame);
			/// Close this connection from whichever thread noticed the problem.
			/// Posts to the io_context so connection_manager is only ever touched
			/// from the io thread, even when MyWrite is called by an application thread.
			void post_stop();

			bool send_file(const std::string& filename, std::string& attachment_name, reply& rep);
			std::ifstream sendfile_;
			void handle_write_file(const boost::system::error_code& e, size_t bytes_transferred);
#define FILE_SEND_BUFFER_SIZE 16 * 1024
			std::unique_ptr<std::array<uint8_t, FILE_SEND_BUFFER_SIZE>> send_buffer_;

			/// Initialize read timeout timer
			void set_read_timeout();
			/// Stop read timeout timer
			void cancel_read_timeout();
			/// Reset read timeout timer
			void reset_read_timeout();

			/// Schedule abandoned timeout timer
			void set_abandoned_timeout();
			/// Stop abandoned timeout timer
			void cancel_abandoned_timeout();
			/// Reschedule abandoned timeout timer
			void reset_abandoned_timeout();

			/// Start/cancel the TLS handshake timeout. Without it a client that opens a
			/// TCP connection to the HTTPS port and then says nothing holds a socket,
			/// an ssl_socket and three timers for the full abandoned timeout (20 min).
			void set_handshake_timeout();
			void cancel_handshake_timeout();
			void handle_handshake_timeout(const boost::system::error_code& error);

			/// Start/cancel the initial-request timeout (see
			/// server_settings::initial_request_timeout). Started once reading
			/// begins (after the TLS handshake, for a secure listener) and
			/// cancelled the moment the first request on the connection completes
			/// -- successfully or as a rejection, either way real progress was
			/// made. Unlike read_timer_ below, this is never reset by individual
			/// bytes arriving, which is exactly the point: it bounds the total time
			/// a connection may hold its global slot without completing any
			/// request at all, closing the slow-trickle path around the ordinary
			/// per-read timeout.
			void set_initial_request_timeout();
			void cancel_initial_request_timeout();
			void handle_initial_request_timeout(const boost::system::error_code& error);

			/// Re-arm the initial-request deadline once a request body has been
			/// admitted, giving it time proportional to the length the client
			/// declared instead of the flat initial_request_timeout.
			///
			/// Without this, the one-shot deadline that makes slow-trickle attacks
			/// unprofitable also kills a large legitimate upload: a 75 MB database
			/// restore cannot finish inside 30 seconds unless the client sustains
			/// 2.5 MB/s. The extension is finite and derived from a Content-Length
			/// the client committed to up front (and which has already been capped
			/// by max_request_body_size and charged to the server-wide budget), so
			/// the connection still cannot be held open indefinitely.
			/// See server_settings::min_request_body_rate.
			void extend_initial_request_timeout_for_body(size_t content_length);

			/// Start/cancel the periodic session-renewal timer used by WebSocket connections.
			/// Fires every kWsSessionRenewalInterval seconds; delegates threshold logic
			/// to cWebem::RenewSessionIfNeeded so no session constants leak into this file.
			void start_ws_session_renewal();
			void cancel_ws_session_renewal();

			/// Serializes every socket write that can originate off the io thread.
			/// WS_Write/WS_WriteBinary/MyWrite are, by design, called from arbitrary
			/// application threads (the writer-callback pattern demonstrated in
			/// examples/03_websocket) -- asio sockets are not safe for concurrent use,
			/// so the actual write (SocketWrite -> async_write) must not run on the
			/// caller's thread. Those three entry points post their work onto this
			/// strand instead of executing it inline; everything that already only
			/// ever runs on the io thread (reads, the TLS handshake, timers, stop())
			/// needs no such wrapping, because connection_manager's contract already
			/// confines it to that one thread (see connection_manager.h) -- this
			/// strand exists purely to bring the application-thread callers into that
			/// same single-thread world instead of letting them touch the socket
			/// directly. It also makes reading connection_type inside MyWrite/WS_Write
			/// race-free, since that read now happens on the strand too.
			boost::asio::strand<boost::asio::io_context::executor_type> strand_;

			/// Socket for the (PLAIN) connection.
			std::unique_ptr<boost::asio::ip::tcp::socket> socket_;
			//Host EndPoints
			std::string host_remote_endpoint_address_;
			std::string host_remote_endpoint_port_;
			std::string host_local_endpoint_address_;
			std::string host_local_endpoint_port_;
			std::string host_last_request_uri_;

			/// If this is a keep-alive connection or not
			bool keepalive_;

			/// Read timeout in seconds
			int read_timeout_;

			/// Read timeout timer
			boost::asio::steady_timer read_timer_;

			/// Abandoned connection timeout (in seconds)
			long default_abandoned_timeout_;
			/// Abandoned timeout timer
			boost::asio::steady_timer abandoned_timer_;

			/// TLS handshake timeout (in seconds); 0 disables it
			int tls_handshake_timeout_;
			/// TLS handshake timeout timer
			boost::asio::steady_timer handshake_timer_;

			/// Initial-request timeout (in seconds); 0 disables it. See
			/// server_settings::initial_request_timeout and
			/// set_initial_request_timeout()'s doc comment above.
			int initial_request_timeout_;
			/// Initial-request timeout timer
			boost::asio::steady_timer initial_request_timer_;
			/// Throughput floor used to size the body extension above; 0 disables
			/// it. See server_settings::min_request_body_rate.
			size_t min_request_body_rate_;

			/// Session ID for WebSocket connections (used for periodic session renewal)
			std::string m_ws_session_id;
			/// Periodic session renewal timer for WebSocket connections
			boost::asio::steady_timer ws_session_renewal_timer_;

			/// The manager for this connection.
			connection_manager& connection_manager_;

			/// The handler used to process the incoming request.
			request_handler& request_handler_;

			/// The parser for the incoming request.
			request_parser request_parser_;

			/// Bytes currently reserved, on behalf of the request presently being
			/// read, from connection_manager's server-wide in-flight-request-body
			/// budget (see server_settings::max_body_bytes_in_flight). 0 when no
			/// reservation is outstanding. Set by the body-admission callback
			/// wired into request_parser_ (see the constructor in connection.cpp)
			/// the moment it is granted, and cleared -- releasing the same amount
			/// back to connection_manager_ -- either when the request completes
			/// normally (handle_read) or when this connection is torn down before
			/// that happens (stop()), so a client that disconnects mid-body cannot
			/// leak its reservation for the life of the process.
			size_t body_bytes_reserved_{ 0 };

			/// The request currently being parsed (or most recently completed) on
			/// this connection. A member rather than a handle_read local so that a
			/// request split across several read callbacks resumes parsing into
			/// the same object instead of starting over; reset once a request
			/// completes or is rejected, so it must never be read across that
			/// boundary.
			request request_;

			/// our write buffer
			std::string write_buffer;

			/// The buffer that we receive data in. Constructed with an explicit
			/// maximum size (see connection.cpp) so a client that ignores every
			/// configured request-size limit hits a clean streambuf allocation
			/// failure -- handled in read_more() -- instead of growing this
			/// without bound.
			boost::asio::streambuf _buf;

			/// How many bytes at the front of _buf's current unconsumed region
			/// have already been fed to request_parser_. Lets handle_read resume
			/// parsing where the previous callback left off instead of
			/// re-parsing from byte 0 every time, which is what made a large
			/// request quadratic in the number of read callbacks it took to
			/// arrive. Reset to 0 whenever _buf is consumed (a request
			/// completed) or parsing is abandoned (a request was rejected).
			size_t buf_parsed_offset_;

			/// The status of the connection (can be initializing, handshaking, waiting, reading, writing)
			enum connection_status {
				INITIALIZING,
				WAITING_HANDSHAKE,
				ENDING_HANDSHAKE,
				WAITING_READ,
				READING,
				WAITING_WRITE,
				ENDING_WRITE
			} status_;

			/// The default number of request to handle with the connection when keep-alive is enabled.
			/// This is the value advertised in the "Keep-Alive: max=" response header.
			unsigned int default_max_requests_;
			/// Hard limit on HTTP requests served by this connection; 0 disables it.
			/// Not applied once the connection has been upgraded to WebSocket or SSE.
			unsigned int max_requests_per_connection_;
			/// Number of complete HTTP requests served so far on this connection
			unsigned int request_count_;

			// secure connection members below
			// secure connection yes/no
			bool secure_;
#ifdef WWW_ENABLE_SSL
			// the SSL socket
			std::unique_ptr<ssl_socket> sslsocket_;
			void handle_handshake(const boost::system::error_code& error);
#endif

			/// Logger
			WebServerLogger m_logger;

			/// websocket stuff
			CWebsocket websocket_parser;
			enum class ConnectionType {
				connection_http,
				connection_websocket,
				connection_websocket_closing,
				connection_sse
			};
			ConnectionType connection_type;

			/// Write `buf` and flip connection_type to new_type in a single strand
			/// task. Used by handle_read for the two upgrade responses (WebSocket
			/// 101, SSE headers): the flip has to land strictly after this write has
			/// been initiated, not before, or a WS_Write/MyWrite call already queued
			/// on strand_ ahead of it (e.g. from a handler's Start()) would see the
			/// new connection_type too early and be handled as post-upgrade traffic
			/// before the upgrade response itself has gone out.
			void WriteThenSetConnectionType(const std::string& buf, ConnectionType new_type);

			/// Active SSE handler for this connection (set when connection_type == connection_sse).
			std::shared_ptr<ISseHandler> sse_handler_;
		};

		typedef std::shared_ptr<connection> connection_ptr;

	} // namespace server
} // namespace http

#endif // HTTP_CONNECTION_H
