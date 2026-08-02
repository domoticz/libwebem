//
// server.h
// ~~~~~~~~~~
//
#pragma once
#ifndef HTTP_SSLSERVER_H
#define HTTP_SSLSERVER_H

#include <boost/asio.hpp>
#include <boost/asio/steady_timer.hpp>
#include <atomic>
#include <string>
#include "connection_manager.h"
#include "request_handler.h"
#include "server_settings.h"
#include "IWebServerLogger.h"

namespace http
{
	namespace server
	{

		typedef std::function<void()> init_connectionhandler_func;
		typedef std::function<void(const boost::system::error_code &error)> accept_handler_func;

		/// The top-level class of the HTTP(S) server.
		class server_base
		{
		      public:
			server_base(const server_base&) = delete;
			server_base& operator=(const server_base&) = delete;

			/// Construct the server to listen on the specified TCP address and port, and
			/// serve up files from the given directory.
			explicit server_base(const server_settings &settings, request_handler &user_request_handler,
					     WebServerLogger logger = nullptr);
			virtual ~server_base() = default;

			/// Run the server's io_context loop. Blocks until stop() is called.
			///
			/// An exception escaping a connection handler no longer terminates this
			/// call on the first occurrence: it is logged and the io_context loop is
			/// restarted in place, so a one-off failure doesn't take the server down.
			/// This should be unreachable in practice -- every known throwing path is
			/// guarded closer to the source -- but if a future change reopens one, the
			/// server degrades to "logging and retrying" rather than silently going
			/// deaf. Retries are bounded, though: after a small number of consecutive
			/// exceptions (the counter resets on a clean, non-throwing run) the loop
			/// logs that the retry limit is exhausted and rethrows, ending the call --
			/// a "should never happen" condition that keeps repeating is a real bug,
			/// and the host application must be able to see it rather than have it
			/// silently absorbed forever. Between attempts, a pending stop() request
			/// is checked and honoured immediately, so shutdown is never delayed by
			/// the retry backoff.
			void run();

			/// Stop the server.
			void stop();

			/// Print server settings to string (debug purpose)
			virtual std::string to_string() const
			{
				return "'server_base[" + settings_.to_string() + "]'";
			}

		      protected:
			void init(const init_connectionhandler_func &init_connection_handler, accept_handler_func accept_handler);

			/// Re-arm the acceptor after a short delay.
			///
			/// An accept error is often immediately repeatable — `EMFILE` leaves the
			/// pending connection in the queue, so retrying at once spins the single io
			/// thread at 100% CPU. Backing off keeps the listener alive without burning
			/// the loop. @p rearm is invoked on the io thread once the delay elapses.
			void schedule_accept_retry(const std::function<void()> &rearm);

			/// Logger shared across all server components
			WebServerLogger m_logger;

			/// The io_context used to perform asynchronous operations.
			boost::asio::io_context io_context_;

			/// Acceptor used to listen for incoming connections.
			boost::asio::ip::tcp::acceptor acceptor_;

			/// Backoff timer used by schedule_accept_retry(). Prevents the single io
			/// thread spinning on immediately-repeatable errors such as EMFILE.
			/// MUST be declared after io_context_: members are initialised in
			/// declaration order, and this one is constructed from io_context_.
			boost::asio::steady_timer accept_retry_timer_;

			/// The handler for all incoming requests.
			request_handler &request_handler_;

			/// The next connection to be accepted.
			connection_ptr new_connection_;

			connection_manager connection_manager_;
			/// server settings
			server_settings settings_;

			/// read timeout in seconds
			int timeout_;

			/// indicate if the server is running. Written by the webserver thread
			/// inside run()'s retry loop and read/written by whichever thread calls
			/// stop(), so it needs to be atomic rather than a plain bool.
			std::atomic<bool> is_running;

		      private:
			/// Handle a request to stop the server.
			void handle_stop();

			/// Set by stop() before it posts handle_stop(). run()'s retry loop checks
			/// this after catching an exception and before restarting the io_context:
			/// io_context_::restart() clears the stopped state that stop() just set,
			/// so without this check a stop() that races the catch block would be
			/// undone and the webserver thread would block in run() forever, past
			/// stop()'s own wait timeout.
			std::atomic<bool> stopping_{false};

			boost::asio::steady_timer m_heartbeat_timer;
			void heart_beat(const boost::system::error_code &error);
		};

		class server : public server_base
		{
		      public:
			/// Construct the HTTP server to listen on the specified TCP address and port, and
			/// serve up files from the given directory.
			server(const server_settings &settings, request_handler &user_request_handler,
			       WebServerLogger logger = nullptr);
			~server() override = default;

			/// Print server settings to string (debug purpose)
			std::string to_string() const override
			{
				return "'server[" + settings_.to_string() + "]'";
			}

		      protected:
			/// Initialize acceptor
			void init_connection();

			/// Handle completion of an asynchronous accept operation.
			void handle_accept(const boost::system::error_code &error);

		      private:
			/// Create the next pending connection and arm the acceptor. This is the
			/// only place the acceptor is re-armed, so the loop cannot silently die.
			void do_accept();
		};

#ifdef WWW_ENABLE_SSL
		class ssl_server : public server_base
		{
		      public:
			/// Construct the HTTPS server to listen on the specified TCP address and port, and
			/// serve up files from the given directory.
			ssl_server(const ssl_server_settings &ssl_settings, request_handler &user_request_handler,
				   WebServerLogger logger = nullptr);
			ssl_server(const server_settings &settings, request_handler &user_request_handler,
				   WebServerLogger logger = nullptr);
			~ssl_server() override = default;

			/// Print server settings to string (debug purpose)
			std::string to_string() const override
			{
				return "'ssl_server[" + settings_.to_string() + "]'";
			}

		      protected:
			/// Initialize acceptor
			void init_connection();

			/// Handle completion of an asynchronous accept operation.
			void handle_accept(const boost::system::error_code &error);

			// The HTTPS server settings
			ssl_server_settings settings_;

		      private:
			/// Create the next pending connection and arm the acceptor.
			void do_accept();
			/// Reload certificate and SSL params if they're changed, then create the
			/// next pending connection.
			///
			/// The certificate reload cannot throw: a momentarily unreadable certificate
			/// (a renewal writing the file non-atomically) must not escape into the accept
			/// handler, where it would unwind out of io_context::run() and leave the
			/// acceptor un-armed. The connection allocation afterwards still can throw
			/// under memory pressure, which do_accept() handles by retrying.
			void reinit_connection();
			time_t dhparam_tm_;
			time_t cert_tm_;
			time_t cert_chain_tm_;

			/// callback for the certficiate passphrase
			std::string get_passphrase() const;

			/// The SSL context
			boost::asio::ssl::context context_;
		};
#endif

		/// server factory
		class server_factory
		{
		      public:
			static std::shared_ptr<server_base> create(const server_settings &settings, request_handler &user_request_handler,
								   WebServerLogger logger = nullptr);

#ifdef WWW_ENABLE_SSL
			static std::shared_ptr<server_base> create(const ssl_server_settings &ssl_settings, request_handler &user_request_handler,
								   WebServerLogger logger = nullptr);
#endif
		};

	} // namespace server
} // namespace http

#endif // HTTP_SERVER_H
