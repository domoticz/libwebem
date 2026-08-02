//
// server.cpp
// ~~~~~~~~~~
//
#include "webem_stdafx.h"
#include <libwebem/server.h>
#include <chrono>
#include <fstream>
#include <future>
#include <thread>
#include <sys/stat.h>

namespace http {
namespace server {

	server_base::server_base(const server_settings &settings, request_handler &user_request_handler, WebServerLogger logger)
		: m_logger(std::move(logger))
		, io_context_()
		, acceptor_(io_context_)
		, accept_retry_timer_(io_context_)	// declared after acceptor_, see server.h
		, request_handler_(user_request_handler)
		, settings_(settings)
		, timeout_(20)
		, // default read timeout in seconds
		is_running(false)
		, m_heartbeat_timer(io_context_)
	{
		if (!settings.is_enabled())
		{
			throw std::invalid_argument("cannot initialize a disabled server (listening port cannot be empty or 0)");
		}
	}

	void server_base::init(const init_connectionhandler_func &init_connection_handler, accept_handler_func accept_handler)
	{
		// Install the connection limits before anything can be accepted.
		connection_manager_.configure(settings_.max_connections, settings_.max_connections_per_ip,
			settings_.max_body_bytes_in_flight, m_logger);
		connection_manager_.set_trusted_proxy_addresses(settings_.trusted_proxy_addresses);

		init_connection_handler();

		if (!new_connection_)
		{
			throw std::invalid_argument("cannot initialize a server without a valid connection");
		}

		// Open the acceptor with the option to reuse the address (i.e. SO_REUSEADDR).
		boost::asio::ip::tcp::resolver resolver(io_context_);
		boost::asio::ip::basic_resolver<boost::asio::ip::tcp>::results_type endpoints = resolver.resolve(settings_.listening_address, settings_.listening_port);
		auto endpoint = *endpoints.begin();
		acceptor_.open(endpoint.endpoint().protocol());
		acceptor_.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
		// bind to both ipv6 and ipv4 sockets for the "::" address only
		if (settings_.listening_address == "::")
		{
			acceptor_.set_option(boost::asio::ip::v6_only(false));
		}
		// bind to our port
		acceptor_.bind(endpoint);
		// listen for incoming requests
		acceptor_.listen();

		// start the accept thread
		acceptor_.async_accept(new_connection_->socket(), accept_handler);
	}

void server_base::run() {
	// The io_context::run() call will block until all asynchronous operations
	// have finished. While the server is running, there is always at least one
	// asynchronous operation outstanding: the asynchronous accept call waiting
	// for new incoming connections.
	//
	// Reaching the catch blocks below used to kill the webserver thread (and,
	// unless the host application both caught the rethrow and called run()
	// again, the process's ability to serve HTTP at all): every throwing path
	// reachable from a connection is now guarded closer to the source instead
	// -- the JWT branch in parse_auth_header, the top-level barrier around
	// request_handler_.handle_request() in connection::handle_read, and the
	// accept loop's own try/catch in do_accept()/handle_accept(), which retries
	// internally and never lets an exception reach io_context::run() in the
	// first place. An exception surfacing here therefore means one of those
	// barriers missed something, not a condition an operator can fix by
	// restarting the process. Recover in place instead: log it, rebuild the
	// io_context, and resume serving. do_accept()'s own re-arm-on-failure logic
	// (and its 100ms retry backoff) lives entirely inside the accept handler
	// and does not depend on this loop, so restarting here does not change how
	// the acceptor recovers from an accept-level error.
	//
	// The retry is bounded, though. Silently absorbing a "should never happen"
	// condition forever would turn a visible crash into a spinning log line that
	// nobody notices -- the host application (Domoticz) needs the ability to see
	// and act on a genuinely broken condition, not just have it swallowed. So the
	// consecutive-exception count is tracked, reset on a clean (non-throwing)
	// io_context::run() return, and once it reaches kMaxConsecutiveExceptions the
	// loop logs that the limit is exhausted and rethrows instead of retrying again.
	//
	// The sleep before retrying only guards against a bug that throws again
	// immediately on every attempt; without it, such a bug would spin this
	// thread at 100% CPU instead of merely repeating a log line. It is checked
	// against stopping_ both before and instead of the sleep: stop() may already
	// be waiting on this thread to exit, and io_context_::restart() would clear
	// the stopped state stop() just set, so a shutdown must never be made to
	// wait out the backoff (or worse, be undone by the restart()).
	constexpr int kMaxConsecutiveExceptions = 5;
	int consecutive_exceptions = 0;
	for (;;) {
		try {
			is_running = true;
			heart_beat(boost::system::error_code());
			io_context_.run();
			is_running = false;
			return;
		} catch (std::exception& e) {
			if (m_logger) m_logger->Log(LogLevel::Error, "[web:%s] exception occurred : '%s' (resuming)", settings_.listening_port.c_str(), e.what());
			is_running = false;
			// A shutdown already in progress wins over both retrying and rethrowing:
			// io_context_.restart() would undo the stopped state stop() just set, and
			// throwing out from under an intentional shutdown serves nobody either.
			if (stopping_) return;
			if (++consecutive_exceptions >= kMaxConsecutiveExceptions) {
				if (m_logger) m_logger->Log(LogLevel::Error, "[web:%s] %d consecutive exceptions, giving up", settings_.listening_port.c_str(), consecutive_exceptions);
				throw;
			}
			io_context_.restart(); // this call is needed before calling run() again
		} catch (...) {
			if (m_logger) m_logger->Log(LogLevel::Error, "[web:%s] unknown exception occurred (resuming)", settings_.listening_port.c_str());
			is_running = false;
			if (stopping_) return;
			if (++consecutive_exceptions >= kMaxConsecutiveExceptions) {
				if (m_logger) m_logger->Log(LogLevel::Error, "[web:%s] %d consecutive exceptions, giving up", settings_.listening_port.c_str(), consecutive_exceptions);
				throw;
			}
			io_context_.restart(); // this call is needed before calling run() again
		}
		if (stopping_) return;
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
	}
}

/// Ask the server to stop using asynchronous command
void server_base::stop() {
	// Set before anything else: run()'s retry loop consults this after catching
	// an exception, and it must see the intent to stop before it decides whether
	// to restart the io_context (io_context_.restart() would otherwise clear the
	// stopped state set below, right out from under this call).
	stopping_ = true;
	if (is_running) {
		// Post a call to the stop function so that server_base::stop() is safe to call from any thread.
		// Rene, set is_running to false, because the following is an io_context call, which makes is_running
		// never set to false whilst in the call itself
		is_running = false;
		std::promise<void> stop_promise;
		auto stop_future = stop_promise.get_future();
		boost::asio::post(io_context_, [this, &stop_promise] {
			handle_stop();
			stop_promise.set_value();
		});
		// Block until handle_stop completes, with a 15-second safety timeout.
		// This replaces the previous sleep_milliseconds(500) polling loop.
		if (stop_future.wait_for(std::chrono::seconds(15)) == std::future_status::timeout)
		{
			if (m_logger)
				m_logger->Log(LogLevel::Error, "[web:%s] timeout waiting for server stop", settings_.listening_port.c_str());
		}
	} else {
		// if io_context is not running then the post call will not be performed
		handle_stop();
	}
	io_context_.stop();

	// Deregister heartbeat
	if (settings_.on_heartbeat_remove)
		settings_.on_heartbeat_remove(std::string("WebServer:") + settings_.listening_port);
}

void server_base::handle_stop() {
	try {
		boost::system::error_code ignored_ec;
		acceptor_.close(ignored_ec);
	} catch (...) {
		if (m_logger) m_logger->Log(LogLevel::Error, "[web:%s] exception occurred while closing acceptor", settings_.listening_port.c_str());
	}
	// Cancel any pending heartbeat timer so the Boost.Asio IOCP timer thread
	// can exit cleanly when io_context_.stop() is called.  Without this the
	// async_wait keeps the internal timer thread alive, causing a shutdown hang.
	m_heartbeat_timer.cancel();
	// Same for a pending accept retry, or shutdown would wait out its backoff.
	accept_retry_timer_.cancel();
	connection_manager_.stop_all();
}

void server_base::heart_beat(const boost::system::error_code& error)
{
	if (!error) {
		// Heartbeat
		if (settings_.on_heartbeat)
			settings_.on_heartbeat(std::string("WebServer:") + settings_.listening_port);

		// Schedule next heartbeat
		m_heartbeat_timer.expires_after(std::chrono::seconds(4));
		m_heartbeat_timer.async_wait([this](auto &&err) { heart_beat(err); });
	}
}

server::server(const server_settings &settings, request_handler &user_request_handler, WebServerLogger logger)
	: server_base(settings, user_request_handler, std::move(logger))
{
	init([this] { init_connection(); }, [this](auto &&err) { handle_accept(err); });
}

void server_base::schedule_accept_retry(const std::function<void()> &rearm)
{
	// The error itself is already logged at error level by the caller; this is
	// just visibility into the backoff for an operator debugging a listener
	// that keeps failing to accept.
	if (m_logger)
		m_logger->Debug(DebugCategory::WebServer, "[web:%s] scheduling accept retry in 100ms", settings_.listening_port.c_str());
	accept_retry_timer_.expires_after(std::chrono::milliseconds(100));
	accept_retry_timer_.async_wait([rearm](const boost::system::error_code &ec) {
		if (ec)
			return; // cancelled during shutdown
		rearm();
	});
}

void server::init_connection() {
	new_connection_.reset(new connection(io_context_, connection_manager_, request_handler_, timeout_, settings_, m_logger));
}

void server::do_accept() {
	if (!acceptor_.is_open())
		return; // stopped

	// Allocating the pending connection can throw (std::bad_alloc under memory
	// pressure). This runs inside an async handler, so letting it escape would unwind
	// out of io_context::run() and leave the acceptor un-armed - the very failure this
	// whole change exists to prevent. Retry instead of dying.
	try {
		init_connection();
	}
	catch (const std::exception &e) {
		if (m_logger)
			m_logger->Log(LogLevel::Error, "[web:%s] could not create a pending connection (%s); retrying",
				      settings_.listening_port.c_str(), e.what());
		schedule_accept_retry([this] { do_accept(); });
		return;
	}
	catch (...) {
		if (m_logger)
			m_logger->Log(LogLevel::Error, "[web:%s] could not create a pending connection; retrying",
				      settings_.listening_port.c_str());
		schedule_accept_retry([this] { do_accept(); });
		return;
	}

	acceptor_.async_accept(new_connection_->socket(), [this](auto &&err) { handle_accept(err); });
}

/**
 * accepting incoming requests and start the client connection loop
 */
void server::handle_accept(const boost::system::error_code& e) {
	if (e == boost::asio::error::operation_aborted)
		return; // shutting down
	if (!acceptor_.is_open())
		return;

	if (!e) {
		// connection_manager_.start() inserts into connections_ plus the per-address
		// bookkeeping maps, which can throw std::bad_alloc under memory pressure. It
		// runs inside this accept handler, so letting it escape would unwind out of
		// io_context::run() and skip do_accept() below -- the only place the acceptor
		// is re-armed -- leaving the listener silently dead while the heartbeat timer
		// keeps the process looking healthy. Lose the connection being started, but
		// keep the acceptor alive by retrying instead.
		try {
			connection_manager_.start(new_connection_);
		}
		catch (const std::exception &ex) {
			if (m_logger)
				m_logger->Log(LogLevel::Error, "[web:%s] could not start accepted connection (%s); retrying",
					      settings_.listening_port.c_str(), ex.what());
			schedule_accept_retry([this] { do_accept(); });
			return;
		}
		catch (...) {
			if (m_logger)
				m_logger->Log(LogLevel::Error, "[web:%s] could not start accepted connection; retrying",
					      settings_.listening_port.c_str());
			schedule_accept_retry([this] { do_accept(); });
			return;
		}
		do_accept();
		return;
	}

	// The acceptor MUST be re-armed even on failure. Previously the re-arm lived
	// inside the success branch, so a single accept error (EMFILE from fd exhaustion,
	// or ECONNABORTED from a client that resets before being accepted) stopped the
	// server accepting new connections permanently and silently: the heartbeat timer
	// kept io_context::run() alive, so the process still looked healthy while being
	// unreachable. Back off briefly first, because EMFILE leaves the pending
	// connection queued and would otherwise spin the io thread.
	if (m_logger)
		m_logger->Log(LogLevel::Error, "[web:%s] accept failed: %s (retrying)",
			      settings_.listening_port.c_str(), e.message().c_str());
	schedule_accept_retry([this] { do_accept(); });
}

#ifdef WWW_ENABLE_SSL
ssl_server::ssl_server(const ssl_server_settings &ssl_settings, request_handler &user_request_handler, WebServerLogger logger)
	: server_base(ssl_settings, user_request_handler, std::move(logger))
	, settings_(ssl_settings)
	, context_(ssl_settings.get_ssl_method())
{
	init([this] { init_connection(); }, [this](auto &&err) { handle_accept(err); });
}

// this constructor will send std::bad_cast exception if the settings argument is not a ssl_server_settings object
ssl_server::ssl_server(const server_settings &settings, request_handler &user_request_handler, WebServerLogger logger)
	: server_base(settings, user_request_handler, std::move(logger))
	, settings_(dynamic_cast<ssl_server_settings const &>(settings))
	, context_(dynamic_cast<ssl_server_settings const &>(settings).get_ssl_method())
{
	init([this] { init_connection(); }, [this](auto &&err) { handle_accept(err); });
}

void ssl_server::init_connection() {
	// the following line gets the passphrase for protected private server keys
	context_.set_password_callback([this](auto &&...) { return get_passphrase(); });

	if (settings_.ssl_options.empty()) {
		if (m_logger) m_logger->Log(LogLevel::Error, "[web:%s] missing SSL options parameter !", settings_.listening_port.c_str());
	} else {
		context_.set_options(settings_.get_ssl_options());
	}

	if (!settings_.cipher_list.empty())
	{
		SSL_CTX_set_cipher_list(context_.native_handle(), settings_.cipher_list.c_str());
		if (m_logger) m_logger->Debug(DebugCategory::WebServer, "[web:%s] Enabled ciphers (TLSv1.2) %s", settings_.listening_port.c_str(), settings_.cipher_list.c_str());
	}

	SSL_CTX_set_min_proto_version(context_.native_handle(), TLS1_2_VERSION);
	SSL_CTX_set_options(context_.native_handle(), SSL_OP_CIPHER_SERVER_PREFERENCE);
	SSL_CTX_set_options(context_.native_handle(), SSL_OP_NO_RENEGOTIATION);

	struct stat st;
	if (settings_.certificate_chain_file_path.empty()) {
		if (m_logger) m_logger->Log(LogLevel::Error, "[web:%s] missing SSL certificate chain file parameter !", settings_.listening_port.c_str());
	} else if (!stat(settings_.certificate_chain_file_path.c_str(), &st)) {
		cert_chain_tm_ = st.st_mtime;
		context_.use_certificate_chain_file(settings_.certificate_chain_file_path);
	} else {
		if (m_logger) m_logger->Log(LogLevel::Error, "[web:%s] missing SSL certificate chain file %s!", settings_.listening_port.c_str(), settings_.certificate_chain_file_path.c_str());
	}

	if (settings_.cert_file_path.empty()) {
		if (m_logger) m_logger->Log(LogLevel::Error, "[web:%s] missing SSL certificate file parameter !", settings_.listening_port.c_str());
	} else if (!stat(settings_.cert_file_path.c_str(), &st)) {
		cert_tm_ = st.st_mtime;
		context_.use_certificate_file(settings_.cert_file_path, boost::asio::ssl::context::pem);
	} else {
		if (m_logger) m_logger->Log(LogLevel::Error, "[web:%s] missing SSL certificate file %s!", settings_.listening_port.c_str(), settings_.cert_file_path.c_str());
	}

	if (settings_.private_key_file_path.empty()) {
		if (m_logger) m_logger->Log(LogLevel::Error, "[web:%s] missing SSL private key file parameter !", settings_.listening_port.c_str());
	} else if (!stat(settings_.private_key_file_path.c_str(), &st)) {
		// We don't actually bother to track the mtime of the private
		// key file as it can't sanely change without changing the
		// certificate too. And may in fact change *before* the
		// certificate does, while the cert is being issued. We
		// don't want to update until the *cert* file changes.
		context_.use_private_key_file(settings_.private_key_file_path, boost::asio::ssl::context::pem);
	} else {
		if (m_logger) m_logger->Log(LogLevel::Error, "[web:%s] missing SSL private key file %s!", settings_.listening_port.c_str(), settings_.private_key_file_path.c_str());
	}

	// Do not work with mobile devices at this time (2016/02)
	if (settings_.verify_peer || settings_.verify_fail_if_no_peer_cert) {
		if (settings_.verify_file_path.empty()) {
			if (m_logger) m_logger->Log(LogLevel::Error, "[web:%s] missing SSL verify file parameter !", settings_.listening_port.c_str());
		} else {
			context_.load_verify_file(settings_.verify_file_path);
			boost::asio::ssl::context::verify_mode verify_mode = 0;
			if (settings_.verify_peer) {
				verify_mode |= boost::asio::ssl::context::verify_peer;
			}
			if (settings_.verify_fail_if_no_peer_cert) {
				verify_mode |= boost::asio::ssl::context::verify_fail_if_no_peer_cert;
			}
			context_.set_verify_mode(verify_mode);
		}
	}

	// Load DH parameters
	if (settings_.tmp_dh_file_path.empty()) {
		if (m_logger) m_logger->Log(LogLevel::Error, "[web:%s] missing SSL DH file parameter", settings_.listening_port.c_str());
	} else if (!stat(settings_.tmp_dh_file_path.c_str(), &st)) {
		dhparam_tm_ = st.st_mtime;

		std::ifstream ifs(settings_.tmp_dh_file_path.c_str());
		std::string content((std::istreambuf_iterator<char>(ifs)),
				(std::istreambuf_iterator<char>()));
		if (content.find("DH PARAMETERS") != std::string::npos) {
			context_.use_tmp_dh_file(settings_.tmp_dh_file_path);
			if (m_logger) m_logger->Debug(DebugCategory::WebServer, "[web:%s] 'DH PARAMETERS' found in file %s", settings_.listening_port.c_str(), settings_.tmp_dh_file_path.c_str());
		} else {
			if (m_logger) m_logger->Log(LogLevel::Error, "[web:%s] missing SSL DH parameters from file %s", settings_.listening_port.c_str(), settings_.tmp_dh_file_path.c_str());
		}
	} else {
		if (m_logger) m_logger->Log(LogLevel::Error, "[web:%s] missing SSL DH parameters file %s!", settings_.listening_port.c_str(), settings_.tmp_dh_file_path.c_str());
	}
	new_connection_.reset(new connection(io_context_, connection_manager_, request_handler_, timeout_, context_, settings_, m_logger));
}

void ssl_server::reinit_connection()
{
	struct stat st;

	// The use_certificate_*/use_private_key_file overloads below throw. This runs from
	// the accept handler, so an exception would unwind out of io_context::run() and
	// leave the acceptor un-armed — a routine certbot renewal that rewrites the file
	// non-atomically could take the HTTPS listener down until the next restart.
	// Contain it: on failure keep serving with the context we already loaded.
	try {

	if ((!settings_.certificate_chain_file_path.empty() &&
	     !stat(settings_.certificate_chain_file_path.c_str(), &st) &&
	     st.st_mtime != cert_chain_tm_)) {
		cert_chain_tm_ = st.st_mtime;
		if (m_logger) m_logger->Log(LogLevel::Status, "[web:%s] Reloading SSL certificate chain file", settings_.listening_port.c_str());
		context_.use_certificate_chain_file(settings_.certificate_chain_file_path);
	}

	if (!settings_.cert_file_path.empty() &&
	    !stat(settings_.cert_file_path.c_str(), &st) &&
	    st.st_mtime != cert_tm_) {
		cert_tm_ = st.st_mtime;
		if (m_logger) m_logger->Log(LogLevel::Status, "[web:%s] Reloading SSL certificate and private key", settings_.listening_port.c_str());
		context_.use_certificate_file(settings_.cert_file_path, boost::asio::ssl::context::pem);
		context_.use_private_key_file(settings_.private_key_file_path, boost::asio::ssl::context::pem);
	}

	if (!settings_.tmp_dh_file_path.empty() &&
	    !stat(settings_.tmp_dh_file_path.c_str(), &st) &&
	    st.st_mtime != dhparam_tm_) {
		dhparam_tm_ = st.st_mtime;
		std::ifstream ifs(settings_.tmp_dh_file_path.c_str());
		std::string content((std::istreambuf_iterator<char>(ifs)),
				(std::istreambuf_iterator<char>()));
		if (content.find("DH PARAMETERS") != std::string::npos) {
			if (m_logger) m_logger->Log(LogLevel::Status, "[web:%s] Reloading SSL DH parameters", settings_.listening_port.c_str());
			context_.use_tmp_dh_file(settings_.tmp_dh_file_path);
		} else {
			if (m_logger) m_logger->Log(LogLevel::Error, "[web:%s] missing SSL DH parameters from file %s", settings_.listening_port.c_str(), settings_.tmp_dh_file_path.c_str());
		}
	}

	}
	catch (const std::exception &e) {
		if (m_logger) m_logger->Log(LogLevel::Error, "[web:%s] failed to reload SSL material (%s); continuing with the previously loaded certificate", settings_.listening_port.c_str(), e.what());
	}
	catch (...) {
		if (m_logger) m_logger->Log(LogLevel::Error, "[web:%s] failed to reload SSL material; continuing with the previously loaded certificate", settings_.listening_port.c_str());
	}

	// Always produce the next pending connection, even if the reload above failed:
	// do_accept() is about to hand its socket to async_accept.
	new_connection_.reset(new connection(io_context_, connection_manager_, request_handler_, timeout_, context_, settings_, m_logger));
}

/**
 * accepting incoming requests and start the client connection loop
 */
void ssl_server::do_accept() {
	if (!acceptor_.is_open())
		return; // stopped

	// reinit_connection() contains its own try/catch around the certificate reload, but
	// the connection allocation after it can still throw. Same reasoning as the plain
	// server: an escape here would kill the accept loop. Retry instead.
	try {
		reinit_connection();   // also creates the next new_connection_
	}
	catch (const std::exception &e) {
		if (m_logger)
			m_logger->Log(LogLevel::Error, "[web:%s] could not create a pending connection (%s); retrying",
				      settings_.listening_port.c_str(), e.what());
		schedule_accept_retry([this] { do_accept(); });
		return;
	}
	catch (...) {
		if (m_logger)
			m_logger->Log(LogLevel::Error, "[web:%s] could not create a pending connection; retrying",
				      settings_.listening_port.c_str());
		schedule_accept_retry([this] { do_accept(); });
		return;
	}

	acceptor_.async_accept(new_connection_->socket(), [this](auto &&err) { handle_accept(err); });
}

void ssl_server::handle_accept(const boost::system::error_code& e) {
	if (e == boost::asio::error::operation_aborted)
		return; // shutting down
	if (!acceptor_.is_open())
		return;

	if (!e) {
		// See the note in server::handle_accept — connection_manager_.start() can
		// throw std::bad_alloc, and losing do_accept()'s re-arm here would leave the
		// HTTPS listener silently deaf. Same recovery: drop the connection, retry.
		try {
			connection_manager_.start(new_connection_);
		}
		catch (const std::exception &ex) {
			if (m_logger)
				m_logger->Log(LogLevel::Error, "[web:%s] could not start accepted connection (%s); retrying",
					      settings_.listening_port.c_str(), ex.what());
			schedule_accept_retry([this] { do_accept(); });
			return;
		}
		catch (...) {
			if (m_logger)
				m_logger->Log(LogLevel::Error, "[web:%s] could not start accepted connection; retrying",
					      settings_.listening_port.c_str());
			schedule_accept_retry([this] { do_accept(); });
			return;
		}
		do_accept();
		return;
	}

	// See the note in server::handle_accept — the acceptor must be re-armed on error
	// or the HTTPS listener goes permanently deaf while the process looks healthy.
	if (m_logger)
		m_logger->Log(LogLevel::Error, "[web:%s] accept failed: %s (retrying)",
			      settings_.listening_port.c_str(), e.message().c_str());
	schedule_accept_retry([this] { do_accept(); });
}

std::string ssl_server::get_passphrase() const {
	return settings_.private_key_pass_phrase;
}
#endif

std::shared_ptr<server_base> server_factory::create(const server_settings & settings, request_handler & user_request_handler, WebServerLogger logger) {
#ifdef WWW_ENABLE_SSL
		if (settings.is_secure()) {
			return create(dynamic_cast<ssl_server_settings const &>(settings), user_request_handler, logger);
		}
#endif
		return std::shared_ptr<server_base>(new server(settings, user_request_handler, logger));
	}

#ifdef WWW_ENABLE_SSL
std::shared_ptr<server_base> server_factory::create(const ssl_server_settings & ssl_settings, request_handler & user_request_handler, WebServerLogger logger) {
		return std::shared_ptr<server_base>(new ssl_server(ssl_settings, user_request_handler, logger));
	}
#endif

} // namespace server
} // namespace http
