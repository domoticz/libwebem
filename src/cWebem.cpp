//mainpage WEBEM
//
//Detailed class and method documentation of the WEBEM C++ embedded web server source code.
//
#include "webem_stdafx.h"
#include <algorithm>
#include <libwebem/cWebem.h>
#include <libwebem/reply.h>
#include <libwebem/request.h>
#include "mime_types.h"
#include "utf.h"
#include <libwebem/Base64.h>
#include "sha1.h"
#ifndef WEBEM_NO_GZIP
#include "GZipHelper.h"
#endif
#include <stdarg.h>
#include <fstream>
#include <sstream>
#include <cstdlib>
#include <libwebem/webem_utils.h>

#define JWT_DISABLE_BASE64
#include <jwt-cpp/traits/open-source-parsers-jsoncpp/defaults.h>

#define SHORT_SESSION_TIMEOUT 600 // 10 minutes
#define LONG_SESSION_TIMEOUT (30 * 86400) // 30 days


namespace http {
	namespace server {

		/// Returns the request's Origin header, or an empty string if absent.
		/// Used to decide whether/what to echo back via reply::add_cors_headers --
		/// never trust this value for anything beyond an exact-match comparison
		/// against a configured allow-list.
		static std::string GetRequestOrigin(const request &req)
		{
			const char *h = request::get_req_header(&req, "Origin");
			return h ? std::string(h) : std::string();
		}

		/// Strips a trailing ":80" (isSecure false) or ":443" (isSecure true) from
		/// a Host-header-shaped "host[:port]" string, leaving anything else
		/// untouched. Browsers never include the scheme's default port in the
		/// Origin header they send (https://fetch.spec.whatwg.org/#concept-origin
		/// serialises it as scheme "://" host, with the port omitted when it is
		/// the scheme's default), but a Host header that explicitly repeats the
		/// default port -- "Host: example.com:80" over plain HTTP, say -- is
		/// still perfectly legal, so the two need normalising onto the same
		/// footing before OriginMatchesRequestHost can compare them.
		static std::string StripDefaultPort(const std::string &host, bool isSecure)
		{
			const std::string defaultPort = isSecure ? "443" : "80";
			// IPv6 literal ("[::1]:80"): the port, if present, follows the closing
			// bracket, so search for the separating ':' from there rather than with
			// rfind, which would otherwise catch one of the address's own colons.
			if (!host.empty() && host.front() == '[')
			{
				std::size_t closeBracket = host.find(']');
				if (closeBracket == std::string::npos)
					return host; // malformed; leave as-is and let the comparison fail
				std::size_t colonPos = host.find(':', closeBracket);
				if (colonPos != std::string::npos && host.substr(colonPos + 1) == defaultPort)
					return host.substr(0, colonPos);
				return host;
			}
			std::size_t colonPos = host.rfind(':');
			if (colonPos != std::string::npos && host.substr(colonPos + 1) == defaultPort)
				return host.substr(0, colonPos);
			return host;
		}

		/// Extracts just the host (no scheme, no port, brackets stripped from an
		/// IPv6 literal) from an Origin header value, given the expected
		/// "scheme://" prefix. Returns empty if origin does not start with that
		/// exact scheme -- callers must treat that as "does not match", not as
		/// "host is empty", since an empty allowed_hosts entry is never expected
		/// to occur and must not accidentally compare equal to it.
		static std::string ExtractOriginHost(const std::string &origin, const std::string &scheme)
		{
			if (origin.rfind(scheme, 0) != 0)
				return std::string();
			std::string hostPort = origin.substr(scheme.size());
			// Same bracket-aware split as StripDefaultPort above (Origin's IPv6
			// literals are bracketed exactly like a Host header's).
			if (!hostPort.empty() && hostPort.front() == '[')
			{
				std::size_t closeBracket = hostPort.find(']');
				return closeBracket == std::string::npos ? hostPort : hostPort.substr(1, closeBracket - 1);
			}
			std::size_t colonPos = hostPort.rfind(':');
			return colonPos == std::string::npos ? hostPort : hostPort.substr(0, colonPos);
		}

		/// True if `origin` is an acceptable same-origin match for this request,
		/// i.e. the WebSocket handshake did not cross an origin boundary this
		/// server cares about. isSecure selects the scheme, since neither Origin
		/// nor Host carries scheme information on its own (well, Origin does,
		/// but it must agree with how this listener is configured).
		///
		/// When settings.allowed_hosts is configured, origin's host is checked
		/// against THAT allow-list rather than against this request's own Host
		/// header. This is the DNS-rebinding fix: comparing Origin to Host tells
		/// you the two AGREE, not that either one is legitimate, and a browser
		/// always derives both from the same URL -- so for a request originated
		/// by a page the browser resolved via a hostname the attacker controls
		/// (a short-TTL DNS record re-pointed at this server's LAN address after
		/// the victim's browser cached the page from it), Origin and Host agree
		/// trivially, on the attacker's own chosen hostname. Comparing against a
		/// fixed, operator-configured list instead requires that hostname to
		/// ALSO be one this server was explicitly told to answer to -- which an
		/// attacker's rebinding domain never is. See server_settings::allowed_hosts.
		///
		/// When allowed_hosts is empty (the default), falls back to the original
		/// behaviour -- Origin compared against this request's own Host header --
		/// so deployments that have not set it are unaffected. See
		/// docs/INTEGRATION.md for why leaving it unset leaves rebinding open.
		static bool OriginMatchesRequestHost(const request &req, const std::string &origin, bool isSecure, const server_settings &settings)
		{
			if (origin.empty())
				return false;
			std::string scheme = isSecure ? "https://" : "http://";

			if (!settings.allowed_hosts.empty())
			{
				std::string originHost = ExtractOriginHost(origin, scheme);
				if (originHost.empty())
					return false; // wrong scheme, or origin had no host at all
				for (const auto &allowed : settings.allowed_hosts)
				{
					if (boost::iequals(originHost, allowed))
						return true;
				}
				return false;
			}

			// Fallback: no allow-list configured. Preserves the pre-fix comparison
			// exactly (including its case-sensitivity, see below) so existing
			// deployments see no behaviour change until they opt in.
			const char *hostHeader = request::get_req_header(&req, "Host");
			if (!hostHeader)
				return false;
			std::string expected = scheme;
			expected += StripDefaultPort(hostHeader, isSecure);
			// Deliberately case-sensitive: browsers lower-case both the scheme and
			// the host when they serialise Origin (RFC 6454), so a real same-origin
			// request always arrives already normalised to match hostHeader's case
			// as sent by that same browser in its own request line.
			return origin == expected;
		}

		/**
		Webem constructor

		@param[in] server_settings  Server settings (IP address, listening port, ssl options...)
		@param[in] doc_root path to folder containing html e.g. "./"
		*/
		cWebem::cWebem(const server_settings &settings, const std::string &doc_root, WebServerLogger logger)
			: m_logger(std::move(logger))
			, m_DigistRealm("webem.local")
			, m_authmethod(AUTH_LOGIN)
			, m_AllowPlainBasicAuth(false)
			, m_session_cookie_name("SID")
			, m_settings(settings)
			, mySessionStore(nullptr)
			, myRequestHandler(doc_root, this, m_logger)
			// Rene, make sure we initialize m_sessions first, before starting a server
			, myServer(server_factory::create(settings, myRequestHandler, m_logger))
			, m_io_context()
			, m_session_clean_timer(m_io_context, std::chrono::minutes(1))
		{
			// associate handler to timer and schedule the first iteration
			m_session_clean_timer.async_wait([this](auto &&) { CleanSessions(); });
			m_io_context_thread = std::make_shared<std::thread>([p = &m_io_context] { p->run(); });
			utils::set_thread_name(m_io_context_thread->native_handle(), "Webem_ssncleaner");
		}

		cWebem::~cWebem()
		{
			// Remove reference to CWebServer before its deletion (fix a "pure virtual method called" exception on server termination)
			mySessionStore = nullptr;
			// Ensure session cleaner thread is stopped before members are destroyed
			try
			{
				if (!m_io_context.stopped())
				{
					m_io_context.stop();
				}
				if (m_io_context_thread)
				{
					m_io_context_thread->join();
					m_io_context_thread.reset();
				}
			}
			catch (...)
			{
			}
		}

		/**

		Start the server.

		This does not return.

		IMPORTANT: This method does not return. If application needs to continue, start new thread with call to this method.

		*/
		void cWebem::Run()
		{
			// Start Web server
			if (myServer != nullptr)
			{
				myServer->run();
			}
		}

		/**

		Stop and delete the internal server.

		IMPORTANT:  To start the server again, delete it and create a new cWebem instance.

		*/
		void cWebem::Stop()
		{
			// Stop session cleaner
			try
			{
				if (!m_io_context.stopped())
				{
					m_io_context.stop();
				}
				if (m_io_context_thread)
				{
					m_io_context_thread->join();
					m_io_context_thread.reset();
				}
			}
			catch (...)
			{
				if (m_logger) m_logger->Log(LogLevel::Error, "[web:%s] exception thrown while stopping session cleaner", GetPort().c_str());
			}
			// Stop Web server
			if (myServer != nullptr)
			{
				myServer->stop();
			}
		}

		void cWebem::SetAuthenticationMethod(const _eAuthenticationMethod amethod)
		{
			m_authmethod = amethod;
		}

		void cWebem::SetWebCompressionMode(_eWebCompressionMode gzmode)
		{
			m_gzipmode = gzmode;
		}

		void cWebem::SetSessionCookieName(const std::string& name)
		{
			m_session_cookie_name = name;
		}

		const std::string& cWebem::GetSessionCookieName() const
		{
			return m_session_cookie_name;
		}

		void cWebem::RegisterWebsocketEndpoint(
			const std::string& path,
			WebsocketHandlerFactory factory,
			const std::string& protocol)
		{
			m_websocketEndpoints.push_back({path, protocol, std::move(factory)});
		}

		WebsocketHandlerFactory cWebem::GetWebsocketFactory(const std::string& path) const
		{
			// Two-pass: exact path first, then "/" catch-all.
			// Without the two-pass approach the "/" endpoint always wins because its
			// condition (ep.path == "/") is unconditionally true, so any specific
			// endpoint registered after "/" is never reached.
			WebsocketHandlerFactory fallback;
			for (const auto& ep : m_websocketEndpoints)
			{
				if (ep.path == path)
					return ep.factory;   // exact match wins
				if (ep.path == "/" && !fallback)
					fallback = ep.factory;  // save catch-all for last resort
			}
			return fallback;
		}

		std::string cWebem::GetWebsocketProtocol(const std::string& path) const
		{
			// Two-pass: exact path first, then "/" catch-all.
			std::string fallback;
			for (const auto& ep : m_websocketEndpoints)
			{
				if (ep.path == path)
					return ep.protocol;  // exact match wins
				if (ep.path == "/" && fallback.empty())
					fallback = ep.protocol;
			}
			return fallback;
		}

		bool cWebem::HasWebsocketEndpoints() const
		{
			return !m_websocketEndpoints.empty();
		}

		void cWebem::RegisterWebsocketHandler(std::shared_ptr<IWebsocketHandler> handler)
		{
			std::lock_guard<std::mutex> lock(m_websocketHandlersMutex);
			m_websocketHandlers.erase(
				std::remove_if(m_websocketHandlers.begin(), m_websocketHandlers.end(),
					[](const std::weak_ptr<IWebsocketHandler>& wp) { return wp.expired(); }),
				m_websocketHandlers.end());
			m_websocketHandlers.push_back(handler);
		}

		void cWebem::ScheduleHandlerCleanup(std::shared_ptr<IWebsocketHandler> handler)
		{
			if (!handler)
				return;
			// If the session-cleaner io_context has already been stopped (e.g. because
			// cWebem::Stop() stops it before myServer->stop() triggers connection teardown),
			// posting to it would silently drop the task and leave the handler — and any
			// resources it owns, like an encoder subscriber or a colorbar worker thread —
			// alive until the io_context is destroyed.  Run Stop() inline in that case so
			// the handler is always cleaned up before cWebem is torn down.
			if (m_io_context.stopped())
			{
				if (m_logger)
					m_logger->Debug(DebugCategory::WebServer, "WebSocket: io_context stopped, running handler cleanup inline");
				try { handler->Stop(); } catch (...) {}
				return;
			}
			if (m_logger)
				m_logger->Debug(DebugCategory::WebServer, "WebSocket: scheduling async handler cleanup");
			boost::asio::post(m_io_context, [handler = std::move(handler), logger = m_logger]() {
				try {
					handler->Stop();
				}
				catch (...) {
					if (logger)
						logger->Log(LogLevel::Error, "WebSocket: exception during async handler cleanup");
				}
			});
		}

		void cWebem::ForEachHandler(std::function<void(IWebsocketHandler*)> callback)
		{
			std::vector<std::shared_ptr<IWebsocketHandler>> live;
			{
				std::lock_guard<std::mutex> lock(m_websocketHandlersMutex);
				auto it = m_websocketHandlers.begin();
				while (it != m_websocketHandlers.end())
				{
					if (auto sp = it->lock())
					{
						live.push_back(sp);
						++it;
					}
					else
					{
						it = m_websocketHandlers.erase(it);
					}
				}
			}
			for (auto& sp : live)
			{
				callback(sp.get());
			}
		}

		void cWebem::RegisterSseEndpoint(const std::string& path, SseHandlerFactory factory)
		{
			std::lock_guard<std::mutex> lock(m_configMutex);
			m_sse_endpoints[path] = std::move(factory);
		}

		SseHandlerFactory cWebem::GetSseFactory(const std::string& path) const
		{
			std::lock_guard<std::mutex> lock(m_configMutex);
			auto it = m_sse_endpoints.find(path);
			if (it != m_sse_endpoints.end())
				return it->second;
			return nullptr;
		}

		void cWebem::RegisterSseHandler(std::shared_ptr<ISseHandler> handler)
		{
			std::lock_guard<std::mutex> lock(m_sse_handlers_mutex);
			m_sse_handlers.erase(
				std::remove_if(m_sse_handlers.begin(), m_sse_handlers.end(),
					[](const std::shared_ptr<ISseHandler>& sp) { return !sp || !sp->IsAlive(); }),
				m_sse_handlers.end());
			m_sse_handlers.push_back(std::move(handler));
		}

		void cWebem::ForEachSseHandler(std::function<void(ISseHandler*)> callback)
		{
			std::vector<std::shared_ptr<ISseHandler>> live;
			{
				std::lock_guard<std::mutex> lock(m_sse_handlers_mutex);
				auto it = m_sse_handlers.begin();
				while (it != m_sse_handlers.end())
				{
					if (*it && (*it)->IsAlive())
					{
						live.push_back(*it);
						++it;
					}
					else
					{
						it = m_sse_handlers.erase(it);
					}
				}
			}
			for (auto& sp : live)
			{
				callback(sp.get());
			}
		}

		void cWebem::ScheduleSseHandlerCleanup(std::shared_ptr<ISseHandler> handler)
		{
			if (!handler)
				return;
			if (m_io_context.stopped())
			{
				if (m_logger)
					m_logger->Debug(DebugCategory::WebServer, "SSE: io_context stopped, running handler cleanup inline");
				try { handler->Stop(); } catch (...) {}
				{
					std::lock_guard<std::mutex> lock(m_sse_handlers_mutex);
					m_sse_handlers.erase(
						std::remove(m_sse_handlers.begin(), m_sse_handlers.end(), handler),
						m_sse_handlers.end());
				}
				return;
			}
			if (m_logger)
				m_logger->Debug(DebugCategory::WebServer, "SSE: scheduling async handler cleanup");
			boost::asio::post(m_io_context, [this, handler = std::move(handler), logger = m_logger]() {
				try {
					handler->Stop();
				}
				catch (...) {
					if (logger)
						logger->Log(LogLevel::Error, "SSE: exception during async handler cleanup");
				}
				std::lock_guard<std::mutex> lock(m_sse_handlers_mutex);
				m_sse_handlers.erase(
					std::remove(m_sse_handlers.begin(), m_sse_handlers.end(), handler),
					m_sse_handlers.end());
			});
		}

		void cWebem::RegisterNoCachePattern(const std::string& pattern)
		{
			std::lock_guard<std::mutex> lock(m_configMutex);
			m_noCachePatterns.push_back(pattern);
		}

		bool cWebem::IsNoCacheURI(const std::string& uri) const
		{
			std::lock_guard<std::mutex> lock(m_configMutex);
			for (const auto& pattern : m_noCachePatterns)
			{
				if (uri.find(pattern) != std::string::npos)
					return true;
			}
			return false;
		}

		void cWebem::SetAllowPlainBasicAuth(const bool bAllow)
		{
			m_AllowPlainBasicAuth = bAllow;
		}

		/**

		Create a link between a string ID and a function to calculate the dynamic content of the string

		The function should return a pointer to wide character buffer.  This should contain a wide character UTF-16 encoded unicode string.
		WEBEM will convert the string to UTF-8 encoding before sending to the browser.

		@param[in] idname  string identifier
		@param[in] fun pointer to function which calculates the string to be displayed

		*/

		void cWebem::RegisterPageCode(const char *pageurl, const webem_page_function &fun, bool bypassAuthentication)
		{
			std::lock_guard<std::mutex> lock(m_configMutex);
			myPages.insert(std::pair<std::string, webem_page_function >(std::string(pageurl), fun));
			if (bypassAuthentication)
			{
				myWhitelistURLs.push_back(pageurl);
			}
		}

		/**

		Specify link between form and application function to run when form submitted

		@param[in] idname string identifier
		@param[in] fun fpointer to function

		*/
		void cWebem::RegisterActionCode(const char *idname, const webem_action_function &fun)
		{
			std::lock_guard<std::mutex> lock(m_configMutex);
			myActions.insert(std::pair<std::string, webem_action_function >(std::string(idname), fun));
		}

		//Used by non basic-auth authentication (for example login forms) to bypass returning false when not authenticated
		void cWebem::RegisterWhitelistURLString(const char* idname)
		{
			std::lock_guard<std::mutex> lock(m_configMutex);
			myWhitelistURLs.push_back(idname);
		}
		void cWebem::RegisterWhitelistCommandsString(const char* idname)
		{
			std::lock_guard<std::mutex> lock(m_configMutex);
			myWhitelistCommands.push_back(idname);
		}

		// Show a Debug line with the registered functions, actions, includes, whitelist urls and commands
		void cWebem::DebugRegistrations()
		{
			std::lock_guard<std::mutex> lock(m_configMutex);
			if (m_logger) m_logger->Debug(DebugCategory::WebServer, "cWebEm Registration: %zu pages, %zu actions, %zu whitelist urls, %zu whitelist commands",
				myPages.size(), myActions.size(), myWhitelistURLs.size(), myWhitelistCommands.size());
		}

		std::istream & safeGetline(std::istream & is, std::string & line)
		{
			std::string myline;
			if (getline(is, myline))
			{
				if (!myline.empty() && myline[myline.size() - 1] == '\r')
				{
					line = myline.substr(0, myline.size() - 1);
				}
				else
				{
					line = myline;
				}
			}
			return is;
		}

		bool cWebem::ExtractPostData(request &req, const char *pContent_Type)
		{
			if (strstr(pContent_Type, "multipart/form-data") != nullptr)
			{
				// Reject excessively large uploads (100 MB max)
				constexpr size_t MAX_UPLOAD_SIZE = 100 * 1024 * 1024;
				if (req.content.size() > MAX_UPLOAD_SIZE)
				{
					if (m_logger) m_logger->Log(LogLevel::Error, "WebServer: Upload too large (%zu bytes, max %zu bytes)", req.content.size(), MAX_UPLOAD_SIZE);
					return false;
				}
				std::string szContent = req.content;
				size_t pos;
				std::string szVariable, szContentType, szValue;

				//first line is our boundary
				pos = szContent.find("\r\n");
				if (pos == std::string::npos)
					return false;
				std::string szBoundary = szContent.substr(0, pos);
				szContent = szContent.substr(pos + 2);

				while (!szContent.empty())
				{
					//Next line will contain our variable name
					pos = szContent.find("\r\n");
					if (pos == std::string::npos)
						return false;
					szVariable = szContent.substr(0, pos);
					szContent = szContent.substr(pos + 2);
					if (szVariable.find("Content-Disposition") != 0)
						return false;
					pos = szVariable.find("name=\"");
					if (pos == std::string::npos)
						return false;
					szVariable = szVariable.substr(pos + 6);
					pos = szVariable.find('"');
					if (pos == std::string::npos)
						return false;
					szVariable = szVariable.substr(0, pos);
					//Next line could be empty, or a Content-Type, if its empty, it is just a string
					pos = szContent.find("\r\n");
					if (pos == std::string::npos)
						return false;
					szContentType = szContent.substr(0, pos);
					szContent = szContent.substr(pos + 2);
					if (
						(szContentType.find("application/octet-stream") != std::string::npos) ||
						(szContentType.find("application/json") != std::string::npos) ||
						(szContentType.find("application/x-zip") != std::string::npos) ||
						(szContentType.find("application/zip") != std::string::npos) ||
						(szContentType.find("Content-Type: text/xml") != std::string::npos) ||
						(szContentType.find("Content-Type: text/x-hex") != std::string::npos) ||
						(szContentType.find("Content-Type: image/") != std::string::npos)
						)
					{
						//Its a file/stream, next line should be empty
						pos = szContent.find("\r\n");
						if (pos == std::string::npos)
							return false;
						szContent = szContent.substr(pos + 2);
					}
					else
					{
						//next line should be empty
						if (!szContentType.empty())
							return false;//dont know this one
					}
					pos = szContent.find(szBoundary);
					if (pos == std::string::npos)
						return false;
					szValue = szContent.substr(0, pos - 2);
					req.parameters.insert(std::pair< std::string, std::string >(szVariable, szValue));

					szContent = szContent.substr(pos + szBoundary.size());
					pos = szContent.find("\r\n");
					if (pos == std::string::npos)
						return false;
					szContent = szContent.substr(pos + 2);
				}
			}
			else if (strstr(pContent_Type, "application/x-www-form-urlencoded") != nullptr)
			{
				std::string params = req.content;
				std::string name;
				std::string value;

				size_t q = 0;
				size_t p = q;
				int flag_done = 0;
				const std::string& uri = params;
				while (!flag_done)
				{
					q = uri.find('=', p);
					if (q == std::string::npos)
					{
						break;
					}
					name = uri.substr(p, q - p);
					p = q + 1;
					q = uri.find('&', p);
					if (q != std::string::npos)
						value = uri.substr(p, q - p);
					else
					{
						value = uri.substr(p);
						flag_done = 1;
					}
					// the browser sends blanks as +
					while (true)
					{
						size_t p = value.find('+');
						if (p == std::string::npos)
							break;
						value.replace(p, 1, " ");
					}

					// now, url-decode only the value
					std::string decoded;
					request_handler::url_decode(value, decoded);
					req.parameters.insert(std::pair< std::string, std::string >(name, decoded));
					p = q + 1;
				}
			}
			else if ((strstr(pContent_Type, "text/plain") != nullptr) || (strstr(pContent_Type, "application/json") != nullptr) ||
				(strstr(pContent_Type, "application/xml") != nullptr))
			{
				//Raw data
				req.parameters.insert(std::pair< std::string, std::string >("data", req.content));
			}
			else
			{
				//Unknown content type
				if (m_logger) m_logger->Debug(DebugCategory::WebServer, "[web:%s] Unable to process POST Data, unknown content type: %s", GetPort().c_str(), pContent_Type);
				return false;
			}
			return true;
		}

		bool cWebem::IsAction(const request& req)
		{
			// look for cWebem form action request
			std::string uri = req.uri;
			size_t q = uri.find(".webem");
			if (q != std::string::npos && req.method == "POST")
				return true;
			return false;
		}

		/**
		Do not call from application code,
		used by server to handle form submissions.

		returns false is authentication is invalid

		*/
		bool cWebem::CheckForAction(WebEmSession & session, request& req)
		{
			// look for cWebem form action request
			if (!IsAction(req))
				return false;

			std::string uri = ExtractRequestPath(req.uri);

			// find function matching action code
			size_t q = uri.find(".webem");
			std::string code = uri.substr(1, q - 1);
			webem_action_function actionFun;
			{
				std::lock_guard<std::mutex> lock(m_configMutex);
				auto pfun = myActions.find(code);
				if (pfun == myActions.end())
					return false;
				actionFun = pfun->second;
			}

			// decode the values
			const char *pContent_Type = request::get_req_header(&req, "Content-Type");
			if (pContent_Type)
			{
				req.parameters.clear();

				bool bExtracted = ExtractPostData(req, pContent_Type);

				// parameters have been extracted, so now execute
				// we should have at least one value
				if (bExtracted && !req.parameters.empty())
				{
					// call the function
					try
					{
						actionFun(session, req, req.uri);
					}
					catch (...)
					{
						return false;
					}
					if ((req.uri[0] == '/') && (m_webRoot.length() > 0))
					{
						// possible incorrect root reference
						size_t q = req.uri.find(m_webRoot);
						if (q != 0)
						{
							std::string olduri = req.uri;
							req.uri = m_webRoot + olduri;
						}
					}
					return true;
				}
			}

			return false;
		}

		bool cWebem::DispatchPageOptions(const request& req)
		{
			std::string request_path;
			request_handler::url_decode(req.uri, request_path);
			request_path = ExtractRequestPath(request_path);

			size_t paramPos = request_path.find_first_of('?');
			if (paramPos != std::string::npos)
				request_path = request_path.substr(0, paramPos);

			std::lock_guard<std::mutex> lock(m_configMutex);
			return myPages.find(request_path) != myPages.end();
		}

		void cWebem::RegisterOptionsCode(const char *pageurl, const webem_page_function &fun)
		{
			std::lock_guard<std::mutex> lock(m_configMutex);
			myOptionsHandlers[std::string(pageurl)] = fun;
		}

		bool cWebem::IsPageOverride(const request& req, reply& rep)
		{
			std::string request_path;
			request_handler::url_decode(req.uri, request_path);
			request_path = ExtractRequestPath(request_path);

			size_t paramPos = request_path.find_first_of('?');
			if (paramPos != std::string::npos)
			{
				request_path = request_path.substr(0, paramPos);
			}

			std::lock_guard<std::mutex> lock(m_configMutex);
			auto pfun = myPages.find(request_path);
			if (pfun != myPages.end())
				return true;
			return false;
		}

		bool cWebem::CheckForPageOverride(WebEmSession & session, request& req, reply& rep)
		{
			std::string request_path;
			request_handler::url_decode(req.uri, request_path);
			request_path = ExtractRequestPath(request_path);

			req.parameters.clear();

			std::string request_path2 = req.uri; // we need the raw request string to parse the get-request
			size_t paramPos = request_path2.find_first_of('?');
			if (paramPos != std::string::npos)
			{
				std::string params = request_path2.substr(paramPos + 1);
				std::string name;
				std::string value;

				size_t q = 0;
				size_t p = q;
				int flag_done = 0;
				const std::string &uri = params;
				while (!flag_done)
				{
					q = uri.find('=', p);
					if (q == std::string::npos)
					{
						break;
					}
					name = uri.substr(p, q - p);
					p = q + 1;
					q = uri.find('&', p);
					if (q != std::string::npos)
						value = uri.substr(p, q - p);
					else
					{
						value = uri.substr(p);
						flag_done = 1;
					}
					// the browser sends blanks as +
					while (true)
					{
						size_t p = value.find('+');
						if (p == std::string::npos)
							break;
						value.replace(p, 1, " ");
					}

					// now, url-decode only the value
					std::string decoded;
					request_handler::url_decode(value, decoded);
					req.parameters.insert(std::pair< std::string, std::string >(name, decoded));
					p = q + 1;
				}
			}
			if (req.method == "POST")
			{
				const char *pContent_Type = request::get_req_header(&req, "Content-Type");
				if (pContent_Type)
				{
					// Extract the POST data into the parameters
					bool bExtracted = ExtractPostData(req, pContent_Type);
				}
			}

			// Determine the file extension.
			std::string extension;
			if (req.uri.find("/json.htm?") != std::string::npos)
			{
				extension = "json";
			}
			else
			{
				std::size_t last_slash_pos = request_path.find_last_of('/');
				std::size_t last_dot_pos = request_path.find_last_of('.');
				if (last_dot_pos != std::string::npos && last_dot_pos > last_slash_pos)
				{
					extension = request_path.substr(last_dot_pos + 1);
				}
			}
			std::string strMimeType = mime_types::extension_to_type(extension);

			webem_page_function pageFun;
			{
				std::lock_guard<std::mutex> lock(m_configMutex);
				auto pfun = myPages.find(request_path);
				if (pfun == myPages.end())
					return false;
				pageFun = pfun->second;
			}
			{
				rep.status = reply::ok;
				try
				{
					pageFun(session, req, rep);
				}
				catch (std::exception& e)
				{
					if (m_logger) m_logger->Log(LogLevel::Error, "[web:%s] PO exception occurred : '%s'", GetPort().c_str(), e.what());
				}
				catch (...)
				{
					if (m_logger) m_logger->Log(LogLevel::Error, "[web:%s] PO unknown exception occurred", GetPort().c_str());
				}
				std::string attachment;
				for (const auto &header : rep.headers)
				{
					if (boost::iequals(header.name, "Content-Disposition"))
					{
						attachment = header.value.substr(header.value.find('=') + 1);
						std::size_t last_dot_pos = attachment.find_last_of('.');
						if (last_dot_pos != std::string::npos)
						{
							extension = attachment.substr(last_dot_pos + 1);
							strMimeType = mime_types::extension_to_type(extension);
						}
						break;
					}
				}

				reply::add_header(&rep, "Content-Length", std::to_string(rep.content.size()));
				if (!boost::algorithm::starts_with(strMimeType, "image"))
				{
					reply::add_header(&rep, "Cache-Control", "no-cache");
					reply::add_header(&rep, "Pragma", "no-cache");
					ApplyCorsHeaders(rep, req);
				}
				else
				{
					reply::add_header(&rep, "Cache-Control", "max-age=3600, public");
				}
				reply::add_header_content_type(&rep, strMimeType);
				reply::add_security_headers(&rep, m_settings.is_secure());
				return true;
			}

			return false;
		}

		void cWebem::SetWebTheme(const std::string &themename)
		{
			m_actTheme = "/styles/" + themename;
		}

		void cWebem::SetWebRoot(const std::string &webRoot)
		{
			// remove trailing slash if required
			if (!webRoot.empty() && webRoot[webRoot.size() - 1] == '/')
			{
				m_webRoot = webRoot.substr(0, webRoot.size() - 1);
			}
			else
			{
				m_webRoot = webRoot;
			}
			// put slash at the front if required
			if (!m_webRoot.empty() && m_webRoot[0] != '/')
			{
				m_webRoot = "/" + webRoot;
			}
		}

		std::string cWebem::ExtractRequestPath(const std::string& original_request_path)
		{
			std::string request_path(original_request_path);
			size_t paramPos = request_path.find_first_of('?');
			if (paramPos != std::string::npos)
			{
				request_path = request_path.substr(0, paramPos);
			}

			if (request_path.find(m_webRoot + "/@login") == 0)
			{
				request_path = m_webRoot + "/";
			}

			if (!m_webRoot.empty())
			{
				// remove web root if present otherwise
				// create invalid request
				if (request_path.find(m_webRoot) == 0)
				{
					request_path = request_path.substr(m_webRoot.size());
				}
				else
				{
					request_path = "";
				}
			}

			return request_path;
		}

		bool cWebem::IsBadRequestPath(const std::string& request_path)
		{
			// Request path must be absolute, must not contain "..", and must not
			// contain control characters (including an embedded NUL from "%00",
			// which would truncate the path when passed to filesystem calls).
			if (request_path.empty() || request_path[0] != '/'
				|| request_path.find("..") != std::string::npos
				|| utils::contains_control_chars(request_path))
			{
				return true;
			}

			// don't allow access to control files
			if (request_path.find(".htpasswd") != std::string::npos)
			{
				return true;
			}

			// if we have a web root set the request must start with it
			if (!m_webRoot.empty())
			{
				if (request_path.find(m_webRoot) != 0)
				{
					return true;
				}
			}

			return false;
		}

		void cWebem::AddUserPassword(const unsigned long ID, const std::string &username, const std::string &password, const std::string &mfatoken, const std::string &passkeys, const _eUserRights userrights, const int activetabs, const std::string &privkey, const std::string &pubkey, uint32_t refreshexpire, const std::string &signingsecret, time_t accept_legacy_until)
		{
			_tWebUserPassword wtmp;
			wtmp.ID = ID;
			wtmp.Username = username;
			wtmp.Password = password;
			wtmp.Mfatoken = mfatoken;
			wtmp.Passkeys = passkeys;
			wtmp.PrivKey = privkey;
			wtmp.PubKey = pubkey;
			wtmp.userrights = userrights;
			wtmp.ActiveTabs = activetabs;
			wtmp.SigningSecret = signingsecret;
			wtmp.RefreshExpire = refreshexpire;
			wtmp.AcceptLegacyTokensUntil = accept_legacy_until;
			wtmp.TotSensors = 0;
			std::lock_guard<std::mutex> lock(m_configMutex);
			m_userpasswords.push_back(wtmp);
		}

		void cWebem::RemoveUserPassword(unsigned long ID)
		{
			std::lock_guard<std::mutex> lock(m_configMutex);
			m_userpasswords.erase(std::remove_if(m_userpasswords.begin(), m_userpasswords.end(),
				[ID](const _tWebUserPassword &u) { return u.ID == ID; }),
				m_userpasswords.end());
		}

		bool cWebem::HasConfiguredUsers() const
		{
			std::lock_guard<std::mutex> cfglock(m_configMutex);
			// URIGHTS_CLIENTID entries are not people and must not count. An
			// integrator registers OAuth2 applications and access tokens through
			// the same AddUserPassword() path as real accounts -- Domoticz seeds
			// an application for its IAM server, so m_userpasswords is non-empty
			// on a brand new installation with no human user at all. Counting
			// those would answer "is anything registered" when the question is
			// "is a login required to use this server", and would leave the
			// WebSocket demanding credentials that no one can possibly hold.
			return std::any_of(m_userpasswords.cbegin(), m_userpasswords.cend(),
					   [](const _tWebUserPassword &u) {
						   return u.userrights != URIGHTS_CLIENTID;
					   });
		}

		void cWebem::ClearUserPasswords()
		{
			{
				std::lock_guard<std::mutex> cfglock(m_configMutex);
				m_userpasswords.clear();
			}

			std::unique_lock<std::mutex> lock(m_sessionsMutex);
			m_sessions.clear(); //TODO : check if it is really necessary
		}

		constexpr std::array<uint8_t, 8> ip_bit_8_array{
			0b00000000, //
			0b10000000, //
			0b11000000, //
			0b11100000, //
			0b11110000, //
			0b11111000, //
			0b11111100, //
			0b11111110, //
		};

		/// Pure network-range membership test shared by
		/// cWebemRequestHandler::IsIPInRange (trusted-network authentication) and
		/// cWebem::IsHostInTrustedNetworks (CORS policy). `ip` must already be a
		/// validated presentation-format address (see cWebem::isValidIP).
		static bool IsIPInNetworkRange(const std::string &ip, const _tIPNetwork &ipnetwork, const bool bIsIPv6)
		{
			if (ipnetwork.bIsIPv6 != bIsIPv6)
				return false;	// No need to check when the IP address and the network are not both IPv4 or IPv6

			uint8_t IP[16] = { 0 };
			if (inet_pton((!bIsIPv6) ? AF_INET : AF_INET6, ip.c_str(), &IP) != 1)
				return false;

			// Determine if the IP address is within the network range
			int iASize = (!bIsIPv6) ? 4 : 16;
			for (int ii = 0; ii < iASize; ii++)
				if (ipnetwork.Network[ii] != (IP[ii] & ipnetwork.Mask[ii]))
					return false;

			return true;
		}

		void cWebem::AddTrustedNetworks(const std::string &network)
		{
			if (network.empty())
			{
				if (m_logger) m_logger->Log(LogLevel::Status, "[web:%s] Empty trusted network string provided! Skipping...", GetPort().c_str());
				return;
			}

			_tIPNetwork ipnetwork;
			ipnetwork.bIsIPv6 = (network.find(':') != std::string::npos);

			uint8_t iASize = (!ipnetwork.bIsIPv6) ? 4 : 16;
			int ii;

			if (m_logger) m_logger->Debug(DebugCategory::WebServer, "[web:%s] Adding IPv%s network (%s) to list of trusted networks.", GetPort().c_str(), (ipnetwork.bIsIPv6 ? "6" : "4"), network.c_str());

			if (network.find('*') != std::string::npos)
			{
				std::vector<std::string> results;
				utils::split_string(network, (!ipnetwork.bIsIPv6) ? "." : ":" , results);
				if (results.size() < 2)
					return;

				uint8_t wPos = 0;
				int wptr = 0;
				std::string szNetwork;
				while (wPos < (uint8_t)results.size())
				{
					bool bIsMask = (results[wPos] == "*");
					ipnetwork.Mask[wptr++] = (!bIsMask) ? 255 : 0;
					if (ipnetwork.bIsIPv6)
					{
						ipnetwork.Mask[wptr++] = (!bIsMask) ? 255 : 0;
					}
					if (!szNetwork.empty())
						szNetwork += (!ipnetwork.bIsIPv6) ? "." : ":";
					szNetwork += (!bIsMask) ? results[wPos] : "0";
					wPos++;
				}
				int totOctets = (!ipnetwork.bIsIPv6) ? 4 : 8;
				while (wPos < totOctets)
				{
					ipnetwork.Mask[wptr++] = 0;
					if (ipnetwork.bIsIPv6)
						ipnetwork.Mask[wptr++] = 0;
					if (!szNetwork.empty())
						szNetwork += (!ipnetwork.bIsIPv6) ? "." : ":";
					szNetwork += "0";
					wPos++;
				}
				
				if (inet_pton((!ipnetwork.bIsIPv6) ? AF_INET : AF_INET6, szNetwork.c_str(), &ipnetwork.Network) != 1)
					return; //invalid address

				//Apply mask to network address
				for (ii = 0; ii < iASize; ii++)
					ipnetwork.Network[ii] = ipnetwork.Network[ii] & ipnetwork.Mask[ii];
			}
			else
			{
				size_t pos = network.find_first_of('/');
				if (pos != std::string::npos)
				{
					std::string szNetwork = network.substr(0, pos);
					std::string szMask = network.substr(pos + 1);
					if (szNetwork.empty() || szMask.empty())
						return;

					if (inet_pton((!ipnetwork.bIsIPv6) ? AF_INET : AF_INET6, szNetwork.c_str(), &ipnetwork.Network) != 1)
						return; //invalid address

					uint8_t iBitcount = std::stoi(szMask);

					if (!ipnetwork.bIsIPv6)
					{
						if (iBitcount > 32)
							return;
					}
					else if (iBitcount > 128)
						return;

					uint8_t tot_c_bytes = iBitcount / 8;
					uint8_t tot_r_bits = iBitcount % 8;

					memset((void*)&ipnetwork.Mask, 0xFF, tot_c_bytes);
					if (tot_r_bits)
						ipnetwork.Mask[tot_c_bytes % 16] = ip_bit_8_array[tot_r_bits];

					//Apply mask to network address
					for (ii = 0; ii < iASize; ii++)
						ipnetwork.Network[ii] = ipnetwork.Network[ii] & ipnetwork.Mask[ii];
				}
				else
				{
					//Single IP or Hostname
					struct addrinfo* addr = nullptr;
					if (getaddrinfo(network.c_str(), "0", nullptr, &addr) == 0)
					{
						struct sockaddr_in* saddr = (((struct sockaddr_in*)addr->ai_addr));
						uint8_t* pAddress = nullptr;
						if (saddr->sin_family == AF_INET)
						{
							ipnetwork.bIsIPv6 = false;
							iASize = 4;
							pAddress = (uint8_t*)&saddr->sin_addr;
						}
						else if (saddr->sin_family == AF_INET6)
						{
							ipnetwork.bIsIPv6 = true;
							iASize = 16;
							struct sockaddr_in6* saddr6 = (((struct sockaddr_in6*)addr->ai_addr));
							pAddress = (uint8_t*)&saddr6->sin6_addr;
						}
						else
						{
							freeaddrinfo(addr);
							return;
						}
						memcpy(&ipnetwork.Network, pAddress, iASize);
						freeaddrinfo(addr);
					}
					else if (inet_pton((!ipnetwork.bIsIPv6) ? AF_INET : AF_INET6, network.c_str(), &ipnetwork.Network) != 1)
						return; //invalid address

					memset((void*)&ipnetwork.Mask, 0xFF, iASize);
					ipnetwork.ip_string = network;
				}
			}

			std::lock_guard<std::mutex> lock(m_configMutex);
			m_localnetworks.push_back(ipnetwork);
		}

		void cWebem::ClearTrustedNetworks()
		{
			std::lock_guard<std::mutex> lock(m_configMutex);
			m_localnetworks.clear();
		}

		bool cWebem::IsHostInTrustedNetworks(const std::string &sHost)
		{
			// Snapshot under lock: AddTrustedNetworks/ClearTrustedNetworks can mutate
			// m_localnetworks from any thread that reconfigures trusted networks
			// while requests are being handled concurrently.
			std::vector<_tIPNetwork> localnetworks;
			{
				std::lock_guard<std::mutex> lock(m_configMutex);
				localnetworks = m_localnetworks;
			}
			if (localnetworks.empty())
				return false;

			// Not a status-level log on failure here (unlike AreWeInTrustedNetwork):
			// hostname origins are perfectly normal traffic on the CORS path and
			// simply do not match, by design.
			std::string sCleanHost = sHost;
			if (!isValidIP(sCleanHost))
				return false;
			const bool bIsIPv6 = (sCleanHost.find(':') != std::string::npos);

			return std::any_of(localnetworks.begin(), localnetworks.end(),
					   [&](const _tIPNetwork &my) { return IsIPInNetworkRange(sCleanHost, my, bIsIPv6); });
		}

		bool cWebem::IsCorsOriginAllowed(const std::string &origin)
		{
			if (origin.empty())
				return false;

			std::vector<std::string> allowed;
			bool bAllowTrusted;
			{
				std::lock_guard<std::mutex> lock(m_configMutex);
				allowed = m_settings.allowed_cors_origins;
				bAllowTrusted = m_settings.cors_allow_trusted_networks;
			}

			for (const auto &entry : allowed)
			{
				// "*" is the explicit allow-any opt-out; see server_settings.
				if (entry == origin || entry == "*")
					return true;
			}
			if (bAllowTrusted)
			{
				// Only IP-literal origins can match the trusted-network ranges;
				// hostname origins are never resolved (see server_settings).
				std::string originHost = ExtractOriginHost(origin, "http://");
				if (originHost.empty())
					originHost = ExtractOriginHost(origin, "https://");
				if (!originHost.empty())
					return IsHostInTrustedNetworks(originHost);
			}
			return false;
		}

		void cWebem::ApplyCorsHeaders(reply &rep, const request &req)
		{
			const std::string origin = GetRequestOrigin(req);
			if (origin.empty())
				return;
			if (IsCorsOriginAllowed(origin))
			{
				// Route the echo through add_cors_headers so its guarantees (exact
				// origin only, never a literal "*", Vary: Origin) apply unchanged.
				reply::add_cors_headers(&rep, origin, { origin });
			}
		}

		void cWebem::SetCorsPolicy(const std::vector<std::string> &origins, const bool bAllowTrustedNetworks)
		{
			std::lock_guard<std::mutex> lock(m_configMutex);
			m_settings.allowed_cors_origins = origins;
			m_settings.cors_allow_trusted_networks = bAllowTrustedNetworks;
		}

		void cWebem::SetDigistRealm(const std::string &realm)
		{
			m_DigistRealm = realm;
		}

		void cWebem::SetZipPassword(const std::string &password)
		{
			m_zippassword = password;
		}

		void cWebem::SetSessionStore(session_store_impl_ptr sessionStore)
		{
			mySessionStore = sessionStore;
		}

		session_store_impl_ptr cWebem::GetSessionStore()
		{
			return mySessionStore;
		}

		std::string cWebem::GetPort()
		{
			return m_settings.listening_port;
		}

		std::string cWebem::GetWebRoot()
		{
			return m_webRoot;
		}

		bool cWebem::GetSession(const std::string & ssid, WebEmSession & out)
		{
			std::unique_lock<std::mutex> lock(m_sessionsMutex);
			auto itt = m_sessions.find(ssid);
			if (itt == m_sessions.end())
				return false;

			out = itt->second;
			return true;
		}

		void cWebem::AddSession(const WebEmSession & session)
		{
			std::unique_lock<std::mutex> lock(m_sessionsMutex);
			m_sessions[session.id] = session;
		}

		void cWebem::RemoveSession(const WebEmSession & session)
		{
			RemoveSession(session.id);
		}

		void cWebem::RemoveSession(const std::string & ssid)
		{
			std::unique_lock<std::mutex> lock(m_sessionsMutex);
			auto itt = m_sessions.find(ssid);
			if (itt != m_sessions.end())
				m_sessions.erase(itt);
		}

		bool cWebem::TouchSessionExpiry(const std::string &ssid, WebEmSession &out)
		{
			if (ssid.empty())
				return false;

			std::unique_lock<std::mutex> lock(m_sessionsMutex);
			auto it = m_sessions.find(ssid);
			if (it == m_sessions.end())
				return false;

			time_t now = utils::webem_time();
			bool renewed = false;
			// Short-session half-life: within SHORT_SESSION_TIMEOUT/2 (5 minutes)
			// of the current expiry, renew with a fresh SHORT_SESSION_TIMEOUT (10
			// minutes). This is what keeps a session alive under regular activity
			// -- any request in the last 5 minutes of the window pushes expiry
			// another 10 minutes out. It also catches a "remember me" (long)
			// session nearing its absolute 30-day expiry, which deliberately
			// drops it to a plain 10-minute session rather than extending
			// remember-me forever.
			if (it->second.expires - (SHORT_SESSION_TIMEOUT / 2) < now)
			{
				it->second.expires = now + SHORT_SESSION_TIMEOUT;
				renewed = true;
			}
			// Long-session half-life: only reached when the branch above did not
			// fire, i.e. expiry is not imminent. The first half of the condition
			// (expires > SHORT_SESSION_TIMEOUT + now) leaves anything close
			// enough to expiry to the short-session branch instead of double-
			// handling it here; the second half fires once a "remember me"
			// session is more than halfway through its 30-day lifetime, renewing
			// it for another full 30 days so continued activity keeps
			// remember-me alive instead of letting it decay into a short session.
			else if ((it->second.expires > SHORT_SESSION_TIMEOUT + now) && (it->second.expires - (LONG_SESSION_TIMEOUT / 2) < now))
			{
				it->second.expires = now + LONG_SESSION_TIMEOUT;
				renewed = true;
			}
			out = it->second;
			return renewed;
		}

		void cWebem::RenewSessionIfNeeded(const std::string &sessionId)
		{
			WebEmSession touched;
			if (!TouchSessionExpiry(sessionId, touched))
				return;

			if (mySessionStore != nullptr)
			{
				auto store = mySessionStore;
				time_t newExpires = touched.expires;
				boost::asio::post(m_io_context, [store, sessionId, newExpires]() {
					store->RenewSessionExpiration(sessionId, newExpires);
				});
			}
		}

		int cWebem::CountSessions()
		{
			std::unique_lock<std::mutex> lock(m_sessionsMutex);
			return (int)m_sessions.size();
		}

		std::vector<std::string> cWebem::GetExpiredSessions()
		{
			std::unique_lock<std::mutex> lock(m_sessionsMutex);
			std::vector<std::string> ret;
			time_t now = utils::webem_time();
			for (const auto &session : m_sessions)
			{
				if (session.second.expires < now)
					ret.push_back(session.second.id);
			}
			return ret;
		}

		void cWebem::CleanSessions()
		{
			if (m_logger) m_logger->Debug(DebugCategory::WebServer, "[web:%s] cleaning sessions...", GetPort().c_str());

			// Clean up timed out sessions from memory
			std::vector<std::string> expired_ssids = GetExpiredSessions();
			for (const auto &ssid : expired_ssids)
			{
				RemoveSession(ssid);
			}
			// Clean up expired sessions from database to avoid unbounded growth in long-running instances.
			if (mySessionStore != nullptr)
			{
				mySessionStore->CleanSessions();
			}
			PruneRemoteClients();
			// Schedule next cleanup
			m_session_clean_timer.expires_after(std::chrono::minutes(15));
			m_session_clean_timer.async_wait([this](auto &&) { CleanSessions(); });
		}

		// Backstop cap on m_remote_web_clients, independent of the staleness
		// pruning in PruneRemoteClients(): a trusted proxy forwarding an
		// attacker-controlled address per request (see findRealHostBehindProxies)
		// could otherwise grow the map by one entry per request. Enforced both
		// from the periodic sweep and inline from TrackRemoteClient(), so the
		// bound holds at all times rather than only right after a sweep.
		static constexpr size_t MAX_REMOTE_WEB_CLIENTS = 50000;

		void cWebem::EvictOldestRemoteClientLocked()
		{
			if (m_remote_clients_by_last_seen.empty())
				return;
			// begin() is the oldest entry precisely because the index is kept
			// ordered by last_seen (see the member declaration in cWebem.h).
			auto oldest = m_remote_clients_by_last_seen.begin();
			m_remote_web_clients.erase(oldest->second);
			m_remote_clients_by_last_seen.erase(oldest);
		}

		void cWebem::PruneRemoteClients()
		{
			std::lock_guard<std::mutex> lock(m_remoteClientsMutex);

			time_t cutoff = utils::webem_time() - SHORT_SESSION_TIMEOUT;
			for (auto it = m_remote_web_clients.begin(); it != m_remote_web_clients.end(); )
			{
				if (it->second.info.last_seen < cutoff)
				{
					m_remote_clients_by_last_seen.erase(it->second.lru_it);
					it = m_remote_web_clients.erase(it);
				}
				else
					++it;
			}

			// Staleness pruning alone doesn't bound growth within a single sweep
			// interval, so drop the oldest entries by last_seen down to the cap if
			// it is still exceeded. Using the last-seen index rather than
			// m_remote_web_clients.begin() matters: that map is keyed by
			// address+port, so its begin() is lexicographically first, not oldest,
			// and evicting by key order would let an attacker feeding descending
			// addresses evict the most recently-seen legitimate entries first.
			while (m_remote_web_clients.size() > MAX_REMOTE_WEB_CLIENTS)
				EvictOldestRemoteClientLocked();
		}

		bool cWebem::TrackRemoteClient(const std::string &remoteHost, const std::string &localPort, const std::string &requestUri)
		{
			std::string key = remoteHost + localPort;
			time_t now = utils::webem_time();

			std::lock_guard<std::mutex> lock(m_remoteClientsMutex);
			bool bSeenBefore = true;
			auto itt_rc = m_remote_web_clients.find(key);
			if (itt_rc == m_remote_web_clients.end())
			{
				// Enforce the cap here too, not just from the periodic
				// CleanSessions() sweep: behind a trusted proxy an attacker can
				// supply a distinct forged address on every request, and up to 15
				// minutes between sweeps is enough time to blow through the cap
				// and keep growing unbounded for the rest of the interval. Evicting
				// via the last-seen index (see EvictOldestRemoteClientLocked) keeps
				// this O(log n) rather than an O(n) scan of a map that can hold
				// MAX_REMOTE_WEB_CLIENTS entries, so paying this cost on every
				// request that introduces a new address stays cheap even at the cap.
				if (m_remote_web_clients.size() >= MAX_REMOTE_WEB_CLIENTS)
					EvictOldestRemoteClientLocked();

				connection::_tRemoteClients rc;
				rc.host_remote_endpoint_address_ = remoteHost;
				rc.host_local_endpoint_port_ = localPort;
				_tRemoteClientRecord rec{ rc, m_remote_clients_by_last_seen.end() };
				itt_rc = m_remote_web_clients.emplace(key, std::move(rec)).first;
				bSeenBefore = false;
			}
			else if (itt_rc->second.info.last_seen < (now - SHORT_SESSION_TIMEOUT))
				bSeenBefore = false;

			// Keep the last-seen index in sync on every touch, not just on first
			// sight: an existing entry's position has to move forward too, or the
			// index would go on reporting it as a stale eviction candidate even
			// though it was just seen again.
			if (itt_rc->second.lru_it != m_remote_clients_by_last_seen.end())
				m_remote_clients_by_last_seen.erase(itt_rc->second.lru_it);
			itt_rc->second.lru_it = m_remote_clients_by_last_seen.emplace(now, key);

			itt_rc->second.info.last_seen = now;
			itt_rc->second.info.host_last_request_uri_ = requestUri;
			return bSeenBefore;
		}

		size_t cWebem::CountRemoteClients()
		{
			std::lock_guard<std::mutex> lock(m_remoteClientsMutex);
			return m_remote_web_clients.size();
		}

		std::vector<connection::_tRemoteClients> cWebem::GetRemoteClients()
		{
			std::lock_guard<std::mutex> lock(m_remoteClientsMutex);
			std::vector<connection::_tRemoteClients> ret;
			ret.reserve(m_remote_web_clients.size());
			for (const auto &entry : m_remote_web_clients)
				ret.push_back(entry.second.info);
			return ret;
		}

		bool cWebem::isValidIP(std::string &ip)
		{
			if (ip.empty())
				return false;

			std::string cleanIP = utils::trim_whitespace(ip);
			bool bIsIPv6 = (cleanIP.find(':') != std::string::npos);
			// IPv6 and IPv4 addresses can be written as quoted strings
			if (cleanIP.front() == '"' && cleanIP.back() == '"')
			{
				cleanIP = cleanIP.substr(1,cleanIP.size()-2);	// Remove quotes from begin and end
			}
			if (bIsIPv6)
			{
				// IPv6 addresses can be written as quoted strings and between brackets (See RFC5952)
				if (cleanIP.front() == '[' && cleanIP.back() == ']')
				{
					cleanIP = cleanIP.substr(1,cleanIP.size()-2);	// Remove brackets from begin and end
				}
				// Link-local IPv6 addresses could have a 'zone-index' identifiyng which interface is used
				// on a machine which has multiple interface. Can be discarded for checking
				if ((cleanIP.find("fe80::") == 0) && (cleanIP.find('%') != std::string::npos))
				{
					cleanIP = cleanIP.substr(0,cleanIP.find('%'));
				}
			}
		#ifndef WIN32
			else
			{
				// Convert from 'IPv4 numbers-and-dots notation' to 'IPv4 dotted-decimal notation' (or sometimes called: IPv4 dotted-quad notation)
				struct in_addr addr;
				if (inet_aton(cleanIP.c_str(), &addr) != 1)
					return false;
				char str[INET_ADDRSTRLEN];
				if (inet_ntop(AF_INET, &addr, str, INET_ADDRSTRLEN) == nullptr)
					return false;
				cleanIP.assign(str);
			}
		#endif
			uint8_t uiIP[16] = { 0 };
			if (inet_pton((!bIsIPv6) ? AF_INET : AF_INET6, cleanIP.c_str(), &uiIP) == 1)
			{
				// It seems to be a valid IPv4 or IPv6, let's try to rewrite it to correct presentation format
				char str[INET6_ADDRSTRLEN];
				if (inet_ntop((!bIsIPv6) ? AF_INET : AF_INET6, &uiIP, str, INET6_ADDRSTRLEN) != nullptr)
				{
					cleanIP.assign(str);
					ip = cleanIP;
					return true;	// Valid IPv4 or IPv6 in presentation format
				}
			}

			return false;
		}

		bool cWebem::findRealHostBehindProxies(const request &req, std::string &realhost, bool &bHaveProxyHeaders)
		{
			// NOTE: every path below returns true -- there is currently no condition
			// that rejects a request outright, so the caller's 403 branch is not
			// reachable today. Both are kept deliberately: the bool contract means a
			// future rejection reason can be added here without the caller having to
			// change, and dropping it would be a fourth incompatible public-symbol
			// change on the heels of the three in the last security release.
			//
			// Checking for 3 possible headers:
			// "Forwarded"	RFC7239  (https://www.rfc-editor.org/rfc/rfc7239)
			// "X-Forwarded-For" The defacto standard header used by many web/proxy servers (https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-For)
			// "X-Real-IP"	The (old) default header used by NGINX  (http://nginx.org/en/docs/http/ngx_http_realip_module.html#real_ip_header)
			//
			// These headers can occur multiple times, so need to be 'squashed' together
			// And a single line can contain multiple (comma separated) values in order

			bHaveProxyHeaders = false;
			realhost.clear();

			// Proxy headers are ignored entirely unless a deployment has explicitly
			// named which single family its reverse proxy writes (m_settings.trusted_proxy_header_family).
			// These three headers are three independent, unauthenticated header
			// families; a real proxy populates only ONE of them, so the others
			// arrive as unmodified client data. Consulting whichever one happens to
			// be present lets the client itself choose which chain the server
			// believes -- see docs/INTEGRATION.md for the concrete bypass this
			// closes. With no family configured there is nothing safe to trust here,
			// so the peer address is used as-is.
			if (m_settings.trusted_proxy_header_family == ProxyHeaderFamily::None)
			{
				return true;
			}

			// Only the configured family's lines are ever parsed into candidate hosts
			// below; the other two are never consulted for their content, so their
			// presence on the request cannot influence the outcome.
			//
			// An earlier revision rejected any request carrying more than one family
			// outright, reasoning by analogy with two disagreeing Content-Length
			// headers. The analogy does not hold: both Content-Length values feed the
			// same framing decision, whereas a non-configured family here is simply
			// never read. The rejection therefore bought no security while breaking
			// every deployment behind a proxy that writes more than one header --
			// nginx Proxy Manager sends X-Forwarded-For and X-Real-IP together by
			// default, which made every proxied request 403 (domoticz/domoticz#6939).
			std::vector<std::string> forwardedLines;
			std::vector<std::string> xForwardedForLines;
			std::vector<std::string> xRealIpLines;
			bool haveForwarded = sumProxyHeader("forwarded", req, forwardedLines);
			bool haveXForwardedFor = sumProxyHeader("x-forwarded-for", req, xForwardedForLines);
			bool haveXRealIp = sumProxyHeader("x-real-ip", req, xRealIpLines);

			// Diagnostic only, and at Debug level: a non-configured family is remotely
			// settable, so logging it at Status would let a client drive an operator's
			// disk -- the same reason malformed-request logging sits at Debug.
			if (m_logger && ((haveForwarded ? 1 : 0) + (haveXForwardedFor ? 1 : 0) + (haveXRealIp ? 1 : 0)) > 1)
				m_logger->Debug(DebugCategory::Auth,
						"[web:%s] Request carries more than one proxy-forwarding header family; only the configured one is read",
						GetPort().c_str());

			std::vector<std::string> hosts;

			switch (m_settings.trusted_proxy_header_family)
			{
			case ProxyHeaderFamily::Forwarded:
				if (!haveForwarded)
					return true;	// configured family not present on this request -- no proxy header
				bHaveProxyHeaders = true;
				parseForwardedProxyHeader(forwardedLines, hosts);
				break;
			case ProxyHeaderFamily::XForwardedFor:
				if (!haveXForwardedFor)
					return true;
				bHaveProxyHeaders = true;
				parseProxyHeader(xForwardedForLines, hosts);
				break;
			case ProxyHeaderFamily::XRealIP:
				if (!haveXRealIp)
					return true;
				bHaveProxyHeaders = true;
				parseProxyHeader(xRealIpLines, hosts);
				break;
			default:
				return true;
			}

			if (hosts.empty())
			{
				// Proxy headers were present but nothing usable survived parsing and
				// filtering (e.g. a proxy that passes the client's header through instead
				// of appending to it, so the only entry was a forged loopback address).
				// Leave realhost empty; the caller must NOT fall back to inheriting the
				// peer's trust, or the forgery succeeds anyway.
				if (m_logger)
					m_logger->Log(LogLevel::Status,
						      "[web:%s] Proxy header present but no usable client address survived filtering; treating origin as untrusted",
						      GetPort().c_str());
				return true;
			}

			// Use the LAST entry, not the first. A proxy appends the address of whoever
			// connected to it, so the rightmost entry is the one our directly-connected
			// proxy wrote and is the only value in the chain we have any reason to
			// believe. Everything to its left is supplied by the client and is forgeable:
			// taking hosts[0] let a remote attacker send "X-Forwarded-For: 127.0.0.1" and
			// be granted trusted-network administrative access.
			realhost = hosts.back();
			return true;
		}

		bool cWebem::sumProxyHeader(const std::string &sHeader, const request &req, std::vector<std::string> &vHeaderLines)
		{
			std::string sHeaderName;
			for (const auto &header : req.headers)
			{
				sHeaderName = header.name;
				std::transform(sHeaderName.begin(), sHeaderName.end(), sHeaderName.begin(), ::tolower);
				// Exact match. This was a prefix test, which also collected unrelated
				// headers such as "X-Forwarded-For-Internal" as if they were ours.
				if (sHeaderName == sHeader)
				{
					vHeaderLines.push_back(header.value);
				}
			}

			return !vHeaderLines.empty();		// Assuming the function is called with an empty vHeaderLines to begin with
		}

		// An address that can never legitimately identify a *forwarded* client.
		//
		// A loopback or link-local address arriving as a forwarded hop is either a
		// misconfigured proxy (one that passes the client's header through instead of
		// appending to it) or an outright forgery. Believing it is what lets a remote
		// attacker claim to be 127.0.0.1 and inherit trusted-network rights.
		//
		// The caller has already run the value through isValidIP(), which normalises it
		// via inet_pton()/inet_ntop(), so exact prefix tests are reliable here.
		static bool IsNonRoutableForwardedAddress(const std::string &ip_in)
		{
			if (ip_in.empty())
				return true;

			// inet_ntop emits lowercase hex today, but normalise once rather than
			// scattering case-insensitive comparisons: a formatter or platform that
			// ever emitted uppercase must not be able to slip an address past this.
			std::string ip = ip_in;
			std::transform(ip.begin(), ip.end(), ip.begin(),
				       [](unsigned char c) { return static_cast<char>(::tolower(c)); });

			if (ip == "::1" || ip == "::" || ip == "0.0.0.0")
				return true;
			// std::string::compare(pos, n, lit) is well defined when the string is
			// shorter than n: it compares the available characters and reports a
			// mismatch, so no length pre-check is needed here.
			if (ip.compare(0, 4, "127.") == 0)			// 127.0.0.0/8, not just 127.0.0.1
				return true;
			if (ip.compare(0, 11, "::ffff:127.") == 0)		// IPv4-mapped loopback
				return true;
			if (ip.compare(0, 8, "169.254.") == 0)			// IPv4 link-local
				return true;
			if (ip.compare(0, 15, "::ffff:169.254.") == 0)
				return true;
			// IPv6 link-local fe80::/10 -> fe80: .. febf:
			if (ip.size() >= 3 && ip[0] == 'f' && ip[1] == 'e')
			{
				const char c = ip[2];
				if (c == '8' || c == '9' || c == 'a' || c == 'b')
					return true;
			}
			return false;
		}

		void cWebem::parseProxyHeader(const std::vector<std::string> &vHeaderLines, std::vector<std::string> &vHosts)
		{
			for (const auto sLine : vHeaderLines)
			{
				std::vector<std::string> vLineParts;
				utils::split_string(sLine, ",", vLineParts);
				for (std::string sPart : vLineParts)
				{
					if (isValidIP(sPart))
					{
						if (!IsNonRoutableForwardedAddress(sPart))
							vHosts.push_back(sPart);
					}
					else {
						size_t dpos = sPart.find_last_of(':');
						if (dpos != std::string::npos)
						{
							//Strip off the port number
							sPart = sPart.substr(0, dpos);
							if (isValidIP(sPart) && !IsNonRoutableForwardedAddress(sPart))
								vHosts.push_back(sPart);
						}
					}
				}
			}

		}

		void cWebem::parseForwardedProxyHeader(const std::vector<std::string> &vHeaderLines, std::vector<std::string> &vHosts)
		{
			for (const auto sLine : vHeaderLines)
			{
				std::vector<std::string> vLineParts;
				utils::split_string(sLine, ",", vLineParts);
				for (std::string sPart : vLineParts)
				{
					utils::trim_whitespace_inplace(sPart);
					// NOTE: this was previously
					//     if (std::size_t isPos = sPart.find("for=") != std::string::npos)
					// where != binds tighter than =, so isPos received the bool 0/1 rather
					// than the match offset. It only ever worked when "for=" sat at offset 0.
					std::size_t isPos = sPart.find("for=");
					if (isPos != std::string::npos)
					{
						isPos += 4;			// skip "for="
						std::size_t iePos = sPart.length();
						std::size_t semi = sPart.find(';', isPos);
						if (semi != std::string::npos)
							iePos = semi;
						std::string sSub = sPart.substr(isPos, (iePos - isPos));
						utils::trim_whitespace_inplace(sSub);
						// RFC 7239 allows the value to be quoted, and IPv6 to be bracketed
						// with an optional port: for="[2001:db8::1]:443"
						if (sSub.size() >= 2 && sSub.front() == '"' && sSub.back() == '"')
							sSub = sSub.substr(1, sSub.size() - 2);
						if (!sSub.empty() && sSub.front() == '[')
						{
							std::size_t rb = sSub.find(']');
							if (rb != std::string::npos)
								sSub = sSub.substr(1, rb - 1);
						}
						else
						{
							// Strip an IPv4 port suffix, but never split a bare IPv6 literal.
							std::size_t colon = sSub.find(':');
							if (colon != std::string::npos && sSub.find(':', colon + 1) == std::string::npos)
								sSub = sSub.substr(0, colon);
						}
						if (isValidIP(sSub) && !IsNonRoutableForwardedAddress(sSub))
							vHosts.push_back(sSub);
					}
				}
			}

		}

		bool cWebem::CheckVHost(const request &req)
		{
			// Host header, name only (port stripped) -- shared by both checks below.
			std::string sHost;
			const char *cHost = req.get_req_header(&req, "Host");
			if (cHost != nullptr)
			{
				std::string scHost(cHost);
				size_t iPos = scHost.find_first_of(":");
				if (iPos != std::string::npos)
					sHost = scHost.substr(0,iPos);
				else
					sHost = scHost;
			}

			// m_settings.allowed_hosts, when configured, validates Host on EVERY
			// request -- HTTP or HTTPS, vhostname or not -- unlike the legacy
			// vhostname check below, which only ever ran for a TLS listener. This
			// is the fix for DNS rebinding against the WebSocket trusted-network
			// same-origin check (see OriginMatchesRequestHost): that check only
			// means anything once Host itself can be trusted, and on a plain-HTTP
			// listener with no vhostname set, nothing previously validated Host at
			// all. See server_settings::allowed_hosts for the full attack and why
			// this defaults to empty (preserving old behaviour) rather than being
			// enforced unconditionally.
			if (!m_settings.allowed_hosts.empty())
			{
				if (cHost == nullptr)
				{
					if (m_logger) m_logger->Debug(DebugCategory::WebServer, "[web:%s] Rejected request: allowed_hosts is configured but Host header is missing", GetPort().c_str());
					return false;
				}
				bool bHostAllowed = false;
				for (const auto &allowed : m_settings.allowed_hosts)
				{
					if (boost::iequals(sHost, allowed))
					{
						bHostAllowed = true;
						break;
					}
				}
				if (!bHostAllowed)
				{
					if (m_logger) m_logger->Log(LogLevel::Status, "[web:%s] Rejected request: Host '%s' is not in the configured allowed_hosts list", GetPort().c_str(), sHost.c_str());
					return false;
				}
			}

			if (m_settings.vhostname.empty() || !m_settings.is_secure())	// Only do vhost checking for Secure (https) server
				return true;

			std::string vHost = m_settings.vhostname;

			// When a vhostname is given, only respond to request addressed to it
			if (cHost == nullptr)
			{
				if (m_logger) m_logger->Debug(DebugCategory::WebServer, "[web:%s] Unable to verify vhostname as Host header is missing in request!", GetPort().c_str());
				return false;
			}

			bool bStatus = (sHost.compare(vHost) == 0);
			if (m_logger) m_logger->Debug(DebugCategory::WebServer, "[web:%s] Checking vhostname (%s) with request (%s) = %d", GetPort().c_str(), vHost.c_str(), sHost.c_str(), bStatus);
			return bStatus;
		}

		bool cWebem::FindAuthenticatedUser(std::string &user, const request &req, reply &rep)
		{
			bool bStatus = myRequestHandler.CheckUserAuthorization(user, req);

			if (user.empty())
			{
				rep = reply::stock_reply(reply::unauthorized, true, m_settings.is_secure());
				ApplyCorsHeaders(rep, req);
				std::string szAuthHeader = "Basic realm=\"" + m_DigistRealm + "\"";
				reply::add_header(&rep, "WWW-Authenticate", szAuthHeader);
			}

			return bStatus;
		}

		bool cWebemRequestHandler::CheckUserAuthorization(std::string &user, const request &req)
		{
			struct ah _ah;

			if(!parse_auth_header(req, &_ah))
				return false;

			return CheckUserAuthorization(user, &_ah);
		}

		bool cWebemRequestHandler::CheckUserAuthorization(std::string &user, struct ah *ah)
		{
			// Check if valid password has been provided for the user
			std::vector<WebUserPassword> userpasswords;
			{
				std::lock_guard<std::mutex> lock(myWebem->m_configMutex);
				userpasswords = myWebem->m_userpasswords;
			}
			for (const auto &my : userpasswords)
			{
				if (my.Username == ah->user && my.userrights != URIGHTS_CLIENTID)
				{
					user = ah->user;	// At least we know it is an existing User
					if (check_password(ah, my.Password))
					{
						ah->qop = std::to_string(my.userrights);
						return true;
					}
				}
			}
			return false;
		}

		// Return 1 on success. Always initializes the ah structure.
		int cWebemRequestHandler::parse_auth_header(const request& req, struct ah *ah)
		{
			const char *auth_header;
			std::vector<WebUserPassword> userpasswords;
			{
				std::lock_guard<std::mutex> lock(myWebem->m_configMutex);
				userpasswords = myWebem->m_userpasswords;
			}

			if ((auth_header = request::get_req_header(&req, "Authorization")) == nullptr)
			{
				return 0;
			}

			// X509 Auth header
			if (boost::icontains(auth_header, "/CN="))
			{
				// DN looks like: /C=Country/ST=State/L=City/O=Org/OU=OrganizationUnit/CN=username/emailAddress=user@mail.com
				std::string dn = auth_header;
				size_t spos, epos;

				spos = dn.find("/CN=");
				epos = dn.find('/', spos + 1);
				if (spos != std::string::npos)
				{
					if (epos == std::string::npos)
					{
						epos = dn.size();
					}
					ah->user = dn.substr(spos + 4, epos - spos - 4);
				}

				spos = dn.find("/emailAddress=");
				epos = dn.find('/', spos + 1);
				if (spos != std::string::npos)
				{
					if (epos == std::string::npos)
					{
						epos = dn.size();
					}
					ah->response = dn.substr(spos + 14, epos - spos - 14);
				}

				if (ah->user.empty()) // TODO: Should ah->response be not empty ?
				{
					return 0;
				}
				ah->method = "X509";
				if (m_logger) m_logger->Debug(DebugCategory::Auth, "[X509] Found a X509 Auth Header (%s)", ah->user.c_str());
				return 1;
			}
			// Basic Auth header
			if (boost::icontains(auth_header, "Basic "))
			{
				std::string decoded = base64_decode(auth_header + 6);
				size_t npos = decoded.find(':');
				if (npos == std::string::npos)
				{
					return 0;
				}

				ah->method = "BASIC";
				ah->user = decoded.substr(0, npos);
				ah->response = decoded.substr(npos + 1);
				if (m_logger) m_logger->Debug(DebugCategory::Auth, "[Basic] Found a Basic Auth Header (%s)", ah->user.c_str());
				return 1;
			}
			// Bearer Auth header
			if (boost::icontains(auth_header, "Bearer "))
			{
				std::string sToken = auth_header + 7;

				// Might be a JWT token, find the first dot
				size_t npos = sToken.find('.');
				if (npos != std::string::npos)
				{
					// Base64decode the first piece to check
					std::string tokentype = base64url_decode(sToken.substr(0, npos));
					if(tokentype.find("JWT") != std::string::npos)
					{
						// We found the text JWT, now let's really check if it as a valid JWT Token
						//
						// jwt::decode() and the claim accessors below throw on anything they
						// don't like: wrong segment count, invalid base64url, invalid JSON,
						// missing claims read via .get_*() before checking .has_*(), etc. This
						// branch is reached before any authentication has succeeded, so an
						// unauthenticated caller fully controls sToken -- letting any of that
						// escape would unwind out of the async completion handler and take the
						// whole server thread down on a single malformed request.
						try
						{
							// Step 1: Check if the JWT has an algorithm in the header AND an issuer (iss) claim in the payload
							auto decodedJWT = jwt::decode(sToken, &base64url_decode);
							if(!decodedJWT.has_algorithm())
							{
								if (m_logger) m_logger->Debug(DebugCategory::Auth,"[JWT] Token does not contain an algorithm!");
								return 0;
							}
							if(!(decodedJWT.has_audience() && decodedJWT.has_issuer()))
							{
								if (m_logger) m_logger->Debug(DebugCategory::Auth,"[JWT] Token does not contain an intended audience and/or issuer!");
								return 0;
							}
							// Step 2: Find the audience = our ClientID (the username associated with the ClientID user right)
							// has_audience() only checks that the claim exists; "aud": [] leaves
							// it present but empty, so cbegin() == cend() and dereferencing it is
							// undefined behaviour rather than a throw -- it needs its own check,
							// the try/catch above does not cover it.
							auto audience = decodedJWT.get_audience();
							if (audience.empty())
							{
								if (m_logger) m_logger->Debug(DebugCategory::Auth,"[JWT] Token audience claim is empty!");
								return 0;
							}
							std::string clientid = *audience.cbegin();	// Only the first element of the AUD set is used; any additional audiences are ignored.
							std::string JWTsubject = decodedJWT.get_subject();
							if (m_logger) m_logger->Debug(DebugCategory::Auth,"[JWT] Token audience : %s", clientid.c_str());

							std::string signingsecret;
							std::string client_password;
							time_t accept_legacy_until = 0;
							std::string clientpubkey;
							std::string client_key_id;
							bool clientispublic = false;
							// Check if the audience has been registered as a User (type CLIENTID)
							for (const auto &my : userpasswords)
							{
								if (my.Username == clientid)
								{
									if (my.userrights == URIGHTS_CLIENTID || clientid.compare(JWTsubject) == 0)
									{
										signingsecret = my.SigningSecret;
										clientpubkey = my.PubKey;
										client_key_id = std::to_string(my.ID);
										client_password = my.Password;
										accept_legacy_until = my.AcceptLegacyTokensUntil;
										clientispublic = my.ActiveTabs;
										break;
									}
								}
							}
							if (client_key_id.empty() || (signingsecret.empty() && clientpubkey.empty()))
							{
								if (m_logger) m_logger->Debug(DebugCategory::Auth, "[JWT] Unable to verify token as no ClientID for the audience has been found!");
								return 0;
							}
							// Step 3: Using the (hashed :( ) password of the ClientID as our ClientSecret to verify the JWT signature
							std::string JWTalgo = decodedJWT.get_algorithm();

							// Bind the algorithm family the token claims to the key material actually
							// registered for this ClientID, BEFORE any verifier is constructed. The
							// check at the top of this loop only required "signingsecret OR
							// clientpubkey non-empty", so a ClientID registered asymmetrically
							// (clientispublic set, PubKey/PrivKey populated by GenerateJwtToken, no
							// SigningSecret) still passed it -- and an HS256 token was then verified
							// with jwt::algorithm::hs256{signingsecret} against an EMPTY string.
							// OpenSSL's HMAC() accepts a zero-length key and happily produces a MAC,
							// so that signature is one any attacker can compute themselves. Rejecting
							// the algorithm/key mismatch here, rather than relying on the empty-key
							// HMAC to somehow fail, is the actual fix; clientispublic (previously
							// assigned and never read) is what makes this an intended per-client
							// symmetric/asymmetric split rather than just an empty-key check.
							bool isHmacAlgo = (JWTalgo == "HS256" || JWTalgo == "HS384" || JWTalgo == "HS512");
							bool isAsymmetricAlgo = (JWTalgo == "RS256" || JWTalgo == "PS256");
							if (isHmacAlgo && (clientispublic || signingsecret.empty()))
							{
								if (m_logger) m_logger->Debug(DebugCategory::Auth, "[JWT] Client %s is not registered for symmetric (HS*) token verification!", clientid.c_str());
								return 0;
							}
							if (isAsymmetricAlgo && (!clientispublic || clientpubkey.empty()))
							{
								if (m_logger) m_logger->Debug(DebugCategory::Auth, "[JWT] Client %s is not registered for asymmetric (RS*/PS*) token verification!", clientid.c_str());
								return 0;
							}
							if (!isHmacAlgo && !isAsymmetricAlgo)
							{
								if (m_logger) m_logger->Debug(DebugCategory::Auth, "[JWT] This token is signed with an unsupported algorithm (%s)!", JWTalgo.c_str());
								return 0;
							}

							std::error_code ec;
							// Build issuer for verification. A fixed, configured issuer is
							// authoritative when set; otherwise fall back to deriving it from the
							// request's own Host header, which is attacker-controlled (a client can
							// send any Host it likes) and so verifies little beyond "the token names
							// an issuer that resembles this request's URL". Deployments that care
							// about issuer validation should set server_settings::jwt_expected_issuer.
							std::string expected_issuer = myWebem->m_DigistRealm;
							if (!myWebem->m_settings.jwt_expected_issuer.empty())
							{
								expected_issuer = myWebem->m_settings.jwt_expected_issuer;
							}
							else
							{
								const char *host_header = request::get_req_header(&req, "Host");
								if (host_header != nullptr)
								{
									expected_issuer = "https://" + std::string(host_header) + "/";
								}
							}

							// Access tokens (subject "at:<id>") are host-independent bearer tokens;
							// skip issuer validation so they work regardless of which address is used to reach the server.
							bool isAccessToken = JWTsubject.size() > 3 && JWTsubject.compare(0, 3, "at:") == 0;
							auto JWTverifyer = isAccessToken
								? jwt::verify().with_audience(clientid)
								: jwt::verify().with_issuer(expected_issuer).with_audience(clientid);
							if (JWTalgo.compare("HS256") == 0)
							{
								JWTverifyer.allow_algorithm(jwt::algorithm::hs256{ signingsecret });
							}
							else if (JWTalgo.compare("HS384") == 0)
							{
								JWTverifyer.allow_algorithm(jwt::algorithm::hs384{ signingsecret });
							}
							else if (JWTalgo.compare("HS512") == 0)
							{
								JWTverifyer.allow_algorithm(jwt::algorithm::hs512{ signingsecret });
							}
							else if (JWTalgo.compare("RS256") == 0)
							{
								JWTverifyer.allow_algorithm(jwt::algorithm::rs256{ clientpubkey });
							}
							else if (JWTalgo.compare("PS256") == 0)
							{
								JWTverifyer.allow_algorithm(jwt::algorithm::ps256{ clientpubkey });
							}
							else
							{
								if (m_logger) m_logger->Debug(DebugCategory::Auth, "[JWT] This token is signed with an unsupported algorithm (%s)!", JWTalgo.c_str());
								return 0;
							}
							JWTverifyer.expires_at_leeway(60);	// 60 seconds leeway time in case clocks are NOT fully (NTP) synced
							JWTverifyer.not_before_leeway(60);
							JWTverifyer.issued_at_leeway(60);
							JWTverifyer.verify(decodedJWT, ec);
							if(ec)
							{
								// Try legacy verification with client_password if within acceptance window
								time_t now = utils::webem_time();
								if (accept_legacy_until > 0 && now < accept_legacy_until && !client_password.empty())
								{
									if (m_logger) m_logger->Debug(DebugCategory::Auth, "[JWT] Trying legacy verification with client_password");
									std::error_code legacy_ec;
									auto LegacyVerifyer = isAccessToken
										? jwt::verify().with_audience(clientid)
										: jwt::verify().with_issuer(expected_issuer).with_audience(clientid);
									if (JWTalgo.compare("HS256") == 0)
									{
										LegacyVerifyer.allow_algorithm(jwt::algorithm::hs256{ client_password });
									}
									else if (JWTalgo.compare("HS384") == 0)
									{
										LegacyVerifyer.allow_algorithm(jwt::algorithm::hs384{ client_password });
									}
									else if (JWTalgo.compare("HS512") == 0)
									{
										LegacyVerifyer.allow_algorithm(jwt::algorithm::hs512{ client_password });
									}
									LegacyVerifyer.expires_at_leeway(60);
									LegacyVerifyer.not_before_leeway(60);
									LegacyVerifyer.issued_at_leeway(60);
									LegacyVerifyer.verify(decodedJWT, legacy_ec);
									if (!legacy_ec)
									{
										if (m_logger) m_logger->Debug(DebugCategory::Auth, "[JWT] Legacy token accepted (expires %ld)", (long)accept_legacy_until);
										ec.clear();
									}
								}
							}

							if(ec)
							{
								if (m_logger) m_logger->Debug(DebugCategory::Auth, "[JWT] Token not valid! (%s)", ec.message().c_str());
								return 0;
							}
							// Step 4: Now also check if other mandatory claims (nbf, exp, sub) have been provided
							if(!(decodedJWT.has_expires_at() && decodedJWT.has_not_before() && decodedJWT.has_issued_at() && decodedJWT.has_subject() && decodedJWT.has_key_id()))
							{
								if (m_logger) m_logger->Debug(DebugCategory::Auth, "[JWT] Mandatory claims KID, NBF, EXP, IAT, SUB are missing!");
								return 0;
							}
							// Step 5: See of the subject (intended user) is available and exists in the User table
							std::string key_id = decodedJWT.get_key_id();
							for (const auto &my : userpasswords)
							{
								if (my.Username == JWTsubject)
								{
									if (my.userrights != URIGHTS_CLIENTID)
									{
										if (key_id.compare(client_key_id) == 0)
										{
											if (m_logger) m_logger->Debug(DebugCategory::Auth,"[JWT] Decoded valid user (%s)", JWTsubject.c_str());
											ah->method = "JWT";
											ah->user = JWTsubject;
											ah->response = my.Password;
											ah->qop = std::to_string(my.userrights);		// Not really intended in original structure but works for passing the userrights
											return 1;
										}
										else
										{
											if (m_logger) m_logger->Debug(DebugCategory::Auth, "[JWT] KID does not match (%s)!", client_key_id.c_str());
											return 0;
										}
									}
								}
							}
							if (m_logger) m_logger->Debug(DebugCategory::Auth, "[JWT] Token contains non-existing user (%s)!", JWTsubject.c_str());
							return 0;
						}
						catch (const std::exception &e)
						{
							// Covers jwt::decode() (wrong segment count, bad base64url) and
							// parse_claims() (invalid JSON payload) -- both throw, and both are
							// just "not a usable token", which correctly falls through to cookie
							// authentication and, ultimately, a 401.
							//
							// Logged at Debug, not Error: a malformed token here is ordinary
							// untrusted input arriving over the network, not a server-side
							// fault. Logging it at Error would let anyone flood the error log
							// simply by sending garbage in the Authorization header. Contrast
							// with the HTTP parse exception, which reflects malformed request
							// framing rather than an application-level credential and is logged
							// at Error.
							if (m_logger) m_logger->Debug(DebugCategory::Auth, "[JWT] Token rejected: %s", e.what());
							return 0;
						}
						catch (...)
						{
							if (m_logger) m_logger->Debug(DebugCategory::Auth, "[JWT] Token rejected due to an unexpected error");
							return 0;
						}
					}
				}
				// No dot found and/or not a JWT, so assume non-JWT type of Bearer token
				ah->method = "Bearer";
				ah->user = "";				// No clue how to deduce the user from the Bearer token provided
				ah->response = sToken; // Let's provide the found token as the 'password'
				if (m_logger) m_logger->Debug(DebugCategory::Auth, "[Bearer] Found a Token (%s)", sToken.c_str());
				return 1;
			}
			return 0;
		}

		// Check the user's password, return 1 if OK
		int cWebemRequestHandler::check_password(struct ah *ah, const std::string &ha1)
		{
			if ((ah->nonce.empty()) && (!ah->response.empty()))
				return utils::ConstantTimeEquals(ha1, utils::GenerateMD5Hash(ah->response)) ? 1 : 0;

			return 0;
		}

		bool cWebem::GenerateJwtToken(std::string &jwttoken, const std::string &clientid, const std::string &user, const uint32_t exptime, const Json::Value jwtpayload, const std::string &issuer)
		{
			bool bOk = false;
			// Snapshot password list under lock before iterating
			std::vector<WebUserPassword> userpasswords;
			{
				std::lock_guard<std::mutex> lock(m_configMutex);
				userpasswords = m_userpasswords;
			}
			// Check if the clientID exists and we have a valid clientSecret for it (used when generating Tokens for registered clients)
			for (const auto &my : userpasswords)
			{
				if (my.Username == clientid)
				{
					if (my.userrights == URIGHTS_CLIENTID)	// The 'user' should have CLIENTID rights to be a real Client
					{
						// Client already validated by caller
						if (m_logger) m_logger->Debug(DebugCategory::Auth, "[JWT] Generate Token for %s using clientid %s (privKey %d)!", user.c_str(), clientid.c_str(), my.ActiveTabs);
						std::string jwt_issuer = issuer.empty() ? m_DigistRealm : issuer;
						auto JWT = jwt::create()
							.set_type("JWT")
							.set_key_id(std::to_string(my.ID))
							.set_issuer(jwt_issuer)
							.set_issued_at(std::chrono::system_clock::now())
							.set_not_before(std::chrono::system_clock::now())
							.set_expires_at(std::chrono::system_clock::now() + std::chrono::seconds{exptime})
							.set_audience(clientid)
							.set_subject(user)
							.set_id(utils::generate_uuid());
						if (!jwtpayload.empty())
						{
							for (auto const& id : jwtpayload.getMemberNames())
							{
								if(!(jwtpayload[id].isNull()))
								{
									if(jwtpayload[id].isNumeric())
									{
										double dVal(jwtpayload[id].asDouble());
										JWT.set_payload_claim(id, jwt::claim(Json::Value(dVal)));
									}
									else if(jwtpayload[id].isString())
									{
										std::string sVal(jwtpayload[id].asString());
										JWT.set_payload_claim(id, jwt::claim(Json::Value(sVal)));
									}
									else if(jwtpayload[id].isArray())
									{
										std::vector<std::string> aStrList;
										aStrList.reserve(jwtpayload[id].size());
										std::transform(jwtpayload[id].begin(), jwtpayload[id].end(), std::back_inserter(aStrList),[](const auto& s) { return s.asString(); });
										JWT.set_payload_claim(id, jwt::claim(aStrList.begin(), aStrList.end()));
									}
								}
							}
						}
						if (my.ActiveTabs)
						{
							jwttoken = JWT.sign(jwt::algorithm::ps256{"", my.PrivKey, "", ""}, &base64url_encode);
						}
						else
						{
							jwttoken = JWT.sign(jwt::algorithm::hs256{my.SigningSecret}, &base64url_encode);
						}
						bOk = true;
					}
				}
			}

			return bOk;
		}

		bool cWebemRequestHandler::IsIPInRange(const std::string &ip, const _tIPNetwork &ipnetwork, const bool &bIsIPv6)
		{
			if (!IsIPInNetworkRange(ip, ipnetwork, bIsIPv6))
				return false;

			// As all segments of the given IP fit within the given network range, otherwise we wouldn't be here
			if (m_logger) m_logger->Debug(DebugCategory::WebServer,"[web:%s] IP (%s) is within Trusted network range!",myWebem->GetPort().c_str(), ip.c_str());
			return true;
		}

		//Returns true is the connected host is in the trusted network
		bool cWebemRequestHandler::AreWeInTrustedNetwork(const std::string &sHost)
		{
			// Snapshot under lock: AddTrustedNetworks/ClearTrustedNetworks can mutate
			// m_localnetworks from any thread that reconfigures trusted networks
			// while requests are being handled concurrently.
			std::vector<_tIPNetwork> localnetworks;
			{
				std::lock_guard<std::mutex> lock(myWebem->m_configMutex);
				localnetworks = myWebem->m_localnetworks;
			}

			//Are there any local networks to check against?
			if (localnetworks.empty())
				return false;

			//Is the given 'host' a valid IP address?
			std::string sCleanHost = sHost;
			if (!cWebem::isValidIP(sCleanHost))			{
				if (m_logger) m_logger->Log(LogLevel::Status,"[web:%s] Given host (%s) is not a valid Ipv4 or IPv6 address! Unable to check if in Trusted Network!", myWebem->GetPort().c_str() ,sHost.c_str());
				return false;	// The IP address is not a valid IPv4 or IPv6 address
			}
			bool bIsIPv6 = (sCleanHost.find(':') != std::string::npos);

			return std::any_of(localnetworks.begin(), localnetworks.end(),
					   [&](const _tIPNetwork &my) { return IsIPInRange(sCleanHost, my, bIsIPv6); });
		}

		std::string cWebemRequestHandler::generateSessionID()
		{
			// Session id must not be predictable: use a cryptographically secure RNG.
			std::string sessionId = utils::GenerateSecureToken(32);
			if (sessionId.empty())
			{
				// RAND_bytes failed (should never happen); fail loudly rather than
				// falling back to a weak/predictable value.
				if (m_logger) m_logger->Log(LogLevel::Error, "[web:%s] Unable to generate a secure session id (CSPRNG failure)!", myWebem->GetPort().c_str());
				return {};
			}

			if (m_logger) m_logger->Debug(DebugCategory::WebServer, "[web:%s] generate new session id token (%s)", myWebem->GetPort().c_str(), sessionId.c_str());

			return sessionId;
		}

		std::string cWebemRequestHandler::generateAuthToken(const WebEmSession & session, const request & req)
		{
			// Authentication token must not be predictable: use a cryptographically secure RNG.
			std::string authToken = utils::GenerateSecureToken(32);
			if (authToken.empty())
			{
				if (m_logger) m_logger->Log(LogLevel::Error, "[web:%s] Unable to generate a secure authentication token (CSPRNG failure)!", myWebem->GetPort().c_str());
				return {};
			}

			if (m_logger) m_logger->Debug(DebugCategory::WebServer, "[web:%s] generate new authentication token (%s) for user (%s)", myWebem->GetPort().c_str(), authToken.c_str(), session.username.c_str());

			session_store_impl_ptr sstore = myWebem->GetSessionStore();
			if (sstore != nullptr)
			{
				WebEmStoredSession storedSession;
				storedSession.id = session.id;
				storedSession.auth_token = utils::GenerateSHA256Hash(authToken); // only save the hash to avoid a security issue if database is stolen
				storedSession.username = session.username;
				storedSession.expires = session.expires;
				storedSession.remote_host = session.remote_host; // to trace host
				storedSession.local_host = session.local_host; // to trace host
				storedSession.remote_port = session.remote_port; // to trace host
				storedSession.local_port = session.local_port; // to trace host
				sstore->StoreSession(storedSession); // only one place to do that
			}

			return authToken;
		}

		void cWebemRequestHandler::send_cookie(reply& rep, const WebEmSession & session)
		{
			const std::string& cookieName = myWebem->m_session_cookie_name;
			std::stringstream sstr;
			sstr << cookieName << "=" << session.id << "_" << session.auth_token << "." << session.expires;
			sstr << "; HttpOnly; SameSite=strict; path=/";
			// Only send the session cookie over encrypted transport when the server is TLS-enabled.
			if (myWebem->m_settings.is_secure())
				sstr << "; Secure";
			// Only set Expires for "remember me" (long-lived) sessions.
			// Short sessions use a browser session cookie (no Expires) so the browser keeps
			// sending it until it is closed, while the server enforces the actual inactivity
			// timeout independently via the session expiry check in CheckAuthentication.
			// Using session.rememberme as primary; fall back to checking the expiry duration
			// so that remember-me sessions still get a persistent cookie after a server restart
			// (when rememberme is not stored in the DB and defaults to false in memory).
			if (session.rememberme || session.expires > utils::webem_time() + SHORT_SESSION_TIMEOUT)
				sstr << "; Expires=" << utils::make_web_time(session.expires);
			reply::add_header(&rep, "Set-Cookie", sstr.str(), false);
		}

		void cWebemRequestHandler::send_remove_cookie(reply& rep)
		{
			const std::string& cookieName = myWebem->m_session_cookie_name;
			std::stringstream sstr;
			sstr << cookieName << "=none";
			// Omitting path=/ allows simultaneous logins to multiple instances on the same host.
			sstr << "; HttpOnly; SameSite=strict";
			if (myWebem->m_settings.is_secure())
				sstr << "; Secure";
			sstr << "; Expires=" << utils::make_web_time(0);
			reply::add_header(&rep, "Set-Cookie", sstr.str(), false);
		}

		bool cWebemRequestHandler::parse_cookie(const request& req, std::string& sSID, std::string& sAuthToken, std::string& szTime, bool& expired)
		{
			bool bCookie = false;
			sSID.clear();
			sAuthToken.clear();
			szTime.clear();
			expired = false;

			//Check if cookie available and still valid
			const char* cookie_header = request::get_req_header(&req, "Cookie");
			if (cookie_header != nullptr)
			{
				// Parse session id and its expiration date
				const std::string cookiePrefix = myWebem->m_session_cookie_name + "=";
				const size_t cookiePrefixLen = cookiePrefix.size();
				std::string scookie = cookie_header;
				size_t fpos = scookie.find(cookiePrefix);
				if (fpos != std::string::npos)
				{
					scookie = scookie.substr(fpos);
					fpos = 0;
					size_t epos = scookie.find(';');	// Check if there are more cookies in this Header (and ignore those)
					if (epos != std::string::npos)
					{
						scookie = scookie.substr(0, epos);
					}
					size_t upos = scookie.find('_', fpos);
					size_t ppos = scookie.find('.', upos);
					if ((fpos != std::string::npos) && (upos != std::string::npos) && (ppos != std::string::npos))
					{
						sSID = scookie.substr(fpos + cookiePrefixLen, upos - fpos - cookiePrefixLen);
						sAuthToken = scookie.substr(upos + 1, ppos - upos - 1);
						szTime = scookie.substr(ppos + 1);

						bCookie = true;
						if (m_logger) m_logger->Debug(DebugCategory::Auth, "[web:%s] Found cookie (%s) with expiration time (%s)", myWebem->GetPort().c_str(), sSID.c_str(), szTime.c_str());
					}
				}
			}
			return bCookie;
		}

		void cWebemRequestHandler::send_authorization_request(const request& req, reply& rep)
		{
			rep = reply::stock_reply(reply::unauthorized, true, myWebem->m_settings.is_secure());
			myWebem->ApplyCorsHeaders(rep, req);
			send_remove_cookie(rep);
			if (myWebem->m_authmethod == AUTH_BASIC)
			{
				std::string szAuthHeader = "Basic realm=\"" + myWebem->m_DigistRealm + "\"";
				reply::add_header(&rep, "WWW-Authenticate", szAuthHeader);
			}
		}

		bool cWebemRequestHandler::CompressWebOutput(const request& req, reply& rep)
		{
			if (myWebem->m_gzipmode != WWW_USE_GZIP)
				return false;

			std::string request_path;
			if (!url_decode(req.uri, request_path))
				return false;
			if (
				(request_path.find(".png") != std::string::npos) ||
				(request_path.find(".jpg") != std::string::npos)
				)
			{
				//don't compress 'compressed' images
				return false;
			}

			const char *encoding_header;
			//check gzip support if yes, send it back in gzip format
			if ((encoding_header = request::get_req_header(&req, "Accept-Encoding")) != nullptr)
			{
				//see if we support gzip
				bool bHaveGZipSupport = (strstr(encoding_header, "gzip") != nullptr);
				if (bHaveGZipSupport)
				{
#ifndef WEBEM_NO_GZIP
					CA2GZIP gzip((char*)rep.content.c_str(), (int)rep.content.size());
					if ((gzip.Length > 0) && (gzip.Length < (int)rep.content.size()))
					{
						rep.bIsGZIP = true; // flag for later
						rep.content.clear();
						rep.content.append((char*)gzip.pgzip, gzip.Length);
						//Set new content length
						reply::add_header(&rep, "Content-Length", std::to_string(rep.content.size()));
						//Add gzip header
						reply::add_header(&rep, "Content-Encoding", "gzip");
						return true;
					}
#endif
				}
			}
			return false;
		}

		std::string cWebemRequestHandler::compute_accept_header(const std::string &websocket_key)
		{
			// the length of an sha1 hash
			#define SHA1_LENGTH 20
			// the GUID as specified in RFC 6455
			const char *GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
			std::string combined = websocket_key + GUID;
			unsigned char sha1result[SHA1_LENGTH];
			sha1::calc((void *)combined.c_str(), combined.length(), sha1result);
			std::string accept = base64_encode_buf(sha1result, SHA1_LENGTH);
			return accept;
		}

		bool cWebemRequestHandler::is_upgrade_request(WebEmSession & session, const request& req, reply& rep)
		{
			// request method should be GET
			if (req.method != "GET")
			{
				return false;
			}
			// http version should be 1.1 at least
			if (((req.http_version_major * 10) + req.http_version_minor) < 11)
			{
				return false;
			}
			const char *h;
			// client MUST include Connection: Upgrade header
			h = request::get_req_header(&req, "Connection");
			if (!h)
			{
				return false;
			}

			// client MUST include Upgrade: websocket
			h = request::get_req_header(&req, "Upgrade");
			if (!h)
			{
				return false;
			}

			std::string upgrade_header = h;
			if (!boost::iequals(upgrade_header, "websocket"))
			{
				return false;
			};

			// Find matching endpoint by request path
			std::string req_path = myWebem->ExtractRequestPath(req.uri);
			WebsocketHandlerFactory ws_factory = myWebem->GetWebsocketFactory(req_path);
			if (!ws_factory)
			{
				rep = reply::stock_reply(reply::not_found);
				return true;
			}
			h = request::get_req_header(&req, "Host");
			// request MUST include a host header, even if we don't check it
			if (h == nullptr)
			{
				rep = reply::stock_reply(reply::forbidden);
				return true;
			}
			// request MUST include an origin header; we only "allow" connections from
			// browser clients
			h = request::get_req_header(&req, "Origin");
			if (h == nullptr)
			{
				rep = reply::stock_reply(reply::bad_request);
				return true;
			}
			{
				std::string origin = h;
				// Enforced for every upgrade that is not carrying a session cookie.
				//
				// Two such cases exist, and both need this for the same reason: a
				// trusted-network session (see CheckAuthentication, called before
				// is_upgrade_request), and -- when no users are configured at all --
				// a plain unauthenticated one. Neither presents a cookie, so there
				// is nothing here for SameSite=strict to protect, and WebSocket is
				// not subject to CORS: without this check ANY website the browser
				// visits could open this WebSocket and read or drive the server with
				// whatever rights it grants (docs/INTEGRATION.md, "Trusted
				// Networks"). That a foreign page cannot READ a cross-origin HTTP
				// response is no help here -- the same-origin policy simply does not
				// apply to this handshake.
				//
				// Cookie-authenticated sessions do not need it: SameSite=strict
				// already stops a foreign site's browser attaching that cookie.
				if (session.istrustednetwork || session.username.empty())
				{
					bool originAllowed = OriginMatchesRequestHost(req, origin, myWebem->m_settings.is_secure(), myWebem->m_settings);
					if (!originAllowed)
					{
						// Same policy as the HTTP CORS headers (explicit list, "*"
						// opt-out, optional trusted-network origins): an origin
						// allowed to read the API cross-origin is equally allowed
						// to open this WebSocket.
						originAllowed = myWebem->IsCorsOriginAllowed(origin);
					}
					if (!originAllowed)
					{
						if (m_logger) m_logger->Log(LogLevel::Status, "[web:%s] Rejected WebSocket upgrade: Origin '%s' is not allowed for a %s session", myWebem->GetPort().c_str(), origin.c_str(),
									    session.istrustednetwork ? "trusted-network" : "cookie-less");
						rep = reply::stock_reply(reply::forbidden);
						return true;
					}
				}
			}
			// request MUST include a version number
			h = request::get_req_header(&req, "Sec-Websocket-Version");
			if (h == nullptr)
			{
				rep = reply::stock_reply(reply::bad_request);
				return true;
			}
			else
			{
				int version = atoi(h);
				// we support versions 13 (and higher)
				if (version < 13)
				{
					rep = reply::stock_reply(reply::bad_request);
					return true;
				}
			}

			h = request::get_req_header(&req, "Sec-Websocket-Protocol");
			// check sub-protocol if the endpoint requires one
			std::string expected_protocol = myWebem->GetWebsocketProtocol(req_path);
			if (!expected_protocol.empty())
			{
				if (!h || std::string(h).find(expected_protocol) == std::string::npos)
				{
					rep = reply::stock_reply(reply::bad_request);
					return true;
				}
			}
			h = request::get_req_header(&req, "Sec-Websocket-Key");
			// request MUST include a sec-websocket-key header and we need to respond to it
			if (h == nullptr)
			{
				rep = reply::stock_reply(reply::bad_request);
				return true;
			}
			std::string websocket_key = h;
			rep = reply::stock_reply(reply::switching_protocols);
			reply::add_header(&rep, "Connection", "Upgrade");
			reply::add_header(&rep, "Upgrade", "websocket");

			std::string accept = compute_accept_header(websocket_key);
			if (accept.empty())
			{
				rep = reply::stock_reply(reply::internal_server_error);
				return true;
			}
			reply::add_header(&rep, "Sec-Websocket-Accept", accept);
			// echo the sub-protocol that the endpoint expects
			if (!expected_protocol.empty())
			{
				reply::add_header(&rep, "Sec-Websocket-Protocol", expected_protocol);
			}
			// Carry the authenticated session to connection.cpp so the factory receives it
			// directly without any cookie re-parsing.
			rep.ws_session = session;
			return true;
		}

		static bool GetURICommandParameter(const std::string &uri, std::string &cmdparam)
		{
			if (uri.find("type=command") == std::string::npos)
				return false;
			size_t ppos1 = uri.find("&param=");
			size_t ppos2 = uri.find("?param=");
			if (
				(ppos1 == std::string::npos) &&
				(ppos2 == std::string::npos)
				)
				return false;
			cmdparam = uri;
			size_t ppos = ppos1;
			if (ppos == std::string::npos)
				ppos = ppos2;
			else
			{
				if ((ppos2 < ppos) && (ppos != std::string::npos))
					ppos = ppos2;
			}
			cmdparam = uri.substr(ppos + 7);
			ppos = cmdparam.find('&');
			if (ppos != std::string::npos)
			{
				cmdparam = cmdparam.substr(0, ppos);
			}
			return true;
		}

		bool cWebemRequestHandler::CheckAuthByPass(const request& req)
		{
			//Check if we need to bypass authentication for this request (URL or command)
			std::vector<std::string> whitelistURLs;
			std::vector<std::string> whitelistCommands;
			{
				std::lock_guard<std::mutex> lock(myWebem->m_configMutex);
				whitelistURLs = myWebem->myWhitelistURLs;
				whitelistCommands = myWebem->myWhitelistCommands;
			}
			for (const auto &url : whitelistURLs)
				if (req.uri.find(url) == 0)
					return true;

			std::string cmdparam;
			if (GetURICommandParameter(req.uri, cmdparam))
			{
				for (const auto &cmd : whitelistCommands)
					if (cmdparam == cmd)
						return true;
			}

			return false;
		}

		bool cWebemRequestHandler::AllowBasicAuth()
		{
			if (myWebem->m_settings.is_secure())		// Basic Auth is allowed when used over HTTPS (SSL Encrypted communication)
				return true;
			else if (myWebem->m_AllowPlainBasicAuth)	// Allow Basic Auth over non HTTPS
				return true;

			return false;
		}

		bool cWebemRequestHandler::CheckAuthentication(WebEmSession &session, const request &req, bool &authErr,
							      bool bTrustedNetworkAllowed)
		{
			session.rights = URIGHTS_NONE; // no rights
			session.id = "";
			session.username = "";
			session.auth_token = "";
			session.istrustednetwork = false;

			// Snapshot the user password list under lock to avoid races with AddUserPassword/ClearUserPasswords
			std::vector<WebUserPassword> userpasswords;
			{
				std::lock_guard<std::mutex> lock(myWebem->m_configMutex);
				userpasswords = myWebem->m_userpasswords;
			}

			if (userpasswords.empty())
			{
				if (m_logger) m_logger->Log(LogLevel::Error, "[Auth Check] No (active) users in the system! There should be at least 1 active Admin user! Please add an Admin user to the system!");
				authErr = true;
				return false; // No users in the system!
			}
			else if (bTrustedNetworkAllowed && AreWeInTrustedNetwork(session.remote_host))
			{
				for (const auto &my : userpasswords)
				{
					if (my.userrights == URIGHTS_ADMIN) // we found an admin
					{
						session.username = my.Username;
						session.rights = my.userrights;
						break;
					}
				}
				if (session.rights == URIGHTS_NONE)
				{
					if (m_logger) m_logger->Log(LogLevel::Status, "[Auth Check] Trusted network exception detected, but no Admin User found! Please add an Admin user to the system!");
					//If the User database table is without an Admin, we will create a temporary Admin user (we are in trusted network anyway)
					session.username = "tmp_admin";
					session.rights = URIGHTS_ADMIN;
				}
				session.istrustednetwork = true;
			}

			//Check for valid Authorization headers (JWT Token, Basis Authentication, etc.) and use these offered credentials
			struct ah _ah;
			if (parse_auth_header(req, &_ah))
			{
				if (_ah.method == "JWT")
				{
					if (m_logger) m_logger->Debug(DebugCategory::Auth, "[Auth Check] Found JWT Authorization token: Method %s, Userdata %s, rights %s", _ah.method.c_str(), _ah.user.c_str(), _ah.qop.c_str());
					session.isnew = false;
					session.rememberme = false;
					session.username = _ah.user;
					session.rights = static_cast<_eUserRights>(std::atoi(_ah.qop.c_str()));
					return true;
				}
				else if (_ah.method == "BASIC")
				{
					// OAuth2 endpoints handle their own client authentication, don't validate as user here
					if (req.uri.find("/oauth2/") != std::string::npos)
					{
						if (m_logger) m_logger->Debug(DebugCategory::Auth, "[Auth Check] Basic Authorization header found for OAuth2 endpoint, will be validated by OAuth2 handler");
						// Don't set session, let OAuth2 code handle it
					}
					else if (req.uri.find("/json.htm?") != std::string::npos)	// Exception for the main API endpoint so scripts can execute them with 'just' Basic AUTH
					{
						if (AllowBasicAuth())	// Check if Basic Auth is allowed either over HTTPS or when explicitly enabled
						{
							if (CheckUserAuthorization(_ah.user, &_ah))
							{
								if (m_logger) m_logger->Debug(DebugCategory::Auth, "[Auth Check] Found Basic Authorization for API call: Method %s, Userdata %s, rights %s", _ah.method.c_str(), _ah.user.c_str(), _ah.qop.c_str());
								session.isnew = false;
								session.rememberme = false;
								session.username = _ah.user;
								session.rights = static_cast<_eUserRights>(std::atoi(_ah.qop.c_str()));
								return true;
							}
							else
							{	// Clear the session as we could be in a Trusted Network BUT have invalid Basic Auth
								if (m_logger) m_logger->Log(LogLevel::Error, "Failed login attempt from %s for user '%s' (API)", session.remote_host.c_str(), _ah.user.c_str());
								session.username = "";
								session.rights = URIGHTS_NONE;
								return false;
							}
						}
						else
						{	// Clear the session as we could be in a Trusted Network BUT rejected Basic Auth
							if (m_logger) m_logger->Debug(DebugCategory::Auth, "[Auth Check] Basic Authorization rejected as it is not done over HTTPS or not explicitly allowed over HTTP!");
							session.username = "";
							session.rights = URIGHTS_NONE;
							return false;
						}
					}
					else
					{
						if (m_logger) m_logger->Debug(DebugCategory::Auth, "[Auth Check] Basic Authorization ignored as this is not a call to the API!");
					}
				}
			}

			//Check if cookie available and still valid
			std::string sSID;
			std::string sAuthToken;
			std::string szTime;
			bool expired = false;
			if(parse_cookie(req, sSID, sAuthToken, szTime, expired))
			{
				if (!(sSID.empty() || sAuthToken.empty() || szTime.empty()))
				{
					time_t now = utils::webem_time();
					WebEmSession oldSession;
					bool haveOldSession = myWebem->GetSession(sSID, oldSession);
					if (haveOldSession && (oldSession.expires < now))
					{
						// Check if session stored in memory is not expired (prevent from spoofing expiration time)
						expired = true;
					}
					if (expired)
					{
						//expired session, remove session
						if (haveOldSession)
						{
							// session exists (delete it from memory and database)
							myWebem->RemoveSession(sSID);
							removeAuthToken(sSID);
						}
						return false;
					}
					if (haveOldSession)
					{
						// session already exists
						session = oldSession;
					}
					else
					{
						// Session does not exists
						session.id = sSID;
					}
					session.auth_token = sAuthToken;
					// Check authen_token and restore session
					if (checkAuthToken(session))
					{
						// user is authenticated
						return true;
					}
				}
			}
			else	// No session cookie found
				session.isnew = true;

			if (session.istrustednetwork)
				return true;

			return false;
		}

		/**
		 * Check authentication token if exists and restore the user session if necessary
		 */
		bool cWebemRequestHandler::checkAuthToken(WebEmSession & session)
		{
			session_store_impl_ptr sstore = myWebem->GetSessionStore();
			if (sstore == nullptr)
			{
				// Fail closed: without a session store we cannot verify the token,
				// so the request must NOT be treated as authenticated.
				if (m_logger) m_logger->Log(LogLevel::Error, "CheckAuthToken(%s_%s) : no store defined, rejecting", session.id.c_str(), session.auth_token.c_str());
				return false;
			}

			if (session.id.empty() || session.auth_token.empty())
			{
				if (m_logger) m_logger->Log(LogLevel::Error, "CheckAuthToken(%s_%s) : session id or auth token is empty", session.id.c_str(), session.auth_token.c_str());
				return false;
			}
			WebEmStoredSession storedSession = sstore->GetSession(session.id);
			if (storedSession.id.empty())
			{
				if (m_logger) m_logger->Debug(DebugCategory::Auth, "[web:%s] CheckAuthToken(%s_%s) : session id not found", myWebem->GetPort().c_str(), session.id.c_str(), session.auth_token.c_str());
				return false;
			}
			if (!utils::ConstantTimeEquals(storedSession.auth_token, utils::GenerateSHA256Hash(session.auth_token)))
			{
				if (m_logger) m_logger->Log(LogLevel::Error, "CheckAuthToken(%s_%s) : auth token mismatch", session.id.c_str(), session.auth_token.c_str());
				removeAuthToken(session.id);
				return false;
			}

			if (m_logger) m_logger->Debug(DebugCategory::Auth, "[web:%s] CheckAuthToken(%s_%s_%s) : Session found & Token authenticated", myWebem->GetPort().c_str(), session.id.c_str(), session.auth_token.c_str(), session.username.c_str());

			if (session.username.empty())
			{
				// Restore session if user exists and session does not already exist
				bool userExists = false;
				bool sessionExpires = false;
				session.username = storedSession.username;
				session.expires = storedSession.expires;
				std::vector<WebUserPassword> userpasswords;
				{
					std::lock_guard<std::mutex> lock(myWebem->m_configMutex);
					userpasswords = myWebem->m_userpasswords;
				}
				for (const auto &my : userpasswords)
				{
					if (my.Username == session.username) // the user still exists
					{
						userExists = true;
						session.rights = my.userrights;
						break;
					}
				}

				time_t now = utils::webem_time();
				sessionExpires = session.expires < now;

				if (!userExists || sessionExpires)
				{
					if (m_logger) m_logger->Debug(DebugCategory::Auth, "[web:%s] CheckAuthToken(%s_%s) : cannot restore session, user not found or session expired (%d)", myWebem->GetPort().c_str(), session.id.c_str(), session.auth_token.c_str(), sessionExpires);
					removeAuthToken(session.id);
					return false;
				}

				WebEmSession existingSession;
				if (!myWebem->GetSession(session.id, existingSession))
				{
					if (m_logger) m_logger->Debug(DebugCategory::Auth, "[web:%s] CheckAuthToken(%s_%s_%s) : restore session", myWebem->GetPort().c_str(), session.id.c_str(), session.auth_token.c_str(), session.username.c_str());
					myWebem->AddSession(session);
				}
			}

			return true;
		}

		void cWebemRequestHandler::removeAuthToken(const std::string & sessionId)
		{
			session_store_impl_ptr sstore = myWebem->GetSessionStore();
			if (sstore != nullptr)
			{
				sstore->RemoveSession(sessionId);
			}
		}

		char *cWebemRequestHandler::strftime_t(const char *format, const time_t rawtime)
		{
			static thread_local char buffer[1024];
			struct tm ltime;
			utils::safe_localtime(&rawtime, &ltime);
			strftime(buffer, sizeof(buffer), format, &ltime);
			return buffer;
		}

		void cWebemRequestHandler::handle_request(const request& req, reply& rep)
		{
			// 0) If extended Webserver debugging is turned on, than log the request details
			if (m_logger) m_logger->Debug(DebugCategory::WebServer, "[web:%s] Host:%s Uri:%s", myWebem->GetPort().c_str(), req.host_remote_address.c_str(), req.uri.c_str());
			if (m_logger) {
				std::string sHeaders;
				for (const auto &header : req.headers)
				{
					sHeaders += header.name + ": " + header.value + "\n";
				}
				m_logger->Debug(DebugCategory::WebServer, "[web:%s] Request Headers:\n%s", myWebem->GetPort().c_str(), sHeaders.c_str());
			}

			// 1) Is the incoming request ment for this Virtual Host?
			if(!myWebem->CheckVHost(req))
			{
				rep = reply::stock_reply(reply::bad_request);
				return;
			}

			// 2) Decode url to path and check for invalid characters
			std::string request_path;
			if (!request_handler::url_decode(req.uri, request_path))
			{
				rep = reply::stock_reply(reply::bad_request);
				return;
			}

			// Initialize session
			WebEmSession session;
			session.remote_host = req.host_remote_address;
			session.remote_port = req.host_remote_port;
			session.local_host = req.host_local_address;
			session.local_port = req.host_local_port;

			rep.status = reply::ok;
			rep.bIsGZIP = false;

			// 3a) Let's examine possible proxies, etc.
			std::string realHost;
			bool bUseRealHost = false;
			bool bHaveProxyHeaders = false;
			bool bTrustedNetworkAllowed = true;
			if(!myWebem->findRealHostBehindProxies(req, realHost, bHaveProxyHeaders))
			{
				if (m_logger) m_logger->Log(LogLevel::Error, "[web:%s]: Unable to determine origin due to improper proxy header(s) (values) being used (Possible spoofing attempt!?), dropping client request (remote address: %s)", myWebem->GetPort().c_str(), session.remote_host.c_str());
				rep = reply::stock_reply(reply::forbidden);
				return;
			}
			else if (realHost.empty() && bHaveProxyHeaders)
			{
				// Proxy headers were present but nothing usable survived filtering. Do not
				// let the request keep the trust that the connecting peer's own address
				// would confer: behind a proxy on a trusted address (commonly 127.0.0.1)
				// that would hand administrative rights to whoever sent the bad header.
				bTrustedNetworkAllowed = false;
			}
			else if (!realHost.empty())
			{
				if (AreWeInTrustedNetwork(session.remote_host))
				{	// 3b) We only use Proxy header information if the connection comes from a Trusted network
					session.remote_host = realHost;		// replace the host of the connection with the originating host behind the proxies
					rep.originHost = realHost;
					bUseRealHost = true;
				}
			}

			// 3c) Check if the remote client is known and update the last seen time.
			// TrackRemoteClient owns the locking: this cache used to be a process-wide
			// global with no synchronisation at all, corrupted by an HTTP and an HTTPS
			// instance (each with its own io thread) doing unsynchronised find/insert
			// on the same map concurrently.
			bool bSeenBefore = myWebem->TrackRemoteClient(session.remote_host, session.local_port, req.uri);

			// 4) Respond to CORS Preflight request (for JSON API)
			if (req.method == "OPTIONS")
			{
				// If the endpoint has a custom OPTIONS handler, call it (e.g. MCP needs extra headers).
				{
					std::string opts_path = request_path;
					size_t paramPos = opts_path.find_first_of('?');
					if (paramPos != std::string::npos)
						opts_path = opts_path.substr(0, paramPos);
					std::lock_guard<std::mutex> lock(myWebem->m_configMutex);
					auto it = myWebem->myOptionsHandlers.find(opts_path);
					if (it != myWebem->myOptionsHandlers.end())
					{
						it->second(session, req, rep);
						return;
					}
				}
				// Check if a registered page handler exists for this preflight path.
				// Handlers are not invoked — just existence is checked so the caller
				// can return 200 + CORS headers without executing API logic.
				if (myWebem->DispatchPageOptions(req))
				{
					reply::add_header(&rep, "Content-Length", "0");
					reply::add_header(&rep, "Access-Control-Max-Age", "3600");
					myWebem->ApplyCorsHeaders(rep, req);
					reply::add_header_if_absent(&rep, "Access-Control-Allow-Methods", "GET, POST");
					reply::add_header_if_absent(&rep, "Access-Control-Allow-Headers", "Authorization, Content-Type");
					return;
				}
				reply::add_header(&rep, "Content-Length", "0");
				reply::add_header(&rep, "Content-Type", "text/plain");
				reply::add_header(&rep, "Access-Control-Max-Age", "3600");
				reply::add_header(&rep, "Access-Control-Allow-Methods", "GET, POST");
				reply::add_header(&rep, "Access-Control-Allow-Headers", "Authorization, Content-Type");
				myWebem->ApplyCorsHeaders(rep, req);
				return;
			}

			// 5) Check Authentication and in case something unexpected went wrong with the authentication, we will return an internal server error and stop processing
			bool bAuthErr = false;
			bool isAuthenticated = CheckAuthentication(session, req, bAuthErr, bTrustedNetworkAllowed);	// This check also restores the session if an active session is found
			if (bAuthErr)
			{
				rep = reply::stock_reply(reply::internal_server_error);
				return;
			}

			// 6) Check the type of request. Is it a page (or an action) or is it 'just' a normal resources being requested
			bool isPage = myWebem->IsPageOverride(req, rep);
			bool isAction = myWebem->IsAction(req);		// This is used but will be removed in the future and replaced by the JSON API commands

			bool isAPI = (isPage && (req.uri.find("/json.htm?") != std::string::npos));
			bool isLogout = (isAPI && (req.uri.find("param=dologout") != std::string::npos));
			bool isLogin = (isAPI && (req.uri.find("param=logincheck") != std::string::npos || req.uri.find("param=passkeylogin-complete") != std::string::npos));

			// 7) If the LogOut API is called, we will remove the session and the cookie
			if (isLogout)
			{
				if (m_logger) m_logger->Debug(DebugCategory::Auth, "[web:%s] Logout : Logging out User %s (%d)", myWebem->GetPort().c_str(), session.username.c_str(), session.rights);

				rep = reply::stock_reply(reply::no_content);
				if(bUseRealHost)
					rep.originHost = realHost;

				//Remove session id based on id found before in cookie
				std::string sSID = session.id;
				if(!sSID.empty())
				{
					if (m_logger) m_logger->Debug(DebugCategory::Auth, "[web:%s] Logout : remove session %s", myWebem->GetPort().c_str(), sSID.c_str());
					myWebem->RemoveSession(sSID);
					removeAuthToken(sSID);
					send_remove_cookie(rep);
				}
				return;
			}

			// 8) Check if this is an upgrade request to a websocket connection
			bool isUpgradeRequest = is_upgrade_request(session, req, rep);

			// 9) Check if the request needs to be authenticated, for pages (and actions) and WebSocket upgrades
			bool needsAuthentication = ((isPage || isUpgradeRequest) ? !CheckAuthByPass(req) : false);

			// An application with no users configured has no authentication to
			// enforce: every page and command is already served to anyone who
			// asks, so demanding credentials for the WebSocket upgrade alone
			// would not protect anything -- an attacker simply uses HTTP instead
			// -- while breaking live updates on an unprotected installation.
			//
			// The same-origin requirement below is NOT relaxed with it, and that
			// distinction matters: WebSocket is not subject to CORS. A browser
			// refuses to let a foreign page READ a cross-origin HTTP response,
			// but places no such restriction on a WebSocket, so an unauthenticated
			// upgrade is reachable from any site the user happens to visit in a
			// way an unauthenticated fetch is not. is_upgrade_request() therefore
			// still requires an Origin that matches this host (see the check in
			// that function).
			if (isUpgradeRequest && needsAuthentication)
			{
				if (myWebem->HasConfiguredUsers())
				{
					// Users exist: authentication is in force, upgrade included.
				}
				else
				{
					if (m_logger) m_logger->Debug(DebugCategory::Auth,
						"[web:%s] No users configured; allowing unauthenticated WebSocket upgrade (origin still enforced)",
						myWebem->GetPort().c_str());
					needsAuthentication = false;
				}
			}

			if (m_logger) m_logger->Debug(DebugCategory::Auth,"[web:%s] isPage %d isAction %d isUpgrade %d needsAuthentication %d isAuthenticated %d (%s) isNew %d", myWebem->GetPort().c_str(), isPage, isAction, isUpgradeRequest, needsAuthentication, isAuthenticated, session.username.c_str(), session.isnew);

			// 10) Check if the request has proper user authentication for those pages (or actions) that require it. If not, send an Authorization request
			if ((isPage || isAction || isUpgradeRequest) && needsAuthentication && !isAuthenticated)
			{
				if (m_logger) m_logger->Debug(DebugCategory::WebServer, "[web:%s] Did not find suitable Authorization!", myWebem->GetPort().c_str());
				send_authorization_request(req, rep);
				if(bUseRealHost)
					rep.originHost = realHost;
				return;
			}

			// 11) If this is an upgrade request, we are done
			if (isUpgradeRequest)	// And authorized, which has been checked above
			{
				return;
			}

			// Copy the request to be able to fill its parameters attribute
			request requestCopy = req;

			// 12a) Run action if exists. NOTE: This is used but will be removed in the future and replaced by the JSON API commands.
			bool bHandledAction = false;
			if (isAction)
			{
				// Post actions only allowed when authenticated and user has admin rights
				if (session.rights != URIGHTS_ADMIN)
				{
					rep = reply::stock_reply(reply::forbidden);
					return;
				}
				bHandledAction = myWebem->CheckForAction(session, requestCopy);
				if (bHandledAction && !requestCopy.uri.empty())
				{
					if ((requestCopy.method == "POST") && (requestCopy.uri[0] != '/'))
					{
						//Send back as data instead of a redirect uri
						rep.status = reply::ok;
						rep.content = requestCopy.uri;
						reply::add_header(&rep, "Content-Length", std::to_string(rep.content.size()));
						reply::add_header(&rep, "Last-Modified", utils::make_web_time(utils::webem_time()), true);
						reply::add_header_content_type(&rep, "application/json");
						return;
					}
				}
			}

			// 12b) If it wasn't an action (removed soon), it is either a page or a resource request
			if (!bHandledAction)
			{
				if (myWebem->CheckForPageOverride(session, requestCopy, rep))
				{
					if (rep.status == reply::status_type::download_file)
						return;

					if (!rep.bIsGZIP)
					{
						CompressWebOutput(req, rep);
					}
				}
				else
				{
					// 11c) do normal handling
					modify_info mInfo;
					try
					{
						if (myWebem->m_actTheme.find("default") == std::string::npos)
						{
							// MOTE: A theme is being used (not default) so some theme specific processing might be neccessary
							std::string uri = myWebem->ExtractRequestPath(requestCopy.uri);
							if (uri.find("/images/") == 0)
							{
								std::string theme_images_path = myWebem->m_actTheme + uri;
								if (utils::file_exists((doc_root_ + theme_images_path).c_str()))
								{
									requestCopy.uri = myWebem->GetWebRoot() + theme_images_path;
									if (m_logger) m_logger->Debug(DebugCategory::WebServer, "[web:%s] modified images request to (%s).", uri.c_str(), requestCopy.uri.c_str());
								}
							}
							else if (uri.find("/styles/") == 0)
							{
								std::string theme_styles_path = myWebem->m_actTheme + uri.substr(15);
								if (utils::file_exists((doc_root_ + theme_styles_path).c_str()))
								{
									requestCopy.uri = myWebem->GetWebRoot() + theme_styles_path;
									if (m_logger) m_logger->Debug(DebugCategory::WebServer, "[web:%s] modified request to (%s).", uri.c_str(), requestCopy.uri.c_str());
								}
							}
						}

						request_handler::handle_request(requestCopy, rep, mInfo);
					}
					catch (...)
					{
						rep = reply::stock_reply(reply::internal_server_error);
						return;
					}
				}
			}

			// 13) Check if we have seen the client before (recently), if not, log it for security purposes
			if (!bSeenBefore)
				if (m_logger) m_logger->Log(LogLevel::Status, "[web:%s] Incoming connection from: %s", myWebem->GetPort().c_str(), session.remote_host.c_str());

			// 14) We handled the request, now we need to check if we need to create a new session or renew the existing one

			if (session.isnew == true && session.istrustednetwork == false)	// No session found and if we need a session (not for API calls or Trusted Network), create a new one
			{
				if (isLogin && !session.username.empty())	// Make sure the login was succesfull
				{
					// Create a new session ID
					session.id = generateSessionID();
					if (session.id.empty())
					{
						// CSPRNG failure: never create a half-initialized session
						rep = reply::stock_reply(reply::internal_server_error);
						return;
					}
					session.expires = utils::webem_time() + SHORT_SESSION_TIMEOUT;
					if (session.rememberme)
					{
						// Extend session by 30 days
						session.expires += LONG_SESSION_TIMEOUT;
					}
					session.auth_token = generateAuthToken(session, req); // do it after expires to save it also
					if (session.auth_token.empty())
					{
						// CSPRNG failure: abort the login rather than issue an empty token
						rep = reply::stock_reply(reply::internal_server_error);
						return;
					}
					session.isnew = false;
					myWebem->AddSession(session);
					send_cookie(rep, session);
				}
			}
			else if (!session.id.empty())	// Session found, Renew session expiration (keep auth token unchanged to avoid race conditions with concurrent requests)
			{
				// Find-and-mutate under a single lock: renewal used to be a
				// read-modify-write through a raw pointer returned by GetSession,
				// with no lock held across the write -- racing the session-cleaner
				// thread's RemoveSession/ClearUserPasswords. TouchSessionExpiry
				// does the whole thing atomically and hands back a snapshot to cookie.
				//
				// A fresh cookie is sent only when TouchSessionExpiry reports that
				// renewal actually happened, not on every request: the client's
				// existing cookie is still valid for the rest of its half-life, so
				// re-issuing an unchanged cookie on every single request would just
				// be wasted work for no benefit. Renew-or-nothing keeps the common
				// case (a session nowhere near its half-life) free of any cookie or
				// session-store write.
				WebEmSession touchedSession;
				if (myWebem->TouchSessionExpiry(session.id, touchedSession))
				{
					session_store_impl_ptr sstore = myWebem->GetSessionStore();
					if (sstore != nullptr)
						sstore->RenewSessionExpiration(touchedSession.id, touchedSession.expires);
					send_cookie(rep, touchedSession);
				}
			}
		}

	} // namespace server
} // namespace http
