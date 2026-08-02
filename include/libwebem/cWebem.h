#pragma once

#include <boost/asio.hpp>
#include <boost/thread.hpp>
#include <json/json.h>
#include "server.h"
#include "session_store.h"
#include "IWebServerLogger.h"
#include "IWebsocketHandler.h"
#include "ISseHandler.h"
#include "session.h"
#include <functional>
#include <vector>
#include <memory>
#include <mutex>
#include <map>

namespace http
{
	namespace server
	{
		enum _eAuthenticationMethod
		{
			AUTH_LOGIN = 0,
			AUTH_BASIC,
		};
		enum _eWebCompressionMode
		{
			WWW_USE_GZIP = 0,
			WWW_USE_STATIC_GZ_FILES,
			WWW_FORCE_NO_GZIP_SUPPORT
		};
		typedef struct _tWebUserPassword
		{
			unsigned long ID;
			std::string Username;
			std::string Password;
			std::string Mfatoken;
			std::string Passkeys;          // JSON array of passkey credentials
			std::string PrivKey;
			std::string PubKey;
			_eUserRights userrights = URIGHTS_VIEWER;
			int TotSensors = 0;
			int ActiveTabs = 0;
			uint32_t RefreshExpire = 0;
			std::string SigningSecret;
			time_t AcceptLegacyTokensUntil = 0;
		} WebUserPassword;

		typedef struct _tIPNetwork
		{
			bool bIsIPv6 = false;
			std::string ip_string;
			uint8_t Network[16] = { 0 };
			uint8_t Mask[16] = { 0 };
		} IPNetwork;

		// Parsed Authorization header (RFC2617)
		struct ah {
			std::string method;		// HTTP request method
			std::string user;		// Username
			std::string response;	// Response with the request-digest
			std::string uri;		// Digest-Uri
			std::string cnonce;		// Client Nonce
			std::string qop;		// Quality of Protection
			std::string nc;			// Nonce Count
			std::string nonce;		// Nonce
			std::string ha1;		// A1 = unq(username-value) ":" unq(realm-value) ":" passwd
		};

		/**

		The link between the embedded web server and the application code


		* Copyright (c) 2008 by James Bremner
		* All rights reserved.
		*
		* Use license: Modified from standard BSD license.
		*
		* Redistribution and use in source and binary forms are permitted
		* provided that the above copyright notice and this paragraph are
		* duplicated in all such forms and that any documentation, advertising
		* materials, Web server pages, and other materials related to such
		* distribution and use acknowledge that the software was developed
		* by James Bremner. The name "James Bremner" may not be used to
		* endorse or promote products derived from this software without
		* specific prior written permission.
		*
		* THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
		* IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
		* WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.



		*/
		class cWebem;
		typedef std::function<void(std::string &content_part)> webem_include_function;
		typedef std::function<void(WebEmSession &session, const request &req, std::string &redirecturi)> webem_action_function;
		typedef std::function<void(WebEmSession &session, const request &req, reply &rep)> webem_page_function;

		/**

		The webem request handler.

		A specialization of the boost::asio request handler

		Application code should not use this class.

		*/
		class cWebemRequestHandler : public request_handler
		{
		      public:
			/// Construct with a directory containing files to be served.
			cWebemRequestHandler(const std::string &doc_root, cWebem *webem, WebServerLogger logger = nullptr)
				: request_handler(doc_root, webem, std::move(logger))
			{
			}

			/// Handle a request and produce a reply.
			void handle_request(const request &req, reply &rep) override;
			bool CheckUserAuthorization(std::string &user, const request &req);

				private:
			char *strftime_t(const char *format, time_t rawtime);
			bool CompressWebOutput(const request &req, reply &rep);
			/// Websocket methods
			bool is_upgrade_request(WebEmSession &session, const request &req, reply &rep);
			std::string compute_accept_header(const std::string &websocket_key);
			bool CheckAuthByPass(const request& req);
			/// @param bTrustedNetworkAllowed pass false to suppress the trusted-network
			///        authentication bypass for this request. Used when proxy headers were
			///        present but unusable, so the request must not inherit the trust that
			///        the connecting proxy's own address would otherwise confer.
			///        Defaults to true so existing direct callers are unaffected.
			bool CheckAuthentication(WebEmSession &session, const request &req, bool &authErr,
						 bool bTrustedNetworkAllowed = true);
			bool CheckUserAuthorization(std::string &user, struct ah *ah);
			bool AllowBasicAuth();
			void send_authorization_request(const request &req, reply &rep);
			void send_remove_cookie(reply &rep);
			std::string generateSessionID();
			void send_cookie(reply &rep, const WebEmSession &session);
			bool parse_cookie(const request &req, std::string &sSID, std::string &sAuthToken, std::string &szTime, bool &expired);
			bool AreWeInTrustedNetwork(const std::string &sHost);
			bool IsIPInRange(const std::string &ip, const _tIPNetwork &ipnetwork, const bool &bIsIPv6);
			int parse_auth_header(const request &req, struct ah *ah);
			std::string generateAuthToken(const WebEmSession &session, const request &req);
			bool checkAuthToken(WebEmSession &session);
			void removeAuthToken(const std::string &sessionId);
			int check_password(struct ah *ah, const std::string &ha1);
		};

		/**
		The webem embedded web server.
		*/
		class cWebem
		{
			friend class cWebemRequestHandler;
		      public:
			cWebem(const server_settings &settings, const std::string &doc_root,
			       WebServerLogger logger = nullptr);
			~cWebem();
			void Run();
			void Stop();

			void RegisterPageCode(const char *pageurl, const webem_page_function &fun, bool bypassAuthentication = false);
			bool DispatchPageOptions(const request& req);
			void RegisterOptionsCode(const char *pageurl, const webem_page_function &fun);

			void RegisterActionCode(const char *idname, const webem_action_function &fun);

			void RegisterWhitelistURLString(const char *idname);
			void RegisterWhitelistCommandsString(const char *idname);

			void DebugRegistrations();

			bool ExtractPostData(request &req, const char *pContent_Type);

			bool IsAction(const request &req);
			bool CheckForAction(WebEmSession &session, request &req);

			bool IsPageOverride(const request &req, reply &rep);
			bool CheckForPageOverride(WebEmSession &session, request &req, reply &rep);

			void SetAuthenticationMethod(_eAuthenticationMethod amethod);
			void SetWebTheme(const std::string &themename);
			void SetWebRoot(const std::string &webRoot);
			void AddUserPassword(unsigned long ID, const std::string &username, const std::string &password, const std::string &mfatoken, const std::string &passkeys, _eUserRights userrights, int activetabs, const std::string &privkey = "", const std::string &pubkey = "", uint32_t refreshexpire = 0, const std::string &signingsecret = "", time_t accept_legacy_until = 0);
			void RemoveUserPassword(unsigned long ID);
			std::string ExtractRequestPath(const std::string &original_request_path);
			bool IsBadRequestPath(const std::string &original_request_path);

			bool GenerateJwtToken(std::string &jwttoken, const std::string &clientid, const std::string &user, const uint32_t exptime, const Json::Value jwtpayload = "", const std::string &issuer = "");
			bool FindAuthenticatedUser(std::string &user, const request &req, reply &rep);
			bool CheckVHost(const request &req);
			/// Resolve the originating client from any proxy headers on the request.
			///
			/// Only consults m_settings.trusted_proxy_header_family -- when that is
			/// ProxyHeaderFamily::None (the default), proxy headers are ignored
			/// entirely and this always returns with @p realhost empty and
			/// @p bHaveProxyHeaders false. When a family IS configured, the other two
			/// families are ignored completely, and a request carrying more than one
			/// family present at once is rejected outright (see @return) rather than
			/// guessing which chain to believe.
			///
			/// CRITICAL: only the RIGHTMOST entry of the chain is believed. A proxy
			/// appends the address of whoever connected to it, so that entry is the one
			/// our proxy wrote; everything to its left is client-supplied and forgeable.
			/// @param realhost      set to the resolved client address, or left empty when
			///                      there were no proxy headers, or when there were but no
			///                      usable address survived filtering.
			/// @param bHaveProxyHeaders set to true if the configured proxy header
			///                      family was present. When this is true and
			///                      @p realhost is empty, the caller must NOT let the
			///                      request inherit the peer's trusted-network rights --
			///                      the proxy headers were present but unusable, so the
			///                      real client address is unknown and must not be
			///                      assumed to be trusted.
			/// @return false if the request carries more than one proxy header family
			///         at once; the caller must reject the request rather than resolve
			///         a client address from it.
			bool findRealHostBehindProxies(const request &req, std::string &realhost, bool &bHaveProxyHeaders);
			static bool isValidIP(std::string& ip);

			void ClearUserPasswords();

			/// True if any user account is configured, i.e. authentication is
			/// actually in force for this server.
			///
			/// With no users, every page and command is already served to anyone
			/// who asks, so there is nothing for a credential check to protect.
			/// Used to decide whether a WebSocket upgrade must be authenticated:
			/// requiring it where HTTP is open would only break live updates on an
			/// unprotected installation without denying an attacker anything.
			/// Takes m_configMutex, so it must not be called with that already held.
			bool HasConfiguredUsers() const;

			std::vector<_tWebUserPassword> m_userpasswords;
			void AddTrustedNetworks(const std::string &network);
			void ClearTrustedNetworks();
			std::vector<_tIPNetwork> m_localnetworks;
			void SetDigistRealm(const std::string &realm);
			std::string m_DigistRealm;
			void SetAllowPlainBasicAuth(const bool bAllow);
			bool m_AllowPlainBasicAuth;
			void SetZipPassword(const std::string &password);

			// Session store manager
			void SetSessionStore(session_store_impl_ptr sessionStore);
			session_store_impl_ptr GetSessionStore();

			std::string m_zippassword;
			std::string GetPort();
			std::string GetWebRoot();
			/// Look up a session by id. On success, copies it into @p out under the
			/// session lock and returns true; the copy is a private snapshot the
			/// caller may read (or discard) without holding any lock. There is
			/// deliberately no pointer-returning overload: a pointer into m_sessions
			/// can be invalidated at any time by RemoveSession/ClearUserPasswords
			/// running on the session-cleaner thread.
			bool GetSession(const std::string &ssid, WebEmSession &out);
			void AddSession(const WebEmSession &session);
			void RemoveSession(const WebEmSession &session);
			void RemoveSession(const std::string &ssid);
			/// Renew a session's expiration if past its half-life, using the same
			/// logic as HTTP request processing. Called by WebSocket connections to
			/// keep the session alive while no HTTP requests are being made.
			void RenewSessionIfNeeded(const std::string &sessionId);
			/// Find the session, and if it is past its half-life, extend its
			/// expiration in place -- all under a single lock, so there is no
			/// window where a caller reads the session, another thread mutates or
			/// erases it, and the caller then writes back through a stale pointer.
			/// @param out receives the (possibly just-renewed) session snapshot
			///            whenever the session is found, whether or not it was
			///            actually renewed. Left untouched if the session is absent.
			/// @return true only when the session was found AND it was already past
			///         its half-life, so renewal was actually applied. Returns false
			///         in the two remaining cases, which @p out cannot be used to
			///         distinguish on its own: the session does not exist (@p out is
			///         left unmodified), or it exists but is not yet due for renewal
			///         (@p out is still filled in with the current, unrenewed
			///         snapshot).
			bool TouchSessionExpiry(const std::string &ssid, WebEmSession &out);
			std::vector<std::string> GetExpiredSessions();
			int CountSessions();

			/// Record that a request was just handled from (remoteHost, localPort),
			/// updating its last-seen time and last-requested URI. Encapsulates all
			/// access to m_remote_web_clients so its mutex is never touched outside
			/// this class. Enforces the size cap on every call (evicting the oldest
			/// entry by last_seen first, if needed) rather than relying solely on
			/// the periodic sweep, so the bound holds between sweeps too.
			/// @return true if this address/port pair had already been
			/// seen within SHORT_SESSION_TIMEOUT (i.e. it is not a "first sighting").
			bool TrackRemoteClient(const std::string &remoteHost, const std::string &localPort, const std::string &requestUri);
			/// Current size of the recently-seen-clients cache. Exposed for
			/// diagnostics and tests; production code has no need to read it.
			size_t CountRemoteClients();
			/// Evict entries from the recently-seen-clients cache that are older
			/// than SHORT_SESSION_TIMEOUT, and cap what remains as a backstop.
			/// Called from the periodic CleanSessions() sweep; also safe to call
			/// directly (it does not touch the session-cleanup timer), which tests
			/// use to exercise pruning without waiting on the real 15-minute period.
			void PruneRemoteClients();
			/// Point-in-time snapshot of the recently-seen-clients cache, copied
			/// under m_remoteClientsMutex. Follows the same pattern as GetSession:
			/// no reference or pointer into m_remote_web_clients is ever handed
			/// out, so the caller can iterate the result freely -- including from
			/// another thread -- without holding any lock and without risking a
			/// dangling reference if TrackRemoteClient/PruneRemoteClients mutate
			/// or evict entries afterwards. Since this is per-instance (unlike the
			/// process-global map it replaced), a caller that wants a full picture
			/// across multiple cWebem instances (e.g. separate HTTP/HTTPS servers)
			/// must call this on each instance and merge the results itself.
			std::vector<connection::_tRemoteClients> GetRemoteClients();
			_eAuthenticationMethod m_authmethod;
			// Whitelist url strings that bypass authentication checks (not used by basic-auth authentication)
			std::vector<std::string> myWhitelistURLs;
			std::vector<std::string> myWhitelistCommands;
			std::map<std::string, WebEmSession> m_sessions;
			server_settings m_settings;
			// actual theme selected
			std::string m_actTheme;

			void SetWebCompressionMode(_eWebCompressionMode gzmode);
			_eWebCompressionMode m_gzipmode;

			/// Set the session cookie name used in Set-Cookie / Cookie headers.
			/// Defaults to "SID".
			void SetSessionCookieName(const std::string& name);
			const std::string& GetSessionCookieName() const;
			std::string m_session_cookie_name;

			// WebSocket endpoint registry
			void RegisterWebsocketEndpoint(
				const std::string& path,
				WebsocketHandlerFactory factory,
				const std::string& protocol = "");
			WebsocketHandlerFactory GetWebsocketFactory(const std::string& path) const;
			std::string GetWebsocketProtocol(const std::string& path) const;
			bool HasWebsocketEndpoints() const;

			/// Iterate all active WebSocket handlers, pruning disconnected ones.
			/// The callback is invoked outside the mutex lock to prevent deadlocks.
			void ForEachHandler(std::function<void(IWebsocketHandler*)> callback);

			/// Called internally when a new WebSocket handler is created.
			void RegisterWebsocketHandler(std::shared_ptr<IWebsocketHandler> handler);

			/// Schedule async cleanup of a WebSocket handler.
			/// Handler::Stop() is called on a background thread, never on the server io_context.
			void ScheduleHandlerCleanup(std::shared_ptr<IWebsocketHandler> handler);

			// SSE endpoint registry
			void RegisterSseEndpoint(const std::string& path, SseHandlerFactory factory);
			SseHandlerFactory GetSseFactory(const std::string& path) const;

			/// Called internally when a new SSE handler is created.
			void RegisterSseHandler(std::shared_ptr<ISseHandler> handler);

			/// Iterate all active SSE handlers, pruning dead ones.
			/// The callback is invoked outside the mutex lock to prevent deadlocks.
			void ForEachSseHandler(std::function<void(ISseHandler*)> callback);

			/// Schedule async cleanup of an SSE handler.
			/// Handler::Stop() is called on a background thread, never on the server io_context.
			void ScheduleSseHandlerCleanup(std::shared_ptr<ISseHandler> handler);

			/// Register a URI substring pattern that forces no-cache response headers.
			/// Any request whose URI contains this substring will receive
			/// "Cache-Control: no-cache,must-revalidate" regardless of the file type.
			void RegisterNoCachePattern(const std::string& pattern);

			/// Returns true if the URI matches any registered no-cache pattern.
			bool IsNoCacheURI(const std::string& uri) const;

			/// Set the application version string used in ETag headers for HTTP caching.
			void SetAppVersion(const std::string& version) { m_app_version = version; }
			/// Get the application version string used in ETag headers.
			const std::string& GetAppVersion() const { return m_app_version; }

			/// Enable or disable HTTP caching (ETag / Cache-Control headers).
			void SetCacheEnabled(bool enabled) { m_cache_enabled = enabled; }
			/// Returns true if HTTP caching is enabled.
			bool IsCacheEnabled() const { return m_cache_enabled; }

		      public:
			WebServerLogger m_logger;
			/// URI substring patterns that force no-cache response headers.
			/// Registered via RegisterNoCachePattern().
			std::vector<std::string> m_noCachePatterns;
		      private:
			/// Protects configuration collections (myActions, myPages, myWhitelistURLs,
			/// myWhitelistCommands, m_noCachePatterns, m_userpasswords) against
			/// concurrent access from registration and request-handler threads.
			mutable std::mutex m_configMutex;

			/// Registry of active WebSocket handlers (weak references).
			/// Pruned automatically by ForEachHandler when connections close.
			std::vector<std::weak_ptr<IWebsocketHandler>> m_websocketHandlers;
			std::mutex m_websocketHandlersMutex;
			/// Application version string sent as ETag header value.
			std::string m_app_version;
			/// Whether HTTP caching (ETag / Cache-Control) is enabled.
			bool m_cache_enabled = false;

			struct WebsocketEndpoint {
				std::string path;
				std::string protocol;
				WebsocketHandlerFactory factory;
			};
			std::vector<WebsocketEndpoint> m_websocketEndpoints;

			/// Registry of active SSE handlers (strong references; pruned by ForEachSseHandler).
			std::vector<std::shared_ptr<ISseHandler>> m_sse_handlers;
			std::mutex m_sse_handlers_mutex;

			/// SSE endpoint factory registry, keyed by URL path.
			std::map<std::string, SseHandlerFactory> m_sse_endpoints;

			/// store map between include codes and application functions (20230525 No longer in use! Will be removed soon!)
			// std::map<std::string, webem_include_function> myIncludes;
			/// store map between action codes and application functions
			std::map<std::string, webem_action_function> myActions;
			/// store name walue pairs for form submit action
			std::map<std::string, webem_page_function> myPages;
			/// store map of custom OPTIONS handlers (for endpoints needing non-default CORS headers)
			std::map<std::string, webem_page_function> myOptionsHandlers;

			void CleanSessions();
			bool sumProxyHeader(const std::string &sHeader, const request &req, std::vector<std::string> &vHeaderLines);
			/// Appends every usable client address found in the given header lines to
			/// @p vHosts, in wire order. Non-routable values are discarded.
			void parseProxyHeader(const std::vector<std::string> &vHeaderLines, std::vector<std::string> &vHosts);
			/// As parseProxyHeader, for the RFC 7239 "Forwarded" syntax.
			void parseForwardedProxyHeader(const std::vector<std::string> &vHeaderLines, std::vector<std::string> &vHosts);
			session_store_impl_ptr mySessionStore; /// session store
			/// request handler specialized to handle webem requests
			/// Rene: Beware: myRequestHandler should be declared BEFORE myServer
			cWebemRequestHandler myRequestHandler;
			/// boost::asio web server (RK: plain or secure)
			std::shared_ptr<server_base> myServer;
			// root of url
			std::string m_webRoot;
			/// sessions management
			std::mutex m_sessionsMutex;

			/// A tracked client record together with its position in
			/// m_remote_clients_by_last_seen, so that position can be dropped in
			/// O(1) (given the iterator) and re-inserted in O(log n) every time the
			/// record is touched, instead of an O(n) scan to find where it belongs.
			struct _tRemoteClientRecord
			{
				connection::_tRemoteClients info;
				std::multimap<time_t, std::string>::iterator lru_it;
			};

			/// Cache of distinct client addresses recently seen, keyed by
			/// remote_host + local_port (see handle_request). Formerly a
			/// process-wide global, so an HTTP and an HTTPS cWebem instance --
			/// each with its own io thread -- did unsynchronised find/insert on
			/// the same map. Now scoped per-instance and protected by its own
			/// mutex; pruned and size-capped in PruneRemoteClients(), and also
			/// capped inline by TrackRemoteClient() so the bound holds between
			/// sweeps.
			std::map<std::string, _tRemoteClientRecord> m_remote_web_clients;
			/// Secondary index over m_remote_web_clients ordered by last_seen
			/// (oldest first), so the eviction candidate is always
			/// m_remote_clients_by_last_seen.begin() -- an O(log n) lookup instead
			/// of an O(n) scan of a map that can hold up to MAX_REMOTE_WEB_CLIENTS
			/// entries. The mapped string is the corresponding key in
			/// m_remote_web_clients. Kept in sync with it under the same mutex.
			std::multimap<time_t, std::string> m_remote_clients_by_last_seen;
			std::mutex m_remoteClientsMutex;
			/// Evict the single oldest entry (by last_seen) from
			/// m_remote_web_clients and its index. No-op if the cache is empty.
			/// Caller must already hold m_remoteClientsMutex.
			void EvictOldestRemoteClientLocked();

			boost::asio::io_context m_io_context;
			boost::asio::steady_timer m_session_clean_timer;
			std::shared_ptr<std::thread> m_io_context_thread;
		};

	} // namespace server
} // namespace http
