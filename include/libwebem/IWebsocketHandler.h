#pragma once
#include <string>
#include <functional>
#include <memory>

namespace http {
namespace server {

	class cWebem;
	class request;
	struct reply;

	class IWebsocketHandler {
	public:
		virtual ~IWebsocketHandler() = default;

		// Called when a complete WebSocket message is received
		virtual bool Handle(const std::string& packet_data, bool outbound) = 0;

		// Lifecycle
		virtual void Start() = 0;
		virtual void Stop() = 0;

		// Called after upgrade to store session info from the HTTP handshake
		virtual void store_session_id(const request& req, const reply& rep) = 0;
	};

	// Factory: given a webem pointer and two writer functions (text and binary), create a handler for a specific connection
	using WebsocketHandlerFactory = std::function<
		std::shared_ptr<IWebsocketHandler>(
			cWebem*                                   webem,
			std::function<void(const std::string&)>   text_writer,   // opcode_text (existing)
			std::function<void(const std::string&)>   binary_writer  // opcode_binary (NEW)
		)
	>;

} // namespace server
} // namespace http
