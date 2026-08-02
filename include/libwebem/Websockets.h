#pragma once
#include <boost/logic/tribool.hpp>
#include <string>
#include "IWebsocketHandler.h"

namespace http
{
	namespace server
	{

		enum opcodes
		{
			opcode_continuation = 0x00,
			opcode_text = 0x01,
			opcode_binary = 0x02,
			opcode_close = 0x08,
			opcode_ping = 0x09,
			opcode_pong = 0x0a
		};

		/// Outcome of CWebsocketFrame::Parse. A plain bool used to conflate "not
		/// enough bytes have arrived yet" with "this frame violates the
		/// protocol" -- both returned false -- which is exactly how an
		/// attacker-declared oversized frame turned into unbounded buffering:
		/// the caller had no way to tell "keep waiting for more data" apart
		/// from "stop now, this connection must be failed".
		enum class frame_parse_result
		{
			need_more_data, ///< not enough bytes buffered yet; caller should wait for more
			ok,             ///< a complete, valid frame was parsed
			protocol_error  ///< the frame violates RFC 6455; the connection must be failed
		};

		class connection;
		class cWebem;

		class CWebsocketFrame
		{
		      public:
			CWebsocketFrame();
			~CWebsocketFrame() = default;
			/// Parse one frame out of [bytes, bytes+size). max_frame_size bounds
			/// the payload length (0 = unlimited) and is enforced immediately
			/// after the length prefix is decoded, before any payload bytes are
			/// required to be present.
			frame_parse_result Parse(const uint8_t *bytes, size_t size, size_t max_frame_size);
			const std::string &Payload();
			bool isFinal();
			size_t Consumed();
			opcodes Opcode();
			static std::string Create(opcodes opcode, const std::string &payload, bool domasking);

		      private:
			static std::string unmask(const uint8_t *mask, const uint8_t *bytes, size_t payloadlen);
			bool fin;
			bool rsvi1;
			bool rsvi2;
			bool rsvi3;
			opcodes opcode;
			bool masking;
			size_t payloadlen, bytes_consumed;
			std::string payload;
		};

		class CWebsocket
		{
		      public:
			CWebsocket(std::function<void(const std::string &packet_data)> _MyWrite, std::function<void(const std::string &packet_data)> _WSWrite);
			~CWebsocket() = default;
			virtual boost::tribool parse(const uint8_t *begin, size_t size, size_t &bytes_consumed, bool &keep_alive);
			virtual void SendClose(const std::string &packet_data);
			virtual void SendPing();
			virtual void Start();
			virtual void Stop();
			virtual IWebsocketHandler *GetHandler();
			void SetHandler(std::shared_ptr<IWebsocketHandler> handler);
			/// Configure the WebSocket size limits enforced while parsing. Defaults
			/// (member initializers below) match server_settings' defaults, so a
			/// CWebsocket used without an explicit call -- e.g. in unit tests --
			/// still enforces sane bounds. 0 disables the corresponding limit.
			void SetLimits(size_t max_frame_size, size_t max_message_size);
			/// Detach the handler for async cleanup. Returns the handler shared_ptr.
			/// After this call, the CWebsocket no longer holds a reference.
			/// @note Only safe to call from the io_context thread (e.g., from connection::stop()).
			std::shared_ptr<IWebsocketHandler> DetachHandler();

		      private:
			virtual bool OnReceiveText(const std::string &packet_data);
			virtual bool OnReceiveBinary(const std::string &packet_data);
			virtual void OnPong(const std::string &packet_data);
			virtual void SendPong(const std::string &packet_data);
			std::string packet_data;
			bool start_new_packet;
			opcodes last_opcode;
			std::string OUR_PING_ID;
			/// Passed to CWebsocketFrame::Parse for each frame; see SetLimits.
			size_t max_frame_size_{ 1 * 1024 * 1024 };
			/// Bounds packet_data's reassembled size; see SetLimits.
			size_t max_message_size_{ 4 * 1024 * 1024 };
			std::shared_ptr<IWebsocketHandler> m_handler;
			std::function<void(const std::string &packet_data)> MyWrite;
			std::function<void(const std::string &packet_data)> m_WSWrite;
		};

	} // namespace server
} // namespace http
