#include "webem_stdafx.h"
#include <libwebem/Websockets.h>
#include <json/json.h>
#include <openssl/rand.h>

#include <cstdint>
#include <limits>
#include <utility>

#define FIN_MASK 0x80
#define RSVI1_MASK 0x40
#define RSVI2_MASK 0x20
#define RSVI3_MASK 0x10
#define OPCODE_MASK 0x0f
#define MASKING_MASK 0x80
#define PAYLOADLEN_MASK 0x7f

namespace http {
	namespace server {

		CWebsocketFrame::CWebsocketFrame() {
			fin = false;
			rsvi1 = rsvi2 = rsvi3 = false;
			opcode = opcode_continuation;
			masking = false;
			payloadlen = 0;
			bytes_consumed = 0;
		};

		std::string CWebsocketFrame::unmask(const uint8_t *mask, const uint8_t *bytes, size_t payloadlen) {
			std::string result;
			result.resize(payloadlen);
			for (size_t i = 0; i < payloadlen; i++) {
				result[i] = (uint8_t)(bytes[i] ^ mask[i % 4]);
			}
			return result;
		}

		std::string CWebsocketFrame::Create(opcodes opcode, const std::string &payload, bool domasking)
		{
			size_t payloadlen = payload.length();
			std::string res;
			// byte 0
			res += ((uint8_t)opcode | FIN_MASK);
			if (payloadlen < 126) {
				res += (uint8_t)payloadlen | (domasking ? MASKING_MASK : 0);
			}
			else {
				if (payloadlen <= 0xffff) {
					res += (uint8_t)126 | (domasking ? MASKING_MASK : 0);
					int bits = 16;
					while (bits) {
						bits -= 8;
						res += (uint8_t)((payloadlen >> bits) & 0xff);
					}
				}
				else {
					res += (uint8_t)127 | (domasking ? MASKING_MASK : 0);
					// Widen to a fixed-width 64-bit type before shifting: payloadlen
					// is size_t, which is only 32 bits on a 32-bit build (armhf
					// Raspberry Pi is a first-class target), and shifting by 56/48/
					// 40/32 bits would be undefined behaviour on a 32-bit operand.
					uint64_t len64 = (uint64_t)payloadlen;
					int bits = 64;
					while (bits) {
						bits -= 8;
						uint8_t ch = (uint8_t)((len64 >> bits) & 0xff);
						res += ch;
					}
				}
			}
			if (domasking) {
				// masking key - must be unpredictable per RFC 6455, use a CSPRNG
				uint8_t masking_key[4];
				if (RAND_bytes(masking_key, sizeof(masking_key)) != 1)
				{
					// Extremely unlikely CSPRNG failure; fall back to a weak source
					// rather than sending an all-zero (no-op) mask.
					for (unsigned char &i : masking_key)
						i = (uint8_t)rand();
				}
				for (unsigned char i : masking_key)
					res += (char)i;
				res += unmask(masking_key, (const uint8_t *)payload.c_str(), (size_t)payloadlen);
			}
			else {
				res += payload;
			}
			return res;
		}

		frame_parse_result CWebsocketFrame::Parse(const uint8_t *bytes, size_t size, size_t max_frame_size) {
			uint8_t masking_key[4];
			size_t remaining = size;
			bytes_consumed = 0;
			if (remaining < 2) {
				return frame_parse_result::need_more_data;
			}
			fin = (bytes[0] & FIN_MASK) > 0;
			rsvi1 = (bytes[0] & RSVI1_MASK) > 0;
			rsvi2 = (bytes[0] & RSVI2_MASK) > 0;
			rsvi3 = (bytes[0] & RSVI3_MASK) > 0;
			opcode = (opcodes)(bytes[0] & OPCODE_MASK);
			masking = (bytes[1] & MASKING_MASK) > 0;
			payloadlen = (bytes[1] & PAYLOADLEN_MASK);
			remaining -= 2;
			size_t ptr = 2;

			// No extensions are negotiated, so the reserved bits must be zero
			// (RFC 6455 S5.2).
			if (rsvi1 || rsvi2 || rsvi3) {
				return frame_parse_result::protocol_error;
			}
			// RFC 6455 S5.1: every frame sent from client to server must be
			// masked. Checked before the length is even decoded: an unmasked
			// frame is malformed regardless of what it claims its length is.
			if (!masking) {
				return frame_parse_result::protocol_error;
			}

			if (payloadlen == 126) {
				if (remaining < 2) {
					return frame_parse_result::need_more_data;
				}
				uint64_t len64 = 0;
				int bits = 16;
				for (uint8_t i = 0; i < 2; i++) {
					bits -= 8;
					len64 += (uint64_t)bytes[ptr++] << bits;
					remaining--;
				}
				payloadlen = (size_t)len64;
			}
			else if (payloadlen == 127) {
				if (remaining < 8) {
					return frame_parse_result::need_more_data;
				}
				// Accumulate into an explicit 64-bit type: on a 32-bit build
				// size_t is only 32 bits, and shifting by 56/48/40/32 bits
				// would be undefined behaviour on a 32-bit operand.
				uint64_t len64 = 0;
				int bits = 64;
				for (uint8_t i = 0; i < 8; i++) {
					bits -= 8;
					len64 += (uint64_t)bytes[ptr++] << bits;
					remaining--;
				}
				// Range-check the 64-bit value before narrowing to size_t: an
				// attacker-declared length that does not fit in size_t must
				// never reach the buffering gate below, on any build.
				if (len64 > (uint64_t)(std::numeric_limits<size_t>::max)()) {
					return frame_parse_result::protocol_error;
				}
				payloadlen = (size_t)len64;
			}

			// Reject an oversized frame immediately after decoding the length,
			// before the "have all the bytes arrived yet" gate below --
			// otherwise the connection buffers toward a size it will never be
			// allowed to reach, reading a few KB at a time until an
			// attacker-controlled 64-bit length is fully resident.
			if ((max_frame_size > 0) && (payloadlen > max_frame_size)) {
				return frame_parse_result::protocol_error;
			}

			// RFC 6455 S5.5: control frames must not be fragmented and must
			// carry no more than 125 bytes of payload.
			if (opcode >= opcode_close) {
				if (!fin || (payloadlen > 125)) {
					return frame_parse_result::protocol_error;
				}
			}

			if (remaining < 4) {
				return frame_parse_result::need_more_data;
			}
			for (unsigned char &i : masking_key)
			{
				i = bytes[ptr++];
				remaining--;
			}
			if (remaining < payloadlen) {
				return frame_parse_result::need_more_data;
			}
			payload = unmask(masking_key, &bytes[ptr], payloadlen);
			remaining -= payloadlen;
			ptr += payloadlen;
			bytes_consumed = ptr;
			return frame_parse_result::ok;
		};

		const std::string &CWebsocketFrame::Payload() {
			return payload;
		};

		bool CWebsocketFrame::isFinal() {
			return fin;
		};

		size_t CWebsocketFrame::Consumed() {
			return bytes_consumed;
		};

		opcodes CWebsocketFrame::Opcode() {
			return opcode;
		};

		CWebsocket::CWebsocket(std::function<void(const std::string &packet_data)> _MyWrite, std::function<void(const std::string &packet_data)> _WSWrite)
			: OUR_PING_ID("fd")
			, m_WSWrite(std::move(_WSWrite))
		{
			start_new_packet = true;
			MyWrite = std::move(_MyWrite);
		}

		void CWebsocket::SetHandler(std::shared_ptr<IWebsocketHandler> handler)
		{
			m_handler = std::move(handler);
		}

		void CWebsocket::SetLimits(size_t max_frame_size, size_t max_message_size)
		{
			max_frame_size_ = max_frame_size;
			max_message_size_ = max_message_size;
		}

		boost::tribool CWebsocket::parse(const uint8_t *begin, size_t size, size_t &bytes_consumed, bool &keep_alive)
		{
			CWebsocketFrame frame;
			frame_parse_result presult = frame.Parse(begin, size, max_frame_size_);
			if (presult == frame_parse_result::need_more_data) {
				bytes_consumed = 0;
				return boost::indeterminate;
			}
			if (presult == frame_parse_result::protocol_error) {
				// The frame itself violates RFC 6455 (oversized, reserved
				// opcode/bits, unmasked, malformed control frame, ...). Fail the
				// connection instead of leaving it to buffer toward a limit it
				// will never be allowed to reach.
				bytes_consumed = 0;
				keep_alive = false;
				return false;
			}
			bytes_consumed = frame.Consumed();
			if (start_new_packet) {
				packet_data.clear();
				last_opcode = frame.Opcode();
			}
			const std::string &frame_payload = frame.Payload();
			// Cap the reassembled message before appending: a message is
			// reassembled here one fragment at a time, and Parse()'s per-frame
			// limit alone does nothing to bound how many fragments a chain of
			// continuation frames can accumulate.
			if ((max_message_size_ > 0) && ((packet_data.size() + frame_payload.size()) > max_message_size_)) {
				// Mirror the protocol_error path: nothing should be credited as
				// consumed toward a connection that is being dropped.
				bytes_consumed = 0;
				keep_alive = false;
				return false;
			}
			packet_data += frame_payload;
			if (frame.isFinal()) {
				// packet is ready for packet handler
				start_new_packet = true;
				switch (last_opcode) {
				case opcode_continuation:
					// shouldn't occur here
					return false;
					break;
				case opcode_text:
					if (!OnReceiveText(packet_data)) {
						keep_alive = false;
						return false;
					}
					return true;
					break;
				case opcode_binary:
					if (!OnReceiveBinary(packet_data)) {
						keep_alive = false;
						return false;
					}
					return true;
					break;
				case opcode_close:
					SendClose("");
					keep_alive = false;
					return false;
					break;
				case opcode_ping:
					SendPong(packet_data);
					return false;
					break;
				case opcode_pong:
					OnPong(packet_data);
					return false;
					break;
				default:
					// RFC 6455 S5.2: opcodes 0x03-0x07 and 0x0B-0x0F are reserved
					// and carry no defined meaning. Without this case, a single
					// reserved-opcode frame permanently wedges the state machine:
					// start_new_packet was just set true above, but falling out
					// of the switch without returning reaches the "wait for more
					// fragments" code below, which sets it back to false --
					// packet_data is then never cleared again and nothing is
					// ever dispatched. Failing the connection here is what stops
					// that; the caller (CWebsocket::parse's do-while drain loop
					// in connection.cpp) then closes the connection.
					keep_alive = false;
					return false;
				}
			}
			// packet waits for more fragments
			start_new_packet = false;
			return false;
		}

		// we receive a json request here. the final format is still to be decided
		// todo: move the body of this function to the websocket handler, so it can be
		// re-used from the proxy client
		// note: We mimic a web request here. This is just for testing purposes to see
		//       if everything works. We need a proper implementation here.
		bool CWebsocket::OnReceiveText(const std::string &packet_data)
		{
			if (m_handler && !m_handler->Handle(packet_data, false))
			{
				SendClose("");
				return false;
			}
			return true;
		}

		bool CWebsocket::OnReceiveBinary(const std::string &packet_data)
		{
			const std::string &the_data = packet_data;
			return OnReceiveText(the_data);
		}

		void CWebsocket::SendPing()
		{
			// todo: set the ping timer
			std::string frame = CWebsocketFrame::Create(opcode_ping, OUR_PING_ID, false);
			MyWrite(frame);
		}

		void CWebsocket::OnPong(const std::string &packet_data)
		{
			if (packet_data == OUR_PING_ID) {
				// todo: this was a response to one of our pings. reset the ping timer.
			}
		}

		void CWebsocket::SendPong(const std::string &packet_data)
		{
			std::string frame = CWebsocketFrame::Create(opcode_pong, packet_data, false);
			MyWrite(frame);
		}

		void CWebsocket::SendClose(const std::string &packet_data)
		{
			std::string frame = CWebsocketFrame::Create(opcode_close, packet_data, false);
			MyWrite(frame);
		}

		void CWebsocket::Start()
		{
			if (m_handler) m_handler->Start();
		}

		void CWebsocket::Stop()
		{
			if (m_handler) m_handler->Stop();
			m_handler.reset();
		}

		std::shared_ptr<IWebsocketHandler> CWebsocket::DetachHandler()
		{
			return std::move(m_handler);
		}

		IWebsocketHandler * CWebsocket::GetHandler()
		{
			return m_handler.get();
		}

	} // namespace server
} // namespace http
