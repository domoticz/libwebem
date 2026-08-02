//
// connection_manager.cpp
// ~~~~~~~~~~~~~~~~~~~~~~
//
// Copyright (c) 2003-2008 Christopher M. Kohlhoff (chris at kohlhoff dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
#include "webem_stdafx.h"
#include <libwebem/connection_manager.h>
#include <libwebem/webem_utils.h>
#include <algorithm>
#include <iostream>
#include <utility>

namespace http {
namespace server {

	void connection_manager::configure(size_t max_connections, size_t max_connections_per_ip,
		size_t max_body_bytes_in_flight, WebServerLogger logger)
	{
		max_connections_ = max_connections;
		max_connections_per_ip_ = max_connections_per_ip;
		max_body_bytes_in_flight_ = max_body_bytes_in_flight;
		m_logger = std::move(logger);
	}

	void connection_manager::set_trusted_proxy_addresses(const std::vector<std::string> &addresses)
	{
		trusted_proxy_addresses_ = std::set<std::string>(addresses.begin(), addresses.end());
	}

	void connection_manager::log_refusal(const char *what, const std::string &remote_address, size_t limit)
	{
		++refusals_since_log_;
		const time_t now = utils::webem_time();
		if ((last_refusal_log_ != 0) && ((now - last_refusal_log_) < kRefusalLogInterval))
			return; // throttled - see the note in the header
		if (m_logger)
			m_logger->Log(LogLevel::Error, "Refusing connection from %s: %s limit (%zu) reached (%zu refused since last report)",
				      remote_address.empty() ? "<unknown>" : remote_address.c_str(), what, limit, refusals_since_log_);
		last_refusal_log_ = now;
		refusals_since_log_ = 0;
	}

	void connection_manager::start(const connection_ptr &c)
	{
		// Resolve the peer up front. This is the key we will have to decrement by in
		// stop(), and by then the socket may already be closed, so it must be captured
		// now and remembered rather than re-queried later.
		std::string remote_address;
		{
			boost::system::error_code ec;
			boost::asio::ip::tcp::endpoint ep = c->socket().remote_endpoint(ec);
			if (!ec)
				remote_address = ep.address().to_string();
			else if (m_logger)
				// Without an address the per-address cap cannot be applied to this
				// connection. The global cap below still is, and connection::start()
				// will fail the connection for the same reason moments later.
				m_logger->Log(LogLevel::Error, "Could not resolve peer address (%s); per-address limit not applied",
					      ec.message().c_str());
		}

		if ((max_connections_ > 0) && (connections_.size() >= max_connections_))
		{
			log_refusal("global connection", remote_address, max_connections_);
			boost::system::error_code ec;
			c->socket().close(ec);
			return;
		}

		// Addresses in trusted_proxy_addresses_ (typically the reverse proxy libwebem
		// sits behind) are exempt: every real client behind it would otherwise be
		// counted against this one address, and the proxy would eventually be
		// refused -- taking every client behind it down with it -- once enough of
		// them are connected at once. See server_settings::trusted_proxy_addresses.
		if ((max_connections_per_ip_ > 0) && (!remote_address.empty())
		    && (trusted_proxy_addresses_.find(remote_address) == trusted_proxy_addresses_.end()))
		{
			auto itc = per_ip_counts_.find(remote_address);
			if ((itc != per_ip_counts_.end()) && (itc->second >= max_connections_per_ip_))
			{
				log_refusal("per-address connection", remote_address, max_connections_per_ip_);
				boost::system::error_code ec;
				c->socket().close(ec);
				return;
			}
		}

		connections_.insert(c);
		if (!remote_address.empty())
		{
			connection_addresses_[c.get()] = remote_address;
			++per_ip_counts_[remote_address];
		}
		// NOTE: c->start() can fail and call back into stop() synchronously (it does so
		// when remote_endpoint() errors). That is safe: the bookkeeping above is already
		// complete, so stop() finds and unwinds it correctly.
		c->start();
	}

	void connection_manager::stop(const connection_ptr &c)
	{
		// Release the per-address slot. Guarded by the presence of the entry, so a
		// second stop() for the same connection cannot decrement the count twice.
		auto ita = connection_addresses_.find(c.get());
		if (ita != connection_addresses_.end())
		{
			auto itc = per_ip_counts_.find(ita->second);
			if (itc != per_ip_counts_.end())
			{
				if (itc->second > 1)
					--itc->second;
				else
					per_ip_counts_.erase(itc); // drop empty entries; keeps the map bounded
			}
			connection_addresses_.erase(ita);
		}
		connections_.erase(c);
		c->stop();
	}

void connection_manager::stop_all()
{
	for (const auto &con : connections_)
	{
		con->stop();
	}
	connections_.clear();
	connection_addresses_.clear();
	per_ip_counts_.clear();
}

bool connection_manager::reserve_body_bytes(size_t bytes, const std::string &remote_address)
{
	if (max_body_bytes_in_flight_ == 0)
		return true; // unlimited

	// Overflow-safe: never form body_bytes_in_flight_ + bytes, which could wrap.
	// Mirrors the same pattern used for the per-connection write-queue bound in
	// connection.cpp (MyWriteOnStrand/QueuePreUpgradeFrame).
	if ((bytes > max_body_bytes_in_flight_) || (body_bytes_in_flight_ > (max_body_bytes_in_flight_ - bytes)))
	{
		log_refusal("server-wide in-flight request-body", remote_address, max_body_bytes_in_flight_);
		return false;
	}
	body_bytes_in_flight_ += bytes;
	return true;
}

void connection_manager::release_body_bytes(size_t bytes)
{
	// Defensive clamp, not an expected path: under correct pairing this can
	// never go negative. Degrading into a clamp (with a loud log) rather than
	// wrapping keeps a hypothetical accounting bug from turning into a stuck
	// "budget permanently exhausted" state for the life of the process.
	if (body_bytes_in_flight_ < bytes)
	{
		if (m_logger) m_logger->Log(LogLevel::Error,
			"body-budget accounting drift (%zu < %zu); please report",
			body_bytes_in_flight_, bytes);
		body_bytes_in_flight_ = 0;
	}
	else
	{
		body_bytes_in_flight_ -= bytes;
	}
}


} // namespace server
} // namespace http
