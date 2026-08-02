//
// connection_manager.h
// ~~~~~~~~~~~~~~~~~~~~~~
//
// Copyright (c) 2003-2008 Christopher M. Kohlhoff (chris at kohlhoff dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
#pragma once
#ifndef HTTP_CONNECTION_MANAGER_H
#define HTTP_CONNECTION_MANAGER_H

#include <set>
#include <map>
#include <string>
#include <vector>
#include <ctime>
#include "connection.h"

namespace http {
namespace server {

/// Manages open connections so that they may be cleanly stopped when the server
/// needs to shut down, and enforces the connection-count limits.
///
/// Threading: every method must be called from the io thread. connection::post_stop()
/// exists so that application threads never reach this class directly.
class connection_manager
{
public:
  connection_manager(const connection_manager&) = delete;
  connection_manager& operator=(const connection_manager&) = delete;
  connection_manager() = default;

  /// Configure the connection limits. Called once by server_base::init() before the
  /// acceptor is armed. A limit of 0 disables that particular check.
  ///
  /// NOTE on max_connections_per_ip: behind a reverse proxy every connection appears to
  /// come from the proxy's address, so a non-zero value there would throttle the whole
  /// server. It defaults to 0 for exactly that reason - see server_settings.
  void configure(size_t max_connections, size_t max_connections_per_ip,
      size_t max_body_bytes_in_flight, WebServerLogger logger);

  /// Addresses exempted from max_connections_per_ip -- see
  /// server_settings::trusted_proxy_addresses for the reasoning. Replaces any
  /// previously configured list. Safe to call at any point before or after
  /// configure(); both are set once by server_base::init() before the
  /// acceptor is armed.
  void set_trusted_proxy_addresses(const std::vector<std::string> &addresses);

  /// Add the specified connection to the manager and start it.
  /// If a limit would be exceeded the socket is closed and the connection is not started.
  void start(const connection_ptr &c);

  /// Stop the specified connection.
  void stop(const connection_ptr &c);

  /// Stop all connections.
  void stop_all();

  /// Number of connections currently being managed (diagnostics / tests).
  size_t count() const { return connections_.size(); }

  /// Reserve `bytes` from the server-wide in-flight-request-body budget (see
  /// server_settings::max_body_bytes_in_flight). Called from request_parser's
  /// body-admission callback (wired up in connection.cpp), once per request,
  /// the moment its Content-Length has been validated -- before any of that
  /// body has been read. Returns false (reserving nothing) if the budget has
  /// no room; the caller must then reject the request rather than let it
  /// proceed to read the body. 0 (the configured limit) disables the check,
  /// same convention as every other limit in this class. Must be called from
  /// the io thread, same as every other method here -- request parsing, like
  /// everything else that reaches this class, runs there.
  bool reserve_body_bytes(size_t bytes, const std::string &remote_address);

  /// Release `bytes` previously granted by reserve_body_bytes(), once that
  /// request's body has been fully received or its connection is torn down
  /// before that happens (see connection::stop()). Must balance exactly one
  /// reserve_body_bytes() call each; connection.cpp's body_bytes_reserved_
  /// member is what makes that pairing hold even when a connection is
  /// dropped mid-body.
  void release_body_bytes(size_t bytes);

  /// Current in-flight-request-body total (diagnostics / tests).
  size_t body_bytes_in_flight() const { return body_bytes_in_flight_; }

private:
  /// The managed connections.
  std::set<connection_ptr> connections_;
  /// Remote address recorded per connection at insert time. We cannot re-query the
  /// socket on the way out (it may already be closed), so the key used to increment
  /// per_ip_counts_ has to be remembered here in order to decrement the same one.
  std::map<connection*, std::string> connection_addresses_;
  /// Live connection count per remote address. Entries are erased when they reach
  /// zero so this map cannot grow without bound.
  std::map<std::string, size_t> per_ip_counts_;

  size_t max_connections_{ 0 };
  size_t max_connections_per_ip_{ 0 };
  /// See set_trusted_proxy_addresses() above / server_settings::trusted_proxy_addresses.
  /// A set rather than the input vector for O(log n) lookup per accepted connection.
  std::set<std::string> trusted_proxy_addresses_;

  /// Configured budget backing reserve_body_bytes()/release_body_bytes() above.
  /// 0 = unlimited. See server_settings::max_body_bytes_in_flight.
  size_t max_body_bytes_in_flight_{ 0 };
  /// Running total currently reserved. Never touched outside the io thread,
  /// same as every other member here, so no lock is needed.
  size_t body_bytes_in_flight_{ 0 };

  WebServerLogger m_logger;

  /// Log a refused connection, at most once per kRefusalLogInterval seconds.
  /// A connection flood is exactly the situation where these limits engage, so an
  /// unthrottled log line per refusal would let the attacker drive our disk I/O and
  /// fill the log - amplifying the very attack the limit is there to stop.
  void log_refusal(const char *what, const std::string &remote_address, size_t limit);
  static constexpr time_t kRefusalLogInterval = 60;
  time_t last_refusal_log_{ 0 };
  size_t refusals_since_log_{ 0 };
};

} // namespace server
} // namespace http

#endif // HTTP_CONNECTION_MANAGER_H
