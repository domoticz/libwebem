//
// request_parser.h
// ~~~~~~~~~~~~~~~~~~
//
// Copyright (c) 2003-2008 Christopher M. Kohlhoff (chris at kohlhoff dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
#pragma once
#ifndef HTTP_REQUEST_PARSER_H
#define HTTP_REQUEST_PARSER_H

#include <boost/logic/tribool.hpp>
#include <boost/tuple/tuple.hpp>
#include <cstddef>
#include <functional>

namespace http {
namespace server {

class request;

/// Parser for incoming requests.
class request_parser
{
public:
  /// Construct ready to parse the request method.
  request_parser() = default;

  /// Reset to initial parser state.
  void reset();

  /// Why the most recent consume() returned false, so the caller can pick the
  /// right HTTP status. A parser failure is a 400 in every case except a
  /// Transfer-Encoding header, which is a 501 because chunked decoding is not
  /// implemented -- accepting the header without decoding it is what makes
  /// TE.CL / CL.TE smuggling possible in the first place -- and the size
  /// limits, which each map to the status that names the part actually
  /// breached.
  ///
  /// The size limits are deliberately NOT one shared reason. A client that
  /// uploads a file too large for the configured body cap and is told "431
  /// Request Header Fields Too Large" cannot act on that: it will go looking
  /// at its headers. Worse, a caller that retries on 503 but gives up on 413
  /// needs the aggregate-budget case -- which is transient and worth retrying
  /// -- kept apart from the per-request cap, which is not.
  enum class reject_reason
  {
    none,
    bad_request,
    not_implemented,
    /// Request line, header count, single header, or the header block as a
    /// whole exceeded its limit. -> 431.
    header_too_large,
    /// The URI alone exceeded max_request_line_length. -> 414.
    uri_too_long,
    /// The declared Content-Length exceeded kMaxContentLength or the
    /// configured max_request_body_size. -> 413.
    body_too_large,
    /// The body would have fit, but the server-wide in-flight-body budget
    /// (max_body_bytes_in_flight) had no room for it right now. Transient and
    /// not the client's fault, so it is the one size breach that is retryable.
    /// -> 503.
    body_budget_exhausted
  };

  /// Valid to call once consume()/parse() has returned false; meaningless otherwise.
  reject_reason last_reject_reason() const { return reject_reason_; }

  /// Upper bound on a request body (Content-Length), enforced in the
  /// expecting_newline_3 case in request_parser.cpp. Not one of the
  /// configurable limits below: unlike the header-block limits, a legitimate
  /// large upload needs this to stay generous, so it is a fixed constant
  /// rather than something a Raspberry Pi deployment would want to shrink.
  /// Exposed so connection.h can size its receive buffer to hold one whole
  /// request (header block + body) without allowing unbounded growth.
  static constexpr long kMaxContentLength = 100L * 1024 * 1024; // 100 MB max

  /// Default per-request body cap. Defined here, next to the ceiling it must
  /// stay under, and referenced by server_settings::max_request_body_size so
  /// the two cannot drift apart: the parser's own member default is what a
  /// default-constructed parser enforces (unit tests, and any caller that
  /// never calls set_max_request_body_size), while server_settings is what a
  /// real server pushes into it. When those disagreed, a size accepted by the
  /// server was rejected by a directly-driven parser -- see the 75 MB restore
  /// test in tests/test_http_framing.cpp, which is what caught it.
  static constexpr size_t kDefaultMaxRequestBodySize = 100u * 1024 * 1024;
  static_assert(static_cast<long>(kDefaultMaxRequestBodySize) <= kMaxContentLength,
                "the default body cap cannot exceed the fixed ceiling it sits under");

  /// Configure the size limits enforced while parsing. Defaults (set as
  /// member initializers below) match server_settings' defaults, so a parser
  /// used without an explicit call -- e.g. in unit tests -- still enforces
  /// sane bounds rather than the SIZE_MAX a default-constructed parser would
  /// otherwise allow. 0 disables the corresponding limit, consistent with
  /// the rest of server_settings' resource limits.
  void set_limits(size_t max_request_line_length, size_t max_header_length,
      size_t max_header_count, size_t max_request_size);

  /// Configure the per-request body cap (see server_settings::max_request_body_size).
  /// Checked against the declared Content-Length in the expecting_newline_3 case,
  /// alongside (and tighter than) the fixed kMaxContentLength ceiling above.
  /// 0 disables this check, leaving kMaxContentLength as the only bound.
  void set_max_request_body_size(size_t max_request_body_size) { max_request_body_size_ = max_request_body_size; }

  /// Install a callback consulted exactly once per request that declares a
  /// non-empty body, at the point its Content-Length has just been validated
  /// and the parser is about to start reading that body (state_ ->
  /// reading_content) -- before a single byte of it has been buffered for
  /// this request. Receives the declared content length; returning false
  /// rejects the request (reject_reason::body_budget_exhausted, which the
  /// connection layer answers with a retryable 503 rather than the 413 a
  /// genuinely oversized body gets) instead of proceeding to read it.
  ///
  /// This is how connection.cpp wires in connection_manager's server-wide
  /// in-flight-body-bytes budget (server_settings::max_body_bytes_in_flight):
  /// the parser itself has no notion of "other connections", so the actual
  /// admission decision -- and, on success, reserving the bytes -- happens
  /// inside the callback the caller supplies; this class only guarantees
  /// exactly when it is invoked. Left unset (the default), no such check is
  /// performed, which is what every direct/unit-test use of this class
  /// (constructing a request_parser without going through connection) gets.
  void set_body_admission_check(std::function<bool(long content_length)> check) { body_admission_check_ = std::move(check); }

  /// Bytes of the current request's header block processed so far (see
  /// bytes_consumed_ below). Exposed read-only for diagnostics and for tests
  /// that verify parsing genuinely resumes across calls instead of
  /// re-walking bytes it has already seen.
  size_t bytes_consumed() const { return bytes_consumed_; }

  /// Parse some data. The tribool return value is true when a complete request
  /// has been parsed, false if the data is invalid, indeterminate when more
  /// data is required. The InputIterator return value indicates how much of the
  /// input has been consumed.
  template <typename InputIterator>
  boost::tuple<boost::tribool, InputIterator> parse(request& req,
      InputIterator& begin, InputIterator end)
  {
	  while ( begin != end)
	  {
		  InputIterator before = begin;
		  boost::tribool result = consume(req, begin, end);

		  if (result || !result) {
			  return { result, begin };
		  }
		  // consume() returned indeterminate without moving begin: it saw
		  // some input but ruled that it is not enough to make progress
		  // (currently only reading_content, waiting for the rest of a body
		  // that has not arrived yet) rather than having consumed a byte and
		  // asked for more. That is this function's "need more data" signal
		  // and the loop's termination condition -- calling consume() again
		  // with identical arguments would just repeat the same answer
		  // forever, so stop and hand back to the caller instead of spinning.
		  if (begin == before) {
			  break;
		  }
	  }
	  boost::tribool result = boost::indeterminate;
	  return { result, begin };
  }


private:
  /// Handle the next character of input.
  boost::tribool consume(request& req, const char* &input, const char *end);

  /// Check if a byte is an HTTP character.
  static bool is_char(int c);

  /// Check if a byte is an HTTP control character.
  static bool is_ctl(int c);

  /// Check if a byte is defined as an HTTP tspecial character.
  static bool is_tspecial(int c);

  /// Check if a byte is a digit.
  static bool is_digit(int c);

  /// The current state of the parser.
  enum state
  {
	  method_start,
	  method,
	  uri_start,
	  uri,
	  http_version_h,
	  http_version_t_1,
	  http_version_t_2,
	  http_version_p,
	  http_version_slash,
	  http_version_major_start,
	  http_version_major,
	  http_version_minor_start,
	  http_version_minor,
	  expecting_newline_1,
	  header_line_start,
	  header_name,
	  space_before_header_value,
	  header_value,
	  expecting_newline_2,
	  expecting_newline_3,
	  reading_content
  } state_{ method_start };

  reject_reason reject_reason_{ reject_reason::none };

  // ---- Size limits (DoS mitigation) --------------------------------------
  // Bound what a single request's header block can make the server allocate
  // and how long re-synchronizing after a bad request can take. Defaults are
  // sized for a Raspberry Pi deployment. 0 = unlimited.

  /// Caps req.uri.size() in the `uri` state. The request line's method and
  /// HTTP version are already tightly constrained by the state machine, so
  /// only the URI needs an explicit cap here.
  size_t max_request_line_length_{ 8 * 1024 };

  /// Caps the combined name+value length of the header currently being
  /// parsed, checked in the `header_name` and `header_value` states.
  size_t max_header_length_{ 8 * 1024 };

  /// Caps req.headers.size(), checked in `header_line_start` before a new
  /// header is pushed.
  size_t max_header_count_{ 100 };

  /// Caps the running total of bytes consumed for the current request's
  /// header block (request line plus all header lines, up to and including
  /// the blank line that ends them). The body is bounded separately by
  /// kMaxContentLength above.
  size_t max_request_size_{ 64 * 1024 };

  /// Running total backing max_request_size_ above; counts every byte
  /// consumed while state_ != reading_content. Reset in reset().
  size_t bytes_consumed_{ 0 };

  /// Per-request body cap; see set_max_request_body_size() above. Shares its
  /// default with server_settings::max_request_body_size via the constant
  /// above rather than repeating the number, which is how the two previously
  /// drifted apart.
  size_t max_request_body_size_{ kDefaultMaxRequestBodySize };

  /// See set_body_admission_check() above. Unset by default.
  std::function<bool(long content_length)> body_admission_check_;
};

} // namespace server
} // namespace http

#endif // HTTP_REQUEST_PARSER_H
