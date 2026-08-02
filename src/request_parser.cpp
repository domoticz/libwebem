//
// request_parser.cpp
// ~~~~~~~~~~~~~~~~~~
//
// Copyright (c) 2003-2008 Christopher M. Kohlhoff (chris at kohlhoff dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
#include "webem_stdafx.h"
#include <libwebem/request_parser.h>
#include <libwebem/request.h>
#include <algorithm>
#include <cstdlib>
#include <limits>

namespace http {
namespace server {

void request_parser::reset()
{
  state_ = method_start;
  reject_reason_ = reject_reason::none;
  bytes_consumed_ = 0;
}

void request_parser::set_limits(size_t max_request_line_length, size_t max_header_length,
    size_t max_header_count, size_t max_request_size)
{
  max_request_line_length_ = max_request_line_length;
  max_header_length_ = max_header_length;
  max_header_count_ = max_header_count;
  max_request_size_ = max_request_size;
}

boost::tribool request_parser::consume(request& req, const char* &pInput, const char *end)
{
  if (state_ != reading_content)
  {
    // Bounds the header block independently of the body, which has its own
    // cap (kMaxContentLength) applied once Content-Length is known. Checked
    // before the byte below is consumed, so a breach is caught before it
    // grows anything further.
    if (max_request_size_ && bytes_consumed_ >= max_request_size_)
    {
      reject_reason_ = reject_reason::header_too_large;
      return false;
    }
    ++bytes_consumed_;
  }
  char input = *pInput++;
  switch (state_)
  {
  case method_start:
    if (!is_char(input) || is_ctl(input) || is_tspecial(input))
    {
      reject_reason_ = reject_reason::bad_request;
      return false;
    }
    else
    {
      state_ = method;
      req.method.push_back(input);
      return boost::indeterminate;
    }
  case method:
    if (input == ' ')
    {
      state_ = uri;
      return boost::indeterminate;
    }
    else if (!is_char(input) || is_ctl(input) || is_tspecial(input))
    {
      reject_reason_ = reject_reason::bad_request;
      return false;
    }
    else
    {
      req.method.push_back(input);
      return boost::indeterminate;
    }
  case uri_start:
    if (is_ctl(input))
    {
      reject_reason_ = reject_reason::bad_request;
      return false;
    }
    else
    {
      state_ = uri;
      req.uri.push_back(input);
      return boost::indeterminate;
    }
  case uri:
    if (input == ' ')
    {
      state_ = http_version_h;
      return boost::indeterminate;
    }
    else if (is_ctl(input))
    {
      reject_reason_ = reject_reason::bad_request;
      return false;
    }
    else if (max_request_line_length_ && req.uri.size() >= max_request_line_length_)
    {
      reject_reason_ = reject_reason::uri_too_long;
      return false;
    }
    else
    {
      req.uri.push_back(input);
      return boost::indeterminate;
    }
  case http_version_h:
    if (input == 'H')
    {
      state_ = http_version_t_1;
      return boost::indeterminate;
    }
    else
    {
      reject_reason_ = reject_reason::bad_request;
      return false;
    }
  case http_version_t_1:
    if (input == 'T')
    {
      state_ = http_version_t_2;
      return boost::indeterminate;
    }
    else
    {
      reject_reason_ = reject_reason::bad_request;
      return false;
    }
  case http_version_t_2:
    if (input == 'T')
    {
      state_ = http_version_p;
      return boost::indeterminate;
    }
    else
    {
      reject_reason_ = reject_reason::bad_request;
      return false;
    }
  case http_version_p:
    if (input == 'P')
    {
      state_ = http_version_slash;
      return boost::indeterminate;
    }
    else
    {
      reject_reason_ = reject_reason::bad_request;
      return false;
    }
  case http_version_slash:
    if (input == '/')
    {
      req.http_version_major = 0;
      req.http_version_minor = 0;
      state_ = http_version_major_start;
      return boost::indeterminate;
    }
    else
    {
      reject_reason_ = reject_reason::bad_request;
      return false;
    }
  case http_version_major_start:
    if (is_digit(input))
    {
      req.http_version_major = req.http_version_major * 10 + input - '0';
      state_ = http_version_major;
      return boost::indeterminate;
    }
    else
    {
      reject_reason_ = reject_reason::bad_request;
      return false;
    }
  case http_version_major:
    if (input == '.')
    {
      state_ = http_version_minor_start;
      return boost::indeterminate;
    }
    else if (is_digit(input))
    {
      req.http_version_major = req.http_version_major * 10 + input - '0';
      return boost::indeterminate;
    }
    else
    {
      reject_reason_ = reject_reason::bad_request;
      return false;
    }
  case http_version_minor_start:
    if (is_digit(input))
    {
      req.http_version_minor = req.http_version_minor * 10 + input - '0';
      state_ = http_version_minor;
      return boost::indeterminate;
    }
    else
    {
      reject_reason_ = reject_reason::bad_request;
      return false;
    }
  case http_version_minor:
    if (input == '\r')
    {
      state_ = expecting_newline_1;
      return boost::indeterminate;
    }
    else if (is_digit(input))
    {
      req.http_version_minor = req.http_version_minor * 10 + input - '0';
      return boost::indeterminate;
    }
    else
    {
      reject_reason_ = reject_reason::bad_request;
      return false;
    }
  case expecting_newline_1:
    if (input == '\n')
    {
      state_ = header_line_start;
      return boost::indeterminate;
    }
    else
    {
      reject_reason_ = reject_reason::bad_request;
      return false;
    }
  case header_line_start:
    if (input == '\r')
    {
      state_ = expecting_newline_3;
      return boost::indeterminate;
    }
    else if (!req.headers.empty() && (input == ' ' || input == '\t'))
    {
      // obs-fold (RFC 7230 SS3.2.4): a header continuation line, folded onto
      // the previous header by leading whitespace. This used to be accepted
      // and appended directly onto the previous header's value with no
      // separator inserted (see the removed header_lws state), so
      // "Content-Length: 1\r\n 0\r\n" silently became value "10" -- a value
      // no conforming intermediary would derive from the same bytes. A
      // front-end that either rejects obs-fold (most do) or that unfolds it
      // by inserting a space, per the RFC, before computing Content-Length
      // would desynchronise from this parser on a connection-reusing path:
      // the third request-smuggling primitive alongside the CL.CL and TE
      // cases already rejected below. obs-fold is deprecated and no real
      // client emits it, so refuse it outright rather than normalise it --
      // consistent with how Transfer-Encoding is rejected rather than
      // special-cased elsewhere in this parser.
      reject_reason_ = reject_reason::bad_request;
      return false;
    }
    else if (!is_char(input) || is_ctl(input) || is_tspecial(input))
    {
      reject_reason_ = reject_reason::bad_request;
      return false;
    }
    else if (max_header_count_ && req.headers.size() >= max_header_count_)
    {
      reject_reason_ = reject_reason::header_too_large;
      return false;
    }
    else
    {
      req.headers.push_back(header());
      req.headers.back().name.push_back(input);
      state_ = header_name;
      return boost::indeterminate;
    }
  case header_name:
    if (input == ':')
    {
      state_ = space_before_header_value;
      return boost::indeterminate;
    }
    else if (!is_char(input) || is_ctl(input) || is_tspecial(input))
    {
      reject_reason_ = reject_reason::bad_request;
      return false;
    }
    else if (max_header_length_ &&
        (req.headers.back().name.size() + req.headers.back().value.size()) >= max_header_length_)
    {
      reject_reason_ = reject_reason::header_too_large;
      return false;
    }
    else
    {
      req.headers.back().name.push_back(input);
      return boost::indeterminate;
    }
  case space_before_header_value:
    if (input == ' ')
    {
      state_ = header_value;
      return boost::indeterminate;
    }
    else
    {
      reject_reason_ = reject_reason::bad_request;
      return false;
    }
  case header_value:
    if (input == '\r')
    {
      state_ = expecting_newline_2;
      return boost::indeterminate;
    }
    else if (is_ctl(input))
    {
      reject_reason_ = reject_reason::bad_request;
      return false;
    }
    else if (max_header_length_ &&
        (req.headers.back().name.size() + req.headers.back().value.size()) >= max_header_length_)
    {
      reject_reason_ = reject_reason::header_too_large;
      return false;
    }
    else
    {
      req.headers.back().value.push_back(input);
      return boost::indeterminate;
    }
  case expecting_newline_2:
    if (input == '\n')
    {
      state_ = header_line_start;
      return boost::indeterminate;
    }
    else
    {
      reject_reason_ = reject_reason::bad_request;
      return false;
    }
  case expecting_newline_3:
	  if (input == '\n')
	  {
		  // Content-Length gates the body for every method, not just POST: leaving
		  // it unread for e.g. GET/DELETE would strand the declared body bytes in
		  // the connection buffer, where the next read re-parses them as a brand
		  // new request (request smuggling on any connection-reusing front-end).
		  req.content_length = 0;
		  bool have_content_length = false;
		  bool have_transfer_encoding = false;
		  for (auto &ph : req.headers)
		  {
			  std::string hname = ph.name;
			  std::transform(hname.begin(), hname.end(), hname.begin(), ::tolower);
			  if (hname == "transfer-encoding")
			  {
				  have_transfer_encoding = true;
			  }
			  else if (hname == "content-length")
			  {
				  // Parse strictly: reject non-numeric, negative, or out-of-range values.
				  // A negative/malformed length previously flowed into
				  // std::string(pInput, content_length) as a huge size_t -> crash (DoS).
				  const char *cl_cstr = ph.value.c_str();
				  char *cl_endp = nullptr;
				  long cl_parsed = std::strtol(cl_cstr, &cl_endp, 10);
				  // req.content_length is an int, so the cap enforced here must stay
				  // well below INT_MAX or the static_cast below could wrap; the
				  // static_assert makes that dependency explicit if the cap ever grows.
				  static_assert(kMaxContentLength <= std::numeric_limits<int>::max(),
					  "kMaxContentLength must fit in req.content_length (int) without overflow");
				  if (cl_endp == cl_cstr || *cl_endp != '\0' || cl_parsed < 0)
				  {
					  reject_reason_ = reject_reason::bad_request;
					  return false; // Request rejected - not a valid non-negative integer
				  }
				  if (cl_parsed > kMaxContentLength)
				  {
					  reject_reason_ = reject_reason::body_too_large;
					  return false; // Request rejected - body too large
				  }
				  // Tighter, configurable cap on top of the fixed ceiling above (see
				  // set_max_request_body_size / server_settings::max_request_body_size).
				  // kMaxContentLength bounds the absolute worst case a single connection
				  // could ever buffer; this is what a deployment actually wants to run
				  // with day to day, generous enough for a legitimate upload but far
				  // below that worst case.
				  if (max_request_body_size_ && cl_parsed > static_cast<long>(max_request_body_size_))
				  {
					  reject_reason_ = reject_reason::body_too_large;
					  return false; // Request rejected - body too large for the configured per-request cap
				  }
				  // A second Content-Length header that disagrees with the first is
				  // the CL.CL smuggling primitive: two framing lengths, and which one
				  // wins depends on which layer of a proxy chain you ask. There is no
				  // safe interpretation, so refuse the request outright rather than
				  // guessing. req.content_length already holds the value parsed from
				  // the first Content-Length header at this point (set below on the
				  // first pass), so this is a comparison against that already-stored
				  // value, not a re-derivation of it.
				  if (have_content_length && cl_parsed != req.content_length)
				  {
					  reject_reason_ = reject_reason::bad_request;
					  return false;
				  }
				  req.content_length = static_cast<int>(cl_parsed);
				  have_content_length = true;
			  }
		  }

		  // Transfer-Encoding decoding is not implemented, so a request carrying it
		  // can never be framed correctly here. Combined with Content-Length it is
		  // the other canonical desync primitive (TE.CL / CL.TE): a front-end and
		  // this parser could honour different headers and disagree on where the
		  // body ends, so that combination is a plain 400. Transfer-Encoding on its
		  // own is a 501: we understand the request, we just cannot decode it.
		  //
		  // This rejects the header outright regardless of its value, so
		  // "Transfer-Encoding: identity" -- which RFC 7230 permits as a no-op
		  // meaning "no encoding" -- is refused too. That is deliberate: real
		  // clients omit the header entirely rather than sending "identity", and
		  // refusing anything we cannot decode is the safe choice. Do not special-
		  // case "identity" through without re-examining that assumption --
		  // letting it pass without a decoder behind it reopens the desync this
		  // whole block exists to close.
		  if (have_transfer_encoding && have_content_length)
		  {
			  reject_reason_ = reject_reason::bad_request;
			  return false;
		  }
		  if (have_transfer_encoding)
		  {
			  reject_reason_ = reject_reason::not_implemented;
			  return false;
		  }

		  // check on content_length, we might be done already
		  if (req.content_length == 0)
		  {
			  return true;
		  }

		  // Server-wide, cross-connection budget of in-flight request-body bytes
		  // (see set_body_admission_check / server_settings::max_body_bytes_in_flight).
		  // Consulted here, once, and before a single byte of this request's body
		  // has been read: a per-connection cap alone (max_request_body_size_
		  // above) bounds one connection, but nothing stops many connections from
		  // each buffering up to that amount at the same time, so the aggregate
		  // needs its own check that spans all of them. The parser has no notion
		  // of "other connections" itself, so the actual admission decision -- and
		  // reserving the bytes on success -- lives in whatever callback the
		  // caller installed (connection.cpp wires this to connection_manager).
		  if (body_admission_check_ && !body_admission_check_(req.content_length))
		  {
			  reject_reason_ = reject_reason::body_budget_exhausted;
			  return false; // Request rejected - server-wide body budget exhausted
		  }

		  state_ = reading_content;
		  return boost::indeterminate;
	  }
	  reject_reason_ = reject_reason::bad_request;
	  return false;
  case reading_content:
	   // reset pInput to start value
	  pInput--;
	  // now we check if we have enough input
	  // end - pInput is a ptrdiff_t and req.content_length is an int already
	  // validated non-negative above, so the comparison is well-defined; end
	  // >= pInput always holds here because the caller only ever advances
	  // pInput up to end, never past it.
	  if ((end - pInput) < req.content_length) {
		// Not enough input yet. Do NOT advance pInput to end here: pInput is
		// this call's only record of where the body starts, and the caller
		// resumes the next call from whatever position we hand back (see
		// connection::handle_read's buf_parsed_offset_, or parse()'s own
		// InputIterator& begin above). Fast-forwarding to end would throw
		// that position away, so the next call -- seeing only its own
		// newly-arrived bytes between the old end and the new one -- could
		// never compare the *cumulative* body received so far against
		// content_length, and a body split across more than one read would
		// never be recognised as complete. Leaving pInput here means the
		// next call re-examines the whole body-so-far against a larger end.
		return boost::indeterminate;
	  }
	  // read all content
	  req.content = std::string(pInput, req.content_length);
	  // adjust input pointer past exactly the body, so a pipelined request
	  // immediately following it is not discarded along with the body
	  pInput += req.content_length;
	  // all good
	  return true;
  default:
    reject_reason_ = reject_reason::bad_request;
    return false;
  }
}

bool request_parser::is_char(int c)
{
  return ((c >= 0) && (c <= 127));
}

bool request_parser::is_ctl(int c)
{
  return ((c >= 0) && (c <= 31)) || (c == 127);
}

bool request_parser::is_tspecial(int c)
{
  switch (c)
  {
  case '(': case ')': case '<': case '>': case '@':
  case ',': case ';': case ':': case '\\': case '"':
  case '/': case '[': case ']': case '?': case '=':
  case '{': case '}': case ' ': case '\t':
    return true;
  default:
    return false;
  }
}

bool request_parser::is_digit(int c)
{
  return c >= '0' && c <= '9';
}



} // namespace server
} // namespace http
