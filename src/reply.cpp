//
// reply.cpp
// ~~~~~~~~~
//
// Copyright (c) 2003-2008 Christopher M. Kohlhoff (chris at kohlhoff dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
#include "webem_stdafx.h"
#include <libwebem/reply.h>
#include <libwebem/webem_utils.h>
#include "mime_types.h"
#include "utf.h"
#include <string>
#include <fstream>
#include <cstdint>
#include <boost/algorithm/string.hpp>

namespace http {
namespace server {

namespace status_strings {

	constexpr auto switching_protocols = "HTTP/1.1 101 Switching Protocols\r\n";
	constexpr auto download_file = "HTTP/1.1 102 Download File\r\n";
	constexpr auto ok = "HTTP/1.1 200 OK\r\n";
	constexpr auto created = "HTTP/1.1 201 Created\r\n";
	constexpr auto accepted = "HTTP/1.1 202 Accepted\r\n";
	constexpr auto no_content = "HTTP/1.1 204 No Content\r\n";
	constexpr auto multiple_choices = "HTTP/1.1 300 Multiple Choices\r\n";
	constexpr auto moved_permanently = "HTTP/1.1 301 Moved Permanently\r\n";
	constexpr auto moved_temporarily = "HTTP/1.1 302 Moved Temporarily\r\n";
	constexpr auto not_modified = "HTTP/1.1 304 Not Modified\r\n";
	constexpr auto bad_request = "HTTP/1.1 400 Bad Request\r\n";
	constexpr auto unauthorized = "HTTP/1.1 401 Unauthorized\r\n";
	constexpr auto forbidden = "HTTP/1.1 403 Forbidden\r\n";
	constexpr auto not_found = "HTTP/1.1 404 Not Found\r\n";
	constexpr auto method_not_allowed = "HTTP/1.1 405 Method Not Allowed\r\n";
	constexpr auto payload_too_large = "HTTP/1.1 413 Payload Too Large\r\n";
	constexpr auto uri_too_long = "HTTP/1.1 414 URI Too Long\r\n";
	constexpr auto request_header_fields_too_large = "HTTP/1.1 431 Request Header Fields Too Large\r\n";
	constexpr auto internal_server_error = "HTTP/1.1 500 Internal Server Error\r\n";
	constexpr auto not_implemented = "HTTP/1.1 501 Not Implemented\r\n";
	constexpr auto bad_gateway = "HTTP/1.1 502 Bad Gateway\r\n";
	constexpr auto service_unavailable = "HTTP/1.1 503 Service Unavailable\r\n";

	std::string to_string(const reply::status_type &status)
	{
		switch (status)
		{
			case reply::switching_protocols:
				return switching_protocols;
			case reply::download_file:
				return download_file;
			case reply::ok:
				return ok;
			case reply::created:
				return created;
			case reply::accepted:
				return accepted;
			case reply::no_content:
				return no_content;
			case reply::multiple_choices:
				return multiple_choices;
			case reply::moved_permanently:
				return moved_permanently;
			case reply::moved_temporarily:
				return moved_temporarily;
			case reply::not_modified:
				return not_modified;
			case reply::bad_request:
				return bad_request;
			case reply::unauthorized:
				return unauthorized;
			case reply::forbidden:
				return forbidden;
			case reply::not_found:
				return not_found;
			case reply::method_not_allowed:
				return method_not_allowed;
			case reply::payload_too_large:
				return payload_too_large;
			case reply::uri_too_long:
				return uri_too_long;
			case reply::request_header_fields_too_large:
				return request_header_fields_too_large;
			case reply::internal_server_error:
				return internal_server_error;
			case reply::not_implemented:
				return not_implemented;
			case reply::bad_gateway:
				return bad_gateway;
			case reply::service_unavailable:
				return service_unavailable;
			default:
				return internal_server_error;
		}
}

} // namespace status_strings

namespace misc_strings {

	constexpr char name_value_separator[] = { ':', ' ', 0 };
	constexpr char crlf[] = { '\r', '\n', 0 };

} // namespace misc_strings

namespace {

	// set_content_from_file() buffers the whole file into rep->content in memory, so an
	// upper bound is needed independent of what tellg() reports. 512 MiB comfortably
	// covers any legitimate static asset or download libwebem is expected to serve
	// in-memory, while still ruling out accidentally reading a multi-GB or unbounded
	// (e.g. non-seekable) source into a single std::string.
	// Kept at this (anonymous-namespace, module) scope rather than inside the
	// function because it is a library-wide bound: every caller of
	// set_content_from_file() is subject to the same limit, not a
	// per-call-site parameter.
	constexpr uintmax_t MAX_REPLY_FILE_SIZE = 512ULL * 1024 * 1024;

} // namespace

std::string reply::header_to_string()
{
	std::string buffers = status_strings::to_string(status);
	for (const auto &h : headers)
		buffers += h.name + misc_strings::name_value_separator + h.value + misc_strings::crlf;

	buffers += misc_strings::crlf;
	return buffers;
}

std::string reply::to_string(const std::string &method)
{
	std::string buffers = header_to_string();
	if (method != "HEAD") {
		buffers += content;
	}
	return buffers;
}

void reply::reset()
{
	headers.clear();
	content = "";
	bIsGZIP = false;
	ws_session = WebEmSession{};
}

namespace stock_replies {

	constexpr auto switching_protocols = "";
	constexpr auto download_file = "";
	constexpr auto ok = "";
	constexpr auto created = "<html>"
				 "<head><title>Created</title></head>"
				 "<body><h1>201 Created</h1></body>"
				 "</html>";
	constexpr auto accepted = "<html>"
				  "<head><title>Accepted</title></head>"
				  "<body><h1>202 Accepted</h1></body>"
				  "</html>";
	constexpr auto no_content = ""; // The 204 response MUST NOT contain a message-body
	constexpr auto multiple_choices = "<html>"
					  "<head><title>Multiple Choices</title></head>"
					  "<body><h1>300 Multiple Choices</h1></body>"
					  "</html>";
	constexpr auto moved_permanently = "<html>"
					   "<head><title>Moved Permanently</title></head>"
					   "<body><h1>301 Moved Permanently</h1></body>"
					   "</html>";
	constexpr auto moved_temporarily = "<html>"
					   "<head><title>Moved Temporarily</title></head>"
					   "<body><h1>302 Moved Temporarily</h1></body>"
					   "</html>";
	constexpr auto not_modified = ""; // The 304 response MUST NOT contain a message-body
	constexpr auto bad_request = "<html>"
				     "<head><title>Bad Request</title></head>"
				     "<body><h1>400 Bad Request</h1></body>"
				     "</html>";
	constexpr auto unauthorized = "<html>"
				      "<head><title>Unauthorized</title></head>"
				      "<body><h1>401 Unauthorized</h1></body>"
				      "</html>";
	constexpr auto forbidden = "<html>"
				   "<head><title>Forbidden</title></head>"
				   "<body><h1>403 Forbidden</h1></body>"
				   "</html>";
	constexpr auto not_found = "<html>"
				   "<head><title>Not Found</title></head>"
				   "<body><h1>404 Not Found</h1></body>"
				   "</html>";
	constexpr auto method_not_allowed = "<html>"
				   "<head><title>Method Not Allowed</title></head>"
				   "<body><h1>405 Method Not Allowed</h1></body>"
				   "</html>";
	constexpr auto payload_too_large = "<html>"
				   "<head><title>Payload Too Large</title></head>"
				   "<body><h1>413 Payload Too Large</h1></body>"
				   "</html>";
	constexpr auto uri_too_long = "<html>"
				   "<head><title>URI Too Long</title></head>"
				   "<body><h1>414 URI Too Long</h1></body>"
				   "</html>";
	constexpr auto request_header_fields_too_large = "<html>"
				   "<head><title>Request Header Fields Too Large</title></head>"
				   "<body><h1>431 Request Header Fields Too Large</h1></body>"
				   "</html>";
	constexpr auto internal_server_error = "<html>"
					       "<head><title>Internal Server Error</title></head>"
					       "<body><h1>500 Internal Server Error</h1></body>"
					       "</html>";
	constexpr auto not_implemented = "<html>"
					 "<head><title>Not Implemented</title></head>"
					 "<body><h1>501 Not Implemented</h1></body>"
					 "</html>";
	constexpr auto bad_gateway = "<html>"
				     "<head><title>Bad Gateway</title></head>"
				     "<body><h1>502 Bad Gateway</h1></body>"
				     "</html>";
	constexpr auto service_unavailable = "<html>"
					     "<head><title>Service Unavailable</title></head>"
					     "<body><h1>503 Service Unavailable</h1></body>"
					     "</html>";

	std::string to_string(const reply::status_type &status)
	{
		switch (status)
		{
			case reply::switching_protocols:
				return switching_protocols;
			case reply::download_file:
				return download_file;
			case reply::ok:
				return ok;
			case reply::created:
				return created;
			case reply::accepted:
				return accepted;
			case reply::no_content:
				return no_content;
			case reply::multiple_choices:
				return multiple_choices;
			case reply::moved_permanently:
				return moved_permanently;
			case reply::moved_temporarily:
				return moved_temporarily;
			case reply::not_modified:
				return not_modified;
			case reply::bad_request:
				return bad_request;
			case reply::unauthorized:
				return unauthorized;
			case reply::forbidden:
				return forbidden;
			case reply::not_found:
				return not_found;
			case reply::method_not_allowed:
				return method_not_allowed;
			case reply::payload_too_large:
				return payload_too_large;
			case reply::uri_too_long:
				return uri_too_long;
			case reply::request_header_fields_too_large:
				return request_header_fields_too_large;
			case reply::internal_server_error:
				return internal_server_error;
			case reply::not_implemented:
				return not_implemented;
			case reply::bad_gateway:
				return bad_gateway;
			case reply::service_unavailable:
				return service_unavailable;
			default:
				return internal_server_error;
		}
	}

} // namespace stock_replies

reply reply::stock_reply(reply::status_type status, bool addsecheaders, bool is_tls)
{
	reply rep;
	rep.status = status;
	rep.content = stock_replies::to_string(status);
	if (!rep.content.empty()) { // response can be empty (eg. HTTP 304)
		rep.headers.resize(2);
		rep.headers[0].name = "Content-Length";
		rep.headers[0].value = std::to_string(rep.content.size());
		rep.headers[1].name = "Content-Type";
		rep.headers[1].value = "text/html;charset=UTF-8";
	}
	if (addsecheaders)
		add_security_headers(&rep, is_tls);
	return rep;
}

void reply::add_security_headers(reply *rep, bool is_tls)
{
	if (is_tls)
		add_header(rep, "Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload", true);
	add_header(rep, "X-Content-Type-Options", "nosniff", true);
	add_header(rep, "Content-Security-Policy", "frame-ancestors 'self'", true);
	//add_header(rep, "X-XSS-Protection", "1; mode=block", true);	// obsolete thx to CSP
	//add_header(rep, "X-Frame-Options", "SAMEORIGIN", true);	// obsolete thx to CSP
}

void reply::add_cors_headers(reply *rep, const std::string &origin, const std::vector<std::string> &allowed_origins)
{
	// No Origin header, or nothing configured: send no CORS headers at all. That is
	// the correct default for a control API -- see the header-file comment.
	if (origin.empty())
		return;
	for (const auto &allowed : allowed_origins)
	{
		if (allowed == origin)
		{
			// Echo the exact origin, never "*": ACAO:* combined with an
			// IP/trusted-network authenticated session would let any site the
			// browser visits read the response.
			add_header(rep, "Access-Control-Allow-Origin", origin, true);
			add_header(rep, "Vary", "Origin", true);
			return;
		}
	}
}

void reply::add_header(reply *rep, const std::string &name, const std::string &value, bool replace)
{
	// A CR/LF in either the name or the value would be emitted verbatim by
	// header_to_string() and split the response, letting the caller inject
	// arbitrary further headers or body content (HTTP response splitting). Every
	// in-repo call site is built from static strings or values request_parser.cpp
	// already stripped of control characters before they ever reach here; if this
	// ever fires, the caller supplied a bad value and has a bug. Reject rather than
	// strip -- silently mangling the header would hide exactly the bug that needs
	// fixing. add_header returns void (a very widely called function, inside and
	// outside this repo), and this is a static function with no logger of its own
	// to report through, so drop the rejected header silently rather than write to
	// stderr: an application bug that calls add_header in a loop with a bad value
	// would otherwise flood a library-owned output stream the caller never asked
	// for and may not even control (stderr may be redirected, closed, or shared
	// with unrelated processes). Callers that can offer a better signal already
	// do -- add_header_attachment and set_download_file perform this same check
	// themselves and return false, which is the honest place for the caller to
	// learn about and handle the rejection.
	if (utils::contains_control_chars(name) || utils::contains_control_chars(value))
	{
		return;
	}

	size_t num = rep->headers.size();
	if (replace) {
		for (auto &h : rep->headers)
		{
			if (boost::iequals(h.name, name))
			{
				h.value = value;
				return;
			}
		}
	}
	rep->headers.resize(num + 1);
	rep->headers[num].name = name;
	rep->headers[num].value = value;
}

void reply::add_header_if_absent(reply *rep, const std::string &name, const std::string &value)
{
	for (const auto &h : rep->headers)
	{
		if (boost::iequals(h.name, name))
		{
			// is present
			return;
		}
	}
	add_header(rep, name, value, false);
}

void reply::set_content(reply *rep, const std::string &content)
{
	rep->content = content;
}

void reply::set_content(reply *rep, const std::wstring &content_w)
{
	cUTF utf( content_w.c_str() );
	rep->content.assign(utf.get8(), strlen(utf.get8()));
}

bool reply::set_content_from_file(reply *rep, const std::string &file_path)
{
	std::ifstream file(file_path.c_str(), std::ios::in | std::ios::binary);
	if (!file.is_open())
		return false;
	file.seekg(0, std::ios::end);
	std::streamoff len = file.tellg();
	// tellg() returns -1 for a non-seekable source (FIFO, character device, some
	// /proc entries); casting that to size_t would yield SIZE_MAX and make resize()
	// below throw. Reject it outright instead of guessing a size.
	if (len < 0)
		return false;
	// Compare in uintmax_t rather than size_t: defensive against a platform
	// where std::streamoff is wider than size_t, so the cast to size_t below
	// (once this check has passed) cannot itself have already truncated len.
	if (static_cast<uintmax_t>(len) > MAX_REPLY_FILE_SIZE)
		return false;
	size_t fileSize = static_cast<size_t>(len);
	if (fileSize > 0) {
		rep->content.resize(fileSize);
		file.seekg(0, std::ios::beg);
		file.read(&rep->content[0], rep->content.size());
	}
	file.close();
	return true;
}

bool reply::set_content_from_file(reply *rep, const std::string &file_path, const std::string &attachment, bool set_content_type)
{
	if (!reply::set_content_from_file(rep, file_path))
		return false;
	if (!reply::add_header_attachment(rep, attachment))
		return false;
	if (set_content_type == true) {
		std::size_t last_dot_pos = attachment.find_last_of('.');
		if (last_dot_pos != std::string::npos) {
			std::string file_extension = attachment.substr(last_dot_pos + 1);
			std::string mime_type = mime_types::extension_to_type(file_extension);
			reply::add_header_content_type(rep, mime_type);
		}
	}
	return true;
}

bool reply::set_download_file(reply* rep, const std::string& file_path, const std::string& attachment)
{
	if (file_path.empty() || attachment.empty())
		return false;
	// file_path and attachment are joined with "\r\n" as an internal delimiter, then
	// split apart again by connection.cpp's send_file dispatch, which takes
	// everything after the first CRLF as the attachment name. A CR/LF embedded in
	// either value would let the caller smuggle a second delimiter (or, once past
	// add_header_attachment downstream, split the Content-Disposition header
	// itself). Reject here, at the point the application supplies the value,
	// rather than deep in the write path.
	if (utils::contains_control_chars(file_path) || utils::contains_control_chars(attachment))
		return false;
	rep->reset();
	rep->status = reply::status_type::download_file;
	rep->content = file_path + "\r\n" + attachment;
	return true;
}

bool reply::add_header_attachment(reply *rep, const std::string &attachment)
{
	if (utils::contains_control_chars(attachment))
		return false;
	reply::add_header(rep, "Content-Disposition", "attachment; filename=" + attachment);
	return true;
}

/*
RFC-7231
Hypertext Transfer Protocol (HTTP/1.1): Semantics and Content
3.1.1.5. Content-Type

A sender that generates a message containing a payload body SHOULD
generate a Content-Type header field in that message unless the
intended media type of the enclosed representation is unknown to the
sender.
*/
void reply::add_header_content_type(reply *rep, const std::string & content_type) {
	if (!content_type.empty())
	{
		std::string charset = "";
		if (((content_type.find("text/") != std::string::npos) ||
			(content_type.find("/xml") != std::string::npos) ||
			(content_type.find("/javascript") != std::string::npos) ||
			(content_type.find("/json") != std::string::npos)) &&
			(content_type.find("charset") == std::string::npos)) {
			// Add charset on text content
			charset = ";charset=UTF-8";
		}
		reply::add_header(rep, "Content-Type", content_type + charset);
	}
}

} // namespace server
} // namespace http
