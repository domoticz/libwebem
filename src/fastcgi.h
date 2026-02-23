#pragma once
#ifndef HTTP_FASTCGI_H
#define HTTP_FASTCGI_H

#include <libwebem/request_handler.h>
#include <libwebem/IWebServerLogger.h>
#include <boost/logic/tribool.hpp>

#include <libwebem/reply.h>
#include <libwebem/request.h>
#include <libwebem/server_settings.h>


namespace http {
namespace server {

class fastcgi_parser
{
public:
	static bool handlePHP(const server_settings &settings, const std::string &script_path, const request &req, reply &rep, modify_info &mInfo, const WebServerLogger &logger = nullptr);
	static uint16_t request_id_;
};

} //namespace server
} //namespace http

#endif //HTTP_FASTCGI_H

