//
// test_download_leak_server.cpp
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// Server for test_download_leak.py, which exercises the 16 KB heap leak in
// connection::handle_write_file (send_buffer_.release() instead of .reset()).
// Every reply::download_file response allocates FILE_SEND_BUFFER_SIZE (16 KB)
// into connection::send_buffer_ on first use; before the fix that buffer was
// leaked -- deliberately, not accidentally -- on every single download,
// whether it completed normally or was aborted mid-transfer.
//
// The payload file is a few hundred KB so a client can abort partway through
// a multi-chunk transfer (matching the plan's verification recipe: "loop many
// download requests, aborting each after the first chunk").
//
#include <libwebem/cWebem.h>

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>

using namespace http::server;

namespace {
const char *kPayloadPath = "download_leak_test_payload.bin";
}

int main(int argc, char **argv)
{
	if (argc < 2)
	{
		std::fprintf(stderr, "usage: %s <port>\n", argv[0]);
		return 2;
	}

	server_settings settings;
	settings.listening_address = "127.0.0.1";
	settings.listening_port = argv[1];
	settings.server_name = "libwebem-download-leak-test/1.0";

	// ~512 KB: about 32 chunks of FILE_SEND_BUFFER_SIZE (16 KB), so an
	// "abort after the first chunk" client genuinely interrupts a multi-write
	// transfer instead of racing a single already-complete response.
	{
		std::ofstream f(kPayloadPath, std::ios::binary | std::ios::trunc);
		const std::string chunk(4096, 'x');
		for (int i = 0; i < 128; ++i)
			f.write(chunk.data(), static_cast<std::streamsize>(chunk.size()));
	}

	cWebem server(settings, "./www");

	// CheckAuthentication fails closed when the user table is empty (every
	// request would 500 before it even gets to the bypass-authentication
	// check below), so register one user. Password is the MD5 of "test".
	server.AddUserPassword(1, "test", "098f6bcd4621d373cade4e832627b4f6", "", "",
			       URIGHTS_ADMIN, 0);

	server.RegisterPageCode(
		"/api/download",
		[](WebEmSession &, const request &, reply &rep) {
			rep.status = reply::download_file;
			// handle_write_file splits this on the first "\r\n": filename,
			// then the attachment name to send back in Content-Disposition.
			rep.content = std::string(kPayloadPath) + "\r\n" + "payload.bin";
		},
		/*bypassAuthentication=*/true);

	server.RegisterPageCode(
		"/api/download-bad-attachment",
		[](WebEmSession &, const request &, reply &rep) {
			rep.status = reply::download_file;
			// Sets rep.status/rep.content directly instead of going through
			// reply::set_download_file(), the way application code manipulating
			// the public reply fields itself (rather than the exported setter)
			// could -- so the CRLF-laden attachment name below never passes
			// through set_download_file()'s own contains_control_chars() check.
			// connection::send_file()'s add_header_attachment() check is the
			// only thing left standing between this and a split response.
			rep.content = std::string(kPayloadPath) + "\r\n" + "a\r\nX-Injected: 1";
		},
		/*bypassAuthentication=*/true);

	std::printf("READY %s\n", settings.listening_port.c_str());
	std::fflush(stdout);

	server.Run();
	return 0;
}
