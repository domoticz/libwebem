# Unit tests for libwebem

add_executable(webem_tests test_security.cpp)

target_link_libraries(webem_tests PRIVATE webem)

# webem exposes Boost and OpenSSL via its PUBLIC link interface; the request
# parser template pulls in Boost headers directly.
find_package(Boost REQUIRED COMPONENTS thread)
target_link_libraries(webem_tests PRIVATE Boost::boost)

add_test(NAME webem_tests COMMAND webem_tests)

# Standalone unit-test executables, each with its own main() and lightweight
# CHECK harness in the style of test_security.cpp.
add_executable(webem_test_http_framing test_http_framing.cpp)
target_link_libraries(webem_test_http_framing PRIVATE webem Boost::boost)
add_test(NAME webem_test_http_framing COMMAND webem_test_http_framing)

add_executable(webem_test_session_lifetime test_session_lifetime.cpp)
target_link_libraries(webem_test_session_lifetime PRIVATE webem Boost::boost)
add_test(NAME webem_test_session_lifetime COMMAND webem_test_session_lifetime)

add_executable(webem_test_hash_and_reply test_hash_and_reply.cpp)
target_link_libraries(webem_test_hash_and_reply PRIVATE webem Boost::boost)
add_test(NAME webem_test_hash_and_reply COMMAND webem_test_hash_and_reply)

add_executable(webem_test_response_headers test_response_headers.cpp)
target_link_libraries(webem_test_response_headers PRIVATE webem Boost::boost)
add_test(NAME webem_test_response_headers COMMAND webem_test_response_headers)

# Regression test for the httpoxy class of bugs (CVE-2016-5385): a "Proxy:" request
# header must not become HTTP_PROXY in the PHP/CGI child's environment. Calls
# fastcgi_parser::handlePHP() directly, so it needs src/ (an internal, non-installed
# include directory of the webem target) on its include path for "fastcgi.h", and it
# needs WEBEM_ENABLE_FASTCGI -- handlePHP only exists when FastCGI support is built.
if(WEBEM_ENABLE_FASTCGI)
    add_executable(test_httpoxy_helper test_httpoxy_helper.cpp)

    add_executable(webem_test_httpoxy test_httpoxy.cpp)
    target_link_libraries(webem_test_httpoxy PRIVATE webem Boost::boost)
    target_include_directories(webem_test_httpoxy PRIVATE ${CMAKE_SOURCE_DIR}/src)
    add_test(NAME webem_test_httpoxy
        COMMAND webem_test_httpoxy $<TARGET_FILE:test_httpoxy_helper>)
else()
    message(STATUS "webem tests: WEBEM_ENABLE_FASTCGI is OFF -- webem_test_httpoxy "
                    "(httpoxy / CVE-2016-5385 regression) will not be registered with ctest.")
endif()

# Configurable server used by test_connection_limits.py to exercise the
# connection resource limits against a real listening socket.
add_executable(test_connection_limits_server test_connection_limits_server.cpp)
target_link_libraries(test_connection_limits_server PRIVATE webem Boost::boost)

# Server used by test_proxy_trust.py. Trusts the loopback address, reproducing the
# reverse-proxy-on-localhost deployment where a forged forwarded-for header would
# otherwise buy administrative access.
add_executable(test_proxy_trust_server test_proxy_trust_server.cpp)
target_link_libraries(test_proxy_trust_server PRIVATE webem Boost::boost)

# Server used by test_auth_hardening.py. A single malformed Authorization header
# used to be able to throw an uncaught exception out of parse_auth_header's JWT
# branch (or hit undefined behaviour on an empty "aud" array) and take the
# webserver thread down; this proves malformed tokens are now rejected instead.
add_executable(test_auth_hardening_server test_auth_hardening_server.cpp)
target_link_libraries(test_auth_hardening_server PRIVATE webem Boost::boost)

# Server used by test_auth_bypass.py. The API command whitelist used to be
# judged by a raw-URI substring search for "?param=" / "&param=" while the page
# handler dispatched on the tokenised request::parameters; a whitelisted
# command name planted inside another parameter's value granted the bypass for
# a request that then ran a protected command. Both now read the same parsed set.
add_executable(test_auth_bypass_server test_auth_bypass_server.cpp)
target_link_libraries(test_auth_bypass_server PRIVATE webem Boost::boost)

# Server used by test_download_leak.py. Every reply::download_file response used
# to leak connection::send_buffer_ (16 KB) via a unique_ptr::release() instead of
# ::reset() in handle_write_file -- on completion AND on an aborted transfer.
add_executable(test_download_leak_server test_download_leak_server.cpp)
target_link_libraries(test_download_leak_server PRIVATE webem Boost::boost)

# Server used by test_ws_write_race.py. Stress-exercises WS_Write() being called
# from an application thread (the documented writer-callback pattern) while the
# io thread tears the same connection down -- the socket concurrency finding
# fixed by giving connection a strand (see connection.h's strand_ member).
add_executable(test_ws_write_race_server test_ws_write_race_server.cpp)
target_link_libraries(test_ws_write_race_server PRIVATE webem Boost::boost)

# Server used by test_cors.py. Trusts the loopback address, the same
# reverse-proxy-on-localhost deployment shape as test_proxy_trust_server.cpp, so
# every request arrives already carrying admin rights with no cookie -- exactly
# the deployment finding #15 is about. Proves CORS headers on API/page responses
# no longer default to "*", that a configured allow-list origin is echoed
# exactly, that static assets are unaffected, and that a WebSocket upgrade with a
# foreign Origin is rejected for a trusted-network-authenticated session.
add_executable(test_cors_server test_cors_server.cpp)
target_link_libraries(test_cors_server PRIVATE webem Boost::boost)

# Server used by test_dns_rebinding.py. Same trusted-loopback deployment shape as
# test_cors_server.cpp, plus server_settings::allowed_hosts configured. Proves an
# attacker-controlled hostname reaching this server via DNS rebinding (Host and
# Origin both naming a hostname not in allowed_hosts) is rejected -- for a plain
# request and for a WebSocket upgrade -- rather than trivially "matching itself".
add_executable(test_dns_rebinding_server test_dns_rebinding_server.cpp)
target_link_libraries(test_dns_rebinding_server PRIVATE webem Boost::boost)

# Server used by test_initial_request_timeout.py. Exercises
# server_settings::initial_request_timeout: a connection that never completes its
# first HTTP request -- whether silent or trickling one byte at a time, which
# would keep resetting the ordinary read_timeout indefinitely -- must be dropped
# near this bound instead of holding a global connection slot for the life of
# read_timeout or the 20-minute abandoned-connection timeout.
add_executable(test_initial_request_timeout_server test_initial_request_timeout_server.cpp)
target_link_libraries(test_initial_request_timeout_server PRIVATE webem Boost::boost)

# Integration tests: each Python driver launches its own server binary over a
# loopback TCP port and exercises it from outside the process, so they cover
# things the in-process unit tests structurally cannot (real accept()/socket
# teardown races, actual process memory growth, TCP-level framing). Registered
# with ctest so "run everything" is one command instead of someone having to
# know which driver pairs with which server binary.
#
# $<TARGET_FILE:...> resolves to the built executable regardless of build
# directory, generator or configuration (Debug/Release subdirectory on
# multi-config generators), so these work the same way the *_server targets
# above are built.
find_package(Python3 COMPONENTS Interpreter QUIET)
if(Python3_Interpreter_FOUND)
    function(webem_add_python_test name script server_target)
        add_test(NAME ${name}
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/${script} $<TARGET_FILE:${server_target}>)
        # Generous but finite: these are stress/soak drivers (connection floods,
        # a multi-second WebSocket race storm); a regression that hangs the
        # server should show up as a ctest timeout, not block the run forever.
        set_tests_properties(${name} PROPERTIES TIMEOUT 300)
    endfunction()

    webem_add_python_test(test_connection_limits  test_connection_limits.py  test_connection_limits_server)
    webem_add_python_test(test_proxy_trust        test_proxy_trust.py       test_proxy_trust_server)
    webem_add_python_test(test_accept_resilience  test_accept_resilience.py test_connection_limits_server)
    webem_add_python_test(test_auth_hardening     test_auth_hardening.py    test_auth_hardening_server)
    webem_add_python_test(test_auth_bypass        test_auth_bypass.py       test_auth_bypass_server)
    webem_add_python_test(test_download_leak      test_download_leak.py     test_download_leak_server)
    webem_add_python_test(test_cors               test_cors.py              test_cors_server)
    webem_add_python_test(test_ws_write_race      test_ws_write_race.py     test_ws_write_race_server)
    webem_add_python_test(test_dns_rebinding             test_dns_rebinding.py             test_dns_rebinding_server)
    webem_add_python_test(test_initial_request_timeout   test_initial_request_timeout.py   test_initial_request_timeout_server)
else()
    message(STATUS "webem tests: Python 3 interpreter not found -- the 10 Python-driven "
                    "integration tests (test_connection_limits, test_proxy_trust, "
                    "test_accept_resilience, test_auth_hardening, test_auth_bypass, test_download_leak, "
                    "test_cors, test_ws_write_race, test_dns_rebinding, "
                    "test_initial_request_timeout) will not be registered with ctest. "
                    "Install Python 3 and re-run cmake to enable them.")
endif()

# TLS handshake timeout: a client that completes the TCP connection but never
# sends a TLS ClientHello must be dropped near tls_handshake_timeout rather
# than held open (previously bounded only by the 20-minute abandoned-
# connection timeout). Needs a real listening HTTPS server, so this needs a
# self-signed certificate -- generated once at configure time below -- on top
# of the same Python3 requirement as the other integration tests above.
if(WEBEM_ENABLE_SSL AND Python3_Interpreter_FOUND)
    # On Windows, openssl.exe is frequently not on PATH inside a plain MSVC
    # dev shell (it never ships with Visual Studio) even when it is present
    # on disk -- Git for Windows bundles its own, so it is a common install
    # to fall back to.
    find_program(WEBEM_OPENSSL_EXECUTABLE openssl
        HINTS "C:/Program Files/Git/mingw64/bin" "C:/Program Files/Git/usr/bin")
    if(WEBEM_OPENSSL_EXECUTABLE)
        set(_webem_tls_cert_dir ${CMAKE_CURRENT_BINARY_DIR}/tls_handshake_timeout_certs)
        file(MAKE_DIRECTORY ${_webem_tls_cert_dir})
        set(_webem_tls_cert ${_webem_tls_cert_dir}/server.crt)
        set(_webem_tls_key  ${_webem_tls_cert_dir}/server.key)
        if(NOT EXISTS ${_webem_tls_cert} OR NOT EXISTS ${_webem_tls_key})
            # No DH params: tmp_dh_file_path left empty is a supported,
            # logged-but-non-fatal configuration (see ssl_server::init() in
            # server.cpp), and this test never negotiates a DHE suite on
            # purpose -- it never completes a handshake at all.
            execute_process(
                COMMAND ${WEBEM_OPENSSL_EXECUTABLE} req -new -x509 -newkey rsa:2048
                        -keyout ${_webem_tls_key} -out ${_webem_tls_cert}
                        -days 3650 -nodes -subj "/CN=127.0.0.1"
                RESULT_VARIABLE _webem_tls_cert_rc
                OUTPUT_QUIET ERROR_QUIET)
            if(NOT _webem_tls_cert_rc EQUAL 0)
                message(STATUS "webem tests: found openssl but self-signed certificate generation "
                                "failed -- test_tls_handshake_timeout will not be registered.")
                set(WEBEM_OPENSSL_EXECUTABLE "")
            endif()
        endif()
    else()
        message(STATUS "webem tests: openssl executable not found -- test_tls_handshake_timeout "
                        "(TLS handshake timeout regression) will not be registered with ctest. "
                        "Install openssl and re-run cmake to enable it.")
    endif()

    if(WEBEM_OPENSSL_EXECUTABLE)
        add_executable(test_tls_handshake_timeout_server test_tls_handshake_timeout_server.cpp)
        target_link_libraries(test_tls_handshake_timeout_server PRIVATE webem Boost::boost)

        add_test(NAME test_tls_handshake_timeout
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test_tls_handshake_timeout.py
                    $<TARGET_FILE:test_tls_handshake_timeout_server> ${_webem_tls_cert} ${_webem_tls_key})
        set_tests_properties(test_tls_handshake_timeout PROPERTIES TIMEOUT 60)
    endif()
elseif(NOT WEBEM_ENABLE_SSL)
    message(STATUS "webem tests: WEBEM_ENABLE_SSL is OFF -- test_tls_handshake_timeout "
                    "will not be registered with ctest.")
endif()
