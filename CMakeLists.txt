cmake_minimum_required(VERSION 3.16)
project(webem VERSION 1.31.0 LANGUAGES CXX)

include(FetchContent)

# Policies for newer CMake versions
if(POLICY CMP0144)
    cmake_policy(SET CMP0144 NEW)  # Use upper-case <PACKAGENAME>_ROOT variables
endif()
if(POLICY CMP0167)
    cmake_policy(SET CMP0167 OLD)  # Keep FindBoost module (removed in 4.2)
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Options
option(WEBEM_ENABLE_SSL      "Enable HTTPS/SSL support"              ON)
option(WEBEM_ENABLE_ZIP      "Enable ZIP file serving"               ON)
option(WEBEM_ENABLE_FASTCGI  "Enable FastCGI support"                ON)
option(WEBEM_ENABLE_GZIP     "Enable GZip compression (requires zlib)" ON)
option(WEBEM_BUILD_EXAMPLES  "Build example applications"            OFF)
option(WEBEM_BUILD_TESTS    "Build unit tests"           OFF)
option(BUILD_SHARED_LIBS    "Build shared library"       OFF)
option(WEBEM_ENABLE_ASAN    "Build with AddressSanitizer" OFF)

# AddressSanitizer, opt-in. This library has memory-safety-sensitive code paths
# (session lifetime handling, per-download buffer ownership, JWT payload
# parsing) where a use-after-free, a leaked heap allocation, or undefined
# behaviour on malformed input would silently pass a plain Debug build -- ASan
# is what makes those fail loudly instead. MSVC has supported /fsanitize=address
# since VS 16.9 but has no ThreadSanitizer equivalent; data races around shared
# connection state are only checkable with TSan on a non-MSVC toolchain.
#
# The MSVC ASan runtime is a DLL (clang_rt.asan_dynamic-x86_64.dll) that ships
# with the toolchain rather than next to the built binaries, so it must be on
# PATH at run time or every ASan-built executable fails to start -- see
# tests/README.md for where to find it.
#
# Applied at directory scope, before any targets are declared, so it covers the
# webem library itself and everything under tests/.
if(WEBEM_ENABLE_ASAN)
    if(MSVC)
        add_compile_options(/fsanitize=address)
        # ASan's shadow-memory instrumentation is incompatible with MSVC's
        # /RTC runtime checks (auto-enabled in Debug) and with incremental
        # linking; both must come out or the build/link fails outright.
        foreach(_flags_var CMAKE_CXX_FLAGS_DEBUG CMAKE_C_FLAGS_DEBUG)
            string(REGEX REPLACE "/RTC[1csu]*" "" ${_flags_var} "${${_flags_var}}")
        endforeach()
        add_link_options($<$<CONFIG:Debug>:/INCREMENTAL:NO>)
    else()
        add_compile_options(-fsanitize=address -fno-omit-frame-pointer)
        add_link_options(-fsanitize=address)
    endif()
endif()

# Core source files (in src/)
set(WEBEM_SOURCES
    src/Base64.cpp
    src/connection.cpp
    src/connection_manager.cpp
    src/cWebem.cpp
    src/mime_types.cpp
    src/reply.cpp
    src/request_handler.cpp
    src/request_parser.cpp
    src/server.cpp
    src/Websockets.cpp
    src/webem_utils.cpp
)

# Public header files (in include/libwebem/)
set(WEBEM_PUBLIC_HEADERS
    include/libwebem/libwebem.h
    include/libwebem/Base64.h
    include/libwebem/connection.h
    include/libwebem/connection_manager.h
    include/libwebem/cWebem.h
    include/libwebem/header.h
    include/libwebem/IWebServerLogger.h
    include/libwebem/IWebsocketHandler.h
    include/libwebem/reply.h
    include/libwebem/request.h
    include/libwebem/request_handler.h
    include/libwebem/request_parser.h
    include/libwebem/server.h
    include/libwebem/server_settings.h
    include/libwebem/session_store.h
    include/libwebem/webem_utils.h
    include/libwebem/webem_version.h
    include/libwebem/Websockets.h
)

# Internal header files (in src/)
set(WEBEM_INTERNAL_HEADERS
    src/GZipHelper.h
    src/mime_types.h
    src/sha1.h
    src/utf.h
    src/webem_stdafx.h
)

if(WEBEM_ENABLE_FASTCGI)
    list(APPEND WEBEM_SOURCES src/fastcgi.cpp src/url_encode.cpp)
    list(APPEND WEBEM_INTERNAL_HEADERS src/fastcgi.h src/url_encode.h)
endif()

# Library target
add_library(webem ${WEBEM_SOURCES} ${WEBEM_PUBLIC_HEADERS} ${WEBEM_INTERNAL_HEADERS})
add_library(webem::webem ALIAS webem)

# Shared library versioning (for .so symlinks on Linux)
set_target_properties(webem PROPERTIES
    VERSION   ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
)

# Position-independent code (required for shared libraries, harmless for static)
set_target_properties(webem PROPERTIES POSITION_INDEPENDENT_CODE ON)

target_include_directories(webem
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# Dependencies
find_package(Boost REQUIRED COMPONENTS thread)
target_link_libraries(webem
    PUBLIC
        Boost::boost   # Headers exposed via server.h, connection.h, cWebem.h, server_settings.h
    PRIVATE
        Boost::thread
)

if(WEBEM_ENABLE_GZIP)
    # ZLIB - try find_package first, fall back to consumer-provided target
    find_package(ZLIB QUIET)
    if(ZLIB_FOUND)
        target_link_libraries(webem PUBLIC ZLIB::ZLIB)
    else()
        message(STATUS "System ZLIB not found, consumer must provide ZLIB")
    endif()
else()
    target_compile_definitions(webem PUBLIC WEBEM_NO_GZIP)
endif()

if(NOT WEBEM_ENABLE_FASTCGI)
    # src/fastcgi.cpp is left out of WEBEM_SOURCES above, so the PHP hand-off in
    # request_handler.cpp has to be compiled out with it or the library does not
    # link (undefined reference to fastcgi_parser::handlePHP).
    target_compile_definitions(webem PUBLIC WEBEM_NO_FASTCGI)
endif()

# jsoncpp - 3-tier: parent target → find_package → FetchContent
#
# PUBLIC, not PRIVATE: include/libwebem/cWebem.h includes <json/json.h>, so
# anything that consumes that header needs jsoncpp's include directories too.
# With PRIVATE they do not propagate, and every target linking webem fails to
# compile unless jsoncpp happens to sit somewhere already searched (a system
# install under /usr/include). That masked the breakage until the test targets
# were added and CI, which has no libjsoncpp-dev, fell through to FetchContent.
if(TARGET jsoncpp_static)
    message(STATUS "webem: using parent-provided jsoncpp_static target")
    target_link_libraries(webem PUBLIC jsoncpp_static)
elseif(TARGET jsoncpp_lib)
    message(STATUS "webem: using parent-provided jsoncpp_lib target")
    target_link_libraries(webem PUBLIC jsoncpp_lib)
else()
    find_package(jsoncpp QUIET)
    if(jsoncpp_FOUND)
        message(STATUS "webem: using system jsoncpp")
        target_link_libraries(webem PUBLIC jsoncpp_lib)
    else()
        message(STATUS "webem: fetching jsoncpp 1.9.6 via FetchContent")
        set(JSONCPP_WITH_TESTS              OFF CACHE BOOL "" FORCE)
        set(JSONCPP_WITH_POST_BUILD_UNITTEST OFF CACHE BOOL "" FORCE)
        set(BUILD_OBJECT_LIBS               OFF CACHE BOOL "" FORCE)
        set(BUILD_SHARED_LIBS               OFF CACHE BOOL "" FORCE)
        set(BUILD_STATIC_LIBS               ON  CACHE BOOL "" FORCE)
        FetchContent_Declare(
            jsoncpp
            GIT_REPOSITORY https://github.com/open-source-parsers/jsoncpp.git
            GIT_TAG        1.9.6
            GIT_SHALLOW    TRUE
        )
        FetchContent_MakeAvailable(jsoncpp)
        target_link_libraries(webem PUBLIC jsoncpp_static)
    endif()
endif()

# OpenSSL is always required (jwt-cpp depends on it for JWT signing)
find_package(OpenSSL REQUIRED)
target_link_libraries(webem PUBLIC OpenSSL::SSL OpenSSL::Crypto)

if(WEBEM_ENABLE_SSL)
    target_compile_definitions(webem PUBLIC WWW_ENABLE_SSL)
endif()

if(WEBEM_ENABLE_ZIP)
    # Prefer parent-provided target, then find_package; warn and disable if not found
    if(TARGET minizip)
        message(STATUS "webem: using parent-provided minizip target")
        target_link_libraries(webem PRIVATE minizip)
    elseif(TARGET minizip::minizip)
        target_link_libraries(webem PRIVATE minizip::minizip)
    else()
        find_package(minizip QUIET)
        if(minizip_FOUND)
            target_link_libraries(webem PRIVATE minizip::minizip)
        else()
            message(WARNING "minizip not found - disabling ZIP support. Install minizip to enable it.")
            target_compile_definitions(webem PUBLIC WEBSERVER_DONT_USE_ZIP)
        endif()
    endif()
else()
    target_compile_definitions(webem PUBLIC WEBSERVER_DONT_USE_ZIP)
endif()

# jwt-cpp - 3-tier: parent target → find_package → FetchContent (header-only)
if(TARGET jwt-cpp::jwt-cpp)
    message(STATUS "webem: using parent-provided jwt-cpp::jwt-cpp target")
else()
    find_package(jwt-cpp QUIET)
    if(jwt-cpp_FOUND)
        message(STATUS "webem: using system jwt-cpp")
    else()
        message(STATUS "webem: fetching jwt-cpp v0.7.2 via FetchContent (header-only)")
        FetchContent_Declare(
            jwt-cpp
            GIT_REPOSITORY https://github.com/Thalhammer/jwt-cpp.git
            GIT_TAG        v0.7.2
            GIT_SHALLOW    TRUE
        )
        FetchContent_GetProperties(jwt-cpp)
        if(NOT jwt-cpp_POPULATED)
            FetchContent_Populate(jwt-cpp)
        endif()
        # jwt-cpp is header-only; create a simple INTERFACE target
        # (avoids running jwt-cpp's own CMakeLists.txt which has extra dependencies)
        add_library(jwt-cpp_header_only INTERFACE)
        target_include_directories(jwt-cpp_header_only INTERFACE
            $<BUILD_INTERFACE:${jwt-cpp_SOURCE_DIR}/include>
            $<INSTALL_INTERFACE:include>
        )
        add_library(jwt-cpp::jwt-cpp ALIAS jwt-cpp_header_only)
    endif()
endif()
target_link_libraries(webem PRIVATE jwt-cpp::jwt-cpp)

# Platform-specific libraries
if(WIN32)
    target_link_libraries(webem PUBLIC ws2_32 mswsock)
endif()

# Install rules (only when built standalone, not as a subdirectory)
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    # Collect targets that must be exported alongside webem
    set(_webem_export_targets webem)
    if(TARGET jwt-cpp_header_only)
        list(APPEND _webem_export_targets jwt-cpp_header_only)
    endif()
    install(TARGETS ${_webem_export_targets} EXPORT webemTargets
        ARCHIVE DESTINATION lib
        LIBRARY DESTINATION lib
    )
    install(DIRECTORY include/libwebem/ DESTINATION include/libwebem
        FILES_MATCHING PATTERN "*.h" PATTERN "*.hpp"
    )
    install(EXPORT webemTargets
        FILE webemConfig.cmake
        NAMESPACE webem::
        DESTINATION lib/cmake/webem
    )

    # pkg-config file for system package managers (apt, dnf, etc.)
    configure_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/webem.pc.in
        ${CMAKE_CURRENT_BINARY_DIR}/webem.pc
        @ONLY
    )
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/webem.pc
        DESTINATION lib/pkgconfig
    )
endif()

# Tests (opt-in)
if(WEBEM_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# Examples (opt-in; off by default to keep the library build fast)
if(WEBEM_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()
