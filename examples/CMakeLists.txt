cmake_minimum_required(VERSION 3.16)
project(webem_examples LANGUAGES CXX)

# When built as part of the webem project (via WEBEM_BUILD_EXAMPLES=ON),
# the webem::webem target is already available.
# When built standalone, try find_package first, then add_subdirectory.
if(NOT TARGET webem::webem)
    find_package(webem QUIET)
    if(NOT webem_FOUND)
        message(STATUS "webem not found via find_package, building from parent directory")
        add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/.. ${CMAKE_CURRENT_BINARY_DIR}/webem_build)
    endif()
endif()

add_subdirectory(01_simple_http)
add_subdirectory(02_https)
add_subdirectory(03_websocket)
add_subdirectory(04_authentication)
add_subdirectory(05_custom_logger)
