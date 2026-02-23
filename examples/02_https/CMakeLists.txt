add_executable(https_server main.cpp)
target_link_libraries(https_server PRIVATE webem::webem)

# Copy www/ folder next to the built executable
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/www DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

# Note: this example requires WEBEM_ENABLE_SSL=ON (the default).
# If SSL was disabled, the build will fail with a clear error at compile time
# because ssl_server_settings is only defined when WWW_ENABLE_SSL is set.
