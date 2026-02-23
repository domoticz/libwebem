add_executable(auth_server main.cpp)
target_link_libraries(auth_server PRIVATE webem::webem)

# Copy www/ folder next to the built executable
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/www DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
