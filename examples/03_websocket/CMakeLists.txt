add_executable(websocket_server main.cpp)
target_link_libraries(websocket_server PRIVATE webem::webem)

# Copy www/ folder (includes the JS WebSocket test client) next to the executable
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/www DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
