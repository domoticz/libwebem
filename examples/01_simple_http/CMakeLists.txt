add_executable(simple_http main.cpp)
target_link_libraries(simple_http PRIVATE webem::webem)

# Copy the www/ folder next to the built executable so the server can find it
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/www DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
