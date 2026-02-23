add_executable(custom_logger main.cpp)
target_link_libraries(custom_logger PRIVATE webem::webem)

# Copy www/ folder next to the built executable
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/www DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
