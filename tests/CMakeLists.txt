# Unit tests for libwebem

add_executable(webem_tests test_security.cpp)

target_link_libraries(webem_tests PRIVATE webem)

# webem exposes Boost and OpenSSL via its PUBLIC link interface; the request
# parser template pulls in Boost headers directly.
find_package(Boost REQUIRED COMPONENTS thread)
target_link_libraries(webem_tests PRIVATE Boost::boost)

add_test(NAME webem_tests COMMAND webem_tests)
