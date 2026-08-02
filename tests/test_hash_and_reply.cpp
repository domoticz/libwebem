//
// test_hash_and_reply.cpp
// ~~~~~~~~~~~~~~~~~~~~~~~
//
// Standalone regression tests (own main(), no external test framework) for a
// handful of small, independent fixes:
//
//   - request::print() must return the parameters of the request it was called
//     with, not a value cached from the first call ever made in the process.
//   - ConstantTimeEquals() must not treat two empty inputs as equal, and must
//     otherwise still behave as a normal constant-time string comparison.
//   - GenerateMD5Hash() / GenerateSHA256Hash() must still produce correct,
//     known-vector output now that their OpenSSL return values are checked.
//   - reply::set_content_from_file() must succeed on an ordinary file with the
//     right size/content, and fail cleanly (no throw) on a missing path.
//
// Lightweight harness (same style as test_security.cpp): each check increments
// a global counter and the process exits non-zero if anything fails.
//

#include <libwebem/webem_utils.h>
#include <libwebem/request.h>
#include <libwebem/reply.h>

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>

static int g_failures = 0;
static int g_checks = 0;

#define CHECK(cond)                                                        \
    do {                                                                   \
        ++g_checks;                                                        \
        if (!(cond)) {                                                     \
            ++g_failures;                                                  \
            std::printf("FAIL: %s (line %d)\n", #cond, __LINE__);          \
        }                                                                  \
    } while (0)

using namespace http::server;

// Regression test for finding #18: request::print() used to cache its result in
// a function-local static, so every call after the first returned the FIRST
// request's parameters regardless of which request was passed in. Two requests
// with different parameter sets must each get their own rendering back.
static void test_request_print_is_per_request()
{
    request req1;
    req1.parameters.insert(std::make_pair("username", "alice"));
    req1.parameters.insert(std::make_pair("password", "hunter2"));

    std::string out1 = request::print(&req1);
    CHECK(out1.find("alice") != std::string::npos);
    CHECK(out1.find("hunter2") != std::string::npos);

    request req2;
    req2.parameters.insert(std::make_pair("username", "bob"));
    req2.parameters.insert(std::make_pair("token", "abc123"));

    std::string out2 = request::print(&req2);
    CHECK(out2.find("bob") != std::string::npos);
    CHECK(out2.find("abc123") != std::string::npos);
    // req2's rendering must NOT leak req1's parameters.
    CHECK(out2.find("alice") == std::string::npos);
    CHECK(out2.find("hunter2") == std::string::npos);

    // Calling print() again for req1 (after req2 was rendered) must still
    // return req1's own parameters, not req2's.
    std::string out1_again = request::print(&req1);
    CHECK(out1_again.find("alice") != std::string::npos);
    CHECK(out1_again.find("bob") == std::string::npos);
    CHECK(out1_again == out1);
}

// Finding #19: ConstantTimeEquals("", "") must be false (an empty hash means
// the digest computation failed, and must never authenticate), while normal
// equal/unequal/different-length comparisons keep working.
static void test_constant_time_equals()
{
    CHECK(!utils::ConstantTimeEquals("", ""));
    CHECK(!utils::ConstantTimeEquals("", "x"));
    CHECK(!utils::ConstantTimeEquals("x", ""));

    CHECK(utils::ConstantTimeEquals("secret-value", "secret-value"));
    CHECK(!utils::ConstantTimeEquals("secret-value", "secret-valuf"));
    CHECK(!utils::ConstantTimeEquals("short", "shorter"));
    CHECK(!utils::ConstantTimeEquals("shorter", "short"));
}

// Finding #19: adding EVP return-value checks must not change the output of
// the success path. Verify against known vectors.
static void test_hash_known_vectors()
{
    CHECK(utils::GenerateMD5Hash("abc") == "900150983cd24fb0d6963f7d28e17f72");
    CHECK(utils::GenerateMD5Hash("") == "d41d8cd98f00b204e9800998ecf8427e");
    CHECK(utils::GenerateMD5Hash("a", "bc") == utils::GenerateMD5Hash("abc"));

    CHECK(utils::GenerateSHA256Hash("") ==
          "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    CHECK(utils::GenerateSHA256Hash("abc") ==
          "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

// Finding #20: an ordinary, seekable file must still be read back correctly.
static void test_set_content_from_file_success()
{
    const std::string path = "test_hash_and_reply_tmpfile.bin";
    const std::string body = "The quick brown fox jumps over the lazy dog.\n\x01\x02\x03";

    {
        std::ofstream out(path.c_str(), std::ios::out | std::ios::binary | std::ios::trunc);
        CHECK(out.is_open());
        out.write(body.data(), static_cast<std::streamsize>(body.size()));
    }

    reply rep;
    bool ok = reply::set_content_from_file(&rep, path);
    CHECK(ok);
    CHECK(rep.content.size() == body.size());
    CHECK(rep.content == body);

    std::remove(path.c_str());
}

// Finding #20: a non-existent path must return false, not throw.
static void test_set_content_from_file_missing()
{
    reply rep;
    bool ok = reply::set_content_from_file(&rep, "this_path_definitely_does_not_exist_12345.bin");
    CHECK(!ok);

    // NOTE: a genuinely non-seekable target (FIFO, character device) has no
    // portable equivalent on Windows that std::ifstream can open the way this
    // test suite runs (named pipes require CreateFile/CreateNamedPipe, and
    // devices like "NUL"/"CON" do not reproduce tellg() returning -1 the way a
    // POSIX FIFO does). Rather than fake that behavior with a mechanism that
    // would not actually exercise the tellg()<0 branch, this case is left
    // untested here; the tellg()<0 check itself is a direct, inspectable
    // one-line guard in reply.cpp.
}

int main()
{
    test_request_print_is_per_request();
    test_constant_time_equals();
    test_hash_known_vectors();
    test_set_content_from_file_success();
    test_set_content_from_file_missing();

    std::printf("\n%d checks, %d failure(s)\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
