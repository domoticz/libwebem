//
// webem_utils.h
// ~~~~~~~~~~~~~
//
// Internal utility functions for the webserver library.
// These are self-contained and have no dependency on the application core.
//
#pragma once
#include <string>
#include <vector>
#include <ctime>
#include <chrono>
#include <algorithm>
#include <cctype>
#include <thread>
#include <sys/stat.h>

namespace http {
namespace server {
namespace utils {

    /// Wraps ::time() with the same signature.
    inline time_t webem_time(time_t* t = nullptr)
    {
        return ::time(t);
    }

    /// Splits 'input' on 'delimiter' and appends each token to 'results'.
    /// Consecutive delimiters produce empty-string tokens.
    void split_string(const std::string& input,
                      const std::string& delimiter,
                      std::vector<std::string>& results);

    /// Cross-platform localtime_r wrapper.
    /// On Windows uses localtime_s (reversed argument order); on POSIX uses
    /// localtime_r directly.  Returns 'result' on success, nullptr on error.
    inline struct tm* safe_localtime(const time_t* time, struct tm* result)
    {
#ifdef _WIN32
        if (localtime_s(result, time) == 0)
            return result;
        return nullptr;
#else
        return localtime_r(time, result);
#endif
    }

    /// Replaces all occurrences of replaceWhat in inoutstring with replaceWithWhat.
    inline void str_replace(std::string& inoutstring,
                            const std::string& replaceWhat,
                            const std::string& replaceWithWhat)
    {
        if (replaceWhat.empty())
            return;
        std::string::size_type pos = 0;
        while ((pos = inoutstring.find(replaceWhat, pos)) != std::string::npos)
        {
            inoutstring.replace(pos, replaceWhat.size(), replaceWithWhat);
            pos += replaceWithWhat.size();
        }
    }

    /// Converts inoutstring to upper case in place.
    inline void str_upper(std::string& inoutstring)
    {
        std::transform(inoutstring.begin(), inoutstring.end(),
                       inoutstring.begin(),
                       [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
    }

    /// Returns a copy of s with leading and trailing whitespace removed.
    inline std::string trim_whitespace(const std::string& s)
    {
        auto start = s.find_first_not_of(" \t\r\n");
        if (start == std::string::npos)
            return {};
        auto end = s.find_last_not_of(" \t\r\n");
        return s.substr(start, end - start + 1);
    }

    /// In-place variant: trims leading and trailing whitespace from s.
    inline void trim_whitespace_inplace(std::string& s)
    {
        s = trim_whitespace(s);
    }

    /// Returns a random UUID v4 string (e.g. "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx").
    std::string generate_uuid();

    /// Returns true if the file at path exists and is accessible.
    inline bool file_exists(const char* path)
    {
        struct stat st;
        return (stat(path, &st) == 0);
    }

    /// Sets the OS-level name of the given thread handle.
    int set_thread_name(const std::thread::native_handle_type& thread, const char* name);

    /// Formats rawtime as an RFC 1123 HTTP date string.
    /// Returns a pointer to a thread-local static buffer; valid until the
    /// next call on the same thread.
    char* make_web_time(const time_t rawtime);

    /// Compute MD5 hash of InputString concatenated with Salt.
    /// Requires OpenSSL (libcrypto).
    /// NOTE: MD5 is cryptographically weak and is retained ONLY for backwards
    /// compatibility with stored credentials (HTTP Digest / legacy password
    /// hashes). Do not use it for new secret hashing; use GenerateSHA256Hash.
    std::string GenerateMD5Hash(const std::string& InputString, const std::string& Salt = "");

    /// Compute SHA-256 hash (lowercase hex) of InputString concatenated with Salt.
    /// Requires OpenSSL (libcrypto).
    std::string GenerateSHA256Hash(const std::string& InputString, const std::string& Salt = "");

    /// Generate a cryptographically secure random token as a lowercase hex string.
    /// nbytes is the number of random bytes drawn (default 32 = 256 bits); the
    /// returned string is 2*nbytes hex characters. Backed by OpenSSL RAND_bytes.
    /// Returns an empty string if the CSPRNG fails (callers must treat empty as failure).
    std::string GenerateSecureToken(size_t nbytes = 32);

    /// Constant-time comparison of two strings. Returns true if they are equal.
    /// The running time does not depend on the position of the first differing
    /// byte, preventing timing side-channels when comparing secrets/hashes.
    bool ConstantTimeEquals(const std::string& a, const std::string& b);

    /// Returns true if s contains any ASCII control character (0x00-0x1F or 0x7F),
    /// including an embedded NUL. Used to reject malformed/decoded request paths.
    bool contains_control_chars(const std::string& s);

    /// True if the comma-separated header value `value` contains `token` as a
    /// whole, case-insensitive element -- the form RFC 9110 s5.6.1 defines for
    /// list-valued headers such as Connection ("keep-alive, Upgrade").
    ///
    /// Matching the whole header string instead would both miss "close" inside
    /// "TE, close" and match "keep-alive" inside a token like "no-keep-alive",
    /// so surrounding whitespace is trimmed and each element compared entire.
    bool header_has_token(const std::string& value, const std::string& token);

    /// Cross-platform gettimeofday replacement.
    /// On POSIX, delegates to ::gettimeofday(). On Windows, uses GetSystemTimeAsFileTime().
    /// Namespaced to avoid linker conflicts with consumer-provided implementations.
    int get_timeofday(struct timeval* tp);

} // namespace utils
} // namespace server
} // namespace http
