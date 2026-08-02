//
// webem_utils.cpp
// ~~~~~~~~~~~~~~~
//
// Implementation of internal webserver utility functions.
//
#include "webem_stdafx.h"
// On Windows, winsock2.h is included via webem_stdafx.h.
// Include <windows.h> here for additional Win32 API used below.
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <pthread.h>
#include <sys/time.h>
#endif

#include <libwebem/webem_utils.h>
#include <cstdio>
#include <cstring>
#include <random>
#include <thread>
#include <memory>
#include <vector>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

namespace http {
namespace server {
namespace utils {

int get_timeofday(struct timeval* tp)
{
#ifdef _WIN32
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER ui;
    ui.LowPart  = ft.dwLowDateTime;
    ui.HighPart = ft.dwHighDateTime;
    // Difference in 100-ns ticks between 1601-01-01 and 1970-01-01
    const uint64_t EPOCH_DIFF = 116444736000000000ULL;
    uint64_t ticks = ui.QuadPart - EPOCH_DIFF;
    tp->tv_sec  = static_cast<long>(ticks / 10000000ULL);
    tp->tv_usec = static_cast<long>((ticks % 10000000ULL) / 10ULL);
    return 0;
#else
    return ::gettimeofday(tp, nullptr);
#endif
}

void split_string(const std::string& input,
                  const std::string& delimiter,
                  std::vector<std::string>& results)
{
    if (delimiter.empty())
    {
        results.push_back(input);
        return;
    }

    std::string::size_type start = 0;
    std::string::size_type pos   = input.find(delimiter, start);

    while (pos != std::string::npos)
    {
        results.push_back(input.substr(start, pos - start));
        start = pos + delimiter.size();
        pos   = input.find(delimiter, start);
    }

    // Push the last (or only) segment, even if it is empty.
    results.push_back(input.substr(start));
}

std::string generate_uuid()
{
    // UUID v4: random-based, format xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
    // Use seed_seq with multiple random_device draws for better entropy.
    // thread_local avoids both lock contention and re-seeding on every call.
    static thread_local std::mt19937_64 gen([] {
        std::random_device rd;
        std::seed_seq ss{rd(), rd(), rd(), rd()};
        return std::mt19937_64(ss);
    }());
    std::uniform_int_distribution<uint32_t> dist32;
    std::uniform_int_distribution<uint16_t> dist16;

    uint32_t d0 = dist32(gen);
    uint16_t d1 = dist16(gen);
    uint16_t d2 = static_cast<uint16_t>((dist16(gen) & 0x0FFFu) | 0x4000u); // version 4
    uint16_t d3 = static_cast<uint16_t>((dist16(gen) & 0x3FFFu) | 0x8000u); // variant bits
    uint32_t d4 = dist32(gen);
    uint16_t d5 = dist16(gen);

    char buf[37];
    std::snprintf(buf, sizeof(buf),
        "%08x-%04x-%04x-%04x-%08x%04x",
        d0, d1, d2, d3, d4, d5);
    return buf;
}

int set_thread_name(const std::thread::native_handle_type& thread, const char* name)
{
#ifdef _WIN32
    // Use SetThreadDescription (available on Windows 10 version 1607+)
    // Convert narrow string to wide for the Windows API.
    int wlen = MultiByteToWideChar(CP_UTF8, 0, name, -1, nullptr, 0);
    if (wlen > 0)
    {
        std::wstring wname(static_cast<size_t>(wlen), L'\0');
        MultiByteToWideChar(CP_UTF8, 0, name, -1, &wname[0], wlen);
        // SetThreadDescription may not exist on older Windows; load dynamically.
        typedef HRESULT (WINAPI *PFN_SetThreadDescription)(HANDLE, PCWSTR);
        HMODULE hKernel = GetModuleHandleW(L"kernel32.dll");
        if (hKernel)
        {
            auto pfn = reinterpret_cast<PFN_SetThreadDescription>(
                GetProcAddress(hKernel, "SetThreadDescription"));
            if (pfn)
                pfn(static_cast<HANDLE>(thread), wname.c_str());
        }
    }
    return 0;
#elif defined(__linux__) || defined(__linux) || defined(linux)
    char name_trunc[16];
    std::strncpy(name_trunc, name, sizeof(name_trunc));
    name_trunc[sizeof(name_trunc) - 1] = '\0';
    return pthread_setname_np(thread, name_trunc);
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
    // macOS/BSD: can only name the current thread
    (void)thread;
    (void)name;
    return 0;
#else
    (void)thread;
    (void)name;
    return 0;
#endif
}

// Month abbreviations used by make_web_time.
static constexpr const char* webem_months[12] = {
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};
static constexpr const char* webem_wkdays[7] = {
    "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"
};

char* make_web_time(const time_t rawtime)
{
    static thread_local char buffer[64];
    struct tm gmt {};
#ifdef _WIN32
    if (gmtime_s(&gmt, &rawtime) != 0)
#else
    if (gmtime_r(&rawtime, &gmt) == nullptr)
#endif
    {
        std::snprintf(buffer, sizeof(buffer), "Thu, 01 Jan 1970 00:00:00 GMT");
    }
    else
    {
        std::snprintf(buffer, sizeof(buffer),
                      "%s, %02d %s %04d %02d:%02d:%02d GMT",
                      webem_wkdays[gmt.tm_wday],
                      gmt.tm_mday,
                      webem_months[gmt.tm_mon],
                      gmt.tm_year + 1900,
                      gmt.tm_hour,
                      gmt.tm_min,
                      gmt.tm_sec);
    }
    return buffer;
}

std::string GenerateMD5Hash(const std::string& InputString, const std::string& Salt)
{
    std::string cstring = InputString + Salt;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int hash_length = 0;

    auto md5ctx = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>(
        EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!md5ctx)
        return {};

    if (EVP_DigestInit_ex(md5ctx.get(), EVP_md5(), nullptr) != 1)
        return {}; // e.g. MD5 not offered by a FIPS provider - fail closed, not with a silent empty hash
    if (EVP_DigestUpdate(md5ctx.get(), cstring.c_str(), cstring.size()) != 1)
        return {}; // fail closed: an empty return is deliberate, not an incidental empty hash
    if (EVP_DigestFinal_ex(md5ctx.get(), digest, &hash_length) != 1)
        return {}; // fail closed: an empty return is deliberate, not an incidental empty hash
    if (hash_length > EVP_MAX_MD_SIZE)
        return {}; // guard the mdString/digest indexing below against a hash_length OpenSSL should never hand back, but that this code should not trust blindly

    char mdString[(EVP_MAX_MD_SIZE * 2) + 1];
    mdString[hash_length * 2] = '\0';
    for (unsigned int i = 0; i < hash_length; i++)
        std::snprintf(&mdString[i * 2], 3, "%02x", static_cast<unsigned int>(digest[i]));

    return mdString;
}

std::string GenerateSHA256Hash(const std::string& InputString, const std::string& Salt)
{
    std::string cstring = InputString + Salt;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int hash_length = 0;

    auto ctx = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>(
        EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!ctx)
        return {};

    if (EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1)
        return {}; // fail closed: an empty return is deliberate, not an incidental empty hash
    if (EVP_DigestUpdate(ctx.get(), cstring.c_str(), cstring.size()) != 1)
        return {}; // fail closed: an empty return is deliberate, not an incidental empty hash
    if (EVP_DigestFinal_ex(ctx.get(), digest, &hash_length) != 1)
        return {}; // fail closed: an empty return is deliberate, not an incidental empty hash
    if (hash_length > EVP_MAX_MD_SIZE)
        return {}; // guard the out/digest indexing below against a hash_length OpenSSL should never hand back, but that this code should not trust blindly

    char out[(EVP_MAX_MD_SIZE * 2) + 1];
    out[hash_length * 2] = '\0';
    for (unsigned int i = 0; i < hash_length; i++)
        std::snprintf(&out[i * 2], 3, "%02x", static_cast<unsigned int>(digest[i]));

    return out;
}

std::string GenerateSecureToken(size_t nbytes)
{
    if (nbytes == 0)
        nbytes = 32;
    std::vector<unsigned char> buf(nbytes);
    if (RAND_bytes(buf.data(), static_cast<int>(nbytes)) != 1)
        return {}; // CSPRNG failure - caller must treat empty result as an error

    static const char* hexchars = "0123456789abcdef";
    std::string out;
    out.reserve(nbytes * 2);
    for (unsigned char c : buf)
    {
        out.push_back(hexchars[c >> 4]);
        out.push_back(hexchars[c & 0x0F]);
    }
    return out;
}

// An empty string never compares equal here, even to another empty string.
// GenerateMD5Hash/GenerateSHA256Hash/GenerateSecureToken all return empty to
// mean "generation failed", never a real digest/token, so treating two empty
// values as a match would let a caller that forgot to check for that failure
// accept an unauthenticated value as if it had authenticated successfully.
bool ConstantTimeEquals(const std::string& a, const std::string& b)
{
    // Length is not itself secret for the fixed-size hashes/tokens we compare,
    // so an early length check is acceptable and required by CRYPTO_memcmp.
    if (a.size() != b.size())
        return false;
    if (a.empty())
        return false; // two empty secrets never authenticate: an empty hash means digest generation failed
    return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

bool contains_control_chars(const std::string& s)
{
    return std::any_of(s.begin(), s.end(), [](unsigned char c) {
        return c < 0x20 || c == 0x7F;
    });
}

bool header_has_token(const std::string& value, const std::string& token)
{
    size_t pos = 0;
    while (pos <= value.size())
    {
        size_t comma = value.find(',', pos);
        if (comma == std::string::npos)
            comma = value.size();

        // Trim OWS around this element (RFC 9110 allows spaces and htabs).
        size_t b = pos;
        size_t e = comma;
        while ((b < e) && ((value[b] == ' ') || (value[b] == '\t')))
            ++b;
        while ((e > b) && ((value[e - 1] == ' ') || (value[e - 1] == '\t')))
            --e;

        if ((e - b) == token.size())
        {
            bool same = true;
            for (size_t i = 0; i < token.size(); ++i)
            {
                if (std::tolower(static_cast<unsigned char>(value[b + i]))
                    != std::tolower(static_cast<unsigned char>(token[i])))
                {
                    same = false;
                    break;
                }
            }
            if (same)
                return true;
        }

        if (comma == value.size())
            break;
        pos = comma + 1;
    }
    return false;
}

} // namespace utils
} // namespace server
} // namespace http
