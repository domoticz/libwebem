//
// test_session_lifetime.cpp
// ~~~~~~~~~~~~~~~~~~~~~~~~~
//
// Regression coverage for two cWebem concurrency defects:
//
//   1) GetSession() used to hand back a raw pointer into the mutex-protected
//      m_sessions map, then release the lock as it returned. Every caller
//      dereferenced that pointer -- one of them wrote through it -- with no
//      lock held, while a dedicated session-cleaner thread could erase (or,
//      via ClearUserPasswords(), clear() the entire map) concurrently. That
//      is a use-after-free, including a use-after-free *write*.
//
//      The fix returns sessions by value (a private snapshot copied under
//      the lock) and adds TouchSessionExpiry() to do renewal as a single
//      find-and-mutate-under-lock operation, rather than a read-modify-write
//      through a pointer that could go stale between the read and the write.
//
//   2) m_remote_web_clients used to be a process-wide global std::map with no
//      locking at all, shared -- unsynchronised -- by every cWebem instance
//      in the process (e.g. a concurrent HTTP and HTTPS instance, each with
//      its own io thread), and it was never pruned. It is now a per-instance
//      member guarded by its own mutex, pruned and size-capped both by the
//      periodic sweep and inline on every TrackRemoteClient() call (so the
//      cap holds between sweeps too), with eviction ordered by last_seen
//      rather than by map key.
//
// Lightweight harness (no external test framework), matching test_security.cpp:
// each check increments a global counter and the process exits non-zero if
// anything fails.
//

#include <libwebem/cWebem.h>
#include <libwebem/session.h>
#include <libwebem/server_settings.h>
#include <libwebem/webem_utils.h>

#include <boost/asio.hpp>

#include <atomic>
#include <cstdio>
#include <string>
#include <thread>
#include <vector>

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

// Mirrors the (unexported) constants in src/cWebem.cpp: SHORT_SESSION_TIMEOUT
// is 10 minutes, LONG_SESSION_TIMEOUT is 30 days. Not part of the public
// header, so duplicated here to exercise TouchSessionExpiry's two renewal
// branches with the same thresholds production code uses.
static constexpr time_t kShortSessionTimeout = 600;
static constexpr time_t kLongSessionTimeout = 30 * 86400;

static unsigned short free_tcp_port()
{
    boost::asio::io_context io;
    boost::asio::ip::tcp::acceptor a(io);
    boost::asio::ip::tcp::endpoint ep(boost::asio::ip::make_address("127.0.0.1"), 0);
    a.open(ep.protocol());
    a.bind(ep);
    unsigned short p = a.local_endpoint().port();
    a.close();
    return p;
}

static std::unique_ptr<cWebem> make_webem()
{
    server_settings s;
    s.listening_address = "127.0.0.1";
    s.listening_port = std::to_string(free_tcp_port());
    return std::make_unique<cWebem>(s, "./www");
}

static WebEmSession make_session(const std::string &id, time_t expires)
{
    WebEmSession session;
    session.id = id;
    session.username = "alice";
    session.remote_host = "203.0.113.7";
    session.expires = expires;
    session.rights = URIGHTS_VIEWER;
    return session;
}

// ---------------------------------------------------------------------------
// GetSession: value semantics
// ---------------------------------------------------------------------------

static void test_add_and_get_session()
{
    auto web = make_webem();
    time_t now = utils::webem_time();

    WebEmSession original = make_session("sess-1", now + 1000);
    web->AddSession(original);

    WebEmSession copy;
    CHECK(web->GetSession("sess-1", copy) == true);
    CHECK(copy.id == original.id);
    CHECK(copy.username == original.username);
    CHECK(copy.remote_host == original.remote_host);
    CHECK(copy.expires == original.expires);

    // Mutating the caller's copy must never reach the stored session: there
    // is no pointer aliasing the two anymore.
    copy.username = "mallory";
    copy.expires = 0;

    WebEmSession secondLook;
    CHECK(web->GetSession("sess-1", secondLook) == true);
    CHECK(secondLook.username == "alice");
    CHECK(secondLook.expires == now + 1000);

    web->Stop();
}

static void test_get_nonexistent_session()
{
    auto web = make_webem();

    WebEmSession out;
    out.username = "sentinel"; // must be left untouched on a "not found" result
    CHECK(web->GetSession("no-such-session", out) == false);
    CHECK(out.username == "sentinel");

    web->Stop();
}

static void test_remove_then_get_session()
{
    auto web = make_webem();
    time_t now = utils::webem_time();

    web->AddSession(make_session("sess-remove", now + 1000));
    WebEmSession out;
    CHECK(web->GetSession("sess-remove", out) == true);

    web->RemoveSession(std::string("sess-remove"));
    CHECK(web->GetSession("sess-remove", out) == false);

    web->Stop();
}

// ---------------------------------------------------------------------------
// TouchSessionExpiry: single-lock find-and-mutate renewal
// ---------------------------------------------------------------------------

static void test_touch_session_expiry_short_renewal()
{
    auto web = make_webem();
    time_t now = utils::webem_time();

    // Past the short-session half-life (< now + SHORT/2) -> due for renewal.
    web->AddSession(make_session("sess-short", now + 100));

    WebEmSession touched;
    CHECK(web->TouchSessionExpiry("sess-short", touched) == true);
    CHECK(touched.id == "sess-short");
    // Allow a couple of seconds of slack for wall-clock time elapsed in-test.
    CHECK(touched.expires >= now + kShortSessionTimeout - 2);
    CHECK(touched.expires <= now + kShortSessionTimeout + 2);

    // The mutation must be visible to a subsequent, independent lookup --
    // i.e. it was applied to the stored session, not just the out-param.
    WebEmSession stored;
    CHECK(web->GetSession("sess-short", stored) == true);
    CHECK(stored.expires == touched.expires);

    web->Stop();
}

static void test_touch_session_expiry_long_renewal()
{
    auto web = make_webem();
    time_t now = utils::webem_time();

    // Past SHORT_SESSION_TIMEOUT but within the long-session half-life window.
    web->AddSession(make_session("sess-long", now + kShortSessionTimeout + 10));

    WebEmSession touched;
    CHECK(web->TouchSessionExpiry("sess-long", touched) == true);
    CHECK(touched.expires >= now + kLongSessionTimeout - 2);
    CHECK(touched.expires <= now + kLongSessionTimeout + 2);

    web->Stop();
}

static void test_touch_session_expiry_not_due()
{
    auto web = make_webem();
    time_t now = utils::webem_time();

    // Fresh session, nowhere near its half-life: must not be renewed.
    web->AddSession(make_session("sess-fresh", now + kShortSessionTimeout));

    WebEmSession touched;
    CHECK(web->TouchSessionExpiry("sess-fresh", touched) == false);
    // Even when not renewed, the found session's data is still handed back.
    CHECK(touched.id == "sess-fresh");

    web->Stop();
}

static void test_touch_session_expiry_missing_session()
{
    auto web = make_webem();
    WebEmSession touched;
    CHECK(web->TouchSessionExpiry("does-not-exist", touched) == false);
    CHECK(web->TouchSessionExpiry("", touched) == false); // empty id short-circuits
}

// ---------------------------------------------------------------------------
// The actual regression: concurrent readers/renewers vs. a mutator thread
// that adds, removes, and (via ClearUserPasswords) bulk-clears sessions.
// Before the fix, GetSession returned a raw pointer that this mutator could
// invalidate mid-use on another thread -- including a use-after-free write
// at the old handle_request renewal site. There is nothing sanitizer-only
// about the bug: TouchSessionExpiry/GetSession now only ever hand out values
// copied under lock, so this drives the API hard enough to catch a
// regression back to pointer semantics even without ASan/TSan.
// ---------------------------------------------------------------------------

static void test_concurrent_session_lifetime()
{
    auto web = make_webem();

    constexpr int kSessionCount = 16;
    constexpr int kReaderThreads = 4;
    constexpr int kIterationsPerReader = 8000;
    constexpr int kMutatorIterations = 4000;

    std::vector<std::string> ids;
    for (int i = 0; i < kSessionCount; ++i)
        ids.push_back("concurrent-sess-" + std::to_string(i));

    time_t now = utils::webem_time();
    for (const auto &id : ids)
        web->AddSession(make_session(id, now + 100)); // due for renewal immediately

    std::atomic<bool> sawInconsistency{false};
    std::atomic<int> foundCount{0};

    std::vector<std::thread> readers;
    for (int t = 0; t < kReaderThreads; ++t)
    {
        readers.emplace_back([&, t]() {
            for (int i = 0; i < kIterationsPerReader; ++i)
            {
                const std::string &id = ids[(i + t) % ids.size()];

                WebEmSession snap;
                if (web->GetSession(id, snap))
                {
                    ++foundCount;
                    // Whatever was retrieved must be internally consistent:
                    // a corrupted/half-written object (the UAF symptom) would
                    // show up as the id not matching what we looked up.
                    if (snap.id != id)
                        sawInconsistency = true;
                }

                WebEmSession touched;
                if (web->TouchSessionExpiry(id, touched))
                {
                    if (touched.id != id)
                        sawInconsistency = true;
                }
            }
        });
    }

    std::thread mutator([&]() {
        for (int i = 0; i < kMutatorIterations; ++i)
        {
            const std::string &id = ids[i % ids.size()];
            web->RemoveSession(id);
            web->AddSession(make_session(id, utils::webem_time() + 100));

            if (i % 200 == 0)
            {
                // The reliable trigger from the original report: clears every
                // session at once while readers may be mid-lookup.
                web->ClearUserPasswords();
                // Re-seed so readers keep finding sessions rather than racing
                // an (uninteresting) all-empty map for the rest of the run.
                for (const auto &sid : ids)
                    web->AddSession(make_session(sid, utils::webem_time() + 100));
            }
        }
    });

    for (auto &th : readers)
        th.join();
    mutator.join();

    CHECK(sawInconsistency == false);
    // Sanity: the readers should have found sessions most of the time (the
    // mutator only clears/removes briefly relative to the total run).
    CHECK(foundCount.load() > 0);

    web->Stop();
}

// ---------------------------------------------------------------------------
// m_remote_web_clients: per-instance, locked, bounded
// ---------------------------------------------------------------------------

static void test_remote_client_tracking_seen_before()
{
    auto web = make_webem();

    // First sighting of an address must be reported as such.
    CHECK(web->TrackRemoteClient("198.51.100.1", "8080", "/index.html") == false);
    // Immediately afterwards, it's within SHORT_SESSION_TIMEOUT -> seen before.
    CHECK(web->TrackRemoteClient("198.51.100.1", "8080", "/other.html") == true);
    // A different port on the same host is a distinct key.
    CHECK(web->TrackRemoteClient("198.51.100.1", "9090", "/index.html") == false);

    web->Stop();
}

static void test_remote_client_map_stays_bounded()
{
    auto web = make_webem();

    // Simulate far more distinct client addresses than the backstop cap
    // allows (an attacker behind a trusted proxy supplying an arbitrary
    // X-Forwarded-For per request would otherwise grow this without limit --
    // see findRealHostBehindProxies). Deliberately never calls
    // PruneRemoteClients(): the whole point of the inline cap is that the
    // bound holds on every TrackRemoteClient() call by itself, not only
    // right after the periodic (15-minute) sweep runs.
    constexpr int kDistinctClients = 60000;
    for (int i = 0; i < kDistinctClients; ++i)
    {
        std::string host = "10." + std::to_string((i >> 16) & 0xFF) + "." +
                            std::to_string((i >> 8) & 0xFF) + "." + std::to_string(i & 0xFF);
        web->TrackRemoteClient(host, "80", "/x");
    }

    // Bounded by the backstop cap, and strictly less than what was inserted
    // -- with no call to PruneRemoteClients() anywhere in this test.
    CHECK(web->CountRemoteClients() <= 50000);
    CHECK(web->CountRemoteClients() < (size_t)kDistinctClients);

    // The periodic sweep must remain safe (and a no-op here) on top of that.
    web->PruneRemoteClients();
    CHECK(web->CountRemoteClients() <= 50000);

    web->Stop();
}

static void test_remote_client_eviction_is_oldest_by_last_seen()
{
    auto web = make_webem();

    // Touch this one first, so it is the oldest entry by last_seen -- and
    // give it a key that sorts lexicographically AFTER every key added
    // below, so std::map key order would protect it from eviction while
    // last_seen order would not. This is exactly the scenario the fix
    // matters for: keying eviction off m_remote_web_clients.begin() (i.e.
    // address+port order) would let an attacker feeding descending
    // addresses evict the most recently-seen legitimate entries first,
    // while this one -- the actual oldest -- would survive indefinitely.
    CHECK(web->TrackRemoteClient("9.9.9.9", "80", "/first") == false);

    // Fill up to (and one past) the cap with distinct keys that all sort
    // lexicographically before "9.9.9.9", each touched strictly after it.
    constexpr int kFillCount = 50000;
    for (int i = 0; i < kFillCount; ++i)
    {
        std::string host = "10." + std::to_string((i >> 16) & 0xFF) + "." +
                            std::to_string((i >> 8) & 0xFF) + "." + std::to_string(i & 0xFF);
        web->TrackRemoteClient(host, "80", "/x");
    }

    // The cap held throughout, purely from the inline enforcement.
    CHECK(web->CountRemoteClients() == 50000);

    // The oldest entry -- "9.9.9.9" -- must have been evicted to make room,
    // even though its key sorts last and so would have been the least
    // likely candidate under key-order eviction. Seeing it reported as a
    // fresh sighting again proves it is gone.
    CHECK(web->TrackRemoteClient("9.9.9.9", "80", "/first-again") == false);

    web->Stop();
}

static void test_get_remote_clients_snapshot()
{
    auto web = make_webem();

    CHECK(web->TrackRemoteClient("203.0.113.1", "80", "/a") == false);
    CHECK(web->TrackRemoteClient("203.0.113.2", "443", "/b") == false);
    CHECK(web->TrackRemoteClient("203.0.113.3", "8080", "/c") == false);

    auto snapshot = web->GetRemoteClients();
    CHECK(snapshot.size() == 3);

    // Every tracked address/port/uri combination must be present in the
    // snapshot, by value -- GetRemoteClients() must never hand back a
    // reference or pointer into the locked map (see cWebem.h), so this is
    // the caller's own private copy.
    auto find_by_host = [&](const std::string &host) -> const connection::_tRemoteClients * {
        for (const auto &c : snapshot)
        {
            if (c.host_remote_endpoint_address_ == host)
                return &c;
        }
        return nullptr;
    };

    const auto *a = find_by_host("203.0.113.1");
    CHECK(a != nullptr);
    if (a)
    {
        CHECK(a->host_local_endpoint_port_ == "80");
        CHECK(a->host_last_request_uri_ == "/a");
    }

    const auto *b = find_by_host("203.0.113.2");
    CHECK(b != nullptr);
    if (b)
    {
        CHECK(b->host_local_endpoint_port_ == "443");
        CHECK(b->host_last_request_uri_ == "/b");
    }

    CHECK(find_by_host("203.0.113.3") != nullptr);

    // Mutating the snapshot must not reach back into the stored data: it is
    // a copy, not a view. Corrupt every field of the local copy...
    for (auto &c : snapshot)
    {
        c.host_remote_endpoint_address_ = "mutated";
        c.host_local_endpoint_port_ = "0";
        c.host_last_request_uri_ = "/mutated";
        c.last_seen = 0;
    }

    // ...then take a fresh snapshot and confirm the original data survived
    // untouched.
    auto snapshot2 = web->GetRemoteClients();
    CHECK(snapshot2.size() == 3);
    bool foundA2 = false, foundB2 = false, foundC2 = false;
    for (const auto &c : snapshot2)
    {
        if (c.host_remote_endpoint_address_ == "203.0.113.1" && c.host_local_endpoint_port_ == "80" && c.host_last_request_uri_ == "/a")
            foundA2 = true;
        if (c.host_remote_endpoint_address_ == "203.0.113.2" && c.host_local_endpoint_port_ == "443" && c.host_last_request_uri_ == "/b")
            foundB2 = true;
        if (c.host_remote_endpoint_address_ == "203.0.113.3" && c.host_local_endpoint_port_ == "8080" && c.host_last_request_uri_ == "/c")
            foundC2 = true;
        CHECK(c.host_remote_endpoint_address_ != "mutated");
    }
    CHECK(foundA2);
    CHECK(foundB2);
    CHECK(foundC2);

    web->Stop();
}

int main()
{
    test_add_and_get_session();
    test_get_nonexistent_session();
    test_remove_then_get_session();

    test_touch_session_expiry_short_renewal();
    test_touch_session_expiry_long_renewal();
    test_touch_session_expiry_not_due();
    test_touch_session_expiry_missing_session();

    test_concurrent_session_lifetime();

    test_remote_client_tracking_seen_before();
    test_remote_client_map_stays_bounded();
    test_remote_client_eviction_is_oldest_by_last_seen();
    test_get_remote_clients_snapshot();

    std::printf("\n%d checks, %d failure(s)\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
