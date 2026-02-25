// Example 03 — WebSocket server: multiple endpoints, topic subscriptions, and server-side broadcast
//
// Architecture overview
// =====================
// libwebem maintains a central registry of every live WebSocket handler inside
// cWebem.  When a client connects, the registered factory lambda creates a new
// handler instance (one per connection).  libwebem automatically stores a
// weak_ptr to that handler and prunes it when the connection closes.
//
// Two server-to-client push patterns are demonstrated:
//
//   Pattern 1 — Per-handler push  (topic: "ticker")
//   ------------------------------------------------
//   Each PubSubHandler owns a background thread.  Every two seconds the thread
//   checks whether *this* client has subscribed to "ticker" and, if so, writes
//   directly to that client's socket.  Each client gets its own independent
//   tick counter; no cross-handler coordination is required.
//
//       Do_Work()
//         └─ isSubscribed("ticker")
//              └─ m_writer(json)          // writes only to this connection
//
//   Pattern 2 — Broadcast push  (topic: "announce")
//   ------------------------------------------------
//   When any client publishes a message, or a server-side timer fires,
//   cWebem::ForEachHandler() is called.  That method collects a snapshot of
//   every live handler under an internal mutex, then invokes the callback
//   *outside* the mutex (preventing deadlocks during I/O).  Each visited
//   handler checks its own subscription state before writing, so only clients
//   that subscribed to "announce" receive the message.
//
//       (incoming publish or server timer)
//         └─ cWebem::ForEachHandler(callback)
//              └─ callback(IWebsocketHandler*)
//                   └─ dynamic_cast<PubSubHandler*>
//                        └─ SendToTopic("announce", json)
//                             └─ isSubscribed("announce")
//                                  └─ m_writer(json)   // only subscribed clients
//
// Subscription protocol (JSON over WebSocket)
// ============================================
//   Client → Server:  {"event":"subscribe",   "topic":"<name>"}
//   Client → Server:  {"event":"unsubscribe",  "topic":"<name>"}
//   Server → Client:  {"event":"subscribed",   "topic":"<name>"}
//   Server → Client:  {"event":"unsubscribed", "topic":"<name>"}
//
//   Broadcast (forwarded to every client subscribed to the topic):
//   Client → Server:  {"event":"publish", "topic":"<name>", "text":"<msg>"}
//   Server → Client:  {"event":"message", "topic":"<name>", "text":"<msg>"}
//
//   Per-client tick (delivered only to this connection):
//   Server → Client:  {"event":"tick", "count":<n>}
//
// Endpoints
// =========
//   ws://localhost:8080/ws/echo    — simple echo, no subscriptions
//   ws://localhost:8080/ws/pubsub  — topic pub/sub (ticker + announce)
//
// Testing with wscat
// ==================
//   npx wscat -c ws://localhost:8080/ws/echo
//   npx wscat -c ws://localhost:8080/ws/pubsub
//     > {"event":"subscribe","topic":"ticker"}
//     > {"event":"subscribe","topic":"announce"}
//     > {"event":"publish","topic":"announce","text":"hello everyone"}
//
// Run
// ===
//   ./websocket_server
//   Open http://localhost:8080/ in a browser for an interactive test client.

#include <libwebem/cWebem.h>
#include <libwebem/IWebsocketHandler.h>

#include <atomic>
#include <chrono>
#include <csignal>
#include <iostream>
#include <map>
#include <mutex>
#include <string>
#include <thread>

static http::server::cWebem* g_server  = nullptr;
static std::atomic<bool>     g_running { true };

static void signal_handler(int /*sig*/)
{
    g_running = false;
    if (g_server)
        g_server->Stop();
}

// ---------------------------------------------------------------------------
// EchoHandler — sends back exactly what it receives (no subscription logic)
// ---------------------------------------------------------------------------
class EchoHandler : public http::server::IWebsocketHandler
{
public:
    EchoHandler(http::server::cWebem* /*webem*/,
                std::function<void(const std::string&)> writer)
        : m_writer(std::move(writer))
    {}

    bool Handle(const std::string& data, bool outbound) override
    {
        if (outbound)
            return true;  // ignore messages we sent ourselves

        std::cout << "[echo] received: " << data << "\n";
        m_writer(data);
        return true;
    }

    void Start() override
    {
        std::cout << "[echo] client connected\n";
        m_writer(R"({"event":"connected","text":"Echo endpoint: everything you send is reflected back."})");
    }

    void Stop() override { std::cout << "[echo] client disconnected\n"; }

    void store_session_id(const http::server::request& /*req*/,
                          const http::server::reply&   /*rep*/) override {}

private:
    std::function<void(const std::string&)> m_writer;
};

// ---------------------------------------------------------------------------
// PubSubHandler — demonstrates both per-handler and broadcast push patterns.
//
// Topic "ticker"
//   The handler's own background thread (Do_Work) pushes an incrementing tick
//   count to this client every two seconds.  No other handler is involved.
//
// Topic "announce"
//   Any client can broadcast a text message to every connected client that has
//   subscribed to "announce" by sending {"event":"publish","topic":"announce",
//   "text":"..."}.  The handler calls cWebem::ForEachHandler() to reach all
//   live connections.  The server-side timer in main() uses the same mechanism
//   to push periodic server announcements without any client request.
// ---------------------------------------------------------------------------
class PubSubHandler : public http::server::IWebsocketHandler
{
public:
    PubSubHandler(http::server::cWebem* webem,
                  std::function<void(const std::string&)> writer)
        : m_webem(webem), m_writer(std::move(writer))
    {}

    ~PubSubHandler() override { Stop(); }

    // ------------------------------------------------------------------
    // IWebsocketHandler interface
    // ------------------------------------------------------------------

    bool Handle(const std::string& data, bool outbound) override
    {
        if (outbound)
            return true;

        // Parse incoming JSON message.
        Json::Value msg;
        Json::CharReaderBuilder builder;
        std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
        std::string errs;
        if (!reader->parse(data.c_str(), data.c_str() + data.size(), &msg, &errs))
        {
            m_writer(R"({"event":"error","text":"invalid JSON"})");
            return true;
        }

        const std::string event = msg["event"].asString();
        const std::string topic = msg["topic"].asString();

        if (event == "subscribe" && !topic.empty())
        {
            {
                std::lock_guard<std::mutex> lock(m_topicsMutex);
                m_topics[topic] = true;
            }
            Json::Value reply;
            reply["event"] = "subscribed";
            reply["topic"] = topic;
            m_writer(reply.toStyledString());
            std::cout << "[pubsub] client subscribed to '" << topic << "'\n";
            return true;
        }

        if (event == "unsubscribe" && !topic.empty())
        {
            {
                std::lock_guard<std::mutex> lock(m_topicsMutex);
                m_topics.erase(topic);
            }
            Json::Value reply;
            reply["event"] = "unsubscribed";
            reply["topic"] = topic;
            m_writer(reply.toStyledString());
            std::cout << "[pubsub] client unsubscribed from '" << topic << "'\n";
            return true;
        }

        if (event == "publish" && !topic.empty())
        {
            // Build the broadcast payload once, then deliver it to every client
            // subscribed to this topic via the central handler registry.
            Json::Value broadcast;
            broadcast["event"] = "message";
            broadcast["topic"] = topic;
            broadcast["text"]  = msg["text"].asString();
            const std::string json = broadcast.toStyledString();

            std::cout << "[pubsub] broadcasting to topic '" << topic << "': "
                      << msg["text"].asString() << "\n";

            // Pattern 2: ForEachHandler iterates all live connections.
            // The callback is invoked outside the internal mutex, so it is safe
            // to call m_writer() (which does I/O) without risking a deadlock.
            m_webem->ForEachHandler([&json, &topic](http::server::IWebsocketHandler* h) {
                auto* handler = dynamic_cast<PubSubHandler*>(h);
                if (handler)
                    handler->SendToTopic(topic, json);
            });
            return true;
        }

        m_writer(R"({"event":"error","text":"unknown event"})");
        return true;
    }

    void Start() override
    {
        m_running = true;
        m_thread = std::thread([this] { Do_Work(); });

        std::cout << "[pubsub] client connected\n";
        m_writer(R"({"event":"connected","text":"PubSub endpoint ready. Subscribe to 'ticker' for per-client push or 'announce' for broadcasts."})");
    }

    void Stop() override
    {
        m_running = false;
        if (m_thread.joinable())
            m_thread.join();

        std::cout << "[pubsub] client disconnected\n";
    }

    void store_session_id(const http::server::request& /*req*/,
                          const http::server::reply&   /*rep*/) override {}

    // ------------------------------------------------------------------
    // Called via ForEachHandler to deliver a broadcast to this client.
    // Silently drops the message if this client is not subscribed.
    // ------------------------------------------------------------------
    void SendToTopic(const std::string& topic, const std::string& json_msg)
    {
        if (isSubscribed(topic))
            m_writer(json_msg);
    }

private:
    bool isSubscribed(const std::string& topic)
    {
        std::lock_guard<std::mutex> lock(m_topicsMutex);
        return m_topics.count(topic) > 0;
    }

    // Pattern 1: per-handler background thread — pushes only to this connection.
    void Do_Work()
    {
        int tick = 0;
        while (m_running)
        {
            // Sleep in short increments so Stop() is responsive.
            for (int i = 0; i < 20 && m_running; ++i)
                std::this_thread::sleep_for(std::chrono::milliseconds(100));

            if (!m_running)
                break;

            ++tick;

            if (isSubscribed("ticker"))
            {
                Json::Value msg;
                msg["event"] = "tick";
                msg["count"] = tick;
                m_writer(msg.toStyledString());
            }
        }
    }

    http::server::cWebem*                    m_webem;
    std::function<void(const std::string&)>  m_writer;
    std::map<std::string, bool>              m_topics;
    std::mutex                               m_topicsMutex;
    std::atomic<bool>                        m_running { false };
    std::thread                              m_thread;
};

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main()
{
    http::server::server_settings settings;
    settings.listening_address = "::";
    settings.listening_port    = "8080";

    http::server::cWebem server(settings, "./www");
    g_server = &server;

    std::signal(SIGINT,  signal_handler);
    std::signal(SIGTERM, signal_handler);

    // Register echo endpoint: ws://localhost:8080/ws/echo
    server.RegisterWebsocketEndpoint(
        "/ws/echo",
        [](http::server::cWebem* webem,
           std::function<void(const std::string&)> writer)
        {
            return std::make_shared<EchoHandler>(webem, std::move(writer));
        },
        "echo"
    );

    // Register pub/sub endpoint: ws://localhost:8080/ws/pubsub
    server.RegisterWebsocketEndpoint(
        "/ws/pubsub",
        [](http::server::cWebem* webem,
           std::function<void(const std::string&)> writer)
        {
            return std::make_shared<PubSubHandler>(webem, std::move(writer));
        },
        "pubsub"
    );

    // Server-side broadcast thread: pushes a server announcement to all clients
    // subscribed to "announce" every 15 seconds.  This demonstrates that
    // ForEachHandler can be called from any thread, not just from within a
    // WebSocket message handler.
    std::thread announceThread([&server]() {
        int count = 0;
        while (g_running)
        {
            for (int i = 0; i < 150 && g_running; ++i)
                std::this_thread::sleep_for(std::chrono::milliseconds(100));

            if (!g_running)
                break;

            ++count;

            Json::Value msg;
            msg["event"] = "message";
            msg["topic"] = "announce";
            msg["text"]  = "Server announcement #" + std::to_string(count);
            const std::string json = msg.toStyledString();

            std::cout << "[server] broadcasting announcement #" << count << "\n";

            server.ForEachHandler([&json](http::server::IWebsocketHandler* h) {
                auto* handler = dynamic_cast<PubSubHandler*>(h);
                if (handler)
                    handler->SendToTopic("announce", json);
            });
        }
    });

    std::cout << "WebSocket server running on http://localhost:8080\n";
    std::cout << "  Echo endpoint:   ws://localhost:8080/ws/echo\n";
    std::cout << "  PubSub endpoint: ws://localhost:8080/ws/pubsub\n";
    std::cout << "  Web client:      http://localhost:8080/\n";
    std::cout << "Press Ctrl+C to stop.\n";

    server.Run();

    g_running = false;
    announceThread.join();

    std::cout << "Server stopped.\n";
    return 0;
}
