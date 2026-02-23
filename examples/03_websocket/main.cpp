// Example 03 — WebSocket server with multiple endpoints
//
// Demonstrates:
//   - Implementing IWebsocketHandler for custom message handling
//   - Registering multiple WebSocket endpoints on different URL paths
//   - Using the writer function to send messages back to the client
//   - Lifecycle callbacks: Start() and Stop()
//   - Sub-protocol negotiation
//
// Run:
//   ./websocket_server
//   Open http://localhost:8080/ in a browser for an interactive test client.
//   Or test with wscat:
//     npx wscat -c ws://localhost:8080/ws/echo
//     npx wscat -c ws://localhost:8080/ws/chat

#include <libwebem/cWebem.h>
#include <libwebem/IWebsocketHandler.h>
#include <iostream>
#include <csignal>

static http::server::cWebem* g_server = nullptr;

static void signal_handler(int /*sig*/)
{
    if (g_server)
        g_server->Stop();
}

// ---------------------------------------------------------------------------
// EchoHandler — sends back exactly what it receives
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
        m_writer(data);   // echo back
        return true;
    }

    void Start() override
    {
        std::cout << "[echo] client connected\n";
        m_writer("Welcome to the echo endpoint!");
    }

    void Stop() override
    {
        std::cout << "[echo] client disconnected\n";
    }

    void store_session_id(const http::server::request& /*req*/,
                          const http::server::reply&  /*rep*/) override
    {}

private:
    std::function<void(const std::string&)> m_writer;
};

// ---------------------------------------------------------------------------
// ChatHandler — wraps messages in a simple JSON envelope
// ---------------------------------------------------------------------------
class ChatHandler : public http::server::IWebsocketHandler
{
public:
    ChatHandler(http::server::cWebem* /*webem*/,
                std::function<void(const std::string&)> writer)
        : m_writer(std::move(writer))
    {}

    bool Handle(const std::string& data, bool outbound) override
    {
        if (outbound)
            return true;

        std::cout << "[chat] message: " << data << "\n";

        // Wrap the received text in a JSON envelope.
        // In a real application you would parse the JSON and broadcast to all
        // connected clients.  This single-connection demo just sends a reply.
        std::string response = R"({"type":"message","from":"server","text":")" + data + R"("})";
        m_writer(response);
        return true;
    }

    void Start() override
    {
        std::cout << "[chat] client connected\n";
        m_writer(R"({"type":"welcome","text":"Welcome to the chat endpoint!"})");
    }

    void Stop() override
    {
        std::cout << "[chat] client disconnected\n";
    }

    void store_session_id(const http::server::request& /*req*/,
                          const http::server::reply&  /*rep*/) override
    {}

private:
    std::function<void(const std::string&)> m_writer;
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
        "echo"   // Sec-WebSocket-Protocol sub-protocol name
    );

    // Register chat endpoint: ws://localhost:8080/ws/chat
    server.RegisterWebsocketEndpoint(
        "/ws/chat",
        [](http::server::cWebem* webem,
           std::function<void(const std::string&)> writer)
        {
            return std::make_shared<ChatHandler>(webem, std::move(writer));
        },
        "chat-v1"
    );

    std::cout << "WebSocket server running on http://localhost:8080\n";
    std::cout << "  Echo endpoint: ws://localhost:8080/ws/echo\n";
    std::cout << "  Chat endpoint: ws://localhost:8080/ws/chat\n";
    std::cout << "  Web client:    http://localhost:8080/\n";
    std::cout << "Press Ctrl+C to stop.\n";

    server.Run();

    std::cout << "Server stopped.\n";
    return 0;
}
