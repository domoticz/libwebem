// Example 05 — Custom logger
//
// Demonstrates:
//   - Implementing IWebServerLogger with colored console output
//   - Writing access logs to a file (Apache Combined Log Format)
//   - Enabling/disabling verbose debug output at runtime
//   - Passing the logger to cWebem via the constructor
//
// Run:
//   ./custom_logger
//   curl http://localhost:8080/
//   curl http://localhost:8080/api/hello
//   cat access.log

#include <libwebem/cWebem.h>
#include <libwebem/IWebServerLogger.h>
#include <iostream>
#include <fstream>
#include <cstdarg>
#include <mutex>
#include <ctime>
#include <csignal>

// ---------------------------------------------------------------------------
// ConsoleLogger — writes to stdout/stderr with level prefixes and timestamps,
//                 and optionally appends access log entries to a file.
// ---------------------------------------------------------------------------
class ConsoleLogger : public http::server::IWebServerLogger
{
public:
    explicit ConsoleLogger(const std::string& access_log_path = "", bool verbose = false)
        : m_verbose(verbose)
    {
        if (!access_log_path.empty())
        {
            m_access_log.open(access_log_path, std::ios::app);
            if (!m_access_log.is_open())
                std::cerr << "[ConsoleLogger] WARNING: could not open access log: "
                          << access_log_path << "\n";
        }
    }

    // -----------------------------------------------------------------------
    // IWebServerLogger interface
    // -----------------------------------------------------------------------

    void Log(http::server::LogLevel level, const char* fmt, ...) override
    {
        char buf[4096];
        va_list args;
        va_start(args, fmt);
        vsnprintf(buf, sizeof(buf), fmt, args);
        va_end(args);

        std::lock_guard<std::mutex> lock(m_mutex);
        const char* prefix = nullptr;
        std::ostream* out  = &std::cout;
        switch (level)
        {
            case http::server::LogLevel::Error:
                prefix = "\033[31m[ERROR]\033[0m ";  // red
                out    = &std::cerr;
                break;
            case http::server::LogLevel::Status:
                prefix = "\033[32m[INFO ]\033[0m ";  // green
                break;
            default:
                prefix = "\033[90m[DEBUG]\033[0m ";  // grey
                break;
        }
        *out << timestamp() << " " << prefix << buf << "\n";
    }

    void Debug(http::server::DebugCategory /*category*/, const char* fmt, ...) override
    {
        if (!m_verbose)
            return;

        char buf[4096];
        va_list args;
        va_start(args, fmt);
        vsnprintf(buf, sizeof(buf), fmt, args);
        va_end(args);

        std::lock_guard<std::mutex> lock(m_mutex);
        std::cout << timestamp() << " \033[90m[DEBUG]\033[0m " << buf << "\n";
    }

    bool IsAccessLogEnabled() override
    {
        return m_access_log.is_open();
    }

    void AccessLog(const char* fmt, ...) override
    {
        if (!m_access_log.is_open())
            return;

        char buf[8192];
        va_list args;
        va_start(args, fmt);
        vsnprintf(buf, sizeof(buf), fmt, args);
        va_end(args);

        std::lock_guard<std::mutex> lock(m_mutex);
        m_access_log << buf << "\n";
        m_access_log.flush();
    }

    // -----------------------------------------------------------------------
    // Extra controls
    // -----------------------------------------------------------------------
    void SetVerbose(bool verbose) { m_verbose = verbose; }

private:
    std::mutex    m_mutex;
    std::ofstream m_access_log;
    bool          m_verbose;

    static std::string timestamp()
    {
        std::time_t now = std::time(nullptr);
        char buf[32];
        std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", std::localtime(&now));
        return buf;
    }
};

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
static http::server::cWebem* g_server = nullptr;

static void signal_handler(int /*sig*/)
{
    if (g_server)
        g_server->Stop();
}

int main()
{
    // ------------------------------------------------------------------
    // 1. Create and configure the logger
    // ------------------------------------------------------------------
    auto logger = std::make_shared<ConsoleLogger>("access.log", /*verbose=*/false);

    // ------------------------------------------------------------------
    // 2. Configure and create the server — pass the logger to the constructor
    // ------------------------------------------------------------------
    http::server::server_settings settings;
    settings.listening_address = "::";
    settings.listening_port    = "8080";

    // cWebem accepts a std::shared_ptr<IWebServerLogger> as the third argument.
    http::server::cWebem server(settings, "./www", logger);
    g_server = &server;

    std::signal(SIGINT,  signal_handler);
    std::signal(SIGTERM, signal_handler);

    // ------------------------------------------------------------------
    // 3. Register a simple endpoint so there is something to log
    // ------------------------------------------------------------------
    server.RegisterPageCode("/api/hello",
        [](http::server::WebEmSession& /*session*/,
           const http::server::request& /*req*/,
           http::server::reply& rep)
        {
            rep.status  = http::server::reply::ok;
            rep.content = R"({"message":"Hello from libwebem!"})";
            http::server::reply::add_header(&rep, "Content-Type", "application/json");
        },
        /*bypassAuthentication=*/true);

    // ------------------------------------------------------------------
    // 4. Start the server
    // ------------------------------------------------------------------
    std::cout << "Custom-logger server running on http://localhost:8080\n";
    std::cout << "  Access log:  ./access.log\n";
    std::cout << "  Try:  curl http://localhost:8080/api/hello\n";
    std::cout << "Press Ctrl+C to stop.\n";

    server.Run();

    std::cout << "Server stopped.\n";
    return 0;
}
