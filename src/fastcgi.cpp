#include "webem_stdafx.h"
#include "fastcgi.h"
#include <fstream>
#include <sstream>
#include <vector>
#include <map>
#include "url_encode.h"
#include <libwebem/webem_utils.h>

#ifndef WIN32
#include <unistd.h>
#include <sys/wait.h>
extern char **environ;
#endif

//(c) 2016 GizMoCuz

//To be done!
//ibfcgi-dev << source also contains win32 project
//The below is not FastCGI (yet)

namespace http {
	namespace server {

uint16_t fastcgi_parser::request_id_ = 1;
		
//http://www.mit.edu/~yandros/doc/specs/fcgi-spec.html
struct _tFCGI_Header {
	uint8_t version;
	uint8_t type;
	uint8_t requestIdB1;
	uint8_t requestIdB0;
	uint8_t contentLengthB1;
	uint8_t contentLengthB0;
	uint8_t paddingLength; //We recommend that records be placed on boundaries that are multiples of eight bytes. The fixed-length portion of a FCGI_Record is eight bytes.
	uint8_t reserved;
};

/*
* Number of bytes in a FCGI_Header.  Future versions of the protocol
* will not reduce this number.
*/
#define FCGI_HEADER_LEN  8

/*
* Value for version component of FCGI_Header
*/
#define FCGI_VERSION_1           1

#define FCGI_BEGIN_REQUEST       1
#define FCGI_ABORT_REQUEST       2
#define FCGI_END_REQUEST         3
#define FCGI_PARAMS              4
#define FCGI_STDIN               5
#define FCGI_STDOUT              6
#define FCGI_STDERR              7
#define FCGI_DATA                8
#define FCGI_GET_VALUES          9
#define FCGI_GET_VALUES_RESULT  10
#define FCGI_UNKNOWN_TYPE       11
#define FCGI_MAXTYPE (FCGI_UNKNOWN_TYPE)

/*
* Value for requestId component of FCGI_Header
*/
#define FCGI_NULL_REQUEST_ID     0

struct _tFCGI_BeginRequestBody {
	uint8_t roleB1;
	uint8_t roleB0;
	uint8_t flags;
	uint8_t reserved[5];
};

struct _tFCGI_BeginRequestRecord {
	_tFCGI_Header header;
	_tFCGI_BeginRequestBody body;
} ;

/*
* Mask for flags component of FCGI_BeginRequestBody
*/
#define FCGI_KEEP_CONN  1

/*
* Values for role component of FCGI_BeginRequestBody
*/
#define FCGI_RESPONDER  1
#define FCGI_AUTHORIZER 2
#define FCGI_FILTER     3

struct _tFCGI_EndRequestBody {
	uint8_t appStatusB3;
	uint8_t appStatusB2;
	uint8_t appStatusB1;
	uint8_t appStatusB0;
	uint8_t protocolStatus;
	uint8_t reserved[3];
};

struct _tFCGI_EndRequestRecord {
	_tFCGI_Header header;
	_tFCGI_EndRequestBody body;
};

/*
* Values for protocolStatus component of FCGI_EndRequestBody
*/
#define FCGI_REQUEST_COMPLETE 0
#define FCGI_CANT_MPX_CONN    1
#define FCGI_OVERLOADED       2
#define FCGI_UNKNOWN_ROLE     3

/*
* Variable names for FCGI_GET_VALUES / FCGI_GET_VALUES_RESULT records
*/
#define FCGI_MAX_CONNS  "FCGI_MAX_CONNS"
#define FCGI_MAX_REQS   "FCGI_MAX_REQS"
#define FCGI_MPXS_CONNS "FCGI_MPXS_CONNS"

struct _tFCGI_UnknownTypeBody {
	uint8_t type;
	uint8_t reserved[7];
};

struct _tFCGI_UnknownTypeRecord {
	_tFCGI_Header header;
	_tFCGI_UnknownTypeBody body;
};

#ifdef WIN32
// Quote a single argument according to the rules used by the Microsoft C runtime
// argv parser, so it survives CreateProcess without any shell interpretation.
static std::string Win32QuoteArg(const std::string &arg)
{
	if (!arg.empty() && arg.find_first_of(" \t\n\v\"") == std::string::npos)
		return arg;
	std::string q = "\"";
	for (size_t i = 0;; ++i)
	{
		unsigned num_backslashes = 0;
		while (i < arg.size() && arg[i] == '\\')
		{
			++i;
			++num_backslashes;
		}
		if (i == arg.size())
		{
			q.append(num_backslashes * 2, '\\');
			break;
		}
		if (arg[i] == '"')
		{
			q.append(num_backslashes * 2 + 1, '\\');
			q.push_back('"');
		}
		else
		{
			q.append(num_backslashes, '\\');
			q.push_back(arg[i]);
		}
	}
	q.push_back('"');
	return q;
}
#endif

// Execute a child process directly, WITHOUT going through a shell, capturing its
// stdout. The executable and its arguments are passed as a discrete argv array and
// all request-controlled data is passed through the child environment, so shell
// metacharacters can never be interpreted as commands (prevents command injection).
std::vector<char> ExecuteProcessAndReturnRaw(const std::string &exePath,
											 const std::vector<std::string> &args,
											 const std::map<std::string, std::string> &extraEnv)
{
	std::vector<char> myData;
#ifdef WIN32
	// Build the command line with per-argument quoting (no shell parsing).
	std::string cmdline = Win32QuoteArg(exePath);
	for (const auto &a : args)
	{
		cmdline += " ";
		cmdline += Win32QuoteArg(a);
	}

	// Build the environment block: inherit the parent environment, overlaid with
	// the CGI variables. Double-NUL terminated, sorted map keeps it well-formed.
	std::map<std::string, std::string> merged;
	if (LPCH envStrings = GetEnvironmentStringsA())
	{
		for (LPCH p = envStrings; *p;)
		{
			std::string entry(p);
			p += entry.size() + 1;
			size_t eq = entry.find('=');
			if (eq != std::string::npos && eq > 0)
				merged[entry.substr(0, eq)] = entry.substr(eq + 1);
		}
		FreeEnvironmentStringsA(envStrings);
	}
	for (const auto &kv : extraEnv)
		merged[kv.first] = kv.second;
	std::string envBlock;
	for (const auto &kv : merged)
	{
		envBlock += kv.first;
		envBlock += "=";
		envBlock += kv.second;
		envBlock.push_back('\0');
	}
	envBlock.push_back('\0');

	SECURITY_ATTRIBUTES sa{};
	sa.nLength = sizeof(sa);
	sa.bInheritHandle = TRUE;
	sa.lpSecurityDescriptor = nullptr;

	HANDLE hRead = nullptr, hWrite = nullptr;
	if (!CreatePipe(&hRead, &hWrite, &sa, 0))
		return myData;
	SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

	STARTUPINFOA si{};
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESTDHANDLES;
	si.hStdOutput = hWrite;
	si.hStdError = hWrite;
	si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
	PROCESS_INFORMATION pi{};

	std::vector<char> cmdlineBuf(cmdline.begin(), cmdline.end());
	cmdlineBuf.push_back('\0');

	BOOL ok = CreateProcessA(exePath.c_str(), cmdlineBuf.data(), nullptr, nullptr, TRUE,
							 0, static_cast<LPVOID>(&envBlock[0]), nullptr, &si, &pi);
	CloseHandle(hWrite);
	if (!ok)
	{
		CloseHandle(hRead);
		return myData;
	}

	char buf[4096];
	DWORD nread = 0;
	while (ReadFile(hRead, buf, sizeof(buf), &nread, nullptr) && nread > 0)
		myData.insert(myData.end(), buf, buf + nread);
	CloseHandle(hRead);
	WaitForSingleObject(pi.hProcess, INFINITE);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
#else
	// Build argv and envp fully in the parent, so the child only performs
	// async-signal-safe calls between fork() and execve().
	std::vector<std::string> argvStrings;
	argvStrings.reserve(args.size() + 1);
	argvStrings.push_back(exePath);
	for (const auto &a : args)
		argvStrings.push_back(a);
	std::vector<char *> argv;
	argv.reserve(argvStrings.size() + 1);
	for (auto &s : argvStrings)
		argv.push_back(const_cast<char *>(s.c_str()));
	argv.push_back(nullptr);

	std::vector<std::string> envStrings;
	for (char **e = environ; e != nullptr && *e != nullptr; ++e)
	{
		std::string entry(*e);
		std::string key = entry.substr(0, entry.find('='));
		if (extraEnv.find(key) == extraEnv.end())
			envStrings.push_back(entry);
	}
	for (const auto &kv : extraEnv)
		envStrings.push_back(kv.first + "=" + kv.second);
	std::vector<char *> envp;
	envp.reserve(envStrings.size() + 1);
	for (auto &s : envStrings)
		envp.push_back(const_cast<char *>(s.c_str()));
	envp.push_back(nullptr);

	int pipefd[2];
	if (pipe(pipefd) != 0)
		return myData;
	pid_t pid = fork();
	if (pid < 0)
	{
		close(pipefd[0]);
		close(pipefd[1]);
		return myData;
	}
	if (pid == 0)
	{
		// Child: redirect stdout to the pipe and exec directly (no shell).
		dup2(pipefd[1], STDOUT_FILENO);
		close(pipefd[0]);
		close(pipefd[1]);
		execve(exePath.c_str(), argv.data(), envp.data());
		_exit(127); // exec failed
	}
	close(pipefd[1]);
	char buf[4096];
	ssize_t n;
	while ((n = read(pipefd[0], buf, sizeof(buf))) > 0)
		myData.insert(myData.end(), buf, buf + static_cast<size_t>(n));
	close(pipefd[0]);
	int status = 0;
	waitpid(pid, &status, 0);
#endif
	return myData;
}

extern std::istream & safeGetline(std::istream & is, std::string & line);

bool fastcgi_parser::handlePHP(const server_settings &settings, const std::string &script_path, const request &req, reply &rep, modify_info &mInfo, const WebServerLogger &logger)
{
	std::string full_path = settings.www_root + script_path;
	std::ifstream is(full_path.c_str(), std::ios::in | std::ios::binary);
	if (!is)
	{
		rep = reply::stock_reply(reply::not_found);
		return false;
	}
	is.close();

	std::multimap<std::string, std::string> parameters;

	std::string request_path2 = req.uri; // we need the raw request string to parse the get-request
	std::string szQueryString;
	size_t paramPos = request_path2.find_first_of('?');
	if (paramPos != std::string::npos)
	{
		std::string params = request_path2.substr(paramPos + 1);
		szQueryString = request_path2.substr(paramPos + 1);
		std::string name;
		std::string value;

		size_t q = 0;
		size_t p = q;
		int flag_done = 0;
		const std::string &uri = params;
		while (!flag_done) {
			q = uri.find('=', p);
			if (q == std::string::npos)
			{
				break;
			}
			name = uri.substr(p, q - p);
			p = q + 1;
			q = uri.find('&', p);
			if (q != std::string::npos)
				value = uri.substr(p, q - p);
			else {
				value = uri.substr(p);
				flag_done = 1;
			}
			// the browser sends blanks as +
			while (true)
			{
				size_t p = value.find('+');
				if (p == std::string::npos)
					break;
				value.replace(p, 1, " ");
			}
			parameters.insert(std::pair< std::string, std::string >(name, value));
			p = q + 1;
		}
	}
	if (req.method == "POST") {
		const char *pContent_Type = request::get_req_header(&req, "Content-Type");
		if (pContent_Type)
		{
			if (strstr(pContent_Type, "multipart") != nullptr)
			{
				const char *pBoundary = strstr(pContent_Type, "boundary=");
				if (pBoundary != nullptr)
				{
					std::string szBoundary = std::string("--") + (pBoundary + 9);
					//Find boundary in content
					std::istringstream ss(req.content);
					std::string csubstr;
					int ii = 0;
					std::string vName;
					while (!ss.eof())
					{
						safeGetline(ss, csubstr);
						if (ii == 0)
						{
							//Boundary
							if (csubstr != szBoundary)
							{
								rep = reply::stock_reply(reply::bad_request);
								return false;
							}
							ii++;
						}
						else if (ii == 1)
						{
							if (csubstr.find("Content-Disposition:") != std::string::npos)
							{
								size_t npos = csubstr.find("name=\"");
								if (npos == std::string::npos)
								{
									rep = reply::stock_reply(reply::bad_request);
									return false;
								}
								vName = csubstr.substr(npos + 6);
								npos = vName.find('"');
								if (npos == std::string::npos)
								{
									rep = reply::stock_reply(reply::bad_request);
									return false;
								}
								vName = vName.substr(0, npos);
								ii++;
							}
						}
						else if (ii == 2)
						{
							if (csubstr.empty())
							{
								ii++;
								//2 empty lines, rest is data
								std::string szContent;
								size_t bpos = size_t(ss.tellg());
								szContent = req.content.substr(bpos, ss.rdbuf()->str().size() - bpos - szBoundary.size() - 6);
								parameters.insert(std::pair< std::string, std::string >(vName, szContent));
								break;
							}
						}
					}
				}
			}
		}
	}

	//
	
	_tFCGI_Header gfci;
	gfci.version = 1;
	gfci.type = 1;
	gfci.requestIdB1 = (request_id_ & 0xFF00 >> 8);
	gfci.requestIdB0 = request_id_ & 0xFF;
	gfci.paddingLength = 0;
	request_id_++;


	// CGI variables passed to the PHP process via its environment (NOT the command line).
	std::map<std::string, std::string> fcgi_params;
	fcgi_params["SCRIPT_FILENAME"] = settings.www_root + script_path;
	fcgi_params["QUERY_STRING"] = szQueryString;
	fcgi_params["REQUEST_METHOD"] = "GET";
	fcgi_params["CONTENT_TYPE"] = "";
	fcgi_params["CONTENT_LENGTH"] = "";
	fcgi_params["SCRIPT_NAME"] = script_path;
	fcgi_params["REQUEST_URI"] = script_path;
	fcgi_params["DOCUMENT_URI"] = script_path;
	fcgi_params["DOCUMENT_ROOT"] = settings.www_root;
	fcgi_params["SERVER_PROTOCOL"] = "HTTP/1.1";
	fcgi_params["REQUEST_SCHEME"] = "http";
	fcgi_params["GATEWAY_INTERFACE"] = "CGI/1.1";
	fcgi_params["SERVER_SOFTWARE"] = settings.server_name.empty() ? "webem" : settings.server_name;
	fcgi_params["REMOTE_ADDR"] = req.host_remote_address;
	fcgi_params["REMOTE_PORT"] = req.host_remote_port;
	fcgi_params["SERVER_ADDR"] = req.host_local_address;
	fcgi_params["SERVER_PORT"] = req.host_local_port;
	fcgi_params["SERVER_NAME"] = "localhost";
	fcgi_params["REDIRECT_STATUS"] = "200";

	// Expose request headers as HTTP_* CGI variables using their raw values.
	// These are environment values only and cannot be interpreted as commands.
	for (const auto &header : req.headers)
	{
		// Skip "Proxy" (case-insensitively): mapped straight through, it becomes
		// HTTP_PROXY in the child's environment, and libcurl/PHP streams/most
		// HTTP clients treat that variable as "use this as my outbound proxy"
		// (the httpoxy class of bugs, CVE-2016-5385). An unauthenticated client
		// could then redirect every outbound request the PHP script makes
		// through a server of its choosing. Apache, nginx and PHP itself all
		// added the same exclusion in 2016; there is no legitimate use of this
		// request header that requires it to reach the CGI environment.
		if (request::mg_strcasecmp(header.name.c_str(), "Proxy") == 0)
			continue;
		std::string rName = "HTTP_" + header.name;
		http::server::utils::str_replace(rName, "-", "_");
		http::server::utils::str_upper(rName);
		fcgi_params[rName] = header.value;
	}

	// The PHP-CGI binary receives ONLY the script path as an argument. Request
	// parameters are read by the script from the QUERY_STRING environment
	// variable, so they are not passed on the command line at all. This keeps
	// attacker-controlled data off argv entirely (defence in depth on top of the
	// no-shell spawn below).
	std::vector<std::string> args;
	args.push_back(full_path);

	if (logger) logger->Debug(DebugCategory::WebServer, "[PHP] Executing %s (%s)", settings.php_cgi_path.c_str(), full_path.c_str());
	std::vector<char> v = ExecuteProcessAndReturnRaw(settings.php_cgi_path, args, fcgi_params);
	std::string pret(v.begin(), v.end());
	if (pret.empty())
	{
		rep = reply::stock_reply(reply::not_found);
		return false;
	}
	rep.status = reply::ok;
	//Add the headers
	bool bDoneWithHeaders = false;
	while (!bDoneWithHeaders)
	{
		if (pret[0] == '\r') pret=pret.substr(1);	//Skip CR symbol if present
		
		size_t tpos = pret.find('\n');
		if (tpos == std::string::npos)
		{
			rep = reply::stock_reply(reply::internal_server_error);
			return false;
		}

		if (tpos == 0)
		{
			bDoneWithHeaders = true;
			pret = pret.substr(tpos + 1);
		}
		else
		{
			std::string theader = pret.substr(0, tpos);
			pret = pret.substr(tpos + 1);

			//Check if we have a status return
			if (theader.find("Status") == 0)
			{
				tpos = theader.find(':');
				if (tpos == std::string::npos)
					continue;
				theader = theader.substr(tpos + 1);
				if (theader[0] == ' ')
					theader = theader.substr(1);
				tpos = theader.find(' ');
				if (tpos == std::string::npos)
					continue;
				std::string errcode = theader.substr(0, tpos);
				rep = reply::stock_reply((reply::status_type)atoi(errcode.c_str()));
				return true;
			}

			tpos = theader.find(':');
			if (tpos == std::string::npos)
				continue;
			std::string hfirst = theader.substr(0, tpos);
			std::string hlast = theader.substr(tpos + 1);
			if (hlast.empty())
				continue;
			if (hlast[0] == ' ')
				hlast = hlast.substr(1);
			reply::add_header(&rep, hfirst, hlast);
		}
	}
	if (!pret.empty())
	{
		rep.content.append(pret);
		reply::add_header(&rep, "Content-Length", std::to_string(rep.content.size()));
	}
	mInfo.delay_status = true;
	return true;
}

	} // namespace server
} // namespace http
