#include "util.h"
#include "config/version.h"

#include <cctype>
#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <limits>
#include <mutex>
#include <thread>
#include <string_view>

#if WINDOWS
#  define WIN32_LEAN_AND_MEAN 1
#  include <windows.h>
#  include <winsock2.h>
#  include <mstcpip.h>
#  include <ws2tcpip.h>
#  include <psapi.h>
#  include <io.h>              // for _write(), _read(), _pipe(), _close()
#  include <fcntl.h>           // for O_BINARY, O_TEXT
#  include <errno.h>           // for errno
#elif UNIX
#  include <netinet/in.h>
#  include <netinet/tcp.h>
#  include <stdio.h>           // for fileno()
#  if __has_include(<sys/types.h>)
#    include <sys/types.h>
#  endif
#  include <sys/socket.h>      // for setsockopt()
#  include <unistd.h>          // for write(), read(), pipe(), close(), isatty()
#endif

InternalError::~InternalError() {} // for vtable

/* static */ std::atomic<int> Log::logLevel = static_cast<int>(VERSION_IS_RELEASE ? Level::Info : Level::Debug);

/* static */ std::function<void()> Log::fatalCallback;

static const auto g_main_thread_id = std::this_thread::get_id();

static bool isMainThread(std::thread::id *id_out = nullptr) {
    const auto tid = std::this_thread::get_id();
    if (id_out) *id_out = tid;
    return tid == g_main_thread_id;
}

Log::~Log()
{
    if (doprt) {
        std::string thrdStr;
        if (!isMainThread()) {
            thrdStr = "<" + util::ThreadGetName() + "> ";
        }
        const std::string theString = thrdStr + (isaTTY(useStdOut) ? colorize(s.str(), color) : s.str()) + (autoNewLine ? "\n" : "");

        // just print to console for now..
        auto * const strm = useStdOut ? stdout : stderr;
        {
            static std::mutex mut;
            std::unique_lock g(mut);
            std::fwrite(theString.c_str(), sizeof(std::string::value_type), theString.size(), strm);
            if (!didDisableStdBuffering) std::fflush(strm);
        }

        // Fatal flags the app to quit
        if (level == static_cast<int>(Level::Fatal) && fatalCallback) {
            fatalCallback();
        }
    }
}

/* static */
bool Log::isaTTY(const bool stdOut) {
    auto inner = [](bool stdOut) -> bool {
#if WINDOWS
        if (const int fd = _fileno(stdOut ? stdout : stderr); fd >= 0 && _isatty(fd)) {
            HANDLE h = GetStdHandle(stdOut ? STD_OUTPUT_HANDLE : STD_ERROR_HANDLE); // handle h should not be CloseHandle'd
            // set console mode to enable VT codes
            if (DWORD mode{}; h != INVALID_HANDLE_VALUE && GetConsoleMode(h, &mode) && SetConsoleMode(h, mode | 0x0004 /* ENABLE_VIRTUAL_TERMINAL_PROCESSING */))
                return true;
        }
        return false;
#else
        const int fd = fileno(stdOut ? stdout : stderr);
        return isatty(fd);
#endif
    };
    static const bool cached[2] = {inner(false), inner(true)};
    return cached[stdOut];
}

/* static */
bool Log::disableStdBuffering() {
    if (std::setvbuf(stdout, nullptr, _IONBF, 8192) == 0 && std::setvbuf(stderr, nullptr, _IONBF, 8192) == 0) {
        didDisableStdBuffering = true;
        return true;
    }
    return false;
}

/* static */
std::string Log::colorString(Color c) {
    using namespace std::string_view_literals;

    std::string str{"\033"sv}; /* prefix, esc = 033 in octal */

    switch(c) {
    case Black: str += "[30m"sv; break;
    case Red: str += "[31m"sv; break;
    case Green: str += "[32m"sv; break;
    case Yellow: str += "[33m"sv; break;
    case Blue: str += "[34m"sv; break;
    case Magenta: str += "[35m"sv; break;
    case Cyan: str += "[36m"sv; break;
    case White: str += "[37m"sv; break;
    case BrightBlack: str += "[30;1m"sv; break;
    case BrightRed: str += "[31;1m"sv; break;
    case BrightGreen: str += "[32;1m"sv; break;
    case BrightYellow: str += "[33;1m"sv; break;
    case BrightBlue: str += "[34;1m"sv; break;
    case BrightMagenta: str += "[35;1m"sv; break;
    case BrightCyan: str += "[36;1m"sv; break;
    case BrightWhite: str += "[37;1m"sv; break;
    case Normal:
    default:
        str += "[0m"sv; // normal
        break;
    }

    return str;
}

std::string Log::colorize(const std::string &str, Color c) {
    std::string colorStr = useColor && c != Normal ? colorString(c) : "";
    std::string normalStr = useColor && c != Normal ? colorString(Normal) : "";
    return colorStr + str + normalStr;
}

template <> Log & Log::operator<<(const Color &c) { setColor(c); return *this; }
template <> Log & Log::operator<<(const std::string &t) { s << t.c_str(); return *this; }

Debug::~Debug()
{
    level = static_cast<int>(Level::Debug);
    doprt = isEnabled();
    if (!doprt) return;
    if (!colorOverridden) color = Cyan;
    s.str("(Debug) " + s.str());
}

bool Debug::forceEnable = false;

bool Debug::isEnabled() {
    return forceEnable || logLevel.load() >= static_cast<int>(Level::Debug);
}

Trace::~Trace()
{
    level = static_cast<int>(Level::Debug);
    doprt = isEnabled();
    if (!doprt) return;
    if (!colorOverridden) color = Green;
    s.str("(Trace) " + s.str());
}

bool Trace::forceEnable = false;

bool Trace::isEnabled() {
    return forceEnable || logLevel.load() >= static_cast<int>(Level::Trace);
}

Error::~Error()
{
    level = static_cast<int>(Level::Critical);
    if (!colorOverridden) color = BrightRed;
}

Warning::~Warning()
{
    level = static_cast<int>(Level::Warning);
    if (!colorOverridden) color = Yellow;
}

Fatal::~Fatal()
{
    level = static_cast<int>(Level::Fatal);
    s.str("FATAL: " + s.str());
    if (!colorOverridden) color = BrightRed;
}

namespace AsyncSignalSafe {
namespace {
#if WINDOWS
auto writeFD = ::_write; // Windows API docs say to use this function, since write() is deprecated
auto readFD  = ::_read;  // Windows API docs say to use this function, since read() is deprecated
auto closeFD = ::_close; // Windows API docs say to use this function, since close() is deprecated
inline constexpr std::array<char, 3> NL{"\r\n"};
#elif UNIX
auto writeFD = ::write;
auto readFD  = ::read;
auto closeFD = ::close;
inline constexpr std::array<char, 2> NL{"\n"};
#else
// no-op on unknown platform (this platform would use the cond variable and doesn't need read/close/pipe)
auto writeFD = [](int, const void *, size_t n) { return int(n); };
inline constexpr std::array<char, 1> NL{0};
#endif
}
void writeStdErr(const std::string_view &sv, bool wrnl) noexcept {
    constexpr int stderr_fd = 2; /* this is the case on all platforms */
    writeFD(stderr_fd, sv.data(), sv.length());
    if (wrnl && NL.size() > 1)
        writeFD(stderr_fd, NL.data(), NL.size()-1);
}
#if WINDOWS || UNIX
Sem::Pipe::Pipe() {
    const int res =
#    if WINDOWS
        ::_pipe(fds, 32 /* bufsize */, O_BINARY);
#    else
        ::pipe(fds);
#    endif
    if (res != 0)
        throw InternalError(std::format("Failed to create a Cond::Pipe: ({}) {}", errno, std::strerror(errno)));
}
Sem::Pipe::~Pipe() { closeFD(fds[0]), closeFD(fds[1]); }
std::optional<SBuf<>> Sem::acquire() noexcept {
    std::optional<SBuf<>> ret;
    char c;
    if (const int res = readFD(p.fds[0], &c, 1); res != 1)
        ret.emplace("Sem::acquire: readFD returned ", res);
    return ret;
}
std::optional<SBuf<>> Sem::release() noexcept {
    std::optional<SBuf<>> ret;
    const char c = 0;
    if (const int res = writeFD(p.fds[1], &c, 1); res != 1)
        ret.emplace("Sem::release: writeFD returned ", res);
    return ret;
}
#else /* !WINDOWS && !UNIX */
// fallback to emulated -- use std C++ condition variable which is not technically
// guaranteed async signal safe, but for all pratical purposes it's safe enough as a fallback.
std::optional<SBuf<>> Sem::acquire() noexcept {
    std::mutex dummy; // hack, but works
    std::unique_lock l(dummy);
    p.cond.wait(l);
    return std::nullopt;
}
std::optional<SBuf<>> Sem::release() noexcept {
    p.cond.notify_one();
    return std::nullopt;
}
#endif // WINDOWS || UNIX
} // end namespace AsyncSignalSafe

namespace util {
namespace { thread_local std::string g_thread_name; }

bool SetupNetworking() {
#if WINDOWS
    // the below guard is to ensure we can call SetupNetworking() from multiple
    // places in the codebase and that WSAStartup() will only execute precisely
    // once, with the results cached in the static variable.
    static const bool wsaResult = [] {
        // Initialize Windows Sockets.
        WSADATA wsadata;
        int ret = WSAStartup(MAKEWORD(2, 2), &wsadata);
        if (ret != NO_ERROR || LOBYTE(wsadata.wVersion) != 2 ||
            HIBYTE(wsadata.wVersion) != 2) {
            return false;
        }
        return true;
    }();
    return wsaResult;
#else
    return true;
#endif
}

const std::string & ThreadGetName() {
    if (!g_thread_name.empty()) {
        return g_thread_name;
    } // else ...
    static thread_local std::string fallback_name;
    if (fallback_name.empty()) {
        if (std::thread::id tid; isMainThread(&tid)) {
            fallback_name = "main";
        } else {
            std::ostringstream os;
            os << tid << std::flush;
            fallback_name = os.str();
        }
    }
    return fallback_name;
}

#if (defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__DragonFly__))
#include <pthread.h>
#include <pthread_np.h>
#endif

#if  __has_include(<sys/prctl.h>)
#include <sys/prctl.h> // For prctl, PR_SET_NAME, PR_GET_NAME
#endif

void ThreadSetName(std::string_view name) {
    g_thread_name = name;
#if defined(PR_SET_NAME)
    // Only the first 15 characters are used (16 - NUL terminator)
    ::prctl(PR_SET_NAME, g_thread_name.c_str(), 0, 0, 0);
#elif (defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__DragonFly__))
    pthread_set_name_np(pthread_self(), g_thread_name.c_str());
#elif defined(__MACH__) && defined(__APPLE__)
    pthread_setname_np(g_thread_name.c_str());
#endif
}

namespace {
const int8_t hexDigits[256] = {
    -1, -1,  -1,  -1,  -1,  -1,  -1,  -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1,  -1,  -1,  -1,  -1,  -1,  -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1,  -1,  -1,  -1,  -1,  -1,  -1, -1, -1, -1, -1, -1, -1, -1, -1,
     0,  1,   2,   3,   4,   5,   6,   7,  8,  9, -1, -1, -1, -1, -1, -1,
    -1, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1,  -1,  -1,  -1,  -1,  -1,  -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1,  -1,  -1,  -1,  -1,  -1,  -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1,  -1,  -1,  -1,  -1,  -1,  -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1,  -1,  -1,  -1,  -1,  -1,  -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1,  -1,  -1,  -1,  -1,  -1,  -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1,  -1,  -1,  -1,  -1,  -1,  -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1,  -1,  -1,  -1,  -1,  -1,  -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1,  -1,  -1,  -1,  -1,  -1,  -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1,  -1,  -1,  -1,  -1,  -1,  -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1,  -1,  -1,  -1,  -1,  -1,  -1, -1, -1, -1, -1, -1, -1, -1, -1,
};
const char hexMap[513] =
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"
    "303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"
    "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f"
    "909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
    "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef"
    "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";

} // namespace

std::optional<std::vector<uint8_t>> FromHex(std::string_view s) {
    std::vector<uint8_t> vch;
    // skip leading and trailing whitespace
    while (!s.empty() && std::isspace(s.front())) s = s.substr(1);
    while (!s.empty() && std::isspace(s.back())) s = s.substr(0, s.size() - 1);
    if (s.size() % 2 != 0) return std::nullopt; // invalid number of chars
    vch.reserve(s.size() / 2);
    for (size_t i = 0; i < s.size(); i += 2) {
        static_assert(std::numeric_limits<uint8_t>::max() < std::size(hexDigits));
        const int8_t c1 = hexDigits[uint8_t(s[i])],
                     c2 = hexDigits[uint8_t(s[i + 1])];
        if (c1 < 0 || c2 < 0) return std::nullopt; // not in hex charset
        vch.push_back((uint8_t(c1) << 4) | uint8_t(c2));
    }
    return vch;
}

std::string ToHex(std::span<const uint8_t> bytes) {
    std::string ret;
    ret.reserve(bytes.size() * 2);
    for (const unsigned b : bytes) {
        static_assert(std::numeric_limits<uint8_t>::max() * 2u + 2u < std::size(hexMap));
        const char * const digitPair = hexMap + b * 2u;
        ret.append(digitPair, 2);
    }
    return ret;
}

std::string_view Trim(std::string_view str) {
    while (!str.empty() && std::isspace(str.front())) str = str.substr(1);
    while (!str.empty() && std::isspace(str.back())) str = str.substr(0, str.size() - 1);
    return str;
}

bool EqualsIgnoreCase(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    return ToLower(a) == ToLower(b);
}

bool SocketSetKeepAlive(const int sockfd, const bool bkeepalive,
                        const int tcp_keepcnt [[maybe_unused]], const int tcp_keepidle [[maybe_unused]],
                        const int tcp_keepintvl [[maybe_unused]])
{
    const int keepalive = bkeepalive;
#ifndef WIN32
    if (UNLIKELY(setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive))))
        return false;
#ifdef __linux
    if (UNLIKELY(setsockopt(sockfd, SOL_TCP, TCP_KEEPCNT, &tcp_keepcnt, sizeof(tcp_keepcnt))))
        return false;
    if (unlikely(setsockopt(sockfd, SOL_TCP, TCP_KEEPIDLE, &tcp_keepidle, sizeof(tcp_keepidle))))
        return false;
    if (UNLIKELY(setsockopt(sockfd, SOL_TCP, TCP_KEEPINTVL, &tcp_keepintvl, sizeof(tcp_keepintvl))))
        return false;
#endif /* __linux */
#ifdef __APPLE_CC__
    if (UNLIKELY(setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPALIVE, &tcp_keepintvl, sizeof(tcp_keepintvl))))
        return false;
#endif /* __APPLE_CC__ */
#else /* WIN32 */
    struct tcp_keepalive vals = {};
    vals.onoff = keepalive;
    vals.keepalivetime = tcp_keepidle * 1000;
    vals.keepaliveinterval = tcp_keepintvl * 1000;
    DWORD outputBytes;
    if (UNLIKELY(WSAIoctl(sockfd, SIO_KEEPALIVE_VALS, &vals, sizeof(vals), nullptr, 0, &outputBytes, nullptr, nullptr)))
        return false;
#endif /* WIN32 */

    return true;
}

} // namespace util
