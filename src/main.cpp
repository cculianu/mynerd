#include "config/version.h"
#include "hash.h"
#include "util.h"

// TESTING
#include <cassert>
#include <charconv>
#include <list>
#include <string>
#include <string_view>
#include <utility>
#include <curl/curl.h> // TESTING

#include <univalue.h>
// /TESTING

#include <stdexcept>

namespace {
std::string UserAgent{PROG_NAME_STR "/" PROG_VERSION_STR};

enum TestFlags {
    TF_None = 0,
    TF_LongPoll = 1 << 0,
};

void testCurl(const std::string & url, const std::string &rpc_req, const std::string &userpass = {},
              const int testFlags = TF_None) {
    CURL *curl = curl_easy_init();

    if (UNLIKELY(!curl)) {
        Error("CURL initialization failed");
        return;
    }

    Defer d([&curl] { if (curl) { curl_easy_cleanup(curl); curl = nullptr; } });

    struct Header {
        size_t content_length = 0u;
        std::string lp_path, reason, stratum_url;
        std::list<std::pair<std::string, std::string>> extra_headers;
    };

    struct AllData {
        Header header;
        std::string data;
    };

    AllData all_data;

    static const
    auto all_data_cb = [](const void *ptr, size_t size, size_t nmemb, void *user_data) -> size_t {
        AllData *ad = std::launder(reinterpret_cast<AllData *>(reinterpret_cast<char *>(user_data)));
        assert(ad);
        const size_t len = size * nmemb;
        Debug() << "Got data of length: " << len;
        auto & data = ad->data;
        // Pre-allocate Content-Length bytes, up to 8MB
        if (const size_t prealloc = std::min<size_t>(8'000'000, ad->header.content_length); data.capacity() < prealloc) {
            data.reserve(prealloc);
            DebugMF("all_data_cb: Preallocated: {} bytes", prealloc);
        }
        data.append(reinterpret_cast<const char *>(ptr), len);
        DebugMF("all_data_cb: Copied {} bytes", len);
        return len;
    };

    static const
    auto resp_hdr_cb = [](const void *ptr, size_t size, size_t nmemb, void *user_data) -> size_t {
        Header *h = std::launder(reinterpret_cast<Header *>(reinterpret_cast<char *>(user_data)));
        assert(h);
        const size_t len = size * nmemb;
        std::string_view line(reinterpret_cast<const char *>(ptr), len);
        auto pos = line.find(':');
        if (pos == line.npos || pos == 0u) return len; // skip empty lines
        auto key = line.substr(0, pos);
        auto val = line.substr(pos + 1);
        // trim leading/trailing spaces
        for (auto *v : {&key, &val}) *v = util::Trim(*v);
        DebugMF("Parsed header: key = \"{}\", val = \"{}\"", key, val);
        if (val.empty() || key.empty()) return len; // skip empty key and/or val

        if (util::EqualsIgnoreCase(key, "X-Long-Polling"))
            h->lp_path = val;
        else if (util::EqualsIgnoreCase(key, "X-Reject-Reason"))
            h->reason = val;
        else if (util::EqualsIgnoreCase(key, "X-Stratum"))
            h->stratum_url = val;
        else if (util::EqualsIgnoreCase(key, "Content-Length")) {
            auto res = std::from_chars(val.begin(), val.end(), h->content_length);
            if (res.ec != decltype(res.ec){}) {
                Error("Cannot parse content length \"{}\", got ec result: {}", val, int(res.ec));
            }
        } else
            h->extra_headers.emplace_back(key, val);
        return len;
    };

    char curl_err_str[CURL_ERROR_SIZE] = {0};
    const long timeout = 30;

    if (Log::logLevel >= int(Log::Level::Trace))
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    //if (opt_cert)
    //    curl_easy_setopt(curl, CURLOPT_CAINFO, opt_cert);
    curl_easy_setopt(curl, CURLOPT_ENCODING, "");
    curl_easy_setopt(curl, CURLOPT_FAILONERROR, 0);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
    curl_easy_setopt(curl, CURLOPT_TCP_NODELAY, 1);
    using CbFunc = size_t (*)(const void *, size_t, size_t, void *); // required to avoid UB with lambdas above
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, static_cast<CbFunc>(all_data_cb));
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, reinterpret_cast<char *>(&all_data));
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curl_err_str);
    //if (opt_redirect)
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, static_cast<CbFunc>(resp_hdr_cb));
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, reinterpret_cast<char *>(&all_data.header));
    //if (opt_proxy) {
    //    curl_easy_setopt(curl, CURLOPT_PROXY, opt_proxy);
    //    curl_easy_setopt(curl, CURLOPT_PROXYTYPE, opt_proxy_type);
    //}
    if (!userpass.empty()) {
        curl_easy_setopt(curl, CURLOPT_USERPWD, userpass.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
    }
    if constexpr (LIBCURL_VERSION_NUM >= 0x070f06) {
        if (testFlags & TF_LongPoll) {
            static  const auto sockopt_keepalive_cb = [](void *, curl_socket_t fd, curlsocktype) -> int {
                if ( ! util::SocketSetKeepAlive(fd, true) ) {
                    Error("sockopt_keepalive_cb: failed to set keepalive on socket {}", fd);
                    return 1;
                }
                DebugMF("sockopt_keepalive_cb: success on socket {}", fd);
                return 0;
            };
            using KeepAliveCb = int (*)(void *, curl_socket_t, curlsocktype);
            curl_easy_setopt(curl, CURLOPT_SOCKOPTFUNCTION, static_cast<KeepAliveCb>(sockopt_keepalive_cb));
        }
    }
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, rpc_req.c_str());
    //if (opt_protocol)
        DebugM("JSON protocol request: ", rpc_req);

    curl_slist *headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, ("User-Agent: " + UserAgent).c_str());
    headers = curl_slist_append(headers, "X-Mining-Extensions: midstate");
    headers = curl_slist_append(headers, "Accept:"); /* disable Accept hdr*/
    headers = curl_slist_append(headers, "Expect:"); /* disable Expect hdr*/

    Defer d2([&headers] { if (headers) curl_slist_free_all(headers); headers = nullptr; });

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    const int rc = curl_easy_perform(curl);
    long http_rc{};
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_rc);
    if (rc || (http_rc != 200 && http_rc != 500)) {
        Error("HTTP request failed: code={}, error={}", http_rc, curl_err_str);
        return;
    }

#if 0
    /* If X-Stratum was found, activate Stratum */
    if (want_stratum && hi.stratum_url &&
        !strncasecmp(hi.stratum_url, "stratum+tcp://", 14)) {
        have_stratum = true;
        tq_push(thr_info[stratum_thr_id].q, hi.stratum_url);
        hi.stratum_url = NULL;
    }
#endif

#if 0
    /* If X-Long-Polling was found, activate long polling */
    if (!have_longpoll && want_longpoll && hi.lp_path && !have_gbt &&
        allow_getwork && !have_stratum) {
        have_longpoll = true;
        tq_push(thr_info[longpoll_thr_id].q, hi.lp_path);
        hi.lp_path = NULL;
    }
#endif

    if (Debug::isEnabled())
        for (const auto & [k, v] : all_data.header.extra_headers)
            Debug("Extra-header -> {}: {}", k, v);

    if (all_data.data.empty()) {
        Error("Empty data received in json_rpc_call.");
        return;
    }

    TraceMF("RAW response:\n{}\n", all_data.data);

    UniValue uv;
    if (!uv.read(all_data.data)) {
        Error("Failed to parse: {}", all_data.data);
        return;
    }

    if (auto *error = uv.locate("error"); error && !error->isNull()) {
        Warning(Log::Color::BrightYellow, "error:\n{}\n", UniValue::stringify(*error, 2));
    } else if (auto *result = uv.locate("result"); result && !result->isNull()) {
        Log("result:\n{}\n", UniValue::stringify(*result, 2));
    } else {
        Error("Unexpected response: {}", all_data.data);
    }
}

} // namespace

int main(int argc, char **argv) {
    if (!util::SetupNetworking()) throw std::runtime_error("Failed to setup networking");
    if (!Log::disableStdBuffering()) throw std::runtime_error("Failed to disable stdio buffering");
    Log::logLevel = int(Log::Level::Trace); // force Trace log

    Log(Log::BrightCyan) << PROG_NAME_STR << " " << PROG_VERSION_STR << Log::NoNL;
    Log(Log::BrightGreen) << " Using SHA256: " << GetSha256Implementation();
    Log() << util::ToHex(Hash(util::FromHex("010203").value()));

    if (argc > 2) {
        testCurl(argv[1], argv[2], argc > 3 ? argv[3] : "", TF_LongPoll);
    }
    return 0;
}
