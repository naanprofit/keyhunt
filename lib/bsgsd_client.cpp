/*
 * libbsgsd_client implementation.
 *
 * Pure C++17, no third-party deps -- just POSIX sockets + getaddrinfo
 * + std::mutex.  Builds standalone into libbsgsd_client.a.
 */

#include "bsgsd_client.h"

#include <arpa/inet.h>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <errno.h>
#include <fcntl.h>
#include <future>
#include <mutex>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sstream>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <thread>
#include <unistd.h>
#include <vector>

namespace bsgsd_client {

namespace {

/* Connect to host:port with a soft timeout.  Returns fd>=0 on success, -1
 * on failure (and writes a human-readable error into err). */
int dial(const std::string &host, uint16_t port, double timeout_seconds,
         std::string &err) {
    struct addrinfo hints, *res = nullptr;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;     /* allow v4 or v6 */
    hints.ai_socktype = SOCK_STREAM;
    char port_str[16];
    std::snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);
    int gai = getaddrinfo(host.c_str(), port_str, &hints, &res);
    if (gai != 0 || res == nullptr) {
        err = "getaddrinfo(" + host + "): " + gai_strerror(gai);
        return -1;
    }

    int fd = -1;
    for (struct addrinfo *p = res; p != nullptr; p = p->ai_next) {
        fd = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) continue;

        /* Non-blocking connect with poll() so we can enforce timeout. */
        int flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);

        int rc = ::connect(fd, p->ai_addr, p->ai_addrlen);
        if (rc == 0) {
            fcntl(fd, F_SETFL, flags);
            break;
        }
        if (errno == EINPROGRESS) {
            struct pollfd pfd { fd, POLLOUT, 0 };
            int wait_ms = (timeout_seconds > 0) ? (int)(timeout_seconds * 1000) : 5000;
            int pr = poll(&pfd, 1, wait_ms);
            if (pr > 0 && (pfd.revents & POLLOUT)) {
                int so_err = 0; socklen_t sl = sizeof(so_err);
                getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_err, &sl);
                if (so_err == 0) {
                    fcntl(fd, F_SETFL, flags);
                    break;
                }
                err = "connect(" + host + "): " + std::strerror(so_err);
            } else if (pr == 0) {
                err = "connect(" + host + "): timeout";
            } else {
                err = "connect(" + host + "): poll: " + std::strerror(errno);
            }
        } else {
            err = "connect(" + host + "): " + std::strerror(errno);
        }
        ::close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

bool send_all(int fd, const std::string &data) {
    size_t sent = 0;
    while (sent < data.size()) {
        ssize_t n = ::send(fd, data.data() + sent, data.size() - sent,
#ifdef MSG_NOSIGNAL
                           MSG_NOSIGNAL
#else
                           0
#endif
                           );
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (n == 0) return false;
        sent += (size_t)n;
    }
    return true;
}

std::string recv_all(int fd, double timeout_seconds, std::string &err) {
    std::string buf;
    buf.reserve(4096);
    char tmp[4096];
    auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::milliseconds((int)(timeout_seconds * 1000));
    while (true) {
        if (timeout_seconds > 0) {
            auto now = std::chrono::steady_clock::now();
            if (now >= deadline) { err = "recv: timeout"; break; }
            int wait_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                              deadline - now).count();
            struct pollfd pfd { fd, POLLIN, 0 };
            int pr = poll(&pfd, 1, wait_ms);
            if (pr <= 0) { err = "recv: timeout"; break; }
        }
        ssize_t n = ::recv(fd, tmp, sizeof(tmp), 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            err = std::string("recv: ") + std::strerror(errno);
            break;
        }
        if (n == 0) break;       /* EOF -- daemon closed connection */
        buf.append(tmp, (size_t)n);
    }
    return buf;
}

/* Parse the header block of an HTTP response, populating result
 * fields.  Returns the body. */
std::string parse_http_response(const std::string &raw, SearchResult &out) {
    size_t pos = raw.find("\r\n\r\n");
    if (pos == std::string::npos) {
        out.error_message = "malformed HTTP: no header terminator";
        return "";
    }
    std::string header = raw.substr(0, pos);
    std::string body   = raw.substr(pos + 4);

    /* Status line */
    size_t sp1 = header.find(' ');
    if (sp1 != std::string::npos) {
        size_t sp2 = header.find(' ', sp1 + 1);
        if (sp2 != std::string::npos) {
            int code = std::atoi(header.substr(sp1 + 1, sp2 - sp1 - 1).c_str());
            if (code == 200) out.status = Status::FOUND;
            else if (code == 404) out.status = Status::NOT_FOUND;
            else if (code == 400) out.status = Status::BAD_REQUEST;
            else                  out.status = Status::NETWORK_ERROR;
        }
    }

    /* Header parsing -- look for X-* diagnostic fields. */
    auto get_h = [&header](const std::string &key) -> std::string {
        std::string needle = "\r\n" + key + ":";
        size_t p = header.find(needle);
        if (p == std::string::npos) {
            /* maybe at start */
            std::string alt = key + ":";
            if (header.compare(0, alt.size(), alt) == 0) p = 0;
            else return "";
        } else p += 2;
        size_t v = header.find(':', p) + 1;
        while (v < header.size() && (header[v] == ' ' || header[v] == '\t')) v++;
        size_t end = header.find("\r\n", v);
        if (end == std::string::npos) end = header.size();
        return header.substr(v, end - v);
    };

    std::string e = get_h("X-Elapsed-Seconds");
    if (!e.empty()) out.elapsed_seconds = std::atof(e.c_str());

    std::string steps = get_h("X-Steps");
    if (!steps.empty()) out.total_steps = std::strtoull(steps.c_str(), nullptr, 10);

    out.bsgs_endo_mode = get_h("X-BSGS-Endo");
    std::string gpu = get_h("X-GPU-Bloom");
    out.gpu_bloom = gpu.empty() ? -1 : std::atoi(gpu.c_str());

    for (int L = 0; L < 3; L++) {
        char k1[32], k2[32], k3[32];
        std::snprintf(k1, sizeof(k1), "X-Lane-%d-Probes", L);
        std::snprintf(k2, sizeof(k2), "X-Lane-%d-Hits",   L);
        std::snprintf(k3, sizeof(k3), "X-Lane-%d-Recov",  L);
        out.lanes[L].probes   = std::strtoull(get_h(k1).c_str(), nullptr, 10);
        out.lanes[L].hits     = std::strtoull(get_h(k2).c_str(), nullptr, 10);
        out.lanes[L].recovers = std::strtoull(get_h(k3).c_str(), nullptr, 10);
    }
    return body;
}

} /* anonymous namespace */

SearchResult search_one(const HostSpec &host,
                        const std::string &pubkey_hex,
                        const std::string &from_hex,
                        const std::string &to_hex,
                        double max_wait_seconds) {
    SearchResult r{};
    r.status = Status::NETWORK_ERROR;
    r.gpu_bloom = -1;

    std::string err;
    /* Connect timeout = 5s; total request timeout = max_wait or 1h cap. */
    double connect_to = 5.0;
    double read_to = (max_wait_seconds > 0) ? max_wait_seconds : 3600.0;

    int fd = dial(host.host, host.port, connect_to, err);
    if (fd < 0) {
        r.error_message = err;
        return r;
    }

    if (host.transport == Transport::TCP_SINGLE_LINE) {
        std::string req = pubkey_hex + " " + from_hex + ":" + to_hex + "\n";
        if (!send_all(fd, req)) {
            r.error_message = "send_all failed";
            ::close(fd);
            return r;
        }
        std::string reply = recv_all(fd, read_to, err);
        ::close(fd);
        if (!err.empty() && reply.empty()) {
            r.error_message = err;
            r.status = (err == "recv: timeout") ? Status::TIMEOUT
                                                : Status::NETWORK_ERROR;
            return r;
        }
        /* Trim trailing newline. */
        while (!reply.empty() && (reply.back() == '\n' || reply.back() == '\r'))
            reply.pop_back();
        if (reply == "404 Not Found") {
            r.status = Status::NOT_FOUND;
        } else if (reply == "400 Bad Request") {
            r.status = Status::BAD_REQUEST;
        } else if (!reply.empty()) {
            r.status = Status::FOUND;
            r.private_key_hex = reply;
        }
        return r;
    }

    /* HTTP POST JSON */
    std::ostringstream json;
    json << "{\"pubkey\":\"" << pubkey_hex
         << "\",\"from\":\"" << from_hex
         << "\",\"to\":\""   << to_hex << "\"}";
    std::string body = json.str();
    std::ostringstream req;
    req << "POST / HTTP/1.1\r\n"
        << "Host: " << host.host << ":" << host.port << "\r\n"
        << "Content-Type: application/json\r\n"
        << "Content-Length: " << body.size() << "\r\n"
        << "Connection: close\r\n"
        << "\r\n"
        << body;
    if (!send_all(fd, req.str())) {
        r.error_message = "send_all failed";
        ::close(fd);
        return r;
    }
    std::string reply = recv_all(fd, read_to, err);
    ::close(fd);
    if (reply.empty()) {
        r.error_message = err.empty() ? "empty response" : err;
        r.status = (err == "recv: timeout") ? Status::TIMEOUT
                                            : Status::NETWORK_ERROR;
        return r;
    }
    std::string http_body = parse_http_response(reply, r);
    /* Trim newline */
    while (!http_body.empty() && (http_body.back() == '\n' || http_body.back() == '\r'))
        http_body.pop_back();
    if (r.status == Status::FOUND) {
        r.private_key_hex = http_body;
    }
    return r;
}

/* ---------- Pool ---------- */

namespace {
double steady_now_seconds() {
    auto t = std::chrono::steady_clock::now().time_since_epoch();
    return std::chrono::duration<double>(t).count();
}
} /* anon */

Pool::Pool(std::vector<HostSpec> hosts)
    : next_rr_(0), unhealthy_window_(30.0) {
    hosts_.reserve(hosts.size());
    for (auto &h : hosts) hosts_.push_back({h, 0.0});
}

size_t Pool::healthy_host_count() const {
    double now = steady_now_seconds();
    size_t n = 0;
    for (auto &h : hosts_) if (h.unhealthy_until <= now) n++;
    return n;
}

std::vector<bool> Pool::healthy_mask() const {
    double now = steady_now_seconds();
    std::vector<bool> m;
    m.reserve(hosts_.size());
    for (auto &h : hosts_) m.push_back(h.unhealthy_until <= now);
    return m;
}

SearchResult Pool::search_round_robin(const std::string &pubkey_hex,
                                      const std::string &from_hex,
                                      const std::string &to_hex,
                                      double max_wait_seconds) {
    SearchResult last{};
    last.status = Status::NETWORK_ERROR;
    last.error_message = "no hosts in pool";
    if (hosts_.empty()) return last;

    /* Try each host once, starting at next_rr_. */
    for (size_t attempt = 0; attempt < hosts_.size(); attempt++) {
        size_t idx = (next_rr_ + attempt) % hosts_.size();
        double now = steady_now_seconds();
        if (hosts_[idx].unhealthy_until > now) continue;
        SearchResult r = search_one(hosts_[idx].spec,
                                    pubkey_hex, from_hex, to_hex,
                                    max_wait_seconds);
        if (r.status == Status::NETWORK_ERROR ||
            r.status == Status::TIMEOUT) {
            hosts_[idx].unhealthy_until = now + unhealthy_window_;
            last = r;
            continue;
        }
        next_rr_ = (idx + 1) % hosts_.size();
        return r;
    }
    return last;
}

SearchResult Pool::search_fanout(const std::string &pubkey_hex,
                                 const std::string &from_hex,
                                 const std::string &to_hex,
                                 double max_wait_seconds) {
    /* Simple equal-split fanout: convert from/to to 256-bit big-endian
     * uint64 lanes (good enough for puzzle ranges <= 2^63 -- caller is
     * expected to validate before invoking).  Beyond 2^64 we fall back
     * to round-robin since proper big-int splitting requires Int.
     *
     * TODO: link against secp256k1/Int.cpp for full 256-bit splitting.
     */
    char *endp;
    uint64_t from = std::strtoull(from_hex.c_str(), &endp, 16);
    if (*endp != '\0') return search_round_robin(pubkey_hex, from_hex, to_hex,
                                                  max_wait_seconds);
    uint64_t to = std::strtoull(to_hex.c_str(), &endp, 16);
    if (*endp != '\0' || to <= from)
        return search_round_robin(pubkey_hex, from_hex, to_hex,
                                  max_wait_seconds);

    auto healthy = healthy_mask();
    std::vector<size_t> healthy_idx;
    for (size_t i = 0; i < hosts_.size(); i++) if (healthy[i]) healthy_idx.push_back(i);
    if (healthy_idx.empty()) {
        SearchResult r{}; r.status = Status::NETWORK_ERROR;
        r.error_message = "no healthy hosts";
        return r;
    }

    uint64_t span = to - from;
    uint64_t per  = span / healthy_idx.size();
    if (per == 0) per = 1;

    std::vector<std::future<SearchResult>> futures;
    futures.reserve(healthy_idx.size());
    for (size_t i = 0; i < healthy_idx.size(); i++) {
        uint64_t a = from + i * per;
        uint64_t b = (i + 1 == healthy_idx.size()) ? to : a + per;
        char ah[32], bh[32];
        std::snprintf(ah, sizeof(ah), "%llx", (unsigned long long)a);
        std::snprintf(bh, sizeof(bh), "%llx", (unsigned long long)b);
        HostSpec spec = hosts_[healthy_idx[i]].spec;
        std::string from_h = ah, to_h = bh;
        futures.emplace_back(std::async(std::launch::async,
            [spec, pubkey_hex, from_h, to_h, max_wait_seconds]() {
                return search_one(spec, pubkey_hex, from_h, to_h,
                                  max_wait_seconds);
            }));
    }

    SearchResult last{}; last.status = Status::NOT_FOUND;
    for (auto &f : futures) {
        SearchResult r = f.get();
        if (r.status == Status::FOUND) return r;
        last = r;
    }
    return last;
}

} /* namespace bsgsd_client */
