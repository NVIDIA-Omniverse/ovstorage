// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// In-process loopback HTTP server used by ovstorage bridge and OpenUSD
// composition smokes. Serves two named payloads at /root.usda and
// /child.usda. Deterministic and single-thread — good enough for test
// fixtures, not a general-purpose server.

#pragma once

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <utility>

namespace ovstorage::usd_resolver::test_support
{

class LocalHttpServer
{
#if defined(_WIN32)
    using Socket = SOCKET;
    using SocketLength = int;
    static constexpr Socket invalidSocket = INVALID_SOCKET;
    static void releaseSocket(Socket socket) { ::closesocket(socket); }
    static std::string socketError() { return std::to_string(WSAGetLastError()); }
    static constexpr int shutdownBoth = SD_BOTH;
#else
    using Socket = int;
    using SocketLength = socklen_t;
    static constexpr Socket invalidSocket = -1;
    static void releaseSocket(Socket socket) { ::close(socket); }
    static std::string socketError() { return std::strerror(errno); }
    static constexpr int shutdownBoth = SHUT_RDWR;
#endif
public:
    // Extra path -> payload map, keyed by the full request path (leading `/`,
    // e.g. "/generated.usdz"). Matched after `/root.usda` and `/child.usda`
    // so the existing HTTP layer smokes stay unchanged; a request for an
    // extra path never falls through to a 404 as long as the map has the
    // suffix. Values are `std::string` (not `std::vector<std::uint8_t>`) so
    // binary payloads (e.g. USDZ zip bytes) can carry embedded NULs
    // without the caller having to reinterpret_cast.
    using ExtraObjects = std::map<std::string, std::string>;

    LocalHttpServer(std::string rootPayload, std::string childPayload, ExtraObjects extraObjects)
        : m_rootPayload(std::move(rootPayload)),
          m_childPayload(std::move(childPayload)),
          m_extraObjects(std::move(extraObjects))
    {
#if defined(_WIN32)
        WSADATA data {};
        const int startup = WSAStartup(MAKEWORD(2, 2), &data);
        if (startup != 0)
        {
            m_error = "WSAStartup failed: " + std::to_string(startup);
            return;
        }
        m_winsockStarted = true;
#endif
        m_socket = ::socket(AF_INET, SOCK_STREAM, 0);
        if (m_socket == invalidSocket)
        {
            m_error = std::string("socket failed: ") + socketError();
            return;
        }

        const int enabled = 1;
#if defined(_WIN32)
        constexpr int reuseOption = SO_EXCLUSIVEADDRUSE;
#else
        constexpr int reuseOption = SO_REUSEADDR;
#endif
        if (::setsockopt(m_socket, SOL_SOCKET, reuseOption,
                reinterpret_cast<const char*>(&enabled), sizeof(enabled)) != 0)
        {
            m_error = std::string("socket exclusivity setup failed: ") + socketError();
            closeSocket();
            return;
        }

        sockaddr_in address {};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        address.sin_port = 0;

        if (::bind(m_socket, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0)
        {
            m_error = std::string("bind failed: ") + socketError();
            closeSocket();
            return;
        }

        SocketLength length = sizeof(address);
        if (::getsockname(m_socket, reinterpret_cast<sockaddr*>(&address), &length) != 0)
        {
            m_error = std::string("getsockname failed: ") + socketError();
            closeSocket();
            return;
        }
        m_port = ntohs(address.sin_port);

        if (::listen(m_socket, 8) != 0)
        {
            m_error = std::string("listen failed: ") + socketError();
            closeSocket();
            return;
        }

        m_running = true;
        m_thread = std::thread([this]() { serve(); });
    }

    LocalHttpServer(std::string rootPayload, std::string childPayload)
        : LocalHttpServer(std::move(rootPayload), std::move(childPayload), ExtraObjects())
    {
    }

    explicit LocalHttpServer(std::string rootPayload)
        : LocalHttpServer(std::move(rootPayload), std::string(), ExtraObjects())
    {
    }

    explicit LocalHttpServer(ExtraObjects extraObjects)
        : LocalHttpServer(std::string(), std::string(), std::move(extraObjects))
    {
    }

    ~LocalHttpServer()
    {
        m_running = false;
        closeSocket();
        if (m_thread.joinable())
        {
            m_thread.join();
        }
#if defined(_WIN32)
        if (m_winsockStarted) WSACleanup();
#endif
    }

    LocalHttpServer(const LocalHttpServer&) = delete;
    LocalHttpServer& operator=(const LocalHttpServer&) = delete;

    bool ok() const
    {
        return m_socket != invalidSocket && m_running;
    }

    std::uint16_t port() const
    {
        return m_port;
    }

    const std::string& error() const
    {
        return m_error;
    }

    int rootRequestCount() const
    {
        return m_rootRequests.load();
    }

    int childRequestCount() const
    {
        return m_childRequests.load();
    }

    // Total requests handled via the extra-objects dispatcher (across
    // every configured extra path). Serialized through m_extraMutex.
    int extraRequestCountTotal() const
    {
        std::lock_guard<std::mutex> lock(m_extraMutex);
        return m_extraRequestsTotal;
    }

    // Requests handled for a specific extra path (e.g. "/generated.usdz").
    int extraRequestCount(const std::string& path) const
    {
        std::lock_guard<std::mutex> lock(m_extraMutex);
        const auto it = m_extraRequestsByPath.find(path);
        return it == m_extraRequestsByPath.end() ? 0 : it->second;
    }

    // When set to a non-empty RFC 1123 date string, the server emits
    // `Last-Modified: <value>` on every 200 and 206 response. Otherwise
    // no `Last-Modified` header is emitted — matching the fixture's
    // historical behavior. Used by smokes that need to assert the
    // resolver's positive-mtime path.
    void setLastModified(std::string value)
    {
        m_lastModified = std::move(value);
    }

private:
    void closeSocket()
    {
        const Socket fd = m_socket.exchange(invalidSocket);
        if (fd != invalidSocket)
        {
            ::shutdown(fd, shutdownBoth);
            releaseSocket(fd);
        }
    }

    void serve()
    {
        while (m_running)
        {
            sockaddr_in clientAddress {};
            SocketLength clientLength = sizeof(clientAddress);
            const Socket client = ::accept(m_socket, reinterpret_cast<sockaddr*>(&clientAddress), &clientLength);
            if (client == invalidSocket)
            {
#if defined(_WIN32)
                const int error = WSAGetLastError();
                const bool closed = error == WSAENOTSOCK || error == WSAEINVAL;
#else
                const bool closed = errno == EBADF || errno == EINVAL;
#endif
                if (m_running && !closed)
                {
                    continue;
                }
                return;
            }
#if defined(SO_NOSIGPIPE)
            const int noSignal = 1;
            ::setsockopt(client, SOL_SOCKET, SO_NOSIGPIPE, &noSignal, sizeof(noSignal));
#endif
            handleClient(client);
            releaseSocket(client);
        }
    }

    struct RangeSpec
    {
        std::uint64_t start = 0;
        std::uint64_t endInclusive = 0;
    };

    // Parse a `Range: bytes=X-Y` header. HTTP headers are case-insensitive
    // (RFC 7230 §3.2), so search the request line-by-line rather than
    // matching a fixed-case prefix — different HTTP clients (hyper/reqwest,
    // curl, etc.) normalize header casing differently. Only the
    // single-range form is supported — that's all the ovstorage HTTP
    // plugin issues. Returns nullopt when the request has no Range header.
    static std::optional<RangeSpec> parseRangeHeader(std::string_view request)
    {
        constexpr std::string_view kHeaderName = "range";
        constexpr std::string_view kValuePrefix = "bytes=";
        auto iequals = [](char a, char b) {
            if (a >= 'A' && a <= 'Z') a = static_cast<char>(a + ('a' - 'A'));
            if (b >= 'A' && b <= 'Z') b = static_cast<char>(b + ('a' - 'A'));
            return a == b;
        };
        std::size_t cursor = 0;
        while (cursor < request.size())
        {
            const auto lineEnd = request.find("\r\n", cursor);
            if (lineEnd == std::string_view::npos)
            {
                break;
            }
            const auto line = request.substr(cursor, lineEnd - cursor);
            cursor = lineEnd + 2;
            if (line.size() < kHeaderName.size() + 1)
            {
                continue;
            }
            bool matches = true;
            for (std::size_t i = 0; i < kHeaderName.size(); ++i)
            {
                if (!iequals(line[i], kHeaderName[i]))
                {
                    matches = false;
                    break;
                }
            }
            if (!matches || line[kHeaderName.size()] != ':')
            {
                continue;
            }
            std::size_t valueStart = kHeaderName.size() + 1;
            while (valueStart < line.size() && (line[valueStart] == ' ' || line[valueStart] == '\t'))
            {
                ++valueStart;
            }
            if (valueStart + kValuePrefix.size() > line.size())
            {
                return std::nullopt;
            }
            for (std::size_t i = 0; i < kValuePrefix.size(); ++i)
            {
                if (!iequals(line[valueStart + i], kValuePrefix[i]))
                {
                    return std::nullopt;
                }
            }
            const auto value = line.substr(valueStart + kValuePrefix.size());
            const auto dash = value.find('-');
            if (dash == std::string_view::npos || dash == 0 || dash == value.size() - 1)
            {
                return std::nullopt;
            }
            RangeSpec spec;
            for (char c : value.substr(0, dash))
            {
                if (c < '0' || c > '9')
                {
                    return std::nullopt;
                }
                spec.start = spec.start * 10 + static_cast<std::uint64_t>(c - '0');
            }
            for (char c : value.substr(dash + 1))
            {
                if (c < '0' || c > '9')
                {
                    return std::nullopt;
                }
                spec.endInclusive = spec.endInclusive * 10 + static_cast<std::uint64_t>(c - '0');
            }
            return spec;
        }
        return std::nullopt;
    }

    void handleClient(Socket client)
    {
        char buffer[2048] {};
        const auto received = ::recv(client, buffer, sizeof(buffer) - 1, 0);
        if (received <= 0)
        {
            return;
        }

        const std::string request(buffer, static_cast<std::size_t>(received));
        const auto range = parseRangeHeader(request);
        const bool isHead = request.rfind("HEAD /root.usda ", 0) == 0;
        const bool isGet = request.rfind("GET /root.usda ", 0) == 0;
        if (isHead || isGet)
        {
            ++m_rootRequests;
            sendObjectResponse(client, isGet, m_rootPayload, range);
            return;
        }

        const bool isChildHead = request.rfind("HEAD /child.usda ", 0) == 0;
        const bool isChildGet = request.rfind("GET /child.usda ", 0) == 0;
        if ((isChildHead || isChildGet) && !m_childPayload.empty())
        {
            ++m_childRequests;
            sendObjectResponse(client, isChildGet, m_childPayload, range);
            return;
        }

        // Extra-object dispatch. Parse the request line's path (`GET /X `
        // or `HEAD /X `) and, if it matches an entry, serve that payload.
        // A hit increments a per-path counter so the smoke can assert
        // exactly which payloads the fixture served.
        std::string_view requestView(request);
        const bool isExtraHead = requestView.rfind("HEAD ", 0) == 0;
        const bool isExtraGet = requestView.rfind("GET ", 0) == 0;
        if (isExtraHead || isExtraGet)
        {
            const auto pathStart = isExtraGet ? 4 : 5;
            const auto pathEnd = requestView.find(' ', pathStart);
            if (pathEnd != std::string_view::npos)
            {
                const std::string path(requestView.substr(pathStart, pathEnd - pathStart));
                const auto it = m_extraObjects.find(path);
                if (it != m_extraObjects.end())
                {
                    // The server uses one accept thread, so this
                    // write is effectively serialized against the readers,
                    // but take the mutex explicitly to match the read
                    // side and to stay correct if the accept loop ever
                    // grows a worker pool.
                    {
                        std::lock_guard<std::mutex> lock(m_extraMutex);
                        ++m_extraRequestsTotal;
                        m_extraRequestsByPath[path]++;
                    }
                    sendObjectResponse(client, isExtraGet, it->second, range);
                    return;
                }
            }
        }

        const std::string response =
            "HTTP/1.1 404 Not Found\r\n"
            "Content-Length: 0\r\n"
            "Connection: close\r\n"
            "\r\n";
        writeAll(client, response);
    }

    void sendObjectResponse(
        Socket client,
        bool includeBody,
        const std::string& payload,
        const std::optional<RangeSpec>& range)
    {
        // Bytes-range: reply 206 Partial Content with only the requested
        // slice. Out-of-bounds ranges get 416. This mirrors the shape the
        // ovstorage HTTP plugin expects when it sets `Range: bytes=X-Y`.
        if (range.has_value())
        {
            if (range->start >= payload.size() || range->endInclusive < range->start)
            {
                const std::string response =
                    "HTTP/1.1 416 Range Not Satisfiable\r\n"
                    "Content-Length: 0\r\n"
                    "Content-Range: bytes */" + std::to_string(payload.size()) + "\r\n"
                    "Connection: close\r\n"
                    "\r\n";
                writeAll(client, response);
                return;
            }
            const std::uint64_t clampedEnd = range->endInclusive >= payload.size()
                ? payload.size() - 1
                : range->endInclusive;
            const std::string slice = payload.substr(
                static_cast<std::size_t>(range->start),
                static_cast<std::size_t>(clampedEnd - range->start + 1));
            std::string response =
                "HTTP/1.1 206 Partial Content\r\n"
                "Content-Type: model/vnd.usda\r\n"
                "Content-Length: " + std::to_string(slice.size()) + "\r\n"
                "Content-Range: bytes " + std::to_string(range->start) + "-" +
                std::to_string(clampedEnd) + "/" + std::to_string(payload.size()) + "\r\n" +
                lastModifiedHeader() +
                "Connection: close\r\n"
                "\r\n";
            if (includeBody)
            {
                response.append(slice);
            }
            writeAll(client, response);
            return;
        }

        std::string response =
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: model/vnd.usda\r\n"
            "Accept-Ranges: bytes\r\n"
            "Content-Length: " + std::to_string(payload.size()) + "\r\n" +
            lastModifiedHeader() +
            "Connection: close\r\n"
            "\r\n";
        if (includeBody)
        {
            response.append(payload);
        }
        writeAll(client, response);
    }

    // Builds the `Last-Modified: <date>\r\n` line, or an empty string
    // when the fixture has no configured mtime. Callers concatenate the
    // result into their response builder directly.
    std::string lastModifiedHeader() const
    {
        if (m_lastModified.empty())
        {
            return {};
        }
        return "Last-Modified: " + m_lastModified + "\r\n";
    }

    static void writeAll(Socket client, const std::string& data)
    {
        std::size_t sent = 0;
        while (sent < data.size())
        {
            const auto remaining = std::min<std::size_t>(data.size() - sent, 1024 * 1024);
#if defined(MSG_NOSIGNAL)
            constexpr int flags = MSG_NOSIGNAL;
#else
            constexpr int flags = 0;
#endif
            const auto written = ::send(client, data.data() + sent, static_cast<int>(remaining), flags);
            if (written <= 0)
            {
                return;
            }
            sent += static_cast<std::size_t>(written);
        }
    }

    std::string m_rootPayload;
    std::string m_childPayload;
    ExtraObjects m_extraObjects;
    std::string m_lastModified;
    std::string m_error;
    std::atomic<Socket> m_socket { invalidSocket };
#if defined(_WIN32)
    bool m_winsockStarted = false;
#endif
    std::atomic<bool> m_running { false };
    std::atomic<int> m_rootRequests { 0 };
    std::atomic<int> m_childRequests { 0 };
    mutable std::mutex m_extraMutex;
    int m_extraRequestsTotal { 0 };
    std::map<std::string, int> m_extraRequestsByPath;
    std::uint16_t m_port = 0;
    std::thread m_thread;
};

} // namespace ovstorage::usd_resolver::test_support
