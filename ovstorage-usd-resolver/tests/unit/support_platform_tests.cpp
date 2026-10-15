// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
// Exercise process helpers before socket helpers, as the SDK fixtures do.
#include "support/platform.hpp"
#include "support/local_http_server.hpp"
#include <fstream>
#include <iostream>
#include <iterator>

namespace support = ovstorage::usd_resolver::test_support;
int main(int argc, char** argv)
{
    if (argc > 1)
    {
        for (int i = 1; i < argc; ++i) std::cout << argv[i] << '\n';
        return 23;
    }
    std::error_code error;
    auto output = ovstorage::usd_resolver::detail::TemporaryFile::create(
        std::filesystem::temp_directory_path(), "txt", error);
    if (!output) return 1;
    output->close();
    const std::vector<std::string> arguments {"two words", "\"quoted\"", "trailing\\", "", "$()%!"};
    if (support::runProcess(std::filesystem::absolute(argv[0]), arguments, output->path()) != 23)
        return 2;
    std::ifstream input(output->path(), std::ios::binary);
    const std::string actual((std::istreambuf_iterator<char>(input)), {});
    std::string expected;
    for (const auto& argument : arguments) expected += argument + "\n";
#if defined(_WIN32)
    std::string windowsExpected;
    for (char c : expected) { if (c == '\n') windowsExpected += '\r'; windowsExpected += c; }
    expected = windowsExpected;
#endif
    if (actual != expected) { std::cerr << "child arguments were changed\n"; return 3; }
    support::LocalHttpServer server("fixture payload");
    if (!server.ok()) { std::cerr << server.error(); return 4; }
    const auto client = ::socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in address {};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(server.port());
    if (::connect(client, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) return 5;
    const std::string request = "GET /root.usda HTTP/1.0\r\nHost: localhost\r\n\r\n";
    if (::send(client, request.data(), static_cast<int>(request.size()), 0) <= 0) return 6;
    std::string response;
    char buffer[1024];
    for (;;)
    {
        const auto count = ::recv(client, buffer, sizeof(buffer), 0);
        if (count <= 0) break;
        response.append(buffer, count);
    }
#if defined(_WIN32)
    ::closesocket(client);
#else
    ::close(client);
#endif
    if (response.find("200 OK") == std::string::npos || response.find("fixture payload") == std::string::npos)
        return 7;
    return server.rootRequestCount() == 1 ? 0 : 8;
}
