// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "../../src/platform.hpp"
#include "../../src/file_root.hpp"
#include <cstdlib>
#include <vector>
#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
// Do not import legacy Winsock before a later loopback-server include.
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <unistd.h>
#include <sys/wait.h>
#endif

namespace ovstorage::usd_resolver::test_support
{
using detail::processId;
using detail::pathToUtf8;
using detail::providerLibraryName;
using detail::fileRootUrl;
inline std::string fileUrl(const std::filesystem::path& path)
{
    const auto absolute = std::filesystem::absolute(path);
    return fileRootUrl(absolute.parent_path()) + detail::percentEncodePath(pathToUtf8(absolute.filename()));
}

inline int setEnvironment(const char* name, const std::string& value)
{
#if defined(_WIN32)
    return ::_putenv_s(name, value.c_str());
#else
    return ::setenv(name, value.c_str(), 1);
#endif
}

#if defined(_WIN32)
inline std::wstring wide(const std::string& value)
{
    if (value.empty()) return {};
    const auto count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
        value.data(), static_cast<int>(value.size()), nullptr, 0);
    if (!count) throw std::runtime_error("invalid UTF-8 process argument");
    std::wstring result(count, L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
        static_cast<int>(value.size()), result.data(), count);
    return result;
}

// Quote argv for the Microsoft CRT, including empty arguments and trailing
// backslashes. No command shell interprets any of these bytes.
inline std::wstring quoteArgument(const std::wstring& value)
{
    std::wstring result = L"\"";
    unsigned slashes = 0;
    for (wchar_t c : value)
    {
        if (c == L'\\') { ++slashes; continue; }
        result.append(c == L'"' ? 2 * slashes + 1 : slashes, L'\\');
        slashes = 0;
        result += c;
    }
    result.append(2 * slashes, L'\\');
    result += L'"';
    return result;
}
#endif

inline int runProcess(const std::filesystem::path& executable,
    const std::vector<std::string>& arguments, const std::filesystem::path& outputPath,
    const std::filesystem::path& workingDirectory = {})
{
#if defined(_WIN32)
    SECURITY_ATTRIBUTES security { sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE };
    HANDLE output = CreateFileW(outputPath.c_str(), GENERIC_WRITE,
        FILE_SHARE_READ, &security, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (output == INVALID_HANDLE_VALUE) return -1;
    std::wstring command = quoteArgument(executable.wstring());
    for (const auto& argument : arguments)
        command += L" " + quoteArgument(wide(argument));
    STARTUPINFOW startup {};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdOutput = output;
    startup.hStdError = output;
    startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    PROCESS_INFORMATION process {};
    const BOOL created = CreateProcessW(executable.c_str(), command.data(),
        nullptr, nullptr, TRUE, 0, nullptr,
        workingDirectory.empty() ? nullptr : workingDirectory.c_str(), &startup, &process);
    CloseHandle(output);
    if (!created) return -1;
    CloseHandle(process.hThread);
    const auto wait = WaitForSingleObject(process.hProcess, 60000);
    DWORD status = 0;
    const bool exited = wait == WAIT_OBJECT_0 && GetExitCodeProcess(process.hProcess, &status);
    if (!exited) { TerminateProcess(process.hProcess, 124); WaitForSingleObject(process.hProcess, INFINITE); }
    CloseHandle(process.hProcess);
    return exited ? static_cast<int>(status) : -1;
#else
    std::vector<std::string> values { executable.string() };
    values.insert(values.end(), arguments.begin(), arguments.end());
    std::vector<char*> argv;
    for (auto& value : values) argv.push_back(value.data());
    argv.push_back(nullptr);
    const int output = ::open(outputPath.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (output < 0) return -1;
    const pid_t child = ::fork();
    if (child == 0)
    {
        if (::dup2(output, STDOUT_FILENO) < 0 || ::dup2(output, STDERR_FILENO) < 0)
            ::_exit(126);
        ::close(output);
        if (!workingDirectory.empty() && ::chdir(workingDirectory.c_str()) != 0)
            ::_exit(126);
        ::execv(executable.c_str(), argv.data());
        ::_exit(127);
    }
    ::close(output);
    if (child < 0) return -1;
    int status = 0;
    while (::waitpid(child, &status, 0) < 0)
        if (errno != EINTR) return -1;
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
#endif
}
} // namespace ovstorage::usd_resolver::test_support
