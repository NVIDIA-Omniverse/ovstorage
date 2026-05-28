// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Smoke test for the C++20 coroutine wrapper around the ovstorage C ABI.
//
// Exercises:
//   1. Library lifecycle (Library::init -> destructor calls
//      ovstorage_library_shutdown).
//   2. Round-trip through the coroutine bridge: stat() on a non-routable
//      address resolves the task<Info> with a Result<Info>::failure.
//      This proves the trampoline + tokio-thread resume() + Result
//      delivery works end-to-end.
//   3. CancelToken RAII + cancel() / is_canceled().
//   4. co_await chaining inside a user coroutine, driven from main()
//      via sync_wait().
//   5. End-to-end real-backend round-trip: register a temp-dir file
//      backend, write/read/stat a small object back.

#include "ovstorage.hpp"

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <optional>
#include <string>

namespace {

int failures = 0;

void check(bool cond, const char* what)
{
    if (cond) {
        std::printf("  ok   %s\n", what);
    } else {
        std::printf("  FAIL %s\n", what);
        ++failures;
    }
}

ovstorage::task<bool> stat_returns_error(const ovstorage::Library& lib)
{
    auto result = co_await lib.stat("file:/definitely/not/configured/path");
    co_return ovstorage::Result<bool>::success(!result.has_value());
}

ovstorage::task<bool> chained_calls(const ovstorage::Library& lib)
{
    auto a = co_await lib.stat("file:/nowhere/a");
    auto b = co_await lib.stat("file:/nowhere/b");
    bool both_failed = !a.has_value() && !b.has_value();
    co_return ovstorage::Result<bool>::success(both_failed);
}

ovstorage::task<bool> precanceled_returns(const ovstorage::Library& lib)
{
    ovstorage::CancelToken token;
    token.cancel();
    auto r = co_await lib.stat("file:/nowhere/here", false, &token);
    // We don't require a specific status code (NoRoute or Cancelled
    // are both plausible depending on order), only that the bridge
    // delivers *some* result without hanging.
    co_return ovstorage::Result<bool>::success(true);
    (void)r;
}

void test_cancel_token_lifecycle()
{
    std::printf("test_cancel_token_lifecycle\n");
    ovstorage::CancelToken token;
    check(!token.is_canceled(), "fresh token is not canceled");
    token.cancel();
    check(token.is_canceled(), "after cancel(), is_canceled() == true");

    // Independent tokens cancel independently.
    ovstorage::CancelToken other;
    check(!other.is_canceled(), "second token is independent");
    other.cancel();
    check(other.is_canceled(), "second token cancellable");
}

void test_stat_error_round_trip(const ovstorage::Library& lib)
{
    std::printf("test_stat_error_round_trip\n");
    auto outcome = ovstorage::sync_wait(stat_returns_error(lib));
    check(outcome.has_value(), "task completed");
    check(outcome.has_value() && outcome.value(),
        "stat on non-routable address resolves to failure");
}

void test_chained_co_await(const ovstorage::Library& lib)
{
    std::printf("test_chained_co_await\n");
    auto outcome = ovstorage::sync_wait(chained_calls(lib));
    check(outcome.has_value(), "chained task completed");
    check(outcome.has_value() && outcome.value(),
        "two sequential co_awaits both complete");
}

void test_precanceled_token_does_not_hang(const ovstorage::Library& lib)
{
    std::printf("test_precanceled_token_does_not_hang\n");
    auto outcome = ovstorage::sync_wait(precanceled_returns(lib));
    check(outcome.has_value(),
        "task with pre-canceled token completes (does not hang)");
}

void test_null_handle_guard()
{
    std::printf("test_null_handle_guard\n");
    // Default-constructed Library has handle_ == nullptr. The C ABI
    // would log + return without firing on_complete (and the
    // coroutine would hang); the C++ wrapper short-circuits with a
    // failed Result instead.
    ovstorage::Library empty;
    auto outcome = ovstorage::sync_wait(empty.stat("file:/nowhere"));
    check(!outcome.has_value(), "null-handle stat resolves to failure");
    check(outcome.error().code() == OvStorage_Status_InvalidArgument,
        "null-handle failure carries InvalidArgument");
    bool message_mentions_null = outcome.error().message().find("null") != std::string::npos;
    check(message_mentions_null, "null-handle failure message mentions null");
}

bool test_load_plugins_from_dir(const ovstorage::Library& lib)
{
    std::printf("test_load_plugins_from_dir\n");
#ifdef OVSTORAGE_CPP_ASYNC_PLUGIN_DIR
    std::optional<std::string> plugin_dir =
        std::string(OVSTORAGE_CPP_ASYNC_PLUGIN_DIR);
#else
    std::optional<std::string> plugin_dir = std::nullopt;
#endif
    auto outcome = ovstorage::sync_wait(lib.load_plugins_from_dir(plugin_dir));
    if (!outcome.has_value()) {
        std::printf("    load_plugins_from_dir failed: %s\n",
            outcome.error().message().c_str());
    }
    check(outcome.has_value(), "plugin directory loaded");
    return outcome.has_value();
}

bool backend_kind_available(const ovstorage::Library& lib, const char* wanted)
{
    auto outcome = ovstorage::sync_wait(lib.list_backend_kinds());
    if (!outcome.has_value()) {
        std::printf("  FAIL list_backend_kinds: %s\n",
            outcome.error().message().c_str());
        ++failures;
        return false;
    }
    auto kinds = std::move(outcome).value();
    for (std::size_t i = 0; i < kinds.size(); ++i) {
        const OvStorage_BackendKindDescriptor* d = kinds.item_at(i);
        const char* kind = ovstorage_backend_kind_descriptor_kind(d);
        if (kind != nullptr && std::string(kind) == wanted) {
            return true;
        }
    }
    return false;
}

// Build a ConnectionRequest via the C++ RAII wrappers, register a
// temp-dir file backend, write a small payload, read it back, stat it.
ovstorage::task<bool> file_backend_round_trip(
    const ovstorage::Library& lib,
    std::string root,
    std::string addr,
    std::string payload)
{
    ovstorage::ConnectionRequest request("file");
    if (!request.add_config("root", ovstorage::ConfigValue::string_(root))) {
        std::printf("    add_config failed\n");
        co_return ovstorage::Result<bool>::success(false);
    }
    auto registered = co_await lib.add_connection(std::move(request));
    if (!registered.has_value()) {
        std::printf("    add_connection failed: %s\n",
            registered.error().message().c_str());
        co_return ovstorage::Result<bool>::success(false);
    }

    std::span<const std::byte> payload_span(
        reinterpret_cast<const std::byte*>(payload.data()), payload.size());
    auto write_outcome = co_await lib.write(addr, payload_span);
    if (!write_outcome.has_value()) {
        std::printf("    write failed: %s\n",
            write_outcome.error().message().c_str());
        co_return ovstorage::Result<bool>::success(false);
    }

    auto read_outcome = co_await lib.read_bytes(addr);
    if (!read_outcome.has_value()) {
        std::printf("    read_bytes failed: %s\n",
            read_outcome.error().message().c_str());
        co_return ovstorage::Result<bool>::success(false);
    }
    auto& [bytes, info] = read_outcome.value();
    auto bytes_span = bytes.span();
    bool size_matches = bytes_span.size() == payload.size();
    bool content_matches = size_matches
        && std::memcmp(bytes_span.data(), payload.data(), payload.size()) == 0;

    auto stat_outcome = co_await lib.stat(addr);
    bool stat_ok = stat_outcome.has_value()
        && stat_outcome.value().size() == payload.size();

    co_return ovstorage::Result<bool>::success(
        size_matches && content_matches && stat_ok);
}

void test_file_backend_round_trip(const ovstorage::Library& lib)
{
    std::printf("test_file_backend_round_trip\n");
    auto temp = std::filesystem::temp_directory_path()
        / std::filesystem::path("ovstorage-cpp-async-test");
    std::error_code ec;
    std::filesystem::remove_all(temp, ec);
    std::filesystem::create_directories(temp, ec);
    if (ec) {
        std::printf("  FAIL setup tempdir: %s\n", ec.message().c_str());
        ++failures;
        return;
    }
    std::string root = temp.string();
    std::string addr = "file://" + root + "/hello.txt";
    std::string payload = "hello from cpp-async";

    auto outcome = ovstorage::sync_wait(
        file_backend_round_trip(lib, root, addr, payload));
    check(outcome.has_value(), "round-trip task completed");
    check(outcome.has_value() && outcome.value(),
        "register_file_connection + write + read_bytes + stat all match");

    std::filesystem::remove_all(temp, ec);
}

// Optional full-surface check against plugin-test when that dev-only
// backend is present.
ovstorage::task<bool> plugin_test_full_surface(
    const ovstorage::Library& lib,
    std::string root)
{
    // Register a plugin-test connection with a multi-event auth flow.
    ovstorage::ConnectionRequest request("test");
    request.add_config("test_root", ovstorage::ConfigValue::string_(root));
    request.add_config("test_caps", ovstorage::ConfigValue::string_(std::string("full")));
    request.add_config("test_auth_flow",
        ovstorage::ConfigValue::string_(std::string("progress-then-succeed")));
    auto added = co_await lib.add_connection(std::move(request));
    if (!added.has_value()) {
        std::printf("    add_connection: %s\n",
            added.error().message().c_str());
        co_return ovstorage::Result<bool>::success(false);
    }
    auto conn = std::move(added).value();
    std::string conn_id = conn.id();

    // list_connections should include this id.
    auto list_outcome = co_await lib.list_connections();
    if (!list_outcome.has_value()) {
        std::printf("    list_connections: %s\n",
            list_outcome.error().message().c_str());
        co_return ovstorage::Result<bool>::success(false);
    }
    auto conn_list = std::move(list_outcome).value();
    bool found_in_list = false;
    for (std::size_t i = 0; i < conn_list.size(); ++i) {
        const OvStorage_Connection* item = conn_list.item_at(i);
        const char* id_ptr = ovstorage_connection_id(item);
        if (id_ptr != nullptr && conn_id == id_ptr) {
            found_in_list = true;
            break;
        }
    }
    if (!found_in_list) {
        std::printf("    connection not found in list_connections\n");
        co_return ovstorage::Result<bool>::success(false);
    }

    // authenticate_connection should drain a Progress + Succeeded
    // event sequence.
    auto auth_outcome = co_await lib.authenticate_connection(conn_id);
    if (!auth_outcome.has_value()) {
        std::printf("    authenticate_connection: %s\n",
            auth_outcome.error().message().c_str());
        co_return ovstorage::Result<bool>::success(false);
    }
    auto events = std::move(auth_outcome).value();
    bool saw_progress = false;
    bool saw_succeeded = false;
    for (auto& e : events) {
        if (e.kind() == OvStorage_AuthEventKind_Progress) saw_progress = true;
        if (e.kind() == OvStorage_AuthEventKind_Succeeded) saw_succeeded = true;
    }
    if (!saw_progress || !saw_succeeded) {
        std::printf("    auth flow missing events; got %zu\n", events.size());
        co_return ovstorage::Result<bool>::success(false);
    }

    // capabilities_for the connection's prefix; just check we got
    // *something* back without crashing.
    auto caps_outcome = co_await lib.capabilities_for(root);
    if (!caps_outcome.has_value()) {
        std::printf("    capabilities_for: %s\n",
            caps_outcome.error().message().c_str());
        co_return ovstorage::Result<bool>::success(false);
    }

    // list_backend_kinds should include "test" and "file".
    auto kinds_outcome = co_await lib.list_backend_kinds();
    if (!kinds_outcome.has_value()) {
        std::printf("    list_backend_kinds: %s\n",
            kinds_outcome.error().message().c_str());
        co_return ovstorage::Result<bool>::success(false);
    }
    auto kinds = std::move(kinds_outcome).value();
    bool saw_test = false;
    bool saw_file = false;
    for (std::size_t i = 0; i < kinds.size(); ++i) {
        const OvStorage_BackendKindDescriptor* d = kinds.item_at(i);
        const char* k = ovstorage_backend_kind_descriptor_kind(d);
        if (k == nullptr) continue;
        std::string kind(k);
        if (kind == "test") saw_test = true;
        if (kind == "file") saw_file = true;
    }
    if (!saw_test || !saw_file) {
        std::printf("    list_backend_kinds missing test/file\n");
        co_return ovstorage::Result<bool>::success(false);
    }

    ovstorage::CancelToken watch_cancel;
    std::atomic_bool saw_snapshot{false};
    auto watch_outcome = co_await lib.watch_address_roots(
        [&](ovstorage::AddressRootList snapshot) {
            saw_snapshot.store(snapshot.size() > 0, std::memory_order_release);
            watch_cancel.cancel();
        },
        &watch_cancel);
    if (!watch_outcome.has_value()) {
        std::printf("    watch_address_roots: %s\n",
            watch_outcome.error().message().c_str());
        co_return ovstorage::Result<bool>::success(false);
    }
    if (!saw_snapshot.load(std::memory_order_acquire)) {
        std::printf("    watch_address_roots missing Snapshot\n");
        co_return ovstorage::Result<bool>::success(false);
    }

    // remove_connection
    auto removed = co_await lib.remove_connection(conn_id);
    if (!removed.has_value()) {
        std::printf("    remove_connection: %s\n",
            removed.error().message().c_str());
        co_return ovstorage::Result<bool>::success(false);
    }

    co_return ovstorage::Result<bool>::success(true);
}

void test_plugin_test_full_surface(const ovstorage::Library& lib)
{
    std::printf("test_plugin_test_full_surface\n");
    if (!backend_kind_available(lib, "test")) {
        std::printf("  skip plugin-test backend not present\n");
        return;
    }
    std::string root = "test://cpp-async-full/";
    auto outcome = ovstorage::sync_wait(plugin_test_full_surface(lib, root));
    check(outcome.has_value(), "task completed");
    check(outcome.has_value() && outcome.value(),
        "add_connection + list + authenticate + capabilities_for + "
        "list_backend_kinds + watch_address_roots + remove all succeed");
}

} // namespace

// The plugin-SPI substrate registers process-globally on first
// Library::init, so the whole driver shares a single library handle.
// Mirrors the Rust integration test pattern in
// ovstorage-capi/tests/library_init.rs.
int main()
{
    std::printf("test_library_init_shutdown\n");
    auto lib_result = ovstorage::Library::init();
    if (!lib_result) {
        std::printf("  FAIL Library::init: %s\n", lib_result.error().message().c_str());
        return 1;
    }
    std::printf("  ok   Library::init succeeds\n");
    auto lib = std::move(lib_result).value();
    bool plugins_loaded = test_load_plugins_from_dir(lib);

    test_cancel_token_lifecycle();
    test_null_handle_guard();
    test_stat_error_round_trip(lib);
    test_chained_co_await(lib);
    test_precanceled_token_does_not_hang(lib);
    if (plugins_loaded) {
        test_file_backend_round_trip(lib);
        test_plugin_test_full_surface(lib);
    }

    // Library destructor here -> ovstorage_library_shutdown.
    if (failures != 0) {
        std::printf("\n%d failures\n", failures);
        return 1;
    }
    std::printf("\nall ok\n");
    return 0;
}
