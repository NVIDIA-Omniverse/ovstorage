// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// End-to-end round trip driven through the shipped C++20 wrapper against
// the pure-C implementation this crate compiles and links — the shipped
// configuration, wrapper over C source.
//
// The whole round trip runs inside one coroutine driven by a single
// `sync_wait`, so every op is reached by `co_await`: that exercises the
// wrapper's awaiter handshake, its trampolines, and chained resumption,
// not just the C ABI underneath.

#include "ovstorage.hpp"

#include "../../../../ovstorage-c-source/src/temp_dir.h"

// The auth-event fixture Layer, minted in C next to the other stub Layers.
extern "C" {
OvStoragePlugin_LayerHandle ovstorage_c_source_auth_stub_root(void);
OvStoragePlugin_LayerHandle ovstorage_c_source_new_ops_stub_root(void);
int ovstorage_c_source_auth_stub_wait_emitted(void);
void ovstorage_c_source_auth_stub_release(void);
const char* ovstorage_c_source_auth_stub_user_code(void);
const char* ovstorage_c_source_auth_stub_verification_url(void);
int ovstorage_c_source_new_ops_watch_since_present(void);
std::size_t ovstorage_c_source_new_ops_watch_since_len(void);
}

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <span>
#include <stdexcept>
#include <thread>
#include <string>
#include <string_view>
#include <vector>
#include <utility>

#if defined(_WIN32)
#include <windows.h>
#else
#include <unistd.h>
#endif

// The `file://` encoding rule and the Windows POSIX shims live next to this
// driver and are shared with the C drivers and the shipped examples, so every
// driver builds addresses and removes paths the same way.
#include "file_url.h"
#if defined(_WIN32)
#include "windows_posix_compat.h"
#endif

namespace {

// The `file://` address for a temp root.
//
// The RFC-3986 encoding rule, the `\` -> `/` rewrite and the UNC refusal all
// live in `file_url.h`, which the shipped C examples use too, so this driver
// addresses a root exactly as a customer's example does.
//
// `ovc_temp_dir_create` hands back a NATIVE path and the caller owns the
// encoding (see src/temp_dir.h). It matters: a temp root holding `#`, `?` or
// `%` changes how the address parses, or is rejected outright, and the default
// Windows temp root sits under `C:\Users\<username>\...` where spaces are
// routine.
//
// Returns an empty string for a UNC root, which has no `file://` spelling this
// backend accepts.
std::string test_root_address(const std::string& directory)
{
    // Worst case every byte escapes to three, plus the leading `/` on Windows
    // and the terminator.
    std::vector<char> encoded(directory.size() * 3 + 3);

    if (test_file_url_path(directory.c_str(), encoded.data(), encoded.size()) !=
        0) {
        return std::string{};
    }
    return "file://" + std::string(encoded.data()) + "/";
}

#if defined(_WIN32)
// Removal and error formatting come from `windows_posix_compat.h`, the same
// helpers the C drivers use, so an absent path reports `ENOENT` here exactly
// as it does there — best-effort cleanup keys on that.
int test_unlink(const std::string& path)
{
    return ovc_test_remove_file(path.c_str());
}

int test_rmdir(const std::string& path)
{
    return ovc_test_remove_dir(path.c_str());
}

std::string test_error_message(int error)
{
    return ovc_test_strerror(error);
}
#else
int test_unlink(const std::string& path)
{
    return unlink(path.c_str());
}

int test_rmdir(const std::string& path)
{
    return rmdir(path.c_str());
}

std::string test_error_message(int error)
{
    return std::strerror(error);
}
#endif


template <class T>
bool succeeded(const char* operation, const ovstorage::Result<T>& result)
{
    if (result) {
        return true;
    }
    std::cerr << operation << " failed with status "
              << static_cast<int>(result.error().code());
    if (!result.error().message().empty()) {
        std::cerr << ": " << result.error().message();
    }
    std::cerr << '\n';
    return false;
}

template <class T>
bool failed_with(const char* operation,
                 const ovstorage::Result<T>& result,
                 OvStorage_Status expected)
{
    if (!result && result.error().code() == expected) {
        return true;
    }
    if (result) {
        std::cerr << operation << " unexpectedly succeeded\n";
    } else {
        std::cerr << operation << " failed with status "
                  << static_cast<int>(result.error().code())
                  << " instead of " << static_cast<int>(expected);
        if (!result.error().message().empty()) {
            std::cerr << ": " << result.error().message();
        }
        std::cerr << '\n';
    }
    return false;
}

// The reason must be the one named, not merely the status. Status alone is
// too weak: the C implementation independently answers InvalidArgument for
// several unrelated inputs (a truncated list page token, for one), so a
// status-only assertion would pass even with the checked guard removed.
template <class T>
bool failed_with_message(const char* operation,
                         const ovstorage::Result<T>& result,
                         OvStorage_Status expected,
                         const char* expected_reason)
{
    if (!failed_with(operation, result, expected)) {
        return false;
    }
    if (result.error().message().find(expected_reason) == std::string::npos) {
        std::cerr << operation << " was rejected with \""
                  << result.error().message() << "\" rather than for \""
                  << expected_reason << "\"\n";
        return false;
    }
    return true;
}

template <class T>
bool rejected_by_input_guard(const char* operation,
                             const ovstorage::Result<T>& result,
                             const char* expected_reason)
{
    return failed_with_message(
        operation, result, OvStorage_Status_InvalidArgument, expected_reason);
}

template <class T>
bool rejected_by_nul_guard(const char* operation,
                           const ovstorage::Result<T>& result)
{
    return rejected_by_input_guard(operation, result, "embedded NUL");
}

std::span<const std::byte> as_bytes(std::string_view text)
{
    return std::span<const std::byte>(
        reinterpret_cast<const std::byte*>(text.data()), text.size());
}

std::string_view as_text(const std::vector<std::byte>& bytes)
{
    return std::string_view(
        reinterpret_cast<const char*>(bytes.data()), bytes.size());
}

// A ranged read must return the named slice AT the length that slice has.
// Both halves matter: a read that dropped the range comes back whole, which
// this rejects on length, and a read that mis-seeks comes back the right
// length with the wrong bytes, which it rejects on content.
bool window_equals(const char* operation,
                   std::string_view actual,
                   std::string_view expected)
{
    if (actual == expected) {
        return true;
    }
    std::cerr << operation << " returned " << actual.size() << " bytes (\""
              << actual << "\") instead of the " << expected.size()
              << "-byte window \"" << expected << "\"\n";
    return false;
}

// Drive `ovstorage_write` directly, bypassing the C++ wrapper entirely.
//
// The wrapper refuses a `no_overwrite` + `if_match_etag` combination before
// the C layer ever sees it, which is exactly why the C implementation's own
// copy of that check needs a test that does not go through the wrapper: a C
// caller reaches `ovc_dispatch_write_options` with no wrapper in front of it.
struct RawWriteOutcome {
    std::mutex mutex;
    std::condition_variable done;
    bool fired = false;
    OvStorage_Status status = OvStorage_Status_Ok;
    std::string message;
};

void raw_write_complete(OvStorage_Status status,
                        OvStorage_Info* info,
                        const OvStorage_Error* error,
                        void* user_data)
{
    auto& outcome = *static_cast<RawWriteOutcome*>(user_data);
    {
        std::lock_guard<std::mutex> lock(outcome.mutex);
        outcome.status = status;
        if (error != nullptr && ovstorage_error_message(error) != nullptr) {
            outcome.message = ovstorage_error_message(error);
        }
        outcome.fired = true;
    }
    ovstorage_info_destroy(info);
    outcome.done.notify_one();
}

bool raw_write_is_rejected(const char* operation,
                           const ovstorage::LayerHandle& layer,
                           const std::string& address,
                           const OvStorage_WriteOptions& options,
                           const char* expected_reason)
{
    static const std::uint8_t body[] = {'x'};
    RawWriteOutcome outcome;

    ovstorage_write(layer.get(), address.c_str(), body, sizeof(body), &options,
                    nullptr, &raw_write_complete, &outcome);
    {
        std::unique_lock<std::mutex> lock(outcome.mutex);
        outcome.done.wait(lock, [&] { return outcome.fired; });
    }
    if (outcome.status != OvStorage_Status_InvalidArgument) {
        std::cerr << operation << " through the raw C entry point reported "
                  << static_cast<int>(outcome.status)
                  << " instead of InvalidArgument ("
                  << static_cast<int>(OvStorage_Status_InvalidArgument)
                  << "): " << outcome.message << '\n';
        return false;
    }
    if (outcome.message.find(expected_reason) == std::string::npos) {
        std::cerr << operation << " through the raw C entry point was "
                  << "rejected with \"" << outcome.message
                  << "\" rather than for \"" << expected_reason << "\"\n";
        return false;
    }
    return true;
}

struct CppWriteSource {
    std::size_t index = 0;
    int drops = 0;
};

OvStorage_WriteStreamStep cpp_write_source_next(
    void* opaque,
    OvStorage_Bytes* out_chunk,
    OvStorage_Status* /* out_status */,
    const char** /* out_error_message */)
{
    static const std::string_view chunks[] = {"streamed ", "write"};
    auto& source = *static_cast<CppWriteSource*>(opaque);
    *out_chunk = OvStorage_Bytes{};
    if (source.index == 2) {
        return OvStorage_WriteStreamStep_End;
    }
    out_chunk->data = reinterpret_cast<const std::uint8_t*>(
        chunks[source.index].data());
    out_chunk->len = chunks[source.index].size();
    ++source.index;
    return OvStorage_WriteStreamStep_Chunk;
}

void cpp_write_source_drop(void* opaque)
{
    ++static_cast<CppWriteSource*>(opaque)->drops;
}

ovstorage::task<bool> exercise_new_operations(
    const ovstorage::LayerHandle& layer)
{
    CppWriteSource source;
    auto streamed = co_await layer.write_stream(
        "test://streamed-write",
        ovstorage::WriteStream(
            &source, cpp_write_source_next, cpp_write_source_drop),
        false,
        std::uint64_t{14});
    if (!succeeded("LayerHandle::write_stream", streamed) ||
        !streamed.value().has_size() || streamed.value().size() != 14 ||
        source.index != 2 || source.drops != 1) {
        std::cerr << "write_stream did not preserve content or ownership\n";
        co_return ovstorage::Result<bool>::success(false);
    }

    auto initial = co_await layer.write_redirect(
        "test://redirect-write", false, std::uint64_t{5});
    if (!succeeded("LayerHandle::write_redirect", initial) ||
        initial.value().size() != 1 ||
        initial.value().continuation().size() != 4 ||
        initial.value().at(0) == nullptr ||
        std::string(initial.value().at(0)->method) != "PUT") {
        std::cerr << "write_redirect returned the wrong plan\n";
        co_return ovstorage::Result<bool>::success(false);
    }

    ovstorage::RedirectResult response;
    response.status_code = 201;
    response.captured_headers.push_back({"etag", "\"abc\""});
    response.captured_body = {'s', 'a', 'v', 'e', 'd'};
    std::vector<ovstorage::RedirectResult> first_results;
    first_results.push_back(response);
    auto continued = co_await layer.continue_write(
        "test://redirect-write", initial.value(), std::move(first_results));
    if (!succeeded("LayerHandle::continue_write redirects", continued) ||
        continued.value().is_done() ||
        continued.value().redirects().size() != 1) {
        std::cerr << "continue_write did not return the next redirect plan\n";
        co_return ovstorage::Result<bool>::success(false);
    }

    auto next = continued.value().take_redirects();
    std::vector<ovstorage::RedirectResult> second_results;
    second_results.push_back(std::move(response));
    auto finished = co_await layer.continue_write(
        "test://redirect-write", next, std::move(second_results));
    if (!succeeded("LayerHandle::continue_write done", finished) ||
        !finished.value().is_done() ||
        !finished.value().info().has_size() ||
        finished.value().info().size() != 5) {
        std::cerr << "continue_write did not return the final object info\n";
        co_return ovstorage::Result<bool>::success(false);
    }

    ovstorage::ReadOptions latest_options;
    latest_options.range_start = 2;
    latest_options.range_end_inclusive = 4;
    auto latest = co_await layer.get_latest_version(
        "test://latest-version", latest_options);
    if (!succeeded("LayerHandle::get_latest_version", latest) ||
        !latest.value().has_size() || latest.value().size() != 777) {
        std::cerr << "get_latest_version did not reach its dedicated slot\n";
        co_return ovstorage::Result<bool>::success(false);
    }

    ovstorage::WatchDirectoryOptions watch_options;
    watch_options.recursive = true;
    watch_options.include_metadata_changes = true;
    watch_options.since = {'s', 'i', 'n', 'c', 'e'};
    watch_options.poll_interval_ms = 25;
    std::vector<ovstorage::BackendChangeEvent> observed;
    auto watched = co_await layer.watch_directory(
        "test://watched/", std::move(watch_options), nullptr,
        [&](const ovstorage::BackendChangeEvent& event) {
            observed.push_back(event);
        });
    if (!succeeded("LayerHandle::watch_directory", watched) ||
        observed.size() != 2 ||
        observed[0].kind() !=
            OvStorage_BackendChangeEventKind_Object ||
        observed[1].kind() !=
            OvStorage_BackendChangeEventKind_Lapsed) {
        std::cerr << "watch_directory did not preserve the event stream\n";
        co_return ovstorage::Result<bool>::success(false);
    }

    // A non-empty cursor must arrive as present. Asserted against what the
    // stub RECEIVED, not against the options this driver believes it sent.
    if (ovstorage_c_source_new_ops_watch_since_present() == 0 ||
        ovstorage_c_source_new_ops_watch_since_len() != 5) {
        std::cerr << "watch_directory with a 5-byte cursor reached the "
                     "backend as "
                  << (ovstorage_c_source_new_ops_watch_since_present() != 0
                          ? "present"
                          : "ABSENT")
                  << " at length "
                  << ovstorage_c_source_new_ops_watch_since_len()
                  << ", so the subscription would replay from the "
                     "beginning instead of resuming\n";
        co_return ovstorage::Result<bool>::success(false);
    }

    auto watched_defaults =
        co_await layer.watch_directory("test://watched-default/");
    if (!succeeded("LayerHandle::watch_directory defaults", watched_defaults)) {
        std::cerr << "watch_directory defaults diverged from the C API\n";
        co_return ovstorage::Result<bool>::success(false);
    }

    // Default options carry no cursor, so the request must reach the
    // backend absent. This is the control for the case below: without it,
    // a marshal that hard-coded `has_since = true` would satisfy that
    // assertion and still be wrong.
    if (ovstorage_c_source_new_ops_watch_since_present() != 0) {
        std::cerr << "watch_directory with no cursor reached the backend as "
                     "present, so a fresh subscription would be treated as "
                     "a resume\n";
        co_return ovstorage::Result<bool>::success(false);
    }

    // The case `has_since` exists for. A backend may mint a ZERO-LENGTH
    // cursor, and length alone cannot distinguish that from having no
    // cursor: without the flag this arrives as `(NULL, 0, false)`, dispatch
    // reads a fresh subscription, and the whole change history replays
    // silently. Nothing about the call's status reveals it, which is why
    // this asserts on the request the stub received.
    ovstorage::WatchDirectoryOptions empty_cursor;
    empty_cursor.has_since = true;
    auto watched_empty_cursor = co_await layer.watch_directory(
        "test://watched/", std::move(empty_cursor));
    if (!succeeded("watch_directory resuming from an empty cursor",
                   watched_empty_cursor)) {
        co_return ovstorage::Result<bool>::success(false);
    }
    if (ovstorage_c_source_new_ops_watch_since_present() == 0) {
        std::cerr << "watch_directory resuming from an explicitly-present "
                     "empty cursor reached the backend as ABSENT, so the "
                     "subscription replays the whole change history "
                     "instead of resuming\n";
        co_return ovstorage::Result<bool>::success(false);
    }
    if (ovstorage_c_source_new_ops_watch_since_len() != 0) {
        std::cerr << "watch_directory resuming from an empty cursor reached "
                     "the backend at length "
                  << ovstorage_c_source_new_ops_watch_since_len()
                  << " instead of 0\n";
        co_return ovstorage::Result<bool>::success(false);
    }

    int throwing_observer_calls = 0;
    auto throwing_watch = co_await layer.watch_directory(
        "test://throwing-watch/", {}, nullptr,
        [&](const ovstorage::BackendChangeEvent&) {
            ++throwing_observer_calls;
            throw std::runtime_error("watch observer blew up");
        });
    if (throwing_watch ||
        throwing_watch.error().code() != OvStorage_Status_Internal ||
        throwing_watch.error().message().find("watch observer blew up") ==
            std::string::npos ||
        throwing_observer_calls != 1) {
        std::cerr << "a throwing watch observer was not cancelled and "
                     "preserved as the first Internal failure\n";
        co_return ovstorage::Result<bool>::success(false);
    }

    ovstorage::CancelToken shared_cancel;
    std::mutex throwing_watch_mutex;
    std::condition_variable throwing_watch_seen;
    bool shared_observer_fired = false;
    int shared_observer_calls = 0;
    auto shared_throwing_watch = layer.watch_directory(
        "test://throwing-watch/", {}, &shared_cancel,
        [&](const ovstorage::BackendChangeEvent&) {
            {
                std::lock_guard<std::mutex> lock(throwing_watch_mutex);
                shared_observer_fired = true;
                ++shared_observer_calls;
            }
            throwing_watch_seen.notify_all();
            throw std::runtime_error("shared-token watch observer blew up");
        });
    {
        std::unique_lock<std::mutex> lock(throwing_watch_mutex);
        if (!throwing_watch_seen.wait_for(
                lock, std::chrono::seconds(5),
                [&] { return shared_observer_fired; })) {
            shared_cancel.cancel();
            auto abandoned_watch = co_await shared_throwing_watch;
            (void)abandoned_watch;
            std::cerr << "the shared-token watch observer never fired\n";
            co_return ovstorage::Result<bool>::success(false);
        }
    }

    ovstorage::ReadOptions shared_latest_options;
    shared_latest_options.range_start = 2;
    shared_latest_options.range_end_inclusive = 4;
    auto shared_latest = co_await layer.get_latest_version(
        "test://latest-version", shared_latest_options, &shared_cancel);
    const bool observer_cancelled_shared_token = shared_cancel.is_canceled();
    shared_cancel.cancel();
    auto shared_watch_result = co_await shared_throwing_watch;
    if (observer_cancelled_shared_token ||
        !succeeded("operation sharing a watch cancel token", shared_latest) ||
        shared_watch_result ||
        shared_watch_result.error().code() != OvStorage_Status_Internal ||
        shared_watch_result.error().message().find(
            "shared-token watch observer blew up") == std::string::npos ||
        shared_observer_calls != 1) {
        std::cerr << "a throwing watch observer cancelled a caller-owned "
                     "shared token or lost its Internal failure\n";
        co_return ovstorage::Result<bool>::success(false);
    }

    static const std::uint8_t secret[] = {1, 2, 3, 4};
    ovstorage::ConnectionRequest request("stub-kind");
    request.set_display_name("Probe Display");
    request.set_persist(true);
    if (!request.add_config(
            "endpoint",
            ovstorage::ConfigValue::string_("test://config-value")) ||
        !request.add_credential(
            "token",
            ovstorage::SecretValue::bytes(secret, 4))) {
        std::cerr << "could not build the probe request\n";
        co_return ovstorage::Result<bool>::success(false);
    }
    auto probed =
        co_await layer.probe("test://probe-target", request);
    if (!succeeded("LayerHandle::probe", probed) ||
        probed.value().id() != "probe-sentinel") {
        std::cerr << "probe did not preserve its borrowed request\n";
        co_return ovstorage::Result<bool>::success(false);
    }
    if (!request.add_config(
            "after-probe", ovstorage::ConfigValue::string_("still-live"))) {
        std::cerr << "probe consumed its borrowed request\n";
        co_return ovstorage::Result<bool>::success(false);
    }

    ovstorage::UpdateMetadataOptions metadata;
    if (!metadata.set("owner", "integration-test") ||
        !metadata.remove("obsolete")) {
        std::cerr << "could not build the connection metadata patch\n";
        co_return ovstorage::Result<bool>::success(false);
    }
    ovstorage::ConnectionAttributePatch patch;
    patch.display_name = "Updated Display";
    patch.access_mode = "read-write";
    patch.visible = false;
    patch.user_metadata = &metadata;
    auto updated = co_await layer.update_connection_attributes(
        "test://attributes-target", "connection-394", std::move(patch));
    if (!succeeded("LayerHandle::update_connection_attributes", updated) ||
        updated.value().id() != "attributes-sentinel") {
        std::cerr << "update_connection_attributes returned the wrong result\n";
        co_return ovstorage::Result<bool>::success(false);
    }

    co_return ovstorage::Result<bool>::success(true);
}

// Every object-I/O op below is reached with `co_await` on the coroutine
// `sync_wait` drives, so the awaiter handshake runs once per op.
ovstorage::task<bool> exercise_layer(const ovstorage::LayerHandle& layer,
                                     std::string root_address,
                                     std::string object_address)
{
    constexpr std::string_view payload = "ovstorage C++20 cc-test round trip";

    auto written = co_await layer.write(object_address, as_bytes(payload));
    if (!succeeded("LayerHandle::write", written)) {
        co_return ovstorage::Result<bool>::success(false);
    }
    if (!written.value().has_size() || written.value().size() != payload.size()) {
        std::cerr << "write returned unexpected object metadata\n";
        co_return ovstorage::Result<bool>::success(false);
    }

    auto stated = co_await layer.stat(object_address);
    if (!succeeded("LayerHandle::stat", stated)) {
        co_return ovstorage::Result<bool>::success(false);
    }
    if (!stated.value().has_size() || stated.value().size() != payload.size()) {
        std::cerr << "stat returned unexpected object metadata\n";
        co_return ovstorage::Result<bool>::success(false);
    }

    auto read = co_await layer.read_bytes(object_address);
    if (!succeeded("LayerHandle::read_bytes", read)) {
        co_return ovstorage::Result<bool>::success(false);
    }
    if (read.value().first.string() != payload) {
        std::cerr << "read_bytes returned unexpected data\n";
        co_return ovstorage::Result<bool>::success(false);
    }

    // ------------------------------------------------------------------
    // Ranged reads. The two shapes `OvStorage_ReadOptions` can carry are
    // both covered: a bounded window, and a start with no end (read to the
    // object's end). Windows are derived from `payload` rather than spelled
    // as literals, so they stay correct if the payload changes.
    // ------------------------------------------------------------------
    constexpr std::size_t window_start = 10;
    constexpr std::size_t window_end_inclusive = 14;
    const std::string_view bounded_window =
        payload.substr(window_start, window_end_inclusive - window_start + 1);
    const std::string_view trailing_window = payload.substr(window_start);

    ovstorage::ReadOptions bounded;
    bounded.range_start = window_start;
    bounded.range_end_inclusive = window_end_inclusive;

    ovstorage::ReadOptions from_offset;
    from_offset.range_start = window_start;

    auto bounded_bytes = co_await layer.read_bytes(object_address, bounded);
    if (!succeeded("LayerHandle::read_bytes with a bounded range",
                   bounded_bytes) ||
        !window_equals("read_bytes with a bounded range",
                       bounded_bytes.value().first.string(), bounded_window)) {
        co_return ovstorage::Result<bool>::success(false);
    }

    auto offset_bytes = co_await layer.read_bytes(object_address, from_offset);
    if (!succeeded("LayerHandle::read_bytes from an offset", offset_bytes) ||
        !window_equals("read_bytes from an offset",
                       offset_bytes.value().first.string(), trailing_window)) {
        co_return ovstorage::Result<bool>::success(false);
    }

    auto bounded_stream = co_await layer.read_stream(object_address, bounded);
    if (!succeeded("LayerHandle::read_stream with a bounded range",
                   bounded_stream) ||
        !window_equals("read_stream with a bounded range",
                       as_text(bounded_stream.value()), bounded_window)) {
        co_return ovstorage::Result<bool>::success(false);
    }

    auto offset_stream = co_await layer.read_stream(object_address, from_offset);
    if (!succeeded("LayerHandle::read_stream from an offset", offset_stream) ||
        !window_equals("read_stream from an offset",
                       as_text(offset_stream.value()), trailing_window)) {
        co_return ovstorage::Result<bool>::success(false);
    }

    // `read_local_file` materializes, and the `file://` backend's materialize
    // refuses a window (`ovc_file_materialize_result`). That refusal is what
    // proves the option reached the backend: an unranged materialize of the
    // same object succeeds, so a wrapper that dropped the range would answer
    // with a local path here instead of an error.
    auto materialized = co_await layer.read_local_file(object_address);
    if (!succeeded("LayerHandle::read_local_file", materialized)) {
        co_return ovstorage::Result<bool>::success(false);
    }
    if (materialized.value().path().empty()) {
        std::cerr << "read_local_file returned no local path\n";
        co_return ovstorage::Result<bool>::success(false);
    }
    auto materialized_window =
        co_await layer.read_local_file(object_address, bounded);
    if (!failed_with_message("read_local_file with a byte range",
                             materialized_window,
                             OvStorage_Status_InvalidArgument,
                             "materialize does not accept a byte range")) {
        co_return ovstorage::Result<bool>::success(false);
    }

    // `OvStorage_ReadOptions` gates both endpoints behind one `has_range`
    // flag, so an end with no start would marshal to "no range at all" and
    // read the whole object. Every read verb refuses it in the wrapper, ahead
    // of the C ABI — pinned by the reason, since the backend answers
    // InvalidArgument for its own unrelated reasons.
    ovstorage::ReadOptions end_without_start;
    end_without_start.range_end_inclusive = window_end_inclusive;
    constexpr const char* range_reason = "a range end requires a range start";

    auto bad_bytes = co_await layer.read_bytes(object_address, end_without_start);
    if (!rejected_by_input_guard("read_bytes with a range end and no start",
                                 bad_bytes, range_reason)) {
        co_return ovstorage::Result<bool>::success(false);
    }
    auto bad_stream =
        co_await layer.read_stream(object_address, end_without_start);
    if (!rejected_by_input_guard("read_stream with a range end and no start",
                                 bad_stream, range_reason)) {
        co_return ovstorage::Result<bool>::success(false);
    }
    auto bad_local =
        co_await layer.read_local_file(object_address, end_without_start);
    if (!rejected_by_input_guard("read_local_file with a range end and no start",
                                 bad_local, range_reason)) {
        co_return ovstorage::Result<bool>::success(false);
    }

    // An inverted window is the sibling of the shape above. It marshals
    // faithfully, so the wrapper refuses it for diagnostics rather than
    // expressibility: the C layer answers every malformed read with one
    // catch-all string that names neither the range nor the endpoint.
    ovstorage::ReadOptions inverted;
    inverted.range_start = window_end_inclusive;
    inverted.range_end_inclusive = window_start;
    constexpr const char* inverted_reason = "a range end precedes its start";

    auto inverted_bytes = co_await layer.read_bytes(object_address, inverted);
    if (!rejected_by_input_guard("read_bytes with an inverted range",
                                 inverted_bytes, inverted_reason)) {
        co_return ovstorage::Result<bool>::success(false);
    }
    auto inverted_stream = co_await layer.read_stream(object_address, inverted);
    if (!rejected_by_input_guard("read_stream with an inverted range",
                                 inverted_stream, inverted_reason)) {
        co_return ovstorage::Result<bool>::success(false);
    }
    auto inverted_local =
        co_await layer.read_local_file(object_address, inverted);
    if (!rejected_by_input_guard("read_local_file with an inverted range",
                                 inverted_local, inverted_reason)) {
        co_return ovstorage::Result<bool>::success(false);
    }

    // ------------------------------------------------------------------
    // Capabilities, asserted in BOTH polarities against one backend.
    //
    // A test that only checked the true fields would pass just as well
    // against a copy that hard-coded true, and one that only checked the
    // false fields would pass against a struct nobody wrote to. The bundled
    // C file backend happens to give both from one answer: it implements
    // write, delete, create_directory and delete_directory, and leaves its
    // write_stream and write_redirect vtable slots on the unsupported stubs
    // (`ovc_file_test_namespace_slots` pins that), so those two must read
    // false while the other four read true.
    // ------------------------------------------------------------------
    auto roots = co_await layer.list_address_roots();
    if (!succeeded("LayerHandle::list_address_roots", roots)) {
        co_return ovstorage::Result<bool>::success(false);
    }
    const OvStorage_RootInfo* root_info = roots.value().item_at(0);
    if (root_info == nullptr) {
        std::cerr << "list_address_roots returned no root to inspect\n";
        co_return ovstorage::Result<bool>::success(false);
    }
    ovstorage::Capabilities caps;
    *caps.raw() = root_info->capabilities;

    struct CapabilityCase {
        const char* name;
        bool actual;
        bool expected;
    };
    const CapabilityCase capability_cases[] = {
        {"supports_write", caps.supports_write(), true},
        {"supports_delete", caps.supports_delete(), true},
        {"supports_create_directory", caps.supports_create_directory(), true},
        {"supports_delete_directory", caps.supports_delete_directory(), true},
        {"supports_write_stream", caps.supports_write_stream(), false},
        {"supports_write_redirect", caps.supports_write_redirect(), false},
    };
    for (const auto& c : capability_cases) {
        if (c.actual != c.expected) {
            std::cerr << "capability " << c.name << " read "
                      << (c.actual ? "true" : "false")
                      << " from the file backend, which reports "
                      << (c.expected ? "true" : "false") << '\n';
            co_return ovstorage::Result<bool>::success(false);
        }
    }

    // `owning_target` is the connection-op target, and it is NOT the root
    // URL: here it is the Layer instance name the Stack was built with.
    if (root_info->owning_target == nullptr ||
        std::string_view(root_info->owning_target) != "files") {
        std::cerr << "root owning_target read \""
                  << (root_info->owning_target == nullptr
                          ? "<null>"
                          : root_info->owning_target)
                  << "\" instead of the owning Layer instance \"files\"\n";
        co_return ovstorage::Result<bool>::success(false);
    }
    // Pinned as Native specifically, not merely "some value": a dropped
    // field would read as Native's own discriminant 0 only if Native were
    // the zero variant — which it is, so the assertion below is paired with
    // the `owning_target` one above, whose absent value is a null pointer.
    if (root_info->range_read_strategy !=
        OvStorage_RangeReadStrategy_Native) {
        std::cerr << "root range_read_strategy read "
                  << static_cast<int>(root_info->range_read_strategy)
                  << " instead of Native\n";
        co_return ovstorage::Result<bool>::success(false);
    }

    // ------------------------------------------------------------------
    // If-match preconditions on write. `supports_if_match_write` has been
    // advertised by this backend all along; until now no C or C++ caller
    // could act on it.
    // ------------------------------------------------------------------
    auto before_cas = co_await layer.stat(object_address);
    if (!succeeded("stat before a compare-and-swap write", before_cas)) {
        co_return ovstorage::Result<bool>::success(false);
    }
    const std::string current_etag = before_cas.value().etag();
    if (current_etag.empty()) {
        std::cerr << "the file backend reported no etag, so an if-match "
                     "precondition cannot be exercised\n";
        co_return ovstorage::Result<bool>::success(false);
    }

    constexpr std::string_view cas_payload = "compare-and-swap";
    ovstorage::WriteOptions match_current;
    match_current.if_match_etag = current_etag;
    auto cas_ok =
        co_await layer.write(object_address, as_bytes(cas_payload), match_current);
    if (!succeeded("write with a matching if_match_etag", cas_ok)) {
        co_return ovstorage::Result<bool>::success(false);
    }
    // "Reported ok" is not "wrote": read the object back.
    auto after_cas = co_await layer.read_bytes(object_address);
    if (!succeeded("read after a matching if_match_etag write", after_cas) ||
        !window_equals("write with a matching if_match_etag",
                       after_cas.value().first.string(), cas_payload)) {
        co_return ovstorage::Result<bool>::success(false);
    }

    // `current_etag` named the object BEFORE the write above, so it is
    // stale by construction rather than by an invented string — which is
    // the case a compare-and-swap actually has to detect.
    ovstorage::WriteOptions match_stale;
    match_stale.if_match_etag = current_etag;
    auto cas_stale =
        co_await layer.write(object_address, as_bytes(payload), match_stale);
    if (!failed_with_message("write with a stale if_match_etag", cas_stale,
                             OvStorage_Status_PreconditionFailed,
                             "write destination etag does not match")) {
        co_return ovstorage::Result<bool>::success(false);
    }
    // A refused precondition must leave the object untouched.
    auto after_stale = co_await layer.read_bytes(object_address);
    if (!succeeded("read after a stale if_match_etag write", after_stale) ||
        !window_equals("object after a refused if_match_etag write",
                       after_stale.value().first.string(), cas_payload)) {
        co_return ovstorage::Result<bool>::success(false);
    }

    // The two preconditions are mutually exclusive, refused rather than
    // given a precedence.
    ovstorage::WriteOptions both_preconditions;
    both_preconditions.no_overwrite = true;
    both_preconditions.if_match_etag = current_etag;
    auto refused_both = co_await layer.write(
        object_address, as_bytes(payload), both_preconditions);
    if (!rejected_by_input_guard(
            "write with both no_overwrite and if_match_etag", refused_both,
            "set both no_overwrite and if_match_etag")) {
        co_return ovstorage::Result<bool>::success(false);
    }

    // An empty etag is refused rather than read as "no precondition",
    // which is what a caller propagating an absent `Info::etag()` would
    // otherwise get: an unconditional overwrite where they asked for a
    // compare-and-swap.
    ovstorage::WriteOptions empty_etag;
    empty_etag.if_match_etag = std::string{};
    auto refused_empty =
        co_await layer.write(object_address, as_bytes(payload), empty_etag);
    if (!rejected_by_input_guard("write with an empty if_match_etag",
                                 refused_empty, "empty if_match_etag")) {
        co_return ovstorage::Result<bool>::success(false);
    }

    // The etag routes through the same string chokepoint every other
    // caller-supplied string does, so a non-UTF-8 one is refused by the
    // wrapper rather than reaching the C ABI.
    ovstorage::WriteOptions non_utf8_etag;
    non_utf8_etag.if_match_etag = std::string("\xff\xfe");
    auto refused_non_utf8 =
        co_await layer.write(object_address, as_bytes(payload), non_utf8_etag);
    if (!rejected_by_input_guard("write with a non-UTF-8 if_match_etag",
                                 refused_non_utf8,
                                 "if_match_etag is not valid UTF-8")) {
        co_return ovstorage::Result<bool>::success(false);
    }

    // Every one of the three refusals above is answered by the wrapper
    // before the C layer sees it, so the C layer's own copies are reachable
    // only from C — which is how a pure-C caller reaches them. Drive the raw
    // entry point at each.
    OvStorage_WriteOptions raw_both{};
    raw_both.no_overwrite = true;
    raw_both.if_match_etag = current_etag.c_str();
    if (!raw_write_is_rejected("write with both no_overwrite and if_match_etag",
                               layer, object_address, raw_both,
                               "set both no_overwrite and if_match_etag")) {
        co_return ovstorage::Result<bool>::success(false);
    }
    OvStorage_WriteOptions raw_empty{};
    static const char empty_c_etag[] = "";
    raw_empty.if_match_etag = empty_c_etag;
    if (!raw_write_is_rejected("write with an empty if_match_etag", layer,
                               object_address, raw_empty,
                               "empty if_match_etag")) {
        co_return ovstorage::Result<bool>::success(false);
    }
    OvStorage_WriteOptions raw_non_utf8{};
    static const char non_utf8_c_etag[] = "\xff\xfe";
    raw_non_utf8.if_match_etag = non_utf8_c_etag;
    if (!raw_write_is_rejected("write with a non-UTF-8 if_match_etag", layer,
                               object_address, raw_non_utf8,
                               "non-UTF-8 if_match_etag")) {
        co_return ovstorage::Result<bool>::success(false);
    }

    auto listed = co_await layer.list(root_address, true);
    if (!succeeded("LayerHandle::list", listed)) {
        co_return ovstorage::Result<bool>::success(false);
    }
    if (listed.value().size() != 1 ||
        listed.value().address(0) != object_address) {
        std::cerr << "list did not return the round-trip object\n";
        co_return ovstorage::Result<bool>::success(false);
    }

    // Error-path pins: exercise the wrapper's error -> Result marshaling
    // (detail::*_awaiter::on_complete), which the happy path never hits.
    auto missing = co_await layer.stat(root_address + "never-written.bin");
    if (!failed_with("stat of a missing address", missing,
                     OvStorage_Status_NotFound)) {
        co_return ovstorage::Result<bool>::success(false);
    }

    auto create_only = co_await layer.write(
        object_address, as_bytes(payload), /*no_overwrite=*/true);
    if (!failed_with("create-only write onto an existing object", create_only,
                     OvStorage_Status_AlreadyExists)) {
        co_return ovstorage::Result<bool>::success(false);
    }

    ovstorage::CancelToken cancelled_token;
    cancelled_token.cancel();
    auto cancelled = co_await layer.read_bytes(object_address, &cancelled_token);
    if (!failed_with("read_bytes with a pre-cancelled token", cancelled,
                     OvStorage_Status_Cancelled)) {
        co_return ovstorage::Result<bool>::success(false);
    }

    // An embedded NUL cannot cross the C ABI's char* boundary, so the
    // wrapper rejects it rather than letting `c_str()` truncate it. Pin
    // the guard on an address...
    const std::string nul_address("file:///tmp/a\0b.bin", 19);
    auto embedded_nul = co_await layer.stat(nul_address);
    if (!rejected_by_nul_guard("stat of an address with an embedded NUL",
                              embedded_nul)) {
        co_return ovstorage::Result<bool>::success(false);
    }

    // ...and on a non-address string input, so what is pinned is the
    // chokepoint every entry point routes through, not one verb's address.
    const std::string nul_page_token("page\0token", 10);
    auto nul_token_list =
        co_await layer.list(root_address, false, 0, nul_page_token);
    if (!rejected_by_nul_guard("list with a page token carrying an embedded NUL",
                              nul_token_list)) {
        co_return ovstorage::Result<bool>::success(false);
    }

    // Delete through the wrapper, then pin that the object is gone.
    auto deleted = co_await layer.delete_object(object_address);
    if (!succeeded("LayerHandle::delete_object", deleted)) {
        co_return ovstorage::Result<bool>::success(false);
    }
    auto stat_after_delete = co_await layer.stat(object_address);
    if (!failed_with("stat after delete", stat_after_delete,
                     OvStorage_Status_NotFound)) {
        co_return ovstorage::Result<bool>::success(false);
    }

    co_return ovstorage::Result<bool>::success(true);
}

// `authenticate_connection`'s observer must see each event AS IT ARRIVES,
// which is the entire reason the observer exists: a device-code flow emits
// its URL and user code and then waits for the user, so a host that only
// learns of them when the task resolves learns too late to act.
//
// The fixture is a Layer whose authenticate slot emits one DeviceCode event
// and then PARKS (`auth_event_stub_c.c`), imported through the handoff verbs.
// The park is what makes the ordering observable rather than assumed: this
// thread waits for the observer to fire, checks the driving task has NOT
// resolved, and only then releases the flow.
bool auth_observer_sees_events_while_the_flow_is_still_running()
{
    auto imported =
        ovstorage::LayerHandle::import_handle(ovstorage_c_source_auth_stub_root());
    if (!succeeded("import of the auth stub root", imported)) {
        return false;
    }
    ovstorage::LayerHandle layer = std::move(imported).value();

    std::mutex mutex;
    std::condition_variable seen;
    std::vector<OvStorage_AuthEventKind> observed;
    std::string observed_user_code;
    std::string observed_url;
    std::atomic<bool> resolved{false};
    ovstorage::Result<std::vector<ovstorage::AuthEvent>> outcome =
        ovstorage::Result<std::vector<ovstorage::AuthEvent>>::failure(
            ovstorage::Error{});

    std::thread worker([&] {
        outcome = ovstorage::sync_wait(layer.authenticate_connection(
            "files", "connection", OvStorage_InteractiveAuthCapability_None,
            /*auto_open_browser=*/false, nullptr,
            [&](const ovstorage::AuthEvent& event) {
                std::lock_guard<std::mutex> lock(mutex);
                observed.push_back(event.kind());
                observed_user_code =
                    event.device_code_user_code().value_or(std::string{});
                observed_url =
                    event.device_code_verification_url().value_or(std::string{});
                seen.notify_all();
            }));
        resolved.store(true, std::memory_order_release);
    });

    // Rendezvous with the stub's own signal, then with the observer's. BOTH
    // waits are bounded: "the flow never reached the Layer" and "the
    // observer never fired" are both regressions this pins, and either
    // should be reported here rather than wedge the test binary until the
    // job times out.
    bool ok = true;
    if (!ovstorage_c_source_auth_stub_wait_emitted()) {
        std::cerr << "the Layer's authenticate slot never ran, so the flow "
                     "never reached the point where an event is emitted\n";
        ovstorage_c_source_auth_stub_release();
        worker.join();
        return false;
    }
    bool observer_fired = false;
    {
        std::unique_lock<std::mutex> lock(mutex);
        observer_fired = seen.wait_for(lock, std::chrono::seconds(30),
            [&] { return !observed.empty(); });
    }

    if (!observer_fired) {
        std::cerr << "the observer never fired, though the Layer had already "
                     "emitted its DeviceCode event: events are not being "
                     "delivered as they arrive\n";
        ok = false;
    }
    if (ok && resolved.load(std::memory_order_acquire)) {
        std::cerr << "the auth task resolved before the observer ran, so the "
                     "observer proves nothing about delivery timing\n";
        ok = false;
    }
    if (ok) {
        if (observed.size() != 1 ||
            observed[0] != OvStorage_AuthEventKind_DeviceCode) {
            std::cerr << "observer did not see exactly one DeviceCode event\n";
            ok = false;
        } else if (observed_user_code !=
                       ovstorage_c_source_auth_stub_user_code() ||
                   observed_url !=
                       ovstorage_c_source_auth_stub_verification_url()) {
            std::cerr << "the observed DeviceCode event lacked the fields a "
                         "host needs to render the prompt: user_code=\""
                      << observed_user_code << "\" url=\"" << observed_url
                      << "\"\n";
            ok = false;
        }
    }

    ovstorage_c_source_auth_stub_release();
    worker.join();

    if (!succeeded("authenticate_connection", outcome)) {
        return false;
    }
    if (outcome.value().size() != 1) {
        std::cerr << "the resolved task delivered " << outcome.value().size()
                  << " events, want 1\n";
        ok = false;
    }
    return ok;
}

// Every LayerHandle verb that takes a string must route it through the
// wrapper's string-input chokepoint. A table rather than a handful of spot
// checks, because the failure this pins is a guard that is PRESENT but
// UNREACHABLE — a guard sitting inside the null-handle branch, after an
// unconditional `co_return`, is one spelling of that. That
// compiles, and a sibling verb's passing assertion covers for it. Only a
// per-verb sweep turns "every entry point is guarded" into something the
// build checks rather than something a comment claims.
//
// Each entry substitutes the bad value for ONE string parameter, so a verb
// taking two strings appears twice.

template <class T>
ovstorage::Error outcome_error(const ovstorage::Result<T>& result)
{
    if (result) {
        return ovstorage::Error(OvStorage_Status_Ok, "unexpectedly succeeded");
    }
    return result.error();
}

using GuardedVerb =
    std::function<ovstorage::Error(const ovstorage::LayerHandle&, const std::string&)>;

std::vector<std::pair<const char*, GuardedVerb>> guarded_verbs()
{
    using L = ovstorage::LayerHandle;
    const auto payload = as_bytes("x");
    return {
        {"stat(address)", [](const L& l, const std::string& b) {
             return outcome_error(ovstorage::sync_wait(l.stat(b))); }},
        {"read_bytes(address)", [](const L& l, const std::string& b) {
             return outcome_error(ovstorage::sync_wait(l.read_bytes(b))); }},
        {"read_stream(address)", [](const L& l, const std::string& b) {
             return outcome_error(ovstorage::sync_wait(l.read_stream(b))); }},
        {"read_local_file(address)", [](const L& l, const std::string& b) {
             return outcome_error(ovstorage::sync_wait(l.read_local_file(b))); }},
        {"write(address)", [payload](const L& l, const std::string& b) {
             return outcome_error(ovstorage::sync_wait(l.write(b, payload))); }},
        {"write_stream(address)", [](const L& l, const std::string& b) {
             return outcome_error(ovstorage::sync_wait(
                 l.write_stream(b, ovstorage::WriteStream{}))); }},
        {"write_redirect(address)", [](const L& l, const std::string& b) {
             return outcome_error(ovstorage::sync_wait(l.write_redirect(b))); }},
        {"continue_write(address)", [](const L& l, const std::string& b) {
             ovstorage::WriteRedirectBatch redirects;
             return outcome_error(ovstorage::sync_wait(
                 l.continue_write(b, redirects, {}))); }},
        {"delete_object(address)", [](const L& l, const std::string& b) {
             return outcome_error(ovstorage::sync_wait(l.delete_object(b))); }},
        {"list(prefix)", [](const L& l, const std::string& b) {
             return outcome_error(ovstorage::sync_wait(l.list(b))); }},
        {"list(page_token)", [](const L& l, const std::string& b) {
             return outcome_error(
                 ovstorage::sync_wait(l.list("file:///tmp/", false, 0, b))); }},
        {"list_versions(address)", [](const L& l, const std::string& b) {
             return outcome_error(ovstorage::sync_wait(l.list_versions(b))); }},
        {"list_versions(page_token)", [](const L& l, const std::string& b) {
             return outcome_error(
                 ovstorage::sync_wait(l.list_versions("file:///tmp/a", 0, b))); }},
        {"get_latest_version(address)", [](const L& l, const std::string& b) {
             return outcome_error(
                 ovstorage::sync_wait(l.get_latest_version(b))); }},
        {"watch_directory(prefix)", [](const L& l, const std::string& b) {
             return outcome_error(
                 ovstorage::sync_wait(l.watch_directory(b))); }},
        {"copy(src)", [](const L& l, const std::string& b) {
             return outcome_error(ovstorage::sync_wait(l.copy(b, "file:///tmp/b"))); }},
        {"copy(dest)", [](const L& l, const std::string& b) {
             return outcome_error(ovstorage::sync_wait(l.copy("file:///tmp/a", b))); }},
        {"rename(src)", [](const L& l, const std::string& b) {
             return outcome_error(ovstorage::sync_wait(l.rename(b, "file:///tmp/b"))); }},
        {"rename(dest)", [](const L& l, const std::string& b) {
             return outcome_error(ovstorage::sync_wait(l.rename("file:///tmp/a", b))); }},
        {"create_directory(address)", [](const L& l, const std::string& b) {
             return outcome_error(ovstorage::sync_wait(l.create_directory(b))); }},
        {"delete_directory(address)", [](const L& l, const std::string& b) {
             return outcome_error(ovstorage::sync_wait(l.delete_directory(b))); }},
        {"update_metadata(address)", [](const L& l, const std::string& b) {
             ovstorage::UpdateMetadataOptions options;
             return outcome_error(
                 ovstorage::sync_wait(l.update_metadata(b, options))); }},
        {"check_access(address)", [](const L& l, const std::string& b) {
             return outcome_error(ovstorage::sync_wait(l.check_access(b, true))); }},
        {"probe(target)", [](const L& l, const std::string& b) {
             ovstorage::ConnectionRequest request("file");
             return outcome_error(
                 ovstorage::sync_wait(l.probe(b, request))); }},
        {"add_connection(target)", [](const L& l, const std::string& b) {
             ovstorage::ConnectionRequest request("file");
             return outcome_error(
                 ovstorage::sync_wait(l.add_connection(b, std::move(request)))); }},
        {"remove_connection(target)", [](const L& l, const std::string& b) {
             return outcome_error(
                 ovstorage::sync_wait(l.remove_connection(b, "id"))); }},
        {"remove_connection(connection_id)", [](const L& l, const std::string& b) {
             return outcome_error(
                 ovstorage::sync_wait(l.remove_connection("files", b))); }},
        {"update_connection_credentials(target)", [](const L& l, const std::string& b) {
             ovstorage::SecretBundle bundle;
             return outcome_error(ovstorage::sync_wait(
                 l.update_connection_credentials(b, "id", std::move(bundle)))); }},
        {"update_connection_credentials(connection_id)",
         [](const L& l, const std::string& b) {
             ovstorage::SecretBundle bundle;
             return outcome_error(ovstorage::sync_wait(
                 l.update_connection_credentials("files", b, std::move(bundle)))); }},
        {"update_connection_attributes(target)",
         [](const L& l, const std::string& b) {
             return outcome_error(ovstorage::sync_wait(
                 l.update_connection_attributes(
                     b, "id", ovstorage::ConnectionAttributePatch{}))); }},
        {"update_connection_attributes(connection_id)",
         [](const L& l, const std::string& b) {
             return outcome_error(ovstorage::sync_wait(
                 l.update_connection_attributes(
                     "files", b, ovstorage::ConnectionAttributePatch{}))); }},
        {"update_connection_attributes(display_name)",
         [](const L& l, const std::string& b) {
             ovstorage::ConnectionAttributePatch patch;
             patch.display_name = b;
             return outcome_error(ovstorage::sync_wait(
                 l.update_connection_attributes(
                     "files", "id", std::move(patch)))); }},
        {"update_connection_attributes(access_mode)",
         [](const L& l, const std::string& b) {
             ovstorage::ConnectionAttributePatch patch;
             patch.access_mode = b;
             return outcome_error(ovstorage::sync_wait(
                 l.update_connection_attributes(
                     "files", "id", std::move(patch)))); }},
        {"authenticate_connection(target)", [](const L& l, const std::string& b) {
             return outcome_error(ovstorage::sync_wait(
                 l.authenticate_connection(b, "id"))); }},
        {"authenticate_connection(connection_id)", [](const L& l, const std::string& b) {
             return outcome_error(ovstorage::sync_wait(
                 l.authenticate_connection("files", b))); }},
    };
}

bool every_string_verb_is_guarded(const ovstorage::LayerHandle& layer)
{
    // "file:///tmp/a\0b" truncates to a valid address; "\x80" is a lone UTF-8
    // continuation byte. Both are ordinary `std::string` values.
    const std::pair<std::string, const char*> bad_inputs[] = {
        {std::string("file:///tmp/a\0b.bin", 19), "embedded NUL"},
        {std::string("file:///tmp/a\x80", 14), "not valid UTF-8"},
    };

    bool ok = true;
    for (const auto& [name, invoke] : guarded_verbs()) {
        for (const auto& [bad, reason] : bad_inputs) {
            const ovstorage::Error error = invoke(layer, bad);
            if (error.code() != OvStorage_Status_InvalidArgument ||
                error.message().find(reason) == std::string::npos) {
                std::cerr << name << " did not reject a " << reason
                          << " input through the wrapper's guard: status "
                          << static_cast<int>(error.code()) << " \""
                          << error.message() << "\"\n";
                ok = false;
            }
        }
    }
    return ok;
}

// A `std::string` can hold bytes that are not UTF-8, and the C ABI rejects
// those in the same prologue that decides whether it consumed a handed-over
// handle. Two things are pinned here.
//
// First: the wrapper's own guard is what rejects them, so that prologue is
// unreachable for a reason a caller controls.
//
// Second, and the point of the exercise: the connection request is STILL
// OWNED afterwards, so the caller can correct the target and retry with the
// same builder. The wrapper's guard runs before it releases the raw pointer,
// which is what keeps a caller-attributable rejection retryable; past that
// point the request is spent whichever way the C call goes, because the C
// side reports what it took by clearing the slot rather than by status.
bool non_utf8_input_never_orphans_a_request(const ovstorage::LayerHandle& layer)
{
    // 0x80 is a stray UTF-8 continuation byte: a perfectly good
    // `std::string`, and not valid UTF-8.
    const std::string not_utf8("files", 6);

    ovstorage::ConnectionRequest request("file");
    if (request.raw() == nullptr) {
        std::cerr << "failed to create the connection request\n";
        return false;
    }
    auto outcome = ovstorage::sync_wait(
        layer.add_connection(not_utf8, std::move(request)));
    if (!rejected_by_input_guard("add_connection with a non-UTF-8 target",
                                 outcome, "not valid UTF-8")) {
        return false;
    }
    if (request.raw() == nullptr) {
        std::cerr << "add_connection released the request into a call that "
                     "never consumed it\n";
        return false;
    }

    // The same guard on an ordinary object verb, which owns no handle.
    auto stated = ovstorage::sync_wait(layer.stat(not_utf8));
    return rejected_by_input_guard("stat of a non-UTF-8 address", stated,
                                   "not valid UTF-8");
}

// `task<T>` is eager: the operation is submitted by the call, not by the
// await. The header says so; this checks it, because a caller who believes
// otherwise can construct a destructive operation thinking it inert.
//
// The stub Layer makes it observable without an await: it signals the moment
// its slot runs, so waiting on that signal while never touching the task
// proves the call alone started the work.
bool tasks_are_eager()
{
    auto imported =
        ovstorage::LayerHandle::import_handle(ovstorage_c_source_auth_stub_root());
    if (!succeeded("import of the auth stub root", imported)) {
        return false;
    }
    ovstorage::LayerHandle layer = std::move(imported).value();

    bool started = false;
    {
        // Constructed and never awaited.
        auto pending = layer.authenticate_connection("files", "connection");
        started = ovstorage_c_source_auth_stub_wait_emitted() != 0;
        ovstorage_c_source_auth_stub_release();
        // `pending` is abandoned here, which is the drop-before-await path
        // the standalone task-drop regressions cover under ASan.
    }
    if (!started) {
        std::cerr << "an un-awaited task never reached the Layer, so the task "
                     "is not eager and the header's guidance is wrong\n";
        return false;
    }
    return true;
}

// The observer is user code invoked from a C callback, so an exception
// escaping it would unwind through the C stream pump — undefined, and it
// would skip the pump's own cleanup. Without the catch this aborts the
// process (`terminate called after throwing an instance of ...`), so the
// assertion is simply that the program is still here to make it.
bool a_throwing_auth_observer_does_not_escape()
{
    auto imported =
        ovstorage::LayerHandle::import_handle(ovstorage_c_source_auth_stub_root());
    if (!succeeded("import of the auth stub root", imported)) {
        return false;
    }
    ovstorage::LayerHandle layer = std::move(imported).value();
    // No park: the flow should reach its terminal on its own.
    ovstorage_c_source_auth_stub_release();

    auto outcome = ovstorage::sync_wait(layer.authenticate_connection(
        "files", "connection", OvStorage_InteractiveAuthCapability_None,
        /*auto_open_browser=*/false, nullptr,
        [](const ovstorage::AuthEvent&) {
            throw std::runtime_error("observer blew up");
        }));

    if (outcome) {
        std::cerr << "a throwing observer left the task successful; the "
                     "failure was swallowed rather than reported\n";
        return false;
    }
    if (outcome.error().code() != OvStorage_Status_Internal ||
        outcome.error().message().find("observer blew up") == std::string::npos) {
        std::cerr << "a throwing observer did not surface as an Internal "
                     "failure naming what was thrown: status "
                  << static_cast<int>(outcome.error().code()) << " \""
                  << outcome.error().message() << "\"\n";
        return false;
    }
    return true;
}

// The embedded-NUL chokepoint also covers the non-coroutine builders,
// whose failure channels differ per entry point: a Result for the Stack
// verbs, a null handle for `ConfigValue`, `false` for the request setters.
bool builders_reject_embedded_nul()
{
    // "files" is a declared instance, so without the guard the truncated
    // id would be ACCEPTED — the guard is the only reason this fails.
    const std::string nul_id("files\0shadow", 12);

    ovstorage::Registry registry;
    ovstorage::Stack stack;
    if (!succeeded("Stack::add_layer", stack.add_layer(registry, "files", "file"))) {
        return false;
    }
    auto rooted = stack.set_root(nul_id);
    if (!rejected_by_nul_guard("Stack::set_root with an embedded NUL", rooted)) {
        return false;
    }

    if (ovstorage::ConfigValue::string_(std::string("a\0b", 3)).raw() != nullptr) {
        std::cerr << "ConfigValue::string_ accepted an embedded NUL\n";
        return false;
    }

    ovstorage::ConnectionRequest request("file");
    if (request.add_config(std::string("ro\0ot", 5),
                           ovstorage::ConfigValue::string_("file:///tmp/"))) {
        std::cerr << "ConnectionRequest::add_config accepted an embedded NUL key\n";
        return false;
    }

    return true;
}

bool layer_config_retains_value_on_failure()
{
    ovstorage::Registry registry;
    ovstorage::Stack stack;
    if (!succeeded("Stack::add_layer for Layer config",
                   stack.add_layer(registry, "files", "file"))) {
        return false;
    }

    auto accepted = ovstorage::ConfigValue::string_("accepted");
    auto configured =
        stack.add_layer_config("files", "mode", std::move(accepted));
    if (!succeeded("Stack::add_layer_config", configured) ||
        accepted.raw() != nullptr) {
        std::cerr << "successful Layer config did not consume its value\n";
        return false;
    }

    auto retained = ovstorage::ConfigValue::string_("first");
    auto rejected =
        stack.add_layer_config("missing", "mode", std::move(retained));
    const char* retained_text =
        retained.raw() == nullptr
            ? nullptr
            : ovstorage_config_value_as_string(retained.raw());
    if (rejected || retained_text == nullptr ||
        std::string(retained_text) != "first") {
        std::cerr << "rejected Layer config did not retain a usable value\n";
        return false;
    }
    return true;
}

// A default-constructed LayerHandle is null. The wrapper short-circuits
// before entering the C ABI so a coroutine caller still sees the ordinary
// failed-Result shape rather than an inline C callback.
bool null_handle_short_circuits()
{
    ovstorage::LayerHandle empty;
    auto outcome = ovstorage::sync_wait(empty.stat("file:///nowhere.bin"));
    return failed_with("stat through a null LayerHandle", outcome,
                       OvStorage_Status_InvalidArgument);
}

bool run_roundtrip(const std::string& root_address,
                   const std::string& object_address)
{
    ovstorage::Registry registry;
    ovstorage::Stack stack;
    if (registry.get() == nullptr || stack.get() == nullptr) {
        std::cerr << "failed to create the registry or Stack builder\n";
        return false;
    }

    // No Plugin exists or is registered. Resolving "file" here proves that
    // Registry seeded the built-in file factory.
    auto added_layer = stack.add_layer(registry, "files", "file");
    if (!succeeded("seeded file resolution with zero plugins loaded",
                   added_layer)) {
        return false;
    }
    auto selected_root = stack.set_root("files");
    if (!succeeded("Stack::set_root", selected_root)) {
        return false;
    }

    ovstorage::ConnectionRequest request("file");
    auto root_value = ovstorage::ConfigValue::string_(root_address);
    if (root_value.raw() == nullptr ||
        !request.add_config("root", std::move(root_value))) {
        std::cerr << "failed to create the file connection config\n";
        return false;
    }

    auto added_connection =
        stack.add_connection("files", std::move(request));
    if (!succeeded("Stack::add_connection", added_connection)) {
        return false;
    }

    // `Stack::build` is itself a coroutine; the local `stack` outlives the
    // await because sync_wait returns only once the build has resolved.
    auto built = ovstorage::sync_wait(stack.build());
    if (!succeeded("Stack::build", built)) {
        return false;
    }
    ovstorage::LayerHandle layer = std::move(built).value();

    auto outcome = ovstorage::sync_wait(
        exercise_layer(layer, root_address, object_address));
    if (!succeeded("round-trip coroutine", outcome)) {
        return false;
    }
    if (!outcome.value() || !null_handle_short_circuits() ||
        !builders_reject_embedded_nul() ||
        !layer_config_retains_value_on_failure() ||
        !non_utf8_input_never_orphans_a_request(layer) ||
        !every_string_verb_is_guarded(layer)) {
        return false;
    }

    auto imported_new_ops = ovstorage::LayerHandle::import_handle(
        ovstorage_c_source_new_ops_stub_root());
    if (!succeeded("import of the new-operation stub root", imported_new_ops)) {
        return false;
    }
    ovstorage::LayerHandle new_ops_layer =
        std::move(imported_new_ops).value();
    auto new_operations =
        ovstorage::sync_wait(exercise_new_operations(new_ops_layer));
    return succeeded("new C++ operation wrappers", new_operations) &&
        new_operations.value() &&
        auth_observer_sees_events_while_the_flow_is_still_running() &&
        a_throwing_auth_observer_does_not_escape() && tasks_are_eager();
}

} // namespace

extern "C" int ovstorage_c_source_roundtrip_cpp20(void)
{
    char directory[OVC_TEMP_DIR_PATH_MAX];
    if (ovc_temp_dir_create("ovstorage-c-source-cc-test-cpp",
                            directory,
                            sizeof(directory)) != 0) {
        std::cerr << "creating a temporary directory failed: "
                  << test_error_message(errno) << '\n';
        return EXIT_FAILURE;
    }

    const std::string root_address = test_root_address(directory);
    const std::string object_address = root_address + "cpp20-roundtrip.bin";
    const std::string native_object =
        std::string(directory) + "/cpp20-roundtrip.bin";

    // Empty means the root has no addressable `file://` form -- a UNC
    // temporary root on Win32. Skip the round trip, but fall through to the
    // cleanup below, which still has a directory to remove.
    bool roundtrip_ok = false;
    if (root_address.empty()) {
        std::fprintf(stderr,
                     "the temporary root is a UNC path (%s); this contract "
                     "needs a local-drive TMP/TEMP\n",
                     directory);
    } else {
        roundtrip_ok = run_roundtrip(root_address, object_address);
    }
    bool cleanup_ok = true;
    // The round trip deletes the object through LayerHandle::delete_object;
    // this ENOENT-tolerant unlink only clears the object if the round trip
    // failed before deleting, so the directory can still be removed.
    if (test_unlink(native_object) != 0 && errno != ENOENT) {
        std::cerr << "file removal failed: " << test_error_message(errno) << '\n';
        cleanup_ok = false;
    }
    if (test_rmdir(directory) != 0) {
        std::cerr << "directory removal failed: " << test_error_message(errno)
                  << '\n';
        cleanup_ok = false;
    }

    return roundtrip_ok && cleanup_ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
