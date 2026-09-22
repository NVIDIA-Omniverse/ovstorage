// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// C++ binding runner for the app-level integration suite: the consume side of
// a Rust -> C++ live handoff.
//
// `tests/cpp.rs` composes the SAME routed `ovstorage::Stack` the Rust leg
// drives (one connection per configured backend, over the default wrapper
// chain `alias -> redirect_follower -> retry -> router`), mints one owned
// `OvStoragePlugin_LayerHandle` over its root with `ovstorage::export_handle`,
// and hands it to `ovsx_cloud_driver_run` below once per (backend, scenario).
// This TU imports it with `ovstorage_import_handle`, wraps the result in the
// shipped C++20 RAII wrapper (`ovstorage.hpp`), and drives the scenario
// against the C++ API — the path a real C++ consumer takes.
//
// ## Why the Stack is composed in Rust and not here
//
// The pure-C runtime in `ovstorage-c-source/` is file-backend-only BY DESIGN:
// it carries no HTTP/TLS client and no redirect follower. Azure and S3 answer
// every read with `ReadResult::Redirect`, and this dispatcher rejects one
// outright ("read returned a redirect but this Stack has no redirect
// follower", `src/dispatch.c`). A Stack composed inside pure C therefore
// cannot read a cloud object at all. Importing a handle over the real Rust
// Stack — which *does* have the follower — is what makes cloud coverage
// reachable from C++, and it is also how C++ hosts embed ovstorage in
// practice.
//
// ## Linkage
//
// This TU is compiled together with the FULL pure-C source distribution
// (`ovstorage-c-source/src/*.c`) into ONE standalone shared object (see
// `CMakeLists.txt` beside this file, staged by
// `tools/ovtasks/_test_plugins.py`). That image must NEVER be linked against
// `ovstorage-plugin`'s rlib: both export `ovstorage_plugin_*` symbols and that
// is a hard link collision. The Rust side `dlopen`s it `RTLD_LOCAL` for the
// same reason — see the header comment on
// `ovstorage-core/ovstorage/tests/handoff_c_source.rs`, the same mechanism in
// the opposite direction.
//
// ## Contract of the entry point
//
// One call runs exactly one scenario and reports a tri-state: 0 pass, 77
// skipped (a visible skip with its reason in `err`, matching the "⊘ SKIPPED"
// convention the Rust and Python legs print), anything else a failure with a
// human-readable message in `err`. Nothing is written to stdout/stderr; the
// Rust side owns the reporting so all three legs read alike.

#include "ovstorage.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <fstream>
#include <iterator>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace {

// Tri-state result codes. 77 is the ctest SKIP_RETURN_CODE convention and is
// deliberately NOT in the "failure" range: a scenario the C++ API cannot
// express must be visible, and must not be mistaken for a broken backend.
constexpr int DRIVER_PASS = 0;
constexpr int DRIVER_FAIL = 1;
constexpr int DRIVER_SKIP = 77;

struct Outcome {
    int code = DRIVER_PASS;
    std::string message;
};

Outcome passed()
{
    return Outcome{DRIVER_PASS, std::string{}};
}

Outcome skipped(std::string why)
{
    return Outcome{DRIVER_SKIP, std::move(why)};
}

Outcome failed(std::string what)
{
    return Outcome{DRIVER_FAIL, std::move(what)};
}

// Everything a scenario needs beyond the imported handle. `caps` is the
// target root's real advertised capability set, read back over the bridge
// through `RootInfo` (see `capabilities_for`) — the same gate the Rust
// scenarios apply, evaluated against what the C ABI actually carries.
struct Context {
    std::string root;
    std::string prefix;
    ovstorage::Capabilities caps;
};

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

std::span<const std::byte> as_bytes(const std::string& value)
{
    return std::span<const std::byte>(
        reinterpret_cast<const std::byte*>(value.data()), value.size());
}

std::string bytes_to_string(std::span<const std::byte> bytes)
{
    return std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size());
}

bool ends_with(const std::string& value, std::string_view suffix)
{
    return value.size() >= suffix.size()
        && value.compare(value.size() - suffix.size(), suffix.size(), suffix) == 0;
}

// Spelled out rather than printed as a bare integer: a failure line naming
// `Unsupported` is actionable, one naming `7` sends the reader to the header.
const char* status_name(OvStorage_Status status)
{
    switch (status) {
    case OvStorage_Status_Ok: return "Ok";
    case OvStorage_Status_NotFound: return "NotFound";
    case OvStorage_Status_AlreadyExists: return "AlreadyExists";
    case OvStorage_Status_PermissionDenied: return "PermissionDenied";
    case OvStorage_Status_PreconditionFailed: return "PreconditionFailed";
    case OvStorage_Status_Conflict: return "Conflict";
    case OvStorage_Status_DirectoryNotEmpty: return "DirectoryNotEmpty";
    case OvStorage_Status_Unsupported: return "Unsupported";
    case OvStorage_Status_InvalidArgument: return "InvalidArgument";
    case OvStorage_Status_ObjectModified: return "ObjectModified";
    case OvStorage_Status_NoRoute: return "NoRoute";
    case OvStorage_Status_Transient: return "Transient";
    case OvStorage_Status_Cancelled: return "Cancelled";
    case OvStorage_Status_IncompatibleType: return "IncompatibleType";
    case OvStorage_Status_ResourceExhausted: return "ResourceExhausted";
    case OvStorage_Status_PartialCompletion: return "PartialCompletion";
    case OvStorage_Status_PluginRejected: return "PluginRejected";
    case OvStorage_Status_Internal: return "Internal";
    }
    // An additive-ABI status this build predates; callers must treat it as
    // Internal-equivalent (see the OvStorage_Status prose in ovstorage.h).
    return "Unknown";
}

std::string describe(const ovstorage::Error& error)
{
    std::string out(status_name(error.code()));
    if (!error.message().empty()) {
        out += ": ";
        out += error.message();
    }
    return out;
}

std::string read_local(const std::string& path)
{
    std::ifstream file(path, std::ios::binary);
    return std::string(
        std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
}

// A payload whose bytes are position-dependent, so a truncated or reordered
// read fails on content rather than only on length.
std::string ramp(std::size_t len)
{
    std::string out;
    out.resize(len);
    for (std::size_t i = 0; i < len; ++i) {
        out[i] = static_cast<char>(i % 251);
    }
    return out;
}

// Assert inside a coroutine. Every scenario body is a coroutine, so a failed
// check cannot `return` — it `co_return`s the failure Outcome, which the
// caller relays verbatim into the caller-supplied `err` buffer.
#define OVSX_CHECK(condition, message)                                        \
    do {                                                                      \
        if (!(condition)) {                                                   \
            co_return ovstorage::Result<Outcome>::success(failed(message));   \
        }                                                                     \
    } while (false)

// `result` must be an lvalue (it is evaluated more than once).
#define OVSX_OK(result, what)                                                 \
    OVSX_CHECK((result).has_value(),                                          \
        std::string(what) + " failed: " + describe((result).error()))

#define OVSX_ERROR_IS(result, expected, what)                                 \
    OVSX_CHECK(!(result).has_value() && (result).error().code() == (expected), \
        std::string(what) + ": expected " + status_name(expected) + ", got "  \
            + ((result).has_value() ? std::string("Ok")                       \
                                    : describe((result).error())))

// ---------------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------------
//
// Each mirrors the assertions of the same-named `async fn` in
// `ovstorage-integration-tests/src/scenarios.rs`. Objects are written only
// under `ctx.prefix` (run-unique, minted by the Rust side) and deleted again
// on the way out; `tests/cpp.rs` sweeps the prefix afterwards as a net for a
// scenario that fails mid-flight.

ovstorage::task<Outcome> write_stat_read(
    const ovstorage::LayerHandle& layer, const Context& ctx)
{
    const std::string address = ctx.prefix + "obj.bin";
    const std::string payload = "hello-live-world";

    auto written = co_await layer.write(address, as_bytes(payload));
    OVSX_OK(written, "write");

    auto stated = co_await layer.stat(address);
    OVSX_OK(stated, "stat");
    OVSX_CHECK(stated.value().has_size() && stated.value().size() == payload.size(),
        "stat reports size: expected " + std::to_string(payload.size()));

    auto read = co_await layer.read_bytes(address);
    OVSX_OK(read, "read_bytes");
    OVSX_CHECK(bytes_to_string(read.value().first.span()) == payload,
        "round-trip bytes match");

    (void)co_await layer.delete_object(address);
    co_return ovstorage::Result<Outcome>::success(passed());
}

ovstorage::task<Outcome> delete_object(
    const ovstorage::LayerHandle& layer, const Context& ctx)
{
    const std::string address = ctx.prefix + "gone.bin";
    const std::string payload = "x";

    auto written = co_await layer.write(address, as_bytes(payload));
    OVSX_OK(written, "write");
    auto deleted = co_await layer.delete_object(address);
    OVSX_OK(deleted, "delete");
    auto stated = co_await layer.stat(address);
    OVSX_ERROR_IS(stated, OvStorage_Status_NotFound, "stat after delete");

    co_return ovstorage::Result<Outcome>::success(passed());
}

// Seed `a.txt`, `b.txt` and `sub/c.txt` under `ctx.prefix`; the two list
// scenarios share the fixture but each mints its own prefix.
ovstorage::task<Outcome> seed_list_children(
    const ovstorage::LayerHandle& layer, const Context& ctx)
{
    const std::string body = "data";
    for (const char* key : {"a.txt", "b.txt", "sub/c.txt"}) {
        auto written = co_await layer.write(ctx.prefix + key, as_bytes(body));
        OVSX_OK(written, std::string("write child ") + key);
    }
    co_return ovstorage::Result<Outcome>::success(passed());
}

ovstorage::task<void> delete_list_children(
    const ovstorage::LayerHandle& layer, const Context& ctx)
{
    for (const char* key : {"a.txt", "b.txt", "sub/c.txt"}) {
        (void)co_await layer.delete_object(ctx.prefix + key);
    }
    co_return ovstorage::Result<void>::success();
}

ovstorage::task<Outcome> list_prefix_delimiter(
    const ovstorage::LayerHandle& layer, const Context& ctx)
{
    if (!ctx.caps.raw().supports_list) {
        co_return ovstorage::Result<Outcome>::success(
            skipped("missing capability supports_list"));
    }
    auto seeded = co_await seed_list_children(layer, ctx);
    OVSX_OK(seeded, "seed");
    OVSX_CHECK(seeded.value().code == DRIVER_PASS, seeded.value().message);

    auto listed = co_await layer.list(ctx.prefix);
    OVSX_OK(listed, "list");

    bool saw_a = false;
    bool saw_b = false;
    bool saw_nested = false;
    bool saw_directory = false;
    for (std::size_t i = 0; i < listed.value().size(); ++i) {
        const std::string address = listed.value().address(i);
        const OvStorage_ObjectKind kind = listed.value().info(i).kind();
        if (kind == OvStorage_ObjectKind_File) {
            saw_a = saw_a || ends_with(address, "a.txt");
            saw_b = saw_b || ends_with(address, "b.txt");
            saw_nested = saw_nested || ends_with(address, "sub/c.txt");
        } else {
            saw_directory = true;
        }
    }
    (void)co_await delete_list_children(layer, ctx);

    OVSX_CHECK(saw_a && saw_b, "list returns the direct file children a.txt + b.txt");
    OVSX_CHECK(!saw_nested, "non-recursive list must not return nested files");
    OVSX_CHECK(saw_directory, "list folds sub/ into a directory entry");

    co_return ovstorage::Result<Outcome>::success(passed());
}

ovstorage::task<Outcome> list_recursive_and_pagination(
    const ovstorage::LayerHandle& layer, const Context& ctx)
{
    if (!ctx.caps.raw().supports_list) {
        co_return ovstorage::Result<Outcome>::success(
            skipped("missing capability supports_list"));
    }
    auto seeded = co_await seed_list_children(layer, ctx);
    OVSX_OK(seeded, "seed");
    OVSX_CHECK(seeded.value().code == DRIVER_PASS, seeded.value().message);

    // `max_results` / `page_token` pass straight through to the backend, so
    // this exercises REAL backend pagination on every cloud target.
    auto first = co_await layer.list(ctx.prefix, /*recursive=*/false,
        /*max_results=*/1, /*page_token=*/{}, /*full_metadata=*/true);
    OVSX_OK(first, "list page 1");
    OVSX_CHECK(first.value().size() == 1,
        "first page size: expected 1, got " + std::to_string(first.value().size()));
    const std::string token = first.value().next_page_token();
    OVSX_CHECK(!token.empty(), "first list page should have a continuation token");
    {
        const ovstorage::InfoView info = first.value().info(0);
        OVSX_CHECK(info.has_size() || info.kind() != OvStorage_ObjectKind_File,
            "full_metadata list returns file sizes");
    }

    auto second = co_await layer.list(ctx.prefix, /*recursive=*/false,
        /*max_results=*/10, token);
    OVSX_OK(second, "list page 2");
    OVSX_CHECK(second.value().size() >= 1,
        "second list page should contain remaining entries");

    auto recursive = co_await layer.list(ctx.prefix, /*recursive=*/true);
    OVSX_OK(recursive, "recursive list");
    bool saw_nested = false;
    for (std::size_t i = 0; i < recursive.value().size(); ++i) {
        saw_nested = saw_nested || ends_with(recursive.value().address(i), "sub/c.txt");
    }
    (void)co_await delete_list_children(layer, ctx);
    OVSX_CHECK(saw_nested, "recursive list includes the nested file sub/c.txt");

    co_return ovstorage::Result<Outcome>::success(passed());
}

ovstorage::task<Outcome> copy_object(
    const ovstorage::LayerHandle& layer, const Context& ctx)
{
    const std::string src = ctx.prefix + "src.bin";
    const std::string dst = ctx.prefix + "dst.bin";
    const std::string payload = "copy-me";

    auto written = co_await layer.write(src, as_bytes(payload));
    OVSX_OK(written, "write src");
    auto copied = co_await layer.copy(src, dst);
    OVSX_OK(copied, "copy");
    auto read = co_await layer.read_bytes(dst);
    OVSX_OK(read, "read dst");
    const bool preserved = bytes_to_string(read.value().first.span()) == payload;

    (void)co_await layer.delete_object(src);
    (void)co_await layer.delete_object(dst);
    OVSX_CHECK(preserved, "copy preserved bytes");

    co_return ovstorage::Result<Outcome>::success(passed());
}

ovstorage::task<Outcome> rename_object(
    const ovstorage::LayerHandle& layer, const Context& ctx)
{
    const std::string src = ctx.prefix + "from.bin";
    const std::string dst = ctx.prefix + "to.bin";
    const std::string payload = "move-me";

    auto written = co_await layer.write(src, as_bytes(payload));
    OVSX_OK(written, "write src");
    auto renamed = co_await layer.rename(src, dst);
    OVSX_OK(renamed, "rename");
    auto read = co_await layer.read_bytes(dst);
    OVSX_OK(read, "read dst");
    const bool preserved = bytes_to_string(read.value().first.span()) == payload;
    auto stated = co_await layer.stat(src);
    const bool source_gone = !stated.has_value()
        && stated.error().code() == OvStorage_Status_NotFound;

    (void)co_await layer.delete_object(dst);
    OVSX_CHECK(preserved, "rename preserved bytes");
    OVSX_CHECK(source_gone, "src gone after rename: expected NotFound");

    co_return ovstorage::Result<Outcome>::success(passed());
}

ovstorage::task<Outcome> update_metadata(
    const ovstorage::LayerHandle& layer, const Context& ctx)
{
    // The Rust scenario also accepts a backend that can only emulate the
    // patch by rewriting the object, because it can set
    // `UpdateMetadataOptions::allow_rewrite_emulation`. The C ABI's
    // `OvStorage_UpdateMetadataOptions` carries no such flag and the
    // dispatcher zero-initializes the plugin request, so the emulation path
    // is unreachable from C/C++ and only a native patch can run here.
    if (!ctx.caps.raw().supports_native_metadata_patch) {
        const char* why = ctx.caps.raw().supports_metadata_rewrite_emulation
            ? "backend advertises only supports_metadata_rewrite_emulation, and the C "
              "ABI's OvStorage_UpdateMetadataOptions has no allow_rewrite_emulation flag"
            : "missing capability supports_native_metadata_patch";
        co_return ovstorage::Result<Outcome>::success(skipped(why));
    }

    const std::string address = ctx.prefix + "meta.bin";
    auto written = co_await layer.write(address, as_bytes(std::string("with-metadata")));
    OVSX_OK(written, "write");

    // C# identifiers, not hyphenated keys: Azure rejects the latter.
    ovstorage::UpdateMetadataOptions set;
    auto set_value = set.set("ov_test_key", "ov_test_value");
    OVSX_OK(set_value, "UpdateMetadataOptions::set(ov_test_key)");
    auto set_doomed = set.set("ov_remove_key", "remove_me");
    OVSX_OK(set_doomed, "UpdateMetadataOptions::set(ov_remove_key)");
    auto applied = co_await layer.update_metadata(address, set);
    OVSX_OK(applied, "update_metadata");

    ovstorage::UpdateMetadataOptions remove;
    auto removal = remove.remove("ov_remove_key");
    OVSX_OK(removal, "UpdateMetadataOptions::remove(ov_remove_key)");
    auto removed = co_await layer.update_metadata(address, remove);
    OVSX_OK(removed, "update_metadata remove");

    auto stated = co_await layer.stat(address, /*full_metadata=*/true);
    OVSX_OK(stated, "stat full_metadata");
    bool echoed = false;
    bool removed_key_present = false;
    for (const auto& entry : stated.value().user_metadata()) {
        echoed = echoed
            || (entry.first == "ov_test_key" && entry.second == "ov_test_value");
        removed_key_present = removed_key_present || entry.first == "ov_remove_key";
    }

    (void)co_await layer.delete_object(address);
    OVSX_CHECK(echoed, "metadata key echoed back as ov_test_key=ov_test_value");
    OVSX_CHECK(!removed_key_present, "metadata removal should drop ov_remove_key");

    co_return ovstorage::Result<Outcome>::success(passed());
}

// The Rust leg drives this scenario through an attributing host, which reads
// the principal off the request extensions. The C ABI carries no request
// extensions, so this leg cannot present a principal and mirrors the portable
// half instead: the reserved attribution key `ovstorage_modified_by` is a
// metadata name every backend stores and reports under exactly that spelling,
// beside ordinary caller metadata.
ovstorage::task<Outcome> attribution_round_trip(
    const ovstorage::LayerHandle& layer, const Context& ctx)
{
    // Same narrowing as `update_metadata`: the C ABI's
    // `OvStorage_UpdateMetadataOptions` has no `allow_rewrite_emulation` flag,
    // so only a native metadata patch is reachable from C/C++.
    if (!ctx.caps.raw().supports_native_metadata_patch) {
        const char* why = ctx.caps.raw().supports_metadata_rewrite_emulation
            ? "backend advertises only supports_metadata_rewrite_emulation, and the C "
              "ABI's OvStorage_UpdateMetadataOptions has no allow_rewrite_emulation flag"
            : "missing capability supports_native_metadata_patch";
        co_return ovstorage::Result<Outcome>::success(skipped(why));
    }

    const std::string address = ctx.prefix + "attributed.bin";
    auto written = co_await layer.write(address, as_bytes(std::string("attributed")));
    OVSX_OK(written, "write");

    ovstorage::UpdateMetadataOptions set;
    auto set_stamp = set.set("ovstorage_modified_by", "alice@example.com");
    OVSX_OK(set_stamp, "UpdateMetadataOptions::set(ovstorage_modified_by)");
    auto set_author = set.set("author", "caller");
    OVSX_OK(set_author, "UpdateMetadataOptions::set(author)");
    auto applied = co_await layer.update_metadata(address, set);
    OVSX_OK(applied, "update_metadata");

    auto stated = co_await layer.stat(address, /*full_metadata=*/true);
    OVSX_OK(stated, "stat full_metadata");
    bool stamped = false;
    bool authored = false;
    for (const auto& entry : stated.value().user_metadata()) {
        stamped = stamped
            || (entry.first == "ovstorage_modified_by" && entry.second == "alice@example.com");
        authored = authored || (entry.first == "author" && entry.second == "caller");
    }

    (void)co_await layer.delete_object(address);
    OVSX_CHECK(stamped, "reserved key read back as ovstorage_modified_by=alice@example.com");
    OVSX_CHECK(authored, "caller metadata read back as author=caller");

    co_return ovstorage::Result<Outcome>::success(passed());
}

ovstorage::task<Outcome> check_access(
    const ovstorage::LayerHandle& layer, const Context& ctx)
{
    if (!ctx.caps.raw().supports_access_check) {
        co_return ovstorage::Result<Outcome>::success(
            skipped("missing capability supports_access_check"));
    }
    // The verdict is asserted, not merely its well-formedness: every
    // credential this suite configures is one the fixture grants read on, so
    // a deny here is a real regression rather than a legitimate policy answer.
    auto decision = co_await layer.check_access(ctx.root, /*read=*/true);
    OVSX_OK(decision, "check_access");
    OVSX_CHECK(decision.value().allowed() && !decision.value().denied_ops().read,
        "configured default target should allow read access: " + decision.value().reason());

    co_return ovstorage::Result<Outcome>::success(passed());
}

ovstorage::task<Outcome> error_path_not_found(
    const ovstorage::LayerHandle& layer, const Context& ctx)
{
    const std::string address = ctx.prefix + "missing.bin";
    auto stated = co_await layer.stat(address);
    OVSX_ERROR_IS(stated, OvStorage_Status_NotFound, "stat missing");
    auto read = co_await layer.read_bytes(address);
    OVSX_ERROR_IS(read, OvStorage_Status_NotFound, "read missing");

    co_return ovstorage::Result<Outcome>::success(passed());
}

ovstorage::task<Outcome> read_stream_and_materialize(
    const ovstorage::LayerHandle& layer, const Context& ctx)
{
    const std::string address = ctx.prefix + "stream-read.bin";
    const std::string payload = ramp(4096);

    auto written = co_await layer.write(address, as_bytes(payload));
    OVSX_OK(written, "write");

    // Bytes only. The Rust scenario also asserts the stream's `info.size`,
    // but `OvStorage_ReadStreamCallback` delivers `(chunk, error, done)` and
    // no `Info`, so the C++ wrapper has no size to hand back.
    auto streamed = co_await layer.read_stream(address);
    OVSX_OK(streamed, "read_stream");
    const bool stream_matches = bytes_to_string(std::span<const std::byte>(
        streamed.value().data(), streamed.value().size())) == payload;

    // On cloud targets this is served by the redirect follower's staged
    // temp-file fallback, with no byte cache composed.
    auto local = co_await layer.read_local_file(address);
    OVSX_OK(local, "read_local_file");
    const bool materialized_matches = read_local(local.value().path()) == payload;

    (void)co_await layer.delete_object(address);
    OVSX_CHECK(stream_matches, "read_stream bytes match");
    OVSX_CHECK(materialized_matches, "materialized bytes match");

    co_return ovstorage::Result<Outcome>::success(passed());
}

ovstorage::task<Outcome> conditional_write(
    const ovstorage::LayerHandle& layer, const Context& ctx)
{
    // This case runs only the create-only (no-overwrite) half of the Rust
    // scenario. TODO: rebuild the etag compare-and-set half against
    // `WriteOptions::if_match_etag`.
    if (!ctx.caps.raw().supports_no_overwrite_write) {
        const char* why = ctx.caps.raw().supports_if_match_write
            ? "backend advertises only supports_if_match_write, and this case's "
              "etag-CAS half is not yet rebuilt against WriteOptions::if_match_etag "
              "(issue #614)"
            : "missing capability supports_no_overwrite_write";
        co_return ovstorage::Result<Outcome>::success(skipped(why));
    }

    const std::string address = ctx.prefix + "cas.bin";
    auto seeded = co_await layer.write(address, as_bytes(std::string("v1")));
    OVSX_OK(seeded, "seed write");

    auto rejected = co_await layer.write(
        address, as_bytes(std::string("v2")), /*no_overwrite=*/true);
    // The file backend answers AlreadyExists; the cloud backends implement
    // no-overwrite as If-None-Match:* and surface the 412 as
    // PreconditionFailed. Both mean the guard rejected the write.
    const bool guarded = !rejected.has_value()
        && (rejected.error().code() == OvStorage_Status_AlreadyExists
            || rejected.error().code() == OvStorage_Status_PreconditionFailed);
    const std::string got = rejected.has_value()
        ? std::string("Ok") : describe(rejected.error());

    (void)co_await layer.delete_object(address);
    OVSX_CHECK(guarded,
        "create-only on existing key: expected AlreadyExists or "
        "PreconditionFailed, got " + got);

    co_return ovstorage::Result<Outcome>::success(passed());
}

// Shared by `directory_ops` (real directories: file, Azure HNS) and
// `directory_marker_ops` (flat stores whose directories are marker objects).
// The Rust side picks WHICH target each runs against, because
// `supports_create_directory` / `supports_delete_directory` are not carried by
// `OvStorage_Capabilities` and so cannot be gated on from here.
ovstorage::task<Outcome> directory_round_trip(
    const ovstorage::LayerHandle& layer, const Context& ctx)
{
    const std::string directory = ctx.prefix + "adir";

    auto created = co_await layer.create_directory(directory);
    OVSX_OK(created, "create_directory");

    auto stated = co_await layer.stat(directory + "/");
    OVSX_OK(stated, "stat directory");
    const OvStorage_ObjectKind kind = stated.value().kind();
    const bool classified = kind == OvStorage_ObjectKind_Directory
        || kind == OvStorage_ObjectKind_DirectoryMarker
        || kind == OvStorage_ObjectKind_DirectoryInferred;

    auto deleted = co_await layer.delete_directory(directory);
    OVSX_CHECK(classified,
        "directory must classify as a directory kind, got kind "
            + std::to_string(static_cast<int>(kind)));
    OVSX_OK(deleted, "delete_directory");

    co_return ovstorage::Result<Outcome>::success(passed());
}

ovstorage::task<Outcome> list_versions(
    const ovstorage::LayerHandle& layer, const Context& ctx)
{
    if (!ctx.caps.raw().supports_version_listing) {
        co_return ovstorage::Result<Outcome>::success(
            skipped("missing capability supports_version_listing"));
    }
    const std::string address = ctx.prefix + "versioned.bin";
    auto first = co_await layer.write(address, as_bytes(std::string("v1")));
    OVSX_OK(first, "write v1");
    auto second = co_await layer.write(address, as_bytes(std::string("v2")));
    OVSX_OK(second, "write v2");

    auto listed = co_await layer.list_versions(address);
    OVSX_OK(listed, "list_versions");

    std::set<std::string> versions;
    std::set<std::string> bodies;
    std::vector<std::string> pinned;
    for (std::size_t i = 0; i < listed.value().size(); ++i) {
        const std::string version = listed.value().info(i).version();
        if (version.empty()) {
            continue;
        }
        versions.insert(version);
        pinned.push_back(listed.value().address(i));
        auto body = co_await layer.read_bytes(pinned.back());
        OVSX_OK(body, "read pinned version " + pinned.back());
        bodies.insert(body.value().first.string());
    }

    // Delete only the version-pinned addresses. Deleting the unpinned base on
    // S3 would create a delete marker rather than remove history.
    for (const std::string& address_pin : pinned) {
        (void)co_await layer.delete_object(address_pin);
    }

    OVSX_CHECK(versions.size() >= 2,
        "a versioned target must retain >=2 distinct versions, got "
            + std::to_string(versions.size()));
    OVSX_CHECK(bodies.count("v1") == 1 && bodies.count("v2") == 1,
        "version list should expose readable v1 and v2 pins");

    co_return ovstorage::Result<Outcome>::success(passed());
}

// ---------------------------------------------------------------------------
// Read-only live fixtures
// ---------------------------------------------------------------------------
//
// The read family mirrors the same-named scenarios in scenarios.rs: gate on
// supports_list / !supports_write (both carried by OvStorage_Capabilities),
// discover an object from the fixture itself, pin follow-up operations to the
// version the listing reported where the backend supplies one, and assert
// self-consistency only — never names, counts, or hashes of the third-party
// fixture. The size bound is discovery-side only in this leg: read_bytes here
// carries no max_bytes cap, and pinned reads cannot grow past the listed size.

// Mirrors MAX_READ_OBJECT_BYTES / MAX_DISCOVERY_PAGES / ABSENT_REVISION in
// scenarios.rs.
constexpr std::uint64_t MAX_READ_OBJECT_BYTES = 4ull * 1024 * 1024;
constexpr int MAX_DISCOVERY_PAGES = 20;
// A syntactically valid version id no repository resolves (the all-zeros git
// object id), used to prove a revision pin is honored rather than ignored.
constexpr const char* ABSENT_REVISION = "0000000000000000000000000000000000000000";

// Recursively list from ctx.root and pick the smallest file whose size is in
// [min_size, MAX_READ_OBJECT_BYTES]; out_version carries the listing's version
// id ("" when the backend supplies none). The pick is the smallest such file
// within the first MAX_DISCOVERY_PAGES pages — an accepted truncation on a
// larger fixture. An unusable fixture is a FAILURE (the target connected and
// listed fine), not a skip.
ovstorage::task<Outcome> discover_smallest_object(
    const ovstorage::LayerHandle& layer, const Context& ctx,
    std::uint64_t min_size, std::string& out_address, std::uint64_t& out_size,
    std::string& out_version)
{
    bool found = false;
    bool truncated = false;
    std::string token;
    for (int page_index = 0; page_index < MAX_DISCOVERY_PAGES; ++page_index) {
        // max_results 0 = no page cap: a read-only backend may serve pages by
        // re-materializing the whole tree, so small pages multiply wire crawls.
        auto page = co_await layer.list(ctx.root, /*recursive=*/true,
            /*max_results=*/0, token, /*full_metadata=*/true);
        OVSX_OK(page, "recursive discovery list");
        for (std::size_t i = 0; i < page.value().size(); ++i) {
            const ovstorage::InfoView info = page.value().info(i);
            if (info.kind() != OvStorage_ObjectKind_File || !info.has_size()) {
                continue;
            }
            const std::uint64_t size = info.size();
            if (size < min_size || size > MAX_READ_OBJECT_BYTES) {
                continue;
            }
            if (!found || size < out_size) {
                found = true;
                out_address = page.value().address(i);
                out_size = size;
                out_version = info.version();
            }
        }
        token = page.value().next_page_token();
        truncated = !token.empty();
        if (token.empty()) {
            break;
        }
    }
    if (!found && truncated) {
        co_return ovstorage::Result<Outcome>::success(failed(
            "the fixture repo's first " + std::to_string(MAX_DISCOVERY_PAGES)
            + " listing pages hold no file between " + std::to_string(min_size)
            + " and " + std::to_string(MAX_READ_OBJECT_BYTES) + " bytes under "
            + ctx.root
            + "; a later page may - point the fixture (OVSTORAGE_HUGGINGFACE_REPO_ID) "
              "at a repo whose small files list early"));
    }
    OVSX_CHECK(found,
        "the fixture repo lists no file between " + std::to_string(min_size)
            + " and " + std::to_string(MAX_READ_OBJECT_BYTES) + " bytes under "
            + ctx.root
            + "; point the fixture (OVSTORAGE_HUGGINGFACE_REPO_ID) at a repo "
              "with at least one small file");
    co_return ovstorage::Result<Outcome>::success(passed());
}

// Pin `address` to `version` with the `revision` query key — the pin grammar
// of the hf:// scheme, the suite's one read-only address family. Only ever
// applied to a listed or read address, which carries no query of its own; if
// that invariant breaks, the malformed address fails the read loudly rather
// than pinning the wrong revision.
std::string revision_pinned(const std::string& address, const std::string& version)
{
    return address + "?revision=" + version;
}

// `address` pinned at the listing's version when the backend supplied one:
// list, stat, and read then observe one snapshot, so a fixture push between
// the calls cannot skew their agreement.
std::string listed_snapshot(const std::string& address, const std::string& version)
{
    return version.empty() ? address : revision_pinned(address, version);
}

ovstorage::task<Outcome> read_only_list_stat_read(
    const ovstorage::LayerHandle& layer, const Context& ctx)
{
    if (!ctx.caps.raw().supports_list) {
        co_return ovstorage::Result<Outcome>::success(
            skipped("missing capability supports_list"));
    }
    if (ctx.caps.raw().supports_write) {
        co_return ovstorage::Result<Outcome>::success(
            skipped("write-capable target; the write family covers it"));
    }

    std::string address;
    std::uint64_t listed_size = 0;
    std::string version;
    auto discovered =
        co_await discover_smallest_object(layer, ctx, 1, address, listed_size, version);
    OVSX_OK(discovered, "discovery");
    OVSX_CHECK(discovered.value().code == DRIVER_PASS, discovered.value().message);
    const std::string snapshot = listed_snapshot(address, version);

    auto stated = co_await layer.stat(snapshot);
    OVSX_OK(stated, "stat");
    OVSX_CHECK(stated.value().has_size() && stated.value().size() == listed_size,
        "stat size agrees with the listing: expected " + std::to_string(listed_size));

    auto read = co_await layer.read_bytes(snapshot);
    OVSX_OK(read, "read_bytes");
    OVSX_CHECK(read.value().first.span().size() == listed_size,
        "read length agrees with the listing: expected " + std::to_string(listed_size));

    co_return ovstorage::Result<Outcome>::success(passed());
}

ovstorage::task<Outcome> read_only_range_read(
    const ovstorage::LayerHandle& layer, const Context& ctx)
{
    if (!ctx.caps.raw().supports_list) {
        co_return ovstorage::Result<Outcome>::success(
            skipped("missing capability supports_list"));
    }
    if (ctx.caps.raw().supports_write) {
        co_return ovstorage::Result<Outcome>::success(
            skipped("write-capable target; the write family covers it"));
    }

    std::string address;
    std::uint64_t size = 0;
    std::string version;
    auto discovered = co_await discover_smallest_object(layer, ctx, 3, address, size, version);
    OVSX_OK(discovered, "discovery");
    OVSX_CHECK(discovered.value().code == DRIVER_PASS, discovered.value().message);
    const std::string snapshot = listed_snapshot(address, version);

    auto full = co_await layer.read_bytes(snapshot);
    OVSX_OK(full, "full read");
    const std::string full_bytes = full.value().first.string();
    OVSX_CHECK(full_bytes.size() >= 3, "discovery guarantees at least three bytes");

    // Strict interior for every len >= 3: excludes byte 0 and the last byte,
    // so the expected slice is provably shorter than the full body.
    const std::uint64_t start = 1;
    const std::uint64_t end_inclusive = full_bytes.size() - 2;
    ovstorage::ReadOptions options;
    options.range_start = start;
    options.range_end_inclusive = end_inclusive;
    auto ranged = co_await layer.read_bytes(snapshot, options);
    if (!ranged.has_value()
        && ranged.error().code() == OvStorage_Status_Unsupported) {
        co_return ovstorage::Result<Outcome>::success(
            skipped("backend does not support range reads"));
    }
    OVSX_OK(ranged, "ranged read");
    OVSX_CHECK(ranged.value().first.span().size() < full_bytes.size(),
        "a honored range returns strictly fewer bytes than the full body");
    OVSX_CHECK(ranged.value().first.string()
            == full_bytes.substr(start, end_inclusive - start + 1),
        "range equals the slice of the full read");

    co_return ovstorage::Result<Outcome>::success(passed());
}

ovstorage::task<Outcome> read_only_version_pinning(
    const ovstorage::LayerHandle& layer, const Context& ctx)
{
    if (!ctx.caps.raw().supports_list) {
        co_return ovstorage::Result<Outcome>::success(
            skipped("missing capability supports_list"));
    }
    if (!ctx.caps.raw().supports_version_listing) {
        co_return ovstorage::Result<Outcome>::success(
            skipped("missing capability supports_version_listing"));
    }
    if (ctx.caps.raw().supports_write) {
        co_return ovstorage::Result<Outcome>::success(
            skipped("write-capable target; the write family covers it"));
    }

    std::string address;
    std::uint64_t size = 0;
    std::string listed_version;
    auto discovered =
        co_await discover_smallest_object(layer, ctx, 1, address, size, listed_version);
    OVSX_OK(discovered, "discovery");
    OVSX_CHECK(discovered.value().code == DRIVER_PASS, discovered.value().message);

    auto unpinned = co_await layer.read_bytes(address);
    OVSX_OK(unpinned, "unpinned read");
    const std::string serving = unpinned.value().second.version();
    OVSX_CHECK(!serving.empty(), "an unpinned read reports its serving version");

    // Same snapshot by construction: the pin is the version the unpinned read
    // itself was served at.
    auto pinned = co_await layer.read_bytes(revision_pinned(address, serving));
    OVSX_OK(pinned, "pinned re-read");
    OVSX_CHECK(pinned.value().first.string() == unpinned.value().first.string(),
        "the pinned re-read returns the same bytes");

    // The pin must steer the read, not decorate it: a version id no repository
    // resolves has to answer NotFound, where an ignored pin would answer the
    // current body.
    auto absent = co_await layer.read_bytes(revision_pinned(address, ABSENT_REVISION));
    OVSX_ERROR_IS(absent, OvStorage_Status_NotFound,
        "read pinned at a version no repository resolves");

    auto latest = co_await layer.get_latest_version(address);
    OVSX_OK(latest, "get_latest_version");
    const std::string latest_version = latest.value().version();
    OVSX_CHECK(!latest_version.empty(),
        "get_latest_version returns a concrete version id");
    OVSX_CHECK(latest.value().address() == revision_pinned(address, latest_version),
        "get_latest_version pins the discovered address at exactly the version it "
        "reports, got " + latest.value().address());

    // Shape only: mutable refs can be rewritten between calls, so ids observed
    // above are not required to remain members of a listing taken afterwards.
    auto listed = co_await layer.list_versions(address);
    OVSX_OK(listed, "list_versions");
    OVSX_CHECK(listed.value().size() >= 1,
        "a readable object lists at least one version");
    for (std::size_t i = 0; i < listed.value().size(); ++i) {
        OVSX_CHECK(!listed.value().info(i).version().empty(),
            "every listed version carries an id");
    }

    co_return ovstorage::Result<Outcome>::success(passed());
}

// ---------------------------------------------------------------------------
// Scenarios the C++ API cannot express
// ---------------------------------------------------------------------------
//
// Re-derived against the CURRENT `ovstorage.h` / `ovstorage.hpp` rather than
// inherited from the pre-`Stack` driver: `range_read` is on this list and was
// not on that one. Each returns a stated reason so a green run can never be
// mistaken for full coverage.
const char* unreachable_reason(std::string_view scenario)
{
    if (scenario == "range_read") {
        // The wrapper carries the overload (read_only_range_read drives it);
        // this write-family case is not yet rebuilt to use it.
        return "the C++ range_read case is not yet rebuilt against ovstorage.hpp's ranged "
               "read_bytes(address, options) overload, which read_only_range_read drives "
               "(issue #614)";
    }
    if (scenario == "key_encoding") {
        // The scenario is about ADDRESS COMPOSITION, not about a literal
        // string: Rust asserts `address::join_relative` percent-encodes
        // reserved characters. Hand-concatenating a pre-encoded string here
        // would assert nothing about the API under test.
        return "no address-composition entry point on the C ABI (Rust's "
               "address::join_relative has no C/C++ equivalent), so there is no "
               "reserved-character encoding behavior to exercise";
    }
    if (scenario == "write_stream") {
        return "the C++ write_stream case is not yet rebuilt against ovstorage.hpp's "
               "write_stream entry point (issue #614)";
    }
    if (scenario == "get_latest_version") {
        return "the C++ get_latest_version case is not yet rebuilt against ovstorage.hpp's "
               "get_latest_version entry point, which read_only_version_pinning drives "
               "(issue #614)";
    }
    if (scenario == "message_annotation") {
        // The Rust scenario stashes a per-operation `message` through
        // `WriteOptions` and `UpdateMetadataOptions`. Neither
        // `OvStorage_WriteOptions` nor the opaque
        // `OvStorage_UpdateMetadataOptions` (create/destroy/set/remove)
        // carries one, so this leg has no way to ask a backend to record the
        // annotation at all.
        return "the C ABI carries no per-operation message: OvStorage_WriteOptions has no "
               "message field and OvStorage_UpdateMetadataOptions has only set/remove, so "
               "this leg cannot ask a backend to stash the annotation";
    }
    return nullptr;
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

// Read the target root's advertised capabilities back over the bridge.
// The handle exposes capabilities through the address-root discovery surface:
// `list_address_roots` -> the `RootInfo` whose root matches, followed by a copy
// of that borrowed entry's capabilities.
ovstorage::task<Outcome> capabilities_for(
    const ovstorage::LayerHandle& layer,
    const std::string& root,
    ovstorage::Capabilities& out)
{
    auto roots = co_await layer.list_address_roots();
    OVSX_OK(roots, "list_address_roots");

    const OvStorage_RootInfo* best = nullptr;
    std::size_t best_len = 0;
    std::string seen;
    for (std::size_t i = 0; i < roots.value().size(); ++i) {
        const OvStorage_RootInfo* item = roots.value().item_at(i);
        if (item == nullptr) {
            continue;
        }
        const char* raw = item->root;
        if (raw == nullptr) {
            continue;
        }
        const std::string candidate(raw);
        if (!seen.empty()) {
            seen += ", ";
        }
        seen += candidate;
        // Exact match wins; otherwise the longest published root that
        // prefixes ours (an alias route can publish a shorter root than the
        // connection's own).
        if (candidate == root) {
            best = item;
            best_len = candidate.size();
            break;
        }
        if (root.compare(0, candidate.size(), candidate) == 0 && candidate.size() > best_len) {
            best = item;
            best_len = candidate.size();
        }
    }
    OVSX_CHECK(best != nullptr,
        "no published address root covers " + root + "; list_address_roots reported: " + seen);
    *out.raw() = best->capabilities;

    co_return ovstorage::Result<Outcome>::success(passed());
}

ovstorage::task<Outcome> run_scenario(
    const ovstorage::LayerHandle& layer,
    std::string scenario,
    std::string root,
    std::string prefix)
{
    if (const char* why = unreachable_reason(scenario)) {
        co_return ovstorage::Result<Outcome>::success(skipped(why));
    }

    Context ctx;
    ctx.root = std::move(root);
    ctx.prefix = std::move(prefix);
    auto resolved = co_await capabilities_for(layer, ctx.root, ctx.caps);
    OVSX_OK(resolved, "capabilities lookup");
    OVSX_CHECK(resolved.value().code == DRIVER_PASS, resolved.value().message);

    if (scenario == "write_stat_read") co_return co_await write_stat_read(layer, ctx);
    if (scenario == "delete") co_return co_await delete_object(layer, ctx);
    if (scenario == "list_prefix_delimiter") co_return co_await list_prefix_delimiter(layer, ctx);
    if (scenario == "list_recursive_and_pagination") {
        co_return co_await list_recursive_and_pagination(layer, ctx);
    }
    if (scenario == "copy") co_return co_await copy_object(layer, ctx);
    if (scenario == "rename") co_return co_await rename_object(layer, ctx);
    if (scenario == "update_metadata") co_return co_await update_metadata(layer, ctx);
    if (scenario == "attribution_round_trip") {
        co_return co_await attribution_round_trip(layer, ctx);
    }
    if (scenario == "check_access") co_return co_await check_access(layer, ctx);
    if (scenario == "error_path_not_found") co_return co_await error_path_not_found(layer, ctx);
    if (scenario == "read_stream_and_materialize") {
        co_return co_await read_stream_and_materialize(layer, ctx);
    }
    if (scenario == "conditional_write") co_return co_await conditional_write(layer, ctx);
    if (scenario == "directory_ops" || scenario == "directory_marker_ops") {
        co_return co_await directory_round_trip(layer, ctx);
    }
    if (scenario == "list_versions") co_return co_await list_versions(layer, ctx);
    if (scenario == "read_only_list_stat_read") {
        co_return co_await read_only_list_stat_read(layer, ctx);
    }
    if (scenario == "read_only_range_read") {
        co_return co_await read_only_range_read(layer, ctx);
    }
    if (scenario == "read_only_version_pinning") {
        co_return co_await read_only_version_pinning(layer, ctx);
    }

    // Not a skip: an unknown name means the shared scenario contract grew and
    // this driver was not updated, which must be loud rather than absent.
    co_return ovstorage::Result<Outcome>::success(
        failed("unknown scenario " + scenario + "; the C++ driver has no case for it"));
}

void write_message(char* err, std::size_t err_len, const std::string& message)
{
    if (err == nullptr || err_len == 0) {
        return;
    }
    const std::size_t len = std::min(message.size(), err_len - 1);
    std::memcpy(err, message.data(), len);
    err[len] = '\0';
}

} // namespace

// Run one scenario against a Stack handed over from Rust.
//
// `handle` is consumed: `ovstorage_import_handle` takes ownership on success,
// and on the two pre-handshake rejections (null state/vtable, undersized
// vtable) it leaves an undroppable handle with the caller — see the ownership
// prose on `ovstorage_import_handle` in `ovstorage.h`.
//
// `root_url` is the target's advertised address root (`azure://acct/container/`,
// `file:///tmp/.../`); `prefix` is a run-unique key prefix beneath it that the
// scenario must confine every object it creates to, so the Rust side can sweep
// what a failed scenario left behind. Both must be NUL-terminated UTF-8.
//
// Returns 0 on pass, 77 on a visible skip, and any other value on failure;
// `err` receives a human-readable message for the latter two (empty on pass).
extern "C" int ovsx_cloud_driver_run(
    OvStoragePlugin_LayerHandle handle,
    const char* scenario,
    const char* root_url,
    const char* prefix,
    char* err,
    std::size_t err_len)
{
    write_message(err, err_len, "");
    try {
        // Import BEFORE screening the string arguments. The handle carries an
        // owned producer-side reference, and the only thing that releases it
        // is the imported `LayerHandle`'s destructor; returning early with the
        // handle still in hand would strand that reference.
        auto imported = ovstorage::LayerHandle::import_handle(handle);
        if (!imported.has_value()) {
            write_message(err, err_len,
                "ovstorage_import_handle failed: " + describe(imported.error()));
            return DRIVER_FAIL;
        }
        // Destroyed at the end of this scope — on THIS thread, after
        // `sync_wait` has returned. Destroying a LayerHandle from inside a
        // coroutine awaiting one of its own tasks is documented UB.
        ovstorage::LayerHandle layer = std::move(imported).value();

        if (scenario == nullptr || root_url == nullptr || prefix == nullptr) {
            write_message(err, err_len, "scenario, root_url and prefix must all be non-NULL");
            return DRIVER_FAIL;
        }

        auto result = ovstorage::sync_wait(
            run_scenario(layer, scenario, root_url, prefix));
        if (!result.has_value()) {
            write_message(err, err_len, "driver task failed: " + describe(result.error()));
            return DRIVER_FAIL;
        }
        write_message(err, err_len, result.value().message);
        return result.value().code;
    } catch (const std::exception& e) {
        // An exception must not unwind through the C boundary into Rust.
        write_message(err, err_len, std::string("C++ exception: ") + e.what());
        return DRIVER_FAIL;
    } catch (...) {
        write_message(err, err_len, "unknown C++ exception");
        return DRIVER_FAIL;
    }
}
