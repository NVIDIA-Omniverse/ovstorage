// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef OVSTORAGE_HPP
#define OVSTORAGE_HPP

/*
 * Async-only C++20 wrapper around the ovstorage C ABI.
 *
 * Requires a C++20 toolchain with working coroutine support: GCC 13+,
 * Clang 17+, or MSVC 19.40+. Both shipped example build files probe the
 * compiler by compiling this header and fail with that message rather
 * than emitting template errors from inside it.
 *
 * Application surface (RFC-0066 layered model): build a `Stack`
 * incrementally and finalize it into a `LayerHandle` that the object-I/O
 * ops dispatch on.
 *
 *   1. `Registry` — seeded with the built-in Layer factories; extend it
 *      with `add_plugin(Plugin)` for plugin-provided kinds.
 *   2. `Plugin` — a loaded cdylib's factories. `Plugin::load(path)` keeps
 *      the cdylib mapped; `Plugin::inspect(path)` enumerates the kinds it
 *      advertises without composing them into a Stack.
 *   3. `Stack` — the mutable builder: declare named Layer instances of a
 *      `kind` resolved through a `Registry` (`add_layer`), name the root
 *      (`set_root`), wire wrapper/router edges (`set_inner` /
 *      `set_children`), attach connections (`add_connection`), then
 *      `build()` to get a `LayerHandle`. `build()` consumes the `Stack`.
 *   4. `LayerHandle` — the built, immutable root. Every long-running
 *      method returns `task<T>`, a C++20 coroutine type that carries an
 *      `ovstorage::Result<T>`. Trampolines hand a `std::coroutine_handle`
 *      to the C callback via `user_data` and resume the coroutine from
 *      the runtime worker thread when the callback fires.
 *
 * Top-level (non-coroutine) callers use `sync_wait(task<T>)` to drive
 * a task to completion on the calling thread.
 *
 * The async runtime is process-global and lazily built once on the first
 * `Stack::build`.
 *
 * Cancellation: `CancelToken` is a RAII wrapper around the C cancel
 * token. The same token can be passed to several in-flight operations
 * for group-cancel.
 *
 * Callback threading: the C ABI does NOT promise that `on_complete`
 * fires off the calling thread. The object/data verbs queue onto a
 * runtime worker, but `ovstorage_stack_build_async` fires every
 * prologue rejection inline on the caller (documented in
 * `ovstorage.h`), the connection/auth verbs invoke the root Layer's
 * slot on the calling thread — so a Layer that answers synchronously
 * completes inline — and every verb reports an allocation or
 * handle-closing failure inline. Each awaiter therefore tolerates both
 * orderings with a single atomic exchange (`state` in
 * `detail::awaiter_base`): `deliver` publishes 1 and `commit_suspend`
 * publishes 2, and whichever loses the exchange drives the resume.
 * `commit_suspend` returning false means the callback already ran, so
 * the body resumes inline instead of suspending.
 *
 * String-input guard: every string crosses the C ABI as a `const char*`
 * and must be valid UTF-8, so a value carrying an embedded NUL would
 * arrive truncated and one carrying non-UTF-8 bytes would be rejected by
 * the C ABI after the wrapper had already handed over any owned handle
 * alongside it. Every entry point screens both and fails with
 * `InvalidArgument` instead — see `detail::invalid_c_input`, the one
 * place the rule lives.
 *
 * Null-handle guard: each method short-circuits to a failed Result if
 * the underlying `OvStorage_LayerHandle*` is null (moved-from
 * LayerHandle). The C ABI itself fires a supplied callback inline with
 * `InvalidArgument` for null handles, but the wrapper intercepts before
 * entering the C ABI so coroutine callers get the normal failed-Result
 * shape.
 *
 * Thread-safety caveat: do NOT destroy a `LayerHandle` inside the body
 * of a coroutine that is awaiting one of its tasks. Run the destructor
 * on the application thread (i.e., after `sync_wait` has returned).
 */

#include "ovstorage.h"

#include <cassert>
#include <atomic>
#include <condition_variable>
#include <coroutine>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <initializer_list>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace ovstorage {

// ---------------------------------------------------------------------------
// Error / Result
// ---------------------------------------------------------------------------

class Error {
public:
    Error() = default;

    Error(OvStorage_Status code, std::string message)
        : code_(code)
        , message_(std::move(message))
    {
    }

    explicit Error(const OvStorage_Error& error)
        : code_(error.code)
        , message_(error.message == nullptr ? "" : error.message)
    {
    }

    OvStorage_Status code() const noexcept { return code_; }
    const std::string& message() const noexcept { return message_; }

private:
    OvStorage_Status code_ = OvStorage_Status_Ok;
    std::string message_;
};

template <class T>
class Result {
public:
    static Result success(T value) { return Result(std::move(value)); }
    static Result failure(Error error) { return Result(std::move(error)); }

    explicit operator bool() const noexcept { return ok_; }
    bool has_value() const noexcept { return ok_; }
    T& value() & { return value_; }
    const T& value() const& { return value_; }
    T&& value() && { return std::move(value_); }
    const Error& error() const& { return error_; }

private:
    explicit Result(T value)
        : ok_(true)
        , value_(std::move(value))
    {
    }

    explicit Result(Error error)
        : ok_(false)
        , error_(std::move(error))
    {
    }

    bool ok_ = false;
    T value_{};
    Error error_{};
};

template <>
class Result<void> {
public:
    static Result success() { return Result(true, Error{}); }
    static Result failure(Error error) { return Result(false, std::move(error)); }

    explicit operator bool() const noexcept { return ok_; }
    bool has_value() const noexcept { return ok_; }
    const Error& error() const& { return error_; }

private:
    Result(bool ok, Error error)
        : ok_(ok)
        , error_(std::move(error))
    {
    }

    bool ok_ = false;
    Error error_{};
};

inline Error take_error(OvStorage_Error& error)
{
    Error out(error);
    ovstorage_error_clear(&error);
    return out;
}

// ---------------------------------------------------------------------------
// String inputs crossing the C ABI
// ---------------------------------------------------------------------------
//
// Two properties every string must have before it can cross.
//
// No embedded NUL: it crosses as a `const char*`, and a C string ends at
// its first NUL, so a value carrying one would arrive truncated — a
// different address, a different config key.
//
// Valid UTF-8: the C ABI validates it (`ovc_dispatch_address_valid`) and
// rejects anything else. `std::string` is a byte string and happily holds
// bytes that are not UTF-8, so this is ordinary caller input, not an
// exotic case.
//
// Screening both here rather than letting the C ABI do it is what keeps
// the ownership rules simple. Several verbs hand an owned handle — a
// connection request, a credential bundle — to the C ABI, which consumes
// it only once its prologue has passed. A rejection inside that prologue
// arrives as an ordinary failed Result, indistinguishable from a
// layer-side error that DID consume the handle, so the wrapper cannot
// safely reclaim it. Rejecting before the call means those prologue
// checks cannot fire for any reason a caller controls.
//
// This is the single chokepoint: every entry point that reaches `c_str()`
// routes its string inputs through `invalid_c_input` first, and none
// tests for either property itself.

namespace detail {

/// Reject anything a strict UTF-8 decoder would: overlong encodings,
/// surrogate halves, scalar values above U+10FFFF, truncated sequences,
/// and stray continuation bytes.
inline bool valid_utf8(std::string_view value) noexcept
{
    const auto* bytes = reinterpret_cast<const unsigned char*>(value.data());
    const std::size_t size = value.size();
    for (std::size_t i = 0; i < size;) {
        const unsigned char lead = bytes[i];
        std::size_t length = 0;
        std::uint32_t code_point = 0;
        if (lead < 0x80) {
            i += 1;
            continue;
        } else if ((lead & 0xE0) == 0xC0) {
            length = 2;
            code_point = lead & 0x1Fu;
        } else if ((lead & 0xF0) == 0xE0) {
            length = 3;
            code_point = lead & 0x0Fu;
        } else if ((lead & 0xF8) == 0xF0) {
            length = 4;
            code_point = lead & 0x07u;
        } else {
            return false;  // continuation byte or 5+ byte lead
        }
        if (size - i < length) {
            return false;  // truncated sequence
        }
        for (std::size_t k = 1; k < length; ++k) {
            const unsigned char continuation = bytes[i + k];
            if ((continuation & 0xC0) != 0x80) {
                return false;
            }
            code_point = (code_point << 6) | (continuation & 0x3Fu);
        }
        // Shortest-form, surrogate and range checks.
        if (length == 2 && code_point < 0x80) return false;
        if (length == 3 && code_point < 0x800) return false;
        if (length == 4 && code_point < 0x10000) return false;
        if (code_point > 0x10FFFF) return false;
        if (code_point >= 0xD800 && code_point <= 0xDFFF) return false;
        i += length;
    }
    return true;
}

/// The first input that cannot cross the boundary, and why. Falsey when
/// every input is fine.
struct input_defect {
    const char* name = nullptr;
    bool not_utf8 = false;

    explicit operator bool() const noexcept { return name != nullptr; }
};

inline input_defect invalid_c_input(
    std::initializer_list<std::pair<const char*, std::string_view>> inputs) noexcept
{
    for (const auto& input : inputs) {
        if (input.second.find('\0') != std::string_view::npos) {
            return input_defect{input.first, false};
        }
        if (!valid_utf8(input.second)) {
            return input_defect{input.first, true};
        }
    }
    return input_defect{};
}

inline Error invalid_c_input_error(input_defect defect)
{
    return Error(
        OvStorage_Status_InvalidArgument,
        std::string(defect.name)
            + (defect.not_utf8
                   ? " is not valid UTF-8, which the C ABI requires"
                   : " contains an embedded NUL, which cannot cross the C ABI's"
                     " char* boundary"));
}

template <class T>
Result<T> invalid_c_input_result(input_defect defect)
{
    return Result<T>::failure(invalid_c_input_error(defect));
}

} // namespace detail

// ---------------------------------------------------------------------------
// RAII wrappers around C result handles
// ---------------------------------------------------------------------------

class Info;

class InfoView {
public:
    InfoView() = default;
    explicit InfoView(const OvStorage_Info* handle) : handle_(handle) {}

    const OvStorage_Info* get() const noexcept { return handle_; }
    std::string address() const { return string_or_empty(handle_ == nullptr ? nullptr : handle_->address); }
    OvStorage_ObjectKind kind() const noexcept
    {
        return handle_ == nullptr ? OvStorage_ObjectKind_File : handle_->kind;
    }
    bool has_size() const noexcept { return handle_ != nullptr && handle_->has_size; }
    std::uint64_t size() const noexcept
    {
        return handle_ == nullptr || !handle_->has_size ? 0 : handle_->size;
    }
    std::string etag() const
    {
        return string_or_empty(handle_ == nullptr ? nullptr : handle_->etag);
    }
    std::string version() const
    {
        return string_or_empty(handle_ == nullptr ? nullptr : handle_->version);
    }
    bool has_mtime_unix_nanos() const noexcept
    {
        return handle_ != nullptr && handle_->has_mtime_unix_nanos;
    }
    std::uint64_t mtime_unix_nanos() const noexcept
    {
        return handle_ == nullptr || !handle_->has_mtime_unix_nanos
            ? 0
            : handle_->mtime_unix_nanos;
    }

    std::vector<std::pair<std::string, std::string>> user_metadata() const
    {
        return metadata(
            handle_ == nullptr ? nullptr : handle_->user_metadata,
            handle_ == nullptr ? 0 : handle_->user_metadata_len);
    }

    /// Backend-owned metadata, distinct from `user_metadata`.
    std::vector<std::pair<std::string, std::string>> system_metadata() const
    {
        return metadata(
            handle_ == nullptr ? nullptr : handle_->system_metadata,
            handle_ == nullptr ? 0 : handle_->system_metadata_len);
    }

    /// The principal the backend says last modified the object;
    /// `std::nullopt` when the backend does not report one. Distinguished
    /// from an empty string, which is a backend that named nobody.
    std::optional<std::string> modified_by() const
    {
        if (handle_ == nullptr || handle_->modified_by == nullptr) {
            return std::nullopt;
        }
        return std::string(handle_->modified_by);
    }

    /// The caller's permissions on this object, reported only by backends
    /// whose `populates_effective_permissions_on_stat` capability is true.
    /// `std::nullopt` is "not reported", which is not "nothing permitted".
    std::optional<OvStorage_AccessOps> effective_permissions() const noexcept
    {
        if (handle_ == nullptr || !handle_->has_effective_permissions) {
            return std::nullopt;
        }
        return handle_->effective_permissions;
    }

    /// Checksums the backend reported, as `(algorithm, raw digest)`. The
    /// digest is raw bytes, not a hex or base64 rendering. An empty vector
    /// means this answer carries none, not that the object has none.
    std::vector<std::pair<std::string, std::vector<std::uint8_t>>>
    checksums() const
    {
        std::vector<std::pair<std::string, std::vector<std::uint8_t>>> out;
        if (handle_ == nullptr || handle_->checksums == nullptr) {
            return out;
        }
        out.reserve(handle_->checksums_len);
        for (std::size_t i = 0; i < handle_->checksums_len; ++i) {
            const auto& entry = handle_->checksums[i];
            out.emplace_back(
                string_or_empty(entry.algorithm),
                std::vector<std::uint8_t>(
                    entry.bytes, entry.bytes + entry.bytes_len));
        }
        return out;
    }

    /// Deep-copy this borrowed view into an independently owned snapshot.
    Info clone() const;

private:
    static std::string string_or_empty(const char* value)
    {
        return value == nullptr ? std::string{} : std::string(value);
    }

    static std::vector<std::pair<std::string, std::string>> metadata(
        const OvStorage_MetadataEntry* entries,
        std::size_t len)
    {
        std::vector<std::pair<std::string, std::string>> out;
        if (entries == nullptr) {
            return out;
        }
        out.reserve(len);
        for (std::size_t i = 0; i < len; ++i) {
            out.emplace_back(
                string_or_empty(entries[i].key),
                string_or_empty(entries[i].value));
        }
        return out;
    }

    const OvStorage_Info* handle_ = nullptr;
};

class Info {
public:
    Info() = default;
    explicit Info(OvStorage_Info* handle) : handle_(handle) {}

    ~Info() { reset(); }
    Info(const Info&) = delete;
    Info& operator=(const Info&) = delete;

    Info(Info&& other) noexcept : handle_(std::exchange(other.handle_, nullptr)) {}
    Info& operator=(Info&& other) noexcept
    {
        if (this != &other) {
            reset();
            handle_ = std::exchange(other.handle_, nullptr);
        }
        return *this;
    }

    const OvStorage_Info* get() const noexcept { return handle_; }

    InfoView view() const noexcept { return InfoView(handle_); }
    std::string address() const { return view().address(); }
    OvStorage_ObjectKind kind() const noexcept { return view().kind(); }
    bool has_size() const noexcept { return view().has_size(); }
    std::uint64_t size() const noexcept { return view().size(); }
    std::string etag() const { return view().etag(); }
    std::string version() const { return view().version(); }
    bool has_mtime_unix_nanos() const noexcept { return view().has_mtime_unix_nanos(); }
    std::uint64_t mtime_unix_nanos() const noexcept { return view().mtime_unix_nanos(); }
    std::vector<std::pair<std::string, std::string>> user_metadata() const
    {
        return view().user_metadata();
    }
    std::vector<std::pair<std::string, std::string>> system_metadata() const
    {
        return view().system_metadata();
    }
    std::optional<std::string> modified_by() const { return view().modified_by(); }
    std::optional<OvStorage_AccessOps> effective_permissions() const noexcept
    {
        return view().effective_permissions();
    }
    std::vector<std::pair<std::string, std::vector<std::uint8_t>>>
    checksums() const
    {
        return view().checksums();
    }

private:
    void reset()
    {
        if (handle_ != nullptr) {
            ovstorage_info_destroy(handle_);
            handle_ = nullptr;
        }
    }

    OvStorage_Info* handle_ = nullptr;
};

inline Info InfoView::clone() const
{
    return Info(ovstorage_info_clone(handle_));
}

class Bytes {
public:
    Bytes() = default;
    explicit Bytes(OvStorage_Bytes bytes) : bytes_(bytes) {}

    ~Bytes() { ovstorage_bytes_destroy(&bytes_); }
    Bytes(const Bytes&) = delete;
    Bytes& operator=(const Bytes&) = delete;

    Bytes(Bytes&& other) noexcept : bytes_(std::exchange(other.bytes_, OvStorage_Bytes{})) {}
    Bytes& operator=(Bytes&& other) noexcept
    {
        if (this != &other) {
            ovstorage_bytes_destroy(&bytes_);
            bytes_ = std::exchange(other.bytes_, OvStorage_Bytes{});
        }
        return *this;
    }

    std::span<const std::byte> span() const noexcept
    {
        return {reinterpret_cast<const std::byte*>(bytes_.data), bytes_.len};
    }

    std::string string() const
    {
        return std::string(reinterpret_cast<const char*>(bytes_.data), bytes_.len);
    }

private:
    OvStorage_Bytes bytes_{};
};

/// Move-only owner for a C pull-stream producer. `next` and `drop` are called
/// from C frames and must not throw. Passing the stream to
/// `LayerHandle::write_stream` transfers it exactly once; an input rejection
/// drops it in this wrapper.
class WriteStream {
public:
    WriteStream() = default;
    WriteStream(
        void* state,
        OvStorage_WriteStreamNext next,
        OvStorage_WriteStreamDrop drop) noexcept
        : stream_{state, next, drop}
    {
    }

    ~WriteStream() { reset(); }
    WriteStream(const WriteStream&) = delete;
    WriteStream& operator=(const WriteStream&) = delete;
    WriteStream(WriteStream&& other) noexcept
        : stream_(std::exchange(other.stream_, OvStorage_WriteStream{}))
    {
    }
    WriteStream& operator=(WriteStream&& other) noexcept
    {
        if (this != &other) {
            reset();
            stream_ = std::exchange(other.stream_, OvStorage_WriteStream{});
        }
        return *this;
    }

    bool valid() const noexcept
    {
        return stream_.next != nullptr && stream_.drop != nullptr;
    }

    OvStorage_WriteStream release() noexcept
    {
        return std::exchange(stream_, OvStorage_WriteStream{});
    }

private:
    void reset() noexcept
    {
        if (stream_.drop != nullptr) {
            stream_.drop(stream_.state);
        }
        stream_ = OvStorage_WriteStream{};
    }

    OvStorage_WriteStream stream_{};
};

/// Move-only direct-upload plan. Every view returned by this object remains
/// valid only until it is moved or destroyed. Before executing a redirect,
/// apply the freshness, URL-scope, operation, credential-header, and body-range
/// checks documented on `OvStorage_WriteRedirect`.
class WriteRedirectBatch {
public:
    WriteRedirectBatch() = default;
    explicit WriteRedirectBatch(OvStorage_WriteRedirectBatch* handle)
        : handle_(handle)
    {
    }

    ~WriteRedirectBatch() { reset(); }
    WriteRedirectBatch(const WriteRedirectBatch&) = delete;
    WriteRedirectBatch& operator=(const WriteRedirectBatch&) = delete;
    WriteRedirectBatch(WriteRedirectBatch&& other) noexcept
        : handle_(std::exchange(other.handle_, nullptr))
    {
    }
    WriteRedirectBatch& operator=(WriteRedirectBatch&& other) noexcept
    {
        if (this != &other) {
            reset();
            handle_ = std::exchange(other.handle_, nullptr);
        }
        return *this;
    }

    const OvStorage_WriteRedirectBatch* get() const noexcept { return handle_; }
    std::span<const std::byte> continuation() const noexcept
    {
        if (handle_ == nullptr || handle_->continuation == nullptr) {
            return {};
        }
        return {
            reinterpret_cast<const std::byte*>(handle_->continuation),
            handle_->continuation_len};
    }
    std::size_t size() const noexcept
    {
        return handle_ == nullptr ? 0 : handle_->redirects_len;
    }
    const OvStorage_WriteRedirect* at(std::size_t index) const noexcept
    {
        return handle_ == nullptr || index >= handle_->redirects_len
            ? nullptr
            : &handle_->redirects[index];
    }

private:
    void reset() noexcept
    {
        if (handle_ != nullptr) {
            ovstorage_write_redirect_batch_destroy(handle_);
            handle_ = nullptr;
        }
    }

    OvStorage_WriteRedirectBatch* handle_ = nullptr;
};

/// One captured HTTP response supplied to `LayerHandle::continue_write`.
struct RedirectResult {
    std::uint16_t status_code = 0;
    std::vector<std::pair<std::string, std::string>> captured_headers;
    std::vector<std::uint8_t> captured_body;
};

struct ReadOptions {
    std::optional<std::uint64_t> range_start;
    std::optional<std::uint64_t> range_end_inclusive;
};

/// Options shared by `LayerHandle::write`, `write_stream` and
/// `write_redirect`.
///
/// `no_overwrite` and `if_match_etag` are the two spellings of a
/// destination precondition and are mutually exclusive: `no_overwrite`
/// means "fail if anything is there", `if_match_etag` means "fail unless
/// what is there is exactly this". Setting both is refused with
/// `InvalidArgument` rather than given a precedence, since either
/// precedence silently ignores half of what the caller asked for.
///
/// The etag is a precondition, never a key — it is compared against
/// whatever is at the address and does not name the object. Pass
/// `std::nullopt` for no precondition; an empty string is refused rather
/// than read as "no precondition", so propagating an absent
/// `Info::etag()` as `""` is an error instead of an unconditional
/// overwrite.
///
/// `size_hint` is honored by `write_stream` and `write_redirect`. `write`
/// knows the length of the buffer it was handed and uses that, so a hint
/// there is ignored.
struct WriteOptions {
    bool no_overwrite = false;
    std::optional<std::string> if_match_etag;
    std::optional<std::uint64_t> size_hint;
};

/// One continuation turn: either final object metadata (`is_done()`) or a new
/// redirect batch to execute and feed back into `continue_write`.
class WriteStep {
public:
    static WriteStep done(Info info)
    {
        WriteStep step;
        step.done_ = true;
        step.info_ = std::move(info);
        return step;
    }

    static WriteStep redirects(WriteRedirectBatch batch)
    {
        WriteStep step;
        step.redirects_ = std::move(batch);
        return step;
    }

    bool is_done() const noexcept { return done_; }
    const Info& info() const noexcept { return info_; }
    const WriteRedirectBatch& redirects() const noexcept { return redirects_; }
    Info take_info() noexcept { return std::move(info_); }
    WriteRedirectBatch take_redirects() noexcept
    {
        return std::move(redirects_);
    }

private:
    bool done_ = false;
    Info info_;
    WriteRedirectBatch redirects_;
};

struct WatchDirectoryOptions {
    bool recursive = false;
    bool include_metadata_changes = true;
    std::vector<std::uint8_t> since;
    /// Resume from `since` even when it is empty.
    ///
    /// A backend may mint a zero-length cursor, and emptiness alone cannot
    /// tell that apart from having no cursor at all — so without this a
    /// caller handed one replays the entire change history instead of
    /// resuming. A non-empty `since` resumes whether or not this is set,
    /// which is the same rule the C struct's `has_since` follows, so the
    /// two hosts agree by construction.
    bool has_since = false;
    std::uint64_t poll_interval_ms = 0;
};

class BackendChangeEvent {
public:
    explicit BackendChangeEvent(const OvStorage_BackendChangeEvent& event)
        : kind_(event.kind)
        , address_(event.address == nullptr ? "" : event.address)
        , change_kind_(event.change_kind)
        , etag_(event.etag == nullptr ? "" : event.etag)
        , version_(event.version == nullptr ? "" : event.version)
        , has_size_(event.has_size)
        , size_(event.size)
        , has_mtime_unix_nanos_(event.has_mtime_unix_nanos)
        , mtime_unix_nanos_(event.mtime_unix_nanos)
        , at_unix_nanos_(event.at_unix_nanos)
        , has_since_unix_nanos_(event.has_since_unix_nanos)
        , since_unix_nanos_(event.since_unix_nanos)
    {
        if (event.cursor != nullptr && event.cursor_len != 0) {
            cursor_.assign(event.cursor, event.cursor + event.cursor_len);
        }
    }

    OvStorage_BackendChangeEventKind kind() const noexcept { return kind_; }
    const std::string& address() const noexcept { return address_; }
    OvStorage_ChangeKind change_kind() const noexcept { return change_kind_; }
    const std::string& etag() const noexcept { return etag_; }
    const std::string& version() const noexcept { return version_; }
    bool has_size() const noexcept { return has_size_; }
    std::uint64_t size() const noexcept { return size_; }
    bool has_mtime_unix_nanos() const noexcept
    {
        return has_mtime_unix_nanos_;
    }
    std::uint64_t mtime_unix_nanos() const noexcept
    {
        return mtime_unix_nanos_;
    }
    std::uint64_t at_unix_nanos() const noexcept { return at_unix_nanos_; }
    bool has_since_unix_nanos() const noexcept
    {
        return has_since_unix_nanos_;
    }
    std::uint64_t since_unix_nanos() const noexcept
    {
        return since_unix_nanos_;
    }
    std::span<const std::uint8_t> cursor() const noexcept { return cursor_; }

private:
    OvStorage_BackendChangeEventKind kind_ =
        OvStorage_BackendChangeEventKind_Lapsed;
    std::string address_;
    OvStorage_ChangeKind change_kind_ = OvStorage_ChangeKind_Modified;
    std::string etag_;
    std::string version_;
    bool has_size_ = false;
    std::uint64_t size_ = 0;
    bool has_mtime_unix_nanos_ = false;
    std::uint64_t mtime_unix_nanos_ = 0;
    std::uint64_t at_unix_nanos_ = 0;
    bool has_since_unix_nanos_ = false;
    std::uint64_t since_unix_nanos_ = 0;
    std::vector<std::uint8_t> cursor_;
};

class LocalDelegate {
public:
    LocalDelegate() = default;
    explicit LocalDelegate(OvStorage_LocalDelegate* handle) : handle_(handle) {}

    ~LocalDelegate() { reset(); }
    LocalDelegate(const LocalDelegate&) = delete;
    LocalDelegate& operator=(const LocalDelegate&) = delete;

    LocalDelegate(LocalDelegate&& other) noexcept
        : handle_(std::exchange(other.handle_, nullptr))
    {
    }
    LocalDelegate& operator=(LocalDelegate&& other) noexcept
    {
        if (this != &other) {
            reset();
            handle_ = std::exchange(other.handle_, nullptr);
        }
        return *this;
    }

    std::string path() const
    {
        const char* p = ovstorage_local_delegate_path(handle_);
        return p == nullptr ? std::string{} : std::string(p);
    }

private:
    void reset()
    {
        if (handle_ != nullptr) {
            ovstorage_local_delegate_destroy(handle_);
            handle_ = nullptr;
        }
    }

    OvStorage_LocalDelegate* handle_ = nullptr;
};

class AccessDecision {
public:
    AccessDecision() = default;
    explicit AccessDecision(OvStorage_AccessDecision decision) : decision_(decision) {}

    ~AccessDecision() { ovstorage_access_decision_clear(&decision_); }
    AccessDecision(const AccessDecision&) = delete;
    AccessDecision& operator=(const AccessDecision&) = delete;

    AccessDecision(AccessDecision&& other) noexcept
        : decision_(std::exchange(other.decision_, OvStorage_AccessDecision{}))
    {
    }
    AccessDecision& operator=(AccessDecision&& other) noexcept
    {
        if (this != &other) {
            ovstorage_access_decision_clear(&decision_);
            decision_ = std::exchange(other.decision_, OvStorage_AccessDecision{});
        }
        return *this;
    }

    bool allowed() const noexcept { return decision_.allowed; }
    OvStorage_AccessOps denied_ops() const noexcept { return decision_.denied_ops; }
    std::string reason() const
    {
        return decision_.reason == nullptr ? std::string{} : std::string(decision_.reason);
    }

private:
    OvStorage_AccessDecision decision_{};
};

class List {
public:
    List() = default;
    explicit List(OvStorage_List* handle) : handle_(handle) {}

    ~List() { reset(); }
    List(const List&) = delete;
    List& operator=(const List&) = delete;

    List(List&& other) noexcept : handle_(std::exchange(other.handle_, nullptr)) {}
    List& operator=(List&& other) noexcept
    {
        if (this != &other) {
            reset();
            handle_ = std::exchange(other.handle_, nullptr);
        }
        return *this;
    }

    std::size_t size() const noexcept { return handle_ == nullptr ? 0 : handle_->len; }

    std::string next_page_token() const
    {
        const char* token = handle_ == nullptr ? nullptr : handle_->next_page_token;
        return token == nullptr ? std::string{} : std::string(token);
    }

    std::string address(std::size_t index) const
    {
        const char* value =
            handle_ == nullptr || handle_->items == nullptr ||
                    index >= handle_->len
            ? nullptr
            : handle_->items[index].address;
        return value == nullptr ? std::string{} : std::string(value);
    }

    InfoView info(std::size_t index) const noexcept
    {
        return InfoView(
            handle_ == nullptr || handle_->items == nullptr ||
                    index >= handle_->len
                ? nullptr
                : &handle_->items[index]);
    }

private:
    void reset()
    {
        if (handle_ != nullptr) {
            ovstorage_list_destroy(handle_);
            handle_ = nullptr;
        }
    }

    OvStorage_List* handle_ = nullptr;
};

class VersionList {
public:
    VersionList() = default;
    explicit VersionList(OvStorage_VersionList* handle) : handle_(handle) {}

    ~VersionList() { reset(); }
    VersionList(const VersionList&) = delete;
    VersionList& operator=(const VersionList&) = delete;

    VersionList(VersionList&& other) noexcept : handle_(std::exchange(other.handle_, nullptr)) {}
    VersionList& operator=(VersionList&& other) noexcept
    {
        if (this != &other) {
            reset();
            handle_ = std::exchange(other.handle_, nullptr);
        }
        return *this;
    }

    std::size_t size() const noexcept { return handle_ == nullptr ? 0 : handle_->len; }

    std::string next_page_token() const
    {
        const char* token = handle_ == nullptr ? nullptr : handle_->next_page_token;
        return token == nullptr ? std::string{} : std::string(token);
    }

    std::string address(std::size_t index) const
    {
        const char* value =
            handle_ == nullptr || handle_->items == nullptr ||
                    index >= handle_->len
            ? nullptr
            : handle_->items[index].address;
        return value == nullptr ? std::string{} : std::string(value);
    }

    InfoView info(std::size_t index) const noexcept
    {
        return InfoView(
            handle_ == nullptr || handle_->items == nullptr ||
                    index >= handle_->len
                ? nullptr
                : &handle_->items[index]);
    }

private:
    void reset()
    {
        if (handle_ != nullptr) {
            ovstorage_version_list_destroy(handle_);
            handle_ = nullptr;
        }
    }

    OvStorage_VersionList* handle_ = nullptr;
};

class UpdateMetadataOptions {
public:
    UpdateMetadataOptions() : handle_(ovstorage_update_metadata_options_create()) {}

    ~UpdateMetadataOptions()
    {
        if (handle_ != nullptr) {
            ovstorage_update_metadata_options_destroy(handle_);
        }
    }

    UpdateMetadataOptions(const UpdateMetadataOptions&) = delete;
    UpdateMetadataOptions& operator=(const UpdateMetadataOptions&) = delete;

    UpdateMetadataOptions(UpdateMetadataOptions&& other) noexcept
        : handle_(std::exchange(other.handle_, nullptr))
    {
    }

    Result<void> set(std::string_view key, std::string_view value)
    {
        if (auto bad = detail::invalid_c_input({{"key", key}, {"value", value}})) {
            return detail::invalid_c_input_result<void>(bad);
        }
        std::string key_string(key);
        std::string value_string(value);
        OvStorage_Error error{};
        auto status = ovstorage_update_metadata_options_set(
            handle_, key_string.c_str(), value_string.c_str(), &error);
        if (status != OvStorage_Status_Ok) {
            return Result<void>::failure(take_error(error));
        }
        return Result<void>::success();
    }

    Result<void> remove(std::string_view key)
    {
        if (auto bad = detail::invalid_c_input({{"key", key}})) {
            return detail::invalid_c_input_result<void>(bad);
        }
        std::string key_string(key);
        OvStorage_Error error{};
        auto status =
            ovstorage_update_metadata_options_remove(handle_, key_string.c_str(), &error);
        if (status != OvStorage_Status_Ok) {
            return Result<void>::failure(take_error(error));
        }
        return Result<void>::success();
    }

    const OvStorage_UpdateMetadataOptions* get() const noexcept { return handle_; }

private:
    OvStorage_UpdateMetadataOptions* handle_ = nullptr;
};

struct ConnectionAttributePatch {
    std::optional<std::string> display_name;
    std::optional<std::string> access_mode;
    std::optional<bool> visible;
    const UpdateMetadataOptions* user_metadata = nullptr;
};

// ---------------------------------------------------------------------------
// Connection / auth / discovery surface
// ---------------------------------------------------------------------------
//
// Builder types (`ConfigValue`, `SecretValue`, `SecretBundle`,
// `ConnectionRequest`) wrap the opaque C builder handles. Their
// `release()` method extracts the raw `*mut` and transfers ownership to
// the consumer (the C ABI's `_add_connection` /
// `_update_connection_credentials` / `stack_add_connection` thunks).
// After `release()`, the C++ wrapper does not own the handle and its
// destructor is a no-op.
//
// Read-side types (`Connection`, `ConnectionList`, `AuthEvent`,
// `RootInfo`, `RootInfoList`, `KindDescriptorList`) are RAII over their
// `_destroy` C functions. List items (`ConnectionList`, `RootInfoList`)
// are borrowed from the list — `item_at` returns a NON-owning pointer;
// only the list destructor frees them. Variant-specific accessors return
// `std::optional<T>` or empty strings for the wrong variant (matches the
// C-side null/0 semantics).
//
// `Capabilities` is a thin value wrapper over the flat
// `OvStorage_Capabilities` struct. Default-constructs with all fields
// zeroed.

class Capabilities {
public:
    /// Every field zeroed, which is also the honest default: each `bool` is
    /// a claim a backend has to make, and the two optional fields read as
    /// absent. Nothing is seeded — a seeded `version_list_order` alongside a
    /// false `has_version_list_order` would assert an ordering no backend
    /// claimed, and an accessor cannot tell that apart from a real answer.
    Capabilities() noexcept { std::memset(&caps_, 0, sizeof(caps_)); }

    OvStorage_Capabilities* raw() noexcept { return &caps_; }
    const OvStorage_Capabilities& raw() const noexcept { return caps_; }

    // Write preconditions and mechanics.
    bool supports_if_match_write() const noexcept { return caps_.supports_if_match_write; }
    bool supports_no_overwrite_write() const noexcept { return caps_.supports_no_overwrite_write; }
    bool writes_are_atomic() const noexcept { return caps_.writes_are_atomic; }

    // Verb availability. Each answers "can this verb be attempted", not
    // "will it succeed for this object".
    bool supports_write() const noexcept { return caps_.supports_write; }
    bool supports_write_stream() const noexcept { return caps_.supports_write_stream; }
    bool supports_write_redirect() const noexcept { return caps_.supports_write_redirect; }
    bool supports_delete() const noexcept { return caps_.supports_delete; }
    bool supports_copy() const noexcept { return caps_.supports_copy; }
    bool supports_rename() const noexcept { return caps_.supports_rename; }
    bool supports_list() const noexcept { return caps_.supports_list; }
    bool supports_create_directory() const noexcept { return caps_.supports_create_directory; }
    bool supports_delete_directory() const noexcept { return caps_.supports_delete_directory; }
    bool supports_access_check() const noexcept { return caps_.supports_access_check; }
    bool supports_watch_directory() const noexcept { return caps_.supports_watch_directory; }
    bool supports_version_listing() const noexcept { return caps_.supports_version_listing; }

    // Mechanism, as distinct from availability: `supports_copy` says a copy
    // can be attempted, these say whether it stays on the server.
    bool supports_server_side_copy() const noexcept { return caps_.supports_server_side_copy; }
    bool supports_server_side_rename() const noexcept { return caps_.supports_server_side_rename; }
    bool supports_atomic_rename() const noexcept { return caps_.supports_atomic_rename; }

    // Metadata and listing behaviour.
    bool supports_native_metadata_patch() const noexcept { return caps_.supports_native_metadata_patch; }
    bool supports_metadata_rewrite_emulation() const noexcept { return caps_.supports_metadata_rewrite_emulation; }
    bool has_real_directories() const noexcept { return caps_.has_real_directories; }
    bool wants_list_backed_stat() const noexcept { return caps_.wants_list_backed_stat; }
    bool supports_recursive_list() const noexcept { return caps_.supports_recursive_list; }
    bool populates_subdirectory_metadata() const noexcept { return caps_.populates_subdirectory_metadata; }
    bool populates_effective_permissions_on_stat() const noexcept
    {
        return caps_.populates_effective_permissions_on_stat;
    }

    bool watch_directory_resumable() const noexcept { return caps_.watch_directory_resumable; }
    const OvStorage_ChangeKindSet& watch_directory_kinds() const noexcept
    {
        return caps_.watch_directory_kinds;
    }

    std::optional<OvStorage_VersionListOrder> version_list_order() const noexcept
    {
        return caps_.has_version_list_order
            ? std::optional<OvStorage_VersionListOrder>(caps_.version_list_order)
            : std::nullopt;
    }

    std::optional<std::uint64_t> watch_directory_max_lag_nanos() const noexcept
    {
        return caps_.has_watch_directory_max_lag
            ? std::optional<std::uint64_t>(caps_.watch_directory_max_lag_nanos)
            : std::nullopt;
    }

    std::optional<std::uint64_t> redirect_size_threshold() const noexcept
    {
        return caps_.has_redirect_size_threshold
            ? std::optional<std::uint64_t>(caps_.redirect_size_threshold)
            : std::nullopt;
    }

private:
    OvStorage_Capabilities caps_{};
};

// ---------------------------------------------------------------------------
// ConfigValue / SecretValue / SecretBundle / ConnectionRequest builders
// ---------------------------------------------------------------------------

class ConfigValue {
public:
    /// A value carrying an embedded NUL yields a null ConfigValue
    /// (`raw() == nullptr`), the same failure shape as an allocation failure.
    static ConfigValue string_(std::string s)
    {
        if (detail::invalid_c_input({{"value", s}})) {
            return ConfigValue(nullptr);
        }
        auto* h = ovstorage_config_value_create_string(s.c_str());
        return ConfigValue(h);
    }
    static ConfigValue int_(std::int64_t v)
    {
        return ConfigValue(ovstorage_config_value_create_int(v));
    }
    static ConfigValue bool_(bool v)
    {
        return ConfigValue(ovstorage_config_value_create_bool(v));
    }
    static ConfigValue toml(std::string toml)
    {
        if (detail::invalid_c_input({{"toml", toml}})) {
            return ConfigValue(nullptr);
        }
        return ConfigValue(ovstorage_config_value_create_toml(toml.c_str()));
    }

    ~ConfigValue() { reset(); }
    ConfigValue(const ConfigValue&) = delete;
    ConfigValue& operator=(const ConfigValue&) = delete;
    ConfigValue(ConfigValue&& other) noexcept
        : handle_(std::exchange(other.handle_, nullptr))
    {
    }
    ConfigValue& operator=(ConfigValue&& other) noexcept
    {
        if (this != &other) {
            reset();
            handle_ = std::exchange(other.handle_, nullptr);
        }
        return *this;
    }

    /// Transfer ownership to a consumer (e.g.
    /// `connection_request_add_config`). Caller is responsible for the
    /// returned pointer afterward.
    OvStorage_ConfigValue* release() noexcept
    {
        return std::exchange(handle_, nullptr);
    }

    OvStorage_ConfigValue* raw() const noexcept { return handle_; }

    /// Wrap a raw handle. Takes ownership.
    explicit ConfigValue(OvStorage_ConfigValue* handle) : handle_(handle) {}

private:
    void reset()
    {
        if (handle_ != nullptr) {
            ovstorage_config_value_destroy(handle_);
            handle_ = nullptr;
        }
    }
    OvStorage_ConfigValue* handle_ = nullptr;
};

class SecretValue {
public:
    static SecretValue bytes(const std::uint8_t* data, std::size_t len)
    {
        return SecretValue(ovstorage_secret_value_create_bytes(data, len));
    }
    static SecretValue file(const std::uint8_t* data, std::size_t len)
    {
        return SecretValue(ovstorage_secret_value_create_file(data, len));
    }
    static SecretValue oauth_token(
        const std::uint8_t* token, std::size_t token_len,
        const std::uint8_t* refresh = nullptr, std::size_t refresh_len = 0,
        std::optional<std::uint64_t> expires_at_unix_nanos = std::nullopt)
    {
        bool has_refresh = refresh != nullptr;
        bool has_expires_at = expires_at_unix_nanos.has_value();
        std::uint64_t expires_at = expires_at_unix_nanos.value_or(0);
        return SecretValue(ovstorage_secret_value_create_oauth_token(
            token, token_len,
            refresh, refresh_len, has_refresh,
            expires_at, has_expires_at));
    }
    static SecretValue mtls_cert_pair(
        const std::uint8_t* cert_pem, std::size_t cert_len,
        const std::uint8_t* key_pem, std::size_t key_len)
    {
        return SecretValue(ovstorage_secret_value_create_mtls_cert_pair(
            cert_pem, cert_len, key_pem, key_len));
    }
    static SecretValue system_identity()
    {
        return SecretValue(ovstorage_secret_value_create_system_identity());
    }

    ~SecretValue() { reset(); }
    SecretValue(const SecretValue&) = delete;
    SecretValue& operator=(const SecretValue&) = delete;
    SecretValue(SecretValue&& other) noexcept
        : handle_(std::exchange(other.handle_, nullptr))
    {
    }
    SecretValue& operator=(SecretValue&& other) noexcept
    {
        if (this != &other) {
            reset();
            handle_ = std::exchange(other.handle_, nullptr);
        }
        return *this;
    }

    OvStorage_SecretValue* release() noexcept
    {
        return std::exchange(handle_, nullptr);
    }
    OvStorage_SecretValue* raw() const noexcept { return handle_; }

    /// Wrap a raw handle. Takes ownership.
    explicit SecretValue(OvStorage_SecretValue* handle) : handle_(handle) {}

private:
    void reset()
    {
        if (handle_ != nullptr) {
            ovstorage_secret_value_destroy(handle_);
            handle_ = nullptr;
        }
    }
    OvStorage_SecretValue* handle_ = nullptr;
};

class SecretBundle {
public:
    SecretBundle() : handle_(ovstorage_secret_bundle_create()) {}
    ~SecretBundle() { reset(); }
    SecretBundle(const SecretBundle&) = delete;
    SecretBundle& operator=(const SecretBundle&) = delete;
    SecretBundle(SecretBundle&& other) noexcept
        : handle_(std::exchange(other.handle_, nullptr))
    {
    }
    SecretBundle& operator=(SecretBundle&& other) noexcept
    {
        if (this != &other) {
            reset();
            handle_ = std::exchange(other.handle_, nullptr);
        }
        return *this;
    }

    /// Returns true on success. On failure, `value` is NOT consumed
    /// and remains owned by the caller.
    bool add(std::string_view key, SecretValue&& value)
    {
        if (detail::invalid_c_input({{"key", key}})) {
            return false;
        }
        std::string key_string(key);
        OvStorage_SecretValue* raw = value.release();
        bool ok = ovstorage_secret_bundle_add(handle_, key_string.c_str(), raw);
        if (!ok && raw != nullptr) {
            // Recover ownership so it gets destroyed normally.
            value = SecretValue(raw);
        }
        return ok;
    }

    OvStorage_SecretBundle* release() noexcept
    {
        return std::exchange(handle_, nullptr);
    }

    OvStorage_SecretBundle* raw() const noexcept { return handle_; }

private:
    void reset()
    {
        if (handle_ != nullptr) {
            ovstorage_secret_bundle_destroy(handle_);
            handle_ = nullptr;
        }
    }
    OvStorage_SecretBundle* handle_ = nullptr;
};

class ConnectionRequest {
public:
    /// A `backend_kind` carrying an embedded NUL leaves the request null,
    /// so every subsequent `add_config` / `add_credential` returns false and
    /// the consuming call rejects it.
    explicit ConnectionRequest(std::string backend_kind)
        : handle_(
              detail::invalid_c_input({{"backend_kind", backend_kind}})
                  ? nullptr
                  : ovstorage_connection_request_create(backend_kind.c_str()))
    {
    }
    ~ConnectionRequest() { reset(); }
    ConnectionRequest(const ConnectionRequest&) = delete;
    ConnectionRequest& operator=(const ConnectionRequest&) = delete;
    ConnectionRequest(ConnectionRequest&& other) noexcept
        : handle_(std::exchange(other.handle_, nullptr))
    {
    }
    ConnectionRequest& operator=(ConnectionRequest&& other) noexcept
    {
        if (this != &other) {
            reset();
            handle_ = std::exchange(other.handle_, nullptr);
        }
        return *this;
    }

    /// A display name carrying an embedded NUL leaves the previous value in
    /// place: the setter has no failure channel, and a truncated label is
    /// worse than an unchanged one.
    void set_display_name(std::string display_name)
    {
        if (detail::invalid_c_input({{"display_name", display_name}})) {
            return;
        }
        ovstorage_connection_request_set_display_name(handle_, display_name.c_str());
    }
    void clear_display_name()
    {
        ovstorage_connection_request_set_display_name(handle_, nullptr);
    }
    void set_persist(bool persist)
    {
        ovstorage_connection_request_set_persist(handle_, persist);
    }
    bool add_config(std::string_view key, ConfigValue&& value)
    {
        if (detail::invalid_c_input({{"key", key}})) {
            return false;
        }
        std::string key_string(key);
        OvStorage_ConfigValue* raw = value.release();
        bool ok = ovstorage_connection_request_add_config(handle_, key_string.c_str(), raw);
        if (!ok && raw != nullptr) {
            value = ConfigValue(raw);
        }
        return ok;
    }
    bool add_credential(std::string_view key, SecretValue&& value)
    {
        if (detail::invalid_c_input({{"key", key}})) {
            return false;
        }
        std::string key_string(key);
        OvStorage_SecretValue* raw = value.release();
        bool ok = ovstorage_connection_request_add_credential(handle_, key_string.c_str(), raw);
        if (!ok && raw != nullptr) {
            value = SecretValue(raw);
        }
        return ok;
    }

    /// Transfer ownership of the underlying builder to the consuming call
    /// (`Stack::add_connection` / `LayerHandle::add_connection`). After
    /// `release()`, this wrapper's destructor is a no-op; the consuming C
    /// function NULLs the slot it is passed through exactly when it takes
    /// the builder, so the raw pointer is only still live if it declined.
    OvStorage_ConnectionRequest* release() noexcept
    {
        return std::exchange(handle_, nullptr);
    }

    OvStorage_ConnectionRequest* raw() const noexcept { return handle_; }

    /// Adopt a raw builder. Used to recover ownership from a consuming call
    /// that the C ABI documents as NOT having consumed it.
    explicit ConnectionRequest(OvStorage_ConnectionRequest* handle) noexcept
        : handle_(handle)
    {
    }

private:
    void reset()
    {
        if (handle_ != nullptr) {
            ovstorage_connection_request_destroy(handle_);
            handle_ = nullptr;
        }
    }
    OvStorage_ConnectionRequest* handle_ = nullptr;
};

// ---------------------------------------------------------------------------
// Connection / ConnectionList (read-side)
// ---------------------------------------------------------------------------

class Connection {
public:
    Connection() = default;
    explicit Connection(OvStorage_Connection* handle) : handle_(handle) {}
    ~Connection() { reset(); }
    Connection(const Connection&) = delete;
    Connection& operator=(const Connection&) = delete;
    Connection(Connection&& other) noexcept
        : handle_(std::exchange(other.handle_, nullptr))
    {
    }
    Connection& operator=(Connection&& other) noexcept
    {
        if (this != &other) {
            reset();
            handle_ = std::exchange(other.handle_, nullptr);
        }
        return *this;
    }

    const OvStorage_Connection* get() const noexcept { return handle_; }

    std::string id() const { return cstring(handle_ == nullptr ? nullptr : handle_->id); }
    std::string backend_kind() const
    {
        return cstring(handle_ == nullptr ? nullptr : handle_->backend_kind);
    }
    std::string display_name() const
    {
        return cstring(handle_ == nullptr ? nullptr : handle_->display_name);
    }
    OvStorage_ConnectionSourceKind source_kind() const noexcept
    {
        return handle_ == nullptr
            ? OvStorage_ConnectionSourceKind_Runtime
            : handle_->source_kind;
    }
    OvStorage_ConnectionAuthStateKind auth_state_kind() const noexcept
    {
        return handle_ == nullptr
            ? OvStorage_ConnectionAuthStateKind_Anonymous
            : handle_->auth_state_kind;
    }
    Capabilities capabilities() const
    {
        Capabilities caps;
        if (handle_ != nullptr) {
            *caps.raw() = handle_->capabilities;
        }
        return caps;
    }
    std::size_t address_count() const noexcept
    {
        return handle_ == nullptr ? 0 : handle_->addresses_len;
    }
    std::string address(std::size_t i) const
    {
        return cstring(
            handle_ == nullptr || handle_->addresses == nullptr ||
                    i >= handle_->addresses_len
                ? nullptr
                : handle_->addresses[i]);
    }

    // Auth-state payloads. Each returns a value only for the variant
    // `auth_state_kind()` names; the C snapshot may leave an inactive
    // variant's fields populated, so these gate on the kind rather than on
    // the field being non-zero.

    /// `AuthFailed`: the coarse status behind the failure. A permanent
    /// rejection reads `PermissionDenied` and a broker outage reads
    /// `Transient`, which is the distinction that decides whether retrying
    /// can help.
    std::optional<OvStorage_Status> auth_failed_code() const noexcept
    {
        if (!is_auth_failed()) return std::nullopt;
        return handle_->auth_failed_code;
    }
    /// `AuthFailed`: the fine-grained plugin error-code name behind
    /// `auth_failed_code()`, for one `"CredentialExpired"` where the status
    /// only says `PermissionDenied`.
    std::optional<std::string> auth_failed_code_name() const
    {
        if (!is_auth_failed() || handle_->auth_failed_code_name == nullptr) {
            return std::nullopt;
        }
        return std::string(handle_->auth_failed_code_name);
    }
    std::optional<std::uint32_t> auth_failed_attempts() const noexcept
    {
        if (!is_auth_failed()) return std::nullopt;
        return handle_->auth_failed_attempts;
    }
    std::optional<std::string> auth_failed_message() const
    {
        if (!is_auth_failed() || handle_->auth_failed_message == nullptr) {
            return std::nullopt;
        }
        return std::string(handle_->auth_failed_message);
    }

    /// `Authenticated`: when the connection last authenticated.
    std::optional<std::uint64_t> authenticated_at_unix_nanos() const noexcept
    {
        if (!is_authenticated() || !handle_->has_authenticated_at) {
            return std::nullopt;
        }
        return handle_->authenticated_at_unix_nanos;
    }
    /// `Authenticated`: when the current credential expires, when the
    /// backend reports one. This is what lets a caller refresh before an
    /// operation fails rather than after.
    std::optional<std::uint64_t> authenticated_expires_at_unix_nanos() const noexcept
    {
        if (!is_authenticated() || !handle_->has_authenticated_expires_at) {
            return std::nullopt;
        }
        return handle_->authenticated_expires_at_unix_nanos;
    }

    /// `AwaitingAuth`: why authentication is pending. The remedies differ
    /// per variant, so a caller that collapses them to "needs auth" prompts
    /// a user who cannot fix anything.
    std::optional<OvStorage_AuthReason> awaiting_auth_reason() const noexcept
    {
        if (!is_awaiting_auth()) return std::nullopt;
        return handle_->awaiting_auth_reason;
    }
    /// `AwaitingAuth`: free-form detail, present only for
    /// `OvStorage_AuthReason_Unknown`.
    std::optional<std::string> awaiting_auth_unknown_details() const
    {
        if (!is_awaiting_auth() ||
            handle_->awaiting_auth_unknown_details == nullptr) {
            return std::nullopt;
        }
        return std::string(handle_->awaiting_auth_unknown_details);
    }

private:
    bool is_auth_failed() const noexcept
    {
        return handle_ != nullptr &&
            handle_->auth_state_kind ==
                OvStorage_ConnectionAuthStateKind_AuthFailed;
    }
    bool is_authenticated() const noexcept
    {
        return handle_ != nullptr &&
            handle_->auth_state_kind ==
                OvStorage_ConnectionAuthStateKind_Authenticated;
    }
    bool is_awaiting_auth() const noexcept
    {
        return handle_ != nullptr &&
            handle_->auth_state_kind ==
                OvStorage_ConnectionAuthStateKind_AwaitingAuth;
    }

    static std::string cstring(const char* p)
    {
        return p == nullptr ? std::string{} : std::string(p);
    }
    void reset()
    {
        if (handle_ != nullptr) {
            ovstorage_connection_destroy(handle_);
            handle_ = nullptr;
        }
    }
    OvStorage_Connection* handle_ = nullptr;
};

class ConnectionList {
public:
    ConnectionList() = default;
    explicit ConnectionList(OvStorage_ConnectionList* handle) : handle_(handle) {}
    ~ConnectionList() { reset(); }
    ConnectionList(const ConnectionList&) = delete;
    ConnectionList& operator=(const ConnectionList&) = delete;
    ConnectionList(ConnectionList&& other) noexcept
        : handle_(std::exchange(other.handle_, nullptr))
    {
    }
    ConnectionList& operator=(ConnectionList&& other) noexcept
    {
        if (this != &other) {
            reset();
            handle_ = std::exchange(other.handle_, nullptr);
        }
        return *this;
    }

    std::size_t size() const noexcept { return handle_ == nullptr ? 0 : handle_->len; }
    /// Returns a borrowed pointer to the i-th connection. Lifetime is
    /// tied to the list handle — do NOT delete or destroy it.
    const OvStorage_Connection* item_at(std::size_t i) const noexcept
    {
        return handle_ == nullptr || handle_->items == nullptr ||
                i >= handle_->len
            ? nullptr
            : &handle_->items[i];
    }

private:
    void reset()
    {
        if (handle_ != nullptr) {
            ovstorage_connection_list_destroy(handle_);
            handle_ = nullptr;
        }
    }
    OvStorage_ConnectionList* handle_ = nullptr;
};

// ---------------------------------------------------------------------------
// AuthEvent (single-event handle for streaming authenticate_connection)
// ---------------------------------------------------------------------------

class AuthEvent {
public:
    AuthEvent() = default;
    explicit AuthEvent(OvStorage_AuthEvent* handle) : handle_(handle) {}
    ~AuthEvent() { reset(); }
    AuthEvent(const AuthEvent&) = delete;
    AuthEvent& operator=(const AuthEvent&) = delete;
    AuthEvent(AuthEvent&& other) noexcept
        : handle_(std::exchange(other.handle_, nullptr))
    {
    }
    AuthEvent& operator=(AuthEvent&& other) noexcept
    {
        if (this != &other) {
            reset();
            handle_ = std::exchange(other.handle_, nullptr);
        }
        return *this;
    }

    OvStorage_AuthEventKind kind() const noexcept
    {
        return handle_ == nullptr
            ? OvStorage_AuthEventKind_Cancelled
            : handle_->kind;
    }

    std::optional<std::string> open_browser_url() const
    {
        const char* p =
            kind() == OvStorage_AuthEventKind_OpenBrowser
            ? handle_->as.open_browser.url
            : nullptr;
        return p == nullptr ? std::nullopt : std::optional<std::string>(p);
    }
    /// Nanoseconds since the Unix epoch at which an OpenBrowser prompt
    /// stops being usable. Zero when the C ABI reports no expiry.
    std::uint64_t open_browser_expires_at_unix_nanos() const noexcept
    {
        return kind() == OvStorage_AuthEventKind_OpenBrowser
            ? handle_->as.open_browser.expires_at_unix_nanos
            : 0;
    }

    // A device-code flow is unusable without all of these: the user needs
    // somewhere to go, something to type, how long it stays valid, and the
    // host needs the interval to pace its polling.
    std::optional<std::string> device_code_user_code() const
    {
        const char* p =
            kind() == OvStorage_AuthEventKind_DeviceCode
            ? handle_->as.device_code.user_code
            : nullptr;
        return p == nullptr ? std::nullopt : std::optional<std::string>(p);
    }
    std::optional<std::string> device_code_verification_url() const
    {
        const char* p =
            kind() == OvStorage_AuthEventKind_DeviceCode
            ? handle_->as.device_code.verification_url
            : nullptr;
        return p == nullptr ? std::nullopt : std::optional<std::string>(p);
    }
    std::uint64_t device_code_expires_at_unix_nanos() const noexcept
    {
        return kind() == OvStorage_AuthEventKind_DeviceCode
            ? handle_->as.device_code.expires_at_unix_nanos
            : 0;
    }
    std::uint64_t device_code_interval_nanos() const noexcept
    {
        return kind() == OvStorage_AuthEventKind_DeviceCode
            ? handle_->as.device_code.interval_nanos
            : 0;
    }
    std::optional<std::string> progress_message() const
    {
        const char* p =
            kind() == OvStorage_AuthEventKind_Progress
            ? handle_->as.progress.message
            : nullptr;
        return p == nullptr ? std::nullopt : std::optional<std::string>(p);
    }
    /// Returns a borrowed pointer to the inner Connection for the
    /// Succeeded variant. Null otherwise. Lifetime tied to the event.
    const OvStorage_Connection* succeeded_connection() const noexcept
    {
        return kind() == OvStorage_AuthEventKind_Succeeded
            ? handle_->as.succeeded.connection
            : nullptr;
    }
    std::optional<std::string> failed_error_message() const
    {
        const char* p =
            kind() == OvStorage_AuthEventKind_Failed
            ? handle_->as.failed.message
            : nullptr;
        return p == nullptr ? std::nullopt : std::optional<std::string>(p);
    }
    OvStorage_Status failed_error_code() const noexcept
    {
        return kind() == OvStorage_AuthEventKind_Failed
            ? handle_->as.failed.code
            : OvStorage_Status_Ok;
    }
    /// The fine-grained plugin error-code name behind
    /// `failed_error_code()`. The coarse status folds an expired
    /// credential, a revoked one and a broker outage that never reached the
    /// identity provider onto neighbouring buckets; this names which it
    /// was, which is the difference between re-prompting a user and
    /// retrying.
    std::optional<std::string> failed_error_code_name() const
    {
        const char* p =
            kind() == OvStorage_AuthEventKind_Failed
            ? handle_->as.failed.code_name
            : nullptr;
        return p == nullptr ? std::nullopt : std::optional<std::string>(p);
    }

private:
    void reset()
    {
        if (handle_ != nullptr) {
            ovstorage_auth_event_destroy(handle_);
            handle_ = nullptr;
        }
    }
    OvStorage_AuthEvent* handle_ = nullptr;
};

// ---------------------------------------------------------------------------
// RootInfo / RootInfoList (address-root discovery, read-side)
// ---------------------------------------------------------------------------

class RootInfo {
public:
    RootInfo() = default;
    explicit RootInfo(OvStorage_RootInfo* handle) : handle_(handle) {}
    ~RootInfo() { reset(); }
    RootInfo(const RootInfo&) = delete;
    RootInfo& operator=(const RootInfo&) = delete;
    RootInfo(RootInfo&& other) noexcept : handle_(std::exchange(other.handle_, nullptr)) {}
    RootInfo& operator=(RootInfo&& other) noexcept
    {
        if (this != &other) {
            reset();
            handle_ = std::exchange(other.handle_, nullptr);
        }
        return *this;
    }

    const OvStorage_RootInfo* get() const noexcept { return handle_; }

    std::string root() const { return cstring(handle_ == nullptr ? nullptr : handle_->root); }
    std::string layer_kind() const
    {
        return cstring(handle_ == nullptr ? nullptr : handle_->layer_kind);
    }
    std::string display_name() const
    {
        return cstring(handle_ == nullptr ? nullptr : handle_->display_name);
    }

    bool has_connection_id() const noexcept
    {
        return handle_ != nullptr && handle_->has_connection_id;
    }
    std::string connection_id() const
    {
        return cstring(
            handle_ == nullptr || !handle_->has_connection_id
                ? nullptr
                : handle_->connection_id);
    }

    bool visible() const noexcept { return handle_ != nullptr && handle_->visible; }
    OvStorage_AddressVisibility visibility() const noexcept
    {
        return handle_ == nullptr
            ? OvStorage_AddressVisibility_Visible
            : handle_->visibility;
    }

    Capabilities capabilities() const
    {
        Capabilities caps;
        if (handle_ != nullptr) {
            *caps.raw() = handle_->capabilities;
        }
        return caps;
    }

    /// Instance name of the Layer that owns connections for this root — the
    /// `target` that `authenticate`, `update_connection_credentials` and
    /// `remove_connection` route by. Not derivable from `root()`: a
    /// composite plugin's internal owning backend has a different name from
    /// the outer root. `std::nullopt` means there is no connection op to
    /// address here.
    std::optional<std::string> owning_target() const
    {
        if (handle_ == nullptr || handle_->owning_target == nullptr) {
            return std::nullopt;
        }
        return std::string(handle_->owning_target);
    }

    /// What a range read against this root actually costs.
    /// `MaterializeOnly` means a one-kilobyte window pulls the whole
    /// object, so a caller weighing `read_bytes` with a window against
    /// `read_local_file` needs this rather than guessing from the scheme.
    OvStorage_RangeReadStrategy range_read_strategy() const noexcept
    {
        return handle_ == nullptr
            ? OvStorage_RangeReadStrategy_Unsupported
            : handle_->range_read_strategy;
    }

    OvStorage_RouteSourceKind source_kind() const noexcept
    {
        return handle_ == nullptr
            ? OvStorage_RouteSourceKind_Static
            : handle_->source_kind;
    }
    OvStorage_ConfigLayer source_static_layer() const noexcept
    {
        return handle_ == nullptr ||
                handle_->source_kind != OvStorage_RouteSourceKind_Static
            ? OvStorage_ConfigLayer_Programmatic
            : handle_->source_static_layer;
    }
    std::string source_connection_id() const
    {
        return cstring(
            handle_ != nullptr &&
                    (handle_->source_kind ==
                         OvStorage_RouteSourceKind_ConnectionContributed ||
                     handle_->source_kind ==
                         OvStorage_RouteSourceKind_BrokerDelivered)
                ? handle_->source_connection_id
                : nullptr);
    }
    std::string source_broker_principal() const
    {
        return cstring(
            handle_ != nullptr &&
                    handle_->source_kind ==
                        OvStorage_RouteSourceKind_BrokerDelivered
                ? handle_->source_broker_principal
                : nullptr);
    }
    std::string source_alias_to() const
    {
        return cstring(
            handle_ != nullptr &&
                    handle_->source_kind == OvStorage_RouteSourceKind_Alias
                ? handle_->source_alias_to
                : nullptr);
    }
    OvStorage_AliasSourceKind source_alias_source_kind() const noexcept
    {
        return handle_ != nullptr &&
                handle_->source_kind == OvStorage_RouteSourceKind_Alias
            ? handle_->source_alias_source_kind
            : OvStorage_AliasSourceKind_Runtime;
    }
    OvStorage_ConfigLayer source_alias_source_static_layer() const noexcept
    {
        return handle_ != nullptr &&
                handle_->source_kind == OvStorage_RouteSourceKind_Alias &&
                handle_->source_alias_source_kind ==
                    OvStorage_AliasSourceKind_Static
            ? handle_->source_alias_source_static_layer
            : OvStorage_ConfigLayer_Programmatic;
    }
    bool source_alias_source_runtime_persisted() const noexcept
    {
        return handle_ != nullptr &&
            handle_->source_kind == OvStorage_RouteSourceKind_Alias &&
            handle_->source_alias_source_kind ==
                OvStorage_AliasSourceKind_Runtime &&
            handle_->source_alias_source_runtime_persisted;
    }
    std::string source_alias_source_broker_principal() const
    {
        return cstring(
            handle_ != nullptr &&
                    handle_->source_kind == OvStorage_RouteSourceKind_Alias &&
                    handle_->source_alias_source_kind ==
                        OvStorage_AliasSourceKind_BrokerDelivered
                ? handle_->source_alias_source_broker_principal
                : nullptr);
    }

    bool has_alias_state() const noexcept
    {
        return handle_ != nullptr && handle_->has_alias_state;
    }
    OvStorage_AliasStateKind alias_state_kind() const noexcept
    {
        return handle_ != nullptr && handle_->has_alias_state
            ? handle_->alias_state_kind
            : OvStorage_AliasStateKind_Live;
    }
    std::string alias_state_chain_too_long_reason() const
    {
        return cstring(
            handle_ != nullptr && handle_->has_alias_state &&
                    handle_->alias_state_kind ==
                        OvStorage_AliasStateKind_ChainTooLong
                ? handle_->alias_state_chain_too_long_reason
                : nullptr);
    }

    std::vector<std::pair<std::string, std::string>> user_metadata() const
    {
        std::vector<std::pair<std::string, std::string>> out;
        const auto len =
            handle_ == nullptr || handle_->user_metadata == nullptr
            ? 0
            : handle_->user_metadata_len;
        out.reserve(len);
        for (std::size_t i = 0; i < len; ++i) {
            out.emplace_back(
                cstring(handle_->user_metadata[i].key),
                cstring(handle_->user_metadata[i].value));
        }
        return out;
    }

    /// Borrowed view of the root's icon bytes. Empty if it has none.
    /// Valid only while this RootInfo (or the owning RootInfoList) lives.
    std::span<const std::byte> icon() const noexcept
    {
        const std::uint8_t* data =
            handle_ == nullptr || !handle_->has_icon ? nullptr : handle_->icon;
        std::size_t len =
            handle_ == nullptr || !handle_->has_icon ? 0 : handle_->icon_len;
        if (data == nullptr || len == 0) {
            return {};
        }
        return {reinterpret_cast<const std::byte*>(data), len};
    }

private:
    static std::string cstring(const char* p)
    {
        return p == nullptr ? std::string{} : std::string(p);
    }
    void reset()
    {
        if (handle_ != nullptr) {
            ovstorage_root_info_destroy(handle_);
            handle_ = nullptr;
        }
    }
    OvStorage_RootInfo* handle_ = nullptr;
};

class RootInfoList {
public:
    RootInfoList() = default;
    explicit RootInfoList(OvStorage_RootInfoList* handle) : handle_(handle) {}
    ~RootInfoList() { reset(); }
    RootInfoList(const RootInfoList&) = delete;
    RootInfoList& operator=(const RootInfoList&) = delete;
    RootInfoList(RootInfoList&& other) noexcept
        : handle_(std::exchange(other.handle_, nullptr))
    {
    }
    RootInfoList& operator=(RootInfoList&& other) noexcept
    {
        if (this != &other) {
            reset();
            handle_ = std::exchange(other.handle_, nullptr);
        }
        return *this;
    }

    std::size_t size() const noexcept { return handle_ == nullptr ? 0 : handle_->len; }
    /// Returns a borrowed pointer to the i-th root. Lifetime is tied to
    /// the list handle — do NOT delete or destroy it.
    const OvStorage_RootInfo* item_at(std::size_t i) const noexcept
    {
        return handle_ == nullptr || handle_->items == nullptr ||
                i >= handle_->len
            ? nullptr
            : &handle_->items[i];
    }

private:
    void reset()
    {
        if (handle_ != nullptr) {
            ovstorage_root_info_list_destroy(handle_);
            handle_ = nullptr;
        }
    }
    OvStorage_RootInfoList* handle_ = nullptr;
};

// ---------------------------------------------------------------------------
// KindDescriptorList (plugin-kind discovery via ovstorage_inspect_plugin)
// ---------------------------------------------------------------------------
//
// The per-item `kind` / `display_name` accessors return a `(ptr, *len)`
// byte slice that is NOT NUL-terminated; this wrapper builds a
// `std::string` from `(ptr, len)` and never calls `strlen`.

class KindDescriptorList {
public:
    KindDescriptorList() = default;
    explicit KindDescriptorList(OvStorage_KindDescriptorList* handle) : handle_(handle) {}
    ~KindDescriptorList() { reset(); }
    KindDescriptorList(const KindDescriptorList&) = delete;
    KindDescriptorList& operator=(const KindDescriptorList&) = delete;
    KindDescriptorList(KindDescriptorList&& other) noexcept
        : handle_(std::exchange(other.handle_, nullptr))
    {
    }
    KindDescriptorList& operator=(KindDescriptorList&& other) noexcept
    {
        if (this != &other) {
            reset();
            handle_ = std::exchange(other.handle_, nullptr);
        }
        return *this;
    }

    std::size_t size() const noexcept { return ovstorage_kind_descriptor_list_len(handle_); }

    /// `layer_type` of item `i`: 0=Backend, 1=Wrapper, 2=Router, -1 if
    /// out of range.
    std::int32_t layer_type(std::size_t i) const noexcept
    {
        return ovstorage_kind_descriptor_list_item_layer_type(handle_, i);
    }

    /// The (non-NUL-terminated) `kind` slice of item `i`, copied into a
    /// `std::string`. Empty if out of range.
    std::string kind(std::size_t i) const { return slice(ovstorage_kind_descriptor_list_item_kind, i); }

    /// The (non-NUL-terminated) `display_name` slice of item `i`, copied
    /// into a `std::string`. Empty if out of range.
    std::string display_name(std::size_t i) const
    {
        return slice(ovstorage_kind_descriptor_list_item_display_name, i);
    }

private:
    std::string slice(
        const char* (*accessor)(const OvStorage_KindDescriptorList*, std::size_t, std::size_t*),
        std::size_t i) const
    {
        std::size_t len = 0;
        const char* ptr = accessor(handle_, i, &len);
        if (ptr == nullptr || len == 0) {
            return std::string{};
        }
        return std::string(ptr, len);
    }
    void reset()
    {
        if (handle_ != nullptr) {
            ovstorage_kind_descriptor_list_destroy(handle_);
            handle_ = nullptr;
        }
    }
    OvStorage_KindDescriptorList* handle_ = nullptr;
};

// ---------------------------------------------------------------------------
// CancelToken
// ---------------------------------------------------------------------------

class CancelToken {
public:
    CancelToken() : handle_(ovstorage_cancel_token_create()) {}

    ~CancelToken() { reset(); }
    CancelToken(const CancelToken&) = delete;
    CancelToken& operator=(const CancelToken&) = delete;

    CancelToken(CancelToken&& other) noexcept
        : handle_(std::exchange(other.handle_, nullptr))
    {
    }
    CancelToken& operator=(CancelToken&& other) noexcept
    {
        if (this != &other) {
            reset();
            handle_ = std::exchange(other.handle_, nullptr);
        }
        return *this;
    }

    void cancel() const noexcept
    {
        if (handle_ != nullptr) {
            ovstorage_cancel_token_cancel(handle_);
        }
    }

    bool is_canceled() const noexcept
    {
        return handle_ != nullptr && ovstorage_cancel_token_is_canceled(handle_);
    }

    const OvStorage_CancelToken* get() const noexcept { return handle_; }

    static const OvStorage_CancelToken* as_ptr(const CancelToken* token) noexcept
    {
        return token == nullptr ? nullptr : token->handle_;
    }

private:
    void reset()
    {
        if (handle_ != nullptr) {
            ovstorage_cancel_token_destroy(handle_);
            handle_ = nullptr;
        }
    }

    OvStorage_CancelToken* handle_ = nullptr;
};

// ---------------------------------------------------------------------------
// task<T> coroutine type
//
// Eager-start (initial_suspend = suspend_never) so that any caller-borrowed
// inputs (`std::span`, `&&` builders, `const UpdateMetadataOptions&`) are
// snapshotted into the awaiter frame before the call expression's
// temporaries die. Eager start means the body may already have completed
// by the time the consumer awaits, AND the body's final_suspend may run
// concurrently with the consumer's await_suspend on a different thread.
//
// To coordinate, promise_type carries an atomic `state`:
//   0 = initial, neither party has acted
//   1 = consumer's task::await_suspend ran first (continuation registered)
//   2 = body's final_awaiter ran first (body completed)
//   3 = consumer abandoned the task (`~task()` ran while body still
//       suspended). The body's eventual final_awaiter sees state==3 and,
//       rather than resuming a non-existent continuation, parks the frame
//       at final-suspend and asks the resumer to reclaim it. The in-flight
//       C callback still runs to completion (its leaked shared_ptr ref
//       keeps the per-awaiter state alive) and the orphaned frame is freed
//       by `detail::deliver` AFTER `resume()` has fully unwound.
// Whichever party arrives second observes the other's value via
// acq_rel exchange and routes accordingly.
//
// The final_awaiter deliberately does NOT `handle.destroy()` on the
// abandoned (state==3) path: freeing a coroutine's own frame from inside
// its final-suspend `await_suspend` is only safe if the compiler emits a
// guaranteed tail-call to the returned handle so nothing touches the frame
// afterward. AddressSanitizer's instrumented frame teardown breaks that
// invariant — it pokes the just-freed frame after the transfer point, so
// the worker thread's `resume()` never returns (a hang, not a diagnosed
// error). Instead the abandoned frame is parked and reclaimed externally by
// `detail::deliver` once resume() has returned (see `resume_owner`). The same
// handoff protects the completed (state==2) path: if `~task()` races any frame
// in the callback worker's symmetric-transfer chain, it requests deferred
// destruction instead of freeing that frame under the worker. Each task await
// registers its continuation with the active resume context, so ownership is
// propagated through user-authored wrapper coroutines as well as the directly
// resumed header-generated method task.
// ---------------------------------------------------------------------------

namespace detail {

// Ownership of a callback-driven call to body.resume(). The callback worker
// publishes `resuming` before entering the coroutine and returns the state to
// `inactive` only after resume() has fully unwound. A concurrent task destructor
// changes `resuming` to `destroy_requested`; whichever side wins the exchange
// owns the frame destruction.
enum class resume_ownership : unsigned char {
    inactive,
    resuming,
    destroy_requested,
};

struct resume_context;

struct resume_record {
    resume_record* previous = nullptr;
    std::coroutine_handle<> handle;
    std::atomic<resume_ownership>* owner = nullptr;
    resume_context** active_context = nullptr;
};

// One callback worker's complete symmetric-transfer chain. Records live in
// their coroutine promises and are linked newest-first, so unwind cleanup can
// release outer frames before the inner frames whose task awaiters they owned.
struct resume_context {
    resume_record* head = nullptr;

    void release() noexcept
    {
        while (head != nullptr) {
            resume_record* record = head;
            head = record->previous;
            auto handle = record->handle;
            auto* owner = record->owner;
            if (record->active_context != nullptr &&
                *record->active_context == this) {
                *record->active_context = nullptr;
            }
            record->active_context = nullptr;
            record->previous = nullptr;
            if (owner->exchange(
                    resume_ownership::inactive,
                    std::memory_order_acq_rel) ==
                resume_ownership::destroy_requested) {
                handle.destroy();
            }
        }
    }
};

template <class Promise>
concept resume_owned_promise = requires(Promise& p) {
    p.resume_owner;
    p.active_resume_context;
    p.resume_record;
};

template <class Promise>
inline void activate_resume(
    std::coroutine_handle<Promise> handle,
    resume_context& context) noexcept
{
    auto& promise = handle.promise();
    promise.resume_record.previous = context.head;
    promise.resume_record.handle = handle;
    promise.resume_record.owner = &promise.resume_owner;
    promise.resume_record.active_context = &promise.active_resume_context;
    promise.active_resume_context = &context;
    context.head = &promise.resume_record;
    [[maybe_unused]] auto ownership = promise.resume_owner.exchange(
        resume_ownership::resuming, std::memory_order_acq_rel);
    // A promise may participate in only one deliver-driven resume at a time.
    assert(ownership == resume_ownership::inactive);
}

// A resumed frame that suspends again must leave its current worker's unwind
// chain before another worker can publish ownership of the same promise. The
// caller must reacquire the returned context when the prospective await
// completes inline and the frame therefore did not suspend.
template <resume_owned_promise Promise>
inline resume_context* release_resume_before_suspend(Promise& promise) noexcept
{
    auto* context = promise.active_resume_context;
    if (context == nullptr) return nullptr;

    auto* record = &promise.resume_record;
    assert(context->head == record);
    context->head = record->previous;
    record->previous = nullptr;
    record->active_context = nullptr;
    promise.active_resume_context = nullptr;
    [[maybe_unused]] auto ownership = promise.resume_owner.exchange(
        resume_ownership::inactive, std::memory_order_acq_rel);
    assert(ownership == resume_ownership::resuming);
    return context;
}

using continuation_activator =
    void (*)(std::coroutine_handle<>, resume_context&) noexcept;

template <class Promise>
inline void activate_continuation(
    std::coroutine_handle<> erased,
    resume_context& context) noexcept
{
    auto typed = std::coroutine_handle<Promise>::from_address(erased.address());
    activate_resume(typed, context);
}

inline bool request_deferred_destroy(
    std::atomic<resume_ownership>& owner) noexcept
{
    auto expected = resume_ownership::resuming;
    return owner.compare_exchange_strong(
        expected,
        resume_ownership::destroy_requested,
        std::memory_order_acq_rel,
        std::memory_order_acquire);
}

// Shared `final_suspend` routing for both `task<T>` promise types. Kept in one
// place so the delicate abandon (state==3) decision cannot diverge between the
// `task<T>` and `task<void>` copies of `final_awaiter`. `Promise` supplies
// `state` (atomic<int>), `continuation`, and `resume_owner` (see the state note
// above). Never destroys the frame: on abandon it parks and asks `deliver` to
// reclaim after `resume()` unwinds.
template <class Promise>
inline std::coroutine_handle<> route_final_suspend(Promise& p) noexcept
{
    int prev = p.state.exchange(2, std::memory_order_acq_rel);
#ifdef OVSTORAGE_DETAIL_TASK_FINAL_SUSPEND_TEST_HOOK
    OVSTORAGE_DETAIL_TASK_FINAL_SUSPEND_TEST_HOOK(prev, p.state);
#endif
    if (prev == 1) {
        if (p.continuation && p.active_resume_context != nullptr &&
            p.continuation_activator != nullptr) {
            p.continuation_activator(
                p.continuation, *p.active_resume_context);
        }
        return p.continuation ? p.continuation : std::noop_coroutine();
    }
    if (prev == 3) {
        (void)request_deferred_destroy(p.resume_owner);
    }
    return std::noop_coroutine();
}

}  // namespace detail

template <class T>
class task {
public:
    struct promise_type;
    using handle_type = std::coroutine_handle<promise_type>;

    struct final_awaiter {
        bool await_ready() noexcept { return false; }
        std::coroutine_handle<> await_suspend(handle_type h) noexcept
        {
            // Shared abandon/route logic (see detail::route_final_suspend): on
            // state==3 it parks and requests deferred destroy rather than
            // self-destroying here (ASan-unsafe — see the state==3 note above).
            return detail::route_final_suspend(h.promise());
        }
        void await_resume() noexcept {}
    };

    struct promise_type {
        std::optional<Result<T>> value;
        std::coroutine_handle<> continuation;
        std::atomic<int> state{0};
        // Tracks whether detail::deliver is inside resume(), so destruction can
        // be handed back to that worker instead of racing or self-destroying.
        std::atomic<detail::resume_ownership> resume_owner{
            detail::resume_ownership::inactive};
        detail::resume_context* active_resume_context = nullptr;
        detail::resume_record resume_record;
        detail::continuation_activator continuation_activator = nullptr;

        task get_return_object() noexcept
        {
            return task(handle_type::from_promise(*this));
        }
        std::suspend_never initial_suspend() noexcept { return {}; }
        final_awaiter final_suspend() noexcept { return {}; }
        void return_value(Result<T> r) { value = std::move(r); }
        void unhandled_exception() noexcept { std::terminate(); }
    };

    task() = default;
    explicit task(handle_type h) : handle_(h) {}

    task(const task&) = delete;
    task& operator=(const task&) = delete;

    task(task&& other) noexcept : handle_(std::exchange(other.handle_, nullptr)) {}
    task& operator=(task&& other) noexcept
    {
        if (this != &other) {
            destroy_handle();
            handle_ = std::exchange(other.handle_, nullptr);
        }
        return *this;
    }

    ~task() { destroy_handle(); }

    bool await_ready() const noexcept
    {
        return !handle_ ||
            handle_.promise().state.load(std::memory_order_acquire) == 2;
    }

    template <class Promise>
    bool await_suspend(std::coroutine_handle<Promise> awaiter) noexcept
    {
        auto& p = handle_.promise();
        detail::resume_context* prior_context = nullptr;
        if constexpr (detail::resume_owned_promise<Promise>) {
            prior_context = detail::release_resume_before_suspend(
                awaiter.promise());
        }
        p.continuation = awaiter;
        if constexpr (detail::resume_owned_promise<Promise>) {
            p.continuation_activator =
                &detail::activate_continuation<Promise>;
        }
        int expected = 0;
        bool suspend = p.state.compare_exchange_strong(
            expected,
            1,
            std::memory_order_acq_rel,
            std::memory_order_acquire);
        if constexpr (detail::resume_owned_promise<Promise>) {
            if (!suspend && prior_context != nullptr) {
                detail::activate_resume(awaiter, *prior_context);
            }
        }
        return suspend;
    }

    Result<T> await_resume()
    {
        return std::move(*handle_.promise().value);
    }

    handle_type handle() const noexcept { return handle_; }

private:
    void destroy_handle() noexcept
    {
        if (!handle_) return;
        auto& p = handle_.promise();
        if (p.state.exchange(3, std::memory_order_acq_rel) == 2) {
            // A synchronous completion, or an async resume that has already
            // unwound, can be destroyed here. If the callback worker is still
            // inside resume(), it observes the request and destroys afterward.
            if (!detail::request_deferred_destroy(p.resume_owner)) {
                handle_.destroy();
            }
        }
    }

    handle_type handle_ = nullptr;
};

// task<void> specialization — promise carries Result<void> and uses
// return_value(Result<void>) just like the generic case.
template <>
class task<void> {
public:
    struct promise_type;
    using handle_type = std::coroutine_handle<promise_type>;

    struct final_awaiter {
        bool await_ready() noexcept { return false; }
        std::coroutine_handle<> await_suspend(handle_type h) noexcept
        {
            // Shared abandon/route logic (see detail::route_final_suspend): on
            // state==3 it parks and requests deferred destroy rather than
            // self-destroying here (ASan-unsafe — see the state==3 note above).
            return detail::route_final_suspend(h.promise());
        }
        void await_resume() noexcept {}
    };

    struct promise_type {
        std::optional<Result<void>> value;
        std::coroutine_handle<> continuation;
        std::atomic<int> state{0};
        // Tracks whether detail::deliver is inside resume(), so destruction can
        // be handed back to that worker instead of racing or self-destroying.
        std::atomic<detail::resume_ownership> resume_owner{
            detail::resume_ownership::inactive};
        detail::resume_context* active_resume_context = nullptr;
        detail::resume_record resume_record;
        detail::continuation_activator continuation_activator = nullptr;

        task get_return_object() noexcept
        {
            return task(handle_type::from_promise(*this));
        }
        std::suspend_never initial_suspend() noexcept { return {}; }
        final_awaiter final_suspend() noexcept { return {}; }
        void return_value(Result<void> r) { value = std::move(r); }
        void unhandled_exception() noexcept { std::terminate(); }
    };

    task() = default;
    explicit task(handle_type h) : handle_(h) {}

    task(const task&) = delete;
    task& operator=(const task&) = delete;

    task(task&& other) noexcept : handle_(std::exchange(other.handle_, nullptr)) {}
    task& operator=(task&& other) noexcept
    {
        if (this != &other) {
            destroy_handle();
            handle_ = std::exchange(other.handle_, nullptr);
        }
        return *this;
    }

    ~task() { destroy_handle(); }

    bool await_ready() const noexcept
    {
        return !handle_ ||
            handle_.promise().state.load(std::memory_order_acquire) == 2;
    }
    template <class Promise>
    bool await_suspend(std::coroutine_handle<Promise> awaiter) noexcept
    {
        auto& p = handle_.promise();
        detail::resume_context* prior_context = nullptr;
        if constexpr (detail::resume_owned_promise<Promise>) {
            prior_context = detail::release_resume_before_suspend(
                awaiter.promise());
        }
        p.continuation = awaiter;
        if constexpr (detail::resume_owned_promise<Promise>) {
            p.continuation_activator =
                &detail::activate_continuation<Promise>;
        }
        int expected = 0;
        bool suspend = p.state.compare_exchange_strong(
            expected,
            1,
            std::memory_order_acq_rel,
            std::memory_order_acquire);
        if constexpr (detail::resume_owned_promise<Promise>) {
            if (!suspend && prior_context != nullptr) {
                detail::activate_resume(awaiter, *prior_context);
            }
        }
        return suspend;
    }
    Result<void> await_resume()
    {
        return std::move(*handle_.promise().value);
    }

    handle_type handle() const noexcept { return handle_; }

private:
    void destroy_handle() noexcept
    {
        if (!handle_) return;
        auto& p = handle_.promise();
        if (p.state.exchange(3, std::memory_order_acq_rel) == 2) {
            if (!detail::request_deferred_destroy(p.resume_owner)) {
                handle_.destroy();
            }
        }
    }

    handle_type handle_ = nullptr;
};

// ---------------------------------------------------------------------------
// sync_wait — drives a task<T> to completion on the calling thread.
// ---------------------------------------------------------------------------

namespace detail {

// Eagerly-started fire-and-forget coroutine used as a runner for
// sync_wait. Does not own/destroy the task it runs — its promise's
// final_suspend returns suspend_never so the runner's coroutine state
// destroys itself on completion.
struct fire_and_forget {
    struct promise_type {
        fire_and_forget get_return_object() noexcept { return {}; }
        std::suspend_never initial_suspend() noexcept { return {}; }
        std::suspend_never final_suspend() noexcept { return {}; }
        void return_void() noexcept {}
        void unhandled_exception() noexcept { std::terminate(); }
    };
};

// The rendezvous between `sync_wait` and the thread that completes the task.
//
// It is heap-allocated and shared rather than kept in `sync_wait`'s frame,
// because the completing thread is whichever thread the C callback fired on
// and it keeps touching these primitives after publishing the result. If the
// waiter owned them, it could observe the result and destroy them out from
// under that thread: `wait(lk, pred)` evaluates the predicate BEFORE
// blocking, so a result published in the window between entering `sync_wait`
// and reaching `wait` lets the waiter return without ever blocking. Shared
// ownership keeps the mutex and condition variable alive until BOTH sides are
// finished with them — including the completing side's unlock, which a
// notify-under-lock alone would not cover.
template <class T>
struct sync_wait_state {
    std::mutex m;
    std::condition_variable cv;
    std::optional<Result<T>> slot;

    // Notify while still holding the lock so a waiter that is already
    // blocked cannot return until this thread is done with `cv`.
    void publish(Result<T> outcome)
    {
        std::lock_guard<std::mutex> lk(m);
        slot.emplace(std::move(outcome));
        cv.notify_all();
    }

    Result<T> wait()
    {
        std::unique_lock<std::mutex> lk(m);
        cv.wait(lk, [this] { return slot.has_value(); });
        return std::move(*slot);
    }
};

// `state` is taken by value, so the coroutine frame owns a reference for as
// long as the runner exists. `fire_and_forget`'s `final_suspend` returns
// `suspend_never`, so the frame — and that reference — is released only after
// the body has fully returned from `publish`.
template <class T>
fire_and_forget run_into_slot(
    task<T> work, std::shared_ptr<sync_wait_state<T>> state)
{
    Result<T> outcome = co_await std::move(work);
    state->publish(std::move(outcome));
}

inline fire_and_forget run_into_slot_void(
    task<void> work, std::shared_ptr<sync_wait_state<void>> state)
{
    Result<void> outcome = co_await std::move(work);
    state->publish(std::move(outcome));
}

} // namespace detail

/// Drive `t` to completion on the calling thread and return its result.
///
/// Blocks. Must NOT be called from a runtime worker thread — the same
/// constraint `ovstorage_stack_build` documents, for the same reason: the
/// process-global runtime has a fixed-size pool whose workers run a task to
/// completion, so a worker that blocks here waiting on work that needs a
/// worker takes a thread out of the pool for the duration. Enough nested
/// calls and the pool has none left and nothing completes.
///
/// The thread that reaches this from `main`, or any thread the application
/// owns, is fine. A thread inside a callback the library invoked is not; use
/// `co_await` there, which suspends instead of blocking.
template <class T>
Result<T> sync_wait(task<T> t)
{
    auto state = std::make_shared<detail::sync_wait_state<T>>();
    detail::run_into_slot<T>(std::move(t), state);
    return state->wait();
}

/// `void` overload of `sync_wait`. The same worker-thread constraint
/// applies.
inline Result<void> sync_wait(task<void> t)
{
    auto state = std::make_shared<detail::sync_wait_state<void>>();
    detail::run_into_slot_void(std::move(t), state);
    return state->wait();
}

// ---------------------------------------------------------------------------
// Per-callback-shape awaiter base classes.
//
// Each base provides the synchronization plumbing shared across all
// async ops that use that callback shape: outcome storage, the
// continuation handle, an atomic state that coordinates the C callback
// (firing on a worker thread) against the consumer's `commit_suspend`
// tail (running on the caller's thread).
//
// The shared state lives in a heap-allocated `awaiter_state<Out>` and
// is referenced both by the awaiter sub-object on the coroutine frame
// and by the C callback's `user_data` (a leaked `shared_ptr` ref count
// that the static thunk reclaims). The leaked ref means the state
// outlives the awaiter sub-object even when the consumer drops the
// task while a callback is in flight: the C-side keeps using its
// reclaimed state to populate the outcome, then resumes the body's
// continuation. The body's promise carries the abandon-handling state
// machine (see the task<T> comment block above) so the resume is safe
// regardless of whether the consumer is still around.
//
// State machine (canonical cppcoro / asio atomic-exchange):
//
//   initial                       = 0
//   on_complete fires             -> exchange(1, ...).
//                                    prev=2 -> consumer suspended;
//                                              resume continuation.
//                                    prev=0 -> consumer hasn't suspended
//                                              yet; commit_suspend will
//                                              observe state=1 and
//                                              resume inline.
//   commit_suspend                -> exchange(2, ...).
//                                    prev=1 -> on_complete already fired;
//                                              return false (resume inline).
//                                    prev=0 -> first; return true (suspend).
// ---------------------------------------------------------------------------

namespace detail {

template <class Out>
struct awaiter_state {
    // What the caller receives when a boundary caught an allocation failure
    // and had nothing it could safely build. The thunks report that case by
    // LEAVING this value in place, so it has to name the failure on its own:
    // `Error{}` defaults to `OvStorage_Status_Ok` with an empty message, which
    // is a failed `Result` whose status claims success.
    //
    // `Internal` rather than `ResourceExhausted`: this ABI documents the
    // latter as a backend quota or capacity limit and reports it as
    // blind-retryable (`ovstorage_status_is_retryable`), and a host-side
    // allocation failure is neither. It is also what `fail_from_observer`
    // already reports for the other host-side failure in this header.
    //
    // The message is short enough to live in the string's inline buffer, so
    // seeding costs no allocation — asserted by the cc-test driver, because
    // this is the seed a boundary falls back to precisely when allocation is
    // what failed.
    Result<Out> outcome = Result<Out>::failure(
        Error(OvStorage_Status_Internal, "out of memory"));
    std::coroutine_handle<typename task<Out>::promise_type> continuation;
    std::atomic<int> state{0};
};

template <class Out, class State = awaiter_state<Out>>
struct awaiter_base {
    std::shared_ptr<State> s = std::make_shared<State>();

    // The coroutine that co_awaits an `awaiter_base<Out>` is always a
    // `task<Out>` body (each op is co_awaited via `co_return co_await` inside a
    // task<Out> method), so its promise is `task<Out>::promise_type`. Ops take
    // this TYPED handle in `await_suspend` (not the erased `coroutine_handle<>`)
    // so the invariant is enforced by the compiler: a mismatched awaiter/task
    // pairing fails to convert the enclosing-promise handle and won't compile,
    // rather than silently accessing the wrong promise layout.
    using body_handle = std::coroutine_handle<typename task<Out>::promise_type>;

    bool await_ready() const noexcept { return false; }
    Result<Out> await_resume() { return std::move(s->outcome); }

    awaiter_base() = default;
    awaiter_base(const awaiter_base&) = delete;
    awaiter_base& operator=(const awaiter_base&) = delete;
    awaiter_base(awaiter_base&&) noexcept = default;
    awaiter_base& operator=(awaiter_base&&) noexcept = default;

    // Hand off an owning ref of the state to the C callback as a void*
    // user_data. The static thunk reclaims via `reclaim_state`.
    void* release_user_data()
    {
        return new std::shared_ptr<State>(s);
    }

    static std::shared_ptr<State> reclaim_state(void* user_data) noexcept
    {
        auto* leaked = static_cast<std::shared_ptr<State>*>(user_data);
        std::shared_ptr<State> ref(std::move(*leaked));
        delete leaked;
        return ref;
    }

    // Borrow the state ref for an intermediate multi-fire callback.
    // Lifetime is tied to the leaked user_data, which the final fire
    // reclaims.
    static State* borrow_state(void* user_data) noexcept
    {
        auto* leaked = static_cast<std::shared_ptr<State>*>(user_data);
        return leaked->get();
    }

    // Drive the state machine after the static thunk has populated
    // `state->outcome`. Resumes the body's continuation if the body
    // suspended at this awaiter; otherwise the body's commit_suspend
    // will observe state=1 and resume inline.
    static void deliver(const std::shared_ptr<State>& ref) noexcept
    {
        int prev = ref->state.exchange(1, std::memory_order_acq_rel);
        if (prev == 2) {
            auto body = ref->continuation;
            resume_context context;
            activate_resume(body, context);
            body.resume();
            // Release only after the full symmetric-transfer chain has
            // unwound. Any destructor that raced a participating frame handed
            // its destruction request to this worker.
#ifdef OVSTORAGE_DETAIL_BEFORE_RESUME_CONTEXT_RELEASE_TEST_HOOK
            OVSTORAGE_DETAIL_BEFORE_RESUME_CONTEXT_RELEASE_TEST_HOOK();
#endif
            context.release();
        }
    }

    // The whole of a single-fire C callback: reclaim the leaked state ref,
    // let `populate` fill in the outcome, and drive the state machine.
    //
    // `noexcept` because the caller is a C frame — the runtime's dispatch pump
    // — and unwinding an exception through one is undefined and would skip the
    // pump's own cleanup. `populate` is where the throwing statement lives:
    // `Error(const OvStorage_Error&)` copies the C message into a
    // `std::string`. Every payload type the success branches build is a
    // pointer/POD adopter, so only the error branch can throw.
    //
    // On a throw, `outcome` keeps the failed `Result` `awaiter_state`
    // initialises it to, and `deliver` still runs. Skipping `deliver` is not
    // an option: `reclaim_state` has already dropped the only reference the C
    // side held, so an un-delivered outcome strands the awaiting coroutine
    // permanently. Nothing on this path allocates, so the handler cannot throw
    // in turn.
    template <class Populate>
    static void complete(void* user_data, Populate&& populate) noexcept
    {
        auto state = reclaim_state(user_data);
        try {
            populate(*state);
        } catch (...) {
            // Reported through the pre-initialised failed `outcome` below.
        }
        deliver(state);
    }

    // Record a C error on a MULTI-fire callback's borrowed state. Those
    // thunks cannot use `complete`: an intermediate fire borrows the state and
    // returns without delivering, so reclaiming there would be wrong. This is
    // their shared equivalent, and the only part of them that can throw.
    //
    // `error_seen` is set BEFORE the copy. The terminal fire reads that flag
    // to choose between the accumulated payload and the failure, so a failed
    // copy must not be able to leave the operation resolving as a SUCCESS
    // carrying a truncated result.
    static void record_c_error(State& st, const OvStorage_Error& error) noexcept
    {
        st.error_seen = true;
        try {
            st.outcome = Result<Out>::failure(Error(error));
        } catch (...) {
            // Reported through the seeded failed `outcome`.
        }
    }

    // Subclass calls this from await_suspend AFTER invoking the C API (so the
    // state fields are fully initialized when on_complete might dereference
    // them) and BEFORE returning, passing the typed body handle. `s->continuation`
    // must already be set to the body handle (before the C API call, so a
    // callback that fires immediately finds it).
    bool commit_suspend(body_handle body)
    {
        auto* prior_context = release_resume_before_suspend(body.promise());
        bool suspend = s->state.exchange(2, std::memory_order_acq_rel) != 1;
        if (!suspend && prior_context != nullptr) {
            activate_resume(body, *prior_context);
        }
        return suspend;
    }
};

// Status callback shape: status + error.
struct status_awaiter : awaiter_base<void> {
    static void on_complete(
        OvStorage_Status /* status */,
        const OvStorage_Error* error,
        void* user_data) noexcept
    {
        complete(user_data, [&](auto& state) {
            if (error != nullptr) {
                state.outcome = Result<void>::failure(Error(*error));
            } else {
                state.outcome = Result<void>::success();
            }
        });
    }
};

// Info callback shape: status + Info* + error.
struct info_awaiter : awaiter_base<Info> {
    static void on_complete(
        OvStorage_Status /* status */,
        OvStorage_Info* info,
        const OvStorage_Error* error,
        void* user_data) noexcept
    {
        complete(user_data, [&](auto& state) {
            if (error != nullptr) {
                state.outcome = Result<Info>::failure(Error(*error));
            } else {
                state.outcome = Result<Info>::success(Info(info));
            }
        });
    }
};

struct write_redirect_awaiter : awaiter_base<WriteRedirectBatch> {
    static void on_complete(
        OvStorage_Status /* status */,
        OvStorage_WriteRedirectBatch* redirects,
        const OvStorage_Error* error,
        void* user_data) noexcept
    {
        complete(user_data, [&](auto& state) {
            if (error != nullptr) {
                ovstorage_write_redirect_batch_destroy(redirects);
                state.outcome =
                    Result<WriteRedirectBatch>::failure(Error(*error));
            } else {
                state.outcome = Result<WriteRedirectBatch>::success(
                    WriteRedirectBatch(redirects));
            }
        });
    }
};

struct write_step_awaiter : awaiter_base<WriteStep> {
    static void on_complete(
        OvStorage_Status /* status */,
        OvStorage_Info* info,
        OvStorage_WriteRedirectBatch* redirects,
        const OvStorage_Error* error,
        void* user_data) noexcept
    {
        complete(user_data, [&](auto& state) {
            if (error != nullptr) {
                ovstorage_info_destroy(info);
                ovstorage_write_redirect_batch_destroy(redirects);
                state.outcome = Result<WriteStep>::failure(Error(*error));
            } else if ((info == nullptr) == (redirects == nullptr)) {
                ovstorage_info_destroy(info);
                ovstorage_write_redirect_batch_destroy(redirects);
                state.outcome = Result<WriteStep>::failure(Error(
                    OvStorage_Status_Internal,
                    "continue_write returned an invalid result shape"));
            } else if (info != nullptr) {
                state.outcome = Result<WriteStep>::success(
                    WriteStep::done(Info(info)));
            } else {
                state.outcome = Result<WriteStep>::success(
                    WriteStep::redirects(WriteRedirectBatch(redirects)));
            }
        });
    }
};

struct read_bytes_awaiter : awaiter_base<std::pair<Bytes, Info>> {
    static void on_complete(
        OvStorage_Status /* status */,
        OvStorage_Bytes bytes,
        OvStorage_Info* info,
        const OvStorage_Error* error,
        void* user_data) noexcept
    {
        complete(user_data, [&](auto& state) {
            if (error != nullptr) {
                // Free the bytes payload (if any was sent on the error path)
                // before the statement that can throw.
                OvStorage_Bytes copy = bytes;
                ovstorage_bytes_destroy(&copy);
                state.outcome =
                    Result<std::pair<Bytes, Info>>::failure(Error(*error));
            } else {
                state.outcome = Result<std::pair<Bytes, Info>>::success(
                    std::pair<Bytes, Info>(Bytes(bytes), Info(info)));
            }
        });
    }
};

struct local_delegate_awaiter : awaiter_base<LocalDelegate> {
    static void on_complete(
        OvStorage_Status /* status */,
        OvStorage_LocalDelegate* delegate,
        const OvStorage_Error* error,
        void* user_data) noexcept
    {
        complete(user_data, [&](auto& state) {
            if (error != nullptr) {
                state.outcome = Result<LocalDelegate>::failure(Error(*error));
            } else {
                state.outcome =
                    Result<LocalDelegate>::success(LocalDelegate(delegate));
            }
        });
    }
};

struct list_awaiter : awaiter_base<List> {
    static void on_complete(
        OvStorage_Status /* status */,
        OvStorage_List* list,
        const OvStorage_Error* error,
        void* user_data) noexcept
    {
        complete(user_data, [&](auto& state) {
            if (error != nullptr) {
                state.outcome = Result<List>::failure(Error(*error));
            } else {
                state.outcome = Result<List>::success(List(list));
            }
        });
    }
};

struct list_versions_awaiter : awaiter_base<VersionList> {
    static void on_complete(
        OvStorage_Status /* status */,
        OvStorage_VersionList* list,
        const OvStorage_Error* error,
        void* user_data) noexcept
    {
        complete(user_data, [&](auto& state) {
            if (error != nullptr) {
                state.outcome = Result<VersionList>::failure(Error(*error));
            } else {
                state.outcome = Result<VersionList>::success(VersionList(list));
            }
        });
    }
};

struct check_access_awaiter : awaiter_base<AccessDecision> {
    static void on_complete(
        OvStorage_Status /* status */,
        OvStorage_AccessDecision decision,
        const OvStorage_Error* error,
        void* user_data) noexcept
    {
        complete(user_data, [&](auto& state) {
            if (error != nullptr) {
                // Released before the statement that can throw.
                OvStorage_AccessDecision copy = decision;
                ovstorage_access_decision_clear(&copy);
                state.outcome = Result<AccessDecision>::failure(Error(*error));
            } else {
                state.outcome =
                    Result<AccessDecision>::success(AccessDecision(decision));
            }
        });
    }
};

// Pre-flight failure used by LayerHandle methods when their handle is
// nullptr (e.g. a moved-from LayerHandle). The C ABI would fire
// on_complete inline with InvalidArgument for a null handle, but the
// C++ wrapper short-circuits with this Result before entering the C ABI
// so coroutine callers get the normal failed-Result shape. Lives in
// `detail` because it's implementation glue, not a public construction
// path.
template <class T>
inline Result<T> null_handle_result()
{
    return Result<T>::failure(Error(
        OvStorage_Status_InvalidArgument,
        "layer handle is null (moved-from or never built)"));
}

// `OvStorage_ReadOptions` gates both endpoints behind a single `has_range`
// flag, so an end with no start has no faithful C spelling: marshalling it
// would send `has_range = false`, and the caller who asked for a bounded
// window would be handed the whole object. The read verbs reject it up front
// instead.
inline bool read_range_is_expressible(const ReadOptions& options) noexcept
{
    return options.range_start.has_value()
        || !options.range_end_inclusive.has_value();
}

inline Error unexpressible_read_range_error()
{
    return Error(
        OvStorage_Status_InvalidArgument, "a range end requires a range start");
}

// The sibling malformed shape. `OvStorage_ReadOptions` *can* carry an
// inverted window, so unlike the case above this is not a marshalling
// limit — it is a diagnostics one. `ovc_dispatch_read_start` answers every
// malformed read with one catch-all `"read arguments are invalid"`, the same
// string a NULL or non-UTF-8 address gets, so a caller with an off-by-one in
// a computed window is told nothing about the window. Refusing it here names
// the endpoint. The file backend's own `"byte range end precedes start"` is
// unreachable for the same reason it was before this guard: dispatch rejects
// the request before any backend sees it.
inline bool read_range_is_ordered(const ReadOptions& options) noexcept
{
    return !options.range_start.has_value()
        || !options.range_end_inclusive.has_value()
        || *options.range_end_inclusive >= *options.range_start;
}

inline Error inverted_read_range_error()
{
    return Error(
        OvStorage_Status_InvalidArgument, "a range end precedes its start");
}

// Marshal to the C struct. Every read verb keeps the result in its awaiter
// rather than in a local, because the C entry point takes its address and the
// awaiter is the storage whose lifetime the wrapper controls.
inline OvStorage_ReadOptions to_raw_read_options(
    const ReadOptions& options) noexcept
{
    OvStorage_ReadOptions raw{};
    raw.has_range = options.range_start.has_value();
    raw.range_start = options.range_start.value_or(0);
    raw.has_range_end = options.range_end_inclusive.has_value();
    raw.range_end_inclusive = options.range_end_inclusive.value_or(0);
    return raw;
}

// Streaming read: the C callback fires repeatedly. Accumulate chunks
// into a flat buffer and resume the coroutine when done==true. This
// loses chunk-level streaming; a chunk-by-chunk async-iterator surface
// is a follow-up.
struct read_stream_state : awaiter_state<std::vector<std::byte>> {
    std::vector<std::byte> accumulated;
    bool error_seen = false;
};

struct read_stream_awaiter
    : awaiter_base<std::vector<std::byte>, read_stream_state> {
    /// `noexcept` for the same reason as the single-fire thunks: the stream
    /// pump that invokes this is a C frame. Unlike them it cannot delegate to
    /// `awaiter_base::complete`, because an intermediate fire borrows the
    /// state rather than reclaiming it and returns without delivering.
    static void on_chunk(
        OvStorage_Bytes chunk,
        const OvStorage_Error* error,
        bool done,
        void* user_data) noexcept
    {
        auto* st = borrow_state(user_data);
        if (error != nullptr) {
            record_c_error(*st, *error);
        } else if (!done && chunk.data != nullptr) {
            // The chunk buffer is handed to this callback to release, and
            // `insert` allocates — so the release is tied to scope exit
            // rather than sequenced after the accumulate, which a throw
            // would skip. It cannot be sequenced BEFORE the accumulate
            // either: `data` and `free_ctx` are the same allocation
            // (`ovstorage_bytes_destroy` frees `free_ctx`), so destroying
            // first would leave `insert` reading freed memory.
            Bytes owned(chunk);
            const auto payload = owned.span();
            try {
                st->accumulated.insert(
                    st->accumulated.end(), payload.begin(), payload.end());
            } catch (...) {
                // The buffer this read is assembling is now incomplete. Fail
                // it at the terminal rather than deliver a short success.
                st->error_seen = true;
            }
            return;
        } else if (!done) {
            return;
        }
        auto state = reclaim_state(user_data);
        if (!state->error_seen) {
            state->outcome = Result<std::vector<std::byte>>::success(
                std::move(state->accumulated));
        }
        deliver(state);
    }
};

// ---- Connection / auth / discovery awaiters --------------------------------

struct connection_awaiter : awaiter_base<Connection> {
    static void on_complete(
        OvStorage_Status /* status */,
        OvStorage_Connection* connection,
        const OvStorage_Error* error,
        void* user_data) noexcept
    {
        complete(user_data, [&](auto& state) {
            if (error != nullptr) {
                state.outcome = Result<Connection>::failure(Error(*error));
            } else {
                state.outcome =
                    Result<Connection>::success(Connection(connection));
            }
        });
    }
};

struct connection_list_awaiter : awaiter_base<ConnectionList> {
    static void on_complete(
        OvStorage_Status /* status */,
        OvStorage_ConnectionList* list,
        const OvStorage_Error* error,
        void* user_data) noexcept
    {
        complete(user_data, [&](auto& state) {
            if (error != nullptr) {
                state.outcome = Result<ConnectionList>::failure(Error(*error));
            } else {
                state.outcome =
                    Result<ConnectionList>::success(ConnectionList(list));
            }
        });
    }
};

struct root_info_list_awaiter : awaiter_base<RootInfoList> {
    static void on_complete(
        OvStorage_Status /* status */,
        OvStorage_RootInfoList* list,
        const OvStorage_Error* error,
        void* user_data) noexcept
    {
        complete(user_data, [&](auto& state) {
            if (error != nullptr) {
                state.outcome = Result<RootInfoList>::failure(Error(*error));
            } else {
                state.outcome =
                    Result<RootInfoList>::success(RootInfoList(list));
            }
        });
    }
};

/// Drain-to-vector for the multi-fire AuthEvent stream. Suitable for
/// auth flows that terminate (succeed/fail/cancel); not appropriate
/// for unbounded continuous streams.
///
/// `observer`, when set, is handed each event AS IT ARRIVES, before the
/// flow terminates. Interactive authentication does not work otherwise: a
/// device-code flow emits its verification URL and user code and then polls
/// until the user acts, so a host that only sees the events after the task
/// resolves shows the user what to do after it was needed.
struct auth_event_drain_state : awaiter_state<std::vector<AuthEvent>> {
    std::vector<AuthEvent> events;
    bool error_seen = false;
    std::function<void(const AuthEvent&)> observer;
    /// Set once the observer has thrown; it is not called again.
    bool observer_failed = false;
};

struct auth_event_drain_awaiter
    : awaiter_base<std::vector<AuthEvent>, auth_event_drain_state> {
    /// `noexcept` because this is a C callback: the stream pump that invokes
    /// it is a C frame, and unwinding an exception through one is undefined
    /// and would skip the pump's own stream and user-data cleanup. The body
    /// catches what it can and the qualifier makes anything it misses a
    /// diagnosable abort here rather than undefined behaviour there.
    static void on_event(
        OvStorage_AuthEvent* event,
        const OvStorage_Error* error,
        bool done,
        void* user_data) noexcept
    {
        auto* st = borrow_state(user_data);
        if (event != nullptr) {
            // Both statements below can throw — `events` allocates, and the
            // observer is user code this wrapper cannot constrain. Turn
            // either into a failed Result rather than letting it escape.
            try {
                st->events.push_back(AuthEvent(event));
                if (st->observer && !st->observer_failed) {
                    // Runs on the thread the C callback fired on, while the
                    // flow is still in progress. The event stays owned by
                    // `events`.
                    st->observer(st->events.back());
                }
            } catch (const std::exception& thrown) {
                fail_from_observer(st, thrown.what());
            } catch (...) {
                fail_from_observer(st, "unknown exception");
            }
        }
        if (error != nullptr) {
            record_c_error(*st, *error);
        }
        if (!done) {
            return;
        }
        auto state = reclaim_state(user_data);
        if (!state->error_seen) {
            state->outcome = Result<std::vector<AuthEvent>>::success(
                std::move(state->events));
        }
        deliver(state);
    }

    /// Record a host-side failure and stop calling the observer. The flow is
    /// left to run to its own terminal — there is no way to cancel it from
    /// inside the callback — but its result is now this failure.
    static void fail_from_observer(
        auth_event_drain_state* st, const char* what) noexcept
    {
        st->observer_failed = true;
        st->error_seen = true;
        try {
            st->outcome = Result<std::vector<AuthEvent>>::failure(Error(
                OvStorage_Status_Internal,
                std::string("the auth event observer threw: ") + what));
        } catch (...) {
            // Even building the message failed. Report without one rather
            // than let this escape into the C frame.
            st->outcome = Result<std::vector<AuthEvent>>::failure(
                Error(OvStorage_Status_Internal, std::string{}));
        }
    }
};

struct watch_event_state : awaiter_state<void> {
    bool error_seen = false;
    std::function<void(const BackendChangeEvent&)> observer;
    bool observer_failed = false;
    /// Non-null only when the wrapper owns the token and may cancel it.
    const OvStorage_CancelToken* cancel = nullptr;
};

struct watch_event_awaiter
    : awaiter_base<void, watch_event_state> {
    static void on_event(
        const OvStorage_BackendChangeEvent* event,
        const OvStorage_Error* error,
        bool done,
        void* user_data) noexcept
    {
        auto* st = borrow_state(user_data);
        if (event != nullptr) {
            try {
                BackendChangeEvent value(*event);
                if (st->observer && !st->observer_failed) {
                    st->observer(value);
                }
            } catch (const std::exception& thrown) {
                fail_from_observer(st, thrown.what());
            } catch (...) {
                fail_from_observer(st, "unknown exception");
            }
        }
        if (error != nullptr && !st->observer_failed) {
            record_c_error(*st, *error);
        }
        if (!done) {
            return;
        }
        auto state = reclaim_state(user_data);
        if (!state->error_seen) {
            state->outcome = Result<void>::success();
        }
        deliver(state);
    }

    static void fail_from_observer(
        watch_event_state* st, const char* what) noexcept
    {
        st->observer_failed = true;
        st->error_seen = true;
        try {
            st->outcome = Result<void>::failure(Error(
                    OvStorage_Status_Internal,
                    std::string("the watch event observer threw: ") + what));
        } catch (...) {
            st->outcome = Result<void>::failure(
                Error(OvStorage_Status_Internal, std::string{}));
        }
        if (st->cancel != nullptr) {
            ovstorage_cancel_token_cancel(st->cancel);
        }
    }
};

// Every C-callback thunk in this header, one line each. The runtime invokes
// them from C frames, and unwinding an exception through one is undefined, so
// dropping a `noexcept` must be a compile failure rather than a silent
// weakening that looks identical in review. `stack_build_awaiter` is asserted
// beside its own definition, below `LayerHandle`.
static_assert(noexcept(status_awaiter::on_complete(
                  OvStorage_Status_Ok, nullptr, nullptr)),
              "status_awaiter::on_complete must be noexcept");
static_assert(noexcept(info_awaiter::on_complete(
                  OvStorage_Status_Ok, nullptr, nullptr, nullptr)),
              "info_awaiter::on_complete must be noexcept");
static_assert(noexcept(write_redirect_awaiter::on_complete(
                  OvStorage_Status_Ok, nullptr, nullptr, nullptr)),
              "write_redirect_awaiter::on_complete must be noexcept");
static_assert(noexcept(write_step_awaiter::on_complete(
                  OvStorage_Status_Ok, nullptr, nullptr, nullptr, nullptr)),
              "write_step_awaiter::on_complete must be noexcept");
static_assert(noexcept(read_bytes_awaiter::on_complete(
                  OvStorage_Status_Ok, OvStorage_Bytes{}, nullptr, nullptr,
                  nullptr)),
              "read_bytes_awaiter::on_complete must be noexcept");
static_assert(noexcept(local_delegate_awaiter::on_complete(
                  OvStorage_Status_Ok, nullptr, nullptr, nullptr)),
              "local_delegate_awaiter::on_complete must be noexcept");
static_assert(noexcept(list_awaiter::on_complete(
                  OvStorage_Status_Ok, nullptr, nullptr, nullptr)),
              "list_awaiter::on_complete must be noexcept");
static_assert(noexcept(list_versions_awaiter::on_complete(
                  OvStorage_Status_Ok, nullptr, nullptr, nullptr)),
              "list_versions_awaiter::on_complete must be noexcept");
static_assert(noexcept(check_access_awaiter::on_complete(
                  OvStorage_Status_Ok, OvStorage_AccessDecision{}, nullptr,
                  nullptr)),
              "check_access_awaiter::on_complete must be noexcept");
static_assert(noexcept(read_stream_awaiter::on_chunk(
                  OvStorage_Bytes{}, nullptr, true, nullptr)),
              "read_stream_awaiter::on_chunk must be noexcept");
static_assert(noexcept(connection_awaiter::on_complete(
                  OvStorage_Status_Ok, nullptr, nullptr, nullptr)),
              "connection_awaiter::on_complete must be noexcept");
static_assert(noexcept(connection_list_awaiter::on_complete(
                  OvStorage_Status_Ok, nullptr, nullptr, nullptr)),
              "connection_list_awaiter::on_complete must be noexcept");
static_assert(noexcept(root_info_list_awaiter::on_complete(
                  OvStorage_Status_Ok, nullptr, nullptr, nullptr)),
              "root_info_list_awaiter::on_complete must be noexcept");
static_assert(noexcept(auth_event_drain_awaiter::on_event(
                  nullptr, nullptr, true, nullptr)),
              "auth_event_drain_awaiter::on_event must be noexcept");
static_assert(noexcept(watch_event_awaiter::on_event(
                  nullptr, nullptr, true, nullptr)),
              "watch_event_awaiter::on_event must be noexcept");

} // namespace detail

// ---------------------------------------------------------------------------
// Registry — `kind` → factory map seeded with the built-in factories.
// ---------------------------------------------------------------------------

class Plugin; // fwd

class Registry {
public:
    Registry() : handle_(ovstorage_registry_create()) {}

    ~Registry() { reset(); }
    Registry(const Registry&) = delete;
    Registry& operator=(const Registry&) = delete;

    Registry(Registry&& other) noexcept : handle_(std::exchange(other.handle_, nullptr)) {}
    Registry& operator=(Registry&& other) noexcept
    {
        if (this != &other) {
            reset();
            handle_ = std::exchange(other.handle_, nullptr);
        }
        return *this;
    }

    /// Register every kind the loaded plugin advertises. The plugin
    /// handle is borrowed (its factory Arcs are cloned), so the caller
    /// still owns and must keep the Plugin alive as long as the registry
    /// (and any Stack built from it) needs the plugin's kinds.
    Result<void> add_plugin(const Plugin& plugin);

    const OvStorage_Registry* get() const noexcept { return handle_; }

private:
    void reset()
    {
        if (handle_ != nullptr) {
            ovstorage_registry_destroy(handle_);
            handle_ = nullptr;
        }
    }
    OvStorage_Registry* handle_ = nullptr;
};

// ---------------------------------------------------------------------------
// Plugin — a loaded cdylib's factories.
// ---------------------------------------------------------------------------

class Plugin {
public:
    Plugin() = default;
    explicit Plugin(OvStorage_Plugin* handle) : handle_(handle) {}

    ~Plugin() { reset(); }
    Plugin(const Plugin&) = delete;
    Plugin& operator=(const Plugin&) = delete;

    Plugin(Plugin&& other) noexcept : handle_(std::exchange(other.handle_, nullptr)) {}
    Plugin& operator=(Plugin&& other) noexcept
    {
        if (this != &other) {
            reset();
            handle_ = std::exchange(other.handle_, nullptr);
        }
        return *this;
    }

    /// Load a plugin cdylib at `path`. Set `allow_test_plugins` only for
    /// tests. Caller must trust the path — `dlopen` runs platform loader
    /// hooks.
    static Result<Plugin> load(std::string path, bool allow_test_plugins = false)
    {
        if (auto bad = detail::invalid_c_input({{"path", path}})) {
            return detail::invalid_c_input_result<Plugin>(bad);
        }
        OvStorage_Plugin* h = nullptr;
        OvStorage_Error err{};
        auto status =
            ovstorage_load_plugin(path.c_str(), allow_test_plugins, &h, &err);
        if (status != OvStorage_Status_Ok) {
            return Result<Plugin>::failure(take_error(err));
        }
        return Result<Plugin>::success(Plugin(h));
    }

    /// Inspect the Layer kinds a plugin provides without composing them
    /// into a Stack. Each call permanently pins the cdylib for the rest
    /// of the process lifetime — inspect a given plugin once.
    static Result<KindDescriptorList> inspect(
        std::string path, bool allow_test_plugins = false)
    {
        if (auto bad = detail::invalid_c_input({{"path", path}})) {
            return detail::invalid_c_input_result<KindDescriptorList>(bad);
        }
        OvStorage_KindDescriptorList* h = nullptr;
        OvStorage_Error err{};
        auto status =
            ovstorage_inspect_plugin(path.c_str(), allow_test_plugins, &h, &err);
        if (status != OvStorage_Status_Ok) {
            return Result<KindDescriptorList>::failure(take_error(err));
        }
        return Result<KindDescriptorList>::success(KindDescriptorList(h));
    }

    const OvStorage_Plugin* get() const noexcept { return handle_; }

private:
    void reset()
    {
        if (handle_ != nullptr) {
            ovstorage_plugin_destroy(handle_);
            handle_ = nullptr;
        }
    }
    OvStorage_Plugin* handle_ = nullptr;
};

inline Result<void> Registry::add_plugin(const Plugin& plugin)
{
    OvStorage_Error err{};
    auto status = ovstorage_registry_add_plugin(handle_, plugin.get(), &err);
    if (status != OvStorage_Status_Ok) {
        return Result<void>::failure(take_error(err));
    }
    return Result<void>::success();
}

// ---------------------------------------------------------------------------
// LayerHandle — the built, immutable Stack root (declared before Stack so
// Stack::build can return one).
// ---------------------------------------------------------------------------

class LayerHandle {
public:
    LayerHandle() = default;
    explicit LayerHandle(OvStorage_LayerHandle* handle) : handle_(handle) {}

    ~LayerHandle() { reset(); }
    LayerHandle(const LayerHandle&) = delete;
    LayerHandle& operator=(const LayerHandle&) = delete;

    LayerHandle(LayerHandle&& other) noexcept
        : handle_(std::exchange(other.handle_, nullptr))
    {
    }
    LayerHandle& operator=(LayerHandle&& other) noexcept
    {
        if (this != &other) {
            reset();
            handle_ = std::exchange(other.handle_, nullptr);
        }
        return *this;
    }

    OvStorage_LayerHandle* get() const noexcept { return handle_; }

    // -----------------------------------------------------------------
    // Async object-I/O. Each returns task<T>, and the task is EAGER: the
    // operation is submitted by the call itself, not by the await. So
    //
    //     auto pending = layer.delete_object(address);
    //
    // has already asked for the delete; `co_await` (or `sync_wait`) only
    // collects the result, and dropping the task without awaiting does not
    // undo it. Do not construct one of these expecting it to be inert.
    // Object-I/O ops take a `const OvStorage_LayerHandle*`.
    // -----------------------------------------------------------------

    task<Info> stat(
        std::string address,
        bool full_metadata = false,
        const CancelToken* cancel = nullptr) const
    {
        if (handle_ == nullptr) co_return detail::null_handle_result<Info>();
        if (auto bad = detail::invalid_c_input({{"address", address}})) {
            co_return detail::invalid_c_input_result<Info>(bad);
        }
        struct op : detail::info_awaiter {
            const OvStorage_LayerHandle* handle;
            std::string addr;
            OvStorage_StatOptions opts;
            const OvStorage_CancelToken* cancel;
            bool await_suspend(body_handle h)
            {
                s->continuation = h;
                ovstorage_stat(handle, addr.c_str(), &opts, cancel,
                    &info_awaiter::on_complete, release_user_data());
                return commit_suspend(h);
            }
        };
        op a{};
        a.handle = handle_;
        a.addr = std::move(address);
        a.opts = OvStorage_StatOptions{};
        a.opts.full_metadata = full_metadata;
        a.cancel = CancelToken::as_ptr(cancel);
        co_return co_await a;
    }

    // Each read verb comes in two forms rather than one method with a
    // defaulted `options`. `cancel` is positional, so a parameter placed ahead
    // of it would change what `read_bytes(address, cancel)` means at every call
    // site that already spells it that way. The three-parameter form puts
    // `options` where `get_latest_version` and the Rust surface put it.
    //
    // A range is honoured by the backend, not by the wrapper: `read_local_file`
    // materializes, and a backend whose materialize refuses a window (the
    // `file://` one does) answers `InvalidArgument`.

    task<std::pair<Bytes, Info>> read_bytes(
        std::string address,
        const CancelToken* cancel = nullptr) const
    {
        return read_bytes(std::move(address), ReadOptions{}, cancel);
    }

    task<std::pair<Bytes, Info>> read_bytes(
        std::string address,
        ReadOptions options,
        const CancelToken* cancel = nullptr) const
    {
        if (handle_ == nullptr) {
            co_return detail::null_handle_result<std::pair<Bytes, Info>>();
        }
        if (auto bad = detail::invalid_c_input({{"address", address}})) {
            co_return detail::invalid_c_input_result<std::pair<Bytes, Info>>(bad);
        }
        if (!detail::read_range_is_expressible(options)) {
            co_return Result<std::pair<Bytes, Info>>::failure(
                detail::unexpressible_read_range_error());
        }
        if (!detail::read_range_is_ordered(options)) {
            co_return Result<std::pair<Bytes, Info>>::failure(
                detail::inverted_read_range_error());
        }
        struct op : detail::read_bytes_awaiter {
            const OvStorage_LayerHandle* handle;
            std::string addr;
            OvStorage_ReadOptions raw_options;
            const OvStorage_CancelToken* cancel;
            bool await_suspend(body_handle h)
            {
                s->continuation = h;
                ovstorage_read_bytes(handle, addr.c_str(), &raw_options, cancel,
                    &read_bytes_awaiter::on_complete, release_user_data());
                return commit_suspend(h);
            }
        };
        op a{};
        a.handle = handle_;
        a.addr = std::move(address);
        a.raw_options = detail::to_raw_read_options(options);
        a.cancel = CancelToken::as_ptr(cancel);
        co_return co_await a;
    }

    task<std::vector<std::byte>> read_stream(
        std::string address,
        const CancelToken* cancel = nullptr) const
    {
        return read_stream(std::move(address), ReadOptions{}, cancel);
    }

    task<std::vector<std::byte>> read_stream(
        std::string address,
        ReadOptions options,
        const CancelToken* cancel = nullptr) const
    {
        if (handle_ == nullptr) {
            co_return detail::null_handle_result<std::vector<std::byte>>();
        }
        if (auto bad = detail::invalid_c_input({{"address", address}})) {
            co_return detail::invalid_c_input_result<std::vector<std::byte>>(bad);
        }
        if (!detail::read_range_is_expressible(options)) {
            co_return Result<std::vector<std::byte>>::failure(
                detail::unexpressible_read_range_error());
        }
        if (!detail::read_range_is_ordered(options)) {
            co_return Result<std::vector<std::byte>>::failure(
                detail::inverted_read_range_error());
        }
        struct op : detail::read_stream_awaiter {
            const OvStorage_LayerHandle* handle;
            std::string addr;
            OvStorage_ReadOptions raw_options;
            const OvStorage_CancelToken* cancel;
            bool await_suspend(body_handle h)
            {
                s->continuation = h;
                ovstorage_read_stream(handle, addr.c_str(), &raw_options, cancel,
                    &read_stream_awaiter::on_chunk, release_user_data());
                return commit_suspend(h);
            }
        };
        op a{};
        a.handle = handle_;
        a.addr = std::move(address);
        a.raw_options = detail::to_raw_read_options(options);
        a.cancel = CancelToken::as_ptr(cancel);
        co_return co_await a;
    }

    task<LocalDelegate> read_local_file(
        std::string address,
        const CancelToken* cancel = nullptr) const
    {
        return read_local_file(std::move(address), ReadOptions{}, cancel);
    }

    task<LocalDelegate> read_local_file(
        std::string address,
        ReadOptions options,
        const CancelToken* cancel = nullptr) const
    {
        if (handle_ == nullptr) co_return detail::null_handle_result<LocalDelegate>();
        if (auto bad = detail::invalid_c_input({{"address", address}})) {
            co_return detail::invalid_c_input_result<LocalDelegate>(bad);
        }
        if (!detail::read_range_is_expressible(options)) {
            co_return Result<LocalDelegate>::failure(
                detail::unexpressible_read_range_error());
        }
        if (!detail::read_range_is_ordered(options)) {
            co_return Result<LocalDelegate>::failure(
                detail::inverted_read_range_error());
        }
        struct op : detail::local_delegate_awaiter {
            const OvStorage_LayerHandle* handle;
            std::string addr;
            OvStorage_ReadOptions raw_options;
            const OvStorage_CancelToken* cancel;
            bool await_suspend(body_handle h)
            {
                s->continuation = h;
                ovstorage_read_local_file(handle, addr.c_str(), &raw_options,
                    cancel, &local_delegate_awaiter::on_complete,
                    release_user_data());
                return commit_suspend(h);
            }
        };
        op a{};
        a.handle = handle_;
        a.addr = std::move(address);
        a.raw_options = detail::to_raw_read_options(options);
        a.cancel = CancelToken::as_ptr(cancel);
        co_return co_await a;
    }

    task<Info> write(
        std::string address,
        std::span<const std::byte> data,
        bool no_overwrite = false,
        const CancelToken* cancel = nullptr) const
    {
        WriteOptions options;
        options.no_overwrite = no_overwrite;
        return write(std::move(address), data, std::move(options), cancel);
    }

    task<Info> write(
        std::string address,
        std::span<const std::byte> data,
        WriteOptions options,
        const CancelToken* cancel = nullptr) const
    {
        if (handle_ == nullptr) co_return detail::null_handle_result<Info>();
        if (auto bad = detail::invalid_c_input({{"address", address}})) {
            co_return detail::invalid_c_input_result<Info>(bad);
        }
        if (options.if_match_etag.has_value()) {
            if (auto bad = detail::invalid_c_input(
                    {{"if_match_etag", *options.if_match_etag}})) {
                co_return detail::invalid_c_input_result<Info>(bad);
            }
        }
        struct op : detail::info_awaiter {
            const OvStorage_LayerHandle* handle;
            std::string addr;
            const std::uint8_t* data_ptr;
            std::size_t data_len;
            std::string etag;
            bool has_etag;
            OvStorage_WriteOptions opts;
            const OvStorage_CancelToken* cancel;
            bool await_suspend(body_handle h)
            {
                s->continuation = h;
                // Points into this awaiter's own `etag`, taken here
                // alongside `addr.c_str()` for the same reason: the C entry
                // point borrows both only for the duration of the call.
                opts.if_match_etag = has_etag ? etag.c_str() : nullptr;
                ovstorage_write(handle, addr.c_str(), data_ptr, data_len, &opts, cancel,
                    &info_awaiter::on_complete, release_user_data());
                return commit_suspend(h);
            }
        };
        op a{};
        a.handle = handle_;
        a.addr = std::move(address);
        a.data_ptr = reinterpret_cast<const std::uint8_t*>(data.data());
        a.data_len = data.size();
        a.has_etag = options.if_match_etag.has_value();
        a.etag = options.if_match_etag.value_or(std::string{});
        a.opts = OvStorage_WriteOptions{};
        a.opts.no_overwrite = options.no_overwrite;
        a.cancel = CancelToken::as_ptr(cancel);
        co_return co_await a;
    }

    task<Info> write_stream(
        std::string address,
        WriteStream&& stream,
        bool no_overwrite = false,
        std::optional<std::uint64_t> size_hint = std::nullopt,
        const CancelToken* cancel = nullptr) const
    {
        WriteOptions options;
        options.no_overwrite = no_overwrite;
        options.size_hint = size_hint;
        return write_stream(
            std::move(address), std::move(stream), std::move(options), cancel);
    }

    task<Info> write_stream(
        std::string address,
        WriteStream&& stream,
        WriteOptions options,
        const CancelToken* cancel = nullptr) const
    {
        if (handle_ == nullptr) co_return detail::null_handle_result<Info>();
        if (auto bad = detail::invalid_c_input({{"address", address}})) {
            co_return detail::invalid_c_input_result<Info>(bad);
        }
        if (options.if_match_etag.has_value()) {
            if (auto bad = detail::invalid_c_input(
                    {{"if_match_etag", *options.if_match_etag}})) {
                co_return detail::invalid_c_input_result<Info>(bad);
            }
        }
        if (!stream.valid()) {
            co_return Result<Info>::failure(Error(
                OvStorage_Status_InvalidArgument,
                "write stream requires both next and drop callbacks"));
        }
        struct op : detail::info_awaiter {
            const OvStorage_LayerHandle* handle;
            std::string addr;
            OvStorage_WriteStream stream;
            std::string etag;
            bool has_etag;
            OvStorage_WriteOptions opts;
            const OvStorage_CancelToken* cancel;
            bool await_suspend(body_handle h)
            {
                s->continuation = h;
                opts.if_match_etag = has_etag ? etag.c_str() : nullptr;
                ovstorage_write_stream(
                    handle, addr.c_str(), &stream, &opts, cancel,
                    &info_awaiter::on_complete, release_user_data());
                if (stream.drop != nullptr) {
                    stream.drop(stream.state);
                    stream = OvStorage_WriteStream{};
                }
                return commit_suspend(h);
            }
        };
        op a{};
        a.handle = handle_;
        a.addr = std::move(address);
        a.stream = stream.release();
        a.has_etag = options.if_match_etag.has_value();
        a.etag = options.if_match_etag.value_or(std::string{});
        a.opts = OvStorage_WriteOptions{};
        a.opts.no_overwrite = options.no_overwrite;
        a.opts.has_size_hint = options.size_hint.has_value();
        a.opts.size_hint = options.size_hint.value_or(0);
        a.cancel = CancelToken::as_ptr(cancel);
        co_return co_await a;
    }

    task<WriteRedirectBatch> write_redirect(
        std::string address,
        bool no_overwrite = false,
        std::optional<std::uint64_t> size_hint = std::nullopt,
        const CancelToken* cancel = nullptr) const
    {
        WriteOptions options;
        options.no_overwrite = no_overwrite;
        options.size_hint = size_hint;
        return write_redirect(
            std::move(address), std::move(options), cancel);
    }

    task<WriteRedirectBatch> write_redirect(
        std::string address,
        WriteOptions options,
        const CancelToken* cancel = nullptr) const
    {
        if (handle_ == nullptr) {
            co_return detail::null_handle_result<WriteRedirectBatch>();
        }
        if (auto bad = detail::invalid_c_input({{"address", address}})) {
            co_return detail::invalid_c_input_result<WriteRedirectBatch>(bad);
        }
        if (options.if_match_etag.has_value()) {
            if (auto bad = detail::invalid_c_input(
                    {{"if_match_etag", *options.if_match_etag}})) {
                co_return detail::invalid_c_input_result<WriteRedirectBatch>(
                    bad);
            }
        }
        struct op : detail::write_redirect_awaiter {
            const OvStorage_LayerHandle* handle;
            std::string addr;
            std::string etag;
            bool has_etag;
            OvStorage_WriteOptions opts;
            const OvStorage_CancelToken* cancel;
            bool await_suspend(body_handle h)
            {
                s->continuation = h;
                opts.if_match_etag = has_etag ? etag.c_str() : nullptr;
                ovstorage_write_redirect(
                    handle, addr.c_str(), &opts, cancel,
                    &write_redirect_awaiter::on_complete,
                    release_user_data());
                return commit_suspend(h);
            }
        };
        op a{};
        a.handle = handle_;
        a.addr = std::move(address);
        a.has_etag = options.if_match_etag.has_value();
        a.etag = options.if_match_etag.value_or(std::string{});
        a.opts = OvStorage_WriteOptions{};
        a.opts.no_overwrite = options.no_overwrite;
        a.opts.has_size_hint = options.size_hint.has_value();
        a.opts.size_hint = options.size_hint.value_or(0);
        a.cancel = CancelToken::as_ptr(cancel);
        co_return co_await a;
    }

    task<WriteStep> continue_write(
        std::string address,
        const WriteRedirectBatch& redirects,
        std::vector<RedirectResult> results,
        const CancelToken* cancel = nullptr) const
    {
        if (handle_ == nullptr) {
            co_return detail::null_handle_result<WriteStep>();
        }
        if (auto bad = detail::invalid_c_input({{"address", address}})) {
            co_return detail::invalid_c_input_result<WriteStep>(bad);
        }
        if (redirects.get() == nullptr) {
            co_return Result<WriteStep>::failure(Error(
                OvStorage_Status_InvalidArgument,
                "redirect batch is null"));
        }
        if (results.size() != redirects.size()) {
            co_return Result<WriteStep>::failure(Error(
                OvStorage_Status_InvalidArgument,
                "redirect result count does not match redirect count"));
        }
        for (const auto& result : results) {
            for (const auto& header : result.captured_headers) {
                if (auto bad = detail::invalid_c_input(
                        {{"header name", header.first},
                         {"header value", header.second}})) {
                    co_return detail::invalid_c_input_result<WriteStep>(bad);
                }
            }
        }
        struct op : detail::write_step_awaiter {
            const OvStorage_LayerHandle* handle;
            std::string addr;
            const OvStorage_WriteRedirectBatch* redirects;
            std::vector<RedirectResult> results;
            std::vector<std::vector<OvStorage_Header>> headers;
            std::vector<OvStorage_RedirectResult> raw_results;
            OvStorage_RedirectResultBatch batch;
            const OvStorage_CancelToken* cancel;
            bool await_suspend(body_handle h)
            {
                s->continuation = h;
                headers.resize(results.size());
                raw_results.resize(results.size());
                for (std::size_t i = 0; i < results.size(); ++i) {
                    auto& raw_headers = headers[i];
                    raw_headers.reserve(results[i].captured_headers.size());
                    for (const auto& header : results[i].captured_headers) {
                        raw_headers.push_back(OvStorage_Header{
                            header.first.c_str(), header.second.c_str()});
                    }
                    raw_results[i] = OvStorage_RedirectResult{
                        results[i].status_code,
                        raw_headers.empty() ? nullptr : raw_headers.data(),
                        raw_headers.size(),
                        results[i].captured_body.empty()
                            ? nullptr
                            : results[i].captured_body.data(),
                        results[i].captured_body.size()};
                }
                batch = OvStorage_RedirectResultBatch{
                    raw_results.empty() ? nullptr : raw_results.data(),
                    raw_results.size()};
                ovstorage_continue_write(
                    handle, addr.c_str(), redirects, &batch, cancel,
                    &write_step_awaiter::on_complete, release_user_data());
                return commit_suspend(h);
            }
        };
        op a{};
        a.handle = handle_;
        a.addr = std::move(address);
        a.redirects = redirects.get();
        a.results = std::move(results);
        a.batch = OvStorage_RedirectResultBatch{};
        a.cancel = CancelToken::as_ptr(cancel);
        co_return co_await a;
    }

    task<Info> get_latest_version(
        std::string address,
        ReadOptions options = {},
        const CancelToken* cancel = nullptr) const
    {
        if (handle_ == nullptr) co_return detail::null_handle_result<Info>();
        if (auto bad = detail::invalid_c_input({{"address", address}})) {
            co_return detail::invalid_c_input_result<Info>(bad);
        }
        if (!detail::read_range_is_expressible(options)) {
            co_return Result<Info>::failure(
                detail::unexpressible_read_range_error());
        }
        if (!detail::read_range_is_ordered(options)) {
            co_return Result<Info>::failure(
                detail::inverted_read_range_error());
        }
        struct op : detail::info_awaiter {
            const OvStorage_LayerHandle* handle;
            std::string addr;
            OvStorage_ReadOptions raw_options;
            const OvStorage_CancelToken* cancel;
            bool await_suspend(body_handle h)
            {
                s->continuation = h;
                ovstorage_get_latest_version(
                    handle, addr.c_str(), &raw_options, cancel,
                    &info_awaiter::on_complete, release_user_data());
                return commit_suspend(h);
            }
        };
        op a{};
        a.handle = handle_;
        a.addr = std::move(address);
        a.raw_options = detail::to_raw_read_options(options);
        a.cancel = CancelToken::as_ptr(cancel);
        co_return co_await a;
    }

    /// Observe a continuous watch stream until it terminates or is cancelled.
    /// Events are delivered to `on_event` as they arrive and are not retained
    /// by the wrapper. The observer runs on the C callback thread; an exception
    /// is contained and returned as an Internal failure.
    task<void> watch_directory(
        std::string prefix,
        WatchDirectoryOptions options = {},
        const CancelToken* cancel = nullptr,
        std::function<void(const BackendChangeEvent&)> on_event = {}) const
    {
        if (handle_ == nullptr) {
            co_return detail::null_handle_result<void>();
        }
        if (auto bad = detail::invalid_c_input({{"prefix", prefix}})) {
            co_return detail::invalid_c_input_result<void>(bad);
        }
        struct op : detail::watch_event_awaiter {
            const OvStorage_LayerHandle* handle;
            std::string prefix;
            WatchDirectoryOptions options;
            OvStorage_WatchDirectoryOptions raw_options;
            std::optional<CancelToken> owned_cancel;
            const OvStorage_CancelToken* cancel;
            bool await_suspend(body_handle h)
            {
                s->continuation = h;
                raw_options = OvStorage_WatchDirectoryOptions{};
                raw_options.recursive = options.recursive;
                raw_options.include_metadata_changes =
                    options.include_metadata_changes;
                raw_options.since =
                    options.since.empty() ? nullptr : options.since.data();
                raw_options.since_len = options.since.size();
                raw_options.has_since =
                    options.has_since || !options.since.empty();
                raw_options.poll_interval_ms = options.poll_interval_ms;
                ovstorage_watch_directory(
                    handle, prefix.c_str(), &raw_options, cancel,
                    &watch_event_awaiter::on_event,
                    release_user_data());
                return commit_suspend(h);
            }
        };
        op a{};
        a.handle = handle_;
        a.prefix = std::move(prefix);
        a.options = std::move(options);
        a.raw_options = OvStorage_WatchDirectoryOptions{};
        a.cancel = CancelToken::as_ptr(cancel);
        if (a.cancel == nullptr) {
            a.owned_cancel.emplace();
            a.cancel = a.owned_cancel->get();
            a.s->cancel = a.cancel;
        }
        a.s->observer = std::move(on_event);
        co_return co_await a;
    }

    task<void> delete_object(
        std::string address,
        const CancelToken* cancel = nullptr) const
    {
        if (handle_ == nullptr) co_return detail::null_handle_result<void>();
        if (auto bad = detail::invalid_c_input({{"address", address}})) {
            co_return detail::invalid_c_input_result<void>(bad);
        }
        struct op : detail::status_awaiter {
            const OvStorage_LayerHandle* handle;
            std::string addr;
            const OvStorage_CancelToken* cancel;
            bool await_suspend(body_handle h)
            {
                s->continuation = h;
                ovstorage_delete(handle, addr.c_str(), cancel,
                    &status_awaiter::on_complete, release_user_data());
                return commit_suspend(h);
            }
        };
        op a{};
        a.handle = handle_;
        a.addr = std::move(address);
        a.cancel = CancelToken::as_ptr(cancel);
        co_return co_await a;
    }

    task<List> list(
        std::string prefix,
        bool recursive = false,
        std::uint32_t max_results = 0,
        std::string page_token = {},
        bool full_metadata = false,
        const CancelToken* cancel = nullptr) const
    {
        if (handle_ == nullptr) co_return detail::null_handle_result<List>();
        if (auto bad = detail::invalid_c_input({{"prefix", prefix}, {"page_token", page_token}})) {
            co_return detail::invalid_c_input_result<List>(bad);
        }
        struct op : detail::list_awaiter {
            const OvStorage_LayerHandle* handle;
            std::string prefix;
            std::string token;
            OvStorage_ListOptions opts;
            const OvStorage_CancelToken* cancel;
            bool await_suspend(body_handle h)
            {
                s->continuation = h;
                opts.page_token = token.empty() ? nullptr : token.c_str();
                ovstorage_list(handle, prefix.c_str(), &opts, cancel,
                    &list_awaiter::on_complete, release_user_data());
                return commit_suspend(h);
            }
        };
        op a{};
        a.handle = handle_;
        a.prefix = std::move(prefix);
        a.token = std::move(page_token);
        a.opts = OvStorage_ListOptions{};
        a.opts.recursive = recursive;
        a.opts.has_max_results = max_results != 0;
        a.opts.max_results = max_results;
        a.opts.full_metadata = full_metadata;
        a.cancel = CancelToken::as_ptr(cancel);
        co_return co_await a;
    }

    task<VersionList> list_versions(
        std::string address,
        std::uint32_t max_results = 0,
        std::string page_token = {},
        const CancelToken* cancel = nullptr) const
    {
        if (handle_ == nullptr) co_return detail::null_handle_result<VersionList>();
        if (auto bad = detail::invalid_c_input({{"address", address}, {"page_token", page_token}})) {
            co_return detail::invalid_c_input_result<VersionList>(bad);
        }
        struct op : detail::list_versions_awaiter {
            const OvStorage_LayerHandle* handle;
            std::string addr;
            std::string token;
            OvStorage_ListVersionsOptions opts;
            const OvStorage_CancelToken* cancel;
            bool await_suspend(body_handle h)
            {
                s->continuation = h;
                opts.page_token = token.empty() ? nullptr : token.c_str();
                ovstorage_list_versions(handle, addr.c_str(), &opts, cancel,
                    &list_versions_awaiter::on_complete, release_user_data());
                return commit_suspend(h);
            }
        };
        op a{};
        a.handle = handle_;
        a.addr = std::move(address);
        a.token = std::move(page_token);
        a.opts = OvStorage_ListVersionsOptions{};
        a.opts.has_max_results = max_results != 0;
        a.opts.max_results = max_results;
        a.cancel = CancelToken::as_ptr(cancel);
        co_return co_await a;
    }

    task<Info> copy(
        std::string src,
        std::string dest,
        const CancelToken* cancel = nullptr) const
    {
        if (handle_ == nullptr) co_return detail::null_handle_result<Info>();
        if (auto bad = detail::invalid_c_input({{"src", src}, {"dest", dest}})) {
            co_return detail::invalid_c_input_result<Info>(bad);
        }
        struct op : detail::info_awaiter {
            const OvStorage_LayerHandle* handle;
            std::string src;
            std::string dest;
            const OvStorage_CancelToken* cancel;
            bool await_suspend(body_handle h)
            {
                s->continuation = h;
                ovstorage_copy(handle, src.c_str(), dest.c_str(), cancel,
                    &info_awaiter::on_complete, release_user_data());
                return commit_suspend(h);
            }
        };
        op a{};
        a.handle = handle_;
        a.src = std::move(src);
        a.dest = std::move(dest);
        a.cancel = CancelToken::as_ptr(cancel);
        co_return co_await a;
    }

    task<void> rename(
        std::string src,
        std::string dest,
        const CancelToken* cancel = nullptr) const
    {
        if (handle_ == nullptr) co_return detail::null_handle_result<void>();
        if (auto bad = detail::invalid_c_input({{"src", src}, {"dest", dest}})) {
            co_return detail::invalid_c_input_result<void>(bad);
        }
        struct op : detail::status_awaiter {
            const OvStorage_LayerHandle* handle;
            std::string src;
            std::string dest;
            const OvStorage_CancelToken* cancel;
            bool await_suspend(body_handle h)
            {
                s->continuation = h;
                ovstorage_rename(handle, src.c_str(), dest.c_str(), cancel,
                    &status_awaiter::on_complete, release_user_data());
                return commit_suspend(h);
            }
        };
        op a{};
        a.handle = handle_;
        a.src = std::move(src);
        a.dest = std::move(dest);
        a.cancel = CancelToken::as_ptr(cancel);
        co_return co_await a;
    }

    task<Info> create_directory(
        std::string address,
        const CancelToken* cancel = nullptr) const
    {
        if (handle_ == nullptr) co_return detail::null_handle_result<Info>();
        if (auto bad = detail::invalid_c_input({{"address", address}})) {
            co_return detail::invalid_c_input_result<Info>(bad);
        }
        struct op : detail::info_awaiter {
            const OvStorage_LayerHandle* handle;
            std::string addr;
            const OvStorage_CancelToken* cancel;
            bool await_suspend(body_handle h)
            {
                s->continuation = h;
                ovstorage_create_directory(handle, addr.c_str(), cancel,
                    &info_awaiter::on_complete, release_user_data());
                return commit_suspend(h);
            }
        };
        op a{};
        a.handle = handle_;
        a.addr = std::move(address);
        a.cancel = CancelToken::as_ptr(cancel);
        co_return co_await a;
    }

    task<void> delete_directory(
        std::string address,
        const CancelToken* cancel = nullptr) const
    {
        if (handle_ == nullptr) co_return detail::null_handle_result<void>();
        if (auto bad = detail::invalid_c_input({{"address", address}})) {
            co_return detail::invalid_c_input_result<void>(bad);
        }
        struct op : detail::status_awaiter {
            const OvStorage_LayerHandle* handle;
            std::string addr;
            const OvStorage_CancelToken* cancel;
            bool await_suspend(body_handle h)
            {
                s->continuation = h;
                ovstorage_delete_directory(handle, addr.c_str(), cancel,
                    &status_awaiter::on_complete, release_user_data());
                return commit_suspend(h);
            }
        };
        op a{};
        a.handle = handle_;
        a.addr = std::move(address);
        a.cancel = CancelToken::as_ptr(cancel);
        co_return co_await a;
    }

    task<Info> update_metadata(
        std::string address,
        const UpdateMetadataOptions& options,
        const CancelToken* cancel = nullptr) const
    {
        if (handle_ == nullptr) co_return detail::null_handle_result<Info>();
        if (auto bad = detail::invalid_c_input({{"address", address}})) {
            co_return detail::invalid_c_input_result<Info>(bad);
        }
        struct op : detail::info_awaiter {
            const OvStorage_LayerHandle* handle;
            std::string addr;
            const OvStorage_UpdateMetadataOptions* opts;
            const OvStorage_CancelToken* cancel;
            bool await_suspend(body_handle h)
            {
                s->continuation = h;
                ovstorage_update_metadata(handle, addr.c_str(), opts, cancel,
                    &info_awaiter::on_complete, release_user_data());
                return commit_suspend(h);
            }
        };
        op a{};
        a.handle = handle_;
        a.addr = std::move(address);
        a.opts = options.get();
        a.cancel = CancelToken::as_ptr(cancel);
        co_return co_await a;
    }

    task<AccessDecision> check_access(
        std::string address,
        bool read = false,
        bool write = false,
        bool delete_object = false,
        bool update_metadata = false,
        const CancelToken* cancel = nullptr) const
    {
        if (handle_ == nullptr) co_return detail::null_handle_result<AccessDecision>();
        if (auto bad = detail::invalid_c_input({{"address", address}})) {
            co_return detail::invalid_c_input_result<AccessDecision>(bad);
        }
        struct op : detail::check_access_awaiter {
            const OvStorage_LayerHandle* handle;
            std::string addr;
            OvStorage_AccessOps ops;
            const OvStorage_CancelToken* cancel;
            bool await_suspend(body_handle h)
            {
                s->continuation = h;
                ovstorage_check_access(handle, addr.c_str(), ops, cancel,
                    &check_access_awaiter::on_complete, release_user_data());
                return commit_suspend(h);
            }
        };
        op a{};
        a.handle = handle_;
        a.addr = std::move(address);
        a.ops = OvStorage_AccessOps{read, write, delete_object, update_metadata};
        a.cancel = CancelToken::as_ptr(cancel);
        co_return co_await a;
    }

    // -----------------------------------------------------------------
    // Connection management (keyed on the built Stack root).
    // -----------------------------------------------------------------

    // Validate a connection request against the Layer named `target`
    // without registering it. Unlike `add_connection`, this borrows the
    // builder: `ovstorage_probe` copies what it needs before dispatching
    // and never consumes the handle, so `request` is owned by the caller
    // throughout and is reusable afterwards — corrected and re-probed, or
    // handed to `add_connection` once it validates.
    task<Connection> probe(
        std::string target,
        const ConnectionRequest& request,
        const CancelToken* cancel = nullptr) const
    {
        if (handle_ == nullptr) {
            co_return detail::null_handle_result<Connection>();
        }
        if (auto bad = detail::invalid_c_input({{"target", target}})) {
            co_return detail::invalid_c_input_result<Connection>(bad);
        }
        if (request.raw() == nullptr) {
            co_return Result<Connection>::failure(Error(
                OvStorage_Status_InvalidArgument,
                "connection request is null"));
        }
        struct op : detail::connection_awaiter {
            const OvStorage_LayerHandle* handle;
            std::string target;
            const OvStorage_ConnectionRequest* request;
            const OvStorage_CancelToken* cancel;
            bool await_suspend(body_handle h)
            {
                s->continuation = h;
                ovstorage_probe(
                    handle, target.c_str(), request, cancel,
                    &connection_awaiter::on_complete, release_user_data());
                return commit_suspend(h);
            }
        };
        op a{};
        a.handle = handle_;
        a.target = std::move(target);
        a.request = request.raw();
        a.cancel = CancelToken::as_ptr(cancel);
        co_return co_await a;
    }

    task<Connection> add_connection(
        std::string target,
        ConnectionRequest&& request,
        const CancelToken* cancel = nullptr) const
    {
        if (handle_ == nullptr) co_return detail::null_handle_result<Connection>();
        if (auto bad = detail::invalid_c_input({{"target", target}})) {
            co_return detail::invalid_c_input_result<Connection>(bad);
        }
        struct op : detail::connection_awaiter {
            const OvStorage_LayerHandle* handle;
            std::string target;
            OvStorage_ConnectionRequest* request;
            const OvStorage_CancelToken* cancel;
            bool await_suspend(body_handle h)
            {
                s->continuation = h;
                ovstorage_add_connection(
                    handle, target.c_str(), &request, cancel,
                    &connection_awaiter::on_complete, release_user_data());
                // Unconditional: NULL once the C side took the request,
                // and the request itself on every path that declined it —
                // including the allocator and shutdown rejections inside
                // the C prologue, which no screening out here can see.
                ovstorage_connection_request_destroy(request);
                request = nullptr;
                return commit_suspend(h);
            }
        };
        op a{};
        a.handle = handle_;
        a.target = std::move(target);
        a.request = request.release();
        a.cancel = CancelToken::as_ptr(cancel);
        co_return co_await a;
    }

    task<ConnectionList> list_connections(const CancelToken* cancel = nullptr) const
    {
        if (handle_ == nullptr) co_return detail::null_handle_result<ConnectionList>();
        struct op : detail::connection_list_awaiter {
            const OvStorage_LayerHandle* handle;
            const OvStorage_CancelToken* cancel;
            bool await_suspend(body_handle h)
            {
                s->continuation = h;
                ovstorage_list_connections(
                    handle, cancel,
                    &connection_list_awaiter::on_complete, release_user_data());
                return commit_suspend(h);
            }
        };
        op a{};
        a.handle = handle_;
        a.cancel = CancelToken::as_ptr(cancel);
        co_return co_await a;
    }

    task<void> remove_connection(
        std::string target,
        std::string connection_id,
        const CancelToken* cancel = nullptr) const
    {
        if (handle_ == nullptr) co_return detail::null_handle_result<void>();
        if (auto bad = detail::invalid_c_input({{"target", target}, {"connection_id", connection_id}})) {
            co_return detail::invalid_c_input_result<void>(bad);
        }
        struct op : detail::status_awaiter {
            const OvStorage_LayerHandle* handle;
            std::string target;
            std::string id;
            const OvStorage_CancelToken* cancel;
            bool await_suspend(body_handle h)
            {
                s->continuation = h;
                ovstorage_remove_connection(
                    handle, target.c_str(), id.c_str(), cancel,
                    &status_awaiter::on_complete, release_user_data());
                return commit_suspend(h);
            }
        };
        op a{};
        a.handle = handle_;
        a.target = std::move(target);
        a.id = std::move(connection_id);
        a.cancel = CancelToken::as_ptr(cancel);
        co_return co_await a;
    }

    // Refresh the credentials on an existing connection owned by
    // `target`. The bundle goes in through a slot that
    // `ovstorage_update_connection_credentials` NULLs exactly when it
    // consumes, and whatever survives in that slot is destroyed here —
    // which is what keeps credential material off the heap on the paths
    // where the C side declines the bundle.
    task<Connection> update_connection_credentials(
        std::string target,
        std::string connection_id,
        SecretBundle&& credentials,
        const CancelToken* cancel = nullptr) const
    {
        if (handle_ == nullptr) co_return detail::null_handle_result<Connection>();
        if (auto bad = detail::invalid_c_input({{"target", target}, {"connection_id", connection_id}})) {
            co_return detail::invalid_c_input_result<Connection>(bad);
        }
        struct op : detail::connection_awaiter {
            const OvStorage_LayerHandle* handle;
            std::string target;
            std::string id;
            OvStorage_SecretBundle* bundle;
            const OvStorage_CancelToken* cancel;
            bool await_suspend(body_handle h)
            {
                s->continuation = h;
                ovstorage_update_connection_credentials(
                    handle, target.c_str(), id.c_str(), &bundle, cancel,
                    &connection_awaiter::on_complete, release_user_data());
                // Unconditional: NULL once the C side took the bundle, and
                // the bundle itself on every path that declined it —
                // including the allocator and shutdown rejections inside
                // the C prologue, which no screening out here can see.
                // `_destroy` zeroes the secrets before freeing them.
                ovstorage_secret_bundle_destroy(bundle);
                bundle = nullptr;
                return commit_suspend(h);
            }
        };
        op a{};
        a.handle = handle_;
        a.target = std::move(target);
        a.id = std::move(connection_id);
        a.bundle = credentials.release();
        a.cancel = CancelToken::as_ptr(cancel);
        co_return co_await a;
    }

    task<Connection> update_connection_attributes(
        std::string target,
        std::string connection_id,
        ConnectionAttributePatch patch,
        const CancelToken* cancel = nullptr) const
    {
        if (handle_ == nullptr) {
            co_return detail::null_handle_result<Connection>();
        }
        if (auto bad = detail::invalid_c_input(
                {{"target", target}, {"connection_id", connection_id}})) {
            co_return detail::invalid_c_input_result<Connection>(bad);
        }
        if (patch.display_name) {
            if (auto bad = detail::invalid_c_input(
                    {{"display_name", *patch.display_name}})) {
                co_return detail::invalid_c_input_result<Connection>(bad);
            }
        }
        if (patch.access_mode) {
            if (auto bad = detail::invalid_c_input(
                    {{"access_mode", *patch.access_mode}})) {
                co_return detail::invalid_c_input_result<Connection>(bad);
            }
        }
        struct op : detail::connection_awaiter {
            const OvStorage_LayerHandle* handle;
            std::string target;
            std::string id;
            ConnectionAttributePatch patch;
            OvStorage_AttributePatch raw_patch;
            const OvStorage_CancelToken* cancel;
            bool await_suspend(body_handle h)
            {
                s->continuation = h;
                raw_patch = OvStorage_AttributePatch{};
                raw_patch.has_display_name = patch.display_name.has_value();
                raw_patch.display_name = patch.display_name
                    ? patch.display_name->c_str()
                    : nullptr;
                raw_patch.has_access_mode = patch.access_mode.has_value();
                raw_patch.access_mode = patch.access_mode
                    ? patch.access_mode->c_str()
                    : nullptr;
                raw_patch.has_visible = patch.visible.has_value();
                raw_patch.visible = patch.visible.value_or(false);
                raw_patch.user_metadata = patch.user_metadata == nullptr
                    ? nullptr
                    : patch.user_metadata->get();
                ovstorage_update_connection_attributes(
                    handle, target.c_str(), id.c_str(), &raw_patch, cancel,
                    &connection_awaiter::on_complete, release_user_data());
                return commit_suspend(h);
            }
        };
        op a{};
        a.handle = handle_;
        a.target = std::move(target);
        a.id = std::move(connection_id);
        a.patch = std::move(patch);
        a.raw_patch = OvStorage_AttributePatch{};
        a.cancel = CancelToken::as_ptr(cancel);
        co_return co_await a;
    }

    /// Drive the auth flow for `connection_id` owned by `target`.
    /// Multi-fire: drains every event the layer produces into a vector,
    /// in order, terminating on the final `done=true` fire. Suitable for
    /// flows that terminate (succeed/fail/cancel).
    ///
    /// Pass `on_event` to observe each event AS IT ARRIVES. Any interactive
    /// flow needs it: a device-code flow emits `DeviceCode` with the
    /// verification URL, user code, expiry and polling interval and then
    /// waits for the user, and an `OpenBrowser` prompt with
    /// `auto_open_browser = false` likewise expects the host to render the
    /// URL. The awaited vector only arrives once the flow has already
    /// finished, which is too late to show either.
    ///
    /// `on_event` is invoked on whichever thread the C ABI fires the
    /// callback on — a runtime worker, not the awaiting thread — so it must
    /// be thread-safe and must not block the flow. The `AuthEvent` reference
    /// is borrowed; copy anything that must outlive the call. The events are
    /// still collected into the returned vector either way.
    ///
    /// It may throw. The callback that invokes it is reached from a C frame,
    /// so the exception is caught at that boundary rather than unwinding
    /// through it: the task resolves to an `Internal` failure naming what was
    /// thrown, and the observer is not called again for the rest of the flow.
    task<std::vector<AuthEvent>> authenticate_connection(
        std::string target,
        std::string connection_id,
        OvStorage_InteractiveAuthCapability capability =
            OvStorage_InteractiveAuthCapability_None,
        bool auto_open_browser = false,
        const CancelToken* cancel = nullptr,
        std::function<void(const AuthEvent&)> on_event = {}) const
    {
        if (handle_ == nullptr)
            co_return detail::null_handle_result<std::vector<AuthEvent>>();
        if (auto bad = detail::invalid_c_input({{"target", target}, {"connection_id", connection_id}})) {
            co_return detail::invalid_c_input_result<std::vector<AuthEvent>>(bad);
        }
        struct op : detail::auth_event_drain_awaiter {
            const OvStorage_LayerHandle* handle;
            std::string target;
            std::string id;
            OvStorage_InteractiveAuthCapability capability;
            bool auto_open_browser;
            const OvStorage_CancelToken* cancel;
            bool await_suspend(body_handle h)
            {
                s->continuation = h;
                ovstorage_authenticate_connection(
                    handle, target.c_str(), id.c_str(), capability,
                    auto_open_browser, cancel,
                    &auth_event_drain_awaiter::on_event, release_user_data());
                return commit_suspend(h);
            }
        };
        op a{};
        a.handle = handle_;
        a.target = std::move(target);
        a.id = std::move(connection_id);
        a.capability = capability;
        a.auto_open_browser = auto_open_browser;
        a.cancel = CancelToken::as_ptr(cancel);
        // Install before the C call: an event can fire inline from it.
        a.s->observer = std::move(on_event);
        co_return co_await a;
    }

    // -----------------------------------------------------------------
    // Address-root discovery (keyed on the built Stack root).
    // -----------------------------------------------------------------

    task<RootInfoList> list_address_roots(const CancelToken* cancel = nullptr) const
    {
        if (handle_ == nullptr) co_return detail::null_handle_result<RootInfoList>();
        struct op : detail::root_info_list_awaiter {
            const OvStorage_LayerHandle* handle;
            const OvStorage_CancelToken* cancel;
            bool await_suspend(body_handle h)
            {
                s->continuation = h;
                ovstorage_list_address_roots(
                    handle, cancel,
                    &root_info_list_awaiter::on_complete, release_user_data());
                return commit_suspend(h);
            }
        };
        op a{};
        a.handle = handle_;
        a.cancel = CancelToken::as_ptr(cancel);
        co_return co_await a;
    }

    // -----------------------------------------------------------------
    // Cross-language live handoff. `export_handle` mints
    // one owned `OvStoragePlugin_LayerHandle` over this handle's root
    // Layer — a bare, vtable-bearing interchange struct that can be driven
    // directly through its vtable or handed to `import_handle` in this
    // process or any other. `import_handle` takes ownership of one (from a
    // same-binary export — fast path, Arc identity preserved — or a foreign
    // producer) and re-seats it as a driveable `LayerHandle`. See the
    // `ovstorage_import_handle` prose in `ovstorage.h` for the raw-vtable
    // consumption contract: callback shape, result/error reclaim rules,
    // drop obligations, and the concurrent-slot thread contract.
    //
    // Handles are move-only (the Layer vtable has no clone slot): each
    // `export_handle` mints exactly one owned reference. The returned
    // struct must be disposed once — by `import_handle` (which consumes it)
    // or by its own `vtable->drop(state)`. The producer must outlive it.
    // -----------------------------------------------------------------

    Result<OvStoragePlugin_LayerHandle> export_handle() const
    {
        OvStoragePlugin_LayerHandle out{};
        OvStorage_Error err{};
        auto status = ovstorage_export_handle(handle_, &out, &err);
        if (status != OvStorage_Status_Ok) {
            return Result<OvStoragePlugin_LayerHandle>::failure(take_error(err));
        }
        return Result<OvStoragePlugin_LayerHandle>::success(out);
    }

    static Result<LayerHandle> import_handle(OvStoragePlugin_LayerHandle handle)
    {
        OvStorage_LayerHandle* out = nullptr;
        OvStorage_Error err{};
        auto status = ovstorage_import_handle(handle, &out, &err);
        if (status != OvStorage_Status_Ok) {
            return Result<LayerHandle>::failure(take_error(err));
        }
        // Consumed on success — the returned LayerHandle owns `out`.
        return Result<LayerHandle>::success(LayerHandle(out));
    }

private:
    void reset()
    {
        if (handle_ != nullptr) {
            ovstorage_layer_handle_destroy(handle_);
            handle_ = nullptr;
        }
    }

    OvStorage_LayerHandle* handle_ = nullptr;
};

namespace detail {

// Stack-build callback shape: status + LayerHandle* + error. Mirrors
// info_awaiter but yields the built root LayerHandle, so it is defined here
// (after the LayerHandle class) rather than beside the other awaiters. On
// success the C ABI delivers an owned handle the wrapped LayerHandle adopts;
// on a build-phase error or cancellation it delivers a null handle with an
// error and leaves the builder intact, so only the error branch runs.
struct stack_build_awaiter : awaiter_base<LayerHandle> {
    static void on_complete(
        OvStorage_Status /* status */,
        OvStorage_LayerHandle* handle,
        const OvStorage_Error* error,
        void* user_data) noexcept
    {
        complete(user_data, [&](auto& state) {
            if (error != nullptr) {
                state.outcome = Result<LayerHandle>::failure(Error(*error));
            } else {
                state.outcome =
                    Result<LayerHandle>::success(LayerHandle(handle));
            }
        });
    }
};

static_assert(noexcept(stack_build_awaiter::on_complete(
                  OvStorage_Status_Ok, nullptr, nullptr, nullptr)),
              "stack_build_awaiter::on_complete is invoked by a C frame and "
              "must be noexcept");

} // namespace detail

// ---------------------------------------------------------------------------
// Stack — the mutable builder accumulator.
// ---------------------------------------------------------------------------

class Stack {
public:
    Stack() : handle_(ovstorage_stack_create()) {}

    ~Stack() { reset(); }
    Stack(const Stack&) = delete;
    Stack& operator=(const Stack&) = delete;

    Stack(Stack&& other) noexcept : handle_(std::exchange(other.handle_, nullptr)) {}
    Stack& operator=(Stack&& other) noexcept
    {
        if (this != &other) {
            reset();
            handle_ = std::exchange(other.handle_, nullptr);
        }
        return *this;
    }

    /// Declare a named Layer instance of `kind`, resolved through
    /// `registry`.
    Result<void> add_layer(
        const Registry& registry, std::string instance_id, std::string kind)
    {
        if (auto bad = detail::invalid_c_input(
                {{"instance_id", instance_id}, {"kind", kind}})) {
            return detail::invalid_c_input_result<void>(bad);
        }
        OvStorage_Error err{};
        auto status = ovstorage_stack_add_layer(
            handle_, registry.get(), instance_id.c_str(), kind.c_str(), &err);
        if (status != OvStorage_Status_Ok) {
            return Result<void>::failure(take_error(err));
        }
        return Result<void>::success();
    }

    /// Add or replace one factory configuration value on a declared Layer.
    /// The value is consumed only on success.
    Result<void> add_layer_config(
        std::string instance_id, std::string key, ConfigValue&& value)
    {
        if (auto bad = detail::invalid_c_input(
                {{"instance_id", instance_id}, {"key", key}})) {
            return detail::invalid_c_input_result<void>(bad);
        }
        OvStorage_ConfigValue* raw = value.release();
        OvStorage_Error err{};
        auto status = ovstorage_stack_add_layer_config(
            handle_, instance_id.c_str(), key.c_str(), raw, &err);
        if (status != OvStorage_Status_Ok) {
            if (raw != nullptr) {
                value = ConfigValue(raw);
            }
            return Result<void>::failure(take_error(err));
        }
        return Result<void>::success();
    }

    /// Name the application-facing root Layer instance.
    Result<void> set_root(std::string instance_id)
    {
        if (auto bad = detail::invalid_c_input({{"instance_id", instance_id}})) {
            return detail::invalid_c_input_result<void>(bad);
        }
        OvStorage_Error err{};
        auto status = ovstorage_stack_set_root(handle_, instance_id.c_str(), &err);
        if (status != OvStorage_Status_Ok) {
            return Result<void>::failure(take_error(err));
        }
        return Result<void>::success();
    }

    /// Record the `inner` edge of a wrapper Layer.
    Result<void> set_inner(std::string wrapper_id, std::string inner_id)
    {
        if (auto bad = detail::invalid_c_input(
                {{"wrapper_id", wrapper_id}, {"inner_id", inner_id}})) {
            return detail::invalid_c_input_result<void>(bad);
        }
        OvStorage_Error err{};
        auto status = ovstorage_stack_set_inner(
            handle_, wrapper_id.c_str(), inner_id.c_str(), &err);
        if (status != OvStorage_Status_Ok) {
            return Result<void>::failure(take_error(err));
        }
        return Result<void>::success();
    }

    /// Record the `children` edges of a router Layer.
    Result<void> set_children(std::string router_id, std::vector<std::string> child_ids)
    {
        if (auto bad = detail::invalid_c_input({{"router_id", router_id}})) {
            return detail::invalid_c_input_result<void>(bad);
        }
        for (const auto& id : child_ids) {
            if (auto bad = detail::invalid_c_input({{"child_id", id}})) {
                return detail::invalid_c_input_result<void>(bad);
            }
        }
        std::vector<const char*> ptrs;
        ptrs.reserve(child_ids.size());
        for (const auto& id : child_ids) {
            ptrs.push_back(id.c_str());
        }
        OvStorage_Error err{};
        auto status = ovstorage_stack_set_children(
            handle_, router_id.c_str(), ptrs.empty() ? nullptr : ptrs.data(),
            ptrs.size(), &err);
        if (status != OvStorage_Status_Ok) {
            return Result<void>::failure(take_error(err));
        }
        return Result<void>::success();
    }

    /// Record a connection owned by the Layer named `target`. Takes the
    /// request handle only if the C side does. On failure `request` is left
    /// holding the builder, so the caller can correct the target and try
    /// again, or simply let it destruct.
    Result<void> add_connection(std::string target, ConnectionRequest&& request)
    {
        if (auto bad = detail::invalid_c_input({{"target", target}})) {
            return detail::invalid_c_input_result<void>(bad);
        }
        // `ovstorage_stack_add_connection` NULLs the slot exactly when it
        // takes the builder, so what comes back is the answer: a pointer
        // means it declined — including on the ordinary undeclared-`target`
        // typo — and the wrapper re-adopts so the request, its config and
        // its credentials are not orphaned on a failed wiring attempt.
        OvStorage_ConnectionRequest* raw = request.release();
        OvStorage_Error err{};
        auto status = ovstorage_stack_add_connection(handle_, target.c_str(), &raw, &err);
        if (raw != nullptr) {
            request = ConnectionRequest(raw);
        }
        if (status != OvStorage_Status_Ok) {
            return Result<void>::failure(take_error(err));
        }
        return Result<void>::success();
    }

    /// Finalize the Stack asynchronously and resolve to the root
    /// `LayerHandle`. Returns a `task<LayerHandle>`, and like every task here
    /// it is EAGER: the build is already under way when `build()` returns,
    /// and `co_await` (or `sync_wait`) collects its result. It drives
    /// `ovstorage_stack_build_async`, so a coroutine host never blocks a
    /// runtime thread. Awaiting yields a `Result<LayerHandle>`.
    ///
    /// The Stack is consumed only when the build succeeds: the wrapper drops
    /// its ownership of the builder without destroying it (the C side already
    /// freed it). A build that fails or is cancelled leaves the Stack owned
    /// by this wrapper, so it is always safe to destroy.
    ///
    /// Whether it is RETRYABLE is implementation-defined, and for the C
    /// implementation shipped alongside this header it generally is not: any
    /// path that reaches the build epilogue zeroes recorded credentials for
    /// secret hygiene, after which every connection that carried secrets is
    /// rejected with `InvalidArgument`. Connections without credentials
    /// retry unchanged, and a prologue rejection leaves the builder
    /// untouched. After a build-phase failure or cancellation, rebuild the
    /// Stack with fresh credentials rather than re-awaiting `build()`.
    ///
    /// The Stack object must outlive the await. The coroutine reads the
    /// builder pointer up front and, on success, clears it after the callback
    /// fires, so the Stack — and every request/config/secret handle recorded
    /// into it — must stay alive and untouched until the task resolves.
    task<LayerHandle> build(
        const OvStorage_StackBuildOptions* options = nullptr,
        const CancelToken* cancel = nullptr)
    {
        struct op : detail::stack_build_awaiter {
            OvStorage_Stack* stack;
            const OvStorage_StackBuildOptions* options;
            const OvStorage_CancelToken* cancel;
            bool await_suspend(body_handle h)
            {
                s->continuation = h;
                ovstorage_stack_build_async(stack, options, cancel,
                    &stack_build_awaiter::on_complete, release_user_data());
                return commit_suspend(h);
            }
        };
        op a{};
        a.stack = handle_;
        a.options = options;
        a.cancel = CancelToken::as_ptr(cancel);
        auto result = co_await a;
        if (result.has_value()) {
            // Consumed on success — the C side freed the builder, so drop our
            // ownership without destroying it. Error/cancel leaves it intact.
            handle_ = nullptr;
        }
        co_return std::move(result);
    }

    const OvStorage_Stack* get() const noexcept { return handle_; }

private:
    void reset()
    {
        if (handle_ != nullptr) {
            ovstorage_stack_destroy(handle_);
            handle_ = nullptr;
        }
    }

    OvStorage_Stack* handle_ = nullptr;
};

} // namespace ovstorage

#endif
