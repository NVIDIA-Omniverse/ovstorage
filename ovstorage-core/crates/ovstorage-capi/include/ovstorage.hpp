// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef OVSTORAGE_HPP
#define OVSTORAGE_HPP

/*
 * Async-only C++20 wrapper around the ovstorage C ABI.
 *
 * Every long-running method returns `task<T>`, a C++20 coroutine type
 * that carries an `ovstorage::Result<T>`. Trampolines hand a
 * `std::coroutine_handle` to the C callback via `user_data` and resume
 * the coroutine from the tokio worker thread when the callback fires.
 *
 * Top-level (non-coroutine) callers use `sync_wait(task<T>)` to drive
 * a task to completion on the calling thread.
 *
 * Cancellation: `CancelToken` is a RAII wrapper around the C cancel
 * token. The same token can be passed to several in-flight operations
 * for group-cancel.
 *
 * The C ABI guarantees the always-async invariant for valid library
 * handles — `on_complete` fires from the runtime. Each awaiter pairs
 * that with a single atomic exchange (`state` in
 * `detail::awaiter_base`) to handle the cross-thread race between the
 * tokio worker firing on_complete and the calling thread finishing
 * `await_suspend`.
 *
 * Null-handle guard: each method short-circuits to a failed Result if
 * the underlying `OvStorage_Library*` is null (moved-from Library,
 * or one constructed via `Library{}`). The C ABI itself fires a
 * supplied callback inline with `InvalidArgument` for null handles,
 * but the wrapper intercepts before entering the C ABI so coroutine
 * callers get the normal failed-Result shape.
 *
 * Thread-safety caveat: the C contract forbids `ovstorage_library_shutdown`
 * from inside an `on_complete` callback. Equivalent in C++: do NOT
 * destroy a `Library` inside the body of a coroutine that is awaiting
 * one of its tasks. Run the destructor on the application thread (i.e.,
 * after `sync_wait` has returned).
 */

#include "ovstorage.h"

#include <atomic>
#include <condition_variable>
#include <coroutine>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
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
// RAII wrappers around C result handles
// ---------------------------------------------------------------------------

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

    std::string address() const { return string_or_empty(ovstorage_info_address(handle_)); }
    OvStorage_ObjectKind kind() const noexcept { return ovstorage_info_kind(handle_); }
    bool has_size() const noexcept { return ovstorage_info_has_size(handle_); }
    std::uint64_t size() const noexcept { return ovstorage_info_size(handle_); }
    std::string etag() const { return string_or_empty(ovstorage_info_etag(handle_)); }
    std::string version() const { return string_or_empty(ovstorage_info_version(handle_)); }

    std::vector<std::pair<std::string, std::string>> user_metadata() const
    {
        std::vector<std::pair<std::string, std::string>> out;
        const auto len = ovstorage_info_user_metadata_len(handle_);
        out.reserve(len);
        for (std::size_t i = 0; i < len; ++i) {
            out.emplace_back(
                string_or_empty(ovstorage_info_user_metadata_key(handle_, i)),
                string_or_empty(ovstorage_info_user_metadata_value(handle_, i)));
        }
        return out;
    }

private:
    static std::string string_or_empty(const char* value)
    {
        return value == nullptr ? std::string{} : std::string(value);
    }

    void reset()
    {
        if (handle_ != nullptr) {
            ovstorage_info_destroy(handle_);
            handle_ = nullptr;
        }
    }

    OvStorage_Info* handle_ = nullptr;
};

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

    std::size_t size() const noexcept { return ovstorage_list_len(handle_); }

    std::string next_page_token() const
    {
        const char* token = ovstorage_list_next_page_token(handle_);
        return token == nullptr ? std::string{} : std::string(token);
    }

    std::string address(std::size_t index) const
    {
        const char* value = ovstorage_list_item_address(handle_, index);
        return value == nullptr ? std::string{} : std::string(value);
    }

    Info info(std::size_t index) const { return Info(ovstorage_list_item_info(handle_, index)); }

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

    std::size_t size() const noexcept { return ovstorage_version_list_len(handle_); }

    std::string next_page_token() const
    {
        const char* token = ovstorage_version_list_next_page_token(handle_);
        return token == nullptr ? std::string{} : std::string(token);
    }

    std::string address(std::size_t index) const
    {
        const char* value = ovstorage_version_list_item_address(handle_, index);
        return value == nullptr ? std::string{} : std::string(value);
    }

    Info info(std::size_t index) const
    {
        return Info(ovstorage_version_list_item_info(handle_, index));
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

// ---------------------------------------------------------------------------
// Connection / auth / aliases / discovery surface
// ---------------------------------------------------------------------------
//
// Builder types (`ConfigValue`, `SecretValue`, `SecretBundle`,
// `ConnectionRequest`, `AliasRequest`) wrap the opaque C builder
// handles. Their `release()` method extracts the raw `*mut` and
// transfers ownership to the consumer (the C ABI's `_add_connection`
// / `_update_connection_credentials` / `_add_alias` thunks). After
// `release()`, the C++ wrapper no longer owns the handle and its
// destructor is a no-op.
//
// Read-side types (`Connection`, `ConnectionList`, `AuthEvent`,
// `Alias`, `AliasList`, `AddressVisibilityOverride`,
// `AddressVisibilityOverrideList`, `AddressRoot`, `AddressRootList`,
// `BackendKindDescriptor`, `BackendKindDescriptorList`) are RAII
// over their `_destroy` C functions. Variant-specific accessors
// return `std::optional<T>` or empty strings for the wrong variant
// (matches the C-side null/0 semantics).
//
// `Capabilities` is a thin value wrapper over the flat
// `OvStorage_CapabilitiesV1` struct. Default-constructs with
// `struct_size` populated and all fields zeroed.

class Capabilities {
public:
    Capabilities() noexcept
    {
        std::memset(&caps_, 0, sizeof(caps_));
        caps_.struct_size = sizeof(OvStorage_CapabilitiesV1);
        caps_.version_list_order = OvStorage_VersionListOrder_Newest;
    }

    OvStorage_CapabilitiesV1* raw() noexcept { return &caps_; }
    const OvStorage_CapabilitiesV1& raw() const noexcept { return caps_; }

    bool supports_if_match_write() const noexcept { return caps_.supports_if_match_write; }
    bool supports_recursive_list() const noexcept { return caps_.supports_recursive_list; }
    bool supports_access_check() const noexcept { return caps_.supports_access_check; }
    bool supports_watch_directory() const noexcept { return caps_.supports_watch_directory; }
    bool supports_version_listing() const noexcept { return caps_.supports_version_listing; }
    bool has_real_directories() const noexcept { return caps_.has_real_directories; }
    bool writes_are_atomic() const noexcept { return caps_.writes_are_atomic; }

    std::optional<std::uint64_t> redirect_size_threshold() const noexcept
    {
        return caps_.has_redirect_size_threshold
            ? std::optional<std::uint64_t>(caps_.redirect_size_threshold)
            : std::nullopt;
    }

private:
    OvStorage_CapabilitiesV1 caps_{};
};

// ---------------------------------------------------------------------------
// ConfigValue / SecretValue / SecretBundle / ConnectionRequest builders
// ---------------------------------------------------------------------------

class ConfigValue {
public:
    static ConfigValue string_(std::string s)
    {
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

private:
    explicit SecretBundle(OvStorage_SecretBundle* h) : handle_(h) {}
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
    explicit ConnectionRequest(std::string backend_kind)
        : handle_(ovstorage_connection_request_create(backend_kind.c_str()))
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

    void set_display_name(std::string display_name)
    {
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
        std::string key_string(key);
        OvStorage_SecretValue* raw = value.release();
        bool ok = ovstorage_connection_request_add_credential(handle_, key_string.c_str(), raw);
        if (!ok && raw != nullptr) {
            value = SecretValue(raw);
        }
        return ok;
    }

    OvStorage_ConnectionRequest* release() noexcept
    {
        return std::exchange(handle_, nullptr);
    }

private:
    explicit ConnectionRequest(OvStorage_ConnectionRequest* h) : handle_(h) {}
    void reset()
    {
        if (handle_ != nullptr) {
            ovstorage_connection_request_destroy(handle_);
            handle_ = nullptr;
        }
    }
    // Friend the SecretValue/ConfigValue constructors-from-raw used in
    // recovery paths above.
    friend class SecretValue;
    friend class ConfigValue;
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

    std::string id() const { return cstring(ovstorage_connection_id(handle_)); }
    std::string backend_kind() const { return cstring(ovstorage_connection_backend_kind(handle_)); }
    std::string display_name() const
    {
        return cstring(ovstorage_connection_display_name(handle_));
    }
    OvStorage_ConnectionSourceKind source_kind() const noexcept
    {
        return ovstorage_connection_source_kind(handle_);
    }
    OvStorage_ConnectionAuthStateKind auth_state_kind() const noexcept
    {
        return ovstorage_connection_auth_state_kind(handle_);
    }
    Capabilities capabilities() const
    {
        Capabilities caps;
        ovstorage_connection_capabilities(handle_, caps.raw());
        return caps;
    }
    std::size_t address_count() const noexcept
    {
        return ovstorage_connection_address_count(handle_);
    }
    std::string address(std::size_t i) const
    {
        return cstring(ovstorage_connection_address_at(handle_, i));
    }

private:
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

    std::size_t size() const noexcept { return ovstorage_connection_list_len(handle_); }
    /// Returns a borrowed pointer to the i-th connection. Lifetime is
    /// tied to the list handle — do NOT delete or destroy it.
    const OvStorage_Connection* item_at(std::size_t i) const noexcept
    {
        return ovstorage_connection_list_item_at(handle_, i);
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
        return ovstorage_auth_event_kind(handle_);
    }

    std::optional<std::string> open_browser_url() const
    {
        const char* p = ovstorage_auth_event_open_browser_url(handle_);
        return p == nullptr ? std::nullopt : std::optional<std::string>(p);
    }
    std::optional<std::string> device_code_user_code() const
    {
        const char* p = ovstorage_auth_event_device_code_user_code(handle_);
        return p == nullptr ? std::nullopt : std::optional<std::string>(p);
    }
    std::optional<std::string> progress_message() const
    {
        const char* p = ovstorage_auth_event_progress_message(handle_);
        return p == nullptr ? std::nullopt : std::optional<std::string>(p);
    }
    /// Returns a borrowed pointer to the inner Connection for the
    /// Succeeded variant. Null otherwise. Lifetime tied to the event.
    const OvStorage_Connection* succeeded_connection() const noexcept
    {
        return ovstorage_auth_event_succeeded_connection(handle_);
    }
    std::optional<std::string> failed_error_message() const
    {
        const char* p = ovstorage_auth_event_failed_error_message(handle_);
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
// Aliases
// ---------------------------------------------------------------------------

class AliasRequest {
public:
    AliasRequest(std::string from, std::string to)
        : handle_(ovstorage_alias_request_create(from.c_str(), to.c_str()))
    {
    }
    ~AliasRequest() { reset(); }
    AliasRequest(const AliasRequest&) = delete;
    AliasRequest& operator=(const AliasRequest&) = delete;
    AliasRequest(AliasRequest&& other) noexcept
        : handle_(std::exchange(other.handle_, nullptr))
    {
    }
    AliasRequest& operator=(AliasRequest&& other) noexcept
    {
        if (this != &other) {
            reset();
            handle_ = std::exchange(other.handle_, nullptr);
        }
        return *this;
    }

    void set_visibility(OvStorage_AddressVisibility v)
    {
        ovstorage_alias_request_set_visibility(handle_, v);
    }
    void set_persist(bool persist)
    {
        ovstorage_alias_request_set_persist(handle_, persist);
    }
    void set_display_name(std::string display_name)
    {
        ovstorage_alias_request_set_display_name(handle_, display_name.c_str());
    }
    bool add_user_metadata(std::string_view key, std::string_view value)
    {
        std::string ks(key), vs(value);
        return ovstorage_alias_request_add_user_metadata(handle_, ks.c_str(), vs.c_str());
    }

    OvStorage_AliasRequest* release() noexcept
    {
        return std::exchange(handle_, nullptr);
    }

private:
    void reset()
    {
        if (handle_ != nullptr) {
            ovstorage_alias_request_destroy(handle_);
            handle_ = nullptr;
        }
    }
    OvStorage_AliasRequest* handle_ = nullptr;
};

class Alias {
public:
    Alias() = default;
    explicit Alias(OvStorage_Alias* handle) : handle_(handle) {}
    ~Alias() { reset(); }
    Alias(const Alias&) = delete;
    Alias& operator=(const Alias&) = delete;
    Alias(Alias&& other) noexcept : handle_(std::exchange(other.handle_, nullptr)) {}
    Alias& operator=(Alias&& other) noexcept
    {
        if (this != &other) {
            reset();
            handle_ = std::exchange(other.handle_, nullptr);
        }
        return *this;
    }

    const OvStorage_Alias* get() const noexcept { return handle_; }
    std::string id() const { return cstring(ovstorage_alias_id(handle_)); }
    std::string from() const { return cstring(ovstorage_alias_from(handle_)); }
    std::string to() const { return cstring(ovstorage_alias_to(handle_)); }
    OvStorage_AddressVisibility visibility() const noexcept
    {
        return ovstorage_alias_visibility(handle_);
    }
    OvStorage_AliasStateKind state_kind() const noexcept
    {
        return ovstorage_alias_state_kind(handle_);
    }
    std::string display_name() const { return cstring(ovstorage_alias_display_name(handle_)); }

private:
    static std::string cstring(const char* p)
    {
        return p == nullptr ? std::string{} : std::string(p);
    }
    void reset()
    {
        if (handle_ != nullptr) {
            ovstorage_alias_destroy(handle_);
            handle_ = nullptr;
        }
    }
    OvStorage_Alias* handle_ = nullptr;
};

class AliasList {
public:
    AliasList() = default;
    explicit AliasList(OvStorage_AliasList* handle) : handle_(handle) {}
    ~AliasList() { reset(); }
    AliasList(const AliasList&) = delete;
    AliasList& operator=(const AliasList&) = delete;
    AliasList(AliasList&& other) noexcept : handle_(std::exchange(other.handle_, nullptr)) {}
    AliasList& operator=(AliasList&& other) noexcept
    {
        if (this != &other) {
            reset();
            handle_ = std::exchange(other.handle_, nullptr);
        }
        return *this;
    }

    std::size_t size() const noexcept { return ovstorage_alias_list_len(handle_); }
    /// Returns borrowed; lifetime tied to the list handle.
    const OvStorage_Alias* item_at(std::size_t i) const noexcept
    {
        return ovstorage_alias_list_item_at(handle_, i);
    }

private:
    void reset()
    {
        if (handle_ != nullptr) {
            ovstorage_alias_list_destroy(handle_);
            handle_ = nullptr;
        }
    }
    OvStorage_AliasList* handle_ = nullptr;
};

// ---------------------------------------------------------------------------
// Visibility overrides + discovery
// ---------------------------------------------------------------------------

class AddressVisibilityOverride {
public:
    AddressVisibilityOverride() = default;
    explicit AddressVisibilityOverride(OvStorage_AddressVisibilityOverride* handle)
        : handle_(handle)
    {
    }
    ~AddressVisibilityOverride() { reset(); }
    AddressVisibilityOverride(const AddressVisibilityOverride&) = delete;
    AddressVisibilityOverride& operator=(const AddressVisibilityOverride&) = delete;
    AddressVisibilityOverride(AddressVisibilityOverride&& other) noexcept
        : handle_(std::exchange(other.handle_, nullptr))
    {
    }
    AddressVisibilityOverride& operator=(AddressVisibilityOverride&& other) noexcept
    {
        if (this != &other) {
            reset();
            handle_ = std::exchange(other.handle_, nullptr);
        }
        return *this;
    }

    std::string address() const
    {
        const char* p = ovstorage_address_visibility_override_address(handle_);
        return p == nullptr ? std::string{} : std::string(p);
    }
    OvStorage_AddressVisibility visibility() const noexcept
    {
        return ovstorage_address_visibility_override_visibility(handle_);
    }
    bool persisted() const noexcept
    {
        return ovstorage_address_visibility_override_persisted(handle_);
    }

private:
    void reset()
    {
        if (handle_ != nullptr) {
            ovstorage_address_visibility_override_destroy(handle_);
            handle_ = nullptr;
        }
    }
    OvStorage_AddressVisibilityOverride* handle_ = nullptr;
};

class AddressVisibilityOverrideList {
public:
    AddressVisibilityOverrideList() = default;
    explicit AddressVisibilityOverrideList(OvStorage_AddressVisibilityOverrideList* handle)
        : handle_(handle)
    {
    }
    ~AddressVisibilityOverrideList() { reset(); }
    AddressVisibilityOverrideList(const AddressVisibilityOverrideList&) = delete;
    AddressVisibilityOverrideList& operator=(const AddressVisibilityOverrideList&) = delete;
    AddressVisibilityOverrideList(AddressVisibilityOverrideList&& other) noexcept
        : handle_(std::exchange(other.handle_, nullptr))
    {
    }
    AddressVisibilityOverrideList& operator=(AddressVisibilityOverrideList&& other) noexcept
    {
        if (this != &other) {
            reset();
            handle_ = std::exchange(other.handle_, nullptr);
        }
        return *this;
    }

    std::size_t size() const noexcept
    {
        return ovstorage_address_visibility_override_list_len(handle_);
    }
    const OvStorage_AddressVisibilityOverride* item_at(std::size_t i) const noexcept
    {
        return ovstorage_address_visibility_override_list_item_at(handle_, i);
    }

private:
    void reset()
    {
        if (handle_ != nullptr) {
            ovstorage_address_visibility_override_list_destroy(handle_);
            handle_ = nullptr;
        }
    }
    OvStorage_AddressVisibilityOverrideList* handle_ = nullptr;
};

class AddressRootList {
public:
    AddressRootList() = default;
    explicit AddressRootList(OvStorage_AddressRootList* handle) : handle_(handle) {}
    ~AddressRootList() { reset(); }
    AddressRootList(const AddressRootList&) = delete;
    AddressRootList& operator=(const AddressRootList&) = delete;
    AddressRootList(AddressRootList&& other) noexcept
        : handle_(std::exchange(other.handle_, nullptr))
    {
    }
    AddressRootList& operator=(AddressRootList&& other) noexcept
    {
        if (this != &other) {
            reset();
            handle_ = std::exchange(other.handle_, nullptr);
        }
        return *this;
    }

    std::size_t size() const noexcept
    {
        return ovstorage_address_root_list_len(handle_);
    }
    const OvStorage_AddressRoot* item_at(std::size_t i) const noexcept
    {
        return ovstorage_address_root_list_item_at(handle_, i);
    }

private:
    void reset()
    {
        if (handle_ != nullptr) {
            ovstorage_address_root_list_destroy(handle_);
            handle_ = nullptr;
        }
    }
    OvStorage_AddressRootList* handle_ = nullptr;
};

using AddressRootSnapshotHandler = std::function<void(AddressRootList)>;

class BackendKindDescriptorList {
public:
    BackendKindDescriptorList() = default;
    explicit BackendKindDescriptorList(OvStorage_BackendKindDescriptorList* handle)
        : handle_(handle)
    {
    }
    ~BackendKindDescriptorList() { reset(); }
    BackendKindDescriptorList(const BackendKindDescriptorList&) = delete;
    BackendKindDescriptorList& operator=(const BackendKindDescriptorList&) = delete;
    BackendKindDescriptorList(BackendKindDescriptorList&& other) noexcept
        : handle_(std::exchange(other.handle_, nullptr))
    {
    }
    BackendKindDescriptorList& operator=(BackendKindDescriptorList&& other) noexcept
    {
        if (this != &other) {
            reset();
            handle_ = std::exchange(other.handle_, nullptr);
        }
        return *this;
    }

    std::size_t size() const noexcept
    {
        return ovstorage_backend_kind_descriptor_list_len(handle_);
    }
    const OvStorage_BackendKindDescriptor* item_at(std::size_t i) const noexcept
    {
        return ovstorage_backend_kind_descriptor_list_item_at(handle_, i);
    }

private:
    void reset()
    {
        if (handle_ != nullptr) {
            ovstorage_backend_kind_descriptor_list_destroy(handle_);
            handle_ = nullptr;
        }
    }
    OvStorage_BackendKindDescriptorList* handle_ = nullptr;
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
//       suspended). The body's eventual final_awaiter sees state==3
//       and destroys the frame instead of resuming a non-existent
//       continuation, so the in-flight C callback can still run to
//       completion (its leaked shared_ptr ref keeps the per-awaiter
//       state alive) and the orphaned body cleans up after itself.
// Whichever party arrives second observes the other's value via
// acq_rel exchange and routes accordingly.
// ---------------------------------------------------------------------------

template <class T>
class task {
public:
    struct promise_type;
    using handle_type = std::coroutine_handle<promise_type>;

    struct final_awaiter {
        bool await_ready() noexcept { return false; }
        std::coroutine_handle<> await_suspend(handle_type h) noexcept
        {
            auto& p = h.promise();
            int prev = p.state.exchange(2, std::memory_order_acq_rel);
            if (prev == 1) {
                return p.continuation ? p.continuation : std::noop_coroutine();
            }
            if (prev == 3) {
                h.destroy();
            }
            return std::noop_coroutine();
        }
        void await_resume() noexcept {}
    };

    struct promise_type {
        std::optional<Result<T>> value;
        std::coroutine_handle<> continuation;
        std::atomic<int> state{0};

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

    bool await_ready() const noexcept { return !handle_ || handle_.done(); }

    bool await_suspend(std::coroutine_handle<> awaiter) noexcept
    {
        auto& p = handle_.promise();
        p.continuation = awaiter;
        return p.state.exchange(1, std::memory_order_acq_rel) != 2;
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
        if (handle_.done()) {
            handle_.destroy();
            return;
        }
        // Body still suspended; let the eventual final_awaiter
        // destroy the frame (state==3 path) so an in-flight C
        // callback can finish using the awaiter state safely.
        if (handle_.promise().state.exchange(3, std::memory_order_acq_rel) == 2) {
            handle_.destroy();
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
            auto& p = h.promise();
            int prev = p.state.exchange(2, std::memory_order_acq_rel);
            if (prev == 1) {
                return p.continuation ? p.continuation : std::noop_coroutine();
            }
            if (prev == 3) {
                h.destroy();
            }
            return std::noop_coroutine();
        }
        void await_resume() noexcept {}
    };

    struct promise_type {
        std::optional<Result<void>> value;
        std::coroutine_handle<> continuation;
        std::atomic<int> state{0};

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

    bool await_ready() const noexcept { return !handle_ || handle_.done(); }
    bool await_suspend(std::coroutine_handle<> awaiter) noexcept
    {
        auto& p = handle_.promise();
        p.continuation = awaiter;
        return p.state.exchange(1, std::memory_order_acq_rel) != 2;
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
        if (handle_.done()) {
            handle_.destroy();
            return;
        }
        if (handle_.promise().state.exchange(3, std::memory_order_acq_rel) == 2) {
            handle_.destroy();
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

template <class T>
fire_and_forget run_into_slot(
    task<T> work,
    std::optional<Result<T>>* slot,
    std::mutex* m,
    std::condition_variable* cv)
{
    Result<T> outcome = co_await std::move(work);
    {
        std::lock_guard<std::mutex> lk(*m);
        slot->emplace(std::move(outcome));
    }
    cv->notify_all();
}

inline fire_and_forget run_into_slot_void(
    task<void> work,
    std::optional<Result<void>>* slot,
    std::mutex* m,
    std::condition_variable* cv)
{
    Result<void> outcome = co_await std::move(work);
    {
        std::lock_guard<std::mutex> lk(*m);
        slot->emplace(std::move(outcome));
    }
    cv->notify_all();
}

} // namespace detail

template <class T>
Result<T> sync_wait(task<T> t)
{
    std::mutex m;
    std::condition_variable cv;
    std::optional<Result<T>> slot;
    detail::run_into_slot<T>(std::move(t), &slot, &m, &cv);
    std::unique_lock<std::mutex> lk(m);
    cv.wait(lk, [&] { return slot.has_value(); });
    return std::move(*slot);
}

inline Result<void> sync_wait(task<void> t)
{
    std::mutex m;
    std::condition_variable cv;
    std::optional<Result<void>> slot;
    detail::run_into_slot_void(std::move(t), &slot, &m, &cv);
    std::unique_lock<std::mutex> lk(m);
    cv.wait(lk, [&] { return slot.has_value(); });
    return std::move(*slot);
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
    Result<Out> outcome = Result<Out>::failure(Error{});
    std::coroutine_handle<> continuation;
    std::atomic<int> state{0};
};

template <class Out, class State = awaiter_state<Out>>
struct awaiter_base {
    std::shared_ptr<State> s = std::make_shared<State>();

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
            ref->continuation.resume();
        }
    }

    // Subclass calls this from await_suspend AFTER invoking the C API
    // (so the state fields are fully initialized when on_complete might
    // dereference them) and BEFORE returning. `s->continuation` must
    // already be set.
    bool commit_suspend()
    {
        return s->state.exchange(2, std::memory_order_acq_rel) != 1;
    }
};

// Status callback shape: status + error.
struct status_awaiter : awaiter_base<void> {
    static void on_complete(
        OvStorage_Status /* status */,
        const OvStorage_Error* error,
        void* user_data)
    {
        auto state = reclaim_state(user_data);
        if (error != nullptr) {
            state->outcome = Result<void>::failure(Error(*error));
        } else {
            state->outcome = Result<void>::success();
        }
        deliver(state);
    }
};

// Info callback shape: status + Info* + error.
struct info_awaiter : awaiter_base<Info> {
    static void on_complete(
        OvStorage_Status /* status */,
        OvStorage_Info* info,
        const OvStorage_Error* error,
        void* user_data)
    {
        auto state = reclaim_state(user_data);
        if (error != nullptr) {
            state->outcome = Result<Info>::failure(Error(*error));
        } else {
            state->outcome = Result<Info>::success(Info(info));
        }
        deliver(state);
    }
};

struct read_bytes_awaiter : awaiter_base<std::pair<Bytes, Info>> {
    static void on_complete(
        OvStorage_Status /* status */,
        OvStorage_Bytes bytes,
        OvStorage_Info* info,
        const OvStorage_Error* error,
        void* user_data)
    {
        auto state = reclaim_state(user_data);
        if (error != nullptr) {
            // Free the bytes payload (if any was sent on the error path).
            OvStorage_Bytes copy = bytes;
            ovstorage_bytes_destroy(&copy);
            state->outcome =
                Result<std::pair<Bytes, Info>>::failure(Error(*error));
        } else {
            state->outcome = Result<std::pair<Bytes, Info>>::success(
                std::pair<Bytes, Info>(Bytes(bytes), Info(info)));
        }
        deliver(state);
    }
};

struct local_delegate_awaiter : awaiter_base<LocalDelegate> {
    static void on_complete(
        OvStorage_Status /* status */,
        OvStorage_LocalDelegate* delegate,
        const OvStorage_Error* error,
        void* user_data)
    {
        auto state = reclaim_state(user_data);
        if (error != nullptr) {
            state->outcome = Result<LocalDelegate>::failure(Error(*error));
        } else {
            state->outcome = Result<LocalDelegate>::success(LocalDelegate(delegate));
        }
        deliver(state);
    }
};

struct list_awaiter : awaiter_base<List> {
    static void on_complete(
        OvStorage_Status /* status */,
        OvStorage_List* list,
        const OvStorage_Error* error,
        void* user_data)
    {
        auto state = reclaim_state(user_data);
        if (error != nullptr) {
            state->outcome = Result<List>::failure(Error(*error));
        } else {
            state->outcome = Result<List>::success(List(list));
        }
        deliver(state);
    }
};

struct list_versions_awaiter : awaiter_base<VersionList> {
    static void on_complete(
        OvStorage_Status /* status */,
        OvStorage_VersionList* list,
        const OvStorage_Error* error,
        void* user_data)
    {
        auto state = reclaim_state(user_data);
        if (error != nullptr) {
            state->outcome = Result<VersionList>::failure(Error(*error));
        } else {
            state->outcome = Result<VersionList>::success(VersionList(list));
        }
        deliver(state);
    }
};

struct check_access_awaiter : awaiter_base<AccessDecision> {
    static void on_complete(
        OvStorage_Status /* status */,
        OvStorage_AccessDecision decision,
        const OvStorage_Error* error,
        void* user_data)
    {
        auto state = reclaim_state(user_data);
        if (error != nullptr) {
            OvStorage_AccessDecision copy = decision;
            ovstorage_access_decision_clear(&copy);
            state->outcome = Result<AccessDecision>::failure(Error(*error));
        } else {
            state->outcome =
                Result<AccessDecision>::success(AccessDecision(decision));
        }
        deliver(state);
    }
};

// Pre-flight failure used by Library methods when their handle is
// nullptr (e.g. moved-from Library, or one whose init() never
// returned Ok). The C ABI wouldn't fire on_complete on a null
// library, so the C++ wrapper short-circuits with this Result rather
// than letting the coroutine hang. Lives in `detail` because it's
// implementation glue, not a public construction path.
template <class T>
inline Result<T> null_library_result()
{
    return Result<T>::failure(Error(
        OvStorage_Status_InvalidArgument,
        "library handle is null (uninitialized or already shut down)"));
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
    static void on_chunk(
        OvStorage_Bytes chunk,
        const OvStorage_Error* error,
        bool done,
        void* user_data)
    {
        auto* st = borrow_state(user_data);
        if (error != nullptr) {
            st->outcome =
                Result<std::vector<std::byte>>::failure(Error(*error));
            st->error_seen = true;
        } else if (!done && chunk.data != nullptr) {
            const auto* p = reinterpret_cast<const std::byte*>(chunk.data);
            st->accumulated.insert(st->accumulated.end(), p, p + chunk.len);
            OvStorage_Bytes copy = chunk;
            ovstorage_bytes_destroy(&copy);
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

// ---- Connection / auth / aliases / discovery awaiters ----------------------

struct connection_awaiter : awaiter_base<Connection> {
    static void on_complete(
        OvStorage_Status /* status */,
        OvStorage_Connection* connection,
        const OvStorage_Error* error,
        void* user_data)
    {
        auto state = reclaim_state(user_data);
        if (error != nullptr) {
            state->outcome = Result<Connection>::failure(Error(*error));
        } else {
            state->outcome = Result<Connection>::success(Connection(connection));
        }
        deliver(state);
    }
};

struct connection_list_awaiter : awaiter_base<ConnectionList> {
    static void on_complete(
        OvStorage_Status /* status */,
        OvStorage_ConnectionList* list,
        const OvStorage_Error* error,
        void* user_data)
    {
        auto state = reclaim_state(user_data);
        if (error != nullptr) {
            state->outcome = Result<ConnectionList>::failure(Error(*error));
        } else {
            state->outcome = Result<ConnectionList>::success(ConnectionList(list));
        }
        deliver(state);
    }
};

struct alias_awaiter : awaiter_base<Alias> {
    static void on_complete(
        OvStorage_Status /* status */,
        OvStorage_Alias* alias,
        const OvStorage_Error* error,
        void* user_data)
    {
        auto state = reclaim_state(user_data);
        if (error != nullptr) {
            state->outcome = Result<Alias>::failure(Error(*error));
        } else {
            state->outcome = Result<Alias>::success(Alias(alias));
        }
        deliver(state);
    }
};

struct alias_list_awaiter : awaiter_base<AliasList> {
    static void on_complete(
        OvStorage_Status /* status */,
        OvStorage_AliasList* list,
        const OvStorage_Error* error,
        void* user_data)
    {
        auto state = reclaim_state(user_data);
        if (error != nullptr) {
            state->outcome = Result<AliasList>::failure(Error(*error));
        } else {
            state->outcome = Result<AliasList>::success(AliasList(list));
        }
        deliver(state);
    }
};

struct address_visibility_override_awaiter : awaiter_base<AddressVisibilityOverride> {
    static void on_complete(
        OvStorage_Status /* status */,
        OvStorage_AddressVisibilityOverride* result,
        const OvStorage_Error* error,
        void* user_data)
    {
        auto state = reclaim_state(user_data);
        if (error != nullptr) {
            state->outcome = Result<AddressVisibilityOverride>::failure(Error(*error));
        } else {
            state->outcome = Result<AddressVisibilityOverride>::success(
                AddressVisibilityOverride(result));
        }
        deliver(state);
    }
};

struct address_visibility_override_list_awaiter
    : awaiter_base<AddressVisibilityOverrideList> {
    static void on_complete(
        OvStorage_Status /* status */,
        OvStorage_AddressVisibilityOverrideList* list,
        const OvStorage_Error* error,
        void* user_data)
    {
        auto state = reclaim_state(user_data);
        if (error != nullptr) {
            state->outcome =
                Result<AddressVisibilityOverrideList>::failure(Error(*error));
        } else {
            state->outcome = Result<AddressVisibilityOverrideList>::success(
                AddressVisibilityOverrideList(list));
        }
        deliver(state);
    }
};

struct address_root_list_awaiter : awaiter_base<AddressRootList> {
    static void on_complete(
        OvStorage_Status /* status */,
        OvStorage_AddressRootList* list,
        const OvStorage_Error* error,
        void* user_data)
    {
        auto state = reclaim_state(user_data);
        if (error != nullptr) {
            state->outcome = Result<AddressRootList>::failure(Error(*error));
        } else {
            state->outcome = Result<AddressRootList>::success(AddressRootList(list));
        }
        deliver(state);
    }
};

struct backend_kind_descriptor_list_awaiter
    : awaiter_base<BackendKindDescriptorList> {
    static void on_complete(
        OvStorage_Status /* status */,
        OvStorage_BackendKindDescriptorList* list,
        const OvStorage_Error* error,
        void* user_data)
    {
        auto state = reclaim_state(user_data);
        if (error != nullptr) {
            state->outcome = Result<BackendKindDescriptorList>::failure(Error(*error));
        } else {
            state->outcome = Result<BackendKindDescriptorList>::success(
                BackendKindDescriptorList(list));
        }
        deliver(state);
    }
};

struct capabilities_awaiter : awaiter_base<Capabilities> {
    static void on_complete(
        OvStorage_Status /* status */,
        const OvStorage_CapabilitiesV1* caps,
        const OvStorage_Error* error,
        void* user_data)
    {
        auto state = reclaim_state(user_data);
        if (error != nullptr) {
            state->outcome = Result<Capabilities>::failure(Error(*error));
        } else if (caps != nullptr) {
            Capabilities c;
            std::memcpy(c.raw(), caps, sizeof(OvStorage_CapabilitiesV1));
            state->outcome = Result<Capabilities>::success(std::move(c));
        } else {
            state->outcome = Result<Capabilities>::failure(Error(
                OvStorage_Status_Internal,
                "capabilities callback received null caps with no error"));
        }
        deliver(state);
    }
};

/// Drain-to-vector for the multi-fire AuthEvent stream. Suitable for
/// auth flows that terminate (succeed/fail/cancel); not appropriate
/// for unbounded continuous streams.
struct auth_event_drain_state : awaiter_state<std::vector<AuthEvent>> {
    std::vector<AuthEvent> events;
    bool error_seen = false;
};

struct auth_event_drain_awaiter
    : awaiter_base<std::vector<AuthEvent>, auth_event_drain_state> {
    static void on_event(
        OvStorage_AuthEvent* event,
        const OvStorage_Error* error,
        bool done,
        void* user_data)
    {
        auto* st = borrow_state(user_data);
        if (event != nullptr) {
            st->events.push_back(AuthEvent(event));
        }
        if (error != nullptr) {
            st->outcome =
                Result<std::vector<AuthEvent>>::failure(Error(*error));
            st->error_seen = true;
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
};

struct address_root_watch_state : awaiter_state<void> {
    AddressRootSnapshotHandler on_snapshot;
    bool error_seen = false;
};

struct address_root_watch_awaiter
    : awaiter_base<void, address_root_watch_state> {
    static void on_event(
        OvStorage_AddressRootList* list,
        const OvStorage_Error* error,
        bool done,
        void* user_data)
    {
        if (done) {
            auto state = reclaim_state(user_data);
            if (error != nullptr) {
                state->outcome = Result<void>::failure(Error(*error));
            } else if (!state->error_seen) {
                state->outcome = Result<void>::success();
            }
            deliver(state);
            return;
        }

        auto* st = borrow_state(user_data);
        if (error != nullptr) {
            if (list != nullptr) {
                ovstorage_address_root_list_destroy(list);
            }
            st->outcome = Result<void>::failure(Error(*error));
            st->error_seen = true;
            return;
        }
        if (list == nullptr) {
            return;
        }
        if (st->error_seen) {
            ovstorage_address_root_list_destroy(list);
            return;
        }

        try {
            st->on_snapshot(AddressRootList(list));
        } catch (...) {
            st->outcome = Result<void>::failure(Error(
                OvStorage_Status_Internal,
                "watch_address_roots snapshot callback threw"));
            st->error_seen = true;
        }
    }
};

} // namespace detail

// ---------------------------------------------------------------------------
// Library
// ---------------------------------------------------------------------------

// -- ticket #64: external token injection ------------------------------------

/// Resolved credential built by a `CredentialCallback::resolve` impl.
/// Holds an opaque C bundle handle internally; add fields via
/// `set_field(...)` which consumes a `SecretValue` (the host copies
/// bytes internally so the customer's source buffers can be freed
/// once `set_field` returns).
class ResolvedCredential {
public:
    ResolvedCredential() : bundle_(ovstorage_resolved_credential_bundle_create()) {}
    ~ResolvedCredential() { reset(); }
    ResolvedCredential(const ResolvedCredential&) = delete;
    ResolvedCredential& operator=(const ResolvedCredential&) = delete;
    ResolvedCredential(ResolvedCredential&& other) noexcept
        : bundle_(std::exchange(other.bundle_, nullptr)),
          has_expires_at(other.has_expires_at),
          expires_at_unix_nanos(other.expires_at_unix_nanos),
          source_name(std::move(other.source_name))
    {
    }
    ResolvedCredential& operator=(ResolvedCredential&& other) noexcept
    {
        if (this != &other) {
            reset();
            bundle_ = std::exchange(other.bundle_, nullptr);
            has_expires_at = other.has_expires_at;
            expires_at_unix_nanos = other.expires_at_unix_nanos;
            source_name = std::move(other.source_name);
        }
        return *this;
    }

    bool has_expires_at = false;
    std::uint64_t expires_at_unix_nanos = 0;
    std::string source_name;

    /// Add a field. On success, `value` is consumed; on failure,
    /// `value` is restored to the caller and an Error is returned.
    Result<void> set_field(std::string_view key, SecretValue&& value)
    {
        std::string key_str(key);
        OvStorage_SecretValue* raw = value.release();
        OvStorage_Error err{};
        OvStorage_Status status = ovstorage_resolved_credential_bundle_add_field(
            bundle_, key_str.c_str(), raw, &err);
        if (status != OvStorage_Status_Ok) {
            // Caller still owns the SecretValue on failure.
            value = SecretValue(raw);
            return Result<void>::failure(take_error(err));
        }
        return Result<void>::success();
    }

    OvStorage_OvResolvedCredentialBundle* release() noexcept
    {
        return std::exchange(bundle_, nullptr);
    }

    OvStorage_OvResolvedCredentialBundle* bundle_handle() const noexcept
    {
        return bundle_;
    }

private:
    void reset()
    {
        if (bundle_ != nullptr) {
            ovstorage_resolved_credential_bundle_destroy(bundle_);
            bundle_ = nullptr;
        }
    }

    OvStorage_OvResolvedCredentialBundle* bundle_ = nullptr;
};

/// Cache durability switch. Mirrors
/// [`OvStorage_CredentialCacheDurability`].
enum class CredentialCacheDurability : int {
    Persistent = 0,
    InMemoryOnly = 1,
};

/// Async-callback interface for the external-token-injection pattern.
/// Implementations override `resolve` to start the async fetch and
/// return a `std::future` that completes with the resolved credential
/// (or an error). The C++ wrapper internally adapts the future to the
/// C ABI's continuation-callback shape — spawns a one-shot thread to
/// `wait()` on the future and fire the C `completion(...)` callback
/// when ready.
///
/// Customers whose async work is event-driven (WebRTC, asyncio loop)
/// should fulfill a `std::promise` from their event handler and
/// return its associated `std::future` from `resolve()` — the wait
/// thread blocks for microseconds until the promise resolves.
class CredentialCallback {
public:
    virtual ~CredentialCallback() = default;
    virtual std::future<Result<ResolvedCredential>> resolve(
        std::string backend_id, std::string principal_id) = 0;
};

namespace detail {

struct CredentialCallbackShim {
    std::shared_ptr<CredentialCallback> callback;
};

inline void credential_callback_resolve_thunk(
    void* userdata,
    const char* backend_id,
    const char* principal_id,
    OvStorage_OvCredentialCallbackCompletion completion,
    void* completion_userdata)
{
    auto* shim = reinterpret_cast<CredentialCallbackShim*>(userdata);
    auto fut = shim->callback->resolve(
        std::string(backend_id), std::string(principal_id));
    // Spawn a one-shot wait thread so the C-side continuation contract
    // (completion fires on any thread, exactly once) is honored even
    // when the customer's future is already-ready or fulfilled
    // asynchronously by their own event loop.
    std::thread([fut = std::move(fut), completion, completion_userdata]() mutable {
        try {
            auto result = fut.get();
            if (result.has_value()) {
                auto& resolved = result.value();
                OvStorage_OvResolvedCredentialV1 ffi{};
                ffi.struct_size = sizeof(OvStorage_OvResolvedCredentialV1);
                ffi.bundle = resolved.release();  // host consumes on Ok
                ffi.has_expires_at = resolved.has_expires_at;
                ffi.expires_at_unix_nanos = resolved.expires_at_unix_nanos;
                ffi.source_name = resolved.source_name.c_str();
                completion(completion_userdata, OvStorage_Status_Ok, &ffi);
            } else {
                completion(completion_userdata, OvStorage_Status_PermissionDenied, nullptr);
            }
        } catch (...) {
            completion(completion_userdata, OvStorage_Status_Internal, nullptr);
        }
    }).detach();
}

inline void credential_callback_free_thunk(void* userdata)
{
    delete reinterpret_cast<CredentialCallbackShim*>(userdata);
}

inline void credential_callback_noop_resolve_thunk(
    void*, const char*, const char*,
    OvStorage_OvCredentialCallbackCompletion completion,
    void* completion_userdata)
{
    if (completion != nullptr) {
        completion(completion_userdata, OvStorage_Status_Internal, nullptr);
    }
}

inline void credential_callback_noop_free_thunk(void*) {}

} // namespace detail

struct LibraryInitOptions {
    std::uint32_t runtime_threads = 0; // 0 = library default (2 workers)
    /// Ticket #64: optional credential callback for external
    /// token-injection patterns. The shared_ptr is stored on the
    /// internal shim and freed when the C library handle drops via
    /// `free_userdata`.
    std::shared_ptr<CredentialCallback> credential_callback{};
    /// Required when `credential_callback` is non-null.
    std::string credential_callback_name{};
    CredentialCacheDurability credential_cache_durability =
        CredentialCacheDurability::Persistent;
};

class Library {
public:
    Library() = default;
    explicit Library(OvStorage_Library* handle) : handle_(handle) {}

    ~Library() { reset(); }
    Library(const Library&) = delete;
    Library& operator=(const Library&) = delete;

    Library(Library&& other) noexcept : handle_(std::exchange(other.handle_, nullptr)) {}
    Library& operator=(Library&& other) noexcept
    {
        if (this != &other) {
            reset();
            handle_ = std::exchange(other.handle_, nullptr);
        }
        return *this;
    }

    static Result<Library> init(LibraryInitOptions opts = {})
    {
        OvStorage_LibraryInitOptionsV1 c_opts{};
        c_opts.struct_size = sizeof(OvStorage_LibraryInitOptionsV1);
        c_opts.runtime_threads = opts.runtime_threads;
        c_opts.interactive_auth_capability = -1; // unspecified default
        c_opts.credential_cache_durability =
            static_cast<int>(opts.credential_cache_durability);
        // The credential callback shim outlives the Library handle —
        // the C side will free it via `free_userdata` on shutdown.
        std::string callback_name_storage = opts.credential_callback_name;
        if (opts.credential_callback) {
            auto* shim = new detail::CredentialCallbackShim{
                std::move(opts.credential_callback)};
            c_opts.has_credential_callback = true;
            c_opts.credential_callback.resolve =
                &detail::credential_callback_resolve_thunk;
            c_opts.credential_callback.free_userdata =
                &detail::credential_callback_free_thunk;
            c_opts.credential_callback.userdata = shim;
            c_opts.credential_callback_name = callback_name_storage.c_str();
        } else {
            c_opts.has_credential_callback = false;
            // The C side ignores `credential_callback` entirely when
            // `has_credential_callback` is false, but the function-pointer
            // fields are non-nullable on the C ABI — point at the no-op
            // resolve/free thunks so a buggy host that dereferences
            // them anyway crashes loudly rather than silently.
            c_opts.credential_callback.resolve =
                &detail::credential_callback_noop_resolve_thunk;
            c_opts.credential_callback.free_userdata =
                &detail::credential_callback_noop_free_thunk;
            c_opts.credential_callback.userdata = nullptr;
            c_opts.credential_callback_name = nullptr;
        }
        OvStorage_Library* h = nullptr;
        OvStorage_Error err{};
        auto status = ovstorage_library_init(&c_opts, &h, &err);
        if (status != OvStorage_Status_Ok) {
            return Result<Library>::failure(take_error(err));
        }
        return Result<Library>::success(Library(h));
    }

    /// Inject a credential into the cache directly (ticket #64).
    /// Bypasses the provider chain. Returns a future that completes
    /// when the host has committed the entry.
    task<void> set_credential(
        std::string backend_id,
        std::string principal_id,
        ResolvedCredential credential) const
    {
        if (handle_ == nullptr) co_return detail::null_library_result<void>();
        struct op : detail::status_awaiter {
            OvStorage_Library* lib;
            std::string backend_id_str;
            std::string principal_id_str;
            std::string source_name_storage;
            OvStorage_OvResolvedCredentialV1 ffi;
            bool await_suspend(std::coroutine_handle<> h)
            {
                s->continuation = h;
                ovstorage_library_set_credential(
                    lib,
                    backend_id_str.c_str(),
                    principal_id_str.c_str(),
                    &ffi,
                    &status_awaiter::on_complete,
                    release_user_data());
                return commit_suspend();
            }
        };
        op a{};
        a.lib = handle_;
        a.backend_id_str = std::move(backend_id);
        a.principal_id_str = std::move(principal_id);
        a.source_name_storage = std::move(credential.source_name);
        a.ffi = OvStorage_OvResolvedCredentialV1{};
        a.ffi.struct_size = sizeof(OvStorage_OvResolvedCredentialV1);
        a.ffi.bundle = credential.release();
        a.ffi.has_expires_at = credential.has_expires_at;
        a.ffi.expires_at_unix_nanos = credential.expires_at_unix_nanos;
        a.ffi.source_name = a.source_name_storage.c_str();
        co_return co_await a;
    }

    OvStorage_Library* handle() const noexcept { return handle_; }

    // -----------------------------------------------------------------
    // Async I/O methods. Each returns task<Result<T>>; the work begins
    // on co_await or sync_wait.
    // -----------------------------------------------------------------

    task<Info> stat(
        std::string address,
        bool full_metadata = false,
        const CancelToken* cancel = nullptr) const
    {
        if (handle_ == nullptr) co_return detail::null_library_result<Info>();
        struct op : detail::info_awaiter {
            OvStorage_Library* lib;
            std::string addr;
            OvStorage_StatOptionsV1 opts;
            const OvStorage_CancelToken* cancel;
            bool await_suspend(std::coroutine_handle<> h)
            {
                s->continuation = h;
                ovstorage_stat(lib, addr.c_str(), &opts, cancel,
                    &info_awaiter::on_complete, release_user_data());
                return commit_suspend();
            }
        };
        op a{};
        a.lib = handle_;
        a.addr = std::move(address);
        a.opts = OvStorage_StatOptionsV1{
            sizeof(OvStorage_StatOptionsV1), full_metadata};
        a.cancel = CancelToken::as_ptr(cancel);
        co_return co_await a;
    }

    task<std::pair<Bytes, Info>> read_bytes(
        std::string address,
        const CancelToken* cancel = nullptr) const
    {
        if (handle_ == nullptr) {
            co_return detail::null_library_result<std::pair<Bytes, Info>>();
        }
        struct op : detail::read_bytes_awaiter {
            OvStorage_Library* lib;
            std::string addr;
            const OvStorage_CancelToken* cancel;
            bool await_suspend(std::coroutine_handle<> h)
            {
                s->continuation = h;
                ovstorage_read_bytes(lib, addr.c_str(), nullptr, cancel,
                    &read_bytes_awaiter::on_complete, release_user_data());
                return commit_suspend();
            }
        };
        op a{};
        a.lib = handle_;
        a.addr = std::move(address);
        a.cancel = CancelToken::as_ptr(cancel);
        co_return co_await a;
    }

    task<std::vector<std::byte>> read_stream(
        std::string address,
        const CancelToken* cancel = nullptr) const
    {
        if (handle_ == nullptr) {
            co_return detail::null_library_result<std::vector<std::byte>>();
        }
        struct op : detail::read_stream_awaiter {
            OvStorage_Library* lib;
            std::string addr;
            const OvStorage_CancelToken* cancel;
            bool await_suspend(std::coroutine_handle<> h)
            {
                s->continuation = h;
                ovstorage_read_stream(lib, addr.c_str(), nullptr, cancel,
                    &read_stream_awaiter::on_chunk, release_user_data());
                return commit_suspend();
            }
        };
        op a{};
        a.lib = handle_;
        a.addr = std::move(address);
        a.cancel = CancelToken::as_ptr(cancel);
        co_return co_await a;
    }

    task<LocalDelegate> read_local_file(
        std::string address,
        const CancelToken* cancel = nullptr) const
    {
        if (handle_ == nullptr) co_return detail::null_library_result<LocalDelegate>();
        struct op : detail::local_delegate_awaiter {
            OvStorage_Library* lib;
            std::string addr;
            const OvStorage_CancelToken* cancel;
            bool await_suspend(std::coroutine_handle<> h)
            {
                s->continuation = h;
                ovstorage_read_local_file(lib, addr.c_str(), nullptr, cancel,
                    &local_delegate_awaiter::on_complete, release_user_data());
                return commit_suspend();
            }
        };
        op a{};
        a.lib = handle_;
        a.addr = std::move(address);
        a.cancel = CancelToken::as_ptr(cancel);
        co_return co_await a;
    }

    task<Info> write(
        std::string address,
        std::span<const std::byte> data,
        bool no_overwrite = false,
        const CancelToken* cancel = nullptr) const
    {
        if (handle_ == nullptr) co_return detail::null_library_result<Info>();
        struct op : detail::info_awaiter {
            OvStorage_Library* lib;
            std::string addr;
            const std::uint8_t* data_ptr;
            std::size_t data_len;
            OvStorage_WriteOptionsV1 opts;
            const OvStorage_CancelToken* cancel;
            bool await_suspend(std::coroutine_handle<> h)
            {
                s->continuation = h;
                ovstorage_write(lib, addr.c_str(), data_ptr, data_len, &opts, cancel,
                    &info_awaiter::on_complete, release_user_data());
                return commit_suspend();
            }
        };
        op a{};
        a.lib = handle_;
        a.addr = std::move(address);
        a.data_ptr = reinterpret_cast<const std::uint8_t*>(data.data());
        a.data_len = data.size();
        a.opts = OvStorage_WriteOptionsV1{
            sizeof(OvStorage_WriteOptionsV1), no_overwrite};
        a.cancel = CancelToken::as_ptr(cancel);
        co_return co_await a;
    }

    task<void> delete_object(
        std::string address,
        const CancelToken* cancel = nullptr) const
    {
        if (handle_ == nullptr) co_return detail::null_library_result<void>();
        struct op : detail::status_awaiter {
            OvStorage_Library* lib;
            std::string addr;
            const OvStorage_CancelToken* cancel;
            bool await_suspend(std::coroutine_handle<> h)
            {
                s->continuation = h;
                ovstorage_delete(lib, addr.c_str(), cancel,
                    &status_awaiter::on_complete, release_user_data());
                return commit_suspend();
            }
        };
        op a{};
        a.lib = handle_;
        a.addr = std::move(address);
        a.cancel = CancelToken::as_ptr(cancel);
        co_return co_await a;
    }

    // Register a connection. Takes ownership of `request`
    // (consumed on success). On prologue error (null library,
    // null/already-consumed request), the request is NOT consumed and
    // the caller's `request` retains ownership.
    task<Connection> add_connection(
        ConnectionRequest&& request,
        const CancelToken* cancel = nullptr) const
    {
        if (handle_ == nullptr) co_return detail::null_library_result<Connection>();
        struct op : detail::connection_awaiter {
            OvStorage_Library* lib;
            OvStorage_ConnectionRequest* request;
            const OvStorage_CancelToken* cancel;
            bool await_suspend(std::coroutine_handle<> h)
            {
                s->continuation = h;
                ovstorage_library_add_connection(
                    lib, request, cancel,
                    &connection_awaiter::on_complete, release_user_data());
                return commit_suspend();
            }
        };
        op a{};
        a.lib = handle_;
        a.request = request.release();
        a.cancel = CancelToken::as_ptr(cancel);
        co_return co_await a;
    }

    task<void> remove_connection(
        std::string connection_id,
        const CancelToken* cancel = nullptr) const
    {
        if (handle_ == nullptr) co_return detail::null_library_result<void>();
        struct op : detail::status_awaiter {
            OvStorage_Library* lib;
            std::string id;
            const OvStorage_CancelToken* cancel;
            bool await_suspend(std::coroutine_handle<> h)
            {
                s->continuation = h;
                ovstorage_library_remove_connection(
                    lib, id.c_str(), cancel,
                    &status_awaiter::on_complete, release_user_data());
                return commit_suspend();
            }
        };
        op a{};
        a.lib = handle_;
        a.id = std::move(connection_id);
        a.cancel = CancelToken::as_ptr(cancel);
        co_return co_await a;
    }

    task<ConnectionList> list_connections(const CancelToken* cancel = nullptr) const
    {
        if (handle_ == nullptr) co_return detail::null_library_result<ConnectionList>();
        struct op : detail::connection_list_awaiter {
            OvStorage_Library* lib;
            const OvStorage_CancelToken* cancel;
            bool await_suspend(std::coroutine_handle<> h)
            {
                s->continuation = h;
                ovstorage_library_list_connections(
                    lib, cancel,
                    &connection_list_awaiter::on_complete, release_user_data());
                return commit_suspend();
            }
        };
        op a{};
        a.lib = handle_;
        a.cancel = CancelToken::as_ptr(cancel);
        co_return co_await a;
    }

    /// Load and register a single plugin cdylib at `path`. Caller must trust
    /// the path — `dlopen` runs platform loader hooks.
    task<void> load_plugin(std::string path) const
    {
        if (handle_ == nullptr) co_return detail::null_library_result<void>();
        struct op : detail::status_awaiter {
            OvStorage_Library* lib;
            std::string path;
            bool await_suspend(std::coroutine_handle<> h)
            {
                s->continuation = h;
                ovstorage_library_load_plugin(
                    lib, path.c_str(),
                    &status_awaiter::on_complete, release_user_data());
                return commit_suspend();
            }
        };
        op a{};
        a.lib = handle_;
        a.path = std::move(path);
        co_return co_await a;
    }

    /// Scan a directory for `libovstorage_plugin_*.{so,dylib,dll}` and load
    /// each. `dir = std::nullopt` resolves to `OVSTORAGE_PLUGIN_DIR` (or
    /// `<exe-dir>/plugins/`). A non-existent directory returns success with
    /// no plugins loaded.
    task<void> load_plugins_from_dir(std::optional<std::string> dir = std::nullopt) const
    {
        if (handle_ == nullptr) co_return detail::null_library_result<void>();
        struct op : detail::status_awaiter {
            OvStorage_Library* lib;
            std::optional<std::string> dir;
            bool await_suspend(std::coroutine_handle<> h)
            {
                s->continuation = h;
                ovstorage_library_load_plugins_from_dir(
                    lib, dir ? dir->c_str() : nullptr,
                    &status_awaiter::on_complete, release_user_data());
                return commit_suspend();
            }
        };
        op a{};
        a.lib = handle_;
        a.dir = std::move(dir);
        co_return co_await a;
    }

    /// Load `ovstorage.toml` and register its `[[connections]]` on this
    /// library. `path = std::nullopt` uses the default search path
    /// (`./ovstorage.toml` then `$XDG_CONFIG_HOME/ovstorage/ovstorage.toml`).
    /// Returns the freshly registered list (empty when no file exists).
    /// Credential refs resolve through the same `SecretStore` namespace the
    /// library was initialized with — so CLI `write-config --secrets keyring`
    /// output is picked up transparently.
    task<ConnectionList> load_config(std::optional<std::string> path = std::nullopt) const
    {
        if (handle_ == nullptr) co_return detail::null_library_result<ConnectionList>();
        struct op : detail::connection_list_awaiter {
            OvStorage_Library* lib;
            std::optional<std::string> path;
            bool await_suspend(std::coroutine_handle<> h)
            {
                s->continuation = h;
                ovstorage_library_load_config(
                    lib, path ? path->c_str() : nullptr,
                    &connection_list_awaiter::on_complete, release_user_data());
                return commit_suspend();
            }
        };
        op a{};
        a.lib = handle_;
        a.path = std::move(path);
        co_return co_await a;
    }

    task<Connection> update_connection_credentials(
        std::string connection_id,
        SecretBundle&& credentials,
        const CancelToken* cancel = nullptr) const
    {
        if (handle_ == nullptr) co_return detail::null_library_result<Connection>();
        struct op : detail::connection_awaiter {
            OvStorage_Library* lib;
            std::string id;
            OvStorage_SecretBundle* bundle;
            const OvStorage_CancelToken* cancel;
            bool await_suspend(std::coroutine_handle<> h)
            {
                s->continuation = h;
                ovstorage_library_update_connection_credentials(
                    lib, id.c_str(), bundle, cancel,
                    &connection_awaiter::on_complete, release_user_data());
                return commit_suspend();
            }
        };
        op a{};
        a.lib = handle_;
        a.id = std::move(connection_id);
        a.bundle = credentials.release();
        a.cancel = CancelToken::as_ptr(cancel);
        co_return co_await a;
    }

    /// Drain-to-vector for the multi-fire authenticate flow. Returns
    /// every event the iterator produced, in order. Suitable for
    /// flows that terminate (succeed/fail/cancel).
    task<std::vector<AuthEvent>> authenticate_connection(
        std::string connection_id,
        const CancelToken* cancel = nullptr) const
    {
        if (handle_ == nullptr)
            co_return detail::null_library_result<std::vector<AuthEvent>>();
        struct op : detail::auth_event_drain_awaiter {
            OvStorage_Library* lib;
            std::string id;
            const OvStorage_CancelToken* cancel;
            bool await_suspend(std::coroutine_handle<> h)
            {
                s->continuation = h;
                ovstorage_library_authenticate_connection(
                    lib, id.c_str(), cancel,
                    &auth_event_drain_awaiter::on_event, release_user_data());
                return commit_suspend();
            }
        };
        op a{};
        a.lib = handle_;
        a.id = std::move(connection_id);
        a.cancel = CancelToken::as_ptr(cancel);
        co_return co_await a;
    }

    task<Alias> add_alias(
        AliasRequest&& request,
        const CancelToken* cancel = nullptr) const
    {
        if (handle_ == nullptr) co_return detail::null_library_result<Alias>();
        struct op : detail::alias_awaiter {
            OvStorage_Library* lib;
            OvStorage_AliasRequest* request;
            const OvStorage_CancelToken* cancel;
            bool await_suspend(std::coroutine_handle<> h)
            {
                s->continuation = h;
                ovstorage_library_add_alias(
                    lib, request, cancel,
                    &alias_awaiter::on_complete, release_user_data());
                return commit_suspend();
            }
        };
        op a{};
        a.lib = handle_;
        a.request = request.release();
        a.cancel = CancelToken::as_ptr(cancel);
        co_return co_await a;
    }

    task<void> remove_alias(
        std::string alias_id,
        const CancelToken* cancel = nullptr) const
    {
        if (handle_ == nullptr) co_return detail::null_library_result<void>();
        struct op : detail::status_awaiter {
            OvStorage_Library* lib;
            std::string id;
            const OvStorage_CancelToken* cancel;
            bool await_suspend(std::coroutine_handle<> h)
            {
                s->continuation = h;
                ovstorage_library_remove_alias(
                    lib, id.c_str(), cancel,
                    &status_awaiter::on_complete, release_user_data());
                return commit_suspend();
            }
        };
        op a{};
        a.lib = handle_;
        a.id = std::move(alias_id);
        a.cancel = CancelToken::as_ptr(cancel);
        co_return co_await a;
    }

    task<AliasList> list_aliases(const CancelToken* cancel = nullptr) const
    {
        if (handle_ == nullptr) co_return detail::null_library_result<AliasList>();
        struct op : detail::alias_list_awaiter {
            OvStorage_Library* lib;
            const OvStorage_CancelToken* cancel;
            bool await_suspend(std::coroutine_handle<> h)
            {
                s->continuation = h;
                ovstorage_library_list_aliases(
                    lib, cancel,
                    &alias_list_awaiter::on_complete, release_user_data());
                return commit_suspend();
            }
        };
        op a{};
        a.lib = handle_;
        a.cancel = CancelToken::as_ptr(cancel);
        co_return co_await a;
    }

    task<AddressVisibilityOverride> set_address_visibility(
        std::string address,
        OvStorage_AddressVisibility visibility,
        bool persist,
        const CancelToken* cancel = nullptr) const
    {
        if (handle_ == nullptr)
            co_return detail::null_library_result<AddressVisibilityOverride>();
        struct op : detail::address_visibility_override_awaiter {
            OvStorage_Library* lib;
            std::string addr;
            OvStorage_AddressVisibility vis;
            bool persist;
            const OvStorage_CancelToken* cancel;
            bool await_suspend(std::coroutine_handle<> h)
            {
                s->continuation = h;
                ovstorage_library_set_address_visibility(
                    lib, addr.c_str(), vis, persist, cancel,
                    &address_visibility_override_awaiter::on_complete, release_user_data());
                return commit_suspend();
            }
        };
        op a{};
        a.lib = handle_;
        a.addr = std::move(address);
        a.vis = visibility;
        a.persist = persist;
        a.cancel = CancelToken::as_ptr(cancel);
        co_return co_await a;
    }

    task<AddressVisibilityOverrideList> list_address_visibility_overrides(
        const CancelToken* cancel = nullptr) const
    {
        if (handle_ == nullptr)
            co_return detail::null_library_result<AddressVisibilityOverrideList>();
        struct op : detail::address_visibility_override_list_awaiter {
            OvStorage_Library* lib;
            const OvStorage_CancelToken* cancel;
            bool await_suspend(std::coroutine_handle<> h)
            {
                s->continuation = h;
                ovstorage_library_list_address_visibility_overrides(
                    lib, cancel,
                    &address_visibility_override_list_awaiter::on_complete, release_user_data());
                return commit_suspend();
            }
        };
        op a{};
        a.lib = handle_;
        a.cancel = CancelToken::as_ptr(cancel);
        co_return co_await a;
    }

    task<AddressRootList> list_address_roots(const CancelToken* cancel = nullptr) const
    {
        if (handle_ == nullptr) co_return detail::null_library_result<AddressRootList>();
        struct op : detail::address_root_list_awaiter {
            OvStorage_Library* lib;
            const OvStorage_CancelToken* cancel;
            bool await_suspend(std::coroutine_handle<> h)
            {
                s->continuation = h;
                ovstorage_library_list_address_roots(
                    lib, cancel,
                    &address_root_list_awaiter::on_complete, release_user_data());
                return commit_suspend();
            }
        };
        op a{};
        a.lib = handle_;
        a.cancel = CancelToken::as_ptr(cancel);
        co_return co_await a;
    }

    /// Continuous address-root watch. `on_snapshot` runs on an
    /// ovstorage worker thread and owns each snapshot list it receives.
    /// Pass a `CancelToken` and cancel it to end the watch deliberately.
    task<void> watch_address_roots(
        AddressRootSnapshotHandler on_snapshot,
        const CancelToken* cancel = nullptr) const
    {
        if (handle_ == nullptr) co_return detail::null_library_result<void>();
        if (!on_snapshot) {
            co_return Result<void>::failure(Error(
                OvStorage_Status_InvalidArgument,
                "watch_address_roots requires a snapshot callback"));
        }
        struct op : detail::address_root_watch_awaiter {
            OvStorage_Library* lib;
            const OvStorage_CancelToken* cancel;
            bool await_suspend(std::coroutine_handle<> h)
            {
                s->continuation = h;
                ovstorage_library_watch_address_roots(
                    lib, cancel,
                    &address_root_watch_awaiter::on_event, release_user_data());
                return commit_suspend();
            }
        };
        op a{};
        a.lib = handle_;
        a.cancel = CancelToken::as_ptr(cancel);
        a.s->on_snapshot = std::move(on_snapshot);
        co_return co_await a;
    }

    task<BackendKindDescriptorList> list_backend_kinds(
        const CancelToken* cancel = nullptr) const
    {
        if (handle_ == nullptr)
            co_return detail::null_library_result<BackendKindDescriptorList>();
        struct op : detail::backend_kind_descriptor_list_awaiter {
            OvStorage_Library* lib;
            const OvStorage_CancelToken* cancel;
            bool await_suspend(std::coroutine_handle<> h)
            {
                s->continuation = h;
                ovstorage_library_list_backend_kinds(
                    lib, cancel,
                    &backend_kind_descriptor_list_awaiter::on_complete, release_user_data());
                return commit_suspend();
            }
        };
        op a{};
        a.lib = handle_;
        a.cancel = CancelToken::as_ptr(cancel);
        co_return co_await a;
    }

    task<Capabilities> capabilities_for(
        std::string prefix,
        const CancelToken* cancel = nullptr) const
    {
        if (handle_ == nullptr) co_return detail::null_library_result<Capabilities>();
        struct op : detail::capabilities_awaiter {
            OvStorage_Library* lib;
            std::string prefix;
            const OvStorage_CancelToken* cancel;
            bool await_suspend(std::coroutine_handle<> h)
            {
                s->continuation = h;
                ovstorage_library_capabilities_for(
                    lib, prefix.c_str(), cancel,
                    &capabilities_awaiter::on_complete, release_user_data());
                return commit_suspend();
            }
        };
        op a{};
        a.lib = handle_;
        a.prefix = std::move(prefix);
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
        if (handle_ == nullptr) co_return detail::null_library_result<List>();
        struct op : detail::list_awaiter {
            OvStorage_Library* lib;
            std::string prefix;
            std::string token;
            OvStorage_ListOptionsV1 opts;
            const OvStorage_CancelToken* cancel;
            bool await_suspend(std::coroutine_handle<> h)
            {
                s->continuation = h;
                opts.page_token = token.empty() ? nullptr : token.c_str();
                ovstorage_list(lib, prefix.c_str(), &opts, cancel,
                    &list_awaiter::on_complete, release_user_data());
                return commit_suspend();
            }
        };
        op a{};
        a.lib = handle_;
        a.prefix = std::move(prefix);
        a.token = std::move(page_token);
        a.opts = OvStorage_ListOptionsV1{};
        a.opts.struct_size = sizeof(OvStorage_ListOptionsV1);
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
        if (handle_ == nullptr) co_return detail::null_library_result<VersionList>();
        struct op : detail::list_versions_awaiter {
            OvStorage_Library* lib;
            std::string addr;
            std::string token;
            OvStorage_ListVersionsOptionsV1 opts;
            const OvStorage_CancelToken* cancel;
            bool await_suspend(std::coroutine_handle<> h)
            {
                s->continuation = h;
                opts.page_token = token.empty() ? nullptr : token.c_str();
                ovstorage_list_versions(lib, addr.c_str(), &opts, cancel,
                    &list_versions_awaiter::on_complete, release_user_data());
                return commit_suspend();
            }
        };
        op a{};
        a.lib = handle_;
        a.addr = std::move(address);
        a.token = std::move(page_token);
        a.opts = OvStorage_ListVersionsOptionsV1{};
        a.opts.struct_size = sizeof(OvStorage_ListVersionsOptionsV1);
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
        if (handle_ == nullptr) co_return detail::null_library_result<Info>();
        struct op : detail::info_awaiter {
            OvStorage_Library* lib;
            std::string src;
            std::string dest;
            const OvStorage_CancelToken* cancel;
            bool await_suspend(std::coroutine_handle<> h)
            {
                s->continuation = h;
                ovstorage_copy(lib, src.c_str(), dest.c_str(), cancel,
                    &info_awaiter::on_complete, release_user_data());
                return commit_suspend();
            }
        };
        op a{};
        a.lib = handle_;
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
        if (handle_ == nullptr) co_return detail::null_library_result<void>();
        struct op : detail::status_awaiter {
            OvStorage_Library* lib;
            std::string src;
            std::string dest;
            const OvStorage_CancelToken* cancel;
            bool await_suspend(std::coroutine_handle<> h)
            {
                s->continuation = h;
                ovstorage_rename(lib, src.c_str(), dest.c_str(), cancel,
                    &status_awaiter::on_complete, release_user_data());
                return commit_suspend();
            }
        };
        op a{};
        a.lib = handle_;
        a.src = std::move(src);
        a.dest = std::move(dest);
        a.cancel = CancelToken::as_ptr(cancel);
        co_return co_await a;
    }

    task<Info> create_directory(
        std::string address,
        const CancelToken* cancel = nullptr) const
    {
        if (handle_ == nullptr) co_return detail::null_library_result<Info>();
        struct op : detail::info_awaiter {
            OvStorage_Library* lib;
            std::string addr;
            OvStorage_CreateDirectoryOptionsV1 opts;
            const OvStorage_CancelToken* cancel;
            bool await_suspend(std::coroutine_handle<> h)
            {
                s->continuation = h;
                ovstorage_create_directory(lib, addr.c_str(), &opts, cancel,
                    &info_awaiter::on_complete, release_user_data());
                return commit_suspend();
            }
        };
        op a{};
        a.lib = handle_;
        a.addr = std::move(address);
        a.opts = OvStorage_CreateDirectoryOptionsV1{
            sizeof(OvStorage_CreateDirectoryOptionsV1)};
        a.cancel = CancelToken::as_ptr(cancel);
        co_return co_await a;
    }

    task<void> delete_directory(
        std::string address,
        const CancelToken* cancel = nullptr) const
    {
        if (handle_ == nullptr) co_return detail::null_library_result<void>();
        struct op : detail::status_awaiter {
            OvStorage_Library* lib;
            std::string addr;
            OvStorage_DeleteDirectoryOptionsV1 opts;
            const OvStorage_CancelToken* cancel;
            bool await_suspend(std::coroutine_handle<> h)
            {
                s->continuation = h;
                ovstorage_delete_directory(lib, addr.c_str(), &opts, cancel,
                    &status_awaiter::on_complete, release_user_data());
                return commit_suspend();
            }
        };
        op a{};
        a.lib = handle_;
        a.addr = std::move(address);
        a.opts = OvStorage_DeleteDirectoryOptionsV1{
            sizeof(OvStorage_DeleteDirectoryOptionsV1), 0};
        a.cancel = CancelToken::as_ptr(cancel);
        co_return co_await a;
    }

    task<Info> update_metadata(
        std::string address,
        const UpdateMetadataOptions& options,
        const CancelToken* cancel = nullptr) const
    {
        if (handle_ == nullptr) co_return detail::null_library_result<Info>();
        struct op : detail::info_awaiter {
            OvStorage_Library* lib;
            std::string addr;
            const OvStorage_UpdateMetadataOptions* opts;
            const OvStorage_CancelToken* cancel;
            bool await_suspend(std::coroutine_handle<> h)
            {
                s->continuation = h;
                ovstorage_update_metadata(lib, addr.c_str(), opts, cancel,
                    &info_awaiter::on_complete, release_user_data());
                return commit_suspend();
            }
        };
        op a{};
        a.lib = handle_;
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
        if (handle_ == nullptr) co_return detail::null_library_result<AccessDecision>();
        struct op : detail::check_access_awaiter {
            OvStorage_Library* lib;
            std::string addr;
            OvStorage_AccessOps ops;
            const OvStorage_CancelToken* cancel;
            bool await_suspend(std::coroutine_handle<> h)
            {
                s->continuation = h;
                ovstorage_check_access(lib, addr.c_str(), ops, cancel,
                    &check_access_awaiter::on_complete, release_user_data());
                return commit_suspend();
            }
        };
        op a{};
        a.lib = handle_;
        a.addr = std::move(address);
        a.ops = OvStorage_AccessOps{read, write, delete_object, update_metadata};
        a.cancel = CancelToken::as_ptr(cancel);
        co_return co_await a;
    }

private:
    void reset()
    {
        if (handle_ != nullptr) {
            ovstorage_library_shutdown(handle_);
            handle_ = nullptr;
        }
    }

    OvStorage_Library* handle_ = nullptr;
};

} // namespace ovstorage

#endif
