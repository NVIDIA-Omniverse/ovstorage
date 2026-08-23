// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Header-conformance gate: this translation unit includes exactly one
// shipped header and nothing else.  A header that stops compiling as
// standalone C++20 (missing cbindgen cpp_compat enum guards or
// extern "C" linkage guards, or a broken wrapper template) fails this
// crate's build instead of the first downstream consumer's.
// tests/roundtrip.rs calls the probe so the object is pulled into the
// link on every target.
//
// `ovstorage.hpp` is the one shipped header that needs C++20: its
// `task<T>` machinery uses `<coroutine>`.  The C headers keep their own
// C99 and C++17 conformance TUs alongside this one.
//
// Parsing the header is not enough for the wrapper itself: a member of a
// non-template class is only type-checked when it is instantiated, so a
// method whose body no longer matches the C signature it calls would
// still parse.  The references below force every RAII type, every
// coroutine method, and every builder verb to be instantiated, which is
// what turns a stale signature into a compile error here.

#include "ovstorage.hpp"

#include <cstddef>

namespace {

// Opaque-handle pointer sizes from the C ABI.
constexpr std::size_t sz_handle_ptr = sizeof(::OvStorage_LayerHandle *);
constexpr std::size_t sz_stack_ptr = sizeof(::OvStorage_Stack *);
constexpr std::size_t sz_status = sizeof(::OvStorage_Status);

// The three read verbs are overloaded on `ReadOptions`, so `auto` cannot
// deduce a member pointer to them. Spelling both signatures is the stronger
// pin: it asserts each arity exists taking exactly these parameters, where
// `auto` only asserted that some unique member carried the name.
template <class T>
using read_fn = ovstorage::task<T> (ovstorage::LayerHandle::*)(
    std::string, const ovstorage::CancelToken*) const;

// The three write verbs are overloaded on `WriteOptions` for the same
// reason and pinned the same way.
using write_fn = ovstorage::task<ovstorage::Info> (ovstorage::LayerHandle::*)(
    std::string,
    std::span<const std::byte>,
    bool,
    const ovstorage::CancelToken*) const;
using options_write_fn =
    ovstorage::task<ovstorage::Info> (ovstorage::LayerHandle::*)(
        std::string,
        std::span<const std::byte>,
        ovstorage::WriteOptions,
        const ovstorage::CancelToken*) const;
using write_stream_fn =
    ovstorage::task<ovstorage::Info> (ovstorage::LayerHandle::*)(
        std::string,
        ovstorage::WriteStream&&,
        bool,
        std::optional<std::uint64_t>,
        const ovstorage::CancelToken*) const;
using options_write_stream_fn =
    ovstorage::task<ovstorage::Info> (ovstorage::LayerHandle::*)(
        std::string,
        ovstorage::WriteStream&&,
        ovstorage::WriteOptions,
        const ovstorage::CancelToken*) const;
using write_redirect_fn =
    ovstorage::task<ovstorage::WriteRedirectBatch> (
        ovstorage::LayerHandle::*)(
        std::string,
        bool,
        std::optional<std::uint64_t>,
        const ovstorage::CancelToken*) const;
using options_write_redirect_fn =
    ovstorage::task<ovstorage::WriteRedirectBatch> (
        ovstorage::LayerHandle::*)(
        std::string,
        ovstorage::WriteOptions,
        const ovstorage::CancelToken*) const;

template <class T>
using ranged_read_fn = ovstorage::task<T> (ovstorage::LayerHandle::*)(
    std::string, ovstorage::ReadOptions, const ovstorage::CancelToken*) const;

// Anchor the wrapper's RAII / value types so their member templates get
// instantiated. Default-constructed handles are all-null and destruct
// cleanly without touching a runtime.
void instantiate_wrapper_types()
{
    ovstorage::Error err;
    (void)err.code();

    // Result<T> / Result<void>.
    auto ok = ovstorage::Result<void>::success();
    (void)ok.has_value();
    auto fail = ovstorage::Result<int>::failure(ovstorage::Error{});
    (void)fail.has_value();

    // Data wrappers — all default-construct to null and self-destruct.
    ovstorage::Info info;
    ovstorage::Bytes bytes;
    ovstorage::WriteStream write_stream;
    ovstorage::WriteRedirectBatch redirects;
    ovstorage::WriteStep write_step;
    ovstorage::ReadOptions read_options;
    ovstorage::WatchDirectoryOptions watch_options;
    ovstorage::WriteOptions write_options;
    ovstorage::ConnectionAttributePatch attribute_patch;
    ovstorage::LocalDelegate delegate;
    ovstorage::AccessDecision decision;
    ovstorage::List list;
    ovstorage::VersionList versions;
    ovstorage::Capabilities caps;
    ovstorage::Connection connection;
    ovstorage::ConnectionList connections;
    ovstorage::AuthEvent event;
    ovstorage::RootInfo root_info;
    ovstorage::RootInfoList root_infos;
    ovstorage::KindDescriptorList kinds;
    ovstorage::CancelToken cancel;
    OvStorage_Info raw_info{};
    raw_info.address = "file:///moved";
    raw_info.kind = OvStorage_ObjectKind_Directory;
    ovstorage::Info owned_info(ovstorage_info_clone(&raw_info));
    ovstorage::Info moved_info(std::move(owned_info));
    assert(moved_info.address() == "file:///moved");
    assert(owned_info.address().empty());
    assert(owned_info.kind() == OvStorage_ObjectKind_File);
    assert(!owned_info.has_size());
    assert(owned_info.size() == 0);
    (void)info.get();
    (void)info.address();
    (void)info.kind();
    (void)info.has_size();
    (void)info.size();
    (void)info.etag();
    (void)info.version();
    (void)info.has_mtime_unix_nanos();
    (void)info.mtime_unix_nanos();
    (void)info.system_metadata();
    (void)info.user_metadata();
    (void)list.size();
    (void)list.next_page_token();
    (void)list.address(0);
    (void)list.info(0).clone();
    (void)versions.size();
    (void)versions.next_page_token();
    (void)versions.address(0);
    (void)versions.info(0).clone();
    (void)write_stream.valid();
    (void)redirects.size();
    (void)write_step.is_done();
    (void)read_options.range_start;
    (void)watch_options.poll_interval_ms;

    // Every field this ABI bump added, named once here.
    //
    // The C structs and the C++ wrapper are separate hand-written models of
    // one surface, and a field added to the first and forgotten in the
    // second is invisible: `WatchDirectoryOptions::has_since` shipped that
    // way, and only the empty-cursor case — the one the flag exists for —
    // misbehaved, silently. Naming each one costs a line and turns the next
    // omission into a build failure instead of a review finding.
    //
    // Options-shaped structs are ASSIGNED, so a missing field fails to
    // compile here. Result-shaped types are read through their accessor,
    // so a missing accessor does the same.
    write_options.no_overwrite = false;
    write_options.if_match_etag = std::string("etag");
    write_options.size_hint = std::uint64_t{0};
    watch_options.has_since = true;

    (void)caps.supports_write();
    (void)caps.supports_write_stream();
    (void)caps.supports_write_redirect();
    (void)caps.supports_delete();
    (void)caps.supports_create_directory();
    (void)caps.supports_delete_directory();
    (void)caps.supports_no_overwrite_write();
    (void)caps.supports_copy();
    (void)caps.supports_rename();
    (void)caps.supports_list();
    (void)caps.supports_server_side_copy();
    (void)caps.supports_server_side_rename();
    (void)caps.supports_atomic_rename();
    (void)caps.supports_native_metadata_patch();
    (void)caps.supports_metadata_rewrite_emulation();
    (void)caps.wants_list_backed_stat();
    (void)caps.populates_subdirectory_metadata();
    (void)caps.populates_effective_permissions_on_stat();
    (void)caps.watch_directory_resumable();
    (void)caps.watch_directory_kinds();
    (void)caps.version_list_order();
    (void)caps.watch_directory_max_lag_nanos();

    (void)info.modified_by();
    (void)info.checksums();
    (void)info.effective_permissions();
    (void)info.view().modified_by();
    (void)info.view().checksums();
    (void)info.view().effective_permissions();

    (void)connection.auth_failed_code();
    (void)connection.auth_failed_code_name();
    (void)connection.auth_failed_attempts();
    (void)connection.auth_failed_message();
    (void)connection.authenticated_at_unix_nanos();
    (void)connection.authenticated_expires_at_unix_nanos();
    (void)connection.awaiting_auth_reason();
    (void)connection.awaiting_auth_unknown_details();

    (void)root_info.owning_target();
    (void)root_info.range_read_strategy();

    (void)event.failed_error_code_name();

    // `PluginRejected` needs no wrapper work: `Error::code()` returns the
    // C enum itself, so a new discriminant is reachable the moment the
    // header carries it. Named anyway, so the accounting is complete.
    (void)OvStorage_Status_PluginRejected;
    (void)attribute_patch.visible;
    (void)caps.raw();
    (void)connection.id();
    (void)connection.backend_kind();
    (void)connection.display_name();
    (void)connection.source_kind();
    (void)connection.auth_state_kind();
    (void)connection.capabilities();
    (void)connection.address_count();
    (void)connection.address(0);
    (void)connections.size();
    (void)connections.item_at(0);
    (void)root_info.root();
    (void)root_info.layer_kind();
    (void)root_info.display_name();
    (void)root_info.has_connection_id();
    (void)root_info.connection_id();
    (void)root_info.visible();
    (void)root_info.visibility();
    (void)root_info.capabilities();
    (void)root_info.source_kind();
    (void)root_info.source_static_layer();
    (void)root_info.source_connection_id();
    (void)root_info.source_broker_principal();
    (void)root_info.source_alias_to();
    (void)root_info.source_alias_source_kind();
    (void)root_info.source_alias_source_static_layer();
    (void)root_info.source_alias_source_runtime_persisted();
    (void)root_info.source_alias_source_broker_principal();
    (void)root_info.has_alias_state();
    (void)root_info.alias_state_kind();
    (void)root_info.alias_state_chain_too_long_reason();
    (void)root_info.user_metadata();
    (void)root_info.icon();
    (void)root_infos.size();
    (void)root_infos.item_at(0);
    (void)kinds.size();
    (void)cancel.is_canceled();
    // Every device-code field a host needs to render the prompt.
    (void)event.kind();
    (void)event.open_browser_url();
    (void)event.open_browser_expires_at_unix_nanos();
    (void)event.device_code_user_code();
    (void)event.device_code_verification_url();
    (void)event.device_code_expires_at_unix_nanos();
    (void)event.device_code_interval_nanos();
    (void)event.progress_message();
    (void)event.succeeded_connection();
    (void)event.failed_error_code();
    (void)event.failed_error_message();
    assert(connection.source_kind() == OvStorage_ConnectionSourceKind_Runtime);
    assert(event.kind() == OvStorage_AuthEventKind_Cancelled);
    assert(event.failed_error_code() == OvStorage_Status_Ok);

    // task<T> awaiter machinery: just name the types.
    using task_info = ovstorage::task<ovstorage::Info>;
    using task_void = ovstorage::task<void>;
    (void)sizeof(task_info);
    (void)sizeof(task_void);

    // Member-function pointers force each LayerHandle coroutine method to
    // be parsed + type-checked (a stale C signature fails to compile).
    auto stat_fn = &ovstorage::LayerHandle::stat;
    using read_bytes_result = std::pair<ovstorage::Bytes, ovstorage::Info>;
    read_fn<read_bytes_result> read_bytes_fn =
        &ovstorage::LayerHandle::read_bytes;
    ranged_read_fn<read_bytes_result> ranged_read_bytes_fn =
        &ovstorage::LayerHandle::read_bytes;
    read_fn<std::vector<std::byte>> read_stream_fn =
        &ovstorage::LayerHandle::read_stream;
    ranged_read_fn<std::vector<std::byte>> ranged_read_stream_fn =
        &ovstorage::LayerHandle::read_stream;
    read_fn<ovstorage::LocalDelegate> read_local_file_fn =
        &ovstorage::LayerHandle::read_local_file;
    ranged_read_fn<ovstorage::LocalDelegate> ranged_read_local_file_fn =
        &ovstorage::LayerHandle::read_local_file;
    write_fn plain_write_fn = &ovstorage::LayerHandle::write;
    options_write_fn options_write = &ovstorage::LayerHandle::write;
    write_stream_fn plain_write_stream_fn =
        &ovstorage::LayerHandle::write_stream;
    options_write_stream_fn options_write_stream =
        &ovstorage::LayerHandle::write_stream;
    write_redirect_fn plain_write_redirect_fn =
        &ovstorage::LayerHandle::write_redirect;
    options_write_redirect_fn options_write_redirect =
        &ovstorage::LayerHandle::write_redirect;
    auto continue_write_fn = &ovstorage::LayerHandle::continue_write;
    auto get_latest_version_fn =
        &ovstorage::LayerHandle::get_latest_version;
    auto watch_directory_fn = &ovstorage::LayerHandle::watch_directory;
    auto delete_fn = &ovstorage::LayerHandle::delete_object;
    auto list_fn = &ovstorage::LayerHandle::list;
    auto list_versions_fn = &ovstorage::LayerHandle::list_versions;
    auto copy_fn = &ovstorage::LayerHandle::copy;
    auto rename_fn = &ovstorage::LayerHandle::rename;
    auto mkdir_fn = &ovstorage::LayerHandle::create_directory;
    auto rmdir_fn = &ovstorage::LayerHandle::delete_directory;
    auto update_md_fn = &ovstorage::LayerHandle::update_metadata;
    auto check_access_fn = &ovstorage::LayerHandle::check_access;
    auto probe_fn = &ovstorage::LayerHandle::probe;
    auto add_conn_fn = &ovstorage::LayerHandle::add_connection;
    auto list_conns_fn = &ovstorage::LayerHandle::list_connections;
    auto remove_conn_fn = &ovstorage::LayerHandle::remove_connection;
    auto update_creds_fn = &ovstorage::LayerHandle::update_connection_credentials;
    auto update_attributes_fn =
        &ovstorage::LayerHandle::update_connection_attributes;
    auto authenticate_fn = &ovstorage::LayerHandle::authenticate_connection;
    auto list_roots_fn = &ovstorage::LayerHandle::list_address_roots;
    // Cross-language live handoff.
    auto export_handle_fn = &ovstorage::LayerHandle::export_handle;
    auto import_handle_fn = &ovstorage::LayerHandle::import_handle;
    (void)stat_fn;
    (void)read_bytes_fn;
    (void)ranged_read_bytes_fn;
    (void)read_stream_fn;
    (void)ranged_read_stream_fn;
    (void)read_local_file_fn;
    (void)ranged_read_local_file_fn;
    (void)plain_write_fn;
    (void)options_write;
    (void)plain_write_stream_fn;
    (void)options_write_stream;
    (void)plain_write_redirect_fn;
    (void)options_write_redirect;
    (void)continue_write_fn;
    (void)get_latest_version_fn;
    (void)watch_directory_fn;
    (void)delete_fn;
    (void)list_fn;
    (void)list_versions_fn;
    (void)copy_fn;
    (void)rename_fn;
    (void)mkdir_fn;
    (void)rmdir_fn;
    (void)update_md_fn;
    (void)check_access_fn;
    (void)probe_fn;
    (void)add_conn_fn;
    (void)list_conns_fn;
    (void)remove_conn_fn;
    (void)update_creds_fn;
    (void)update_attributes_fn;
    (void)authenticate_fn;
    (void)list_roots_fn;
    (void)export_handle_fn;
    (void)import_handle_fn;

    // Stack / Registry / Plugin builder methods.
    auto add_layer_fn = &ovstorage::Stack::add_layer;
    auto add_layer_config_fn = &ovstorage::Stack::add_layer_config;
    auto set_root_fn = &ovstorage::Stack::set_root;
    auto set_inner_fn = &ovstorage::Stack::set_inner;
    auto set_children_fn = &ovstorage::Stack::set_children;
    auto stack_add_conn_fn = &ovstorage::Stack::add_connection;
    auto build_fn = &ovstorage::Stack::build;
    auto reg_add_plugin_fn = &ovstorage::Registry::add_plugin;
    auto plugin_load_fn = &ovstorage::Plugin::load;
    auto plugin_inspect_fn = &ovstorage::Plugin::inspect;
    (void)add_layer_fn;
    (void)add_layer_config_fn;
    (void)set_root_fn;
    (void)set_inner_fn;
    (void)set_children_fn;
    (void)stack_add_conn_fn;
    (void)build_fn;
    (void)reg_add_plugin_fn;
    (void)plugin_load_fn;
    (void)plugin_inspect_fn;
}

}  // namespace

extern "C" int ovstorage_c_source_header_hpp_cpp20();

extern "C" int ovstorage_c_source_header_hpp_cpp20()
{
    // Execute the default/moved-from access path as well as type-checking it:
    // every visible-struct wrapper must guard its null handle.
    instantiate_wrapper_types();
    return static_cast<int>(sz_handle_ptr + sz_stack_ptr + sz_status) != 0 ? 0 : 1;
}
