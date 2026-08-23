/* SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Link-completeness test for the pure-C source distribution.
 *
 * Keep the first table in the same order as the declarations in ovstorage.h
 * and the second in the same order as the ovstorage_plugin_* declarations in
 * ovstorage_plugin.h.  tools/ovtasks/_c_source_examples.py checks that each
 * header and its table contain exactly the same API symbols.  Reading the
 * volatile tables from main prevents an optimizing compiler (and linker
 * garbage collection) from discarding the relocations that make missing
 * implementations a link error.
 */

#include "ovstorage.h"
#include "ovstorage_defaults.h"
#include "ovstorage_plugin.h"

#include <stddef.h>

typedef void (*OvStorage_AnyFunction)(void);

#define OVSTORAGE_API_REF(function) ((OvStorage_AnyFunction) &(function))

static OvStorage_AnyFunction const volatile OVSTORAGE_API_FUNCTIONS[] = {
    OVSTORAGE_API_REF(ovstorage_error_clear),
    OVSTORAGE_API_REF(ovstorage_error_message),
    OVSTORAGE_API_REF(ovstorage_error_code_name),
    OVSTORAGE_API_REF(ovstorage_status_is_retryable),
    OVSTORAGE_API_REF(ovstorage_init_auth_substrate),
    OVSTORAGE_API_REF(ovstorage_cancel_token_create),
    OVSTORAGE_API_REF(ovstorage_cancel_token_destroy),
    OVSTORAGE_API_REF(ovstorage_cancel_token_cancel),
    OVSTORAGE_API_REF(ovstorage_cancel_token_is_canceled),
    OVSTORAGE_API_REF(ovstorage_update_metadata_options_create),
    OVSTORAGE_API_REF(ovstorage_update_metadata_options_destroy),
    OVSTORAGE_API_REF(ovstorage_update_metadata_options_set),
    OVSTORAGE_API_REF(ovstorage_update_metadata_options_remove),
    OVSTORAGE_API_REF(ovstorage_access_decision_clear),
    OVSTORAGE_API_REF(ovstorage_bytes_destroy),
    OVSTORAGE_API_REF(ovstorage_write_redirect_batch_destroy),
    OVSTORAGE_API_REF(ovstorage_info_destroy),
    OVSTORAGE_API_REF(ovstorage_info_clone),
    OVSTORAGE_API_REF(ovstorage_local_delegate_destroy),
    OVSTORAGE_API_REF(ovstorage_local_delegate_path),
    OVSTORAGE_API_REF(ovstorage_local_delegate_info),
    OVSTORAGE_API_REF(ovstorage_list_destroy),
    OVSTORAGE_API_REF(ovstorage_version_list_destroy),
    OVSTORAGE_API_REF(ovstorage_config_value_create_string),
    OVSTORAGE_API_REF(ovstorage_config_value_create_int),
    OVSTORAGE_API_REF(ovstorage_config_value_create_bool),
    OVSTORAGE_API_REF(ovstorage_config_value_create_toml),
    OVSTORAGE_API_REF(ovstorage_config_value_destroy),
    OVSTORAGE_API_REF(ovstorage_config_value_kind),
    OVSTORAGE_API_REF(ovstorage_config_value_as_string),
    OVSTORAGE_API_REF(ovstorage_config_value_as_int),
    OVSTORAGE_API_REF(ovstorage_config_value_as_bool),
    OVSTORAGE_API_REF(ovstorage_config_value_as_toml),
    OVSTORAGE_API_REF(ovstorage_secret_value_create_bytes),
    OVSTORAGE_API_REF(ovstorage_secret_value_create_file),
    OVSTORAGE_API_REF(ovstorage_secret_value_create_oauth_token),
    OVSTORAGE_API_REF(ovstorage_secret_value_create_mtls_cert_pair),
    OVSTORAGE_API_REF(ovstorage_secret_value_create_system_identity),
    OVSTORAGE_API_REF(ovstorage_secret_value_destroy),
    OVSTORAGE_API_REF(ovstorage_connection_request_create),
    OVSTORAGE_API_REF(ovstorage_connection_request_destroy),
    OVSTORAGE_API_REF(ovstorage_connection_request_set_display_name),
    OVSTORAGE_API_REF(ovstorage_connection_request_set_persist),
    OVSTORAGE_API_REF(ovstorage_connection_request_add_config),
    OVSTORAGE_API_REF(ovstorage_connection_request_add_credential),
    OVSTORAGE_API_REF(ovstorage_secret_bundle_create),
    OVSTORAGE_API_REF(ovstorage_secret_bundle_destroy),
    OVSTORAGE_API_REF(ovstorage_secret_bundle_add),
    OVSTORAGE_API_REF(ovstorage_stat),
    OVSTORAGE_API_REF(ovstorage_read_bytes),
    OVSTORAGE_API_REF(ovstorage_read_stream),
    OVSTORAGE_API_REF(ovstorage_read_local_file),
    OVSTORAGE_API_REF(ovstorage_write),
    OVSTORAGE_API_REF(ovstorage_write_stream),
    OVSTORAGE_API_REF(ovstorage_write_redirect),
    OVSTORAGE_API_REF(ovstorage_continue_write),
    OVSTORAGE_API_REF(ovstorage_delete),
    OVSTORAGE_API_REF(ovstorage_list),
    OVSTORAGE_API_REF(ovstorage_list_versions),
    OVSTORAGE_API_REF(ovstorage_get_latest_version),
    OVSTORAGE_API_REF(ovstorage_watch_directory),
    OVSTORAGE_API_REF(ovstorage_copy),
    OVSTORAGE_API_REF(ovstorage_rename),
    OVSTORAGE_API_REF(ovstorage_create_directory),
    OVSTORAGE_API_REF(ovstorage_delete_directory),
    OVSTORAGE_API_REF(ovstorage_update_metadata),
    OVSTORAGE_API_REF(ovstorage_check_access),
    OVSTORAGE_API_REF(ovstorage_load_plugin),
    OVSTORAGE_API_REF(ovstorage_plugin_destroy),
    OVSTORAGE_API_REF(ovstorage_registry_create),
    OVSTORAGE_API_REF(ovstorage_registry_destroy),
    OVSTORAGE_API_REF(ovstorage_registry_add_plugin),
    OVSTORAGE_API_REF(ovstorage_inspect_plugin),
    OVSTORAGE_API_REF(ovstorage_kind_descriptor_list_destroy),
    OVSTORAGE_API_REF(ovstorage_kind_descriptor_list_len),
    OVSTORAGE_API_REF(ovstorage_kind_descriptor_list_item_layer_type),
    OVSTORAGE_API_REF(ovstorage_kind_descriptor_list_item_kind),
    OVSTORAGE_API_REF(ovstorage_kind_descriptor_list_item_display_name),
    OVSTORAGE_API_REF(ovstorage_stack_create),
    OVSTORAGE_API_REF(ovstorage_stack_destroy),
    OVSTORAGE_API_REF(ovstorage_stack_add_layer),
    OVSTORAGE_API_REF(ovstorage_stack_add_layer_config),
    OVSTORAGE_API_REF(ovstorage_stack_set_root),
    OVSTORAGE_API_REF(ovstorage_stack_set_inner),
    OVSTORAGE_API_REF(ovstorage_stack_set_children),
    OVSTORAGE_API_REF(ovstorage_stack_add_connection),
    OVSTORAGE_API_REF(ovstorage_stack_build),
    OVSTORAGE_API_REF(ovstorage_stack_build_async),
    OVSTORAGE_API_REF(ovstorage_layer_handle_destroy),
    OVSTORAGE_API_REF(ovstorage_connection_destroy),
    OVSTORAGE_API_REF(ovstorage_connection_list_destroy),
    OVSTORAGE_API_REF(ovstorage_probe),
    OVSTORAGE_API_REF(ovstorage_add_connection),
    OVSTORAGE_API_REF(ovstorage_list_connections),
    OVSTORAGE_API_REF(ovstorage_remove_connection),
    OVSTORAGE_API_REF(ovstorage_update_connection_credentials),
    OVSTORAGE_API_REF(ovstorage_update_connection_attributes),
    OVSTORAGE_API_REF(ovstorage_auth_event_destroy),
    OVSTORAGE_API_REF(ovstorage_authenticate_connection),
    OVSTORAGE_API_REF(ovstorage_root_info_destroy),
    OVSTORAGE_API_REF(ovstorage_root_info_list_destroy),
    OVSTORAGE_API_REF(ovstorage_list_address_roots),
    OVSTORAGE_API_REF(ovstorage_export_handle),
    OVSTORAGE_API_REF(ovstorage_import_handle),
};

#undef OVSTORAGE_API_REF

/*
 * The plugin/backend surface of the distribution: the host-facing
 * reclamation helpers declared by ovstorage_plugin.h and implemented in
 * src/plugin_values.c.  In the Rust distribution these live in the
 * ovstorage-plugin crate compiled into each plugin; this source set
 * must define them itself or hosts following the header docs fail to link.
 */
#define OVSTORAGE_PLUGIN_API_REF(function) \
    ((OvStorage_AnyFunction) &(function))

static OvStorage_AnyFunction const volatile OVSTORAGE_PLUGIN_API_FUNCTIONS[] = {
    OVSTORAGE_PLUGIN_API_REF(ovstorage_plugin_backend_change_event_free),
    OVSTORAGE_PLUGIN_API_REF(ovstorage_plugin_auth_event_stream_free),
    OVSTORAGE_PLUGIN_API_REF(ovstorage_plugin_backend_change_stream_free),
    OVSTORAGE_PLUGIN_API_REF(ovstorage_plugin_backend_address_roots_change_free),
    OVSTORAGE_PLUGIN_API_REF(ovstorage_plugin_backend_address_roots_stream_free),
    OVSTORAGE_PLUGIN_API_REF(ovstorage_plugin_error_context_free),
    OVSTORAGE_PLUGIN_API_REF(ovstorage_plugin_error_free),
    OVSTORAGE_PLUGIN_API_REF(ovstorage_plugin_error_get_next_action),
    OVSTORAGE_PLUGIN_API_REF(ovstorage_plugin_backend_id_free),
    OVSTORAGE_PLUGIN_API_REF(ovstorage_plugin_resolved_target_free),
    OVSTORAGE_PLUGIN_API_REF(ovstorage_plugin_object_info_free),
    OVSTORAGE_PLUGIN_API_REF(ovstorage_plugin_body_stream_free),
    OVSTORAGE_PLUGIN_API_REF(ovstorage_plugin_body_free),
    OVSTORAGE_PLUGIN_API_REF(ovstorage_plugin_write_result_free),
    OVSTORAGE_PLUGIN_API_REF(ovstorage_plugin_read_result_free),
    OVSTORAGE_PLUGIN_API_REF(ovstorage_plugin_write_step_free),
    OVSTORAGE_PLUGIN_API_REF(ovstorage_plugin_access_decision_free),
    OVSTORAGE_PLUGIN_API_REF(ovstorage_plugin_str_free),
    OVSTORAGE_PLUGIN_API_REF(ovstorage_plugin_bytes_free),
    OVSTORAGE_PLUGIN_API_REF(ovstorage_plugin_storage_backend_kind_descriptor_free),
    OVSTORAGE_PLUGIN_API_REF(ovstorage_plugin_connection_request_free),
    OVSTORAGE_PLUGIN_API_REF(ovstorage_plugin_connection_free),
    OVSTORAGE_PLUGIN_API_REF(ovstorage_plugin_auth_event_free),
    OVSTORAGE_PLUGIN_API_REF(ovstorage_plugin_extension_entry_free),
    OVSTORAGE_PLUGIN_API_REF(ovstorage_plugin_extensions_free),
    OVSTORAGE_PLUGIN_API_REF(ovstorage_plugin_auth_credential_decode),
    OVSTORAGE_PLUGIN_API_REF(ovstorage_plugin_auth_credential_free),
    OVSTORAGE_PLUGIN_API_REF(ovstorage_plugin_root_info_free),
    OVSTORAGE_PLUGIN_API_REF(ovstorage_plugin_root_info_snapshot_free),
    OVSTORAGE_PLUGIN_API_REF(ovstorage_plugin_root_info_change_free),
    OVSTORAGE_PLUGIN_API_REF(ovstorage_plugin_root_info_change_stream_free),
    OVSTORAGE_PLUGIN_API_REF(ovstorage_plugin_connection_snapshot_free),
    OVSTORAGE_PLUGIN_API_REF(ovstorage_plugin_connection_change_free),
    OVSTORAGE_PLUGIN_API_REF(ovstorage_plugin_connection_change_stream_free),
    OVSTORAGE_PLUGIN_API_REF(ovstorage_plugin_list_page_free),
    OVSTORAGE_PLUGIN_API_REF(ovstorage_plugin_version_page_free),
    OVSTORAGE_PLUGIN_API_REF(ovstorage_plugin_list_address_roots_result_free),
    OVSTORAGE_PLUGIN_API_REF(ovstorage_plugin_list_connections_result_free),
    OVSTORAGE_PLUGIN_API_REF(ovstorage_plugin_layer_kind_descriptor_free),
};

#undef OVSTORAGE_PLUGIN_API_REF

/*
 * The request-release entry points declared by include/ovstorage_defaults.h
 * and implemented in src/plugin_values.c.  A declining slot owns the request
 * it was handed, and these are how it gives that ownership back; a third-party
 * plugin that follows the header would otherwise discover a missing definition
 * at its own link time rather than ours.
 */
#define OVSTORAGE_DEFAULTS_API_REF(function) \
    ((OvStorage_AnyFunction) &(function))

static OvStorage_AnyFunction const volatile OVSTORAGE_DEFAULTS_API_FUNCTIONS[] = {
    OVSTORAGE_DEFAULTS_API_REF(ovstorage_plugin_stat_request_release),
    OVSTORAGE_DEFAULTS_API_REF(ovstorage_plugin_read_request_release),
    OVSTORAGE_DEFAULTS_API_REF(ovstorage_plugin_write_request_release),
    OVSTORAGE_DEFAULTS_API_REF(ovstorage_plugin_list_request_release),
    OVSTORAGE_DEFAULTS_API_REF(ovstorage_plugin_delete_request_release),
    OVSTORAGE_DEFAULTS_API_REF(ovstorage_plugin_copy_request_release),
    OVSTORAGE_DEFAULTS_API_REF(ovstorage_plugin_rename_request_release),
    OVSTORAGE_DEFAULTS_API_REF(ovstorage_plugin_update_metadata_request_release),
    OVSTORAGE_DEFAULTS_API_REF(ovstorage_plugin_check_access_request_release),
    OVSTORAGE_DEFAULTS_API_REF(ovstorage_plugin_list_versions_request_release),
    OVSTORAGE_DEFAULTS_API_REF(ovstorage_plugin_watch_directory_request_release),
    OVSTORAGE_DEFAULTS_API_REF(ovstorage_plugin_create_directory_request_release),
    OVSTORAGE_DEFAULTS_API_REF(ovstorage_plugin_delete_directory_request_release),
    OVSTORAGE_DEFAULTS_API_REF(ovstorage_plugin_root_info_for_request_release),
    OVSTORAGE_DEFAULTS_API_REF(ovstorage_plugin_continue_write_request_release),
    OVSTORAGE_DEFAULTS_API_REF(ovstorage_plugin_layer_connection_request_release),
    OVSTORAGE_DEFAULTS_API_REF(ovstorage_plugin_remove_connection_request_release),
    OVSTORAGE_DEFAULTS_API_REF(ovstorage_plugin_update_connection_credentials_request_release),
    OVSTORAGE_DEFAULTS_API_REF(ovstorage_plugin_update_connection_attributes_request_release),
    OVSTORAGE_DEFAULTS_API_REF(ovstorage_plugin_authenticate_request_release),
    OVSTORAGE_DEFAULTS_API_REF(ovstorage_plugin_list_address_roots_request_release),
    OVSTORAGE_DEFAULTS_API_REF(ovstorage_plugin_list_connections_request_release),
};

#undef OVSTORAGE_DEFAULTS_API_REF

int main(void)
{
    size_t index;
    const size_t function_count =
        sizeof(OVSTORAGE_API_FUNCTIONS) / sizeof(OVSTORAGE_API_FUNCTIONS[0]);
    const size_t plugin_function_count =
        sizeof(OVSTORAGE_PLUGIN_API_FUNCTIONS) /
        sizeof(OVSTORAGE_PLUGIN_API_FUNCTIONS[0]);
    const size_t defaults_function_count =
        sizeof(OVSTORAGE_DEFAULTS_API_FUNCTIONS) /
        sizeof(OVSTORAGE_DEFAULTS_API_FUNCTIONS[0]);

    for (index = 0; index < function_count; ++index) {
        if (OVSTORAGE_API_FUNCTIONS[index] == NULL) {
            return 1;
        }
    }
    for (index = 0; index < plugin_function_count; ++index) {
        if (OVSTORAGE_PLUGIN_API_FUNCTIONS[index] == NULL) {
            return 1;
        }
    }
    for (index = 0; index < defaults_function_count; ++index) {
        if (OVSTORAGE_DEFAULTS_API_FUNCTIONS[index] == NULL) {
            return 1;
        }
    }
    return 0;
}
