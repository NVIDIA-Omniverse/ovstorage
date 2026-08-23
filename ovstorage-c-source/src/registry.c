/* SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Layer-factory registry and ABI-v2 plugin lifecycle.
 */

#include "internal.h"

#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define OVC_PLUGIN_MANIFEST_MINIMUM_SIZE                                \
    offsetof(OvStoragePlugin_PluginManifestV1, test_only)
#define OVC_PLUGIN_MANIFEST_TEST_ONLY_SIZE                              \
    (offsetof(OvStoragePlugin_PluginManifestV1, test_only) +            \
     sizeof(((OvStoragePlugin_PluginManifestV1 *)0)->test_only))
#define OVC_PLUGIN_INIT_VTABLE_SIZE                                     \
    (offsetof(OvStoragePlugin_PluginInitResultV1, plugin_vtable) +      \
     sizeof(((OvStoragePlugin_PluginInitResultV1 *)0)->plugin_vtable))
#define OVC_PLUGIN_VTABLE_ABI_SIZE                                      \
    (offsetof(OvStoragePlugin_PluginVTableV1, abi_version) +            \
     sizeof(((OvStoragePlugin_PluginVTableV1 *)0)->abi_version))
#define OVC_PLUGIN_VTABLE_DROP_SIZE                                     \
    (offsetof(OvStoragePlugin_PluginVTableV1, drop) +                   \
     sizeof(((OvStoragePlugin_PluginVTableV1 *)0)->drop))

struct ovc_plugin_registration {
    ovc_ref_count references;
    ovc_dlhandle mapping;
    void *plugin_state;
    const OvStoragePlugin_PluginVTableV1 *plugin_vtable;
};

#if !defined(_WIN32) && !defined(__GNUC__) && !defined(__clang__)
static ovc_mutex g_ovc_registry_reference_lock = OVC_MUTEX_INITIALIZER;
#endif

static OvStorage_Status ovc_registry_error(
    OvStorage_Error *out_error,
    OvStorage_Status status,
    const char *format,
    ...)
{
    char message[1024];
    size_t length;
    va_list arguments;

    if (out_error == NULL) {
        return status;
    }
    ovstorage_error_clear(out_error);
    out_error->code = status;
    out_error->code_name = ovc_status_code_name(status);
    if (format == NULL) {
        return status;
    }

    va_start(arguments, format);
    if (vsnprintf(message, sizeof(message), format, arguments) < 0) {
        message[0] = '\0';
    }
    va_end(arguments);
    message[sizeof(message) - 1] = '\0';

    length = strlen(message);
    if (length == SIZE_MAX) {
        return status;
    }
    out_error->message = (char *)malloc(length + 1);
    if (out_error->message != NULL) {
        memcpy(out_error->message, message, length + 1);
    }
    return status;
}

static void ovc_registry_success(OvStorage_Error *out_error)
{
    ovstorage_error_clear(out_error);
}

static bool ovc_registry_reference_retain(volatile long *references)
{
#if defined(_WIN32)
    long current;

    current = InterlockedCompareExchange(references, 0, 0);
    for (;;) {
        long observed;

        if (current <= 0 || current == LONG_MAX) {
            return false;
        }
        observed = InterlockedCompareExchange(references,
                                              current + 1,
                                              current);
        if (observed == current) {
            return true;
        }
        current = observed;
    }
#elif defined(__GNUC__) || defined(__clang__)
    long current;

    current = __sync_val_compare_and_swap(references, 0L, 0L);
    for (;;) {
        if (current <= 0 || current == LONG_MAX) {
            return false;
        }
        if (__sync_bool_compare_and_swap(references,
                                         current,
                                         current + 1)) {
            return true;
        }
        current = __sync_val_compare_and_swap(references, 0L, 0L);
    }
#else
    bool retained;

    (void)ovc_mutex_lock(&g_ovc_registry_reference_lock);
    retained = *references > 0 && *references < LONG_MAX;
    if (retained) {
        ++*references;
    }
    (void)ovc_mutex_unlock(&g_ovc_registry_reference_lock);
    return retained;
#endif
}

static bool ovc_registry_reference_release(volatile long *references)
{
#if defined(_WIN32)
    return InterlockedDecrement(references) == 0;
#elif defined(__GNUC__) || defined(__clang__)
    return __sync_sub_and_fetch(references, 1L) == 0;
#else
    bool last;

    (void)ovc_mutex_lock(&g_ovc_registry_reference_lock);
    --*references;
    last = *references == 0;
    (void)ovc_mutex_unlock(&g_ovc_registry_reference_lock);
    return last;
#endif
}

static ovc_plugin_registration *ovc_plugin_registration_retain(
    ovc_plugin_registration *registration)
{
    if (registration == NULL ||
        !ovc_registry_reference_retain(&registration->references.value)) {
        return NULL;
    }
    return registration;
}

static void ovc_plugin_registration_release(
    ovc_plugin_registration *registration)
{
    if (registration == NULL ||
        !ovc_registry_reference_release(&registration->references.value)) {
        return;
    }

    if (registration->plugin_state != NULL &&
        registration->plugin_vtable != NULL &&
        registration->plugin_vtable->drop != NULL) {
        registration->plugin_vtable->drop(registration->plugin_state);
    }
    registration->plugin_state = NULL;
    registration->plugin_vtable = NULL;

    /*
     * Deliberately do not close registration->mapping. Plugins may retain
     * host callbacks, and the frozen inspect_plugin contract pins every
     * successful open for the remaining process lifetime.
     */
    registration->mapping = NULL;
    free(registration);
}

ovc_layer_factory *ovc_layer_factory_retain(
    const ovc_layer_factory *factory)
{
    ovc_layer_factory *mutable_factory;

    mutable_factory = (ovc_layer_factory *)factory;
    if (mutable_factory == NULL ||
        !ovc_registry_reference_retain(
            &mutable_factory->references.value)) {
        return NULL;
    }
    return mutable_factory;
}

void ovc_layer_factory_release(ovc_layer_factory *factory)
{
    if (factory == NULL ||
        !ovc_registry_reference_release(&factory->references.value)) {
        return;
    }
    free(factory->kind.ptr);
    free(factory->display_name.ptr);
    ovc_plugin_registration_release(factory->registration);
    free(factory);
}

static OvStorage_Status ovc_registry_validate_plugin_vtable(
    const OvStoragePlugin_PluginVTableV1 *vtable,
    OvStorage_Error *out_error)
{
    if (vtable == NULL) {
        return ovc_registry_error(
            out_error,
            OvStorage_Status_InvalidArgument,
            "plugin init returned a null PluginVTableV1");
    }
    if (vtable->struct_size < sizeof(*vtable)) {
        return ovc_registry_error(
            out_error,
            OvStorage_Status_Internal,
            "plugin PluginVTableV1.struct_size is too small");
    }
    if (vtable->abi_version !=
        OVSTORAGE_PLUGIN_ABI_VERSION) {
        return ovc_registry_error(
            out_error,
            OvStorage_Status_IncompatibleType,
            "plugin PluginVTableV1.abi_version is not the supported Layer ABI");
    }
    if (vtable->drop == NULL) {
        return ovc_registry_error(
            out_error,
            OvStorage_Status_InvalidArgument,
            "plugin PluginVTableV1.drop is null");
    }
    return OvStorage_Status_Ok;
}

static OvStorage_Status ovc_registry_validate_descriptor(
    const OvStoragePlugin_LayerKindDescriptor *descriptor,
    const OvStoragePlugin_PluginVTableV1 *vtable,
    OvStorage_Error *out_error)
{
    if (descriptor == NULL) {
        return ovc_registry_error(out_error,
                                  OvStorage_Status_InvalidArgument,
                                  "plugin kind descriptor is null");
    }
    if (descriptor->struct_size < sizeof(*descriptor)) {
        return ovc_registry_error(
            out_error,
            OvStorage_Status_Internal,
            "plugin LayerKindDescriptor.struct_size is too small");
    }
    if (!ovc_utf8_is_valid(descriptor->kind.ptr, descriptor->kind.len)) {
        return ovc_registry_error(out_error,
                                  OvStorage_Status_InvalidArgument,
                                  "plugin kind is not valid UTF-8");
    }
    if (!ovc_utf8_is_valid(descriptor->display_name.ptr,
                           descriptor->display_name.len)) {
        return ovc_registry_error(out_error,
                                  OvStorage_Status_InvalidArgument,
                                  "plugin display_name is not valid UTF-8");
    }

    switch (descriptor->layer_type) {
    case OvStoragePlugin_LayerType_Backend:
        if (vtable->create_backend == NULL) {
            return ovc_registry_error(
                out_error,
                OvStorage_Status_InvalidArgument,
                "backend kind has no create_backend factory");
        }
        break;
    case OvStoragePlugin_LayerType_Wrapper:
        if (vtable->create_wrapper == NULL) {
            return ovc_registry_error(
                out_error,
                OvStorage_Status_InvalidArgument,
                "wrapper kind has no create_wrapper factory");
        }
        break;
    case OvStoragePlugin_LayerType_Router:
        if (vtable->create_router == NULL) {
            return ovc_registry_error(
                out_error,
                OvStorage_Status_InvalidArgument,
                "router kind has no create_router factory");
        }
        break;
    default:
        return ovc_registry_error(out_error,
                                  OvStorage_Status_InvalidArgument,
                                  "plugin kind has an unknown layer_type");
    }
    return OvStorage_Status_Ok;
}

static OvStorage_Status ovc_registry_validate_plugin_kinds(
    const OvStoragePlugin_PluginInitResultV1 *init,
    OvStorage_Error *out_error)
{
    OvStorage_Status status;
    size_t index;

    for (index = 0; index < init->kind_count; ++index) {
        const OvStoragePlugin_Str *kind;
        size_t previous;

        status = ovc_registry_validate_descriptor(&init->kinds[index],
                                                  init->plugin_vtable,
                                                  out_error);
        if (status != OvStorage_Status_Ok) {
            return status;
        }
        kind = &init->kinds[index].kind;
        if (kind->len == sizeof("file") - 1 &&
            memcmp(kind->ptr, "file", sizeof("file") - 1) == 0) {
            return ovc_registry_error(
                out_error,
                OvStorage_Status_InvalidArgument,
                "plugin advertises reserved built-in Layer kind 'file'");
        }
        for (previous = 0; previous < index; ++previous) {
            const OvStoragePlugin_Str *earlier;

            earlier = &init->kinds[previous].kind;
            if (earlier->len == kind->len &&
                (kind->len == 0 ||
                 memcmp(earlier->ptr, kind->ptr, kind->len) == 0)) {
                const char *kind_ptr;
                int kind_length;

                kind_ptr = kind->ptr == NULL ? "" : kind->ptr;
                kind_length =
                    kind->len > INT_MAX ? INT_MAX : (int)kind->len;
                return ovc_registry_error(
                    out_error,
                    OvStorage_Status_InvalidArgument,
                    "plugin advertises Layer kind '%.*s' more than once",
                    kind_length,
                    kind_ptr);
            }
        }
    }
    return OvStorage_Status_Ok;
}

static bool ovc_registry_slice_copy(ovc_string_slice *out,
                                    const char *source,
                                    size_t length)
{
    size_t allocation_length;

    allocation_length = length == 0 ? 1 : length;
    out->ptr = (char *)malloc(allocation_length);
    if (out->ptr == NULL) {
        out->len = 0;
        return false;
    }
    if (length == 0) {
        out->ptr[0] = '\0';
    } else {
        memcpy(out->ptr, source, length);
    }
    out->len = length;
    return true;
}

static OvStorage_Status ovc_layer_factory_create(
    const OvStoragePlugin_LayerKindDescriptor *descriptor,
    void *plugin_state,
    const OvStoragePlugin_PluginVTableV1 *plugin_vtable,
    ovc_plugin_registration *registration,
    ovc_layer_factory **out_factory,
    OvStorage_Error *out_error)
{
    ovc_layer_factory *factory;
    OvStorage_Status status;

    *out_factory = NULL;
    status = ovc_registry_validate_descriptor(descriptor,
                                              plugin_vtable,
                                              out_error);
    if (status != OvStorage_Status_Ok) {
        return status;
    }

    factory = (ovc_layer_factory *)calloc(1, sizeof(*factory));
    if (factory == NULL) {
        return ovc_registry_error(out_error,
                                  OvStorage_Status_Internal,
                                  "out of memory");
    }
    factory->references.value = 1L;
    if (!ovc_registry_slice_copy(&factory->kind,
                                 descriptor->kind.ptr,
                                 descriptor->kind.len) ||
        !ovc_registry_slice_copy(&factory->display_name,
                                 descriptor->display_name.ptr,
                                 descriptor->display_name.len)) {
        free(factory->kind.ptr);
        free(factory->display_name.ptr);
        free(factory);
        return ovc_registry_error(out_error,
                                  OvStorage_Status_Internal,
                                  "out of memory");
    }
    if (registration != NULL) {
        factory->registration =
            ovc_plugin_registration_retain(registration);
        if (factory->registration == NULL) {
            free(factory->kind.ptr);
            free(factory->display_name.ptr);
            free(factory);
            return ovc_registry_error(
                out_error,
                OvStorage_Status_Internal,
                "plugin registration reference count overflow");
        }
    }
    factory->plugin_state = plugin_state;
    factory->plugin_vtable = plugin_vtable;
    factory->descriptor = descriptor;
    factory->layer_type = descriptor->layer_type;
    factory->accepts_connections = descriptor->accepts_connections;
    *out_factory = factory;
    return OvStorage_Status_Ok;
}

static bool ovc_layer_factory_kind_equals(const ovc_layer_factory *factory,
                                          const char *kind,
                                          size_t kind_length)
{
    return factory != NULL && factory->kind.len == kind_length &&
           (kind_length == 0 ||
            memcmp(factory->kind.ptr, kind, kind_length) == 0);
}

static OvStorage_Status ovc_registry_reserve(OvStorage_Registry *registry,
                                             size_t required,
                                             OvStorage_Error *out_error)
{
    ovc_layer_factory **factories;
    size_t capacity;

    if (required <= registry->factory_capacity) {
        return OvStorage_Status_Ok;
    }
    if (required > SIZE_MAX / sizeof(*factories)) {
        return ovc_registry_error(out_error,
                                  OvStorage_Status_Internal,
                                  "registry capacity overflow");
    }

    capacity = registry->factory_capacity == 0
                   ? 4
                   : registry->factory_capacity;
    while (capacity < required) {
        if (capacity > SIZE_MAX / 2) {
            capacity = required;
            break;
        }
        capacity *= 2;
    }
    if (capacity > SIZE_MAX / sizeof(*factories)) {
        return ovc_registry_error(out_error,
                                  OvStorage_Status_Internal,
                                  "registry capacity overflow");
    }
    factories = (ovc_layer_factory **)realloc(
        registry->factories, capacity * sizeof(*factories));
    if (factories == NULL) {
        return ovc_registry_error(out_error,
                                  OvStorage_Status_Internal,
                                  "out of memory");
    }
    registry->factories = factories;
    registry->factory_capacity = capacity;
    return OvStorage_Status_Ok;
}

static OvStorage_Status ovc_registry_insert_factory(
    OvStorage_Registry *registry,
    ovc_layer_factory *factory,
    OvStorage_Error *out_error)
{
    ovc_layer_factory *retained;
    OvStorage_Status status;
    size_t index;

    if (registry->factory_count == SIZE_MAX) {
        return ovc_registry_error(out_error,
                                  OvStorage_Status_Internal,
                                  "registry factory count overflow");
    }
    status = ovc_registry_reserve(registry,
                                  registry->factory_count + 1,
                                  out_error);
    if (status != OvStorage_Status_Ok) {
        return status;
    }
    retained = ovc_layer_factory_retain(factory);
    if (retained == NULL) {
        return ovc_registry_error(
            out_error,
            OvStorage_Status_Internal,
            "factory reference count overflow");
    }

    for (index = 0; index < registry->factory_count; ++index) {
        if (ovc_layer_factory_kind_equals(registry->factories[index],
                                          factory->kind.ptr,
                                          factory->kind.len)) {
            ovc_layer_factory *replaced;

            replaced = registry->factories[index];
            registry->factories[index] = retained;
            ovc_layer_factory_release(replaced);
            return OvStorage_Status_Ok;
        }
    }
    registry->factories[registry->factory_count++] = retained;
    return OvStorage_Status_Ok;
}

const ovc_layer_factory *ovc_registry_find_factory(
    const OvStorage_Registry *registry,
    const char *kind)
{
    size_t index;
    size_t kind_length;

    if (registry == NULL || kind == NULL) {
        return NULL;
    }
    kind_length = strlen(kind);
    for (index = 0; index < registry->factory_count; ++index) {
        if (ovc_layer_factory_kind_equals(registry->factories[index],
                                          kind,
                                          kind_length)) {
            return registry->factories[index];
        }
    }
    return NULL;
}

OvStorage_Status ovc_registry_register_builtin_kind(
    OvStorage_Registry *registry,
    const OvStoragePlugin_LayerKindDescriptor *descriptor,
    void *plugin_state,
    const OvStoragePlugin_PluginVTableV1 *plugin_vtable,
    OvStorage_Error *out_error)
{
    ovc_layer_factory *factory;
    OvStorage_Status status;

    if (registry == NULL) {
        return ovc_registry_error(out_error,
                                  OvStorage_Status_InvalidArgument,
                                  "registry must not be null");
    }
    status = ovc_registry_validate_plugin_vtable(plugin_vtable,
                                                 out_error);
    if (status != OvStorage_Status_Ok) {
        return status;
    }
    status = ovc_layer_factory_create(descriptor,
                                      plugin_state,
                                      plugin_vtable,
                                      NULL,
                                      &factory,
                                      out_error);
    if (status != OvStorage_Status_Ok) {
        return status;
    }
    status = ovc_registry_insert_factory(registry, factory, out_error);
    ovc_layer_factory_release(factory);
    if (status == OvStorage_Status_Ok) {
        ovc_registry_success(out_error);
    }
    return status;
}

static OvStorage_Status ovc_registry_validate_manifest(
    const OvStoragePlugin_PluginManifestV1 *manifest,
    bool allow_test_plugins,
    OvStorage_Error *out_error)
{
    size_t name_length;
    size_t version_length;
    bool test_only;

    if (manifest == NULL) {
        return ovc_registry_error(out_error,
                                  OvStorage_Status_InvalidArgument,
                                  "plugin manifest pointer is null");
    }
    if (manifest->struct_size < OVC_PLUGIN_MANIFEST_MINIMUM_SIZE) {
        return ovc_registry_error(
            out_error,
            OvStorage_Status_InvalidArgument,
            "plugin manifest struct_size is too small");
    }
    if (manifest->abi_version !=
        OVSTORAGE_PLUGIN_ABI_VERSION) {
        return ovc_registry_error(
            out_error,
            OvStorage_Status_IncompatibleType,
            "plugin manifest abi_version is not the supported Layer ABI");
    }
    if (manifest->name == NULL || manifest->version == NULL) {
        return ovc_registry_error(
            out_error,
            OvStorage_Status_InvalidArgument,
            "plugin manifest name and version must not be null");
    }
    name_length = strlen(manifest->name);
    version_length = strlen(manifest->version);
    if (!ovc_utf8_is_valid(manifest->name, name_length) ||
        !ovc_utf8_is_valid(manifest->version, version_length)) {
        return ovc_registry_error(
            out_error,
            OvStorage_Status_InvalidArgument,
            "plugin manifest name or version is not valid UTF-8");
    }

    test_only = manifest->struct_size >=
                    OVC_PLUGIN_MANIFEST_TEST_ONLY_SIZE
                    ? manifest->test_only
                    : false;
    if (test_only && !allow_test_plugins) {
        return ovc_registry_error(
            out_error,
            OvStorage_Status_PluginRejected,
            "plugin '%s' is marked test_only and allow_test_plugins is false",
            manifest->name);
    }
    return OvStorage_Status_Ok;
}

static void ovc_registry_drop_init_state(
    const OvStoragePlugin_PluginInitResultV1 *init)
{
    if (init == NULL || init->struct_size < OVC_PLUGIN_INIT_VTABLE_SIZE ||
        init->abi_version !=
            OVSTORAGE_PLUGIN_ABI_VERSION ||
        init->plugin_state == NULL ||
        init->plugin_vtable == NULL ||
        init->plugin_vtable->struct_size < OVC_PLUGIN_VTABLE_ABI_SIZE ||
        init->plugin_vtable->abi_version !=
            OVSTORAGE_PLUGIN_ABI_VERSION ||
        init->plugin_vtable->struct_size < OVC_PLUGIN_VTABLE_DROP_SIZE ||
        init->plugin_vtable->drop == NULL) {
        return;
    }
    init->plugin_vtable->drop(init->plugin_state);
}

static OvStorage_Status ovc_registry_finish_plugin_init(
    ovc_dlhandle mapping,
    ovc_plugin_init_v1_fn init_function,
    OvStorage_Plugin **out_plugin,
    OvStorage_Error *out_error)
{
    const OvStoragePlugin_HostCallbacks *callbacks;
    OvStoragePlugin_PluginInitResultV1 init;
    ovc_plugin_registration *registration;
    OvStorage_Plugin *plugin;
    OvStorage_Status status;
    size_t index;

    callbacks = ovc_host_callbacks_get();
    if (callbacks == NULL) {
        return ovc_registry_error(
            out_error,
            OvStorage_Status_Internal,
            "plugin host callbacks are unavailable");
    }
    init = init_function(callbacks);

    if (init.struct_size < sizeof(init)) {
        ovc_registry_drop_init_state(&init);
        return ovc_registry_error(
            out_error,
            OvStorage_Status_Internal,
            "plugin PluginInitResultV1.struct_size is too small");
    }
    if (init.abi_version !=
        OVSTORAGE_PLUGIN_ABI_VERSION) {
        ovc_registry_drop_init_state(&init);
        return ovc_registry_error(
            out_error,
            OvStorage_Status_IncompatibleType,
            "plugin init abi_version is not the supported Layer ABI");
    }
    if (init.plugin_state == NULL) {
        return ovc_registry_error(out_error,
                                  OvStorage_Status_InvalidArgument,
                                  "plugin init returned null plugin_state");
    }
    status = ovc_registry_validate_plugin_vtable(init.plugin_vtable,
                                                 out_error);
    if (status != OvStorage_Status_Ok) {
        ovc_registry_drop_init_state(&init);
        return status;
    }
    if (init.kind_count != 0 && init.kinds == NULL) {
        ovc_registry_drop_init_state(&init);
        return ovc_registry_error(
            out_error,
            OvStorage_Status_InvalidArgument,
            "plugin init returned null kinds with a nonzero kind_count");
    }
    if (init.kind_count > SIZE_MAX / sizeof(ovc_layer_factory *) ||
        init.kind_count >
            SIZE_MAX / sizeof(OvStoragePlugin_LayerKindDescriptor)) {
        ovc_registry_drop_init_state(&init);
        return ovc_registry_error(out_error,
                                  OvStorage_Status_Internal,
                                  "plugin kind_count overflows address space");
    }
    status = ovc_registry_validate_plugin_kinds(&init, out_error);
    if (status != OvStorage_Status_Ok) {
        ovc_registry_drop_init_state(&init);
        return status;
    }

    registration =
        (ovc_plugin_registration *)calloc(1, sizeof(*registration));
    if (registration == NULL) {
        ovc_registry_drop_init_state(&init);
        return ovc_registry_error(out_error,
                                  OvStorage_Status_Internal,
                                  "out of memory");
    }
    registration->references.value = 1L;
    registration->mapping = mapping;
    registration->plugin_state = init.plugin_state;
    registration->plugin_vtable = init.plugin_vtable;

    plugin = (OvStorage_Plugin *)calloc(1, sizeof(*plugin));
    if (plugin == NULL) {
        ovc_plugin_registration_release(registration);
        return ovc_registry_error(out_error,
                                  OvStorage_Status_Internal,
                                  "out of memory");
    }
    plugin->registration = registration;
    if (init.kind_count != 0) {
        plugin->factories = (ovc_layer_factory **)calloc(
            init.kind_count, sizeof(*plugin->factories));
        if (plugin->factories == NULL) {
            ovstorage_plugin_destroy(plugin);
            return ovc_registry_error(out_error,
                                      OvStorage_Status_Internal,
                                      "out of memory");
        }
    }
    plugin->factory_count = init.kind_count;

    for (index = 0; index < init.kind_count; ++index) {
        status = ovc_layer_factory_create(&init.kinds[index],
                                          init.plugin_state,
                                          init.plugin_vtable,
                                          registration,
                                          &plugin->factories[index],
                                          out_error);
        if (status != OvStorage_Status_Ok) {
            ovstorage_plugin_destroy(plugin);
            return status;
        }
    }
    *out_plugin = plugin;
    ovc_registry_success(out_error);
    return OvStorage_Status_Ok;
}

/* `ovc_dlsym` returns a `void *` that becomes an `ovc_plugin_init_v1_fn`.
 * C99 has no `_Static_assert`, so this typedef is the portable spelling:
 * it fails to compile if the two ever differ in width. */
typedef char ovc_plugin_init_pointer_width_check
    [(sizeof(ovc_plugin_init_v1_fn) == sizeof(void *)) ? 1 : -1];

OvStorage_Status ovstorage_load_plugin(const char *path,
                                       bool allow_test_plugins,
                                       OvStorage_Plugin **out_plugin,
                                       OvStorage_Error *out_error)
{
    const OvStoragePlugin_PluginManifestV1 *manifest;
    const char *loader_error;
    ovc_dlhandle mapping;
    ovc_plugin_init_v1_fn init_function;
    OvStorage_Status status;
    void *symbol;

    if (out_plugin == NULL) {
        return ovc_registry_error(out_error,
                                  OvStorage_Status_InvalidArgument,
                                  "out_plugin must not be null");
    }
    *out_plugin = NULL;
    if (path == NULL) {
        return ovc_registry_error(out_error,
                                  OvStorage_Status_InvalidArgument,
                                  "path must not be null");
    }
    if (!ovc_utf8_is_valid(path, strlen(path))) {
        return ovc_registry_error(out_error,
                                  OvStorage_Status_InvalidArgument,
                                  "path is not valid UTF-8");
    }

    status = ovc_auth_substrate_auto_init(out_error);
    if (status != OvStorage_Status_Ok) {
        return status;
    }

    mapping = ovc_dlopen(path);
    if (mapping == NULL) {
        loader_error = ovc_dlerror();
        return ovc_registry_error(
            out_error,
            OvStorage_Status_InvalidArgument,
            "failed to load plugin library: %s",
            loader_error == NULL ? "unknown loader error" : loader_error);
    }

    /*
     * The plugin's init function has not run on any failure below, so the
     * mapping holds no retained host state and unloading is safe (and
     * matches the Rust reference).  The error message is formatted before
     * ovc_dlclose because closing may invalidate the ovc_dlerror string.
     */
    symbol = ovc_dlsym(mapping, "ovstorage_plugin_manifest_v1");
    loader_error = ovc_dlerror();
    if (symbol == NULL || loader_error != NULL) {
        status = ovc_registry_error(
            out_error,
            OvStorage_Status_InvalidArgument,
            "plugin manifest symbol is missing: %s",
            loader_error == NULL ? "symbol resolved to null" : loader_error);
        ovc_dlclose(mapping);
        return status;
    }
    manifest = (const OvStoragePlugin_PluginManifestV1 *)symbol;
    status = ovc_registry_validate_manifest(manifest,
                                            allow_test_plugins,
                                            out_error);
    if (status != OvStorage_Status_Ok) {
        ovc_dlclose(mapping);
        return status;
    }

    symbol = ovc_dlsym(mapping, "ovstorage_plugin_init_v1");
    loader_error = ovc_dlerror();
    if (symbol == NULL || loader_error != NULL) {
        status = ovc_registry_error(
            out_error,
            OvStorage_Status_InvalidArgument,
            "plugin init symbol is missing: %s",
            loader_error == NULL ? "symbol resolved to null" : loader_error);
        ovc_dlclose(mapping);
        return status;
    }
    /* Asserted at compile time above: this is a property of the target,
     * and as a runtime `if` it tripped MSVC C4127 under /W4 /WX. */
    memcpy(&init_function, &symbol, sizeof(init_function));
    /* The host-callbacks probe is the fifth and last pre-init failure: it
     * must close the still-uninitialized mapping here, because the
     * pin-forever contract begins only once the plugin's init function has
     * run.  finish_plugin_init re-reads the callbacks; the repeated lookup
     * is idempotent, and its own NULL arm stays as a backstop for the
     * process-exit race between these two calls. */
    if (ovc_host_callbacks_get() == NULL) {
        ovc_dlclose(mapping);
        return ovc_registry_error(
            out_error,
            OvStorage_Status_Internal,
            "plugin host callbacks are unavailable");
    }
    return ovc_registry_finish_plugin_init(mapping,
                                           init_function,
                                           out_plugin,
                                           out_error);
}

void ovstorage_plugin_destroy(OvStorage_Plugin *plugin)
{
    size_t index;

    if (plugin == NULL) {
        return;
    }
    for (index = 0; index < plugin->factory_count; ++index) {
        ovc_layer_factory_release(plugin->factories[index]);
    }
    free(plugin->factories);
    ovc_plugin_registration_release(plugin->registration);
    free(plugin);
}

OvStorage_Registry *ovstorage_registry_create(void)
{
    OvStorage_Error error;
    OvStorage_Registry *registry;
    OvStorage_Status status;

    memset(&error, 0, sizeof(error));
    registry = (OvStorage_Registry *)calloc(1, sizeof(*registry));
    if (registry == NULL) {
        return NULL;
    }
    status = ovstorage_c_register_builtin_kinds(registry, &error);
    ovstorage_error_clear(&error);
    if (status != OvStorage_Status_Ok) {
        ovstorage_registry_destroy(registry);
        return NULL;
    }
    return registry;
}

void ovstorage_registry_destroy(OvStorage_Registry *registry)
{
    size_t index;

    if (registry == NULL) {
        return;
    }
    for (index = 0; index < registry->factory_count; ++index) {
        ovc_layer_factory_release(registry->factories[index]);
    }
    free(registry->factories);
    free(registry);
}

OvStorage_Status ovstorage_registry_add_plugin(
    OvStorage_Registry *registry,
    const OvStorage_Plugin *plugin,
    OvStorage_Error *out_error)
{
    OvStorage_Status status;
    size_t index;

    if (registry == NULL) {
        return ovc_registry_error(out_error,
                                  OvStorage_Status_InvalidArgument,
                                  "registry must not be null");
    }
    if (plugin == NULL) {
        return ovc_registry_error(out_error,
                                  OvStorage_Status_InvalidArgument,
                                  "plugin must not be null");
    }
    if (plugin->factory_count > SIZE_MAX - registry->factory_count) {
        return ovc_registry_error(out_error,
                                  OvStorage_Status_Internal,
                                  "registry factory count overflow");
    }
    status = ovc_registry_reserve(
        registry,
        registry->factory_count + plugin->factory_count,
        out_error);
    if (status != OvStorage_Status_Ok) {
        return status;
    }
    for (index = 0; index < plugin->factory_count; ++index) {
        status = ovc_registry_insert_factory(registry,
                                             plugin->factories[index],
                                             out_error);
        if (status != OvStorage_Status_Ok) {
            return status;
        }
    }
    ovc_registry_success(out_error);
    return OvStorage_Status_Ok;
}

static OvStorage_Status ovc_registry_descriptor_list_create(
    const OvStorage_Plugin *plugin,
    OvStorage_KindDescriptorList **out_list,
    OvStorage_Error *out_error)
{
    OvStorage_KindDescriptorList *list;
    size_t index;
    size_t offset;
    size_t storage_length;

    storage_length = 0;
    for (index = 0; index < plugin->factory_count; ++index) {
        const ovc_layer_factory *factory;

        factory = plugin->factories[index];
        if (factory->kind.len > SIZE_MAX - storage_length) {
            return ovc_registry_error(out_error,
                                      OvStorage_Status_Internal,
                                      "descriptor string storage overflow");
        }
        storage_length += factory->kind.len;
        if (factory->display_name.len > SIZE_MAX - storage_length) {
            return ovc_registry_error(out_error,
                                      OvStorage_Status_Internal,
                                      "descriptor string storage overflow");
        }
        storage_length += factory->display_name.len;
    }
    if (plugin->factory_count > SIZE_MAX / sizeof(*list->items)) {
        return ovc_registry_error(out_error,
                                  OvStorage_Status_Internal,
                                  "descriptor count overflows address space");
    }

    list = (OvStorage_KindDescriptorList *)calloc(1, sizeof(*list));
    if (list == NULL) {
        return ovc_registry_error(out_error,
                                  OvStorage_Status_Internal,
                                  "out of memory");
    }
    list->len = plugin->factory_count;
    if (list->len != 0) {
        list->items = (ovc_kind_descriptor *)calloc(
            list->len, sizeof(*list->items));
        if (list->items == NULL) {
            ovstorage_kind_descriptor_list_destroy(list);
            return ovc_registry_error(out_error,
                                      OvStorage_Status_Internal,
                                      "out of memory");
        }
    }
    list->string_storage = (char *)malloc(storage_length == 0
                                              ? 1
                                              : storage_length);
    if (list->string_storage == NULL) {
        ovstorage_kind_descriptor_list_destroy(list);
        return ovc_registry_error(out_error,
                                  OvStorage_Status_Internal,
                                  "out of memory");
    }
    if (storage_length == 0) {
        list->string_storage[0] = '\0';
    }

    offset = 0;
    for (index = 0; index < list->len; ++index) {
        const ovc_layer_factory *factory;

        factory = plugin->factories[index];
        list->items[index].layer_type = (int32_t)factory->layer_type;
        list->items[index].kind.ptr = list->string_storage + offset;
        list->items[index].kind.len = factory->kind.len;
        if (factory->kind.len != 0) {
            memcpy(list->string_storage + offset,
                   factory->kind.ptr,
                   factory->kind.len);
            offset += factory->kind.len;
        }
        list->items[index].display_name.ptr =
            list->string_storage + offset;
        list->items[index].display_name.len =
            factory->display_name.len;
        if (factory->display_name.len != 0) {
            memcpy(list->string_storage + offset,
                   factory->display_name.ptr,
                   factory->display_name.len);
            offset += factory->display_name.len;
        }
    }
    *out_list = list;
    return OvStorage_Status_Ok;
}

OvStorage_Status ovstorage_inspect_plugin(
    const char *path,
    bool allow_test_plugins,
    OvStorage_KindDescriptorList **out_list,
    OvStorage_Error *out_error)
{
    OvStorage_Plugin *plugin;
    OvStorage_Status status;

    if (out_list == NULL) {
        return ovc_registry_error(out_error,
                                  OvStorage_Status_InvalidArgument,
                                  "out_list must not be null");
    }
    *out_list = NULL;
    plugin = NULL;
    status = ovstorage_load_plugin(path,
                                   allow_test_plugins,
                                   &plugin,
                                   out_error);
    if (status != OvStorage_Status_Ok) {
        return status;
    }

    status = ovc_registry_descriptor_list_create(plugin,
                                                 out_list,
                                                 out_error);

    /*
     * WARNING: this drops plugin-scoped state after copying the descriptors,
     * but it never unloads the mapping. Every inspect call performs another
     * open + init and permanently pins that loader reference for the rest of
     * the process. Do not deduplicate here: the frozen public contract makes
     * repeated calls leak-by-design and tells callers to inspect only once.
     * No create_backend/create_wrapper/create_router slot is called.
     */
    ovstorage_plugin_destroy(plugin);
    if (status == OvStorage_Status_Ok) {
        ovc_registry_success(out_error);
    }
    return status;
}

#if defined(OVC_REGISTRY_TEST_MAIN)

#include <assert.h>

#if defined(NDEBUG)
#error "OVC_REGISTRY_TEST_MAIN requires assertions to be enabled"
#endif

static char g_ovc_registry_test_file_kind[] = "file";
static char g_ovc_registry_test_file_display_name[] = "Local files";
static char g_ovc_registry_test_plugin_kind[] = "registry-test";
static char g_ovc_registry_test_plugin_display_name[] = "Registry test";
static size_t g_ovc_registry_test_init_count;
static size_t g_ovc_registry_test_drop_count;
static size_t g_ovc_registry_test_create_count;
static int g_ovc_registry_test_plugin_state;

static OvStoragePlugin_FfiStatus ovc_registry_test_create_backend(
    void *plugin_state,
    const OvStoragePlugin_CreateBackendRequest *request,
    OvStoragePlugin_LayerHandle *out,
    OvStoragePlugin_Error **error)
{
    (void)plugin_state;
    (void)request;
    (void)out;
    (void)error;
    ++g_ovc_registry_test_create_count;
    return OvStoragePlugin_FFI_STATUS_ERR;
}

static void ovc_registry_test_drop(void *plugin_state)
{
    assert(plugin_state == &g_ovc_registry_test_plugin_state);
    ++g_ovc_registry_test_drop_count;
}

static void ovc_registry_test_builtin_drop(void *plugin_state)
{
    (void)plugin_state;
    assert(0 && "built-in plugin state must not be dropped by the registry");
}

static const OvStoragePlugin_PluginVTableV1
    g_ovc_registry_test_builtin_vtable = {
        sizeof(OvStoragePlugin_PluginVTableV1),
        OVSTORAGE_PLUGIN_ABI_VERSION,
        ovc_registry_test_builtin_drop,
        ovc_registry_test_create_backend,
        NULL,
        NULL,
        {NULL}};

static const OvStoragePlugin_PluginVTableV1
    g_ovc_registry_test_plugin_vtable = {
        sizeof(OvStoragePlugin_PluginVTableV1),
        OVSTORAGE_PLUGIN_ABI_VERSION,
        ovc_registry_test_drop,
        ovc_registry_test_create_backend,
        NULL,
        NULL,
        {NULL}};

/* Designated, so that a field added to the descriptor lands where it is
   named rather than shifting every member below it. */
static const OvStoragePlugin_LayerKindDescriptor
    g_ovc_registry_test_builtin_descriptor = {
        .struct_size = sizeof(OvStoragePlugin_LayerKindDescriptor),
        .layer_type = OvStoragePlugin_LayerType_Backend,
        .accepts_connections = true,
        .auth_capable = false,
        .supports_user_metadata = false,
        .kind = {g_ovc_registry_test_file_kind,
                 sizeof(g_ovc_registry_test_file_kind) - 1},
        .display_name = {g_ovc_registry_test_file_display_name,
                         sizeof(g_ovc_registry_test_file_display_name) - 1},
        .description = {false, {NULL, 0}},
        .config_schema = {NULL, 0},
        .credential_schema = {NULL, 0},
        .credential_methods = {NULL, 0},
        .icon = {false, {NULL, 0}},
        ._reserved = {NULL}};

/* Designated, so that a field added to the descriptor lands where it is
   named rather than shifting every member below it. */
static const OvStoragePlugin_LayerKindDescriptor
    g_ovc_registry_test_plugin_descriptor = {
        .struct_size = sizeof(OvStoragePlugin_LayerKindDescriptor),
        .layer_type = OvStoragePlugin_LayerType_Backend,
        .accepts_connections = true,
        .auth_capable = false,
        .supports_user_metadata = false,
        .kind = {g_ovc_registry_test_plugin_kind,
                 sizeof(g_ovc_registry_test_plugin_kind) - 1},
        .display_name = {g_ovc_registry_test_plugin_display_name,
                         sizeof(g_ovc_registry_test_plugin_display_name) - 1},
        .description = {false, {NULL, 0}},
        .config_schema = {NULL, 0},
        .credential_schema = {NULL, 0},
        .credential_methods = {NULL, 0},
        .icon = {false, {NULL, 0}},
        ._reserved = {NULL}};

OvStorage_Status ovstorage_c_register_builtin_kinds(
    OvStorage_Registry *registry,
    OvStorage_Error *out_error)
{
    return ovc_registry_register_builtin_kind(
        registry,
        &g_ovc_registry_test_builtin_descriptor,
        NULL,
        &g_ovc_registry_test_builtin_vtable,
        out_error);
}

static OvStoragePlugin_Str ovc_registry_test_str(char *value)
{
    OvStoragePlugin_Str result;

    result.ptr = value;
    result.len = strlen(value);
    return result;
}

static void ovc_registry_test_host_callbacks(
    const OvStoragePlugin_HostCallbacks *host)
{
    static char backend_kind[] = "registry-test";
    static char connection_id[] = "connection";
    static char field[] = "token";
    static uint8_t secret[] = {0x12, 0x34, 0x56};
    OvStoragePlugin_SecretKey key;
    OvStoragePlugin_SecretBytes input;
    OvStoragePlugin_Optional_SecretBytes output;

    assert(host != NULL);
    assert(host->struct_size == sizeof(*host));
    assert(host->host_state != NULL);
    assert(host->secret_get != NULL);
    assert(host->secret_put != NULL);
    assert(host->secret_delete != NULL);
    assert(host->auth_refresh_lock_with_refresh != NULL);
    assert(host->host_kind == 0);
    assert(host->log != NULL);

    key.backend_kind = ovc_registry_test_str(backend_kind);
    key.connection_id.id = ovc_registry_test_str(connection_id);
    key.field = ovc_registry_test_str(field);
    input.bytes.ptr = secret;
    input.bytes.len = sizeof(secret);
    assert(host->secret_put(host->host_state, &key, &input) == NULL);
    memset(&output, 0, sizeof(output));
    assert(host->secret_get(host->host_state, &key, &output) == NULL);
    assert(output.present);
    assert(output.value.bytes.len == sizeof(secret));
    assert(memcmp(output.value.bytes.ptr, secret, sizeof(secret)) == 0);
    /* secret_get minted this buffer with the plugin-ABI allocator. */
    ovc_secure_zero(output.value.bytes.ptr, output.value.bytes.len);
    ovc_abi_free(output.value.bytes.ptr);
    assert(host->secret_delete(host->host_state, &key) == NULL);
}

static OvStoragePlugin_PluginInitResultV1 ovc_registry_test_init(
    const OvStoragePlugin_HostCallbacks *host)
{
    OvStoragePlugin_PluginInitResultV1 result;

    ++g_ovc_registry_test_init_count;
    ovc_registry_test_host_callbacks(host);
    result.struct_size = sizeof(result);
    result.abi_version =
        OVSTORAGE_PLUGIN_ABI_VERSION;
    result.plugin_state = &g_ovc_registry_test_plugin_state;
    result.plugin_vtable = &g_ovc_registry_test_plugin_vtable;
    result.kinds = &g_ovc_registry_test_plugin_descriptor;
    result.kind_count = 1;
    return result;
}

static OvStoragePlugin_PluginInitResultV1
ovc_registry_test_reserved_kind_init(
    const OvStoragePlugin_HostCallbacks *host)
{
    OvStoragePlugin_PluginInitResultV1 result;

    result = ovc_registry_test_init(host);
    result.kinds = &g_ovc_registry_test_builtin_descriptor;
    return result;
}

static OvStoragePlugin_PluginInitResultV1
ovc_registry_test_duplicate_kind_init(
    const OvStoragePlugin_HostCallbacks *host)
{
    static OvStoragePlugin_LayerKindDescriptor descriptors[2];
    OvStoragePlugin_PluginInitResultV1 result;

    descriptors[0] = g_ovc_registry_test_plugin_descriptor;
    descriptors[1] = g_ovc_registry_test_plugin_descriptor;
    result = ovc_registry_test_init(host);
    result.kinds = descriptors;
    result.kind_count = 2;
    return result;
}

static void ovc_registry_test_loaded_lifetimes(void)
{
    static const OvStoragePlugin_PluginManifestV1 manifest = {
        sizeof(OvStoragePlugin_PluginManifestV1),
        OVSTORAGE_PLUGIN_ABI_VERSION,
        "registry-test-plugin",
        "1.0.0",
        false};
    OvStorage_Error error;
    OvStorage_Plugin *plugin;
    OvStorage_Registry *registry;
    ovc_layer_factory *stack_factory;

    memset(&error, 0, sizeof(error));
    assert(ovc_registry_validate_manifest(&manifest, false, &error) ==
           OvStorage_Status_Ok);
    assert(ovc_auth_substrate_auto_init(&error) == OvStorage_Status_Ok);
    plugin = NULL;
    assert(ovc_registry_finish_plugin_init((ovc_dlhandle)(uintptr_t)1,
                                           ovc_registry_test_init,
                                           &plugin,
                                           &error) == OvStorage_Status_Ok);
    assert(plugin != NULL);
    assert(g_ovc_registry_test_init_count == 1);
    assert(g_ovc_registry_test_create_count == 0);

    registry = ovstorage_registry_create();
    assert(registry != NULL);
    assert(ovstorage_registry_add_plugin(registry, plugin, &error) ==
           OvStorage_Status_Ok);
    ovstorage_plugin_destroy(plugin);
    assert(g_ovc_registry_test_drop_count == 0);
    stack_factory = ovc_layer_factory_retain(
        ovc_registry_find_factory(registry, "registry-test"));
    assert(stack_factory != NULL);
    ovstorage_registry_destroy(registry);
    assert(g_ovc_registry_test_drop_count == 0);
    ovc_layer_factory_release(stack_factory);
    assert(g_ovc_registry_test_drop_count == 1);
    ovstorage_error_clear(&error);
}

static void ovc_registry_test_rejects_reserved_and_duplicate_kinds(void)
{
    OvStorage_Error error;
    OvStorage_Plugin *plugin;
    size_t drops;

    memset(&error, 0, sizeof(error));
    drops = g_ovc_registry_test_drop_count;
    plugin = NULL;
    assert(ovc_registry_finish_plugin_init(
               (ovc_dlhandle)(uintptr_t)6,
               ovc_registry_test_reserved_kind_init,
               &plugin,
               &error) == OvStorage_Status_InvalidArgument);
    assert(plugin == NULL);
    assert(error.message != NULL);
    assert(strstr(error.message,
                  "reserved built-in Layer kind 'file'") != NULL);
    assert(g_ovc_registry_test_drop_count == drops + 1);

    assert(ovc_registry_finish_plugin_init(
               (ovc_dlhandle)(uintptr_t)7,
               ovc_registry_test_duplicate_kind_init,
               &plugin,
               &error) == OvStorage_Status_InvalidArgument);
    assert(plugin == NULL);
    assert(error.message != NULL);
    assert(strstr(error.message,
                  "Layer kind 'registry-test' more than once") != NULL);
    assert(g_ovc_registry_test_drop_count == drops + 2);
    ovstorage_error_clear(&error);
}

static void ovc_registry_test_inspection_copy(void)
{
    OvStorage_Error error;
    OvStorage_KindDescriptorList *list;
    OvStorage_Plugin *plugin;
    const char *value;
    size_t length;

    memset(&error, 0, sizeof(error));
    plugin = NULL;
    assert(ovc_registry_finish_plugin_init((ovc_dlhandle)(uintptr_t)2,
                                           ovc_registry_test_init,
                                           &plugin,
                                           &error) == OvStorage_Status_Ok);
    list = NULL;
    assert(ovc_registry_descriptor_list_create(plugin, &list, &error) ==
           OvStorage_Status_Ok);
    ovstorage_plugin_destroy(plugin);
    assert(g_ovc_registry_test_init_count == 2);
    assert(g_ovc_registry_test_drop_count == 2);
    assert(g_ovc_registry_test_create_count == 0);
    assert(ovstorage_kind_descriptor_list_len(list) == 1);
    assert(ovstorage_kind_descriptor_list_item_layer_type(list, 0) == 0);
    value = ovstorage_kind_descriptor_list_item_kind(list, 0, &length);
    assert(length == sizeof(g_ovc_registry_test_plugin_kind) - 1);
    assert(memcmp(value, g_ovc_registry_test_plugin_kind, length) == 0);
    value = ovstorage_kind_descriptor_list_item_display_name(list,
                                                             0,
                                                             &length);
    assert(length == sizeof(g_ovc_registry_test_plugin_display_name) - 1);
    assert(memcmp(value,
                  g_ovc_registry_test_plugin_display_name,
                  length) == 0);
    ovstorage_kind_descriptor_list_destroy(list);
    ovstorage_error_clear(&error);
}

static void ovc_registry_test_policy_gate(void)
{
    static const OvStoragePlugin_PluginManifestV1 test_manifest = {
        sizeof(OvStoragePlugin_PluginManifestV1),
        OVSTORAGE_PLUGIN_ABI_VERSION,
        "test-only",
        "1.0.0",
        true};
    OvStorage_Error error;

    memset(&error, 0, sizeof(error));
    /* A test_only plugin that policy declines is the host's own refusal,
     * not a failure — PluginRejected, as the Rust host reports. */
    assert(ovc_registry_validate_manifest(&test_manifest, false, &error) ==
           OvStorage_Status_PluginRejected);
    assert(error.message != NULL);
    assert(ovc_registry_validate_manifest(&test_manifest, true, &error) ==
           OvStorage_Status_Ok);
    ovstorage_error_clear(&error);
}

static OvStoragePlugin_PluginInitResultV1
ovc_registry_test_undersized_init(
    const OvStoragePlugin_HostCallbacks *host)
{
    OvStoragePlugin_PluginInitResultV1 result;

    (void)host;
    memset(&result, 0, sizeof(result));
    result.struct_size = 0;
    result.plugin_state = (void *)(uintptr_t)1;
    result.plugin_vtable =
        (const OvStoragePlugin_PluginVTableV1 *)(uintptr_t)1;
    return result;
}

static const OvStoragePlugin_PluginVTableV1
    g_ovc_registry_test_unknown_vtable = {
        sizeof(OvStoragePlugin_PluginVTableV1),
        OVSTORAGE_PLUGIN_ABI_VERSION + 1,
        ovc_registry_test_drop,
        ovc_registry_test_create_backend,
        NULL,
        NULL,
        {NULL}};

static OvStoragePlugin_PluginInitResultV1
ovc_registry_test_unknown_init_abi(
    const OvStoragePlugin_HostCallbacks *host)
{
    OvStoragePlugin_PluginInitResultV1 result;

    (void)host;
    memset(&result, 0, sizeof(result));
    result.struct_size = sizeof(result);
    result.abi_version =
        OVSTORAGE_PLUGIN_ABI_VERSION + 1;
    result.plugin_state = &g_ovc_registry_test_plugin_state;
    result.plugin_vtable = &g_ovc_registry_test_plugin_vtable;
    return result;
}

static OvStoragePlugin_PluginInitResultV1
ovc_registry_test_unknown_vtable_abi(
    const OvStoragePlugin_HostCallbacks *host)
{
    OvStoragePlugin_PluginInitResultV1 result;

    (void)host;
    memset(&result, 0, sizeof(result));
    result.struct_size = sizeof(result);
    result.abi_version =
        OVSTORAGE_PLUGIN_ABI_VERSION;
    result.plugin_state = &g_ovc_registry_test_plugin_state;
    result.plugin_vtable = &g_ovc_registry_test_unknown_vtable;
    return result;
}

static void ovc_registry_test_undersized_init_is_not_dereferenced(void)
{
    OvStorage_Error error;
    OvStorage_Plugin *plugin;

    memset(&error, 0, sizeof(error));
    plugin = NULL;
    assert(ovc_registry_finish_plugin_init((ovc_dlhandle)(uintptr_t)3,
                                           ovc_registry_test_undersized_init,
                                           &plugin,
                                           &error) ==
           OvStorage_Status_Internal);
    assert(plugin == NULL);
    ovstorage_error_clear(&error);
}

static void ovc_registry_test_unknown_abi_is_not_dropped(void)
{
    OvStorage_Error error;
    OvStorage_Plugin *plugin;
    size_t drops;

    memset(&error, 0, sizeof(error));
    drops = g_ovc_registry_test_drop_count;
    plugin = NULL;
    /* An ABI-version mismatch is IncompatibleType, the status the C enum
     * already carries for a failed ABI handshake and the one the Rust host
     * reports for the same condition. */
    assert(ovc_registry_finish_plugin_init((ovc_dlhandle)(uintptr_t)4,
                                           ovc_registry_test_unknown_init_abi,
                                           &plugin,
                                           &error) ==
           OvStorage_Status_IncompatibleType);
    assert(plugin == NULL);
    assert(g_ovc_registry_test_drop_count == drops);
    assert(ovc_registry_finish_plugin_init(
               (ovc_dlhandle)(uintptr_t)5,
               ovc_registry_test_unknown_vtable_abi,
               &plugin,
               &error) == OvStorage_Status_IncompatibleType);
    assert(plugin == NULL);
    assert(g_ovc_registry_test_drop_count == drops);
    ovstorage_error_clear(&error);
}

static void ovc_registry_test_shared_utf8_validator(void)
{
    static const uint8_t embedded_nul[] = {'a', 0, 'b'};
    static const uint8_t first_two_byte[] = {0xc2u, 0x80u};
    static const uint8_t first_three_byte[] = {0xe0u, 0xa0u, 0x80u};
    static const uint8_t before_surrogates[] = {0xedu, 0x9fu, 0xbfu};
    static const uint8_t first_four_byte[] = {0xf0u, 0x90u, 0x80u, 0x80u};
    static const uint8_t maximum_scalar[] = {0xf4u, 0x8fu, 0xbfu, 0xbfu};
    static const uint8_t overlong[] = {0xc0u, 0xafu};
    static const uint8_t surrogate[] = {0xedu, 0xa0u, 0x80u};
    static const uint8_t above_maximum[] = {0xf4u, 0x90u, 0x80u, 0x80u};
    static const uint8_t truncated[] = {0xf0u, 0x90u, 0x80u};

    assert(ovc_utf8_is_valid(NULL, 0));
    assert(!ovc_utf8_is_valid(NULL, 1));
    assert(ovc_utf8_is_valid(embedded_nul, sizeof(embedded_nul)));
    assert(ovc_utf8_is_valid(first_two_byte, sizeof(first_two_byte)));
    assert(ovc_utf8_is_valid(first_three_byte, sizeof(first_three_byte)));
    assert(ovc_utf8_is_valid(before_surrogates, sizeof(before_surrogates)));
    assert(ovc_utf8_is_valid(first_four_byte, sizeof(first_four_byte)));
    assert(ovc_utf8_is_valid(maximum_scalar, sizeof(maximum_scalar)));
    assert(!ovc_utf8_is_valid(overlong, sizeof(overlong)));
    assert(!ovc_utf8_is_valid(surrogate, sizeof(surrogate)));
    assert(!ovc_utf8_is_valid(above_maximum, sizeof(above_maximum)));
    assert(!ovc_utf8_is_valid(truncated, sizeof(truncated)));
}

int main(void)
{
    OvStorage_Registry *registry;
    const ovc_layer_factory *file_factory;

    registry = ovstorage_registry_create();
    assert(registry != NULL);
    file_factory = ovc_registry_find_factory(registry, "file");
    assert(file_factory != NULL);
    assert(file_factory->layer_type == OvStoragePlugin_LayerType_Backend);
    ovstorage_registry_destroy(registry);

    ovc_registry_test_policy_gate();
    ovc_registry_test_undersized_init_is_not_dereferenced();
    ovc_registry_test_unknown_abi_is_not_dropped();
    ovc_registry_test_loaded_lifetimes();
    ovc_registry_test_inspection_copy();
    ovc_registry_test_rejects_reserved_and_duplicate_kinds();
    ovc_registry_test_shared_utf8_validator();
    return 0;
}

#endif /* OVC_REGISTRY_TEST_MAIN */
