/* SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Named Stack declaration, edge, and connection recording.
 */

#include "internal.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static OvStorage_Status ovc_stack_error(OvStorage_Error *out_error,
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

static void ovc_stack_success(OvStorage_Error *out_error)
{
    ovstorage_error_clear(out_error);
}

static bool ovc_stack_utf8_is_valid(const char *value)
{
    return ovc_utf8_is_valid(value, strlen(value));
}

static OvStorage_Status ovc_stack_validate_string(
    const char *value,
    const char *argument_name,
    OvStorage_Error *out_error)
{
    if (value == NULL) {
        return ovc_stack_error(out_error,
                               OvStorage_Status_InvalidArgument,
                               "%s must not be null",
                               argument_name);
    }
    if (!ovc_stack_utf8_is_valid(value)) {
        return ovc_stack_error(out_error,
                               OvStorage_Status_InvalidArgument,
                               "%s is not valid UTF-8",
                               argument_name);
    }
    return OvStorage_Status_Ok;
}

static char *ovc_stack_string_duplicate(const char *value)
{
    size_t length;
    char *copy;

    length = strlen(value);
    if (length == SIZE_MAX) {
        return NULL;
    }
    copy = (char *)malloc(length + 1);
    if (copy != NULL) {
        memcpy(copy, value, length + 1);
    }
    return copy;
}

static ovc_stack_layer *ovc_stack_find_layer(OvStorage_Stack *stack,
                                             const char *instance_id)
{
    size_t index;

    for (index = 0; index < stack->layer_count; ++index) {
        if (strcmp(stack->layers[index].instance_id, instance_id) == 0) {
            return &stack->layers[index];
        }
    }
    return NULL;
}

static const ovc_layer_factory *ovc_stack_find_pinned_factory(
    const OvStorage_Stack *stack,
    const char *kind)
{
    size_t index;
    size_t kind_length;

    kind_length = strlen(kind);
    for (index = 0; index < stack->layer_count; ++index) {
        const ovc_layer_factory *factory;

        factory = stack->layers[index].factory;
        if (factory->kind.len == kind_length &&
            (kind_length == 0 ||
             memcmp(factory->kind.ptr, kind, kind_length) == 0)) {
            return factory;
        }
    }
    return NULL;
}

static OvStorage_Status ovc_stack_require_layer(
    OvStorage_Stack *stack,
    const char *instance_id,
    ovc_stack_layer **out_layer,
    OvStorage_Error *out_error)
{
    ovc_stack_layer *layer;

    layer = ovc_stack_find_layer(stack, instance_id);
    if (layer == NULL) {
        return ovc_stack_error(
            out_error,
            OvStorage_Status_InvalidArgument,
            "no layer named `%s` has been declared",
            instance_id);
    }
    *out_layer = layer;
    return OvStorage_Status_Ok;
}

static OvStorage_Status ovc_stack_reserve_layers(
    OvStorage_Stack *stack,
    OvStorage_Error *out_error)
{
    size_t capacity;
    size_t required;
    ovc_stack_layer *layers;

    if (stack->layer_count == SIZE_MAX) {
        return ovc_stack_error(out_error,
                               OvStorage_Status_Internal,
                               "stack layer count overflow");
    }
    required = stack->layer_count + 1;
    if (required <= stack->layer_capacity) {
        return OvStorage_Status_Ok;
    }

    capacity = stack->layer_capacity == 0 ? 4 : stack->layer_capacity;
    while (capacity < required) {
        if (capacity > SIZE_MAX / 2) {
            capacity = required;
            break;
        }
        capacity *= 2;
    }
    if (capacity > SIZE_MAX / sizeof(*layers)) {
        return ovc_stack_error(out_error,
                               OvStorage_Status_Internal,
                               "stack layer capacity overflow");
    }
    layers = (ovc_stack_layer *)realloc(stack->layers,
                                        capacity * sizeof(*layers));
    if (layers == NULL) {
        return ovc_stack_error(out_error,
                               OvStorage_Status_Internal,
                               "out of memory recording a layer");
    }
    stack->layers = layers;
    stack->layer_capacity = capacity;
    return OvStorage_Status_Ok;
}

static OvStorage_Status ovc_stack_reserve_connections(
    OvStorage_Stack *stack,
    OvStorage_Error *out_error)
{
    size_t capacity;
    size_t required;
    ovc_stack_connection *connections;

    if (stack->connection_count == SIZE_MAX) {
        return ovc_stack_error(out_error,
                               OvStorage_Status_Internal,
                               "stack connection count overflow");
    }
    required = stack->connection_count + 1;
    if (required <= stack->connection_capacity) {
        return OvStorage_Status_Ok;
    }

    capacity = stack->connection_capacity == 0
                   ? 4
                   : stack->connection_capacity;
    while (capacity < required) {
        if (capacity > SIZE_MAX / 2) {
            capacity = required;
            break;
        }
        capacity *= 2;
    }
    if (capacity > SIZE_MAX / sizeof(*connections)) {
        return ovc_stack_error(out_error,
                               OvStorage_Status_Internal,
                               "stack connection capacity overflow");
    }
    connections = (ovc_stack_connection *)realloc(
        stack->connections, capacity * sizeof(*connections));
    if (connections == NULL) {
        return ovc_stack_error(out_error,
                               OvStorage_Status_Internal,
                               "out of memory recording a connection");
    }
    stack->connections = connections;
    stack->connection_capacity = capacity;
    return OvStorage_Status_Ok;
}

static void ovc_stack_child_ids_destroy(char **child_ids,
                                        size_t child_count)
{
    size_t index;

    if (child_ids == NULL) {
        return;
    }
    for (index = 0; index < child_count; ++index) {
        free(child_ids[index]);
    }
    free(child_ids);
}

static void ovc_stack_layer_destroy(ovc_stack_layer *layer)
{
    size_t index;

    if (layer == NULL) {
        return;
    }
    for (index = 0; index < layer->config_len; ++index) {
        free(layer->config[index].key);
        ovstorage_config_value_destroy(layer->config[index].value);
    }
    free(layer->instance_id);
    free(layer->config);
    free(layer->inner_id);
    ovc_stack_child_ids_destroy(layer->child_ids, layer->child_count);
    ovc_layer_factory_release(layer->factory);
}

static void ovc_stack_connection_destroy(ovc_stack_connection *connection)
{
    if (connection == NULL) {
        return;
    }
    free(connection->target);
    ovstorage_connection_request_destroy(connection->request);
}

OvStorage_Stack *ovstorage_stack_create(void)
{
    return (OvStorage_Stack *)calloc(1, sizeof(OvStorage_Stack));
}

void ovstorage_stack_destroy(OvStorage_Stack *stack)
{
    size_t index;

    if (stack == NULL) {
        return;
    }
    for (index = 0; index < stack->connection_count; ++index) {
        ovc_stack_connection_destroy(&stack->connections[index]);
    }
    for (index = 0; index < stack->layer_count; ++index) {
        ovc_stack_layer_destroy(&stack->layers[index]);
    }
    free(stack->connections);
    free(stack->layers);
    free(stack->root_id);
    free(stack);
}

OvStorage_Status ovstorage_stack_add_layer(OvStorage_Stack *stack,
                                           const OvStorage_Registry *registry,
                                           const char *instance_id,
                                           const char *kind,
                                           OvStorage_Error *out_error)
{
    const ovc_layer_factory *pinned_factory;
    const ovc_layer_factory *resolved_factory;
    ovc_layer_factory *retained_factory;
    char *instance_copy;
    ovc_stack_layer *layer;
    OvStorage_Status status;

    if (stack == NULL) {
        return ovc_stack_error(out_error,
                               OvStorage_Status_InvalidArgument,
                               "stack must not be null");
    }
    if (registry == NULL) {
        return ovc_stack_error(out_error,
                               OvStorage_Status_InvalidArgument,
                               "registry must not be null");
    }
    status = ovc_stack_validate_string(instance_id,
                                       "instance_id",
                                       out_error);
    if (status != OvStorage_Status_Ok) {
        return status;
    }
    status = ovc_stack_validate_string(kind, "kind", out_error);
    if (status != OvStorage_Status_Ok) {
        return status;
    }

    resolved_factory = ovc_registry_find_factory(registry, kind);
    if (resolved_factory == NULL) {
        return ovc_stack_error(out_error,
                               OvStorage_Status_InvalidArgument,
                               "no factory registered for kind `%s`",
                               kind);
    }
    if (ovc_stack_find_layer(stack, instance_id) != NULL) {
        return ovc_stack_error(
            out_error,
            OvStorage_Status_AlreadyExists,
            "a layer named `%s` is already declared",
            instance_id);
    }

    instance_copy = ovc_stack_string_duplicate(instance_id);
    if (instance_copy == NULL) {
        return ovc_stack_error(out_error,
                               OvStorage_Status_Internal,
                               "out of memory recording a layer name");
    }
    pinned_factory = ovc_stack_find_pinned_factory(stack, kind);
    if (pinned_factory == NULL) {
        pinned_factory = resolved_factory;
    }
    retained_factory = ovc_layer_factory_retain(pinned_factory);
    if (retained_factory == NULL) {
        free(instance_copy);
        return ovc_stack_error(out_error,
                               OvStorage_Status_Internal,
                               "factory reference count overflow");
    }
    status = ovc_stack_reserve_layers(stack, out_error);
    if (status != OvStorage_Status_Ok) {
        ovc_layer_factory_release(retained_factory);
        free(instance_copy);
        return status;
    }

    layer = &stack->layers[stack->layer_count];
    memset(layer, 0, sizeof(*layer));
    layer->instance_id = instance_copy;
    layer->factory = retained_factory;
    /* The Registry cached this value directly from the factory descriptor. */
    layer->layer_type = resolved_factory->layer_type;
    ++stack->layer_count;
    ovc_stack_success(out_error);
    return OvStorage_Status_Ok;
}

OvStorage_Status ovstorage_stack_add_layer_config(
    OvStorage_Stack *stack,
    const char *instance_id,
    const char *key,
    OvStorage_ConfigValue *value,
    OvStorage_Error *out_error)
{
    ovc_stack_layer *layer;
    ovc_config_entry *entries;
    char *key_copy;
    size_t capacity;
    size_t index;
    OvStorage_Status status;

    if (stack == NULL) {
        return ovc_stack_error(out_error,
                               OvStorage_Status_InvalidArgument,
                               "stack must not be null");
    }
    status = ovc_stack_validate_string(instance_id,
                                       "instance_id",
                                       out_error);
    if (status != OvStorage_Status_Ok) {
        return status;
    }
    status = ovc_stack_validate_string(key, "key", out_error);
    if (status != OvStorage_Status_Ok) {
        return status;
    }
    if (value == NULL) {
        return ovc_stack_error(out_error,
                               OvStorage_Status_InvalidArgument,
                               "config value must not be null");
    }
    status = ovc_stack_require_layer(stack,
                                     instance_id,
                                     &layer,
                                     out_error);
    if (status != OvStorage_Status_Ok) {
        return status;
    }
    for (index = 0; index < layer->config_len; ++index) {
        if (strcmp(layer->config[index].key, key) == 0) {
            ovstorage_config_value_destroy(layer->config[index].value);
            layer->config[index].value = value;
            ovc_stack_success(out_error);
            return OvStorage_Status_Ok;
        }
    }
    key_copy = ovc_stack_string_duplicate(key);
    if (key_copy == NULL) {
        return ovc_stack_error(out_error,
                               OvStorage_Status_Internal,
                               "out of memory recording a layer config key");
    }
    if (layer->config_len == layer->config_capacity) {
        capacity = layer->config_capacity == 0
                       ? 4
                       : layer->config_capacity * 2;
        if (capacity < layer->config_capacity ||
            capacity > SIZE_MAX / sizeof(*entries)) {
            free(key_copy);
            return ovc_stack_error(out_error,
                                   OvStorage_Status_Internal,
                                   "stack layer config capacity overflow");
        }
        entries = (ovc_config_entry *)realloc(
            layer->config, capacity * sizeof(*entries));
        if (entries == NULL) {
            free(key_copy);
            return ovc_stack_error(out_error,
                                   OvStorage_Status_Internal,
                                   "out of memory recording layer config");
        }
        layer->config = entries;
        layer->config_capacity = capacity;
    }
    layer->config[layer->config_len].key = key_copy;
    layer->config[layer->config_len].value = value;
    ++layer->config_len;
    ovc_stack_success(out_error);
    return OvStorage_Status_Ok;
}

OvStorage_Status ovstorage_stack_set_root(OvStorage_Stack *stack,
                                          const char *instance_id,
                                          OvStorage_Error *out_error)
{
    char *instance_copy;
    ovc_stack_layer *layer;
    OvStorage_Status status;

    if (stack == NULL) {
        return ovc_stack_error(out_error,
                               OvStorage_Status_InvalidArgument,
                               "stack must not be null");
    }
    status = ovc_stack_validate_string(instance_id,
                                       "instance_id",
                                       out_error);
    if (status != OvStorage_Status_Ok) {
        return status;
    }
    status = ovc_stack_require_layer(stack,
                                     instance_id,
                                     &layer,
                                     out_error);
    if (status != OvStorage_Status_Ok) {
        return status;
    }
    (void)layer;

    instance_copy = ovc_stack_string_duplicate(instance_id);
    if (instance_copy == NULL) {
        return ovc_stack_error(out_error,
                               OvStorage_Status_Internal,
                               "out of memory recording the root layer");
    }
    free(stack->root_id);
    stack->root_id = instance_copy;
    ovc_stack_success(out_error);
    return OvStorage_Status_Ok;
}

OvStorage_Status ovstorage_stack_set_inner(OvStorage_Stack *stack,
                                           const char *wrapper_id,
                                           const char *inner_id,
                                           OvStorage_Error *out_error)
{
    char *inner_copy;
    ovc_stack_layer *inner;
    ovc_stack_layer *wrapper;
    OvStorage_Status status;

    if (stack == NULL) {
        return ovc_stack_error(out_error,
                               OvStorage_Status_InvalidArgument,
                               "stack must not be null");
    }
    status = ovc_stack_validate_string(wrapper_id,
                                       "wrapper_id",
                                       out_error);
    if (status != OvStorage_Status_Ok) {
        return status;
    }
    status = ovc_stack_validate_string(inner_id, "inner_id", out_error);
    if (status != OvStorage_Status_Ok) {
        return status;
    }
    status = ovc_stack_require_layer(stack, inner_id, &inner, out_error);
    if (status != OvStorage_Status_Ok) {
        return status;
    }
    (void)inner;
    status = ovc_stack_require_layer(stack,
                                     wrapper_id,
                                     &wrapper,
                                     out_error);
    if (status != OvStorage_Status_Ok) {
        return status;
    }
    if (wrapper->layer_type != OvStoragePlugin_LayerType_Wrapper) {
        return ovc_stack_error(out_error,
                               OvStorage_Status_InvalidArgument,
                               "layer `%s` is not a Wrapper layer",
                               wrapper_id);
    }

    inner_copy = ovc_stack_string_duplicate(inner_id);
    if (inner_copy == NULL) {
        return ovc_stack_error(out_error,
                               OvStorage_Status_Internal,
                               "out of memory recording a wrapper edge");
    }
    free(wrapper->inner_id);
    wrapper->inner_id = inner_copy;
    ovc_stack_success(out_error);
    return OvStorage_Status_Ok;
}

OvStorage_Status ovstorage_stack_set_children(OvStorage_Stack *stack,
                                              const char *router_id,
                                              const char *const *child_ids,
                                              size_t child_count,
                                              OvStorage_Error *out_error)
{
    char **children;
    ovc_stack_layer *child;
    ovc_stack_layer *router;
    OvStorage_Status status;
    size_t index;

    if (stack == NULL) {
        return ovc_stack_error(out_error,
                               OvStorage_Status_InvalidArgument,
                               "stack must not be null");
    }
    status = ovc_stack_validate_string(router_id,
                                       "router_id",
                                       out_error);
    if (status != OvStorage_Status_Ok) {
        return status;
    }
    if (child_count != 0 && child_ids == NULL) {
        return ovc_stack_error(
            out_error,
            OvStorage_Status_InvalidArgument,
            "child_ids must not be null when child_count is nonzero");
    }
    if (child_count > SIZE_MAX / sizeof(*children)) {
        return ovc_stack_error(out_error,
                               OvStorage_Status_Internal,
                               "router child count overflow");
    }

    children = NULL;
    if (child_count != 0) {
        children = (char **)calloc(child_count, sizeof(*children));
        if (children == NULL) {
            return ovc_stack_error(out_error,
                                   OvStorage_Status_Internal,
                                   "out of memory recording router edges");
        }
    }
    for (index = 0; index < child_count; ++index) {
        status = ovc_stack_validate_string(child_ids[index],
                                           "child_id",
                                           out_error);
        if (status != OvStorage_Status_Ok) {
            ovc_stack_child_ids_destroy(children, child_count);
            return status;
        }
        status = ovc_stack_require_layer(stack,
                                         child_ids[index],
                                         &child,
                                         out_error);
        if (status != OvStorage_Status_Ok) {
            ovc_stack_child_ids_destroy(children, child_count);
            return status;
        }
        (void)child;
        children[index] = ovc_stack_string_duplicate(child_ids[index]);
        if (children[index] == NULL) {
            ovc_stack_child_ids_destroy(children, child_count);
            return ovc_stack_error(
                out_error,
                OvStorage_Status_Internal,
                "out of memory recording a router child name");
        }
    }

    status = ovc_stack_require_layer(stack, router_id, &router, out_error);
    if (status != OvStorage_Status_Ok) {
        ovc_stack_child_ids_destroy(children, child_count);
        return status;
    }
    if (router->layer_type != OvStoragePlugin_LayerType_Router) {
        ovc_stack_child_ids_destroy(children, child_count);
        return ovc_stack_error(out_error,
                               OvStorage_Status_InvalidArgument,
                               "layer `%s` is not a Router layer",
                               router_id);
    }

    ovc_stack_child_ids_destroy(router->child_ids, router->child_count);
    router->child_ids = children;
    router->child_count = child_count;
    ovc_stack_success(out_error);
    return OvStorage_Status_Ok;
}

OvStorage_Status ovstorage_stack_add_connection(OvStorage_Stack *stack,
                                                const char *target,
                                                OvStorage_ConnectionRequest **request_slot,
                                                OvStorage_Error *out_error)
{
    char *target_copy;
    ovc_stack_connection *connection;
    ovc_stack_layer *target_layer;
    OvStorage_ConnectionRequest *request;
    OvStorage_Status status;

    request = (request_slot == NULL) ? NULL : *request_slot;
    if (stack == NULL) {
        return ovc_stack_error(out_error,
                               OvStorage_Status_InvalidArgument,
                               "stack must not be null");
    }
    status = ovc_stack_validate_string(target, "target", out_error);
    if (status != OvStorage_Status_Ok) {
        return status;
    }
    status = ovc_stack_require_layer(stack,
                                     target,
                                     &target_layer,
                                     out_error);
    if (status != OvStorage_Status_Ok) {
        return status;
    }
    (void)target_layer;
    if (request == NULL || request->consumed) {
        return ovc_stack_error(
            out_error,
            OvStorage_Status_InvalidArgument,
            "request must not be null or already consumed");
    }

    target_copy = ovc_stack_string_duplicate(target);
    if (target_copy == NULL) {
        return ovc_stack_error(out_error,
                               OvStorage_Status_Internal,
                               "out of memory recording a connection target");
    }
    status = ovc_stack_reserve_connections(stack, out_error);
    if (status != OvStorage_Status_Ok) {
        free(target_copy);
        return status;
    }

    /*
     * This is the ownership commit point.  Every operation that can fail has
     * completed, so a false result still leaves the request with its caller,
     * while success transfers it to the Stack without a later error path.
     * Clearing the caller's slot is the signal that the transfer happened,
     * so the caller's cleanup is an unconditional destroy of whatever the
     * slot still holds.
     */
    if (!ovc_connection_request_mark_consumed(request)) {
        free(target_copy);
        return ovc_stack_error(
            out_error,
            OvStorage_Status_InvalidArgument,
            "request must not be null or already consumed");
    }
    *request_slot = NULL;
    connection = &stack->connections[stack->connection_count];
    connection->target = target_copy;
    connection->request = request;
    ++stack->connection_count;
    ovc_stack_success(out_error);
    return OvStorage_Status_Ok;
}

/* ------------------------------------------------------------------------- */
/* Stack finalization. */

/*
 * dispatch.c owns the opaque public handle representation.  Keeping this
 * constructor private lets the recording half of the builder remain ignorant
 * of the handle's operation-drain and stream-pump bookkeeping.
 */
OvStorage_LayerHandle *ovc_dispatch_layer_handle_create(
    OvStoragePlugin_LayerHandle root,
    ovc_layer_factory *const *factories,
    size_t factory_count);

typedef struct ovc_stack_build_state {
    OvStorage_Stack *stack;
    unsigned char *visits;
    unsigned char *owned;
    OvStoragePlugin_LayerHandle *handles;
    /* Borrowed view of the async build's token; NULL for the blocking
     * entry, whose caller has no cancellation handle. */
    const OvStoragePlugin_CancelTokenFFI *cancel;
} ovc_stack_build_state;

/*
 * Heap-owned state behind one build-time async plugin slot call
 * (`list_address_roots`, `add_connection`).
 *
 * Two owners hold independent references: the build thread that issued the
 * call, and the plugin's `on_complete`.  Either may release first and the
 * last release frees the state, so a build thread that stops waiting leaves
 * nothing for a late completion to write through, and a completion that
 * never arrives cannot keep the build thread parked.  That is what lets the
 * build abandon a Layer which ignores the cancellation token it was handed.
 *
 * `discard` reclaims an outcome no waiter reads; the payload type is fixed
 * per slot, so each call site supplies the matching reclaimer.
 */
typedef void (*ovc_stack_build_slot_discard_fn)(
    void *result,
    OvStoragePlugin_Error *error);

typedef struct ovc_stack_build_slot {
    ovc_mutex mutex;
    ovc_cond changed;
    unsigned references;
    int fired;
    int canceled;
    void *result;
    OvStoragePlugin_Error *error;
    ovc_stack_build_slot_discard_fn discard;
    /*
     * The Layer whose call is outstanding, adopted when the build thread
     * abandons the wait, so it outlives the partial build and the plugin
     * still owns live state when it completes.
     *
     * That handle is the root of an adopted SUBTREE, and the layers inside it
     * can come from other factories and other plugins than its own — a
     * quarantined wrapper holds a child some other plugin built.  Releasing
     * any of those factories runs its plugin's `drop`, so the quarantine
     * retains every factory the Stack resolved (the superset the built root
     * handle also takes) rather than just the outstanding layer's.
     */
    OvStoragePlugin_LayerHandle quarantine;
    ovc_layer_factory **quarantine_factories;
    size_t quarantine_factory_count;
    size_t quarantine_factory_capacity;
} ovc_stack_build_slot;

typedef struct ovc_stack_route_root {
    char *bytes;
    size_t len;
    size_t child_index;
} ovc_stack_route_root;

/*
 * Every ovc_stack_abi_* helper handles values that cross the plugin ABI in
 * one direction or the other: request payloads the Layer adopts (built with
 * ovc_abi_alloc, released here only on a pre-adoption failure path) and
 * plugin-minted results/errors this file reclaims.  Both sides must use the
 * plugin-ABI allocator pair (ovc_abi_alloc/ovc_abi_free); host-internal
 * bookkeeping in this file stays on plain malloc/free.
 */
static void ovc_stack_abi_str_clear(OvStoragePlugin_Str *value)
{
    if (value == NULL) {
        return;
    }
    ovc_abi_free(value->ptr);
    value->ptr = NULL;
    value->len = 0;
}

static void ovc_stack_abi_bytes_clear(OvStoragePlugin_Bytes *value,
                                      bool secure)
{
    if (value == NULL) {
        return;
    }
    if (secure && value->ptr != NULL) {
        ovc_secure_zero(value->ptr, value->len);
    }
    ovc_abi_free(value->ptr);
    value->ptr = NULL;
    value->len = 0;
}

static void ovc_stack_abi_key_values_clear(
    OvStoragePlugin_KeyValueList *values)
{
    size_t index;

    if (values == NULL) {
        return;
    }
    for (index = 0; index < values->len; ++index) {
        ovc_stack_abi_str_clear(&values->ptr[index].key);
        ovc_stack_abi_str_clear(&values->ptr[index].value);
    }
    ovc_abi_free(values->ptr);
    values->ptr = NULL;
    values->len = 0;
}

/* The plugin minted this error, so its buffers are plugin-ABI allocations.
 * The field teardown is ovc_pval_error_clear's, so this surface cannot fall
 * behind a field added to the struct; only the heap shell is this
 * function's own. */
static void ovc_stack_plugin_error_destroy(OvStoragePlugin_Error *error)
{
    if (error == NULL) {
        return;
    }
    ovc_pval_error_clear(error);
    ovc_abi_free(error);
}

static OvStorage_Status ovc_stack_plugin_failure(
    OvStorage_Error *out_error,
    OvStoragePlugin_Error *plugin_error,
    const char *operation,
    const char *layer_name)
{
    OvStorage_Status status;
    int message_length;

    status = plugin_error == NULL
                 ? OvStorage_Status_Internal
                 : ovc_status_from_plugin_code(plugin_error->code);
    message_length = 0;
    if (plugin_error != NULL && plugin_error->message_ptr != NULL) {
        message_length = plugin_error->message_len > 700
                             ? 700
                             : (int)plugin_error->message_len;
    }
    ovc_stack_error(out_error,
                    status,
                    "%s for layer `%s` failed%s%.*s",
                    operation,
                    layer_name,
                    message_length == 0 ? "" : ": ",
                    message_length,
                    message_length == 0 ? "" : plugin_error->message_ptr);
    /* Report the plugin's fine-grained code name rather than the coarse
     * status-derived one ovc_stack_error recorded. */
    if (out_error != NULL && plugin_error != NULL) {
        out_error->code_name = ovc_plugin_error_code_name(plugin_error->code);
    }
    ovc_stack_plugin_error_destroy(plugin_error);
    return status;
}

static bool ovc_stack_abi_str_copy(OvStoragePlugin_Str *out,
                                   const char *bytes,
                                   size_t len)
{
    size_t allocation_size;

    out->ptr = NULL;
    out->len = 0;
    if (bytes == NULL && len != 0) {
        return false;
    }
    allocation_size = len == 0 ? 1 : len;
    out->ptr = (char *)ovc_abi_alloc(allocation_size);
    if (out->ptr == NULL) {
        return false;
    }
    if (len == 0) {
        out->ptr[0] = '\0';
    } else {
        memcpy(out->ptr, bytes, len);
    }
    out->len = len;
    return true;
}

static bool ovc_stack_abi_bytes_copy(OvStoragePlugin_Bytes *out,
                                     const uint8_t *bytes,
                                     size_t len)
{
    size_t allocation_size;

    out->ptr = NULL;
    out->len = 0;
    if (bytes == NULL && len != 0) {
        return false;
    }
    allocation_size = len == 0 ? 1 : len;
    out->ptr = (uint8_t *)ovc_abi_alloc(allocation_size);
    if (out->ptr == NULL) {
        return false;
    }
    if (len == 0) {
        out->ptr[0] = 0;
    } else {
        memcpy(out->ptr, bytes, len);
    }
    out->len = len;
    return true;
}

static void ovc_stack_abi_config_value_clear(
    OvStoragePlugin_ConfigValue *value)
{
    if (value == NULL) {
        return;
    }
    if (value->tag == OvStoragePlugin_ConfigValueTag_String) {
        ovc_stack_abi_str_clear(&value->string_value);
    } else if (value->tag == OvStoragePlugin_ConfigValueTag_Toml) {
        ovc_stack_abi_str_clear(&value->toml_value);
    }
    memset(value, 0, sizeof(*value));
}

static bool ovc_stack_abi_config_value_copy(
    OvStoragePlugin_ConfigValue *out,
    const OvStorage_ConfigValue *value)
{
    memset(out, 0, sizeof(*out));
    if (value == NULL) {
        return false;
    }
    switch (value->kind) {
    case OvStorage_ConfigValueKind_String:
        out->tag = OvStoragePlugin_ConfigValueTag_String;
        return ovc_stack_abi_str_copy(&out->string_value,
                                      value->payload.string,
                                      strlen(value->payload.string));
    case OvStorage_ConfigValueKind_Int:
        out->tag = OvStoragePlugin_ConfigValueTag_Int;
        out->int_value = value->payload.integer;
        return true;
    case OvStorage_ConfigValueKind_Bool:
        out->tag = OvStoragePlugin_ConfigValueTag_Bool;
        out->bool_value = value->payload.boolean;
        return true;
    case OvStorage_ConfigValueKind_Toml:
        out->tag = OvStoragePlugin_ConfigValueTag_Toml;
        return ovc_stack_abi_str_copy(&out->toml_value,
                                      value->payload.string,
                                      strlen(value->payload.string));
    default:
        return false;
    }
}

static void ovc_stack_abi_config_list_clear(
    OvStoragePlugin_List_ConnectionConfigEntry *config)
{
    size_t index;

    if (config == NULL) {
        return;
    }
    for (index = 0; index < config->len; ++index) {
        ovc_stack_abi_str_clear(&config->ptr[index].key);
        ovc_stack_abi_config_value_clear(&config->ptr[index].value);
    }
    ovc_abi_free(config->ptr);
    config->ptr = NULL;
    config->len = 0;
}

static bool ovc_stack_abi_config_entries_copy(
    OvStoragePlugin_List_ConnectionConfigEntry *out,
    const ovc_config_entry *config,
    size_t config_len)
{
    size_t allocation_count;
    size_t index;

    memset(out, 0, sizeof(*out));
    allocation_count = config_len == 0 ? 1 : config_len;
    if (allocation_count > SIZE_MAX / sizeof(*out->ptr)) {
        return false;
    }
    out->ptr = (OvStoragePlugin_ConnectionConfigEntry *)ovc_abi_alloc(
        allocation_count * sizeof(*out->ptr));
    if (out->ptr == NULL) {
        return false;
    }
    memset(out->ptr, 0, allocation_count * sizeof(*out->ptr));
    for (index = 0; index < config_len; ++index) {
        if (!ovc_stack_abi_str_copy(&out->ptr[index].key,
                                    config[index].key,
                                    strlen(config[index].key)) ||
            !ovc_stack_abi_config_value_copy(
                &out->ptr[index].value,
                config[index].value)) {
            out->len = index + 1;
            ovc_stack_abi_config_list_clear(out);
            return false;
        }
        out->len = index + 1;
    }
    return true;
}

static bool ovc_stack_abi_config_list_copy(
    OvStoragePlugin_List_ConnectionConfigEntry *out,
    const OvStorage_ConnectionRequest *request)
{
    return ovc_stack_abi_config_entries_copy(
        out, request->config, request->config_len);
}

static void ovc_stack_abi_secret_value_clear(
    OvStoragePlugin_SecretValue *value)
{
    if (value == NULL) {
        return;
    }
    switch (value->tag) {
    case OvStoragePlugin_SecretValueTag_Bytes:
        ovc_stack_abi_bytes_clear(&value->bytes.bytes, true);
        break;
    case OvStoragePlugin_SecretValueTag_OAuthToken:
        ovc_stack_abi_bytes_clear(&value->oauth_token.token.bytes, true);
        if (value->oauth_token.refresh.present) {
            ovc_stack_abi_bytes_clear(
                &value->oauth_token.refresh.value.bytes, true);
        }
        break;
    case OvStoragePlugin_SecretValueTag_File:
        ovc_stack_abi_bytes_clear(&value->file.bytes, true);
        break;
    case OvStoragePlugin_SecretValueTag_MtlsCertPair:
        ovc_stack_abi_bytes_clear(&value->mtls_cert_pair.cert_pem.bytes,
                                  true);
        ovc_stack_abi_bytes_clear(&value->mtls_cert_pair.key_pem.bytes,
                                  true);
        break;
    case OvStoragePlugin_SecretValueTag_SystemIdentity:
    default:
        break;
    }
    memset(value, 0, sizeof(*value));
}

static bool ovc_stack_abi_secret_value_copy(
    OvStoragePlugin_SecretValue *out,
    const OvStorage_SecretValue *value)
{
    uint64_t expires_ms;

    memset(out, 0, sizeof(*out));
    if (value == NULL) {
        return false;
    }
    switch (value->kind) {
    case OVC_SECRET_VALUE_BYTES:
        out->tag = OvStoragePlugin_SecretValueTag_Bytes;
        return ovc_stack_abi_bytes_copy(&out->bytes.bytes,
                                        value->payload.bytes.data,
                                        value->payload.bytes.len);
    case OVC_SECRET_VALUE_OAUTH_TOKEN:
        out->tag = OvStoragePlugin_SecretValueTag_OAuthToken;
        if (!ovc_stack_abi_bytes_copy(
                &out->oauth_token.token.bytes,
                value->payload.oauth_token.token.data,
                value->payload.oauth_token.token.len)) {
            return false;
        }
        if (value->payload.oauth_token.has_refresh) {
            out->oauth_token.refresh.present = true;
            if (!ovc_stack_abi_bytes_copy(
                    &out->oauth_token.refresh.value.bytes,
                    value->payload.oauth_token.refresh.data,
                    value->payload.oauth_token.refresh.len)) {
                ovc_stack_abi_secret_value_clear(out);
                return false;
            }
        }
        if (value->payload.oauth_token.has_expires_at) {
            expires_ms =
                value->payload.oauth_token.expires_at_unix_nanos /
                UINT64_C(1000000);
            if (expires_ms > (uint64_t)INT64_MAX) {
                ovc_stack_abi_secret_value_clear(out);
                return false;
            }
            out->oauth_token.expires_at_unix_ms.present = true;
            out->oauth_token.expires_at_unix_ms.value =
                (int64_t)expires_ms;
        }
        return true;
    case OVC_SECRET_VALUE_FILE:
        out->tag = OvStoragePlugin_SecretValueTag_File;
        return ovc_stack_abi_bytes_copy(&out->file.bytes,
                                        value->payload.bytes.data,
                                        value->payload.bytes.len);
    case OVC_SECRET_VALUE_MTLS_CERT_PAIR:
        out->tag = OvStoragePlugin_SecretValueTag_MtlsCertPair;
        if (!ovc_stack_abi_bytes_copy(
                &out->mtls_cert_pair.cert_pem.bytes,
                value->payload.mtls_cert_pair.cert_pem.data,
                value->payload.mtls_cert_pair.cert_pem.len) ||
            !ovc_stack_abi_bytes_copy(
                &out->mtls_cert_pair.key_pem.bytes,
                value->payload.mtls_cert_pair.key_pem.data,
                value->payload.mtls_cert_pair.key_pem.len)) {
            ovc_stack_abi_secret_value_clear(out);
            return false;
        }
        return true;
    case OVC_SECRET_VALUE_SYSTEM_IDENTITY:
        out->tag = OvStoragePlugin_SecretValueTag_SystemIdentity;
        return true;
    default:
        return false;
    }
}

static void ovc_stack_abi_secret_bundle_clear(
    OvStoragePlugin_SecretBundle *bundle)
{
    size_t index;

    if (bundle == NULL) {
        return;
    }
    for (index = 0; index < bundle->entries.len; ++index) {
        ovc_stack_abi_str_clear(&bundle->entries.ptr[index].field);
        ovc_stack_abi_secret_value_clear(
            &bundle->entries.ptr[index].value);
    }
    ovc_abi_free(bundle->entries.ptr);
    bundle->entries.ptr = NULL;
    bundle->entries.len = 0;
}

static bool ovc_stack_abi_secret_bundle_copy(
    OvStoragePlugin_SecretBundle *out,
    const OvStorage_SecretBundle *bundle)
{
    size_t allocation_count;
    size_t index;

    memset(out, 0, sizeof(*out));
    allocation_count = bundle->len == 0 ? 1 : bundle->len;
    if (allocation_count > SIZE_MAX / sizeof(*out->entries.ptr)) {
        return false;
    }
    out->entries.ptr = (OvStoragePlugin_SecretBundleEntry *)ovc_abi_alloc(
        allocation_count * sizeof(*out->entries.ptr));
    if (out->entries.ptr == NULL) {
        return false;
    }
    memset(out->entries.ptr, 0, allocation_count * sizeof(*out->entries.ptr));
    for (index = 0; index < bundle->len; ++index) {
        if (!ovc_stack_abi_str_copy(
                &out->entries.ptr[index].field,
                bundle->entries[index].key,
                strlen(bundle->entries[index].key)) ||
            !ovc_stack_abi_secret_value_copy(
                &out->entries.ptr[index].value,
                bundle->entries[index].value)) {
            out->entries.len = index + 1;
            ovc_stack_abi_secret_bundle_clear(out);
            return false;
        }
        out->entries.len = index + 1;
    }
    return true;
}

static void ovc_stack_abi_connection_request_clear(
    OvStoragePlugin_ConnectionRequest *request)
{
    if (request == NULL) {
        return;
    }
    ovc_stack_abi_str_clear(&request->backend_kind);
    ovc_stack_abi_config_list_clear(&request->config);
    ovc_stack_abi_secret_bundle_clear(&request->credentials);
    if (request->display_name.present) {
        ovc_stack_abi_str_clear(&request->display_name.value);
    }
    memset(request, 0, sizeof(*request));
}

static bool ovc_stack_abi_connection_request_copy(
    OvStoragePlugin_ConnectionRequest *out,
    const OvStorage_ConnectionRequest *request)
{
    memset(out, 0, sizeof(*out));
    if (!ovc_stack_abi_str_copy(&out->backend_kind,
                                request->backend_kind,
                                strlen(request->backend_kind)) ||
        !ovc_stack_abi_config_list_copy(&out->config, request) ||
        !ovc_stack_abi_secret_bundle_copy(&out->credentials,
                                          &request->credentials)) {
        ovc_stack_abi_connection_request_clear(out);
        return false;
    }
    out->persist = request->persist;
    if (request->display_name != NULL) {
        out->display_name.present = true;
        if (!ovc_stack_abi_str_copy(&out->display_name.value,
                                    request->display_name,
                                    strlen(request->display_name))) {
            ovc_stack_abi_connection_request_clear(out);
            return false;
        }
    }
    return true;
}

static void ovc_stack_recorded_bundle_clear(OvStorage_SecretBundle *bundle)
{
    size_t secret_index;
    bool had_entries;

    if (bundle == NULL) {
        return;
    }
    had_entries = bundle->len != 0;
    for (secret_index = 0; secret_index < bundle->len; ++secret_index) {
        free(bundle->entries[secret_index].key);
        ovstorage_secret_value_destroy(bundle->entries[secret_index].value);
    }
    free(bundle->entries);
    bundle->entries = NULL;
    bundle->len = 0;
    bundle->capacity = 0;
    /* Only a bundle that actually carried secrets is poisoned: an empty
     * bundle re-serializes identically on a retry, so wiping it loses
     * nothing and config-only connections must survive a failed build. */
    if (had_entries) {
        bundle->consumed = true;
    }
}

static void ovc_stack_recorded_credentials_clear(OvStorage_Stack *stack)
{
    size_t connection_index;

    if (stack == NULL) {
        return;
    }
    for (connection_index = 0;
         connection_index < stack->connection_count;
         ++connection_index) {
        if (stack->connections[connection_index].request == NULL) {
            continue;
        }
        ovc_stack_recorded_bundle_clear(
            &stack->connections[connection_index].request->credentials);
    }
}

static OvStorage_Status ovc_stack_consumed_credentials_error(
    OvStorage_Error *out_error,
    const char *target)
{
    return ovc_stack_error(
        out_error,
        OvStorage_Status_InvalidArgument,
        "connection credentials for `%s` were consumed by a failed build; "
        "destroy this Stack and rebuild it with fresh credentials",
        target);
}

/*
 * A failed build wipes every recorded bundle (credential hygiene) and marks it
 * consumed.  The public contract still leaves the caller owning the Stack
 * after an error, so a rebuild is legal -- but it must fail loudly here
 * rather than silently serialize an empty SecretBundle into add_connection.
 */
static OvStorage_Status ovc_stack_reject_consumed_credentials(
    const OvStorage_Stack *stack,
    OvStorage_Error *out_error)
{
    size_t connection_index;

    for (connection_index = 0;
         connection_index < stack->connection_count;
         ++connection_index) {
        const ovc_stack_connection *connection;

        connection = &stack->connections[connection_index];
        if (connection->request != NULL &&
            connection->request->credentials.consumed) {
            return ovc_stack_consumed_credentials_error(
                out_error, connection->target);
        }
    }
    return OvStorage_Status_Ok;
}

static size_t ovc_stack_layer_index(const OvStorage_Stack *stack,
                                    const char *instance_id)
{
    size_t index;

    for (index = 0; index < stack->layer_count; ++index) {
        if (strcmp(stack->layers[index].instance_id, instance_id) == 0) {
            return index;
        }
    }
    return SIZE_MAX;
}

static OvStorage_Status ovc_stack_validate_layer_graph(
    ovc_stack_build_state *build,
    size_t index,
    OvStorage_Error *out_error)
{
    ovc_stack_layer *layer;
    OvStorage_Status status;
    size_t child_index;

    if (build->visits[index] == 1) {
        return ovc_stack_error(out_error,
                               OvStorage_Status_InvalidArgument,
                               "layer graph contains a cycle at `%s`",
                               build->stack->layers[index].instance_id);
    }
    if (build->visits[index] == 2) {
        return ovc_stack_error(
            out_error,
            OvStorage_Status_InvalidArgument,
            "layer `%s` is referenced more than once",
            build->stack->layers[index].instance_id);
    }
    build->visits[index] = 1;
    layer = &build->stack->layers[index];

    if (layer->factory == NULL ||
        layer->factory->layer_type != layer->layer_type) {
        return ovc_stack_error(
            out_error,
            OvStorage_Status_InvalidArgument,
            "layer `%s` declares a mismatched layer_type",
            layer->instance_id);
    }
    switch (layer->layer_type) {
    case OvStoragePlugin_LayerType_Backend:
        if (layer->inner_id != NULL || layer->child_count != 0) {
            return ovc_stack_error(
                out_error,
                OvStorage_Status_InvalidArgument,
                "backend layer `%s` must not declare children",
                layer->instance_id);
        }
        break;
    case OvStoragePlugin_LayerType_Wrapper:
        if (layer->inner_id == NULL || layer->child_count != 0) {
            return ovc_stack_error(
                out_error,
                OvStorage_Status_InvalidArgument,
                "wrapper layer `%s` must declare exactly one inner",
                layer->instance_id);
        }
        child_index = ovc_stack_layer_index(build->stack,
                                            layer->inner_id);
        if (child_index == SIZE_MAX) {
            return ovc_stack_error(
                out_error,
                OvStorage_Status_InvalidArgument,
                "layer `%s` references undeclared inner `%s`",
                layer->instance_id,
                layer->inner_id);
        }
        status = ovc_stack_validate_layer_graph(build,
                                                child_index,
                                                out_error);
        if (status != OvStorage_Status_Ok) {
            return status;
        }
        break;
    case OvStoragePlugin_LayerType_Router:
        if (layer->inner_id != NULL) {
            return ovc_stack_error(
                out_error,
                OvStorage_Status_InvalidArgument,
                "router layer `%s` must not declare an inner",
                layer->instance_id);
        }
        for (child_index = 0; child_index < layer->child_count;
             ++child_index) {
            size_t declared_index;

            declared_index = ovc_stack_layer_index(
                build->stack, layer->child_ids[child_index]);
            if (declared_index == SIZE_MAX) {
                return ovc_stack_error(
                    out_error,
                    OvStorage_Status_InvalidArgument,
                    "layer `%s` references undeclared child `%s`",
                    layer->instance_id,
                    layer->child_ids[child_index]);
            }
            status = ovc_stack_validate_layer_graph(build,
                                                    declared_index,
                                                    out_error);
            if (status != OvStorage_Status_Ok) {
                return status;
            }
        }
        break;
    default:
        return ovc_stack_error(out_error,
                               OvStorage_Status_InvalidArgument,
                               "layer `%s` has an unknown layer_type",
                               layer->instance_id);
    }
    build->visits[index] = 2;
    return OvStorage_Status_Ok;
}

static OvStorage_Status ovc_stack_validate_shape(
    ovc_stack_build_state *build,
    size_t *out_root_index,
    OvStorage_Error *out_error)
{
    size_t root_index;
    size_t index;
    OvStorage_Status status;

    if (build->stack->root_id == NULL) {
        return ovc_stack_error(
            out_error,
            OvStorage_Status_InvalidArgument,
            "stack root not set; call ovstorage_stack_set_root before build");
    }
    root_index = ovc_stack_layer_index(build->stack,
                                       build->stack->root_id);
    if (root_index == SIZE_MAX) {
        return ovc_stack_error(out_error,
                               OvStorage_Status_InvalidArgument,
                               "stack root `%s` is not declared",
                               build->stack->root_id);
    }
    status = ovc_stack_validate_layer_graph(build,
                                            root_index,
                                            out_error);
    if (status != OvStorage_Status_Ok) {
        return status;
    }
    for (index = 0; index < build->stack->layer_count; ++index) {
        if (build->visits[index] != 2) {
            return ovc_stack_error(
                out_error,
                OvStorage_Status_InvalidArgument,
                "layer `%s` is unreachable from root `%s`",
                build->stack->layers[index].instance_id,
                build->stack->root_id);
        }
    }
    for (index = 0; index < build->stack->connection_count; ++index) {
        if (ovc_stack_layer_index(build->stack,
                                  build->stack->connections[index].target) ==
            SIZE_MAX) {
            return ovc_stack_error(
                out_error,
                OvStorage_Status_InvalidArgument,
                "connection target `%s` is not declared",
                build->stack->connections[index].target);
        }
    }
    *out_root_index = root_index;
    return OvStorage_Status_Ok;
}

static void ovc_stack_layer_handle_drop(OvStoragePlugin_LayerHandle *handle)
{
    if (handle == NULL || handle->vtable == NULL) {
        return;
    }
    if (handle->vtable->drop != NULL) {
        handle->vtable->drop(handle->state);
    }
    memset(handle, 0, sizeof(*handle));
}

static bool ovc_stack_layer_handle_can_drop(
    const OvStoragePlugin_LayerHandle *handle)
{
    return handle != NULL && handle->vtable != NULL &&
           handle->vtable->struct_size >=
               offsetof(OvStoragePlugin_LayerVTableV1, drop) +
                   sizeof(handle->vtable->drop) &&
           handle->vtable->drop != NULL;
}

static bool ovc_stack_layer_handle_is_valid(
    const OvStoragePlugin_LayerHandle *handle)
{
    return handle != NULL && handle->vtable != NULL &&
           handle->vtable->struct_size >=
               sizeof(OvStoragePlugin_LayerVTableV1) &&
           handle->vtable->abi_version ==
               OVSTORAGE_PLUGIN_ABI_VERSION &&
           handle->vtable->drop != NULL &&
           handle->vtable->name != NULL &&
           handle->vtable->descriptor != NULL &&
           handle->vtable->owned_targets != NULL &&
           handle->vtable->root_info_for != NULL &&
           handle->vtable->list_kinds != NULL &&
           handle->vtable->list_address_roots != NULL &&
           handle->vtable->stat != NULL &&
           handle->vtable->read != NULL &&
           handle->vtable->write != NULL &&
           handle->vtable->write_stream != NULL &&
           handle->vtable->write_redirect != NULL &&
           handle->vtable->continue_write != NULL &&
           handle->vtable->delete_ != NULL &&
           handle->vtable->copy != NULL &&
           handle->vtable->rename != NULL &&
           handle->vtable->update_metadata != NULL &&
           handle->vtable->check_access != NULL &&
           handle->vtable->materialize != NULL &&
           handle->vtable->list != NULL &&
           handle->vtable->list_versions != NULL &&
           handle->vtable->get_latest_version != NULL &&
           handle->vtable->watch_directory != NULL &&
           handle->vtable->create_directory != NULL &&
           handle->vtable->delete_directory != NULL &&
           handle->vtable->probe != NULL &&
           handle->vtable->add_connection != NULL &&
           handle->vtable->remove_connection != NULL &&
           handle->vtable->list_connections != NULL &&
           handle->vtable->update_connection_credentials != NULL &&
           handle->vtable->update_connection_attributes != NULL &&
           handle->vtable->authenticate_connection != NULL;
}

static void ovc_stack_create_backend_request_clear(
    OvStoragePlugin_CreateBackendRequest *request)
{
    ovc_stack_abi_str_clear(&request->kind);
    ovc_stack_abi_str_clear(&request->instance_id);
    ovc_stack_abi_config_list_clear(&request->config);
}

static bool ovc_stack_create_backend_request_init(
    OvStoragePlugin_CreateBackendRequest *request,
    const ovc_stack_layer *layer)
{
    memset(request, 0, sizeof(*request));
    request->struct_size = sizeof(*request);
    if (!ovc_stack_abi_str_copy(&request->kind,
                                layer->factory->kind.ptr,
                                layer->factory->kind.len) ||
        !ovc_stack_abi_str_copy(&request->instance_id,
                                layer->instance_id,
                                strlen(layer->instance_id)) ||
        !ovc_stack_abi_config_entries_copy(&request->config,
                                           layer->config,
                                           layer->config_len)) {
        ovc_stack_create_backend_request_clear(request);
        return false;
    }
    return true;
}

static void ovc_stack_create_wrapper_request_clear(
    OvStoragePlugin_CreateWrapperRequest *request,
    bool clear_inner)
{
    if (clear_inner) {
        ovc_stack_layer_handle_drop(&request->inner);
    }
    ovc_stack_abi_str_clear(&request->kind);
    ovc_stack_abi_str_clear(&request->instance_id);
    ovc_stack_abi_config_list_clear(&request->config);
}

static bool ovc_stack_create_wrapper_request_init(
    OvStoragePlugin_CreateWrapperRequest *request,
    const ovc_stack_layer *layer,
    OvStoragePlugin_LayerHandle inner)
{
    memset(request, 0, sizeof(*request));
    request->struct_size = sizeof(*request);
    request->inner = inner;
    if (!ovc_stack_abi_str_copy(&request->kind,
                                layer->factory->kind.ptr,
                                layer->factory->kind.len) ||
        !ovc_stack_abi_str_copy(&request->instance_id,
                                layer->instance_id,
                                strlen(layer->instance_id)) ||
        !ovc_stack_abi_config_entries_copy(&request->config,
                                           layer->config,
                                           layer->config_len)) {
        ovc_stack_create_wrapper_request_clear(request, false);
        return false;
    }
    return true;
}

static void ovc_stack_root_info_clear(OvStoragePlugin_RootInfo *root)
{
    if (root == NULL) {
        return;
    }
    ovc_stack_abi_str_clear(&root->root);
    if (root->display_name.present) {
        ovc_stack_abi_str_clear(&root->display_name.value);
    }
    ovc_stack_abi_str_clear(&root->layer_kind);
    if (root->connection_id.present) {
        ovc_stack_abi_str_clear(&root->connection_id.value.id);
    }
    if (root->source.connection_id.present) {
        ovc_stack_abi_str_clear(&root->source.connection_id.value.id);
    }
    if (root->source.broker_principal.present) {
        ovc_stack_abi_str_clear(&root->source.broker_principal.value);
    }
    if (root->source.alias_to.present) {
        ovc_stack_abi_str_clear(&root->source.alias_to.value);
    }
    if (root->source.alias_source.present &&
        root->source.alias_source.value.broker_principal.present) {
        ovc_stack_abi_str_clear(
            &root->source.alias_source.value.broker_principal.value);
    }
    if (root->alias_state.present &&
        root->alias_state.value.reason.present) {
        ovc_stack_abi_str_clear(&root->alias_state.value.reason.value);
    }
    if (root->icon.present) {
        ovc_stack_abi_bytes_clear(&root->icon.value, false);
    }
    ovc_stack_abi_key_values_clear(&root->user_metadata);
    if (root->owning_target.present) {
        ovc_stack_abi_str_clear(&root->owning_target.value);
    }
    memset(root, 0, sizeof(*root));
}

static void ovc_stack_root_snapshot_clear(
    OvStoragePlugin_RootInfoSnapshot *snapshot)
{
    size_t index;

    if (snapshot == NULL) {
        return;
    }
    if (snapshot->roots.ptr != NULL) {
        for (index = 0; index < snapshot->roots.len; ++index) {
            /* Do not inspect an untrusted tail from a malformed plugin. */
            if (snapshot->roots.ptr[index].struct_size >=
                sizeof(snapshot->roots.ptr[index])) {
                ovc_stack_root_info_clear(&snapshot->roots.ptr[index]);
            }
        }
    }
    ovc_abi_free(snapshot->roots.ptr);
    memset(snapshot, 0, sizeof(*snapshot));
}

static void ovc_stack_root_updates_destroy(
    OvStoragePlugin_RootInfoChangeStream *updates)
{
    if (updates == NULL) {
        return;
    }
    if (updates->drop_fn != NULL) {
        updates->drop_fn(updates->state);
    }
    /* The stream struct itself is a plugin-minted heap allocation. */
    ovc_abi_free(updates);
}

static void ovc_stack_route_roots_clear(ovc_stack_route_root *roots,
                                        size_t root_count)
{
    size_t index;

    for (index = 0; index < root_count; ++index) {
        free(roots[index].bytes);
    }
    free(roots);
}

/* Whether the (optional) build-scoped cancel token has been canceled. */
static bool ovc_stack_build_is_canceled(const ovc_stack_build_state *build)
{
    return build->cancel != NULL && build->cancel->state != NULL &&
           build->cancel->is_canceled != NULL &&
           build->cancel->is_canceled(build->cancel->state);
}

/* Mint the per-vtable-call token for a build-phase plugin call: a clone
 * of the build-scoped token when one exists (async builds), so a Layer
 * can observe a mid-build cancellation, else an independent
 * never-canceled state exactly as before. */
static OvStoragePlugin_CancelTokenFFI ovc_stack_build_mint_cancel(
    const ovc_stack_build_state *build)
{
    OvStoragePlugin_CancelTokenFFI minted;

    if (build->cancel == NULL || build->cancel->state == NULL ||
        build->cancel->clone == NULL) {
        return ovc_cancel_token_mint(NULL);
    }
    minted = *build->cancel;
    minted.state = minted.clone(minted.state);
    if (minted.state == NULL) {
        /* As in ovc_cancel_token_mint: the by-value ABI has no way to
         * report a minting failure. */
        abort();
    }
    return minted;
}

/* Reclaims an add_connection outcome no waiter reads; defined beside the
 * Connection destroyer it wraps. The list_address_roots twin follows below. */
static void ovc_stack_build_slot_discard_connection(
    void *result,
    OvStoragePlugin_Error *error);

/* Locking a slot is infallible bookkeeping; a platform failure here means
 * the process cannot uphold the reference counts below. */
static void ovc_stack_slot_sync_success(int result)
{
    if (result != 0) {
        abort();
    }
}

/*
 * Create the state for one slot call, carrying both references: the build
 * thread's and the one the plugin's `on_complete` consumes.
 *
 * The factory table is sized here, where an allocation failure is still an
 * ordinary build error, so abandoning later cannot fail for want of memory.
 */
static ovc_stack_build_slot *ovc_stack_build_slot_create(
    const ovc_stack_build_state *build,
    ovc_stack_build_slot_discard_fn discard)
{
    ovc_stack_build_slot *slot;
    size_t capacity;

    capacity = build->stack->layer_count == 0 ? 1 : build->stack->layer_count;
    if (capacity > SIZE_MAX / sizeof(*slot->quarantine_factories)) {
        return NULL;
    }
    slot = (ovc_stack_build_slot *)calloc(1, sizeof(*slot));
    if (slot == NULL) {
        return NULL;
    }
    slot->quarantine_factories = (ovc_layer_factory **)calloc(
        capacity, sizeof(*slot->quarantine_factories));
    if (slot->quarantine_factories == NULL) {
        free(slot);
        return NULL;
    }
    slot->quarantine_factory_capacity = capacity;
    if (ovc_mutex_init(&slot->mutex) != 0) {
        free(slot->quarantine_factories);
        free(slot);
        return NULL;
    }
    if (ovc_cond_init(&slot->changed) != 0) {
        (void)ovc_mutex_destroy(&slot->mutex);
        free(slot->quarantine_factories);
        free(slot);
        return NULL;
    }
    slot->references = 2;
    slot->discard = discard;
    return slot;
}

/*
 * Reclaim everything the slot still owns.  Reaching this point means the slot
 * call returned and its completion was delivered — the same drain condition
 * dispatch.c requires before it drops a Layer through the vtable.
 */
static void ovc_stack_build_slot_destroy(ovc_stack_build_slot *slot)
{
    size_t index;

    /* An outcome still recorded here is one the build thread never took. */
    if (slot->result != NULL || slot->error != NULL) {
        slot->discard(slot->result, slot->error);
    }
    /* The subtree's layers before the factories that keep their code and
     * plugin state loaded. */
    ovc_stack_layer_handle_drop(&slot->quarantine);
    for (index = 0; index < slot->quarantine_factory_count; ++index) {
        ovc_layer_factory_release(slot->quarantine_factories[index]);
    }
    free(slot->quarantine_factories);
    ovc_stack_slot_sync_success(ovc_cond_destroy(&slot->changed));
    ovc_stack_slot_sync_success(ovc_mutex_destroy(&slot->mutex));
    free(slot);
}

/* Whether tearing the slot down would call back into the plugin. */
static bool ovc_stack_build_slot_reenters_plugin(
    const ovc_stack_build_slot *slot)
{
    return slot->quarantine.vtable != NULL || slot->result != NULL ||
           slot->error != NULL;
}

static void ovc_stack_build_slot_reap(void *argument)
{
    ovc_stack_build_slot_destroy((ovc_stack_build_slot *)argument);
}

/*
 * Drop one reference; the last one tears the slot down.  A Layer that never
 * completes its call holds its reference forever: neither that Layer nor the
 * slot can be reclaimed while the plugin may still write the outcome.
 *
 * `from_completion` marks the release the plugin's own `on_complete` hands
 * back.  Only that one is nested inside a live plugin call frame, so only it
 * has to move plugin-visible teardown — a quarantined subtree's drop, and an
 * unread outcome's reclaimer, which for the roots slot drops a plugin-owned
 * update stream — onto a runtime worker.  A build-thread release runs the
 * same teardown in place, where no plugin frame is on the stack.
 *
 * If that hand-off cannot be queued the slot is stranded rather than torn
 * down in place: re-entering the plugin is the hazard this exists to prevent,
 * so the fallback gives up the memory instead of the invariant.  The cost is
 * one slot and one abandoned subtree, in a process already out of memory or
 * already without a runtime.
 */
static void ovc_stack_build_slot_release(ovc_stack_build_slot *slot,
                                         bool from_completion)
{
    unsigned remaining;

    if (slot == NULL) {
        return;
    }
    ovc_stack_slot_sync_success(ovc_mutex_lock(&slot->mutex));
    if (slot->references == 0) {
        ovc_stack_slot_sync_success(ovc_mutex_unlock(&slot->mutex));
        abort();
    }
    --slot->references;
    remaining = slot->references;
    ovc_stack_slot_sync_success(ovc_mutex_unlock(&slot->mutex));
    if (remaining != 0) {
        return;
    }
    if (from_completion && ovc_stack_build_slot_reenters_plugin(slot)) {
        /* Queued, or stranded when it cannot be; either way this thread
         * leaves the slot alone. */
        (void)ovc_runtime_submit(ovc_stack_build_slot_reap, slot);
        return;
    }
    ovc_stack_build_slot_destroy(slot);
}

/*
 * Uniform `OnComplete` for every build-time slot: record the outcome, wake
 * the build thread, and hand back the reference the call was issued with.
 *
 * The ABI fires each slot exactly once, and that single fire is what the
 * plugin's reference pays for.  The `fired` guard covers only the window in
 * which some other reference still holds the slot alive: there a repeat fire
 * neither overwrites the recorded outcome nor double-releases, and reclaims
 * its own payload through the reclaimer captured under the lock.  Once the
 * last reference is gone `user_data` is a freed pointer, so a repeat fire
 * after that is undefined however this function is written — the exactly-once
 * contract is the guarantee, not the guard.
 *
 * The delivered `status` is not recorded: pointer presence is authoritative
 * for every build-time slot, and legacy status values can collide.
 */
static void ovc_stack_build_slot_complete(int32_t status,
                                          void *result,
                                          OvStoragePlugin_Error *error,
                                          void *user_data)
{
    ovc_stack_build_slot *slot;
    ovc_stack_build_slot_discard_fn discard;
    int duplicate;

    (void)status;
    slot = (ovc_stack_build_slot *)user_data;
    ovc_stack_slot_sync_success(ovc_mutex_lock(&slot->mutex));
    duplicate = slot->fired;
    discard = slot->discard;
    if (!duplicate) {
        slot->result = result;
        slot->error = error;
        slot->fired = 1;
        ovc_stack_slot_sync_success(ovc_cond_broadcast(&slot->changed));
    }
    ovc_stack_slot_sync_success(ovc_mutex_unlock(&slot->mutex));
    if (duplicate) {
        discard(result, error);
        return;
    }
    ovc_stack_build_slot_release(slot, true);
}

/* Wake an abandoning build thread when the build-scoped token fires. */
static void ovc_stack_build_slot_wake(void *user_data)
{
    ovc_stack_build_slot *slot;

    slot = (ovc_stack_build_slot *)user_data;
    ovc_stack_slot_sync_success(ovc_mutex_lock(&slot->mutex));
    slot->canceled = 1;
    ovc_stack_slot_sync_success(ovc_cond_broadcast(&slot->changed));
    ovc_stack_slot_sync_success(ovc_mutex_unlock(&slot->mutex));
}

/*
 * Block the build thread until the Layer completes the slot or the
 * build-scoped token fires.  Subscribing to the token is what bounds the
 * wait: a Layer is free to ignore the token clone it was handed, and the
 * build must still be abandonable — the guarantee the Rust host gets from
 * racing the whole build against the token.
 *
 * On true the outcome moved into `*out_result` / `*out_error` and the caller
 * owns it.  On false the wait was abandoned and the caller reports Cancelled
 * after handing the outstanding Layer to ovc_stack_build_slot_abandon.
 */
static bool ovc_stack_build_slot_wait(ovc_stack_build_slot *slot,
                                      const ovc_stack_build_state *build,
                                      void **out_result,
                                      OvStoragePlugin_Error **out_error)
{
    uint64_t subscription;
    bool completed;

    *out_result = NULL;
    *out_error = NULL;
    subscription = 0;
    /*
     * Both halves of the subscription are required: a token that could
     * register a wake but never retract it would leave the wake pointing at
     * a slot this thread is about to release.  Without them the wait falls
     * back to the Layer's own completion, as it does for the blocking entry.
     * An already-canceled token runs the wake inline.  Subscribers run
     * serially on the cancelling thread, so this wake is only as prompt as
     * the other callbacks registered on the same token.
     */
    if (build->cancel != NULL && build->cancel->state != NULL &&
        build->cancel->register_callback != NULL &&
        build->cancel->unregister_callback != NULL) {
        subscription = build->cancel->register_callback(
            build->cancel->state, ovc_stack_build_slot_wake, slot);
    }
    ovc_stack_slot_sync_success(ovc_mutex_lock(&slot->mutex));
    while (!slot->fired && !slot->canceled) {
        ovc_stack_slot_sync_success(
            ovc_cond_wait(&slot->changed, &slot->mutex));
    }
    /* A completion that landed alongside the cancellation is still the
     * Layer's answer; the caller re-checks the token before accepting it. */
    completed = slot->fired != 0;
    if (completed) {
        *out_result = slot->result;
        *out_error = slot->error;
        slot->result = NULL;
        slot->error = NULL;
    }
    ovc_stack_slot_sync_success(ovc_mutex_unlock(&slot->mutex));
    /* Returns only once an in-flight wake has finished touching the slot. */
    if (subscription != 0) {
        build->cancel->unregister_callback(build->cancel->state, subscription);
    }
    return completed;
}

/*
 * Hand the Layer whose call is outstanding to `slot` and release the build
 * thread's reference.
 *
 * The Layer is deliberately excluded from the partial build's unwind: the
 * plugin is still running a call against its state, and the ABI's
 * exclusive-after-drain drop contract holds only once that call's completion
 * has been delivered.  The slot drops it then.
 *
 * What moves across is a whole adopted subtree, so every factory the Stack
 * resolved is retained with it.  A quarantined wrapper or router already owns
 * child handles other plugins built, and releasing one of those factories
 * runs that plugin's `drop` — which would tear down state the quarantined
 * subtree still points at.  The retained set is the Stack's, not the
 * subtree's, for the same reason the built root handle retains the Stack's:
 * a superset needs no reachability walk to stay correct.
 */
static void ovc_stack_build_slot_abandon(ovc_stack_build_slot *slot,
                                         ovc_stack_build_state *build,
                                         size_t layer_index)
{
    size_t index;

    if (build->owned[layer_index]) {
        slot->quarantine = build->handles[layer_index];
        for (index = 0; index < build->stack->layer_count; ++index) {
            ovc_layer_factory *retained;

            retained = ovc_layer_factory_retain(
                build->stack->layers[index].factory);
            if (retained == NULL) {
                /* The build holds a live reference to each of these, so this
                 * only fails on saturation; keeping the subtree without them
                 * would let its code unload under the call it is running. */
                abort();
            }
            slot->quarantine_factories[slot->quarantine_factory_count] =
                retained;
            ++slot->quarantine_factory_count;
        }
        build->owned[layer_index] = 0;
        memset(&build->handles[layer_index],
               0,
               sizeof(build->handles[layer_index]));
    }
    ovc_stack_build_slot_release(slot, false);
}

static void ovc_stack_build_slot_discard_roots(void *result,
                                               OvStoragePlugin_Error *error)
{
    OvStoragePlugin_ListAddressRootsResult *envelope;

    envelope = (OvStoragePlugin_ListAddressRootsResult *)result;
    if (envelope != NULL) {
        ovc_stack_root_snapshot_clear(&envelope->snapshot);
        ovc_stack_root_updates_destroy(envelope->updates);
        ovc_abi_free(envelope);
    }
    ovc_stack_plugin_error_destroy(error);
}

typedef enum {
    /* `*out_result` / `*out_error` are the caller's to reclaim. */
    OVC_STACK_SLOT_TAKEN,
    /* Nothing is outstanding and nothing is left to reclaim. */
    OVC_STACK_SLOT_CANCELLED
} ovc_stack_slot_outcome;

/*
 * Drive one issued slot call to its conclusion: wait for it, abandon it if
 * the build is cancelled first, and settle ownership either way.
 *
 * A Layer may complete SUCCESSFULLY after its token fired, so a result
 * arriving does not mean cancellation lost the race; the token is re-checked
 * before the outcome is accepted, and an outcome the cancellation invalidated
 * is reclaimed here rather than handed back.  Keeping all of that behind one
 * call is what stops a third async slot from re-deriving the protocol.
 */
static ovc_stack_slot_outcome ovc_stack_build_slot_settle(
    ovc_stack_build_slot *slot,
    ovc_stack_build_state *build,
    size_t layer_index,
    void **out_result,
    OvStoragePlugin_Error **out_error)
{
    ovc_stack_build_slot_discard_fn discard;

    discard = slot->discard;
    if (!ovc_stack_build_slot_wait(slot, build, out_result, out_error)) {
        ovc_stack_build_slot_abandon(slot, build, layer_index);
        return OVC_STACK_SLOT_CANCELLED;
    }
    ovc_stack_build_slot_release(slot, false);
    if (ovc_stack_build_is_canceled(build)) {
        discard(*out_result, *out_error);
        *out_result = NULL;
        *out_error = NULL;
        return OVC_STACK_SLOT_CANCELLED;
    }
    return OVC_STACK_SLOT_TAKEN;
}

static OvStorage_Status ovc_stack_validate_router_roots(
    ovc_stack_build_state *build,
    const ovc_stack_layer *router,
    OvStorage_Error *out_error)
{
    ovc_stack_route_root *roots;
    size_t root_count;
    size_t root_capacity;
    size_t child_at;

    roots = NULL;
    root_count = 0;
    root_capacity = 0;
    for (child_at = 0; child_at < router->child_count; ++child_at) {
        size_t child_index;
        OvStoragePlugin_RootInfoSnapshot snapshot;
        OvStoragePlugin_RootInfoChangeStream *updates;
        OvStoragePlugin_ListAddressRootsRequest request;
        OvStoragePlugin_CancelTokenFFI cancel;
        ovc_stack_build_slot *slot;
        void *slot_result;
        OvStoragePlugin_Error *slot_error;
        OvStoragePlugin_ListAddressRootsResult *envelope;
        size_t root_at;

        /* Poll cancellation between children. Each child's slot still gets
         * the build token and a well-behaved layer completes with Cancelled
         * on its own, but a router over slow remote children would otherwise
         * walk the whole child list before reaching the next polled boundary
         * in ovc_stack_instantiate_layer. */
        if (ovc_stack_build_is_canceled(build)) {
            ovc_stack_route_roots_clear(roots, root_count);
            return ovc_stack_error(out_error,
                                   OvStorage_Status_Cancelled,
                                   "stack build canceled");
        }
        child_index = ovc_stack_layer_index(build->stack,
                                            router->child_ids[child_at]);
        /* The v8 list_address_roots slot is async; block the build thread
         * on the slot (a caller or dedicated async-build thread, never a
         * runtime worker — see ovc_stack_build_run — so it cannot starve
         * the io-task pool) to keep root validation synchronous. */
        memset(&request, 0, sizeof(request));
        request.struct_size = sizeof(request);
        slot = ovc_stack_build_slot_create(
            build, ovc_stack_build_slot_discard_roots);
        if (slot == NULL) {
            ovc_stack_route_roots_clear(roots, root_count);
            return ovc_stack_error(
                out_error,
                OvStorage_Status_Internal,
                "could not initialize root introspection for `%s`",
                router->child_ids[child_at]);
        }
        cancel = ovc_stack_build_mint_cancel(build);
        build->handles[child_index].vtable->list_address_roots(
            build->handles[child_index].state,
            &request,
            &cancel,
            ovc_stack_build_slot_complete,
            slot);
        if (cancel.state != NULL && cancel.drop != NULL) {
            cancel.drop(cancel.state);
        }
        /* The ABI request is moved during the vtable's synchronous prologue. */
        memset(&request, 0, sizeof(request));
        if (ovc_stack_build_slot_settle(slot, build, child_index,
                                        &slot_result, &slot_error) !=
            OVC_STACK_SLOT_TAKEN) {
            ovc_stack_route_roots_clear(roots, root_count);
            return ovc_stack_error(out_error,
                                   OvStorage_Status_Cancelled,
                                   "stack build canceled");
        }
        envelope = (OvStoragePlugin_ListAddressRootsResult *)slot_result;
        if (slot_error != NULL || envelope == NULL) {
            /* The error itself is consumed by ovc_stack_plugin_failure. */
            ovc_stack_build_slot_discard_roots(envelope, NULL);
            ovc_stack_route_roots_clear(roots, root_count);
            return ovc_stack_plugin_failure(out_error,
                                            slot_error,
                                            "list_address_roots",
                                            router->child_ids[child_at]);
        }
        /* Adopt the two envelope fields, then free the shell (skipping its
         * Drop) so neither buffer is released twice. */
        snapshot = envelope->snapshot;
        updates = envelope->updates;
        ovc_abi_free(envelope);
        if (snapshot.roots.len != 0 && snapshot.roots.ptr == NULL) {
            ovc_stack_root_snapshot_clear(&snapshot);
            ovc_stack_root_updates_destroy(updates);
            ovc_stack_route_roots_clear(roots, root_count);
            return ovc_stack_error(
                out_error,
                OvStorage_Status_Internal,
                "layer `%s` returned an invalid root snapshot",
                router->child_ids[child_at]);
        }
        if (snapshot.updates != (updates != NULL) ||
            (updates != NULL &&
             (updates->next_fn == NULL || updates->drop_fn == NULL))) {
            ovc_stack_root_snapshot_clear(&snapshot);
            ovc_stack_root_updates_destroy(updates);
            ovc_stack_route_roots_clear(roots, root_count);
            return ovc_stack_error(
                out_error,
                OvStorage_Status_Internal,
                "layer `%s` returned an invalid root update stream",
                router->child_ids[child_at]);
        }
        ovc_stack_root_updates_destroy(updates);
        for (root_at = 0; root_at < snapshot.roots.len; ++root_at) {
            OvStoragePlugin_Str *root;
            size_t prior;

            if (snapshot.roots.ptr[root_at].struct_size <
                sizeof(snapshot.roots.ptr[root_at])) {
                ovc_stack_root_snapshot_clear(&snapshot);
                ovc_stack_route_roots_clear(roots, root_count);
                return ovc_stack_error(
                    out_error,
                    OvStorage_Status_Internal,
                    "layer `%s` returned an invalid root record",
                    router->child_ids[child_at]);
            }
            root = &snapshot.roots.ptr[root_at].root;
            if (root->ptr == NULL) {
                ovc_stack_root_snapshot_clear(&snapshot);
                ovc_stack_route_roots_clear(roots, root_count);
                return ovc_stack_error(
                    out_error,
                    OvStorage_Status_Internal,
                    "layer `%s` returned a null address root",
                    router->child_ids[child_at]);
            }
            for (prior = 0; prior < root_count; ++prior) {
                if (roots[prior].child_index != child_at &&
                    roots[prior].len == root->len &&
                    (root->len == 0 ||
                     memcmp(roots[prior].bytes,
                            root->ptr,
                            root->len) == 0)) {
                    ovc_stack_root_snapshot_clear(&snapshot);
                    ovc_stack_route_roots_clear(roots, root_count);
                    return ovc_stack_error(
                        out_error,
                        OvStorage_Status_Conflict,
                        "router `%s` has an exact address-root collision",
                        router->instance_id);
                }
            }
            if (root_count == root_capacity) {
                size_t next_capacity;
                ovc_stack_route_root *next;

                next_capacity = root_capacity == 0 ? 8 : root_capacity * 2;
                if (next_capacity < root_capacity ||
                    next_capacity > SIZE_MAX / sizeof(*next)) {
                    ovc_stack_root_snapshot_clear(&snapshot);
                    ovc_stack_route_roots_clear(roots, root_count);
                    return ovc_stack_error(out_error,
                                           OvStorage_Status_Internal,
                                           "router root table is too large");
                }
                next = (ovc_stack_route_root *)realloc(
                    roots, next_capacity * sizeof(*next));
                if (next == NULL) {
                    ovc_stack_root_snapshot_clear(&snapshot);
                    ovc_stack_route_roots_clear(roots, root_count);
                    return ovc_stack_error(out_error,
                                           OvStorage_Status_Internal,
                                           "out of memory building router roots");
                }
                roots = next;
                root_capacity = next_capacity;
            }
            /* Host-internal collision-detection copy; never crosses the ABI. */
            roots[root_count].bytes = (char *)malloc(root->len == 0
                                                          ? 1
                                                          : root->len);
            if (roots[root_count].bytes == NULL) {
                ovc_stack_root_snapshot_clear(&snapshot);
                ovc_stack_route_roots_clear(roots, root_count);
                return ovc_stack_error(out_error,
                                       OvStorage_Status_Internal,
                                       "out of memory building router roots");
            }
            if (root->len != 0) {
                memcpy(roots[root_count].bytes, root->ptr, root->len);
            }
            roots[root_count].len = root->len;
            roots[root_count].child_index = child_at;
            ++root_count;
        }
        ovc_stack_root_snapshot_clear(&snapshot);
    }
    ovc_stack_route_roots_clear(roots, root_count);
    return OvStorage_Status_Ok;
}

static void ovc_stack_abi_connection_destroy(
    OvStoragePlugin_Connection *connection)
{
    size_t index;

    if (connection == NULL) {
        return;
    }
    ovc_stack_abi_str_clear(&connection->id.id);
    ovc_stack_abi_str_clear(&connection->backend_kind);
    ovc_stack_abi_str_clear(&connection->display_name);
    if (connection->source.tag ==
        OvStoragePlugin_ConnectionSourceTag_BrokerDelivered) {
        ovc_stack_abi_str_clear(
            &connection->source.broker_delivered.broker_principal);
    }
    for (index = 0; index < connection->current_addresses.len; ++index) {
        ovc_stack_abi_str_clear(&connection->current_addresses.ptr[index]);
    }
    ovc_abi_free(connection->current_addresses.ptr);
    if (connection->auth_state.tag ==
        OvStoragePlugin_ConnectionAuthStateTag_AwaitingAuth) {
        if (connection->auth_state.awaiting_auth.reason.tag ==
            OvStoragePlugin_AuthReasonTag_Unknown) {
            ovc_stack_abi_str_clear(
                &connection->auth_state.awaiting_auth.reason.unknown_details);
        }
        if (connection->auth_state.awaiting_auth.last_attempt.present &&
            connection->auth_state.awaiting_auth.last_attempt.value.error
                .present) {
            ovc_stack_abi_str_clear(
                &connection->auth_state.awaiting_auth.last_attempt.value.error
                     .value.message);
        }
    } else if (connection->auth_state.tag ==
               OvStoragePlugin_ConnectionAuthStateTag_AuthFailed) {
        ovc_stack_abi_str_clear(
            &connection->auth_state.auth_failed.error_message);
    }
    ovc_stack_abi_key_values_clear(&connection->user_metadata);
    /* add_connection's result payload is a plugin-minted heap Connection. */
    ovc_abi_free(connection);
}

static void ovc_stack_build_slot_discard_connection(
    void *result,
    OvStoragePlugin_Error *error)
{
    ovc_stack_abi_connection_destroy((OvStoragePlugin_Connection *)result);
    ovc_stack_plugin_error_destroy(error);
}

static OvStorage_Status ovc_stack_apply_connection(
    ovc_stack_build_state *build,
    size_t connection_index,
    size_t layer_index,
    OvStorage_Error *out_error)
{
    ovc_stack_connection *recorded;
    OvStoragePlugin_LayerConnectionRequest request;
    OvStoragePlugin_CancelTokenFFI cancel;
    ovc_stack_build_slot *slot;
    void *slot_result;
    OvStoragePlugin_Error *slot_error;
    OvStorage_Status status;

    if (ovc_stack_build_is_canceled(build)) {
        return ovc_stack_error(out_error,
                               OvStorage_Status_Cancelled,
                               "stack build was cancelled");
    }
    recorded = &build->stack->connections[connection_index];
    /* Never serialize a bundle that a previous failed build has wiped. */
    if (recorded->request->credentials.consumed) {
        return ovc_stack_consumed_credentials_error(out_error,
                                                    recorded->target);
    }
    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    if (!ovc_stack_abi_str_copy(&request.target,
                                recorded->target,
                                strlen(recorded->target)) ||
        !ovc_stack_abi_connection_request_copy(&request.connection,
                                               recorded->request)) {
        ovc_stack_abi_str_clear(&request.target);
        ovc_stack_abi_connection_request_clear(&request.connection);
        return ovc_stack_error(out_error,
                               OvStorage_Status_Internal,
                               "out of memory preparing connection for `%s`",
                               recorded->target);
    }
    slot = ovc_stack_build_slot_create(build,
                                      ovc_stack_build_slot_discard_connection);
    if (slot == NULL) {
        ovc_stack_abi_str_clear(&request.target);
        ovc_stack_abi_connection_request_clear(&request.connection);
        return ovc_stack_error(out_error,
                               OvStorage_Status_Internal,
                               "could not initialize connection completion");
    }
    cancel = ovc_stack_build_mint_cancel(build);
    build->handles[layer_index].vtable->add_connection(
        build->handles[layer_index].state,
        &request,
        &cancel,
        ovc_stack_build_slot_complete,
        slot);
    /* Credential hygiene: the builder copy must not retain credential material after handoff. */
    ovc_stack_recorded_bundle_clear(&recorded->request->credentials);
    if (cancel.state != NULL && cancel.drop != NULL) {
        cancel.drop(cancel.state);
    }
    /* The ABI request is moved during the vtable's synchronous prologue. */
    memset(&request, 0, sizeof(request));
    if (ovc_stack_build_slot_settle(slot, build, layer_index, &slot_result,
                                    &slot_error) != OVC_STACK_SLOT_TAKEN) {
        return ovc_stack_error(out_error,
                               OvStorage_Status_Cancelled,
                               "stack build canceled");
    }
    /* Pointer presence is authoritative; legacy status values can collide. */
    if (slot_error == NULL && slot_result != NULL) {
        ovc_stack_abi_connection_destroy(
            (OvStoragePlugin_Connection *)slot_result);
        return OvStorage_Status_Ok;
    }
    if (slot_result != NULL) {
        ovc_stack_abi_connection_destroy(
            (OvStoragePlugin_Connection *)slot_result);
    }
    status = ovc_stack_plugin_failure(out_error,
                                      slot_error,
                                      "add_connection",
                                      recorded->target);
    return status;
}

static OvStorage_Status ovc_stack_apply_layer_connections(
    ovc_stack_build_state *build,
    size_t layer_index,
    OvStorage_Error *out_error)
{
    size_t index;

    for (index = 0; index < build->stack->connection_count; ++index) {
        if (strcmp(build->stack->connections[index].target,
                   build->stack->layers[layer_index].instance_id) == 0) {
            OvStorage_Status status;

            status = ovc_stack_apply_connection(build,
                                                index,
                                                layer_index,
                                                out_error);
            if (status != OvStorage_Status_Ok) {
                return status;
            }
        }
    }
    return OvStorage_Status_Ok;
}

static OvStorage_Status ovc_stack_instantiate_layer(
    ovc_stack_build_state *build,
    size_t index,
    OvStorage_Error *out_error)
{
    ovc_stack_layer *layer;
    OvStoragePlugin_LayerHandle out;
    OvStoragePlugin_Error *plugin_error;
    OvStoragePlugin_FfiStatus ffi_status;
    OvStorage_Status status;

    if (build->owned[index]) {
        return OvStorage_Status_Ok;
    }
    if (ovc_stack_build_is_canceled(build)) {
        return ovc_stack_error(out_error,
                               OvStorage_Status_Cancelled,
                               "stack build was cancelled");
    }
    layer = &build->stack->layers[index];
    memset(&out, 0, sizeof(out));
    plugin_error = NULL;

    /*
     * A completed child handle is still directly callable only until its
     * parent factory takes ownership.  Apply that child's recorded
     * connections at the end of its post-order visit; a router factory can
     * then construct its table from already-populated child roots.  The
     * frozen ABI has no post-create "replace router table" slot.
     */
    if (layer->layer_type == OvStoragePlugin_LayerType_Backend) {
        OvStoragePlugin_CreateBackendRequest request;

        if (!ovc_stack_create_backend_request_init(&request, layer)) {
            return ovc_stack_error(out_error,
                                   OvStorage_Status_Internal,
                                   "out of memory creating layer `%s`",
                                   layer->instance_id);
        }
        ffi_status = layer->factory->plugin_vtable->create_backend(
            layer->factory->plugin_state, &request, &out, &plugin_error);
        /* Factory requests are ownership-moving ABI values. */
        memset(&request, 0, sizeof(request));
    } else if (layer->layer_type == OvStoragePlugin_LayerType_Wrapper) {
        size_t inner_index;
        OvStoragePlugin_CreateWrapperRequest request;

        inner_index = ovc_stack_layer_index(build->stack, layer->inner_id);
        status = ovc_stack_instantiate_layer(build,
                                             inner_index,
                                             out_error);
        if (status != OvStorage_Status_Ok) {
            return status;
        }
        if (!ovc_stack_create_wrapper_request_init(
                &request, layer, build->handles[inner_index])) {
            return ovc_stack_error(out_error,
                                   OvStorage_Status_Internal,
                                   "out of memory creating layer `%s`",
                                   layer->instance_id);
        }
        ffi_status = layer->factory->plugin_vtable->create_wrapper(
            layer->factory->plugin_state, &request, &out, &plugin_error);
        /* The factory owns inner on both success and failure. */
        build->owned[inner_index] = 0;
        memset(&build->handles[inner_index],
               0,
               sizeof(build->handles[inner_index]));
        memset(&request, 0, sizeof(request));
    } else {
        OvStoragePlugin_RouterChild *children;
        OvStoragePlugin_CreateRouterRequest request;
        size_t child_at;

        children = NULL;
        if (layer->child_count != 0) {
            if (layer->child_count > SIZE_MAX / sizeof(*children)) {
                return ovc_stack_error(out_error,
                                       OvStorage_Status_Internal,
                                       "router child count overflow");
            }
            children = (OvStoragePlugin_RouterChild *)calloc(
                layer->child_count, sizeof(*children));
            if (children == NULL) {
                return ovc_stack_error(out_error,
                                       OvStorage_Status_Internal,
                                       "out of memory creating router `%s`",
                                       layer->instance_id);
            }
        }
        for (child_at = 0; child_at < layer->child_count; ++child_at) {
            size_t child_index;

            child_index = ovc_stack_layer_index(
                build->stack, layer->child_ids[child_at]);
            status = ovc_stack_instantiate_layer(build,
                                                 child_index,
                                                 out_error);
            if (status != OvStorage_Status_Ok) {
                free(children);
                return status;
            }
            children[child_at].handle = build->handles[child_index];
        }
        status = ovc_stack_validate_router_roots(build, layer, out_error);
        if (status != OvStorage_Status_Ok) {
            free(children);
            return status;
        }
        memset(&request, 0, sizeof(request));
        request.struct_size = sizeof(request);
        request.children = children;
        request.child_count = layer->child_count;
        if (!ovc_stack_abi_str_copy(&request.kind,
                                    layer->factory->kind.ptr,
                                    layer->factory->kind.len) ||
            !ovc_stack_abi_str_copy(&request.instance_id,
                                    layer->instance_id,
                                    strlen(layer->instance_id)) ||
            !ovc_stack_abi_config_entries_copy(&request.config,
                                               layer->config,
                                               layer->config_len)) {
            ovc_stack_abi_str_clear(&request.kind);
            ovc_stack_abi_str_clear(&request.instance_id);
            ovc_stack_abi_config_list_clear(&request.config);
            free(children);
            return ovc_stack_error(out_error,
                                   OvStorage_Status_Internal,
                                   "out of memory creating router `%s`",
                                   layer->instance_id);
        }
        ffi_status = layer->factory->plugin_vtable->create_router(
            layer->factory->plugin_state, &request, &out, &plugin_error);
        for (child_at = 0; child_at < layer->child_count; ++child_at) {
            size_t child_index;

            child_index = ovc_stack_layer_index(
                build->stack, layer->child_ids[child_at]);
            build->owned[child_index] = 0;
            memset(&build->handles[child_index],
                   0,
                   sizeof(build->handles[child_index]));
        }
        free(children);
        memset(&request, 0, sizeof(request));
    }

    if (ffi_status != OvStoragePlugin_FFI_STATUS_OK ||
        plugin_error != NULL || !ovc_stack_layer_handle_is_valid(&out)) {
        if (ovc_stack_layer_handle_can_drop(&out)) {
            ovc_stack_layer_handle_drop(&out);
        }
        if (plugin_error != NULL ||
            ffi_status != OvStoragePlugin_FFI_STATUS_OK) {
            return ovc_stack_plugin_failure(out_error,
                                            plugin_error,
                                            "factory creation",
                                            layer->instance_id);
        }
        return ovc_stack_error(
            out_error,
            OvStorage_Status_Internal,
            "factory for layer `%s` returned an invalid Layer handle",
            layer->instance_id);
    }
    build->handles[index] = out;
    build->owned[index] = 1;
    status = ovc_stack_apply_layer_connections(build, index, out_error);
    if (status != OvStorage_Status_Ok) {
        return status;
    }
    return OvStorage_Status_Ok;
}

static void ovc_stack_build_unwind(ovc_stack_build_state *build)
{
    size_t index;

    if (build == NULL || build->stack == NULL || build->owned == NULL ||
        build->handles == NULL) {
        return;
    }
    /* Every still-owned entry is a root of a disjoint partial-build tree. */
    for (index = build->stack->layer_count; index != 0; --index) {
        size_t at;

        at = index - 1;
        if (build->owned[at]) {
            ovc_stack_layer_handle_drop(&build->handles[at]);
            build->owned[at] = 0;
        }
    }
}

/*
 * Shared build phase for the blocking and asynchronous entry points.  The
 * caller-thread prologue (argument/options validation and runtime
 * initialization) has already accepted the call, and `out_handle` is
 * non-NULL.  Apart from the layer-count overflow rejection, which returns
 * before any build work starts, every failure below reaches the `done`
 * label and wipes the recorded credentials.  `cancel` is a borrowed
 * plugin-ABI view of the async build's token, or NULL from the blocking
 * entry.  This function blocks on completion latches whose completions
 * the io-task pool dispatches (the built-in file backend submits its work
 * there), so it must run on a caller or dedicated thread — never on a
 * pool worker, which could starve the very completions it waits for.
 */
static OvStorage_Status ovc_stack_build_run(
    OvStorage_Stack *stack,
    const OvStoragePlugin_CancelTokenFFI *cancel,
    OvStorage_LayerHandle **out_handle,
    OvStorage_Error *out_error)
{
    ovc_stack_build_state build;
    ovc_layer_factory **factories;
    OvStorage_LayerHandle *handle;
    OvStorage_Status status;
    size_t root_index;
    size_t index;

    memset(&build, 0, sizeof(build));
    factories = NULL;
    handle = NULL;
    status = OvStorage_Status_Internal;
    root_index = SIZE_MAX;

    *out_handle = NULL;
    if (stack->layer_count > SIZE_MAX / sizeof(*build.handles) ||
        stack->layer_count > SIZE_MAX / sizeof(*factories)) {
        return ovc_stack_error(out_error,
                               OvStorage_Status_Internal,
                               "stack layer count overflow");
    }
    build.stack = stack;
    build.cancel = cancel;
    build.visits = (unsigned char *)calloc(stack->layer_count == 0
                                                ? 1
                                                : stack->layer_count,
                                            sizeof(*build.visits));
    build.owned = (unsigned char *)calloc(stack->layer_count == 0
                                              ? 1
                                              : stack->layer_count,
                                          sizeof(*build.owned));
    build.handles = (OvStoragePlugin_LayerHandle *)calloc(
        stack->layer_count == 0 ? 1 : stack->layer_count,
        sizeof(*build.handles));
    factories = (ovc_layer_factory **)calloc(stack->layer_count == 0
                                                  ? 1
                                                  : stack->layer_count,
                                              sizeof(*factories));
    if (build.visits == NULL || build.owned == NULL ||
        build.handles == NULL || factories == NULL) {
        status = ovc_stack_error(out_error,
                                 OvStorage_Status_Internal,
                                 "out of memory building stack");
        goto done;
    }
    status = ovc_stack_validate_shape(&build, &root_index, out_error);
    if (status != OvStorage_Status_Ok) {
        goto done;
    }
    /* A retry after a failed build must fail loudly, not apply empty bundles. */
    status = ovc_stack_reject_consumed_credentials(stack, out_error);
    if (status != OvStorage_Status_Ok) {
        goto done;
    }
    status = ovc_stack_instantiate_layer(&build,
                                         root_index,
                                         out_error);
    if (status != OvStorage_Status_Ok) {
        goto done;
    }
    for (index = 0; index < stack->layer_count; ++index) {
        factories[index] = stack->layers[index].factory;
    }
    handle = ovc_dispatch_layer_handle_create(build.handles[root_index],
                                              factories,
                                              stack->layer_count);
    if (handle == NULL) {
        status = ovc_stack_error(out_error,
                                 OvStorage_Status_Internal,
                                 "out of memory creating the Stack handle");
        goto done;
    }
    build.owned[root_index] = 0;
    memset(&build.handles[root_index],
           0,
           sizeof(build.handles[root_index]));

done:
    /*
     * Credential hygiene: a build that reached this label may already have handed
     * bundle copies to plugins, so wipe every recorded bundle.  The wipe
     * marks the bundles consumed, which makes a retried build fail loudly
     * in ovc_stack_reject_consumed_credentials instead of applying empty
     * credentials.  Prologue failures return before this label and leave
     * the recorded credentials intact.
     */
    ovc_stack_recorded_credentials_clear(stack);
    if (status != OvStorage_Status_Ok) {
        ovc_stack_build_unwind(&build);
    }
    free(factories);
    free(build.handles);
    free(build.owned);
    free(build.visits);
    if (status == OvStorage_Status_Ok) {
        /* Only the successful commit consumes the caller's builder. */
        ovstorage_stack_destroy(stack);
        *out_handle = handle;
        ovc_stack_success(out_error);
    }
    return status;
}

OvStorage_Status ovstorage_stack_build(
    OvStorage_Stack *stack,
    const OvStorage_StackBuildOptions *options,
    OvStorage_LayerHandle **out_handle,
    OvStorage_Error *out_error)
{
    uint32_t runtime_threads;

    runtime_threads = 0;

    /*
     * Prologue rejections return before any build work starts and must not
     * touch the recorded builder state: on error the caller still owns the
     * Stack, and a retry must see its credentials intact.
     */
    if (stack == NULL) {
        return ovc_stack_error(out_error,
                               OvStorage_Status_InvalidArgument,
                               "stack must not be null");
    }
    if (out_handle == NULL) {
        return ovc_stack_error(out_error,
                               OvStorage_Status_InvalidArgument,
                               "out_handle must not be null");
    }
    *out_handle = NULL;
    if (options != NULL) {
        runtime_threads = options->runtime_threads;
    }
    if (ovc_runtime_ensure(runtime_threads) != 0) {
        return ovc_stack_error(out_error,
                               OvStorage_Status_Internal,
                               "could not initialize the process-global runtime");
    }
    /*
     * The blocking adapter drives the shared build phase to completion on
     * the caller's thread.  That thread is never an io-pool worker, so the
     * completion-latch waits inside the build cannot starve the pool.
     */
    return ovc_stack_build_run(stack, NULL, out_handle, out_error);
}

/*
 * Context for one in-flight ovstorage_stack_build_async call.  The build
 * thread owns it outright: `stack` stays caller-owned but must not be
 * touched until `on_complete` fires (public contract), and `cancel` holds
 * one reference to the token state minted during the public call, so the
 * caller may destroy its token wrapper as soon as that call returns.
 */
typedef struct ovc_stack_async_build {
    OvStorage_Stack *stack;
    OvStoragePlugin_CancelTokenFFI cancel;
    OvStorage_StackBuildCallback on_complete;
    void *user_data;
} ovc_stack_async_build;

/* Same joinable-to-detached handoff runtime.c applies to its workers. */
static int ovc_stack_thread_detach(ovc_thread *thread)
{
    if (thread == NULL || !thread->joinable) {
        return EINVAL;
    }

#if defined(_WIN32)
    if (!CloseHandle(thread->handle)) {
        return (int)GetLastError();
    }
    thread->handle = NULL;
    thread->joinable = 0;
    return 0;
#else
    {
        int result;

        result = pthread_detach(thread->handle);
        if (result == 0) {
            thread->joinable = 0;
        }
        return result;
    }
#endif
}

/*
 * Fire a prologue rejection inline on the caller's thread.  The error is
 * borrowed by the callback and released when it returns; the builder is
 * never touched (recorded credentials included), so the caller can fix
 * the rejected argument and call again.
 */
static void ovc_stack_async_reject(OvStorage_StackBuildCallback on_complete,
                                   void *user_data,
                                   OvStorage_Status status,
                                   const char *message)
{
    OvStorage_Error error;

    memset(&error, 0, sizeof(error));
    (void)ovc_stack_error(&error, status, "%s", message);
    on_complete(status, NULL, &error, user_data);
    ovstorage_error_clear(&error);
}

/*
 * Dedicated per-build thread body.  The shared build phase blocks on
 * completion latches that the io-task pool completes, so it must not run
 * on a pool worker (see ovc_stack_build_run); a detached thread keeps the
 * pool non-blocking, exactly like the dedicated stream-pump threads.
 */
static void ovc_stack_async_build_main(void *argument)
{
    ovc_stack_async_build *task;
    OvStorage_LayerHandle *handle;
    OvStorage_Error error;
    OvStorage_Status status;

    task = (ovc_stack_async_build *)argument;
    handle = NULL;
    memset(&error, 0, sizeof(error));
    if (task->cancel.is_canceled(task->cancel.state)) {
        /*
         * Pre-build cancellation is biased ahead of the build: no build
         * work has started, so the builder — recorded credentials
         * included — stays fully intact.
         */
        status = ovc_stack_error(&error,
                                 OvStorage_Status_Cancelled,
                                 "stack build was cancelled");
    } else {
        status = ovc_stack_build_run(task->stack,
                                     &task->cancel,
                                     &handle,
                                     &error);
    }
    if (status == OvStorage_Status_Ok) {
        /* The build phase consumed the builder before this fire; the
         * callback receives the owned root handle. */
        task->on_complete(OvStorage_Status_Ok,
                          handle,
                          NULL,
                          task->user_data);
    } else {
        /* The error is borrowed by the callback and released after it
         * returns; the caller still owns the (intact) builder. */
        task->on_complete(status, NULL, &error, task->user_data);
    }
    ovstorage_error_clear(&error);
    task->cancel.drop(task->cancel.state);
    free(task);
}

void ovstorage_stack_build_async(OvStorage_Stack *stack,
                                 const OvStorage_StackBuildOptions *options,
                                 const OvStorage_CancelToken *cancel,
                                 OvStorage_StackBuildCallback on_complete,
                                 void *user_data)
{
    ovc_stack_async_build *task;
    ovc_thread thread;
    uint32_t runtime_threads;

    if (on_complete == NULL) {
        return;
    }
    runtime_threads = 0;

    /*
     * Prologue: validate on the caller thread.  Every rejection here fires
     * the callback inline and leaves the builder untouched; ownership of
     * `stack` is only consumed by a successful build.  The root check
     * joins the prologue — unlike the blocking entry, where an unset root
     * is a build-phase failure — so the async contract's prologue-error
     * list in ovstorage.h holds and a rejected builder stays reusable.
     */
    if (stack == NULL) {
        ovc_stack_async_reject(on_complete,
                               user_data,
                               OvStorage_Status_InvalidArgument,
                               "stack must not be null");
        return;
    }
    if (options != NULL) {
        runtime_threads = options->runtime_threads;
    }
    if (ovc_runtime_ensure(runtime_threads) != 0) {
        ovc_stack_async_reject(
            on_complete,
            user_data,
            OvStorage_Status_Internal,
            "could not initialize the process-global runtime");
        return;
    }
    if (stack->root_id == NULL) {
        ovc_stack_async_reject(
            on_complete,
            user_data,
            OvStorage_Status_InvalidArgument,
            "stack root not set; call ovstorage_stack_set_root before build");
        return;
    }
    task = (ovc_stack_async_build *)malloc(sizeof(*task));
    if (task == NULL) {
        ovc_stack_async_reject(on_complete,
                               user_data,
                               OvStorage_Status_Internal,
                               "out of memory starting the stack build");
        return;
    }
    task->stack = stack;
    /* Minting retains the token state in the prologue, so the caller's
     * token only has to outlive this call, not the whole build. */
    task->cancel = ovc_cancel_token_mint(cancel);
    task->on_complete = on_complete;
    task->user_data = user_data;
    if (ovc_thread_create(&thread,
                          ovc_stack_async_build_main,
                          task) != 0) {
        task->cancel.drop(task->cancel.state);
        free(task);
        ovc_stack_async_reject(on_complete,
                               user_data,
                               OvStorage_Status_Internal,
                               "could not start the stack build thread");
        return;
    }
    if (ovc_stack_thread_detach(&thread) != 0) {
        /* A successfully-created thread is necessarily joinable here, so
         * treat this handle-state failure like runtime.c's detach. */
        abort();
    }
}

#if defined(OVC_STACK_TEST_MAIN)

#include <assert.h>

#if defined(NDEBUG)
#error "OVC_STACK_TEST_MAIN requires assertions to be enabled"
#endif

static char g_ovc_stack_test_backend_kind[] = "stack-test-backend";
static char g_ovc_stack_test_backend_name[] = "Stack test backend";
static char g_ovc_stack_test_wrapper_kind[] = "stack-test-wrapper";
static char g_ovc_stack_test_wrapper_name[] = "Stack test wrapper";
static char g_ovc_stack_test_router_kind[] = "stack-test-router";
static char g_ovc_stack_test_router_name[] = "Stack test router";

static void ovc_stack_test_factory_drop(void *plugin_state)
{
    (void)plugin_state;
}

static OvStoragePlugin_FfiStatus ovc_stack_test_create_backend(
    void *plugin_state,
    const OvStoragePlugin_CreateBackendRequest *request,
    OvStoragePlugin_LayerHandle *out,
    OvStoragePlugin_Error **error)
{
    (void)plugin_state;
    (void)request;
    (void)out;
    (void)error;
    return OvStoragePlugin_FFI_STATUS_ERR;
}

static OvStoragePlugin_FfiStatus ovc_stack_test_create_wrapper(
    void *plugin_state,
    const OvStoragePlugin_CreateWrapperRequest *request,
    OvStoragePlugin_LayerHandle *out,
    OvStoragePlugin_Error **error)
{
    (void)plugin_state;
    (void)request;
    (void)out;
    (void)error;
    return OvStoragePlugin_FFI_STATUS_ERR;
}

static OvStoragePlugin_FfiStatus ovc_stack_test_create_router(
    void *plugin_state,
    const OvStoragePlugin_CreateRouterRequest *request,
    OvStoragePlugin_LayerHandle *out,
    OvStoragePlugin_Error **error)
{
    (void)plugin_state;
    (void)request;
    (void)out;
    (void)error;
    return OvStoragePlugin_FFI_STATUS_ERR;
}

static const OvStoragePlugin_PluginVTableV1 g_ovc_stack_test_vtable = {
    .struct_size = sizeof(OvStoragePlugin_PluginVTableV1),
    .abi_version = OVSTORAGE_PLUGIN_ABI_VERSION,
    .drop = ovc_stack_test_factory_drop,
    .create_backend = ovc_stack_test_create_backend,
    .create_wrapper = ovc_stack_test_create_wrapper,
    .create_router = ovc_stack_test_create_router,
};

static const OvStoragePlugin_LayerKindDescriptor
    g_ovc_stack_test_backend_descriptor = {
        .struct_size = sizeof(OvStoragePlugin_LayerKindDescriptor),
        .layer_type = OvStoragePlugin_LayerType_Backend,
        .accepts_connections = true,
        .kind = {g_ovc_stack_test_backend_kind,
                 sizeof(g_ovc_stack_test_backend_kind) - 1},
        .display_name = {g_ovc_stack_test_backend_name,
                         sizeof(g_ovc_stack_test_backend_name) - 1},
        .auth_capable = false,
};

static const OvStoragePlugin_LayerKindDescriptor
    g_ovc_stack_test_wrapper_descriptor = {
        .struct_size = sizeof(OvStoragePlugin_LayerKindDescriptor),
        .layer_type = OvStoragePlugin_LayerType_Wrapper,
        .accepts_connections = false,
        .kind = {g_ovc_stack_test_wrapper_kind,
                 sizeof(g_ovc_stack_test_wrapper_kind) - 1},
        .display_name = {g_ovc_stack_test_wrapper_name,
                         sizeof(g_ovc_stack_test_wrapper_name) - 1},
        .auth_capable = false,
};

static const OvStoragePlugin_LayerKindDescriptor
    g_ovc_stack_test_router_descriptor = {
        .struct_size = sizeof(OvStoragePlugin_LayerKindDescriptor),
        .layer_type = OvStoragePlugin_LayerType_Router,
        .accepts_connections = false,
        .kind = {g_ovc_stack_test_router_kind,
                 sizeof(g_ovc_stack_test_router_kind) - 1},
        .display_name = {g_ovc_stack_test_router_name,
                         sizeof(g_ovc_stack_test_router_name) - 1},
        .auth_capable = false,
};

/* Same kind as the backend descriptor, but a different provider/type. */
static const OvStoragePlugin_LayerKindDescriptor
    g_ovc_stack_test_replacement_descriptor = {
        .struct_size = sizeof(OvStoragePlugin_LayerKindDescriptor),
        .layer_type = OvStoragePlugin_LayerType_Wrapper,
        .accepts_connections = false,
        .kind = {g_ovc_stack_test_backend_kind,
                 sizeof(g_ovc_stack_test_backend_kind) - 1},
        .display_name = {g_ovc_stack_test_wrapper_name,
                         sizeof(g_ovc_stack_test_wrapper_name) - 1},
        .auth_capable = false,
};

OvStorage_Status ovstorage_c_register_builtin_kinds(
    OvStorage_Registry *registry,
    OvStorage_Error *out_error)
{
    OvStorage_Status status;

    status = ovc_registry_register_builtin_kind(
        registry,
        &g_ovc_stack_test_backend_descriptor,
        NULL,
        &g_ovc_stack_test_vtable,
        out_error);
    if (status != OvStorage_Status_Ok) {
        return status;
    }
    status = ovc_registry_register_builtin_kind(
        registry,
        &g_ovc_stack_test_wrapper_descriptor,
        NULL,
        &g_ovc_stack_test_vtable,
        out_error);
    if (status != OvStorage_Status_Ok) {
        return status;
    }
    return ovc_registry_register_builtin_kind(
        registry,
        &g_ovc_stack_test_router_descriptor,
        NULL,
        &g_ovc_stack_test_vtable,
        out_error);
}

static void ovc_stack_test_expect_error(OvStorage_Status actual,
                                        OvStorage_Status expected,
                                        const OvStorage_Error *error,
                                        const char *message_part)
{
    assert(actual == expected);
    assert(error->code == expected);
    assert(error->message != NULL);
    assert(strstr(error->message, message_part) != NULL);
}

static void ovc_stack_test_expect_success(OvStorage_Status actual,
                                          const OvStorage_Error *error)
{
    assert(actual == OvStorage_Status_Ok);
    assert(error->code == OvStorage_Status_Ok);
    assert(error->message == NULL);
}

static void ovc_stack_test_layers_and_edges(void)
{
    static const char invalid_utf8[] = "\xC0\xAF";
    const char *children[2];
    const char *invalid_children[1];
    const char *self_child[1];
    long retained_backend_references;
    ovc_layer_factory *backend_factory;
    OvStorage_ConfigValue *config_value;
    OvStoragePlugin_List_ConnectionConfigEntry abi_config;
    ovc_stack_layer *router;
    ovc_stack_layer *wrapper;
    OvStorage_Error error;
    OvStorage_Registry *override_registry;
    OvStorage_Registry *registry;
    OvStorage_Stack *stack;
    size_t layer_count;

    memset(&error, 0, sizeof(error));
    registry = ovstorage_registry_create();
    override_registry = ovstorage_registry_create();
    stack = ovstorage_stack_create();
    assert(registry != NULL);
    assert(override_registry != NULL);
    assert(stack != NULL);

    ovc_stack_test_expect_error(
        ovstorage_stack_add_layer(stack,
                                  registry,
                                  "unknown-kind-layer",
                                  "unknown-kind",
                                  &error),
        OvStorage_Status_InvalidArgument,
        &error,
        "no factory registered");
    ovc_stack_test_expect_error(
        ovstorage_stack_add_layer(stack,
                                  registry,
                                  invalid_utf8,
                                  g_ovc_stack_test_backend_kind,
                                  &error),
        OvStorage_Status_InvalidArgument,
        &error,
        "instance_id is not valid UTF-8");
    ovc_stack_test_expect_error(
        ovstorage_stack_add_layer(stack,
                                  registry,
                                  "invalid-kind-layer",
                                  invalid_utf8,
                                  &error),
        OvStorage_Status_InvalidArgument,
        &error,
        "kind is not valid UTF-8");

    ovc_stack_test_expect_success(
        ovstorage_stack_add_layer(stack,
                                  registry,
                                  "backend-a",
                                  g_ovc_stack_test_backend_kind,
                                  &error),
        &error);
    ovc_stack_test_expect_success(
        ovstorage_stack_add_layer(stack,
                                  registry,
                                  "backend-b",
                                  g_ovc_stack_test_backend_kind,
                                  &error),
        &error);
    ovc_stack_test_expect_success(
        ovstorage_stack_add_layer(stack,
                                  registry,
                                  "wrapper",
                                  g_ovc_stack_test_wrapper_kind,
                                  &error),
        &error);
    ovc_stack_test_expect_success(
        ovstorage_stack_add_layer(stack,
                                  registry,
                                  "router",
                                  g_ovc_stack_test_router_kind,
                                  &error),
        &error);
    config_value = ovstorage_config_value_create_string("first");
    assert(config_value != NULL);
    ovc_stack_test_expect_error(
        ovstorage_stack_add_layer_config(stack,
                                         "missing",
                                         "mode",
                                         config_value,
                                         &error),
        OvStorage_Status_InvalidArgument,
        &error,
        "no layer named");
    assert(strcmp(ovstorage_config_value_as_string(config_value),
                  "first") == 0);
    ovc_stack_test_expect_success(
        ovstorage_stack_add_layer_config(stack,
                                         "wrapper",
                                         "mode",
                                         config_value,
                                         &error),
        &error);
    config_value = ovstorage_config_value_create_int(42);
    assert(config_value != NULL);
    ovc_stack_test_expect_success(
        ovstorage_stack_add_layer_config(stack,
                                         "wrapper",
                                         "mode",
                                         config_value,
                                         &error),
        &error);
    wrapper = ovc_stack_find_layer(stack, "wrapper");
    assert(wrapper != NULL);
    assert(wrapper->config_len == 1);
    assert(strcmp(wrapper->config[0].key, "mode") == 0);
    assert(ovstorage_config_value_kind(wrapper->config[0].value) ==
           OvStorage_ConfigValueKind_Int);
    assert(ovstorage_config_value_as_int(wrapper->config[0].value) == 42);
    assert(ovc_stack_abi_config_entries_copy(&abi_config,
                                             wrapper->config,
                                             wrapper->config_len));
    assert(abi_config.len == 1);
    assert(abi_config.ptr[0].value.tag ==
           OvStoragePlugin_ConfigValueTag_Int);
    assert(abi_config.ptr[0].value.int_value == 42);
    ovc_stack_abi_config_list_clear(&abi_config);
    ovc_stack_test_expect_success(
        ovc_registry_register_builtin_kind(
            override_registry,
            &g_ovc_stack_test_replacement_descriptor,
            NULL,
            &g_ovc_stack_test_vtable,
            &error),
        &error);
    ovc_stack_test_expect_success(
        ovstorage_stack_add_layer(stack,
                                  override_registry,
                                  "same-kind-wrapper",
                                  g_ovc_stack_test_backend_kind,
                                  &error),
        &error);
    ovstorage_registry_destroy(override_registry);
    layer_count = stack->layer_count;
    ovc_stack_test_expect_error(
        ovstorage_stack_add_layer(stack,
                                  registry,
                                  "backend-a",
                                  g_ovc_stack_test_backend_kind,
                                  &error),
        OvStorage_Status_AlreadyExists,
        &error,
        "already declared");
    assert(stack->layer_count == layer_count);
    assert(stack->layer_count == 5);
    assert(stack->layer_capacity >= stack->layer_count);
    assert(stack->layers[0].layer_type ==
           OvStoragePlugin_LayerType_Backend);
    assert(stack->layers[2].layer_type ==
           OvStoragePlugin_LayerType_Wrapper);
    assert(stack->layers[3].layer_type ==
           OvStoragePlugin_LayerType_Router);
    assert(stack->layers[4].layer_type ==
           OvStoragePlugin_LayerType_Wrapper);

    backend_factory = stack->layers[0].factory;
    assert(stack->layers[1].factory == backend_factory);
    assert(stack->layers[4].factory == backend_factory);
    retained_backend_references = backend_factory->references.value;
    assert(retained_backend_references == 4);
    ovstorage_registry_destroy(registry);
    assert(backend_factory->references.value ==
           retained_backend_references - 1);

    ovc_stack_test_expect_error(
        ovstorage_stack_set_root(stack, "missing", &error),
        OvStorage_Status_InvalidArgument,
        &error,
        "no layer named `missing`");
    ovc_stack_test_expect_error(
        ovstorage_stack_set_root(stack, invalid_utf8, &error),
        OvStorage_Status_InvalidArgument,
        &error,
        "instance_id is not valid UTF-8");
    ovc_stack_test_expect_success(
        ovstorage_stack_set_root(stack, "backend-a", &error),
        &error);
    assert(strcmp(stack->root_id, "backend-a") == 0);
    ovc_stack_test_expect_success(
        ovstorage_stack_set_root(stack, "router", &error),
        &error);
    assert(strcmp(stack->root_id, "router") == 0);

    ovc_stack_test_expect_error(
        ovstorage_stack_set_inner(stack, "wrapper", "missing", &error),
        OvStorage_Status_InvalidArgument,
        &error,
        "no layer named `missing`");
    ovc_stack_test_expect_error(
        ovstorage_stack_set_inner(stack,
                                  "backend-a",
                                  "backend-b",
                                  &error),
        OvStorage_Status_InvalidArgument,
        &error,
        "not a Wrapper layer");
    ovc_stack_test_expect_success(
        ovstorage_stack_set_inner(stack, "wrapper", "backend-a", &error),
        &error);
    wrapper = ovc_stack_find_layer(stack, "wrapper");
    assert(wrapper != NULL);
    assert(strcmp(wrapper->inner_id, "backend-a") == 0);
    /* A self-cycle is recorded; whole-graph validation belongs to build. */
    ovc_stack_test_expect_success(
        ovstorage_stack_set_inner(stack, "wrapper", "wrapper", &error),
        &error);
    assert(strcmp(wrapper->inner_id, "wrapper") == 0);
    ovc_stack_test_expect_success(
        ovstorage_stack_set_inner(stack, "wrapper", "backend-b", &error),
        &error);
    assert(strcmp(wrapper->inner_id, "backend-b") == 0);

    ovc_stack_test_expect_error(
        ovstorage_stack_set_children(stack,
                                     "router",
                                     NULL,
                                     1,
                                     &error),
        OvStorage_Status_InvalidArgument,
        &error,
        "child_ids must not be null");
    children[0] = "backend-a";
    children[1] = "wrapper";
    ovc_stack_test_expect_error(
        ovstorage_stack_set_children(stack,
                                     "backend-a",
                                     children,
                                     2,
                                     &error),
        OvStorage_Status_InvalidArgument,
        &error,
        "not a Router layer");
    ovc_stack_test_expect_success(
        ovstorage_stack_set_children(stack, "router", NULL, 0, &error),
        &error);
    router = ovc_stack_find_layer(stack, "router");
    assert(router != NULL);
    assert(router->child_ids == NULL);
    assert(router->child_count == 0);
    ovc_stack_test_expect_success(
        ovstorage_stack_set_children(stack,
                                     "router",
                                     children,
                                     2,
                                     &error),
        &error);
    assert(router->child_count == 2);
    assert(strcmp(router->child_ids[0], "backend-a") == 0);
    assert(strcmp(router->child_ids[1], "wrapper") == 0);

    invalid_children[0] = "missing";
    ovc_stack_test_expect_error(
        ovstorage_stack_set_children(stack,
                                     "router",
                                     invalid_children,
                                     1,
                                     &error),
        OvStorage_Status_InvalidArgument,
        &error,
        "no layer named `missing`");
    assert(router->child_count == 2);
    assert(strcmp(router->child_ids[0], "backend-a") == 0);
    invalid_children[0] = invalid_utf8;
    ovc_stack_test_expect_error(
        ovstorage_stack_set_children(stack,
                                     "router",
                                     invalid_children,
                                     1,
                                     &error),
        OvStorage_Status_InvalidArgument,
        &error,
        "child_id is not valid UTF-8");
    assert(router->child_count == 2);

    self_child[0] = "router";
    ovc_stack_test_expect_success(
        ovstorage_stack_set_children(stack,
                                     "router",
                                     self_child,
                                     1,
                                     &error),
        &error);
    assert(router->child_count == 1);
    assert(strcmp(router->child_ids[0], "router") == 0);

    ovstorage_error_clear(&error);
    ovstorage_stack_destroy(stack);
    ovstorage_stack_destroy(NULL);
}

static void ovc_stack_test_connection_ownership(void)
{
    static const char invalid_utf8[] = "\xED\xA0\x80";
    static const uint8_t secret_bytes[] = {1, 2, 3, 4};
    OvStorage_ConfigValue *config;
    OvStorage_ConnectionRequest *caller_owned;
    OvStorage_ConnectionRequest *request;
    OvStorage_Error error;
    OvStorage_Registry *registry;
    OvStorage_SecretValue *secret;
    OvStorage_Stack *stack;
    char target[] = "backend";
    size_t index;

    memset(&error, 0, sizeof(error));
    registry = ovstorage_registry_create();
    stack = ovstorage_stack_create();
    assert(registry != NULL);
    assert(stack != NULL);
    ovc_stack_test_expect_success(
        ovstorage_stack_add_layer(stack,
                                  registry,
                                  "backend",
                                  g_ovc_stack_test_backend_kind,
                                  &error),
        &error);
    ovc_stack_test_expect_success(
        ovstorage_stack_add_layer(stack,
                                  registry,
                                  "wrapper",
                                  g_ovc_stack_test_wrapper_kind,
                                  &error),
        &error);
    ovstorage_registry_destroy(registry);

    caller_owned = ovstorage_connection_request_create("file");
    assert(caller_owned != NULL);
    ovc_stack_test_expect_error(
        ovstorage_stack_add_connection(NULL,
                                       "backend",
                                       &caller_owned,
                                       &error),
        OvStorage_Status_InvalidArgument,
        &error,
        "stack must not be null");
    /* Declined: the slot still holds the request, so the caller frees it. */
    assert(caller_owned != NULL);
    assert(!caller_owned->consumed);
    ovstorage_connection_request_destroy(caller_owned);

    caller_owned = ovstorage_connection_request_create("file");
    assert(caller_owned != NULL);
    ovc_stack_test_expect_error(
        ovstorage_stack_add_connection(stack, NULL, &caller_owned, &error),
        OvStorage_Status_InvalidArgument,
        &error,
        "target must not be null");
    assert(caller_owned != NULL);
    assert(!caller_owned->consumed);
    ovstorage_connection_request_destroy(caller_owned);

    caller_owned = ovstorage_connection_request_create("file");
    assert(caller_owned != NULL);
    assert(ovc_connection_request_mark_consumed(caller_owned));
    ovc_stack_test_expect_error(
        ovstorage_stack_add_connection(stack,
                                       "backend",
                                       &caller_owned,
                                       &error),
        OvStorage_Status_InvalidArgument,
        &error,
        "already consumed");
    assert(stack->connection_count == 0);
    assert(caller_owned != NULL);
    ovstorage_connection_request_destroy(caller_owned);

    request = ovstorage_connection_request_create("file");
    assert(request != NULL);
    config = ovstorage_config_value_create_string("file:/tmp");
    secret = ovstorage_secret_value_create_bytes(secret_bytes,
                                                  sizeof(secret_bytes));
    assert(config != NULL);
    assert(secret != NULL);
    assert(ovstorage_connection_request_add_config(request,
                                                   "root",
                                                   config));
    assert(ovstorage_connection_request_add_credential(request,
                                                       "token",
                                                       secret));
    ovc_stack_test_expect_error(
        ovstorage_stack_add_connection(stack,
                                       "missing",
                                       &request,
                                       &error),
        OvStorage_Status_InvalidArgument,
        &error,
        "no layer named `missing`");
    assert(request != NULL);
    assert(!request->consumed);
    ovstorage_connection_request_set_persist(request, true);
    assert(request->persist);
    ovc_stack_test_expect_error(
        ovstorage_stack_add_connection(stack,
                                       invalid_utf8,
                                       &request,
                                       &error),
        OvStorage_Status_InvalidArgument,
        &error,
        "target is not valid UTF-8");
    assert(request != NULL);
    assert(!request->consumed);
    ovc_stack_test_expect_error(
        ovstorage_stack_add_connection(stack, "backend", NULL, &error),
        OvStorage_Status_InvalidArgument,
        &error,
        "request must not be null");
    assert(request != NULL);
    assert(!request->consumed);

    ovc_stack_test_expect_success(
        ovstorage_stack_add_connection(stack,
                                       target,
                                       &request,
                                       &error),
        &error);
    assert(stack->connection_count == 1);
    assert(stack->connections[0].request != NULL);
    assert(stack->connections[0].request->consumed);
    target[0] = 'X';
    assert(strcmp(stack->connections[0].target, "backend") == 0);
    /* Taken: the slot is cleared, so the same cleanup call is a no-op. */
    assert(request == NULL);
    ovstorage_connection_request_destroy(request);

    /* accepts_connections is enforced by the Layer, not by recording. */
    request = ovstorage_connection_request_create("alias");
    assert(request != NULL);
    ovc_stack_test_expect_success(
        ovstorage_stack_add_connection(stack,
                                       "wrapper",
                                       &request,
                                       &error),
        &error);
    assert(stack->connection_count == 2);
    assert(stack->connections[1].request != NULL);
    assert(stack->connections[1].request->consumed);
    assert(request == NULL);

    for (index = 0; index < 3; ++index) {
        request = ovstorage_connection_request_create("file");
        assert(request != NULL);
        ovc_stack_test_expect_success(
            ovstorage_stack_add_connection(stack,
                                           "wrapper",
                                           &request,
                                           &error),
            &error);
        assert(request == NULL);
    }
    assert(stack->connection_count == 5);
    assert(stack->connection_capacity >= stack->connection_count);

    ovstorage_error_clear(&error);
    /* Stack destruction owns all successfully handed-off requests. */
    ovstorage_stack_destroy(stack);
}

static void ovc_stack_test_add_credentialed_connection(
    OvStorage_Stack *stack,
    const char *target,
    OvStorage_Error *error)
{
    static const uint8_t credential_bytes[] = {9, 8, 7, 6};
    OvStorage_ConnectionRequest *request;
    OvStorage_SecretValue *credential;

    request = ovstorage_connection_request_create("file");
    credential = ovstorage_secret_value_create_bytes(
        credential_bytes, sizeof(credential_bytes));
    assert(request != NULL);
    assert(credential != NULL);
    assert(ovstorage_connection_request_add_credential(request,
                                                       "token",
                                                       credential));
    ovc_stack_test_expect_success(
        ovstorage_stack_add_connection(stack, target, &request, error),
        error);
}

static void ovc_stack_test_assert_credentials_intact(
    const OvStorage_Stack *stack)
{
    assert(stack->connections[0].request != NULL);
    assert(stack->connections[0].request->credentials.entries != NULL);
    assert(stack->connections[0].request->credentials.len == 1);
    assert(!stack->connections[0].request->credentials.consumed);
    assert(strcmp(stack->connections[0].request->credentials.entries[0].key,
                  "token") == 0);
}

static void ovc_stack_test_assert_credentials_wiped(
    const OvStorage_Stack *stack)
{
    assert(stack->connections[0].request != NULL);
    assert(stack->connections[0].request->credentials.entries == NULL);
    assert(stack->connections[0].request->credentials.len == 0);
    assert(stack->connections[0].request->credentials.capacity == 0);
    assert(stack->connections[0].request->credentials.consumed);
}

static void ovc_stack_test_failed_build_retains_and_zeros(void)
{
    OvStorage_Error error;
    OvStorage_LayerHandle *handle;
    OvStorage_Registry *registry;
    OvStorage_Stack *stack;
    OvStorage_StackBuildOptions default_options;

    memset(&error, 0, sizeof(error));
    registry = ovstorage_registry_create();
    stack = ovstorage_stack_create();
    assert(registry != NULL);
    assert(stack != NULL);
    ovc_stack_test_expect_success(
        ovstorage_stack_add_layer(stack,
                                  registry,
                                  "root",
                                  g_ovc_stack_test_backend_kind,
                                  &error),
        &error);
    ovc_stack_test_expect_success(
        ovstorage_stack_add_layer(stack,
                                  registry,
                                  "orphan",
                                  g_ovc_stack_test_backend_kind,
                                  &error),
        &error);
    ovc_stack_test_expect_success(
        ovstorage_stack_set_root(stack, "root", &error), &error);
    ovc_stack_test_add_credentialed_connection(stack, "root", &error);

    /* Prologue failures must leave the recorded credentials untouched. */
    ovc_stack_test_expect_error(
        ovstorage_stack_build(stack, NULL, NULL, &error),
        OvStorage_Status_InvalidArgument,
        &error,
        "out_handle must not be null");
    ovc_stack_test_assert_credentials_intact(stack);

    /* A build-phase failure wipes and poisons the recorded credentials. */
    handle = (OvStorage_LayerHandle *)(uintptr_t)1;
    ovc_stack_test_expect_error(
        ovstorage_stack_build(stack, NULL, &handle, &error),
        OvStorage_Status_InvalidArgument,
        &error,
        "unreachable");
    assert(handle == NULL);
    assert(stack->layer_count == 2);
    assert(stack->connection_count == 1);
    ovc_stack_test_assert_credentials_wiped(stack);

    /*
     * A zero-initialized options struct asks for defaults and is accepted:
     * the call clears the prologue and fails on the unreachable layer, the
     * same way `options == NULL` does.  Any prologue rejection would report
     * a different message here.
     */
    memset(&default_options, 0, sizeof(default_options));
    handle = (OvStorage_LayerHandle *)(uintptr_t)1;
    ovc_stack_test_expect_error(
        ovstorage_stack_build(stack, &default_options, &handle, &error),
        OvStorage_Status_InvalidArgument,
        &error,
        "unreachable");
    assert(handle == NULL);

    ovstorage_error_clear(&error);
    ovstorage_registry_destroy(registry);
    ovstorage_stack_destroy(stack);
}

static void ovc_stack_test_failed_build_retry_fails_loudly(void)
{
    OvStorage_Error error;
    OvStorage_LayerHandle *handle;
    OvStorage_Registry *registry;
    OvStorage_Stack *stack;

    memset(&error, 0, sizeof(error));
    registry = ovstorage_registry_create();
    stack = ovstorage_stack_create();
    assert(registry != NULL);
    assert(stack != NULL);
    ovc_stack_test_expect_success(
        ovstorage_stack_add_layer(stack,
                                  registry,
                                  "root",
                                  g_ovc_stack_test_backend_kind,
                                  &error),
        &error);
    ovc_stack_test_expect_success(
        ovstorage_stack_set_root(stack, "root", &error), &error);
    ovc_stack_test_add_credentialed_connection(stack, "root", &error);

    /* Shape-valid build fails in the build phase (the factory errors). */
    handle = (OvStorage_LayerHandle *)(uintptr_t)1;
    ovc_stack_test_expect_error(
        ovstorage_stack_build(stack, NULL, &handle, &error),
        OvStorage_Status_Internal,
        &error,
        "factory creation");
    assert(handle == NULL);
    ovc_stack_test_assert_credentials_wiped(stack);

    /* The contract-permitted retry must fail loudly, not apply an empty
     * bundle. */
    handle = (OvStorage_LayerHandle *)(uintptr_t)1;
    ovc_stack_test_expect_error(
        ovstorage_stack_build(stack, NULL, &handle, &error),
        OvStorage_Status_InvalidArgument,
        &error,
        "consumed by a failed build");
    assert(handle == NULL);
    ovc_stack_test_assert_credentials_wiped(stack);

    ovstorage_error_clear(&error);
    ovstorage_registry_destroy(registry);
    ovstorage_stack_destroy(stack);
}

/* A connection that never carried credentials must not be poisoned by a
 * failed build: its empty bundle re-serializes identically, so the retry
 * reaches the build phase again (and fails there, not with the consumed
 * rejection). */
static void ovc_stack_test_config_only_connection_survives_retry(void)
{
    OvStorage_Error error;
    OvStorage_LayerHandle *handle;
    OvStorage_Registry *registry;
    OvStorage_Stack *stack;
    OvStorage_ConnectionRequest *request;

    memset(&error, 0, sizeof(error));
    registry = ovstorage_registry_create();
    stack = ovstorage_stack_create();
    assert(registry != NULL);
    assert(stack != NULL);
    ovc_stack_test_expect_success(
        ovstorage_stack_add_layer(stack,
                                  registry,
                                  "root",
                                  g_ovc_stack_test_backend_kind,
                                  &error),
        &error);
    ovc_stack_test_expect_success(
        ovstorage_stack_set_root(stack, "root", &error), &error);
    request = ovstorage_connection_request_create(
        g_ovc_stack_test_backend_kind);
    assert(request != NULL);
    ovc_stack_test_expect_success(
        ovstorage_stack_add_connection(stack, "root", &request, &error),
        &error);
    request = NULL;

    /* Two consecutive build-phase failures: the second must be the same
     * factory error, proving the empty bundle was not marked consumed. */
    handle = (OvStorage_LayerHandle *)(uintptr_t)1;
    ovc_stack_test_expect_error(
        ovstorage_stack_build(stack, NULL, &handle, &error),
        OvStorage_Status_Internal,
        &error,
        "factory creation");
    assert(handle == NULL);
    handle = (OvStorage_LayerHandle *)(uintptr_t)1;
    ovc_stack_test_expect_error(
        ovstorage_stack_build(stack, NULL, &handle, &error),
        OvStorage_Status_Internal,
        &error,
        "factory creation");
    assert(handle == NULL);

    ovstorage_error_clear(&error);
    ovstorage_registry_destroy(registry);
    ovstorage_stack_destroy(stack);
}

int main(void)
{
    ovc_stack_test_layers_and_edges();
    ovc_stack_test_connection_ownership();
    ovc_stack_test_failed_build_retains_and_zeros();
    ovc_stack_test_failed_build_retry_fails_loudly();
    ovc_stack_test_config_only_connection_survives_retry();
    return 0;
}

#endif /* OVC_STACK_TEST_MAIN */
