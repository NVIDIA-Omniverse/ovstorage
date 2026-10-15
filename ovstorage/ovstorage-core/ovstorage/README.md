<!--
SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# `ovstorage`

`ovstorage` is the host crate for composing and loading storage Layers. Its
application-facing runtime is an immutable [`Stack`] implementing the async
[`Layer`] contract re-exported from `ovstorage-layer`.

ABI-v2 Layer factories are the dynamic storage-plugin surface.

## Composition model

A Stack is a named graph described by [`StackSpec`] and built by
[`StackBuilder`]:

- backend Layers are leaves constructed by [`BackendFactory`];
- wrapper Layers have one child and are constructed by [`WrapperFactory`];
- router Layers have multiple children and are constructed by
  [`RouterFactory`].

[`LayerSpec`] declares each instance. [`LayerConnectionRequest`] attaches
backend configuration and credentials to a named target during build. Graph
validation rejects unknown kinds, missing children, cycles, duplicate use of a
node, and a root that cannot be constructed. A successful build returns one
immutable Stack; callers rebuild and swap when composition changes.

The Stack boundary canonicalizes address-bearing requests before delegating to
the root. That invariant gives aliases, routers, caches, and plugins one URL
identity without a caller-side dispatcher.

## Built-in Layer

[`layers::default_layer_factories`] exposes exactly one plugin-free factory:
the `file` backend. [`layers::register_default_layer_factories`] adds it to a
builder.

Every other public Layer is supplied by an ABI-v2 plugin. The standard
`ovstorage-plugin-core` library supplies router, alias,
cross-root-transfer, and retry kinds; `ovstorage-plugin-cache` supplies byte
and metadata caches; and `ovstorage-plugin-http` supplies the HTTP backend and
redirect-following wrapper. Load the plugins needed by the declared graph
before building the Stack.

## Configuration

[`StackConfig`] is the shared `[ovstorage]` TOML schema. Named
`[ovstorage.layers.<name>]` tables carry `kind`, `inner`, `children`, and flat
Layer config. `[[ovstorage.connections]]` entries remain distinct from graph
shape. [`stack_config_to_spec`] resolves a parsed config against the Layer kinds
available to a host.

See the public [configuration guide](../../docs/public/configuration.md).

## Plugin loading

Call [`init_auth_substrate`] before loading storage plugins. Then use
[`load_layer_plugin`] for one trusted cdylib or
[`load_layer_plugins_from_dir`] for a trusted directory. Both return
[`LoadedLayerFactory`] values to register on a Stack builder.

A host that owns its own load loop (the Python `PluginRegistry` caches its
dlopens, for example) uses the same directory policy through
[`discover_plugin_libraries`] — one level deep, platform plugin filename
shape, sorted — plus [`is_skippable_discovery_error`] for the candidates a
scan steps over rather than fails on.

Loading is `unsafe`: platform loader hooks execute in process. A loaded plugin
is pinned for process lifetime so its code and host callbacks cannot disappear
while a Layer handle remains live. [`inspect_layer_plugin`] performs full ABI-v2
initialization to obtain kind descriptors and has the same pinning behavior.

## Calling a Stack

[`Layer`] is the exact typed operation surface. Requests carry an
[`Extensions`] bag for per-request facts and an optional cancellation token.
Wrappers expose an inner Layer and inherit delegation defaults for slots they
do not intercept.

The opt-in [`ext::LayerExt`] trait provides convenient URL-plus-options calls
such as `read_bytes`, `read_stream`, `list_page`, and ergonomic object verbs.
It is kept in its own module because several helper names intentionally overlap
typed Layer methods; mixed call sites can select the desired trait with UFCS.

Read and write bodies remain streaming across the host/plugin boundary.
Buffering helpers enforce the caller's size limit. Retry, redirect following,
metadata caching, byte caching, aliasing, and cross-root fallback are explicit
wrapper Layers rather than implicit Stack behavior.

## Auth and credentials

The process-global auth substrate owns credential persistence and refresh
serialization shared by loaded plugins. Initialize it once, optionally with a
specific auth directory. Connection authentication is a Layer operation and
returns an event stream for host-driven browser/device-code UI.

## Observability and errors

The crate exports tracing initialization and metric helpers used by hosts.
Addresses and known secret-bearing query fields are redacted before diagnostic
output. Operations return the closed [`ErrorCode`] taxonomy; wrappers decide
retry policy and unsupported capabilities surface as `ErrorCode::Unsupported`.

## More documentation

- [Rust application guide](../../docs/public/library-rust/README.md)
- [Layered architecture RFC](../../docs/rfcs/0066-layered-architecture.md)
- [Configuration guide](../../docs/public/configuration.md)
- [Plugin development](../../docs/public/plugin-development/README.md)
