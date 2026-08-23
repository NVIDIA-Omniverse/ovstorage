<!--
SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# Persona: Rust application using `ovstorage`

Rust callers compose an immutable `ovstorage::Stack` and drive it through the
async `Layer` interface. A Stack is a graph of three Layer shapes:

- backend Layers serve one or more address roots;
- wrapper Layers have one `inner` child and add policy or behavior;
- router Layers select one of several children.

Application code should not add a second dispatcher around `Stack`;
composition, canonicalization, and dispatch already live at the Layer boundary.

## Add the crate

```toml
[dependencies]
ovstorage = "0.2"
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
url = "2"
```

Workspace users can use `ovstorage = { path = "ovstorage-core/ovstorage" }`.

Retry and redirect following are opt-in wrapper Layers: a Stack that does not
declare a `retry` Layer and a `redirect_follower` Layer has neither behavior.
`file` is a built-in kind, so `register_default_layer_factories` gives you a
`file` backend without a plugin build. Resolved credentials are cached in
memory only; the crate exposes no credential-cache persistence seam.

## Compose a Stack

`StackBuilder` is explicit and one-shot: register the factory for every kind,
declare named Layer instances, attach connections, choose a root, then call
`build().await`. The built Stack is immutable and implements `Layer`.

The plugin-free factory is available through
`ovstorage::layers::register_default_layer_factories`: it registers exactly
the `file` backend, which is built in. Everything else, including every
wrapper, must be declared.
Routers and public wrappers come from ABI-v2 plugins loaded
with `load_layer_plugin` or `load_layer_plugins_from_dir`; register each
returned `LoadedLayerFactory` on the builder according to its variant.

```rust
use ovstorage::{LayerSpec, Stack};

let builder = ovstorage::layers::register_default_layer_factories(
    Stack::builder("files"),
)
.layer(LayerSpec::backend(
    "files",
    ovstorage::layers::FILE_BACKEND_KIND,
));

// Add a LayerConnectionRequest targeting "files", then build:
// let stack = builder.connection(connection).build().await?;
```

Connections carry backend config and credentials separately from graph shape.
For deployment configuration, prefer the shared `[ovstorage]` TOML schema in
[`../configuration.md`](../configuration.md). `StackConfig` parses that schema
and `stack_config_to_spec` resolves named kinds against loaded factories.

## Load plugins

Storage plugins are ABI-v2 Layer plugins. Rust hosts initialize the process
auth substrate, load only trusted cdylibs, and register their advertised
factories before building:

```rust
use ovstorage::{LoadedLayerFactory, Stack};

ovstorage::init_auth_substrate(None)?;
let factories = unsafe {
    ovstorage::load_layer_plugin("./plugins/libovstorage_plugin_http.so", false)?
};

let mut builder = Stack::builder("root");
for factory in factories {
    builder = match factory {
        LoadedLayerFactory::Backend(f) => builder.backend_factory(f),
        LoadedLayerFactory::Wrapper(f) => builder.wrapper_factory(f),
        LoadedLayerFactory::Router(f) => builder.router_factory(f),
    };
}
```

Plugin loading is unsafe because opening a shared library runs platform loader
hooks. The host permanently pins a successfully loaded plugin for process
lifetime. `test_only` manifests are rejected unless the load call explicitly
sets `allow_test_plugins = true`.

## Layer operations

`Layer` is the authoritative typed interface. Every async operation accepts a
`Request<T>` plus an optional `CancellationToken`. The request's `Extensions`
bag carries request facts such as principal identity; it is not an instruction
channel.

The operational groups are:

- object I/O: `stat`, `read`, `write`, `write_stream`, `delete`, `copy`,
  `rename`, `materialize`, metadata and directory operations;
- enumeration and change notification: `list`, `list_versions`,
  `get_latest_version`, `watch_directory`;
- introspection: `root_info_for`, `list_kinds`, `list_address_roots`;
- connection lifecycle: add, remove, update, list, and authenticate.

Wrappers return `inner_layer()` and inherit delegation defaults for operations
they do not intercept. Backends and routers implement the slots they support;
unsupported optional behavior returns `ErrorCode::Unsupported`.

### Ergonomic calls

`ovstorage::ext::LayerExt` provides URL-plus-options helpers over any Layer,
including `Stack`: `read_bytes`, `read_stream`, `list_page`, and ergonomic
forms of stat/write/delete/copy/rename/materialize.

```rust
use ovstorage::ext::LayerExt as _;
use ovstorage::{ReadOptions, Url};

let address = Url::parse("file:///data/scene.usd")?;
let (bytes, info) = stack.read_bytes(address, ReadOptions::default(), None).await?;
```

Some helper names intentionally overlap typed `Layer` methods. Where both
traits are in scope, use UFCS (`LayerExt::stat(...)` or `Layer::stat(...)`) to
select the intended form.

## Address and routing contract

The Stack boundary canonicalizes every address-bearing request before the root
Layer sees it. Routers match canonical address roots; aliases and caches can
therefore use canonical URLs as stable keys. Result addresses remain
caller-facing unless an operation's contract explicitly returns another
address.

`RootInfo.capabilities` advertises optional behavior for a route — metadata
patching, directory watches, versioning, conditional writes, server-side copy
and rename. The bits are **hints, and the two answers are not symmetric**:
`false` is actionable (the operation is known to be unavailable, so skip it or
grey it out in a UI), while `true` means only "not known to be impossible."
An advertised operation can still return `Unsupported` — the deployment behind
a protocol may not implement it, a policy Layer may intercept the slot, or the
specific arguments may fall outside what the backend supports. Check
capabilities to avoid round-trips that cannot succeed; still handle
`Unsupported` from the ones you attempt.

For `copy` and `rename` the bits separate three questions. `supports_copy` /
`supports_rename` answer **availability** — whether the operation can be
attempted at all — and are what you want when deciding whether to offer the
action. `supports_server_side_copy` / `supports_server_side_rename` answer
**mechanism**: the backend moves the bytes itself, so there is no egress
through this process and native metadata and checksums survive. Reach for the
mechanism bits only when optimizing; a stack configured with the
`copy_rename_fallback` Layer serves `copy` and `rename` even where the backend
offers neither, by reading the source and writing the destination (and deleting
the source, for `rename`), carrying your `if_source` and `if_dest`
preconditions onto both halves. That fallback is not atomic and does not
preserve backend-native metadata.

`supports_server_side_*` and `supports_atomic_rename` describe what the backend
does when it handles the operation itself. Whether any particular call takes
that path is decided per request — a backend can rename most objects
server-side and decline the one carrying a precondition it cannot express — so
those bits are not lowered when a `copy_rename_fallback` Layer is composed, and
a successful call may still have been emulated. The Layer emits a `tracing`
event each time it emulates; watch that if you need to know whether a given
transfer stayed on the server or a given rename was atomic.

## Errors, cancellation, and streaming

All operations return the closed `ovstorage::ErrorCode` taxonomy. Retry is a
wrapper policy, not implicit behavior of `Stack`; include a `retry` Layer when
the deployment wants it. Cancellation is cooperative through
`tokio_util::sync::CancellationToken`.

Use `LayerExt::read_stream` for bounded-memory reads. `read_bytes` buffers and
enforces `ReadOptions.max_bytes`. `Body::Stream` stays streaming through the
Layer and plugin seams and is not replayable by retry wrappers after
consumption.

## Built-in composition

The common direct-mode chain is:

```text
alias -> copy_rename_fallback -> redirect_follower -> retry -> router -> backends
```

Byte and metadata caches are optional wrappers and belong where the deployment
wants their semantics. The exact graph is configuration, not a hidden default.
See [configuration](../configuration.md) for a complete TOML example.

Concurrent successful `watch_directory` calls are independent logical
subscriptions: each sees all eligible events from the point it returns. On a
competing-consumer backend (where each notification is delivered to exactly one
reader), the backend self-coalesces overlapping subscriptions on one connection
via the SDK `WatchCoalescer` so every subscriber still receives every event. A
subscription with `since` requests replay: a resumable backend may serve it from
a dedicated seek reader with real replay, while a non-resumable
competing-consumer backend coalesces onto the live stream and prepends a single
initial `Lapsed`.

There is no `read_raw` operation. A `read` returns whatever the backend
produces — including a `ReadResult::Redirect` — unless a `redirect_follower`
wrapper above the backend resolves it first. To get the raw, unfollowed
redirect (for example, to hand a pre-signed URL straight to a caller), compose
the Stack without a `redirect_follower` on that path, or configure the wrapper
with `follow_reads = false`; the backend `Redirect` then surfaces to the caller
unchanged. This is how the REST gateway runs — `follow_reads = false`,
surfacing redirects as HTTP 307. One exception: a redirect whose credential
authorizes more than the redirected request is followed locally and returned as
a `Stream` even under `follow_reads = false`, because that credential may not
cross the host boundary. What decides that is the minting backend's own
declaration of what its credential authorizes — an account-scoped signature and
an object-scoped one are indistinguishable on the wire, so it cannot be
inferred from the redirect. A host that means to disclose such redirects
anyway sets `disclose_redirect_credentials` on the layer, which defaults to
refusing.

## Related references

- [Rust caller routing notes](AGENTS.md)
- [Configuration](../configuration.md)
- [Storage plugin behavior](../plugin-storage/README.md)
- [Plugin development](../plugin-development/README.md)
- [Glossary](../GLOSSARY.md)
