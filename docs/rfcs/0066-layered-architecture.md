# RFC-0066: Layered ovstorage — one Layer surface, native dispatch per language

- **Status:** Implemented
- **Depends-on:** —
- **Supersedes:** —
- **Superseded-by:** —

> No backwards compatibility is preserved by this design; the existing plugin C
> ABI, public Rust API, Python wheel surface, and C/C++ header all change shape.

Merging this RFC ratifies the decision. Once Accepted, this file is a frozen
decision record; the living how-it-works surface is the Software Design
Document, updated as implementation lands.

## For readers unfamiliar with ovstorage

`ovstorage` is a storage access layer for Omniverse applications and services. It gives callers one API for common object-store operations — read, write, list, delete, metadata, versioning, permissions checks, local materialization, and authentication — while allowing the actual bytes to live behind different backends such as local files, HTTP(S), cloud object stores, Nucleus-like services, or a broker daemon.

The project has two audiences:

- **Application authors** want a stable, language-friendly library. They should be able to say "read this URL" without knowing whether it routes to `file:`, S3, Azure, a broker, or another backend.
- **Backend-layer authors** want a stable plugin contract. They should be able to add one storage implementation and have it work in direct applications, the REST gateway, the broker daemon, tests, and language bindings.

The 0.x implementation reaches those goals through a central `Library` object. `Library` owns routing, aliases, caching, retry, redirect following, authentication orchestration, connection state, and plugin loading. Storage plugins implement a narrower backend interface underneath that dispatcher. This works, but it means the public application API and the plugin SPI are different surfaces, and cross-cutting behavior is hardwired into one dispatcher instead of being reusable pieces.

This proposal changes that shape. The universal runtime object is a
**Layer**. Plugins export **layer factories**; each factory's static
metadata declares what kind of Layer it produces:

- **Backend layer** (`layer_type = "backend"`): zero children. Handles
  operations directly against one storage dialect, or returns `Unsupported`.
  Examples: `S3Backend`, `FileBackend`, `HttpBackend`, `BrokerClientBackend`.
- **Wrapper layer** (`layer_type = "wrapper"`): exactly one child, called
  `inner` in implementation code. Intercepts the methods it cares about and
  delegates the rest to `inner`. Examples: `ByteCacheWrapper`, `RetryWrapper`,
  `AliasWrapper`, `RedirectFollowerWrapper`.
- **Router layer** (`layer_type = "router"`): many children. Chooses one child
  for an operation, or returns `NotFound` / `Unsupported`. Examples: prefix
  router, scheme router, policy router.

After construction, all three expose the same operational Layer surface. A
backend is therefore not a separate runtime species; it is a Layer type with
zero children. A router is not a special terminal backend; it is a Layer type
with many children.

The application's root is a Layer handle. In configuration, that root names one
Layer instance. Wrapper layers point at `inner`; router layers point at
`children`; backend layers terminate a path.

```text
Application
  ↓
AliasWrapper
  ↓ inner
CopyRenameFallbackWrapper
  ↓ inner
MetadataCacheWrapper
  ↓ inner
Router
  ├──→ ByteCacheWrapper → RetryWrapper → RedirectFollowerWrapper → S3Backend
  ├──→ FileBackend
  ├──→ BrokerClientBackend
  └──→ ...
```

Per-backend composition (e.g. stricter retry for one S3 route, a permission
check on another) is expressed by making a Router child point at a wrapper
subtree rather than directly at a backend layer. The built, callable
composition is a Stack.

The sign-off question for this document is not whether every detail is already implemented. It is whether this is the architecture we want to converge on before the public API, plugin ABI, Python wheel, and C/C++ headers harden.

## Goals

1. **API = SPI through one Layer surface.** An application talking to a
   `file` backend layer, a cache-wrapped S3 path, or a Router-backed Stack
   uses the same storage operation surface. A wrapper layer calls `inner`
   through that same surface.
2. **Compose, don't configure.** Cross-cutting behaviors (routing, caching,
   alias rewriting, redirect following, retry) are composable Layers, not knobs
   on a monolithic dispatcher.
3. **One operational surface, one C ABI.** The C-ABI Layer handle is the source
   of truth for what every Layer instance does. The plugin init/create API exists
   to produce Layer instances whose metadata declares `layer_type =
   "backend" | "wrapper" | "router"`.
4. **Native dispatch in each language.** A pure-Rust Stack dispatches through
   Rust trait objects. A pure-Python Stack dispatches through Python method
   calls. A pure-C/C++ Stack dispatches through the vtable directly. The FFI is
   crossed only at language transitions, so adjacent same-language Layers
   coalesce.
5. **C/C++ ships as source.** No precompiled `libovstorage_static.a` from us.
   We ship a small set of `.c` / `.h` / `.cpp` / `.hpp` files with minimal
   dependencies. Customers build their own static library or include the source
   files directly. A pure-C `file:` backend layer is in the source set so a
   customer who links nothing else gets a working default.

## Non-goals

- Drop-in compatibility with the current 0.x plugin ABI, Rust API, Python wheel surface, or C/C++ header.
- In-broker tenancy. Separate trust scopes remain separate broker deployments.
- Hot-reload of Layers or plugins. Loaded instances live for the host process's lifetime.
- In-place mutation of a built Stack. Stacks are dynamically constructed — directly, from a serialized spec, or by live cross-language handoff of an already-built subtree (see "Cross-language live handoff") — and rebuilt, but an individual built Stack is immutable.
- A blessed precompiled C/C++ binary distribution. We ship source.

## Today's shape

```
                  application
                       |
              ovstorage::Storage   (public API: read_bytes, read_stream,
                       |            materialize, read_raw, write, ...,
                       |            plus connection / alias / auth mgmt)
              ovstorage::Library   (dispatcher: routing, cache, alias,
                       |            redirect-follow, retry, dir-canon,
                       |            URL canon)
                       |
   shim::Backend + shim::Factory   (plugin SPI: stat / read / write /
                       |            list / ..., takes ResolvedTarget,
                       |            returns ReadResult enum)
                       |
                   plugin cdylib   (loaded over plugin C ABI:
                                    ovstorage_plugin_manifest_v1 +
                                    ovstorage_plugin_init_v1)
```

Two surfaces (`Storage` for apps, `Backend` for plugins), two C ABIs, one monolithic dispatcher between them. The split is documented today as load-bearing for the "same plugin binary in library and broker" rule.

## The proposed shape

```
                                                .
                application                     .       application
            (rust / python / c++)               .         (mixed)
                       |                        .             |
        +--------------+--------------+         .   +---------+---------+
        |              |              |         .   |   rust layer      |
   +----+----+   +-----+-----+  +-----+----+    .   +---------+---------+
   |  rust   |   |  python   |  |  c++/c   |    .             |  FFI vtable
   | traits  |   |  classes  |  |  vtable  |    .   +---------+---------+
   | surface |   |  surface  |  |  surface |    .   |   python layer    |
   +----+----+   +-----+-----+  +----+-----+    .   +---------+---------+
        |              |             |          .             |  FFI vtable
        +--------------+-------------+          .   +---------+---------+
                       |                        .   |  rust backend     |
            C ABI Layer vtable                .   +-------------------+
            (the source of truth)               .   (cross-language Stack:
                                                .    one FFI hop per
                                                .    language transition)
```

The C vtable is the lingua franca. Inside one language, Layer instances compose through that language's native dispatch (trait method call in Rust, regular method call in Python, function-pointer call in C/C++). Across languages, composition flows through the vtable. A pure-Rust 6-deep Layer path costs ~6 Rust virtual calls and zero FFI hops; a pure-Python 6-deep Layer path costs ~6 Python method calls and zero FFI hops; a 3-Rust-on-top-of-3-Python path costs ~3 Rust calls + 1 FFI hop + ~3 Python calls.

## Core concepts

The model has one runtime abstraction: **Layer**. Backend, wrapper, and router
are Layer types declared in factory metadata. The distinction matters at
construction time; after construction, every Layer handle exposes the same
storage operation surface.

### Plugin

A `.so` / `.dylib` / `.dll` (a cdylib) that exports two C symbols (`ovstorage_plugin_manifest_v1` and `ovstorage_plugin_init_v1`). Loaded once per process. The manifest declares the **Layer factories** the cdylib can produce. Each factory descriptor includes `layer_type = "backend" | "wrapper" | "router"`, config schema, credential schema, and whether the produced Layer accepts Connections.

The physical C ABI exposes three creation entry points (`create_backend`,
`create_wrapper`, `create_router`) matching the three layer types. The umbrella
concept is still "Layer factory"; the function names are specific to the child
shape each factory needs.

One cdylib may ship multiple Layer factories when they're naturally grouped:

- A "utility" plugin shipping the `AliasWrapper` + `RetryWrapper` + `RedirectFollowerWrapper` wrapper layers and the `Router` router layer together (tiny dependency-free composition machinery).
- A "cache" plugin shipping `ByteCacheWrapper` + `MetadataCacheWrapper` (shared eviction infrastructure).
- An "HTTP" plugin shipping `HttpBackend` + `RedirectFollowerWrapper` (shared HTTP client machinery).

Single-factory plugins are also fine — a `file` plugin ships only `FileBackend`. A `broker-client` plugin ships only `BrokerClientBackend`. The broker server is part of the broker binary itself, not a plugin an application loads; it terminates the broker protocol and forwards authorized requests into the broker's configured Stack. The manifest is static discovery data; runtime construction is explicit so the same loaded cdylib can create independent instances for different Stacks.

### The three scopes (kind / connection / root)

Three distinct levels of information the design carefully keeps separate. Conflating them — putting connection state in a kind descriptor, or per-root capabilities in a connection record — is a recurring trap:

| Scope | What it describes | Lives in | When it's known |
|---|---|---|---|
| **Kind** | "I'm the S3 Layer factory. I produce backend layers. Here's my config schema and credential schema for creating a new connection." | Manifest (`OvStorage_LayerKindDescriptor`, with `layer_type`) | At cdylib compile time; static; readable without init |
| **Connection** | "This specific S3 connection (id `prod`) is configured with bucket=ov-prod, region=us-west-2. Its auth state is Authenticated. It was added at runtime via `add_connection`." | Connection-owning Layer's internal state, queried via `list_connections` | At connection creation; mutates over the connection's lifetime |
| **Root** | "The URL `s3://prod/` has capabilities R+W, is visible in pickers, came from a runtime-added connection." | Returned by `root_info_for(url)` on the Layer instance | At query time; may differ per URL even within one connection |

The kind never knows about specific connections. A connection never carries the full capability set — it carries enough to know *what is configured*; the actual effective capabilities at any URL come from `root_info_for`. The manifest is enough for discovery and UI form generation; the rest is runtime.

### Layer

A runtime unit with a Layer handle. It may have zero, one, or many children according to the factory descriptor's `layer_type`:

- **Backend layer.** `S3Backend`, `HttpBackend`, `FileBackend`, `NucleusBackend`, `BrokerClientBackend`. Has no children. Knows one wire dialect (or a family of related kinds). May own Connections and route incoming requests among them by longest-prefix URL match.
- **Wrapper layer.** `AliasWrapper`, `MetadataCacheWrapper`, `ByteCacheWrapper`, `RetryWrapper`, `RedirectFollowerWrapper`, `CopyRenameFallbackWrapper`. Has exactly one child, called `inner` in implementation code. Adds behavior to specific methods and delegates the rest to `inner`.
- **Router layer.** Holds many children, each child being another Layer handle. Builds a routing table by calling `list_address_roots` on each child at build time. Dispatches incoming requests by URL pattern to the matching child.

After construction, all three present the same operational vtable (`OvStorage_LayerVTable`). Hosts and Layers above don't see whether a Layer is a backend, wrapper, or router; they just call vtable slots.

### Layer factory

A manifest-declared constructor for one Layer kind. The descriptor includes:

- `kind`: stable implementation kind, e.g. `"s3"`, `"byte_cache"`, `"router"`.
- `layer_type`: `"backend"`, `"wrapper"`, or `"router"`.
- `accepts_connections`: whether instances consume `add_connection`.
- config and credential schemas.

Most wrapper Layers are stateless or hold only their own internal caches; they don't own Connections. A few wrapper Layers are **connection-owning** — they accept `add_connection` to configure their own behavior. The canonical example is `AliasWrapper`, which accepts `add_connection({target: "alias", id: "<rule>", config: {from, to}})` to register a URL-rewrite rule (`to` is the rewrite destination; `target` names the owning Layer instance, here `alias`). The Layer overrides `add_connection` to consume requests whose `target` names it and passes the rest through to `inner`. Connection ownership is a behavior of specific Layer factories, not a separate Layer category.

### Stack

A **Stack** is a built, immutable, callable composition of Layer instances with
one root Layer. A Stack may be a simple linear wrapper path, or it may branch
through router Layers into multiple child paths. The config describes the Stack
directly with named Layer instances and their child fields:

- A wrapper layer has `inner = "<layer-name>"`.
- A router layer has `children = ["<layer-name>", ...]`.
- A backend layer has no child field.

The Stack has one configured root Layer. The application talks to the Stack's
root handle, and requests flow down through wrapper layers, through routers when
a branch is needed, and eventually to a backend layer or `Unsupported`.
There is no separate `[ovstorage.stacks.*]` namespace; the Stack is the
composition defined by `[ovstorage].root` plus the named Layer tables.

```text
AliasWrapper
    ↓ inner
CopyRenameFallbackWrapper
    ↓ inner
MetadataCacheWrapper
    ↓ inner
Router
    ├──→ ByteCacheWrapper → RetryWrapper → RedirectFollowerWrapper → S3Backend
    ├──→ PermissionCheckWrapper → RedirectFollowerWrapper → S3Backend
    ├──→ S3Backend "staging"
    └──→ FileBackend
```

Routers reference Layer instances as children. The router calls
`list_address_roots` on each child to build its routing table. From the
outside, every child looks like a Layer handle (same vtable); the Router
doesn't need to know whether a child is a single backend layer or a wrapper
subtree.

Builder APIs enforce the same shape: wrapper `layer(...)` calls can accumulate
freely, but `.build()` is not available until the composition terminates at a
backend or router.

```rust
ovstorage.layer(x).layer(y).layer(z).build()
// invalid: no backend or router terminal

let backend_stack = ovstorage.layer(x).layer(y).layer(z).backend(a).build();
let routed_stack = ovstorage.layer(x).layer(y).layer(z).router(r).build();
```

### Connection

A runtime-configured entry owned by one Layer. Some Connections are auth-bearing
storage endpoints; others are credentialless routing or rewrite entries. For an
`S3Backend`, a Connection is one `(bucket, region, credentials, access_mode)`
combination with auth state. For a `FileBackend`, a Connection is one local
mount with its access mode, usually `Anonymous`. For `AliasWrapper`, a Connection
is a credentialless `(from, to)` URL-rewrite rule.

Connections are internal state — they don't have their own vtable. The owning Layer routes between connections internally by URL prefix match: `S3Backend.read("s3://prod/foo")` looks up the "prod" connection and dispatches; `AliasWrapper.read("assets:/tree.usd")` looks up the matching alias rule and rewrites before calling `inner`.

Connection ownership and auth ownership are related but not identical. An
`AliasWrapper` owns alias Connections, but those Connections do not own
credentials, refresh tasks, or secret-store entries. Auth through an alias is
delegated: the `AliasWrapper` rewrites to the alias destination, asks `inner`
which auth-bearing Connection owns that destination, and forwards the auth
request while preserving the alias as user-facing context.

Connections are managed through the operational vtable: `add_connection`, `remove_connection`, `list_connections`, `update_connection_credentials`, `authenticate_connection`. `list_connections` returns a complete snapshot and, optionally, a change stream for callers that want to watch. Backend layers and connection-owning wrapper layers implement these meaningfully; pure wrappers pass them through to `inner`. Every connection op carries a required `target` Layer name (a field on the `add_connection` / `probe` request, a parameter on the by-id ops), so a Router forwards each call to the child whose subtree owns `target`.

## The Layer vtable

One C-ABI vtable. Same shape for every Layer in every language. After a
wrapper composes around `inner`, or a router composes around its children, the
result still presents this same vtable. The `layer_type` distinction belongs to
factory metadata and config validation, not to runtime dispatch.

```c
typedef struct OvStorage_Extensions OvStorage_Extensions;

typedef struct OvStorage_LayerVTable {
    size_t   struct_size;
    uint32_t abi_version;

    /* Lifecycle */
    void (*drop)(void* state);

    /* Identity (local; never aggregates). `name` is the config Layer name.
       `descriptor` returns the Layer's own kind descriptor, including
       layer_type. */
    void (*name)(void* state, const char** out);
    void (*descriptor)(void* state, OvStorage_LayerKindDescriptor** out);
    /* Connection-owning Layer names reachable through this Layer. A backend
       or connection-owning wrapper includes its own name; pure wrappers
       forward inner results; routers union child results. Routers call this
       on each immediate child to build their static target-name map. */
    void (*owned_targets)(void* state,
                          const char* const** out_targets,
                          size_t* out_target_count,
                          OvStorage_Error** err);

    /* Introspection. Wrappers wrap inner results; backend layers answer
       locally; routers aggregate across children. The three runtime-state
       queries — `root_info_for`, `list_address_roots`, `list_connections` —
       are always-async (callback-shaped, cancellable) because a connection-
       owning backend may resolve them against live connection state and a
       router fans them out across children. `list_kinds` reports fixed
       manifest/graph metadata under the no-I/O contract, so it stays
       synchronous. */
    /* Per-URL root introspection. `result` (on OnComplete): RootInfo. */
    void (*root_info_for)(void* state, const OvStorage_RootInfoForRequest*,
                          OvStorage_CancelToken*,
                          OvStorage_OnComplete, void* user_data);
    /* Enumerate every Layer kind reachable from here. The slot does not
       filter by layer_type; each descriptor's `accepts_connections` tells the
       caller which kinds take `add_connection`. A wrapper adds its own
       kind to inner's set; a router unions across children. Synchronous:
       the kind set is fixed manifest/graph metadata, computed with no I/O. */
    void (*list_kinds)(void* state,
                       OvStorage_LayerKindDescriptorList** out,
                       OvStorage_Error** err);
    /* Returns a complete snapshot and, if the Layer has one, a stream of
       changes that begin after it — the two are paired in the result the
       OnComplete callback receives. Routers call this on each child at build
       time to build their routing table (see "Stack and routing").
       `result` (on OnComplete): ListAddressRootsResult
       (RootInfoSnapshot + optional RootInfo change stream). */
    void (*list_address_roots)(void* state,
                               const OvStorage_ListAddressRootsRequest*,
                               OvStorage_CancelToken*,
                               OvStorage_OnComplete, void* user_data);

    /* Object operations (always-async callback shape) */
    void (*stat)(void* state, const OvStorage_StatRequest*,
                 OvStorage_CancelToken*,
                 OvStorage_OnComplete, void* user_data);
    void (*read)(void* state, const OvStorage_ReadRequest*,
                 OvStorage_CancelToken*,
                 OvStorage_OnComplete, void* user_data);
    /* Buffered write: caller hands the whole body in memory.
       backend-layer-internal handling, no redirect emission. */
    void (*write)(...);
    /* Streamed write: caller hands a chunk-by-chunk stream.
       backend-layer-internal handling, no redirect emission. */
    void (*write_stream)(...);
    /* Body-less redirect-emitting write: the backend layer returns a
       WriteStep::Redirects without ever seeing the body.
       The RedirectFollowerWrapper (or the broker, in pass-through
       mode) executes them. */
    void (*write_redirect)(...);
    /* Continue a multi-stage write after redirects have been
       executed. Threads identically to write. */
    void (*continue_write)(...);
    void (*delete)(...);
    void (*copy)(...);
    void (*rename)(...);
    void (*update_metadata)(...);
    void (*check_access)(...);
    /* Materialize: return a LocalDelegate (a path on disk plus
       an optional lease guard). FileBackend returns the file's own
       path with no guard. ByteCacheWrapper returns inner file://
       delegates unchanged; otherwise it returns a cached row with
       a live lease that pins that row until the delegate/lease drops.
       Most Layers pass through. */
    void (*materialize)(void* state, const OvStorage_ReadRequest*,
                        OvStorage_CancelToken*,
                        OvStorage_OnComplete, void* user_data);
    void (*list)(...);
    void (*list_versions)(...);
    void (*get_latest_version)(...);
    void (*watch_directory)(...);
    void (*create_directory)(...);
    void (*delete_directory)(...);

    /* Connection management. Wrappers pass through unless connection-owning
       and named as `target`; backend layers accept requests targeting them;
       routers forward to the child whose subtree owns `target`. Auth ops
       start at `target`, but a connection-owning wrapper may delegate them
       downstream (for example, AliasWrapper delegates alias auth to the
       rewritten destination's auth-bearing backend connection). `target`
       is required on every connection op. */
    void (*probe)(void* state, const OvStorage_ConnectionRequest*,
                  OvStorage_OnComplete, void* user_data);
    void (*add_connection)(void* state, const OvStorage_ConnectionRequest*,
                           OvStorage_OnComplete, void* user_data);
    /* The by-id management ops identify a connection by (target, id):
       `id` is unique within its owning Layer, and `target` names that
       Layer so the call resolves to exactly one connection even when
       several same-kind backends are reachable (see "Connection
       management routing"). */
    void (*remove_connection)(void* state, const char* target, const char* id,
                              OvStorage_OnComplete, void* user_data);
    /* Returns a complete snapshot and, if the Layer has one, a stream of
       changes that begin after it — paired in the result the OnComplete
       callback receives. Always-async and cancellable: a connection-owning
       backend answers from live state, a router fans out across children.
       `result` (on OnComplete): ListConnectionsResult
       (ConnectionSnapshot + optional Connection change stream). */
    void (*list_connections)(void* state,
                             const OvStorage_ListConnectionsRequest*,
                             OvStorage_CancelToken*,
                             OvStorage_OnComplete, void* user_data);
    void (*update_connection_credentials)(void* state,
                                          const char* target, const char* id,
                                          const OvStorage_SecretBundle*,
                                          OvStorage_OnComplete, void* user_data);
    void (*update_connection_attributes)(void* state,
                                         const char* target, const char* id,
                                         const OvStorage_AttributePatch*,
                                         OvStorage_OnComplete, void* user_data);
    void (*authenticate_connection)(void* state,
                                    const OvStorage_AuthenticateRequest*,
                                    OvStorage_CancelToken*,
                                    OvStorage_Stream** out,  /* items: AuthEvent */
                                    OvStorage_Error** err);

    /* Reserved padding for additive growth pre-2.0 */
    void (*_reserved[16])(void);
} OvStorage_LayerVTable;

typedef struct OvStorage_LayerHandle {
    void* state;                          /* Layer-owned */
    const OvStorage_LayerVTable* vtable;  /* points into the producing binary */
} OvStorage_LayerHandle;

typedef struct OvStorage_AuthenticateRequest {
    size_t struct_size;
    OvStorage_Extensions* extensions;  /* per-request cross-cutting data */
    const char* target;                /* owning Layer name; resolves (target, connection_id) */
    const char* connection_id;         /* unique within the target Layer */
    OvStorage_InteractiveAuthCapability capability;
    bool auto_open_browser;
    void* _reserved[16];
} OvStorage_AuthenticateRequest;

/* Request to create or probe a connection on a specific Layer. `target`
   names the Layer instance that should own the connection — a backend layer
   (s3, file, ...) or a connection-owning wrapper layer (alias) — and is required.
   The vtable routes by `target`: a Router forwards to the child whose
   subtree owns that name; a connection-owning Layer accepts it when the name
   matches itself, otherwise returns `NotFound`. The target Layer's kind
   determines how `config` and `credentials` are interpreted; the
   request carries no `kind` field of its own. */
typedef struct OvStorage_ConnectionRequest {
    size_t struct_size;
    OvStorage_Extensions* extensions;
    const char* target;          /* required: owning Layer name (config key).
                                    The connection's kind is the target Layer's
                                    kind, so it is not carried separately. */
    const char* id;              /* connection id, unique within the owning Layer;
                                    (target, id) is the connection's identity */
    const OvStorage_ConfigTree* config;        /* kind-specific config subtree */
    const OvStorage_SecretBundle* credentials; /* NULL for credential-less kinds (e.g. alias) */
    void* _reserved[16];
} OvStorage_ConnectionRequest;
```

### Cross-language live handoff

A built Stack's root handle is not confined to the binary that composed it.
Because every Layer presents the same `OvStorage_LayerVTable`, and an
`OvStorage_LayerHandle` carries a `vtable` pointer into its producing binary
together with a `drop` slot that frees there, a Stack composed in any
language can be **exported** as an `OvStorage_LayerHandle` and **imported**
by a host in any other language, which then drives it through the vtable —
one FFI hop per operation, exactly as for a plugin-loaded layer. This is the
runtime dual of the on-disk plugin ABI: the plugin ABI imports a
*factory-created* layer from a cdylib; live handoff imports an
*already-composed* root handle from a peer binary. Transferring a whole built
Stack across languages is therefore a first-class, permanent capability —
distinct from, and complementary to, reproducing a composition from a
serialized Stack spec (see "Dynamic Stack construction").

> **Naming.** The plugin crate's generated C header names this raw,
> vtable-bearing struct `OvStoragePlugin_LayerHandle` rather than
> `OvStorage_LayerHandle` as written above: `OvStorage_LayerHandle` is
> already taken by the application C API's *opaque* built-Stack handle
> (`ovstorage.h`, driven by `ovstorage_<op>(handle, …)`) — a different type
> with a `void*`-only representation. The two are distinct handles at two
> different layers of the C surface: the plugin ABI's transparent
> `{state, vtable}` struct, and the application API's opaque built-Stack
> handle. The application API additionally exposes
> `ovstorage_export_handle`/`ovstorage_import_handle` to convert between
> them, so a consumer never has to hand-roll the conversion.

Two operations, symmetric across every binding (uniform `_handle` suffix):

- **`export_handle`** — wrap a native layer/Stack root as an
  `OvStorage_LayerHandle` (`OvStoragePlugin_LayerHandle` in the generated C
  header). Rust exposes it as a free function,
  `ovstorage::export_handle(Arc<dyn Layer>) -> ffi::LayerHandle`, plus an
  `Arc<dyn Layer>::export_handle()` extension-trait method for call-site
  convenience; `Layer` itself gains no new trait method (see "Why a free
  function, not a trait method" below). Python exposes it as
  `LayerBase.export_handle()`. C exposes it as `ovstorage_export_handle`.
- **`import_handle`** — wrap a foreign `OvStorage_LayerHandle` as the
  importing language's native layer, forwarding every vtable slot. Rust:
  `unsafe fn ovstorage::import_handle(ffi::LayerHandle) -> Result<Arc<dyn
  Layer>>`. Python: `LayerBase.import_handle`. C: `ovstorage_import_handle`.
  `import_handle` is an unsafe/trusted boundary in every binding that
  surfaces it as such — see "Security and trust" below.

**Why a free function, not a trait method.** `Layer::export_handle` as a
trait default is impossible in this codebase: `ovstorage-layer` (which
defines `Layer`) does not depend on `ovstorage-plugin` (which defines
`LAYER_VTABLE`), so a default method could not name the vtable it needs to
build; and the vtable slot-order freeze test parses the trait source and
fails on any new trait method that is not explicitly exempted. The surface
is therefore free functions in `ovstorage-plugin`, re-exported as
`ovstorage::export_handle`/`ovstorage::import_handle`, plus the optional
`LayerExportExt` sugar trait for method-call syntax without touching the
frozen `Layer` trait.

Contracts:

- **Ownership.** `export_handle` transfers exactly one owned reference — one
  call mints one owned handle, because the vtable has no clone slot; a
  second consumer requires a second `export_handle` call (each clones the
  producer-side `Arc`). The consumer must eventually release its handle via
  the handle's own `drop` slot. Refcounts never cross the boundary: clone
  and drop execute only inside the producer. The producing binary must
  outlive every handle it exported — and every sub-handle (stream,
  `LocalDelegate` lease, cancel token) derived from it — for as long as that
  handle is live; unloading a producer with live handles is undefined
  behavior and unsupported by design.
- **Failure disposal on import (normative).** `import_handle` validates, in
  order: (a) non-null `state`/`vtable` — on failure, `InvalidArgument`, and
  the handle is returned to the caller **undisposed** (it carries no
  trustworthy `drop` slot to call); (b) `vtable.struct_size` at least the
  consumer's known `LayerVTableV1` size — on failure, `IncompatibleType`,
  likewise returned undisposed; (c) `vtable.abi_version` equal to the Layer
  ABI version the consumer supports — on failure, `IncompatibleType`, and
  this time the handle **is** consumed (dropped through its own `drop`
  slot, trustworthy once (a) and (b) hold). This is the single normative
  statement of import failure disposal; no other prose in this document
  overrides it.
- **Versioning.** The v2 Layer ABI is deliberately **exact-match,
  single-version** — unlike the v1 init-result band, there is no compatible
  range to check against. A bare `OvStorage_LayerHandle` carries no version
  fields of its own; the vtable header (`struct_size`, `abi_version`) is the
  only self-describing surface. `import_handle` accepts a foreign handle
  only when its `abi_version` equals the consumer's supported version, and
  rejects a mismatch with the same typed `ErrorCode::IncompatibleType` a bad
  plugin load raises — no new error variant. A future host able to validate
  more than one Layer ABI would widen this check to a *band*; that is a
  forward extension point, not this design's contract.
- **Runtime / event loop.** Operations are async-callback shaped; the
  producer drives its own runtime and — for a producer-language leaf layer
  (for example, a real Python-implemented Layer) — its own event loop / GIL,
  decoupled from the consumer's calling thread. No blocking cross-boundary
  call may require the peer's lock; a producer whose loop has stopped fails
  the call with a typed error rather than hanging or invoking undefined
  behavior.
- **Same-language fast path.** Importing a handle produced by the *same
  linked binary* (verified by `vtable` pointer identity, not merely
  structural equality) unwraps the raw `Arc` and dispatches natively with
  zero FFI hops, preserving the one-FFI-hop-per-language-transition cost
  model. This check is per-*linked-image*: two independently loaded copies
  of the same producer `.so`, or a host versus a plugin cdylib built from
  the same sources, correctly take the foreign path and pay one FFI hop,
  because they do not share a `LAYER_VTABLE` instance.
- **Re-export cost.** Re-exporting an already-imported foreign layer wraps
  the foreign-vtable adapter behind the local vtable again — one extra FFI
  hop at that boundary. Correct, just slower than the direct path; not a
  correctness concern.
- **Allocator and thread contract.** The cross-binary memory contract is the
  shared raw "ABI allocator" (Rust's `System` allocator, which is
  malloc/free on POSIX): a consumer frees a producer's payloads only through
  the ABI's documented free functions, and a producer must not install a
  custom `#[global_allocator]` that breaks that malloc/free equivalence.
  Concurrent slot invocation across threads is an existing ABI-level
  obligation independent of this feature: a producer's vtable slots may
  already be called from multiple consumer threads with no serialization,
  and `drop` is exclusive only after every in-flight call on that handle has
  drained.

### Security and trust

Crossing a vtable means executing function pointers supplied by another
binary. A foreign `OvStorage_LayerHandle` is exactly as trusted as a
`dlopen`ed plugin: `import_handle` is an unsafe/trusted boundary in every
binding, gated the same way a plugin load is gated — the caller vouches for
the handle's provenance. This design adds no new trust surface beyond "the
producer of a handle you import is as trusted as a plugin you load," and
documents that explicitly rather than leaving it implied. Handles are
process-local pointers: they are never serialized, never sent over IPC, and
carry no meaning outside the process that produced them.

### Plugin cdylib symbol exports

The plugin's create-time API exposes Layer factories. The descriptor for each
factory declares `layer_type = BACKEND | WRAPPER | ROUTER`. The physical ABI
below keeps three create functions because their arguments differ by child
shape: no child, one `inner`, or many `children`. They are not three runtime
species; all return an `OvStorage_LayerHandle`.

```c
/* One per cdylib. Static facts about the cdylib, readable before
   init. Hosts (and CLIs) can read this from a cdylib without
   committing to instantiating anything — useful for discovery
   and lazy loading. */
typedef struct OvStorage_PluginManifestV1 {
    size_t   struct_size;
    uint32_t abi_version;
    const char* name;             /* NUL-terminated, e.g. "cloud-storage" */
    const char* version;          /* NUL-terminated, e.g. "0.2.0" */

    /* Layer kind descriptors. One array for every Layer factory the
       cdylib can produce.
       Strictly KIND-level info only: layer_type, kind name, display name,
       description, icon, config schema, credential schema, and whether
       the kind accepts connections. NOT connection-level info (auth
       state, configured values, current addresses) and NOT root-level
       info (per-prefix capabilities, visibility, alias state). Those are
       runtime-queried via `list_connections` and `root_info_for` on the
       instance. The `layer_type` field tells the host which factory to call
       (`create_backend` / `create_wrapper` / `create_router`). */
    const OvStorage_LayerKindDescriptor* kinds;
    uint32_t kind_count;

    bool     test_only;           /* host opt-in required to load */
} OvStorage_PluginManifestV1;

/* Layer type produced by a factory. Selects the create_* entry point and
   validates config shape: backend has no edge fields, wrapper has `inner`,
   router has `children`. */
typedef enum OvStorage_LayerType {
    OVSTORAGE_LAYER_BACKEND = 0,  /* no child; create_backend */
    OVSTORAGE_LAYER_WRAPPER = 1,  /* one inner child; create_wrapper */
    OVSTORAGE_LAYER_ROUTER  = 2,  /* many children; create_router */
} OvStorage_LayerType;

/* What's true of ALL instances produced by one Layer factory. Static at
   compile time. */
typedef struct OvStorage_LayerKindDescriptor {
    size_t   struct_size;
    OvStorage_LayerType layer_type; /* host: layer_type -> which create_* factory */
    /* Does this kind accept connections via add_connection? True for
       backend layers (s3, file, ...) AND connection-owning wrapper layers
       (alias). False for pure wrappers (retry, cache) and for routers
       (which forward to children). Surfaced explicitly so a UI knows
       where add_connection is valid without inferring it from whether a
       credential schema is present (which breaks for credential-less
       connections such as aliases). */
    bool     accepts_connections;
    const char* kind;             /* unique within a process, e.g. "s3" or "router" */
    const char* display_name;     /* e.g. "Amazon S3" */
    const char* description;      /* optional, NUL-terminated */
    const OvStorage_ConfigField* config_schema;
    uint32_t    config_field_count;
    const OvStorage_CredentialField* credential_schema;
    uint32_t    credential_field_count;
    /* Optional icon bytes (PNG/SVG) for UIs. */
    const uint8_t* icon;
    uint32_t       icon_len;
    void* _reserved[8];
} OvStorage_LayerKindDescriptor;

/* Factory request for a backend layer (S3, File, HTTP, ...). */
typedef struct OvStorage_CreateBackendRequest {
    size_t struct_size;
    OvStorage_Extensions* extensions;
    const char* kind;                   /* a manifest kind with layer_type = BACKEND */
    const char* instance_id;            /* config-visible instance id */
    const OvStorage_ConfigTree* config; /* per-instance config subtree */
    void* _reserved[16];
} OvStorage_CreateBackendRequest;

/* Factory request for a wrapper layer. A wrapper has exactly one inner child. */
typedef struct OvStorage_CreateWrapperRequest {
    size_t struct_size;
    OvStorage_Extensions* extensions;
    OvStorage_LayerHandle inner;        /* the child this wrapper wraps */
    const char* kind;                   /* a manifest kind with layer_type = WRAPPER */
    const char* instance_id;
    const OvStorage_ConfigTree* config;
    void* _reserved[16];
} OvStorage_CreateWrapperRequest;

/* One child of a router layer: its built handle. Routers query each child
   with `name` and `owned_targets` from `OvStorage_LayerVTable` to build a
   (target Layer name -> child) map for connection-management ops,
   complementing the (URL prefix -> child) map they build from
   `list_address_roots` for object ops. Because the Stack is tree-shaped
   (see "Build order"), each target name appears in exactly one child's set. */
typedef struct OvStorage_RouterChild {
    OvStorage_LayerHandle handle;
    void* _reserved[8];
} OvStorage_RouterChild;

/* Factory request for a router layer. A router has multiple children,
   each a built Layer handle. */
typedef struct OvStorage_CreateRouterRequest {
    size_t struct_size;
    OvStorage_Extensions* extensions;
    const char* kind;                   /* a manifest kind with layer_type = ROUTER */
    const char* instance_id;
    const OvStorage_ConfigTree* config;
    const OvStorage_RouterChild* children;
    size_t child_count;
    void* _reserved[16];
} OvStorage_CreateRouterRequest;

typedef struct OvStorage_PluginVTable {
    size_t struct_size;
    uint32_t abi_version;

    void (*drop)(void* plugin_state);

    /* Each factory returns an OvStorage_LayerHandle. The
       host calls the factory matching the kind's declared layer_type; a
       given plugin populates only the factories whose kinds it ships. */
    void (*create_backend)(void* plugin_state,
                           const OvStorage_CreateBackendRequest* request,
                           OvStorage_LayerHandle* out,
                           OvStorage_Error** err);
    void (*create_wrapper)(void* plugin_state,
                           const OvStorage_CreateWrapperRequest* request,
                           OvStorage_LayerHandle* out,
                           OvStorage_Error** err);
    void (*create_router)(void* plugin_state,
                          const OvStorage_CreateRouterRequest* request,
                          OvStorage_LayerHandle* out,
                          OvStorage_Error** err);

    void (*_reserved[16])(void);
} OvStorage_PluginVTable;

/* One per cdylib, returned by init. Init creates plugin-scoped
   resources only. Layer instances are created later, one per Stack entry,
   through the appropriate `create_*` entry point. */
typedef struct OvStorage_PluginInitResultV1 {
    size_t   struct_size;
    uint32_t abi_version;      /* ABI this plugin implements */

    /* Plugin-owned state (e.g. shared HTTP client between Layer
       instances of different kinds in this cdylib). */
    void*    plugin_state;
    const OvStorage_PluginVTable* plugin_vtable;
} OvStorage_PluginInitResultV1;

extern const OvStorage_PluginManifestV1 ovstorage_plugin_manifest_v1;
extern OvStorage_PluginInitResultV1
       ovstorage_plugin_init_v1(const OvStorage_HostCallbacks* host);
```

The manifest's `kinds` array carries one `OvStorage_LayerKindDescriptor` per Layer factory the cdylib ships. The `layer_type` field is load-bearing: the host reads it to choose the construction factory (`create_backend` / `create_wrapper` / `create_router`) and to validate config shape (`inner` for wrappers, `children` for routers, neither for backends). The live `descriptor()` / `list_kinds` vtable slots return this same type, so a Layer-wrapped instance reports its own identity honestly instead of masquerading as the thing it wraps. `accepts_connections` is surfaced explicitly so a UI knows where `add_connection` is valid — true for backend layers and for connection-owning wrapper layers like `alias`, false for pure wrappers and routers — without guessing from whether a credential schema is present.

`ovstorage_plugin_init_v1` is called once when the cdylib is loaded. It does not create Layer instances. The host stores the returned plugin handle in its registry, and Stack construction calls `create_backend`, `create_wrapper`, or `create_router` to get a fresh `OvStorage_LayerHandle` for each Layer instance.

`abi_version` names the ABI implemented by the plugin. Compatibility is a host-loader decision: a host may accept older plugin ABI versions when it still knows how to validate their `struct_size`, vtable layout, and reserved slots. The plugin does not declare a maximum future ABI version because it cannot know which future hosts will preserve compatibility.

The `plugin_state` pointer is for resources shared across the cdylib's runtime instances (shared HTTP client, shared secret-store handle, etc.). The host drops it through `plugin_vtable.drop` after every Layer handle produced by that plugin has been dropped.

### `OvStorage_HostCallbacks`

Pointer struct the host hands the plugin at init time. Carries the host-side facilities the plugin reaches into:

```c
typedef struct OvStorage_HostCallbacks {
    size_t struct_size;
    uint32_t abi_version;
    void* host_state;

    /* Secret persistence (local SQLite / encrypted file / HSM /
       broker-mediated). See "Authentication" below. */
    const OvStorage_SecretStore* secret_store;

    /* Host-owned auth UX and local-machine policy. See "Authentication". */
    const OvStorage_AuthHost* auth_host;

    /* Observability — see "Observability host callbacks" below. */
    const OvStorage_Logger* logger;
    const OvStorage_MetricsSink* metrics;
    const OvStorage_TracerProvider* tracer;

    /* Reserved padding. */
    void* _reserved[16];
} OvStorage_HostCallbacks;

typedef struct OvStorage_LoopbackRedirectRequest {
    size_t struct_size;
    const char* preferred_host;     /* usually "127.0.0.1" */
    uint16_t preferred_port;        /* 0 = host/helper may choose */
    void* _reserved[16];
} OvStorage_LoopbackRedirectRequest;

typedef struct OvStorage_LoopbackRedirectGrant {
    size_t struct_size;
    bool allowed;
    const char* host;
    uint16_t port;                  /* 0 = helper chooses an ephemeral port */
    void* _reserved[16];
} OvStorage_LoopbackRedirectGrant;

typedef struct OvStorage_AuthHost {
    size_t struct_size;
    void* ctx;

    /* Host default used by builders when authenticate requests do not
       override capability explicitly. */
    OvStorage_InteractiveAuthCapability (*interactive_capability)(void* ctx);

    /* Optional convenience for desktop hosts. The host may open a browser,
       no-op, or return an error; the AuthEventStream still carries the URL
       so the UI can render it. */
    void (*open_browser)(void* ctx,
                         const char* url,
                         OvStorage_Error** err);

    /* Local redirect listener policy for browser/PKCE flows. The OAuth
       helper binds and serves the loopback listener; this callback lets the
       host allow/deny loopback auth and constrain host/port choices. */
    void (*authorize_loopback_redirect)(
        void* ctx,
        const OvStorage_LoopbackRedirectRequest* request,
        OvStorage_LoopbackRedirectGrant** out,
        OvStorage_Error** err);

    void* _reserved[16];
} OvStorage_AuthHost;
```

The host owns these pointers; they remain valid for the cdylib's lifetime. The plugin may stash them anywhere within its layers' state.

## Stack and routing

The application talks to a single root Layer handle. The full runtime topology
is a Stack:

- Wrapper layers point to one `inner` Layer.
- Router layers point to many `children`.
- Backend layers terminate paths.

### Anatomy of a Stack

```text
root = alias

AliasWrapper                       shared, cross-backend concerns sit
│ inner                         above the Router fork, so every child
▼                               inherits them
CopyRenameFallbackWrapper          below alias, so the addresses it
│ inner                         compares and transfers are rewritten
▼
MetadataCacheWrapper
│ inner
▼
Router                     the fork: per-backend concerns live below it
├── ByteCacheWrapper              prod S3 gets byte cache + aggressive retry
│   │ inner
│   ▼
│   RetryWrapper
│   │ inner
│   ▼
│   RedirectFollowerWrapper
│   │ inner
│   ▼
│   S3Backend
│
├── PermissionCheckWrapper        secrets get permission check and no byte cache
│   │ inner
│   ▼
│   RedirectFollowerWrapper
│   │ inner
│   ▼
│   S3Backend
│
├── S3Backend                   staging; bare backend layer, no wrappers
│
└── FileBackend                 no byte cache, no retry — the OS already
                                caches local files
```

The rule of thumb: **shared concerns go above the Router fork; per-backend
concerns go below it.** Concerns that are inherently cross-backend —
cross-root transfer, alias rewriting, URL canonicalization (at the
`Stack` boundary), and (here) the metadata cache — sit above the Router, so
every child inherits them. Concerns
that should vary by destination sit below the Router: prod S3 adds a byte cache
and aggressive retry; secrets adds a permission check but deliberately no byte
cache; staging is a bare backend layer; and `FileBackend` is reached straight
from the Router with no byte cache and no retry. Nothing above the fork forces
a cache or retry onto a child that shouldn't pay for it — that placement choice
is exactly what the Stack buys over a single linear pipeline.

### Routing table construction: `list_address_roots`

A Router builds its routing table at **build time** by calling `list_address_roots` on each child Layer handle. The slot is async and cancellable: its `ListAddressRootsResult` pairs a `RootInfo` snapshot — the URL prefixes that child handles, plus capability and presentation data per root — with an optional change stream. The Router awaits each child's completion, then stores the (URL prefix → child handle) mapping and dispatches incoming requests by longest-prefix match. Because the build itself is a cancellable async operation, a stalled child cannot wedge the build: cancelling the build token unwinds every in-flight child query.

```c
/* Already in the Layer vtable. Router uses this on each child. */
void (*list_address_roots)(void* state,
                           const OvStorage_ListAddressRootsRequest*,
                           OvStorage_CancelToken*,
                           OvStorage_OnComplete, void* user_data);
/* result (on OnComplete): ListAddressRootsResult — the RootInfoSnapshot
   paired with an optional RootInfo change stream. */
```

If a child's result carries a change stream, the Router subscribes — adding or removing roots as the child's connection set changes (e.g. when `add_connection` registers a new S3 bucket). This is what allows runtime `add_connection` to propagate: the affected child layer updates its internal connection table, emits a change on its `list_address_roots` stream, and the Router refreshes its routing table without needing a Stack rebuild.

A Router actually keeps **two** maps. The (URL prefix → child) map above routes *object* operations by address. A second (target Layer name → child) map — built at construction by querying each immediate child's `owned_targets` — routes *connection-management* operations by `target`, because `add_connection` for a Layer whose roots don't exist yet can't be placed by URL and must route by name. The prefix map is dynamic (it tracks `list_address_roots` updates); the target map is static, since the Stack's Layer set is fixed at build time — runtime `add_connection` adds connections to existing Layers, never new Layers.

### Configuration

Layer instances are named entities in the configuration. Routers reference
children by Layer name. There is no separate `[ovstorage.backends.*]`
namespace — backend layers are ordinary Layer instances whose factory
descriptor says `layer_type = "backend"`.

```toml
[ovstorage]
root = "alias"

# Layers: every runtime Layer instance, including backend layers, wrappers, and routers.
# `kind` selects a factory; the factory descriptor's `layer_type` decides which
# edge fields are valid. Wrappers have `inner`; routers have `children`;
# backend layers have neither.
#
# `alias` composes ABOVE `copy_rename_fallback`, matching every shipped
# configuration. The ordering is load-bearing: the fallback refuses to emulate
# when source and destination name one object, and it compares the addresses as
# they arrive, so a rewriting layer beneath it could collapse two addresses onto
# one after that check has passed.
[ovstorage.layers.alias]
kind = "alias"
inner = "copy_rename_fallback"

[ovstorage.layers.copy_rename_fallback]
kind = "copy_rename_fallback"
inner = "metadata_cache"

[ovstorage.layers.metadata_cache]
kind = "metadata_cache"
inner = "main-router"
config = { ttl_seconds = 60, max_entries = 10000 }

[ovstorage.layers.main-router]
kind = "router"
children = ["s3-prod-byte-cache", "s3-secrets-permission", "s3-staging-backend", "file-backend"]

[ovstorage.layers.s3-prod-byte-cache]
kind = "byte_cache"
inner = "s3-prod-retry"
config = { cache_dir = "${XDG_CACHE_HOME}/ovstorage", max_bytes = "16 GiB" }

[ovstorage.layers.s3-prod-retry]
kind = "retry"
inner = "s3-prod-redirect-follower"
config = { max_attempts = 10, initial_delay_ms = 200 }

[ovstorage.layers.s3-prod-redirect-follower]
kind = "redirect_follower"
inner = "s3-prod-backend"

[ovstorage.layers.s3-prod-backend]
kind = "s3"
# Backend-layer config only; buckets, regions, and credentials are connections.

[ovstorage.layers.s3-secrets-permission]
kind = "permission_check"
inner = "s3-secrets-redirect-follower"
config = { policy = "secrets" }

[ovstorage.layers.s3-secrets-redirect-follower]
kind = "redirect_follower"
inner = "s3-secrets-backend"

[ovstorage.layers.s3-secrets-backend]
kind = "s3"

[ovstorage.layers.s3-staging-backend]
kind = "s3"

[ovstorage.layers.file-backend]
kind = "file"
# Reached straight from the Router — no byte cache, no retry. The OS
# already caches local files and there is nothing transient to retry.

# Connections: buckets, credentials, and alias rules. Each is owned by one
# Layer instance, named by `target`. The connection's kind is the target Layer's kind,
# so it is not repeated here. Identity is (target, id): `id` is unique within
# the owning Layer, and for an S3 Layer it is also the URL authority the
# connection serves (s3://<id>/). This array is where a runtime add_connection
# serializes back.

# s3-prod-backend owns TWO connections: one backend layer, one wrapper path
# above it, serving two S3 namespaces that `id` distinguishes.
[[ovstorage.connections]]
target = "s3-prod-backend"
id     = "prod"                            # serves s3://prod/*
config = { bucket = "ov-prod", region = "us-west-2" }
credentials = { source = "keyring" }

[[ovstorage.connections]]
target = "s3-prod-backend"                 # same Layer as above
id     = "prod-archive"                    # second namespace: s3://prod-archive/*
config = { bucket = "ov-prod-archive", region = "us-west-2" }
credentials = { source = "keyring" }

[[ovstorage.connections]]
target = "s3-secrets-backend"
id     = "secrets"                         # serves s3://secrets/*
config = { bucket = "ov-secrets", region = "us-west-2" }
credentials = { source = "keyring" }

[[ovstorage.connections]]
target = "s3-staging-backend"
id     = "staging"                         # serves s3://staging/*
config = { bucket = "ov-staging", region = "us-west-2" }
credentials = { source = "env", access_key_id = "${STAGING_KEY}" }
access_mode = "ro"

[[ovstorage.connections]]
target = "alias"                           # owned by the AliasWrapper instance
id     = "my-stuff"
config = { from = "my://stuff", to = "s3://prod/users/me" }
```

An operator reading this can answer the usual questions directly: what does
this talk to (backend-layer entries under `[ovstorage.layers.*]` and their
`[[ovstorage.connections]]`), what processing happens (wrapper layers and their
`inner` links), what the topology is (the root Layer plus the Router's
`children`), and which concerns are shared vs. per-backend (whether a Layer sits
above or below the Router fork).

### Why Routers are still Layers

A wrapper layer has exactly one `inner`. A router layer has multiple `children`. Both are still Layers because both expose the same operational Layer surface after construction. The difference is the factory descriptor's `layer_type`, not a separate runtime API.

Reading the Stack top-down: a wrapper calls `inner`; a backend layer handles the request directly; a router dispatches to one of its children, and each child resumes normal Layer dispatch below it.

### Degenerate compositions

Degenerate but legal cases:

- A root that names a single backend layer is a complete Stack.
- A router with zero children is legal but not useful; it returns `NotFound` /
  `Unsupported` for everything.
- A wrapper without `inner` is invalid.

### Build order

To build the root Stack:

1. **Resolve and validate the spec.** Resolve every named Layer to a manifest
   kind (keyed by `kind`) and verify each kind is provided by a loaded plugin.
   Reject the spec if `root` is undefined; if a reference names something
   undefined; if `inner` appears on a non-wrapper layer; if `children` appears
   on a non-router layer; if a backend layer has any edge field; if a wrapper is
   missing `inner`; if the reference relation contains a **cycle**; or if a
   Layer that **accepts connections** is referenced from more than one place,
   since a connection's `target` must resolve to exactly one instance.
2. **Instantiate bottom-up (post-order).** Start at `root`, recurse through
   `inner` and `children`, and create each Layer after its descendants are
   built. Create backend layers with `create_backend`; create wrappers with
   `create_wrapper` only after `inner` is built; create routers with
   `create_router` only after children are built, passing each child's handle.
3. **Apply persisted connections.** For each `[[ovstorage.connections]]` entry,
   route the connection to its `target` Layer and register it — so a backend
   layer's configured roots (e.g. its S3 buckets) exist *before* any Router
   queries them in the next step.
4. **Build Router routing tables.** For each Router, await `list_address_roots`
   on each built child handle — the call is async and cancellable, so the build
   token unwinds a stalled child — then build the (prefix → child) table and
   subscribe to child update streams. Overlapping roots from different children resolve
   by longest-prefix match; an exact-prefix collision between two children is a
   build error.
5. The result is a single Layer handle for the configured root.

Both construction surfaces converge here. The fluent builders run this whole
sequence inside `.build()` from a declarative spec. The pure-C incremental API
registers named Layer specs and persisted connections, then builds the Stack
from the configured root.

The host stores the root handle and uses it for all subsequent requests. Stack
rebuild (per the existing "Rebuild semantics" section) creates a fresh Stack and
atomically swaps the handle.

## Composition rules

### Inner references

A wrapper Layer holds an `inner` reference to the Layer it wraps (`Arc<dyn Layer>` in Rust, `self._inner` in Python, `std::shared_ptr<Layer>` in C++). Method calls flow down the Stack by each wrapper calling `inner`. A backend layer has no `inner`; a router layer has `children` instead.

```python
class ByteCacheWrapper:
    def __init__(self, inner):
        self._inner = inner    # inner is a Layer handle (possibly Layer-wrapped)
        self._impl = ovstorage._rust.ByteCacheImpl(inner.vtable())

    def vtable(self):
        return self._impl.vtable()

    async def read(self, req):
        return await self._impl.read(req)
```

After composition, the outermost handle exposes the same `OvStorage_LayerVTable` as any other Layer. Wrappers compose by wrapping the result of earlier compositions. Cross-language hops happen exactly where the vtable changes language; same-language adjacency stays in one runtime.

A layer may query what `inner` *can do* — `root_info_for(url)` and the other
introspection slots are the sanctioned way to consult capability hints (for
example, `RedirectFollowerWrapper` checking `supports_write_redirect` before
attempting a redirect-first write, or `CopyRenameFallbackWrapper` probing
`supports_copy` / `supports_rename` before delegating). A layer must never
depend on what `inner` *is* — no kind-sniffing, no downcasting: composition
stays valid only if every child is exchangeable for any Layer advertising the
same roots and hints.

Canonicalization is the `Stack` boundary's job, and it is the one precondition
on "any Layer handle can be a root": a caller that drives a bare Layer without
wrapping it in a `Stack` takes on the canonical-spelling obligation itself.

### URL ownership

URL ownership lives on connection-owning Layers and routers. There are three shapes:

- A **backend layer** (`S3Backend`, `FileBackend`, `HttpBackend`, etc.) owns the URLs of its configured Connections. Each Connection has a URL prefix (`s3://prod/`, `file:///mnt/data/`, etc.); the backend layer uses longest-prefix match across its Connection table to route incoming requests to the right Connection's wire dialect.
- A **connection-owning wrapper layer** such as `AliasWrapper` owns its configured rewrite roots. It may answer `root_info_for` for those roots and rewrite before calling `inner`.
- A **router layer** owns URLs through its children. At build time it calls `list_address_roots` on each child and stores the (prefix → child handle) map; at request time it routes by longest-prefix match across that map.

Pure wrappers don't dispatch by URL ownership — they wrap exactly one `inner` Layer and let inner or a router below them choose the destination. Per-backend Layer composition is achieved by making the Router child point at the outermost wrapper for that destination rather than by URL routing at every wrapper (see "Stack and routing").

A backend layer that doesn't own an incoming URL returns `NotFound` (or `Unsupported`, depending on the slot). It does not delegate, because backend layers have no `inner`. Errors from the owning backend layer are final and never trigger fallback dispatch.

`stat` keeps the existing bare-path directory convenience inside the owning backend layer. For a bare address such as `s3://prod/foo`, the backend layer probes the exact object first and, only if that probe returns a true not-found result, probes the slash-form directory or prefix representation (`s3://prod/foo/`). A request already written in slash form is handled as that exact slash-form request and never probes the bare path. Auth and permission failures from either probe are final.

Note the interaction with `Stack`-entry canonicalization: an **authority-form**
address (`mock://team` — the name sits in the URL authority and the path is
empty) is normalized to its slash form (`mock://team/`) before any layer sees
it, so the exact-object probe is unreachable for that spelling. This is a
declared break with 0.x behavior — see "What this breaks" #14. Path-form
addresses (`s3://prod/foo`) are unaffected.

### Identity vs introspection methods

| Category | Wrapper layer | Backend layer | Router layer | Examples |
|---|---|---|---|---|
| Identity | Local | Local | Local | `descriptor` |
| Introspection (set union) | `self ∪ inner` | Local | Union across children | `list_kinds`, `list_address_roots`, `list_connections` |
| Introspection (per-field mask/override) | Wrap inner result and adjust | Per-Connection | Delegate to child by URL | `root_info_for` |
| Object operations | Call inner inside the wrapper's logic | Handle directly | Delegate by URL to child | `stat`, `read`, `write`, `list`, ... |
| Connection management | Pass through to inner unless connection-owning and named as `target` | Accept calls targeting it | Forward to child named by `target` | `add_connection`, `list_connections`, ... |
| Lifecycle | Local | Local | Local | `drop` |

Defaults are layer-type-aware. Wrapper authors override the methods they actually handle and inherit pass-through for the rest. Backend-layer authors override the slots they need and let the rest return `Unsupported`. Router authors route methods they support and return `NotFound` / `Unsupported` when no child can handle the request.

### `RootInfo` and `Capabilities` composition

`root_info_for(url) -> RootInfo` is the single query that returns **everything the host needs to know about that specific URL or prefix** — capabilities, presentation, provenance, alias state. `Capabilities` is a nested struct inside `RootInfo` carrying only the operation-gate bits. The split is structural: capabilities are about *what the composed Stack exposes to the caller*; the surrounding fields are about *what the route is for*.

`list_address_roots()` returns a snapshot of `RootInfo` values whose `address` fields are roots. If the caller asks for updates, the update stream also carries `RootInfo` additions / updates and root removals by address. `root_info_for(url)` accepts any URL and returns the effective root information selected by longest-prefix, alias, and policy logic.

```text
pub struct RootInfo {
    pub address:        Url,
    pub capabilities:   Capabilities,
    pub visible:        bool,           /* show in pickers; presentation only */
    pub display_name:   Option<String>,
    pub source:         RouteSource,    /* where this root came from */
    pub alias_state:    Option<AliasState>,
    pub icon:           Option<Vec<u8>>,
    pub user_metadata:  UserMetadata,
}

pub struct Capabilities {
    pub range_read_strategy:             RangeReadStrategy,
    pub supports_if_match_write:           bool,
    pub supports_no_overwrite_write:       bool,
    pub supports_native_metadata_patch:    bool,
    pub supports_metadata_rewrite_emulation: bool,
    pub writes_are_atomic:                 bool,
    pub supports_server_side_copy:         bool,
    pub supports_server_side_rename:       bool,
    pub supports_atomic_rename:            bool,
    pub has_real_directories:              bool,
    pub supports_list:                     bool,
    pub supports_recursive_list:           bool,
    pub wants_list_backed_stat:            bool,
    pub populates_subdirectory_metadata:   bool,
    pub address_roots_are_dynamic:         bool,
    pub supports_version_listing:          bool,
    pub version_list_order:                Option<VersionListOrder>,
    pub populates_effective_permissions_on_stat: bool,
    pub supports_access_check:             bool,
    pub supports_watch_directory:          bool,
    pub watch_directory_kinds:             ChangeKindSet,
    pub watch_directory_resumable:         bool,
    pub watch_directory_max_lag:           Option<Duration>,
    pub redirect_size_threshold:           Option<u64>,
}

pub enum RangeReadStrategy {
    Native,            /* backend can fetch requested byte ranges directly */
    CachedReadThrough, /* cache can fetch/cache bounded chunks from a range-capable inner layer */
    MaterializeOnly,   /* use materialize for random access; direct range reads are not efficient */
    Unsupported,
}

pub struct ObjectInfo {
    /* existing metadata fields omitted */
    pub cache_locality: CacheLocality,
}

pub enum CacheLocality {
    CachedComplete,          /* this object/version is available for local random access */
    CachedPartial,           /* some byte ranges are cached; read may fetch missing ranges if policy allows */
    NotCached,
}

pub enum RouteSource {
    Static       { layer: String },        /* from TOML at startup */
    Runtime      { persisted: bool },      /* from add_connection */
    BrokerDelivered { principal: String }, /* received from a broker */
}

pub enum AliasState {
    Live,                                   /* chain terminates at a non-alias root within the hop cap */
    Dangling,                               /* chain terminates nowhere (target does not resolve) */
    ChainTooLong { reason: String },        /* chain exceeded the hop cap or cycled */
}
```

`visible` is presentation only: a root with `visible: false` is omitted from
pickers but remains directly addressable (the compat category for hidden
mounts). **Suppression is different — and it is not a `RootInfo` state,
because a suppressed root is never returned at all.** Suppression is a
configuration directive on the connection-owning wrapper that owns the rule
(`AliasWrapper`). For `Alias("a:" → "b:")` over `Backend("b:")`: the backend
advertises root `b:`; the wrapper projects the caller-space root `a:` (derived
from the matched inner root) and says nothing about `b:` in its
`list_address_roots` / `root_info_for` results. From outside the composition,
the suppressed namespace does not exist — it is reachable only through the
rule that targets it, like an rvalue usable only through a reference. v1
`rewrite_to` mounts suppress their physical target namespace by construction;
plain aliases into an otherwise-visible root leave that root untouched.
(Advertisement of alias roots over suppressed targets: issue #161.)

**Projection and enforcement must agree.** A layer that withholds a root from
its projected introspection results must also refuse operations addressed into
that namespace: `AliasWrapper` returns `NoRoute` for a direct request into a
suppressed namespace, exactly as if the root did not exist — returning
anything more specific would leak the suppressed configuration. The same law
binds policy layers: masking bits or hiding roots in introspection is
presentation; a layer that hides a route it still serves has enforced nothing
— it must intercept the operations too (see "Capability semantics" below).

### Alias resolution: bounded multi-hop chains

`AliasWrapper` rule application **iterates** — resolution follows chains of
`from`→`to` rules rather than applying a single rewrite (issue #172):

1. At each step, if a real root matches the current address with a **longer
   prefix than any rule**, resolution stops and the address dispatches to that
   root (the specificity rule, applied per hop).
2. Otherwise the longest-prefix rule rewrites the address and resolution
   repeats — guarded by a fixed hop cap (8) and a seen-set; a breach is
   `ChainTooLong`.

Chains are load-bearing, not a convenience: because rewrite targets are
suppressed (never projected), forbidding chains would force a user alias into
a rewrite mount to hard-code the hidden physical namespace — exactly the
coupling suppression exists to prevent. Rules compose against caller-visible
names; a chain through a suppressed intermediate namespace is the normal case
(the 0.x alias→`rewrite_to` behavior is the N=2 instance).

Resolution iterates at dispatch; it is **not** compiled to single-hop rules at
configuration time. Eager composition is subtle under overlapping target
sub-prefixes (with `a: → b:`, `b:sub/ → d:`, and `b: → c:`, the address
`a:sub/y` must resolve via the longer rule at the second hop), while per-hop
longest-prefix selection against the actual intermediate address is correct by
construction and costs only a few in-memory lookups.

Reverse projection iterates symmetrically: result addresses map back through
inverse rules, longest-prefix per hop, until no rule matches — the outermost
caller-space spelling — and applies only to results of requests that were
forward-rewritten. Validation is eager: `create_alias` rejects cycles and cap
breaches (`ChainTooLong`) at configuration time and advertises unterminated
chains as `Dangling`; a dispatch-time `NoRoute` from a broken chain occurs
only under concurrent rule removal.

`RootInfo` is **per-root** even when queried with a deeper URL: a backend layer with multiple internal Connections answers from the Connection whose configured prefix is the longest match for `url`.

Composition rules:

- A **backend layer** answers from the Connection that owns the longest-matching prefix for `url`. If no Connection matches, it returns `NotFound`; backend layers have no `inner` and do not delegate.
- A **router layer** delegates to whichever child serves `url` (longest-prefix match across the routing table built from `list_address_roots`).
- A **wrapper layer** computes `let mut info = self.inner.root_info_for(url).await?` and adjusts:
  - **`capabilities`**: set to the Layer's caller-visible effective behavior. Most Layers only mask bits; some add behavior they implement themselves (for example, metadata-rewrite emulation, cache-backed `materialize`). A policy-enforcing Layer (such as one a broker daemon composes) strips bits forbidden by policy.
  - **`visible`**, **`display_name`**, **`icon`**: override permitted. A policy-enforcing Layer may set `visible: false` for a policy-hidden route (and must also intercept the ops it forbids — see "Capability semantics" below); a UI-hint Layer may rewrite `display_name`. A wrapper may also **omit** a root from its projected results entirely — in which case it must refuse direct operations into that namespace with `NoRoute` ("projection and enforcement must agree", below).
  - **`alias_state`**: set by `AliasWrapper` based on its alias rules; left as `inner.alias_state` otherwise.
  - **`source`**: passed through unchanged. Only backend layers set `source`; wrappers preserve it.
  - **`user_metadata`**: merged (caller-owned metadata accumulates as it flows up; later Layers override on key collision).

Composition is associative. Capabilities are effective at the point where they are returned; Layer authors decide whether their implementation preserves, masks, or synthesizes caller-visible behavior. Presentation and alias-state fields can be set anywhere in the Stack.

### Capability semantics: hints, not enforcement

`Capabilities` bits are **hints**: they exist so callers can avoid round-trips
that cannot succeed and so UIs can grey out unsupported actions. They are not
an enforcement mechanism, and no Layer pre-gates an operation on another
Layer's behalf. The enforcement contract is:

- **Backend layers behave sensibly when called anyway.** A backend layer that
  does not support an operation returns `Unsupported` (or the appropriate
  typed error) with no side effects when a caller ignores the hint and calls
  the slot regardless. This self-gate is a conformance-tested contract, not a
  convention (scenarios tracked in issue #170).
- **Masking a capability bit is not enforcement.** A wrapper that strips a bit
  from `root_info_for` results changes the hint only. A policy-enforcing Layer
  (for example `PermissionCheckWrapper`, or a broker-composed policy Layer)
  must also intercept the operation slots it forbids and reject them.
- **Connection-level restrictions are enforced by the owning backend layer.**
  A connection with `access_mode = "ro"` is the owning backend's state; the
  backend rejecting mutations on it *is* "behaving sensibly," not host gating.
- **The v1 compatibility adapter is the one place host-style gating remains.**
  v1 plugins were written against the inverse contract (the v1 dispatcher
  gated; backends did not self-check), so `CompatBackendLayer` reproduces the
  v1 per-route capability gates on their behalf until every v1 cdylib is
  ported.

Range reads are intentionally not represented as a simple boolean. A client that needs random access to a large object first calls `root_info_for(url)` and inspects `range_read_strategy`: `Native` and `CachedReadThrough` are suitable for direct range reads; `MaterializeOnly` means the client should call `materialize()` before doing local random access; `Unsupported` means the backend cannot efficiently serve random access. `stat(url)` returns `ObjectInfo.cache_locality` so a cache can report that a specific object/version is already locally available even when the root's normal strategy is weaker.

`wants_list_backed_stat` lets `MetadataCacheWrapper` optionally answer eligible `stat` calls from a cached or freshly fetched parent `list` entry. Eligibility is narrow: the request is unversioned, not a directory stat, does not ask for full metadata, and the list entry carries stat-equivalent identity. This is only a cache optimization; the owning backend layer still implements real `stat` semantics.

### Connection management routing

When the application calls `root.add_connection({target: "s3-prod-backend", id: "prod", config: {...}})`:

1. Outer **wrapper layers** pass through to `inner` (the default behavior). A connection-owning Layer (e.g. `AliasWrapper`) consumes the request only when `target` names it; everything else passes through. Because `target` is required, a wrapper never greedily consumes a matching-kind request and so never shadows an inner same-kind owner.
2. A **router layer** forwards to the child whose subtree owns `target` — resolved through the (target → child) map it built by querying each child's `owned_targets` at construction. A **backend layer** accepts the call when `target` names it and registers the Connection in its internal table, interpreting `config` according to its own kind; a `target` that no reachable Layer owns returns `NotFound`, and a `target` that names a Layer which doesn't accept connections (a pure wrapper or a router) returns `Unsupported`.

Because connections are addressed by `target`, multiple backend layers of the
same kind (`s3-prod-backend`, `s3-secrets-backend`, `s3-staging-backend`) are
unambiguous — each is a distinct Layer instance name. The `target` is the
owning Layer instance (e.g. `s3-prod-backend`); the Router maps the Layer name
to the right child via that child's `owned_targets`. Config and lifecycle ops
(`remove_connection`, `update_connection_attributes`) route to the Layer that
owns `(target, id)` and mutate that Connection directly. Auth ops
(`update_connection_credentials`, `authenticate_connection`) also start at
`(target, id)`, but a connection-owning wrapper may delegate them. For example,
`AliasWrapper.authenticate_connection("alias", "my-storage")` resolves the alias
target and forwards to the downstream auth-bearing backend Connection while
preserving `my-storage` as user-facing context. This matches the config surface,
where `[[ovstorage.connections]]` entries carry `target = "<layer-name>"` (see
"TOML configuration").

For `target` to name exactly one Layer instance, the Stack topology is a tree of
configured Layer names: the builder rejects any spec that references the same
Layer name from more than one place. A Layer that should appear in two branches
must be declared twice under distinct names. Template expansion therefore never
yields two instances that collide on a `target` name, and connection routing can
treat each reachable target as owned by exactly one subtree.

`list_connections()` aggregates the snapshot. A Router merges its children's snapshots into one unified result; on update streams, it multiplexes children. A **connection-owning** Layer returns its own Connections unioned with inner's (`self ∪ inner`, per the identity table — e.g. `AliasWrapper` includes its alias rules); a **pure** Layer passes inner's through, optionally hiding or annotating entries (e.g. a permission-filter Layer omits entries the principal can't see).

The Stack always reaches either a backend layer or a router layer, so an unrouteable `add_connection` has a definite answer — `NotFound` for an unknown `target`, or `Unsupported` when the named Layer doesn't accept connections. There's no synthetic fallback at the bottom because each Layer type defines its terminal/default semantics.

### Streaming invariant

Every Layer that handles `Body::Stream` or `ReadResult::Stream` forwards chunk-by-chunk; no Layer drains a stream into a buffer. Each ships a `streaming_invariant` test asserting peak in-flight bytes ≤ chunk-size × small-const.

## Built-in Layer factories vs. plugins

A **built-in** Layer factory is one that's available without loading a cdylib.
A **plugin** Layer factory ships as a cdylib that the host loads at runtime
(via the C ABI we've designed). Built-in and plugin factories produce the same
runtime thing: an `OvStorage_LayerHandle`.

What counts as "built-in" depends on which language distribution you're using:

| Distribution | What's built-in | How |
|---|---|---|
| Rust `ovstorage` crate | All the "no external deps" Layer factories (see table below) | statically linked into the crate |
| Python wheel | Same set as Rust | the wheel bundles the Rust crate's native code |
| Pure-C source distribution | `FileBackend` plus the dispatcher and plugin loader | C source files the customer compiles with their app |

The pure-C distribution intentionally has a smaller built-in set than the Rust
crate. We don't reimplement every Layer factory in pure C — we ship just enough
to (a) compose a working Stack from cdylibs and (b) handle `file:` URLs
out of the box.

### Layer factory dependencies and shipping form

The shipping-form decision is driven by dependency weight, not policy:

| Layer factory | `layer_type` | External deps | Rust crate / Python wheel | Pure-C source | Shipping artifact |
|---|---|---|---|---|---|
| `FileBackend` | backend | libc / POSIX / Win32 | built-in | built-in | `file_backend.c` |
| `CopyRenameFallbackWrapper` / `AliasWrapper` / `RetryWrapper` | wrapper | none / timer | built-in | plugin | `libovstorage_core` |
| `Router` | router | none | built-in | plugin | `libovstorage_core` |
| `MetadataCacheWrapper` / `ByteCacheWrapper` | wrapper | in-memory / sqlite (bundled, no network) | built-in | plugin | `libovstorage_cache` |
| `RedirectFollowerWrapper` / `HttpBackend` | wrapper / backend | HTTP client | plugin | plugin | `libovstorage_http` |
| `S3Backend` | backend | AWS SDK / HTTP + signing | plugin | plugin | `libovstorage_s3` |
| `AzureBackend` | backend | Azure SDK / HTTP + signing | plugin | plugin | `libovstorage_azure` |
| `GcsBackend` | backend | GCP SDK / HTTP + signing | plugin | plugin | `libovstorage_gcs` |
| `NucleusBackend` | backend | Nucleus client / auth | plugin | plugin | `libovstorage_nucleus` |
| `ServicesClientBackend` | backend | HTTP/gRPC storage API client | plugin | plugin | `libovstorage_services_client` |
| `BrokerClientBackend` | backend | gRPC (tonic) | plugin | plugin | `libovstorage_broker_client` |

The "Rust crate / Python wheel" column reflects what's available in any Rust / Python app that links `ovstorage` with no cdylib loads. The "Pure-C source" column reflects what's in `ovstorage-c-source/src/`. The shipping-artifact column names either the pure-C source file or the cdylib that provides the kind.

### What the pure-C distribution always provides

The C source set is intentionally minimal:

1. **Dispatcher + Stack construction** (`dispatch.c`): validates a named
   Stack, instantiates its Layers, wires `inner` / `children`, and returns
   the root `OvStorage_LayerHandle*`. Runtime calls walk the Layer links from
   that root handle.
2. **Plugin registry + loader** (`dispatch.c`): registry-resolved APIs for
   config-driven construction plus explicit plugin-handle APIs for advanced
   callers. The builder reads each kind's `layer_type` from the manifest and
   validates the shape accordingly — backend layers have no child, wrapper
   layers have one `inner`, and router layers have `children`.
   - `ovstorage_load_plugin("/path/to/cdylib.so", &err)` opens the cdylib, validates the manifest, calls init, and returns an `OvStorage_Plugin*` handle that owns the cdylib and plugin-scoped state.
   - `ovstorage_registry_add_plugin(registry, plugin, &err)` registers the plugin's manifest kinds in the stack-builder registry.
   - `ovstorage_stack_add_layer(stack, registry, "s3-prod-retry", "retry", config, &err)` resolves the kind through the registry and records a fresh Layer instance named by `instance_id`.
   - `ovstorage_stack_set_root(stack, "copy_rename_fallback", &err)` names the application-facing Layer.
   - The `instance_id` is the Layer's name within the Stack — the same handle `ovstorage_stack_add_connection`'s `target` refers to, the `[ovstorage.layers.<name>]` table key in TOML, and the `instance_id` field on the relevant create request. It must be unique within the built Stack; that uniqueness is what lets two `s3` backend layers (`s3-prod-backend`, `s3-secrets-backend`) coexist and be addressed unambiguously by `add_connection`.
   - `*_from_plugin` variants take the same `instance_id` + kind but bypass registry resolution, building from a specific plugin handle — for tests, custom embedders, or ambiguous provider cases.
   - `ovstorage_stack_set_inner(stack, "s3-prod-retry", "s3-prod-backend", &err)` records the `inner` edge for a wrapper Layer. The builder validates that the source Layer's factory descriptor has `layer_type = "wrapper"`.
   - `ovstorage_stack_set_children(stack, "main-router", child_names, child_count, &err)` records the `children` edges for a router Layer. The builder validates that the source Layer's factory descriptor has `layer_type = "router"`.
   - `ovstorage_stack_add_connection(stack, "s3-prod-backend", "prod", config, credentials, &err)` records a Connection on the builder, owned by the Layer named in the `target` argument. The builder applies it during `build` — "Build order" step 3 — so the Layer's roots exist before any Router's routing table is built in step 4. It is the construction-time counterpart to the operational `add_connection` vtable call: pre-`build` you register `(target, id)` through the builder; after `build`, the same `(target, id)` registration is the operational `add_connection` on the built root handle, used for runtime changes.
   - `ovstorage_stack_build(stack, &err)` finalizes the Stack and returns the root `OvStorage_LayerHandle*`. It instantiates backend layers, wrappers, and routers bottom-up from `root`, then calls `list_address_roots` on each Router child to construct routing tables. Call it exactly once after all Layer declarations, edges, and connections have been added; the builder is consumed and the resulting Stack is immutable.

A single-call convenience for the common case:
`ovstorage_stack_load_and_add_layer(stack, registry, path, "s3-prod-backend",
"s3", config, &err)` loads a plugin, registers it, and records the named kind
according to its `layer_type`.

Routers are not a separate builder mode. A Router is just a Layer with
`children`; the config loader reads those names from TOML, and the incremental
builder records them through `ovstorage_stack_set_children`. Both paths validate
the child names, build each child handle, and pass them to `create_router`.

3. **`file_backend.c`** (pure-C `FileBackend`): the built-in filesystem handler.
4. **`cancel.c`**: atomic-flag cancel token, no async runtime required.
5. **`runtime.c`**: thread-pool-backed callback dispatch.

A pure-C app that links nothing else gets `file:` operation plus the ability to
load any cdylib for extra schemes. To talk to S3, the app loads
`libovstorage_s3.so`, registers the plugin, records an `s3` backend Layer, and
either sets that Layer as the root or names it as a Router child. The cdylib
itself is built from the Rust workspace (same source as the Rust-crate plugin);
the C app is just the loader.

### Why source, not a prebuilt library

The distribution ships buildable C source, not a prebuilt
`libovstorage_static.a`. The deciding factor is *linkage*, not a general
"binary vs. source" preference:

- **The C host and built-in `file:` backend are statically linked into the
  consumer's binary.** An `ov*` library such as `ovrtx` embeds ovstorage so
  `ovrtx.load(file)` works self-contained. Statically-linked code must match
  the consumer's exact platform × libc × compiler × flags; a prebuilt static
  lib reintroduces the artifact-matrix problem that made binary distribution
  untenable in the predecessor project. Vendored source compiles into any
  consumer's build for any target they already support, with no
  prebuilt-artifact matrix to produce or version-match.
- **Backends (`s3`, `http`, …) are dynamically loaded cdylibs.** A `.so` only
  has to match the frozen ABI at `dlopen` time — decoupled from the
  consumer's build — so backends stay single-sourced as Rust-built cdylibs.
  This asymmetry is why prebuilt backend binaries are acceptable while a
  prebuilt static core is not.
- **`file:` is compiled in** (rather than shipped as a `.so`) so the baseline
  needs nothing else — no companion library to ship, locate, or
  version-match. The cost is a from-scratch C implementation of the host plus
  the file backend that must stay behaviorally faithful to the Rust
  reference; a shared cross-host conformance suite (running the same vectors
  against both hosts) is the intended guard against drift.

### Discovery and introspection

The plugin manifest carries Layer factory descriptors as static data — hosts can read them from a cdylib without initializing the plugin or instantiating anything. This decouples *discovery* ("what kinds are available?") from *loading* ("make this plugin available to create instances"). A separate symbol or callback is not needed: `ovstorage_inspect_plugin("/path/to/cdylib.so", &err)` reads only the manifest (which includes the kind descriptors), without calling init or constructing any instances.

The CLI's startup flow:

```
ovstorage read s3://prod/file.txt
  |
  1. Parse the URL. Scheme = "s3".
  |
  2. Walk plugin search paths (e.g. /usr/lib/ovstorage/plugins,
     ${OVSTORAGE_PLUGIN_DIR}, ~/.local/lib/ovstorage/plugins).
     For each .so, read the manifest only:
        ovstorage_inspect_plugin(path) -> manifest
     Build an in-memory map { kind_name -> plugin_path }.
  |
  3. Look up "s3" in the map. Find /usr/lib/ovstorage/plugins/
     libovstorage_s3.so (which declares kind s3 in its manifest's
     layer_type-tagged `kinds`).
  |
  4. Load only that plugin:
        ovstorage_load_plugin(path, &err) -> OvStorage_Plugin*
     Now it has plugin-scoped state ready for layer creation.
  |
  5. Record the s3 backend layer (instance "s3", kind "s3") and make it
     the CLI Stack root:
        ovstorage_stack_add_layer(stack, registry, "s3", "s3", config)
        ovstorage_stack_set_root(stack, "s3")
     Only the requested kind is instantiated.
  |
  6. Apply the matching connection from the user's config: the s3
     "prod" connection (bucket + credentials), via
     ovstorage_stack_add_connection targeting the s3 Layer.
     Bucket/region/credentials are connection state, not
     Layer config, so without this the Layer owns no
     URLs and serves nothing.
  |
  7. Finalize the Stack:
        ovstorage_stack_build(stack, &err) -> OvStorage_LayerHandle*
     This Stack has no Router, so the routing-table step is a
     no-op, but build is the call that yields the usable root handle.
  |
  8. Execute the read.
```

Other introspection use cases the manifest covers:

- **`ovstorage plugins list`**: walks the plugin dirs, reads each manifest, prints `(plugin_name, version, kinds_provided)`.
- **`ovstorage kinds list`**: aggregates kinds across all manifest reads, shows `kind`, `display_name`, `description`.
- **`ovstorage kinds describe s3`**: reads the manifest of whichever plugin provides `s3`, prints config schema and credential schema for UI / scripting.
- **UI form generation**: a graphical configurator reads manifest descriptors and renders a configuration form from `config_schema` / `credential_schema` without instantiating any Layer.

For applications that don't need lazy loading (e.g. a long-running service that wants all plugins available up front), there's a convenience: `ovstorage_load_plugins_from_dir(handle, dir, &err)` loads every plugin in a directory and registers their manifests / create handles. The CLI uses the lazy path; daemons may use either.

### What every host language exposes uniformly

Regardless of language, every host can:

- Build a Stack from Layer instances (some built-in to the host, others loaded from cdylibs).
- Load any cdylib that conforms to the storage plugin ABI into a plugin registry.
- Compose the same root Layer surface with the same per-call semantics.

So a pure-C app and a Rust app can both load `libovstorage_s3.so` and end up
with the same `S3Backend` in their Stack. The only difference is what was
statically available before the load.

### `FileBackend` in the default Stack

The default `Stack()` builder includes a `FileBackend` among its Router's
children **and installs an implicit `file:///` Connection on it** (a read-write
root mount). This means a bare `Stack.default().read("/tmp/data.txt")`
works without any explicit setup — native paths and `file:` URLs resolve through
that default mount. Backend layers of other kinds start with no Connections (so
they own no URLs until one is added via `add_connection`); `FileBackend` is the
exception precisely because a local-filesystem root needs no credentials or
endpoint configuration.

```python
stack = Stack.default()           # default — includes FileBackend
stack.read("/tmp/data.txt")       # works
stack.read("file:///tmp/data.txt") # also works

stack = Stack.empty()             # no layers configured
stack.read("/tmp/data.txt")       # Unsupported
```

Sandboxed contexts (render workers, CI runners, untrusted code paths) construct
their Stack with `Stack.empty()` and add only the Layer factories they
explicitly want.

### Native-path normalization

Inputs like `/tmp/data.txt` (Linux/macOS) and `C:\Users\name\data.txt`
(Windows) are not URLs. The library normalizes them to `file:///tmp/data.txt`
and `file:///C:/Users/name/data.txt` respectively before they enter the Layer
Stack. Every Layer receives URL-shaped addresses regardless of where it sits in
the Stack.

Normalization rules:

- A string with no `scheme://` prefix is assumed to be a native path. The library applies platform-specific normalization (absolutize, convert `\` to `/` on Windows, percent-encode reserved characters).
- A string starting with `~/` is expanded to the user's home directory before normalization.
- A string with a Windows drive letter (`C:`, `D:`, ...) is treated as native.

The `FileBackend` only ever receives `file:` URLs (in their canonical
three-slash form, e.g. `file:///tmp/data.txt`). The normalization is the
library's responsibility, not the `FileBackend`'s. Configured file roots are
exported namespace boundaries, not realpath jails: the backend rejects caller
spellings that lexically escape a configured root, but symlinks located under
that root may resolve elsewhere on disk because operators use them to assemble
virtual trees intentionally.

## Layer taxonomy

Concrete in-tree Layer kinds under this model:

### Backend layers (0 children)

| Backend layer | Built-in / plugin | What it implements meaningfully |
|---|---|---|
| `FileBackend` | built-in | object ops via local filesystem; the sole built-in public Layer |
| `HttpBackend` | plugin | object ops via HTTP(S), Connection per (base URL, auth) |
| `S3Backend` | plugin | object ops via S3 API, Connection per bucket |
| `AzureBackend` | plugin | object ops via Azure Blob Storage API, Connection per container or account scope |
| `GcsBackend` | plugin | object ops via Google Cloud Storage API, Connection per bucket |
| `NucleusBackend` | plugin | object ops via Nucleus services, Connection per server/root scope |
| `ServicesClientBackend` | plugin | talks to the Omniverse Storage Service storage API; appears as one or more configured Connections |
| `BrokerClientBackend` | plugin | talks to a remote `ovstorage-broker` endpoint; exposes broker-delivered roots through one configured broker endpoint |

### Wrapper layers (1 child, `inner`)

| Wrapper layer | Built-in / plugin | What it implements meaningfully |
|---|---|---|
| `AliasWrapper` | core plugin | connection-owning: accepts `from`→`to` Connections that target its `alias` Layer instance and rewrites matching addresses before delegating, reverse-mapping returned addresses back to caller space. This `from`→`to` rewrite is also how v1 `route.rewrite_to` mount/prefix translation is expressed — there is no separate rewrite layer. Resolution follows rule chains up to a fixed hop cap (see "Alias resolution: bounded multi-hop chains"). (URL canonicalization is the `Stack` boundary's job, not this layer's; see "URL canonicalization" below.) |
| `CopyRenameFallbackWrapper` | core plugin | serves two-address `copy` / `rename` by read+write (plus source delete for `rename`) whenever the layer below declines the operation |
| `RetryWrapper` | core plugin | idempotent retry on `Transient` |
| `ByteCacheWrapper` | cache plugin | byte cache lookup + commit for `read` |
| `MetadataCacheWrapper` | cache plugin | result cache for `stat`, `list`, `list_versions`, `get_latest_version`, `check_access`, `root_info_for`; optional list-backed `stat` optimization when `wants_list_backed_stat` applies |
| `RedirectFollowerWrapper` | HTTP plugin | executes plugin-returned `Redirect` requests |
| `PermissionCheckWrapper` | plugin | enforces a host-supplied permission policy on operations for matching routes (e.g. an extra gate on a secrets bucket); used in the "Stack and routing" example |

### Router layers (many children)

| Router layer | Built-in / plugin | What it implements meaningfully |
|---|---|---|
| `Router` | core plugin | dispatches to multiple child Layers by URL prefix; builds the routing table via `list_address_roots` on each child |

Plugins may bundle multiple kinds when their dependencies and lifecycle are naturally shared. The core, cache, and HTTP plugins are bundles; cloud SDK-backed backend layers typically ship as separate cdylibs because their SDK dependencies differ. The host statically provides only `file`; every other public Layer kind must be loaded or supplied natively by the embedding application.

## Default application Stack

A typical application configuration assembles this root Stack from the
file host factory and the installed public plugins:

```
[application]
      ↓
Stack                       <- canonicalizes every address-bearing request
                             (the layer-chain entry boundary)
      ↓ root
AliasWrapper                <- alias / mount URL rewriting + visibility /
                             discovery (the from→to rewrite also covers
                             v1 route.rewrite_to mount translation)
  ↓ inner
CopyRenameFallbackWrapper    <- copy / rename fallback when the layer below
                             declines; sits below alias so it transfers
                             already-rewritten addresses
  ↓ inner
MetadataCacheWrapper        <- caches stat / list / list_versions /
                             get_latest_version / check_access /
                             root_info_for
  ↓ inner
ByteCacheWrapper            <- byte cache for read
  ↓ inner
RetryWrapper                <- idempotent retry on Transient /
                             ResourceExhausted
  ↓ inner
RedirectFollowerWrapper     <- executes backend-returned Redirect requests
  ↓ inner
Router:
  routes by URL prefix to:
      ├── S3Backend       (Connections per bucket)
      ├── HttpBackend     (Connections per base URL)
      ├── FileBackend     (Connections per mount point)
      └── ...
```

Each Layer's position is meaningful:

- **Stack canonicalizes at the chain entry**: the `Stack` normalizes every address-bearing request to a canonical URL spelling *before* any layer (including the wrappers above) sees it, so alias resolution, cache-key identity, and routing all key off one spelling. The contract is enforced in `Stack` itself — not a caller-side facade — so a consumer driving the `Stack` API directly (e.g. through the C ABI) cannot bypass it.
- **CopyRenameFallback below Alias**: the fallback composes *under* every address-rewriting layer, which is where all four shipped configurations place it (`alias.inner = copy_rename_fallback`). It therefore sees addresses that aliases have already rewritten. This ordering is load-bearing, not stylistic: the emulation refuses to run when source and destination name one object, and there is no address-resolution slot in the SPI, so a rewriting layer below this one could collapse two distinct caller addresses onto one object after that check has passed — the emulation would write the object onto itself and, for `rename`, delete the only copy. Whether the fallback *engages* is decided by the layer below declining the operation — a `false` `supports_copy` / `supports_rename` on the source root, or an `Unsupported` answer — never by comparing the two roots. Root topology is not a proxy for capability: keying on it made a stack serve a cross-root `copy` while rejecting the same-root one.
- **Alias above the caches**: cache keys see post-alias (post-`from`→`to`-rewrite) URLs, not user-typed aliases or caller-facing mount prefixes.
- **MetadataCache above ByteCache** (convention; they handle disjoint methods so order doesn't affect correctness): the smaller, faster cache sits higher.
- **Caches above Retry**: cache hits don't pay retry overhead.
- **Retry above RedirectFollower**: a transient error during a redirect bubbles as `Transient`; Retry re-invokes RedirectFollower, which re-asks the backend layer for a fresh redirect (handles presigned-URL expiry naturally).
- **RedirectFollower above the Router**: the Router doesn't see redirects; only the Layer responsible for following them does.

This default keeps the caches and retry **above** the Router, treating every
backend layer uniformly — including `file:` reads, which get a redundant but
harmless byte-cache pass. It is the simple common case. A host that wants
per-backend treatment — skipping the byte cache for `file:` or a secrets bucket,
or giving one backend stricter retry — makes the Router child point at a
destination-specific wrapper path, exactly as the "Stack and routing"
worked example shows. Layer ordering and placement are per-host configuration,
not a global constant.

### Redirect credential disclosure

A redirect carries a credential, and whether the host may hand it to the
caller that asked for it is a property of the **deployment**, not of the
credential. A broker is not always a credential boundary: it is sometimes a
central configuration point for clients that are already inside the trust
boundary, and refusing them a redirect costs the performance the redirect
exists for. So it is an operator setting, `redirect_credential_disclosure`,
governing the read and the write path identically.

The host cannot decide it by inspection. An account-wide signature and one
scoped to a single object are byte-identical on the wire, so the property is
**declared by the minting backend** on `RedirectScope.credential`
(`None` / `Request` / `Connection` / `Unspecified`). `Unspecified` is
fail-safe: a host treats it exactly as `Connection`. Inspection remains as a
one-way check that can lower a declaration and never raise one, so a backend
that declares a request-scoped credential and attaches a header the host
cannot account for costs a proxied transfer rather than a disclosure.

Enforcement sits in two places, answering different questions. The
`redirect_follower` Layer applies it where a refusal is still graceful — it
holds the connection and fetches the bytes itself. Each host applies it again
at its own out-edge, because the Layer graph is operator configuration: a
graph that renames or omits the follower would otherwise lose the policy
silently, and the host would forward whatever the graph left it. Grace in the
Layer, guarantee at the boundary.

### Byte-cache identity

`ByteCacheWrapper` keys byte rows by `(policy partition, canonical post-alias URL, etag)`. The identity intentionally does **not** include `backend_id`, connection id, route id, or backend-layer provenance. The URL component is the address visible below `AliasWrapper` (post-`from`→`to` rewrite); the policy partition is the cache-sharing boundary supplied by host policy; and the `etag` must be a byte-identity validator for that URL.

There are no URL-only byte-cache hits. If a request cannot be associated with an etag, `ByteCacheWrapper` skips byte caching for that object and passes through. It does not synthesize an alternate weak validator from size, modified time, route identity, or other metadata.

Sharing the same cached bytes for the same canonical URL and same etag across overlapping backend layers is intentional. If two configured backend layers can serve the same URL, they may co-hit only when they report the same etag for that URL and the request is in the same policy partition.

## Behavior placement

| Behavior | Owner |
|---|---|
| URL rewriting (aliases + caller→physical mount/prefix translation) | `AliasWrapper` `from`→`to` connections (targeting the `alias` Layer instance) — bounded multi-hop resolution (see "Alias resolution: bounded multi-hop chains") |
| Bare-path `stat` fallback from exact object to slash-form directory/prefix representation | owning backend layer |
| Backend-specific stat behavior for objects vs. directories | owning backend layer |
| URL canonicalization (lowercase scheme, IDN punycode, default-port strip, empty-authority-path normalization, and the path pipeline: decode escapes, collapse runs of `/`, resolve dot segments, drop the fragment, re-encode once — the trailing slash is never added or removed) | `Stack` at the chain entry (re-applies the rule on every address-bearing request) and `address::parse` at the string→`Url` boundary — so every layer below sees one canonical spelling |
| Byte cache (`read` results) | `ByteCacheWrapper` keyed by policy partition + canonical post-alias URL + etag; no backend id and no URL-only hits |
| Byte-cache invalidation on write | `ByteCacheWrapper` (hooks `write` / `delete` / `rename` to invalidate the dest) |
| Range reads | owning backend layer when native; `ByteCacheWrapper` when cached or when doing bounded read-through from a range-capable inner; otherwise `MaterializeOnly` / `Unsupported` |
| Metadata cache (`stat`, `list`, `list_versions`, `get_latest_version`, `check_access`, `root_info_for`) | `MetadataCacheWrapper` |
| Optional list-backed `stat` cache hits for eligible unversioned object requests | `MetadataCacheWrapper` (uses cached/fresh parent `list` entries when `Capabilities.wants_list_backed_stat` is true; backend layers still own real `stat`) |
| Metadata-cache invalidation on mutation | `MetadataCacheWrapper` (hooks every mutation; fans out to parent-prefix entries) |
| Watch-driven freshness for cached metadata (optional) | `MetadataCacheWrapper` subscribes to `watch_directory` on routes that support it |
| `materialize` — return a `LocalDelegate` path | `FileBackend` (returns the file's own path, no guard); `ByteCacheWrapper` (returns inner `file://` / `FileBackend` delegates unchanged, otherwise returns its cached row with a live lease only when the full byte-cache identity is known). Other wrapper layers pass through; other backend layers return `Unsupported`. |
| Idempotent retry on `Transient` / `ResourceExhausted` | `RetryWrapper` |
| HTTP-level retry on redirect-followed requests (`Retry-After`) | `RedirectFollowerWrapper` (internal) |
| Following backend-returned `ReadResult::Redirect` / `WriteStep::Redirects` | `RedirectFollowerWrapper` — converts redirect responses into byte streams. **Omitting this Layer is how a host opts into "see the raw redirect" semantics** (REST gateway, broker daemon). |
| Write-protocol selection — whether a caller's `write` / `write_stream` is attempted redirect-first | `RedirectFollowerWrapper` (write path), consuming the `supports_write_redirect` / `redirect_size_threshold` hints via `root_info_for`; `Unsupported` fall-through to the body-typed slot preserves correctness when hints are stale or absent. An **explicit** `write_redirect` call is never threshold-gated — the caller asked for the plan. |
| `Body::Stream` chunk-by-chunk forwarding | every Layer (streaming-invariant test per kind) |
| Multipart upload part buffering | `RedirectFollowerWrapper` (documented streaming-invariant exception — see "Operation flow walkthroughs § S3 multipart upload") |
| Cancellation propagation | every Layer (token threaded through every async method) |
| Routing across child Layers by URL prefix (and connection ops by `target` name) | `Router` |
| Address-level routing across multiple Connections of one kind | owning backend layer (e.g. `S3Backend` does longest-prefix match across its registered buckets) |
| Per-Connection auth state, refresh, interactive flow | owning backend layer (`S3Backend`, `HttpBackend`, ...) |
| Persistent secret storage | host-callback secret store (local SQLite, encrypted file, HSM, broker-mediated) |
| Server-side same-root `copy` / `rename` when supported | owning backend layer |
| `copy` / `rename` fallback | `CopyRenameFallbackWrapper` delegates inward first, so a backend advertising a server-side op performs it; when the layer below declines — a `false` `supports_copy` / `supports_rename`, or an `Unsupported` answer — it composes read/write/delete instead. Differing roots are one reason a layer declines, not a precondition for the fallback |
| Multipart upload state machine | owning backend layer (across multiple `continue_write` calls) |
| Brokered authorization | broker server internal logic (loads authz cdylibs that have their own separate ABI, distinct from the storage Layer ABI); not a storage Layer |
| Remote dispatch | `BrokerClientBackend` (backend layer on application) |

### Write slots: one operation for callers, a cooperative protocol underneath

The vtable's four write slots are two operations, both first-class on the
uniform surface (API = SPI holds — any caller may invoke any slot):

- **`write` / `write_stream`** — "store this body." Variants by *input shape*
  only (buffered vs. streamed); a caller never expresses how it expects the
  server to behave.
- **`write_redirect` / `continue_write`** — "plan a write; I will execute the
  transfers and report back." A cooperative protocol for callers that move
  bytes themselves: `RedirectFollowerWrapper` on behalf of body-typed callers,
  or raw-redirect hosts (REST gateway, broker) that forward the plan onward.

The split exists because of body ownership across the ABI: the redirect
*executor* holds the body and slices it per round
(`RedirectBodySource::UserBytes`), while the backend plans by `size_hint`
without ever seeing bytes — a backend cannot "return a redirect from `write`"
once a streamed body has crossed the boundary. This also explains the
read/write asymmetry: read redirects are a *result variant* of the one `read`
slot (there is no caller body to hand back, so the follower intercepts `read`
and converts), while write redirects are a *separate slot* (the follower
converts by translating `write` → `write_redirect` below itself). A
consequence worth knowing: `write_redirect` returns the raw plan even through
a Stack that composes a follower — the follower only follows plans it
solicited for a body-typed write; it has nothing to execute a direct plan
request with.

**Per-slot contract** (uniform-surface obligations every wrapper inherits;
conformance scenarios in issue #170):

- **Mutations commit at `continue_write → Done`, not at `write_redirect`.** A
  plan request is not a mutation. Mutation-observing wrappers (caches, audit,
  permission enforcement) hook the `Done` step of `continue_write` exactly as
  they hook `write` — `ByteCacheWrapper` is the model implementation.
- **`RetryWrapper` never retries `continue_write`.** The continuation is
  opaque backend state; replaying it can double-apply executed parts.
- **Protocol slots default to pass-through.** A wrapper that does not
  understand the write-plan protocol forwards `write_redirect` /
  `continue_write` untouched.

## Specialized host Stacks

The default Stack fits applications. Specialized hosts diverge by omitting or
inserting specific Layers, or by choosing a different root path and terminal
backend/router shape:

| Host | Root Stack | Why |
|---|---|---|
| Application | `Alias` → `CopyRenameFallback` → `MetadataCache` → `ByteCache` → `Retry` → `RedirectFollower` → `Router` → `S3Backend` / `HttpBackend` / `FileBackend` / ... | Cache and follow redirects locally; retry transient errors; compose emulated copy / rename beneath alias rewriting. |
| REST gateway | `[Alias, CopyRenameFallback]` → `Router` → ... | No `MetadataCache` / `ByteCache` (gateway should be stateless), no `Retry` (HTTP clients retry), **no `RedirectFollower` so `read` returns `ReadResult::Redirect` unchanged for the gateway to emit as HTTP 307**. The fallback stays below aliases so it transfers the rewritten addresses, matching applications. |
| Broker daemon | `[broker server, Alias, CopyRenameFallback]` → `Router` → ... | The broker server consults its loaded authz plugins internally and forwards or denies. No `ByteCache` (per-tenant data must not co-cache); `MetadataCache` optional with principal-scoped keying. `RedirectFollower` omitted so the broker forwards redirects to the client. The fallback runs only after broker authz admits the operation and its fallback effects: source read, destination write, and source delete for rename. |
| Broker client (inside an application) | `Alias` → `CopyRenameFallback` → `MetadataCache` → `ByteCache` → `Retry` → `RedirectFollower` → `BrokerClientBackend` | `BrokerClientBackend` is the single terminal backend layer for a configured broker endpoint; the rest of the path runs locally on the application side. No Router needed — the Stack is single-terminal. |

Layer ordering and Stack composition is per-host configuration, not a global
constant. The same backend-layer binaries serve all four hosts; the differences
are entirely in which wrapper Layers are composed above the terminal Layer and
which terminal Layer that is.

## OpenUSD, ovpopulation, and ovrtx integration MVP

The main application owns one ovstorage root handle for the active user,
session, and deployment. It constructs that Stack once, including plugin
discovery/registration, configured roots, auth state, aliases, broker-client
routes, caches, and retry/redirect policy, then passes the shared handle to
ovpopulation, ovrtx, and other subcomponents during initialization. Components
that are initialized earlier can accept the same handle later through an
explicit `set_ovstorage`-style hook. Subcomponents should not independently
discover plugins or build parallel Stacks unless they are intentionally isolated
hosts.

`set_ovstorage` is, in general, an in-process **cross-language** handoff:
this RFC does not constrain a subcomponent's implementation language — and
OpenUSD and ovrtx are C++ — so a subcomponent accepting the shared handle
through this hook is a concrete consumer of `import_handle` (see
"Cross-language live handoff"), not a separate same-language mechanism. A
subcomponent's own `set_ovstorage(OvStorage_LayerBase*)` is satisfied by
handing it either the application API's opaque imported handle or the raw
`OvStorage_LayerHandle` to drive directly.

Local workflows remain first class. A root USD on local disk, local sublayers/references/payloads, and local authored files continue to work through OpenUSD and normal filesystem APIs with no ovstorage or cloud SDK dependency. ovstorage is optional integration for cloud, service-backed, brokered, or otherwise non-local assets.

When ovstorage is present, ovpopulation/OpenUSD uses the shared root handle
through an `ArResolver` and materialization bridge. The bridge covers the root
USD, sublayers, references, payloads, relative path resolution, and authored
assets that need stable local paths. Materialized files are leased for the
lifetime of the opened stage or authoring operation that depends on them.

ovrtx uses the same shared root handle for render-time dependencies: MDL
modules, textures, HDR environments, IES profiles, and other resource files.
Render materializations are leased for the lifetime of the render session or
job. Cache eviction must not invalidate live stages, authoring operations, or
renders; eviction can reclaim only unleased materialized rows.

Headless render workers use the same model with non-interactive auth. The
application or worker host configures broker-client or service credentials
before constructing the Stack, then hands that authenticated root handle to
ovrtx and any loading pipeline pieces. Plugin registration order is part of the
host contract and should be documented beside application Stack construction so
USD resolution and render-time resource loading see the same schemes and
aliases.

## Operation flow walkthroughs

### Read with redirect (S3)

`stack.read("s3://prod/file.bin", opts, cancel)` — the `Stack` canonicalizes the
request URL spelling before delegating to its root layer (step 1):

1. **`AliasWrapper.read`** / **`CopyRenameFallbackWrapper.read`** — no alias rule matches; no two-address transfer behavior applies, pass through.
2. **`ByteCacheWrapper.read`** — checks the exact byte-cache identity when the request already carries or can cheaply resolve an etag. If no etag is available yet, it treats the lookup as ineligible rather than probing by URL alone. Misses and ineligible lookups pass through with a deferred commit handler that will fire only if the returned `ReadResult::Stream.info` carries an etag.
3. **`RetryWrapper.read`** — wraps the call in the retry budget, passes through.
4. **`RedirectFollowerWrapper.read`** — calls `inner.read(...)`.
5. **`Router.read`** — `"s3://" → S3Backend`, forwards.
6. **`S3Backend.read`** — looks up the `"prod"` connection in its internal table, returns `ReadResult::Redirect(ReadRedirect { request: GET https://..., response_parsing, ... })`.
7. **`RedirectFollowerWrapper`** — executes the HTTP GET, parses headers per `response_parsing`, builds a `ReadResult::Stream { stream, info }`, returns it. (If the HTTP GET fails with 503, `RedirectFollowerWrapper` returns `Err(Transient)`.)
8. **`RetryWrapper`** — `Ok(Stream)` is returned. If `Err(Transient)`, sleeps, retries from step 4 — which re-asks `S3Backend` and gets a fresh presigned URL.
9. **`ByteCacheWrapper`** — if the stream is cache-eligible, taps the stream so chunks commit to cache under `(policy partition, canonical post-alias URL, etag)` as they pass through, then returns the tapped stream to the caller. If the stream lacks an etag, it returns the original stream unchanged.
10. **`CopyRenameFallbackWrapper`**, **`AliasWrapper`** — pass through.

Retry re-invokes everything below it including the redirect-asking step; this naturally handles presigned-URL expiry.

### S3 multipart upload

`stack.write("s3://prod/big.bin", Body::Stream(chunks), opts, cancel)`:

1. **`Alias`** / **`CopyRenameFallback`** — pass through.
2. **`Cache.write`** — pass through; queues invalidation on success.
3. **`Retry.write`** — stream-bodied writes can't be replayed once started, so `RetryWrapper` refuses to retry past the first chunk; it passes through.
4. **`RedirectFollower.write`** — calls `inner.write(...)`.
5. **`Router`** — forwards to `S3Backend`.
6. **`S3Backend.write`** — returns `WriteStep::Redirects(WriteRedirectBatch { continuation, redirects: [initiate_multipart_request] })`.
7. **`RedirectFollower`** — executes Initiate, captures the `UploadId`, calls `inner.continue_write(redirects, results, cancel)`.
8. **`Router`** → **`S3Backend.continue_write`** — deserializes the continuation, parses `UploadId`, returns `WriteStep::Redirects(batch_2 = [upload_part_1, ..., upload_part_N])` with body slices sourced from the user's stream (`RedirectBodySource::UserBytes { offset, len }`).
9. **`RedirectFollower`** — executes the N part uploads. **Part boundaries do not align with the user's stream chunk boundaries**, so `RedirectFollower` buffers exactly one part (up to the per-part size limit, typically 5 MiB – 5 GiB depending on backend) into a `Vec<u8>` before issuing each HTTP PUT. This is the **documented exception** to the streaming-invariant rule: the host buffers *one part at a time*, not the whole upload. Peak in-flight bytes are `(part_size × concurrent_parts)`, not `object_size`. After all parts succeed, collects part ETags and calls `inner.continue_write(batch_2, results_2)`.
10. **`S3Backend.continue_write`** — returns `WriteStep::Redirects(batch_3 = [complete_multipart])` with an inline XML body.
11. **`RedirectFollower`** — executes Complete, calls `inner.continue_write(batch_3, results_3)`.
12. **`S3Backend.continue_write`** — returns `WriteStep::Done(WriteResult { info })`.
13. **`RedirectFollower`** — returns `Done` up the Stack.
14. **`Retry / Cache / CopyRenameFallback / Alias`** — see `Ok`, return. `Cache` fires its invalidation hook for the dest URL.

`continue_write` is a vtable slot, so it threads through the Stack identically
to `write`. The multipart state lives in the S3 backend layer, keyed by the
opaque `continuation` blob the host echoes back.

### Materialize (`LocalDelegate` with lease)

`stack.materialize("s3://prod/big.bin", opts, cancel)`:

1. **`AliasWrapper`** / **`CopyRenameFallbackWrapper`** — pass through.
2. **`MetadataCacheWrapper`** — pass through (materialize is bytes, not metadata).
3. **`ByteCacheWrapper.materialize`** — checks for a cached row for this policy partition + canonical post-alias URL + etag. The etag must be known before a row can be reused; materialize never returns a URL-only cache hit.
   - **Hit**: returns `LocalDelegate { path: <cache row path>, guard: Some(<lease handle>) }`. The lease pins the row against eviction until the caller drops the delegate.
   - **Miss, inner returns a `file://` / `FileBackend` delegate**: returns that `LocalDelegate` unchanged. The bytes already live at their authoritative local path, so the cache layer does not copy them into a second cache row.
   - **Miss, inner returns any other local delegate or streamable fallback is required**: populates its own row when policy allows and the inner result carries an etag, then returns a `LocalDelegate { path: <cache row path>, guard: Some(<lease handle>) }`. If no etag is available, the cache layer does not populate a byte-cache row for that object.
4. **`RetryWrapper / RedirectFollowerWrapper`** — pass through if inner returns `LocalDelegate` directly; if inner returns `Stream`, the redirect follower drains into the cache only when the full byte-cache identity is known. Without an etag, there is no cache-backed `LocalDelegate` fallback.
5. **`Router / S3Backend`** — `S3Backend.materialize` is typically not implemented natively; it returns `Unsupported`, the cache layer above falls back to `read_stream → cache_commit → LocalDelegate` only for cache-eligible objects.
6. **`FileBackend.materialize`** — returns `LocalDelegate { path: <the actual file>, guard: None }`. The path is stable; the FileBackend doesn't manage a cache so no guard is needed.

The lease guard is opaque to layers above the one that issued it. A live lease pins the cache row until the caller drops the `LocalDelegate` or the lease handle itself. There is no active live-lease timeout or reclaim path: GC must not break a valid lease, even if the delegate appears leaked. Implementations may warn, expose diagnostics, or account the retained bytes to the leaking process, but leaked delegates over-retain cache space until their process releases the lease. Dead-process recovery is different: after restart or interprocess lease-owner death detection proves that no live holder remains, the cache may reap rows that were only protected by the dead owner.

### Range read for a large scene

A client that needs random access to a large object should not discover range-read support by trial and error. It first calls `root_info_for(scene_url)`:

1. **`range_read_strategy = Native`** — issue range reads directly. The owning backend layer is expected to fetch the requested byte ranges without reading the skipped bytes.
2. **`range_read_strategy = CachedReadThrough`** — issue range reads through `ByteCacheWrapper`. For small ranges, the cache may fetch a larger aligned block from a range-capable inner layer (for example 4 MiB), store it, and return only the requested bytes.
3. **`range_read_strategy = MaterializeOnly`** — call `materialize()` and render from the local delegate once the materializer can provide local random access.
4. **`range_read_strategy = Unsupported`** — fail early with a clear message that the selected backend cannot efficiently support random access.

`ByteCacheWrapper` only upgrades range behavior when it can do so honestly. If `stat(url)` reports `cache_locality = CachedComplete` for the same policy partition, canonical post-alias URL, and etag, the cache can serve arbitrary ranges locally even when the inner backend is streaming-only. If the object is not cached under that full identity and the inner layer is streaming-only, the cache does not silently read and discard bytes to satisfy a tiny range at a large offset. A policy knob may allow bounded streaming fill for specialized deployments, but the default is to return `MaterializeOnly` or `Unsupported` rather than accidentally downloading gigabytes for a small range.

### Read with no cache and no follower (REST gateway)

`stack.read("s3://prod/file.bin", opts, cancel)` on a REST-gateway Stack
`AliasWrapper -> CopyRenameFallbackWrapper -> Router -> S3Backend`:

1. **`AliasWrapper`** / **`CopyRenameFallbackWrapper`** — pass through.
2. **`Router`** — forwards to `S3Backend`.
3. **`S3Backend.read`** — returns `ReadResult::Redirect(ReadRedirect { request, response_parsing, expires_at, ... })`.
4. **`Router`** / **`CopyRenameFallbackWrapper`** / **`AliasWrapper`** — pass through unchanged.
5. The REST gateway's HTTP handler inspects the `ReadResult` variant: `Redirect` → emit an HTTP 307 response with the `Location` header set to `request.url` and `X-OV-Audit-Id` carried from the gateway's request context.

The gateway never instantiates a `RedirectFollowerWrapper`. The unfollowed
redirect flows up the Stack because nothing above the `S3Backend` consumes the
`Redirect` variant. This is the canonical example of how layer omission
expresses raw-passthrough semantics — the role served by `read_raw`.

### Metadata cache invalidation on write

`stack.write("s3://prod/dir/file.bin", body, opts, cancel)`:

1. **`AliasWrapper`** / **`CopyRenameFallbackWrapper`** — pass through.
2. **`MetadataCacheWrapper.write`** — queues invalidations for `stat("s3://prod/dir/file.bin")`, `list("s3://prod/dir/")`, `list_versions("s3://prod/dir/file.bin")`, `get_latest_version("s3://prod/dir/file.bin")`. Does not fire them yet — only on `Ok`. Passes through.
3. **`ByteCacheWrapper.write`** — queues byte-cache invalidation for the dest canonical URL in the request policy partition. Passes through.
4. **`RetryWrapper`** through to the owning backend layer — see the multipart walkthrough.
5. On `Ok(WriteResult)` returning up the Stack:
   - `ByteCacheWrapper` invalidates byte-cache rows for the dest canonical URL in the request policy partition. Hits still require an etag, so stale URL-only reuse is impossible; eager invalidation reclaims rows and keeps materialize locality reports conservative.
   - `MetadataCacheWrapper` invalidates all queued metadata entries. If the metadata cache has a watch subscription on `s3://prod/dir/`, the underlying `watch_directory` will produce a `Created` / `Modified` event soon; the cache refreshes from that event rather than from a cold list.

The fan-out pattern (one mutation invalidates entries at multiple keys) is the difference between byte cache and metadata cache. `MetadataCacheWrapper` indexes its entries by parent-prefix so `list(parent)` invalidations are O(1) lookups rather than scans.

### Emulated copy / rename

`stack.copy(src, dest, opts, cancel)` and `stack.rename(src, dest, opts, cancel)` reach `CopyRenameFallbackWrapper` after the address-rewriting layers above it have run:

1. **Ask, unless the root says the operation is unavailable** — the layer reads `supports_copy` / `supports_rename` for the source root and delegates the original request inward when the answer is `true` or unresolvable. This preserves backend-layer behavior, including server-side copy, server-side rename, and atomic rename when the selected backend supports them. The gate is deliberately the *availability* bit, not `supports_server_side_*`: a backend that performs `copy` without the bytes staying on the server must still be asked.
2. **Fall back when the layer below declines** — an `Unsupported` answer means the layer below does not perform this operation for this request, whatever the reason: the addresses resolve to different roots, the backend has no copy at all, or it refuses a precondition it cannot enforce. Every other error code propagates unchanged. Root topology is not part of the trigger.
3. **Emulated copy** — perform `inner.read(src)` and stream the result into `inner.write(dest)`. `CopyOptions::if_source` maps to the read precondition; `CopyOptions::if_dest` maps to the write precondition; `message` is passed to the write side. The layer does not recursively list directories or synthesize recursive copy semantics; it only composes the single-object operations already present in the vtable.
4. **Emulated rename** — perform the emulated copy, then call `inner.delete(src)` only after the write succeeds, carrying `RenameOptions::if_source` onto the delete. This is explicitly non-atomic. A delete failure after a committed destination surfaces as `CommitAmbiguous` naming both addresses, because the object may exist at both; a `NotFound` there is success, since that is the state a rename produces.
5. **Refuse an in-place operation** — when both endpoints resolve to one object, the emulation would read and write the same address, and for `rename` then delete the only copy. Both refuse with `InvalidArgument` instead.

The fallback sits directly beneath `AliasWrapper` so that the addresses it
compares and transfers are the rewritten ones. `AliasWrapper` continues to
participate in `root_info_for` and in the later delegated reads, writes,
deletes, or natively-served copy / rename requests.

### Cancellation mid-stream

`stack.read(..., Some(&token))` is in flight; user calls `token.cancel()`.

- `CancellationToken` is `Arc<tokio_util::sync::CancellationToken>`. Every Layer in the Stack received it and passed it down; cancellation is cooperative at every `.await` point.
- For a stream in flight, `token.cancel()` causes the producer to stop producing; the next `.next().await` on the stream returns `Err(Cancelled)`. Each `Stream` impl along the Stack forwards.
- `ByteCacheWrapper` cancellation rule: if a read is cancelled before `info.size` bytes have been observed, the in-progress cache row is discarded — no half-cached rows.
- Cross-language: `OvStorage_CancelToken*` is a stable opaque handle. The C ABI plumbs cancellation through the vtable identically to in-process Rust.

## Authentication

Authentication state is per auth-bearing Connection. Backend Connections usually
own credentials, refresh logic, and interactive flow state; alias Connections do
not. Alias Connections still participate in auth by delegating through their
rewrite target to the downstream auth-bearing Connection.

For example, `my-storage:` may rewrite to
`omniverse://some-server/users/brian`. Calling authenticate on the alias
Connection presents `my-storage:` to the user, but the credentials, refresh
lifecycle, and secret-store keys belong to the backend Connection for
`omniverse://some-server`.

### Per-connection state

Each auth-bearing connection inside a connection-owning Layer carries one
`ConnectionAuthState`:

```text
enum ConnectionAuthState {
    Authenticated { last_authenticated_at, expires_at: Option<SystemTime> },
    AwaitingAuth  { reason: AuthReason, last_attempt: Option<AuthAttempt> },
    AuthFailed    { error: Error, attempts: u32 },
    Anonymous,
}

enum AuthReason {
    NeverAuthenticated,
    RefreshTokenExpired,
    RefreshTokenRevoked,
    CredentialsRotated,
    ManuallyRequested,
    BackendUnreachable,
    Unknown { details: String },
}
```

The state is exposed in the `Connection` view returned by `list_connections()` and emitted on the optional connection update stream when it changes. The application UI requests that stream to know when a connection needs interactive re-auth.

### Background token refresh

For OAuth-style auth with refresh tokens, the backend layer spawns one background task per auth-bearing connection on its tokio runtime:

- Schedule wakeup at `expires_at - refresh_skew` (default 60 s).
- On wakeup, hit the IdP refresh endpoint with the refresh token.
- On success: atomically swap the connection's credentials, update `auth_state.expires_at`, persist the new refresh token to the secret store, emit `ConnectionChange::Updated`.
- On failure with a retryable error: back off and retry.
- On failure with a non-retryable error (refresh token revoked or expired): transition the connection to `AwaitingAuth { reason: RefreshTokenExpired | RefreshTokenRevoked }`, emit `ConnectionChange::Updated` so the UI can prompt the user.

None of this makes a wrapping Layer own credentials; credentials never leak
above the owning backend layer.

### Interactive flow

`stack.authenticate_connection(request, cancel)` returns an `AuthEventStream`. The owning backend layer drives the appropriate OAuth subflow based on the `InteractiveAuthCapability` declared by the host or supplied in the request:

```text
struct AuthenticateRequest {
    target: String,        // owning Layer; (target, connection_id) identifies the connection
    connection_id: String,
    capability: InteractiveAuthCapability,
    auto_open_browser: bool,
}

enum InteractiveAuthCapability {
    None,      // CI / render workers / sandboxed services.
               //   The backend layer emits Err(AuthRequired) immediately;
               //   no AuthEvent ever lands on the wire.
    Headless,  // SSH session / container shell. The host can show
               //   URLs and codes but cannot bind a local redirect
               //   listener. The backend layer uses device flow (RFC 8628).
    Browser,   // Desktop GUI / local terminal. The host can launch a
               //   browser and bind a 127.0.0.1 redirect listener.
               //   The backend layer uses PKCE.
}

enum AuthEvent {
    OpenBrowser  { url: String, expires_at: SystemTime },
    DeviceCode   { user_code, verification_url, expires_at, interval },
    Progress     { message: String },
    Succeeded    {
        connection: Box<Connection>,
        /// New credentials produced by the flow, if any. The backend layer
        /// receives these and is expected to persist them via the secret
        /// store and atomically swap them into the connection's
        /// in-memory state before forwarding the `Succeeded` event to
        /// the caller. `None` for warm-continue (the backend layer already
        /// has fresh credentials in hand, e.g. from a refresh-token-only
        /// flow that completed without user interaction).
        credentials: Option<SecretBundle>,
    },
    Failed       { error: Error },
    Cancelled,
}
```

Auth responsibility is split deliberately:

- **Host UI** renders the `AuthEventStream`: modal dialogs, "please sign in using your browser" text, device-flow URL/code display, progress messages, errors, and cancel buttons. Pressing Cancel cancels the `CancelToken`; the backend/helper emits `AuthEvent::Cancelled`.
- **Host callbacks** expose local-machine policy and conveniences: `auth_host.interactive_capability()`, `auth_host.open_browser(url)`, and `auth_host.authorize_loopback_redirect(...)`.
- **Owning backend layer** owns backend-specific auth state, chooses PKCE vs. device flow from `AuthenticateRequest.capability`, persists tokens through `SecretStore`, and updates `ConnectionAuthState`.
- **Shared helper code** may implement common OAuth mechanics: PKCE verifier/challenge, device-flow polling, loopback redirect listener binding, code capture, token exchange, refresh, and OAuth error normalization. This is an implementation detail; a backend layer can implement the protocol itself if it still honors the auth-event and host-callback contracts.

For browser auth, the backend layer starts a PKCE flow directly or through shared helper code. Before binding a local listener, it calls `HostCallbacks.auth_host.authorize_loopback_redirect`. The backend layer emits `AuthEvent::OpenBrowser`; if `auto_open_browser` is true, it may also call `HostCallbacks.auth_host.open_browser(url)`. The event still carries the URL so GUI, terminal, and remote hosts can render it according to their own policy. Exchanging the returned code for tokens is protocol logic in the backend/helper, not UI logic in the host.

For device flow, the backend layer emits `AuthEvent::DeviceCode`. The host renders the verification URL and code, then cancellation is handled only through the same cancel token used by other async operations.

| Capability | OAuth-IDP plugins | Long-flow plugins | Anonymous / non-interactive |
|---|---|---|---|
| `None` | `Err(AuthRequired)` immediately | `Err(AuthRequired)` immediately | `Err(Unsupported)` immediately |
| `Headless` | Device flow | URL+nonce-poll (the user can open the URL on any device) | `Err(Unsupported)` immediately |
| `Browser` | PKCE (or device fallback if the IdP advertises only device) | URL+nonce-poll | `Err(Unsupported)` immediately |

The last column is capability-independent: the capability describes what the
*host* can drive, and a backend whose credentials arrive with the connection has
nothing to drive under any of them. The error is raised before any event stream
exists, so the connection's state is untouched — a connection parked by a
refused credential stays parked rather than being promoted on no grant and no
probe. In-tree, `azure`, `gcs`, `s3` and `opendal` answer it from their
connection-auth drivers, as does the broker client for its direct-endpoint
addresses — anything that is not `http(s)://`, so `grpc://`, `grpc+tcp://`,
`grpc+tls://`, `unix:/…` and `npipe:/…` — which have no OAuth surface; a
layer with no connection-auth driver at all — `file`, `http` — answers it from
the `Layer` leaf default, which is the same code. This column is decided before
the capability check, because whether a backend has a flow is a property of the
backend rather than of what the host could drive.

`InteractiveAuthCapability` resolution (host-side, at stack-build time):
explicit builder override > `HostCallbacks.auth_host.interactive_capability()`
> `OV_INTERACTIVE_AUTH_CAPABILITY` env var > smart default. Smart defaults: CI
environments → `None`, SSH sessions / Linux without `$DISPLAY` → `Headless`,
desktop with browser available → `Browser`. The resolved capability rides the
broker's gRPC metadata header (`x-ov-iauth: browser | headless | none`) for
brokered hosts so the broker can apply the same gating to upstream IdP flows.

### Secret storage

Persistent secrets — refresh tokens, API keys, mTLS key material, encrypted cached credentials — live in a host-provided secret store exposed via `OvStorage_HostCallbacks`:

```c
typedef struct OvStorage_SecretStore {
    /* Get a secret by key. Returns NULL on miss. */
    OvStorage_SecretBytes* (*get)(void* ctx, const char* key,
                                  OvStorage_Error** err);

    /* Persist a secret. */
    void (*set)(void* ctx, const char* key,
                const OvStorage_SecretBytes* value,
                OvStorage_Error** err);

    /* Delete a secret. */
    void (*delete)(void* ctx, const char* key,
                   OvStorage_Error** err);

    /* List keys under a prefix (for cleanup). */
    void (*list)(void* ctx, const char* prefix,
                 OvStorage_StringList** out,
                 OvStorage_Error** err);

    /* Cross-process refresh-token coalescing for credentials stored here.
       Returns a lease when this process should refresh. Returns no lease
       plus a snapshot when another process refreshed recently. */
    void (*begin_refresh)(void* ctx,
                          const char* key,
                          uint64_t freshness_window_ms,
                          OvStorage_SecretRefreshDecision** out,
                          OvStorage_Error** err);

    /* Publish the successful refresh result and release the lease. */
    void (*finish_refresh)(void* ctx,
                           OvStorage_SecretRefreshLease* lease,
                           const OvStorage_SecretRefreshSnapshot* snapshot,
                           OvStorage_Error** err);

    /* Release the lease without publishing a refresh result. */
    void (*abort_refresh)(void* ctx,
                          OvStorage_SecretRefreshLease* lease);

    void* ctx;
} OvStorage_SecretStore;
```

Backend layers receive the secret store via `OvStorage_HostCallbacks` at init time. They reach into it for:

- Looking up a refresh token on connection rehydration at startup.
- Writing a new refresh token after a successful interactive flow.
- Writing a rotated refresh token after a background refresh.
- Deleting all secrets for a connection on `remove_connection`.
- Coalescing refresh work across processes so multiple clients sharing the same store do not all refresh the same token at once.

The host chooses the backing implementation — but not from this list, and not through the struct above: `OvStorage_SecretStore` does not appear in the shipped headers. What ships is `OvStoragePlugin_HostCallbacks`, whose secret-facing slots are `secret_get` / `secret_put` / `secret_delete` plus `auth_refresh_lock_with_refresh` for the cross-process coalescing named above; the host fills that table and hands it to the plugin at init. In tree the Rust host routes them to `auth::SqliteSecretStore`, which keeps credential bytes in a `secrets` table in `auth.sqlite` under owner-only permissions; the C source host routes them to a process-global in-memory list that does not outlive the process. The list below names *intended* backings beyond the one that ships, and nothing selects among them by configuration.

- **Local SQLite** — a `secrets` table in `auth.sqlite`, under the auth directory, created `0700` with the database `0600` and an owner-only DACL on Windows. This is the backing that ships. It replaced an OS-keyring backing, which was a real secret store on only two of the four host substrates: on Linux the `keyring` crate resolved to kernel keyutils, whose per-user quota is a hard ceiling of roughly five to nine connections and whose durability turns on which keyrings the kernel offers, and the standalone C host never had one at all. Credential bytes therefore reach disk on every platform now; the protection against another user on the box is file permissions rather than a separate daemon.
- **Encrypted local file** — **(spec)** XDG-located, encrypted with a process-local key. Note that keeping such a key in an OS keyring is not a route to this: on Linux that key would live in volatile keyutils, so after a reboot the database would be present and unreadable.
- **Broker-mediated** — **(spec)** as a secret-store backing: the broker holds secrets and hands out short-lived working credentials over gRPC. Intended for render workers and CI runners. Distinct from what the broker does today, where backend plugins loaded into the broker process hold their own credentials and presign.
- **HSM / TPM** — **(spec)** for high-assurance deployments. Optional.

`SecretBytes` is the cross-ABI representation: heap-allocated, zeroize-on-drop, redacted `Debug`, no `Display`, no `serde::Serialize`. The same shape that exists today.

### Shared OAuth helper code

PKCE flow, device flow, redirect-listener binding, refresh-token rotation, and IdP-discovery (OpenID Connect's `.well-known/openid-configuration`) can be factored into shared helper code such as an `ovstorage-oauth` Rust crate. This helper is not part of the plugin ABI and not a host callback. It exists to avoid duplicating protocol machinery across `S3Backend`, `AzureBackend`, `GcsBackend`, `NucleusBackend`, `ServicesClientBackend`, and `BrokerClientBackend`.

Such a helper could expose:

- `PkceFlow::new(idp_config).drive(request, auth_host)` → `AuthEventStream`.
- `DeviceFlow::new(idp_config).drive()` → `AuthEventStream`.
- `RefreshDriver::new(idp_config, refresh_token).next_token()`.
- A `RedirectListener` that asks `auth_host.authorize_loopback_redirect(...)`, binds 127.0.0.1, accepts the redirect, parses the auth code.

Equivalent helper APIs may exist in the Python wheel (`ovstorage.oauth.PkceFlow`, etc.) and as C functions in the source distribution (`ovstorage_oauth_pkce_drive`, ...) for layer authors who cannot link the Rust crate. Layers may also bring their own OAuth implementation when they need an SDK-specific flow.

### Brokered auth

`BrokerClientBackend` has two auth surfaces, matching the current broker plugin and broker protocol: **client → broker listener auth** (covered here) and **brokered upstream auth** (covered under "Brokered upstream auth" below, after the orchestration model both surfaces build on).

**Client → broker listener auth.** This is the auth for the configured broker endpoint/session. Direct endpoint schemes (UDS, named pipe, direct gRPC) may have no OAuth surface; listener auth is handled by the transport (peer credentials, mTLS, token file, etc.). Discovery URLs (`http://` / `https://`) can publish an auth-config document. The broker client uses that document to install an access token on its gRPC interceptor, refresh it when needed, and send `x-ov-iauth` metadata on each RPC so the broker knows what interactive auth capability the caller can surface.

`stack.authenticate_connection({ target: broker_client, connection_id, ... }, cancel)` on the client drives only this client → broker endpoint auth. It may warm-continue from a refresh token in `SecretStore`, use configured client credentials, or run an interactive PKCE/device flow against the broker-published IdP.

### Orchestration: state machine and lifecycle

Auth-bearing Connections progress through `ConnectionAuthState` via a small set of orchestration entry points. The owning backend layer is the only thing that mutates state; the host triggers state changes via vtable calls.

| State | Triggered by | Transitions to |
|---|---|---|
| `Anonymous` | `add_connection` with no credentials and no IdP config | stays `Anonymous` until removed |
| `AwaitingAuth { NeverAuthenticated }` | `add_connection` with IdP config but no usable credentials in the secret store | `Authenticated` on successful `authenticate_connection`; `AuthFailed` if interactive flow fails terminally |
| `Authenticated { expires_at }` | initial credentials accepted, OR refresh succeeded, OR interactive flow's `Succeeded` event processed | `AwaitingAuth { RefreshTokenExpired \| RefreshTokenRevoked }` on refresh failure; `Authenticated` again on `update_connection_credentials` |
| `AwaitingAuth { RefreshTokenExpired }` | background refresh fails with `invalid_grant` / 401 from IdP | `Authenticated` on `authenticate_connection`; `AuthFailed` after configurable attempts |
| `AwaitingAuth { RefreshTokenRevoked }` | background refresh returns explicit revocation | `Authenticated` on `authenticate_connection` |
| `AwaitingAuth { CredentialsRotated }` | `update_connection_credentials` called with creds that the backend layer determines need re-auth (e.g. service account key rotation requiring a new bind) | `Authenticated` once new creds are validated |
| `AwaitingAuth { ManuallyRequested }` | application explicitly requests re-auth (e.g. user clicks "sign in again" in a UI) | `Authenticated` on flow completion |
| `AwaitingAuth { BackendUnreachable }` | the backend layer distinguishes "creds bad" from "wire problem" and parked due to the latter | retries the refresh in the background; transitions to `Authenticated` if it succeeds |
| `AuthFailed { error, attempts }` | terminal failure threshold (configurable, default 5 attempts) reached on a non-retryable error | `Authenticated` only via `update_connection_credentials` (the host has supplied fresh creds out-of-band) |

`AuthAttempt` history is recorded on every transition that involves a real attempt: timestamp + error code (if any). The history informs the UI and is bounded (last N entries).

### Orchestration: when to call which method

Three operations a host can do, with their use cases:

| Method | When the host calls it | What the backend layer does |
|---|---|---|
| `update_connection_credentials(target, id, secrets)` | Application has new credentials out-of-band (operator pasted them, broker pushed them, env-var rotation, etc.). No interactive flow required. | Validate the credentials against the backend; on success, swap atomically into in-memory state, persist to the secret store, transition to `Authenticated`. On failure, transition to `AwaitingAuth { CredentialsRotated }` and return the error. |
| `authenticate_connection(request, cancel)` | Application needs interactive OAuth / device flow. The connection is in `AwaitingAuth` or `AuthFailed`. Returns an `AuthEventStream`, or `Err(Unsupported)` when the backend has no interactive flow at all — in which case nothing ran and the connection's state is unchanged. | Drive the flow directly or through shared OAuth helper code, using the host auth callbacks for browser/loopback policy. Emit `OpenBrowser` / `DeviceCode` / `Progress` events for the UI. On `Succeeded { credentials: Some(...) }`, persist to the secret store, atomically swap into connection state, transition to `Authenticated`, then forward `Succeeded`. On `Failed`, increment `attempts` and transition to `AwaitingAuth { last_attempt: Some(...) }`; after the threshold, `AuthFailed`. On `Cancelled`, leave state unchanged. |
| Background refresh | Internal timer. No host call. | Wake at `expires_at - refresh_skew`, attempt refresh directly or through shared OAuth helper code. On success, persist new refresh token, swap creds, update `expires_at`, emit `ConnectionChange::Updated`. On non-retryable failure, transition to `AwaitingAuth { RefreshTokenExpired \| RefreshTokenRevoked }` and emit `ConnectionChange::Updated` so the UI prompts. |

### Orchestration: error code mapping

When an object operation hits an auth-related error, the backend layer returns a closed-taxonomy `ErrorCode` that the host's retry / UI logic acts on:

| `ErrorCode` | Meaning | Host action |
|---|---|---|
| `AuthRequired` | Interactive flow needed (no usable creds, `InteractiveAuthCapability::None` host can't drive one) | Surface to the UI; don't retry. |
| `AuthCancelled` | The flow was cancelled (user closed browser, refresh token revoked at the IdP) | Surface to the UI; don't retry. |
| `AuthExpired` | Credentials expired and refresh failed | Same as `AuthRequired`. UI can offer "re-authenticate." |
| `PermissionDenied` | The principal authenticated but lacks permission | Don't re-auth (won't help). Surface as a permission error. |
| `CredentialUnavailable` | No credentials reached the backend layer (secret store empty for this connection) | Caller should call `update_connection_credentials` or `authenticate_connection`. |
| `Transient` | Wire-level failure (network blip, IdP 5xx) | `RetryWrapper` retries on a budget. |

The backend layer returns these from object-op methods, not from `authenticate_connection` directly. `authenticate_connection` returns the event stream and reports flow-level failures via `AuthEvent::Failed`.

### Data-path recovery for hosts without a UI

The table above says "surface to the UI" — headless hosts (broker workers,
render farms, CI) have none, and background refresh only covers credentials
whose expiry is known in advance. For an ordinary connection, recovery from
credentials that die without warning (revocation, out-of-band rotation, STS
re-resolution) is owned by the connection-lifecycle machinery **inside the
owning backend layer**: on a credential-classed error from an object op, it
invalidates the cached credentials for that connection, re-resolves through
the credential sources, and retries the operation **once** before surfacing
the error. `PermissionDenied` is excluded (re-auth won't help), and
interactive-only failures still surface. This keeps recovery inside the
component that owns the credential rather than in a generic host retry
wrapper. (Tracked: issue #167; part of the generic connection-lifecycle
library, issue #166.)

The broker's per-principal upstream-OAuth boundary is a specialized credential
owner rather than an ordinary backend connection. Its bounded recovery path is
therefore implemented at that boundary: only a request stamped there with an
opaque credential lease is eligible; after the registered consumer returns
`AuthRequired`, the boundary re-verifies that the route is owned by the
provider's backend kind, conditionally invalidates that exact lease, coalesces
refresh for the `(backend, principal)` slot, and replays the operation once.
An unstamped request, a route-owner mismatch, another error code, or a second
`AuthRequired` is returned without recovery. This is not a general Layer retry
policy and does not authorize hosts or unrelated wrappers to replay backend
operations.

### Brokered upstream auth

Broker-mediated upstream OAuth is separate from
`BrokerClientBackend.authenticate_connection`. An object operation can report
that one of the broker's upstream backend layers needs a per-user credential.
The client then starts address-scoped authentication over the broker protocol:

1. `BrokerClientBackend` calls `Auth(address)` with the host-selected
   interactive capability and receives a stream of `AuthEventEnvelope` values
   (`OpenBrowser`, `DeviceCode`, `Progress`, `Succeeded`, `Failed`,
   `Cancelled`).
2. The broker's authenticated Stack resolves and authorizes the caller,
   selects the configured upstream provider, and drives the permitted OAuth
   flow on the daemon. The broker persists the resulting credential in that
   principal's broker-side secret slot before emitting `Succeeded`.
3. `BrokerClientBackend` mirrors the wire events into the host's normal
   `AuthEvent` shape so the same UI code can render browser prompts, device
   codes, progress, and cancellation. `Succeeded` carries connection identity,
   never upstream credential bytes; the client retries the original operation.
4. `RegisterCredential(address, access_token, refresh_token, expires_at)` is a
   separate authenticated surface for a flow completed by external client
   tooling. Its primary broker use is a remote PKCE-only provider, because a
   remote browser cannot reach the daemon's loopback redirect listener. The
   broker stores that supplied credential through the same principal-scoped
   upstream-credential layer; it is not paired with an in-flight `Auth` stream.

Workers without interactive UI can decline or cancel the `Auth` stream. Remote
automatic authentication supports device-capable providers; PKCE-only remote
flows require the explicit external `RegisterCredential` path above.

### What this means for backend-layer authors

A backend-layer author embeds the shared connection-lifecycle machinery — a
generic `ConnectionSet` parameterized over a small per-backend driver (issue
#166) — and writes only the protocol verbs:

- **validate** — check credentials against the backend (bind/probe).
- **refresh** — obtain fresh credentials (OAuth refresh via `ovstorage-oauth`,
  SigV4/STS re-resolution, or nothing for static keys).
- **interactive** — drive the interactive flow (usually delegating to
  `ovstorage-oauth`), emitting `AuthEvent`s; on `Succeeded`, credentials are
  persisted to the secret store and swapped into in-memory state before the
  event is forwarded.
- **classify** — map the backend's errors onto the closed `ErrorCode`
  taxonomy above.

The generic machinery supplies everything backend-agnostic: the
`ConnectionAuthState` state machine and its transitions, single-flight
bring-up coalescing and failure cooldown, the credential cache and its
invalidation, background-refresh scheduling, cross-process refresh coalescing
(via `SecretStore.begin_refresh` / `finish_refresh` / `abort_refresh`), the
data-path recovery loop above, secret-store persistence conventions, and
connection-change event emission. Session-full backends (Nucleus) add an
on-authenticated hook for session establishment; reconnection semantics stay
per-backend. There is deliberately **no connection-manager Layer**: a wrapper
owning connections for the layers below it would invert connection ownership
across the vtable and split connection state across two homes.

Authors do *not* implement OAuth from scratch, hand-roll the state machine or
its coalescing, reimplement secret-store integration, or reinvent the AuthEvent
vocabulary.

## Per-language idiomatic surfaces

Every host language exposes one operational object: a Layer. The language may
give nicer names to the three factory shapes at construction time, but once a
Layer is built the caller sees the same storage methods whether that Layer is a
backend layer, a wrapper layer, or a router layer.

The important split is therefore:

- **Operational trait / base class:** `Layer` — the API = SPI surface.
- **Factory shape:** backend factory (0 children), wrapper factory (1 `inner`),
  router factory (many `children`).

This keeps the Tower intuition where it helps — wrappers have an `inner` and
compose bottom-up — without forcing routers to pretend they are wrappers.

### Rust

Rust uses one operational trait plus small factory traits for the three
construction shapes.

```rust
#[async_trait]
pub trait Layer: Send + Sync {
    fn name(&self) -> &str;
    fn descriptor(&self) -> LayerKindDescriptor;
    fn owned_targets(&self) -> Vec<String>;

    async fn stat(&self, req: Request<StatRequest>) -> Result<ObjectInfo>;
    async fn read(&self, req: Request<ReadRequest>) -> Result<ReadResult>;
    async fn list(&self, req: Request<ListRequest>) -> Result<ListPage>;
    /* ... full operational surface ... */

    async fn add_connection(&self, req: Request<ConnectionRequest>) -> Result<Connection>;
    async fn list_address_roots(&self, req: Request<ListAddressRootsRequest>)
        -> Result<(RootInfoSnapshot, Option<RootInfoChangeStream>)>;
    /* ... */

    /// Computed lazily on first cross-language hop; pure-Rust Stacks never
    /// construct one.
    fn handle(&self) -> OvStorage_LayerHandle;
}

pub trait BackendFactory: Send + Sync {
    fn create(&self, ctx: CreateBackend) -> Result<Arc<dyn Layer>>;
}

pub trait WrapperFactory: Send + Sync {
    fn wrap(&self, inner: Arc<dyn Layer>, ctx: CreateWrapper) -> Result<Arc<dyn Layer>>;
}

pub trait RouterFactory: Send + Sync {
    fn create(&self, children: Vec<Arc<dyn Layer>>, ctx: CreateRouter)
        -> Result<Arc<dyn Layer>>;
}

pub struct ByteCacheWrapper { inner: Arc<dyn Layer>, cache: Cache }

#[async_trait]
impl Layer for ByteCacheWrapper {
    async fn read(&self, req: Request<ReadRequest>) -> Result<ReadResult> {
        /* cache-specific behavior, then self.inner.read(req).await */
    }
    /* other methods use pass-through defaults */
}
```

A Rust Stack is built bottom-up: instantiate backend and router leaves,
then thread wrapper factories from the innermost wrapper outward. Calls are
virtual trait dispatch via `Arc<dyn Layer>`; the C-ABI handle is only constructed
on demand when a foreign-language Layer is composed on top.

### Python

A class hierarchy can expose one base class with `layer_type` metadata. The
default methods are selected from `layer_type`: wrappers pass through to
`inner`, backend layers return `Unsupported` for methods they do not implement,
and routers route to children.

```python
from ovstorage import LayerBase
from ovstorage.cache import ByteCacheWrapper
from ovstorage.router import Router
from ovstorage.s3 import S3Backend

class AuditWrapper(LayerBase):
    layer_type = "wrapper"

    """Pure-Python Layer that logs every read."""
    def __init__(self, inner, log_path):
        super().__init__(inner=inner)
        self._log = open(log_path, "a")

    async def read(self, req):
        self._log.write(f"read {req.address}\n")
        return await self._inner.read(req)

# Build a Stack: Layer names from outermost-in, ending in a backend or router.
stack = (ovstorage.Stack()
    .layer(AuditWrapper, log_path="/tmp/audit.log")
    .layer(ByteCacheWrapper, cache_dir="/tmp/cache")
    .router(Router, children=[S3Backend(name="s3-prod-backend")])
    .build())

await stack.add_connection({
    "target": "s3-prod-backend", "id": "prod",
    "config": {...}, "credentials": {...},
})
data, info = await stack.read_bytes("s3://prod/file")
```

High-level builders use `.backend(...)` and `.router(...)` as terminal methods:
they declare the terminal Layer, create the final edge, and make `.build()`
available. Under the hood, those methods compile to the same named Layer
declarations and edges used by TOML and the C builder.
The built Stack presents the same Layer interface regardless of whether each
link is pure Python, Rust-backed, or C-backed.

### C++

A C++ wrapper can mirror the Python shape: one `ovstorage::LayerBase`, with
metadata declaring whether the concrete class is a backend, wrapper, or router.

```cpp
#include <ovstorage.hpp>

class AuditWrapper : public ovstorage::LayerBase {
public:
    static constexpr auto layer_type = ovstorage::LayerType::Wrapper;

    AuditWrapper(ovstorage::Layer inner, std::string log_path);

    awaitable<ovstorage::ReadResult>
    read(ovstorage::Request<ovstorage::ReadRequest> req) override {
        log_->info("read {}", req.message().address());
        return co_await inner_->read(std::move(req));
    }
};

auto stack = ovstorage::Stack{}
    .layer<AuditWrapper>("/tmp/audit.log")
    .layer<ovstorage::ByteCacheWrapper>("/tmp/cache")
    .router<ovstorage::Router>(children)
    .build();
```

### Pure C

No abstract base above the vtable. Authors populate `OvStorage_LayerVTable` directly. Two default tables are provided to make Layer authoring ergonomic:

- `OVSTORAGE_PASSTHROUGH_VTABLE` — every slot calls `inner` (use for wrapper layers).
- `OVSTORAGE_UNSUPPORTED_VTABLE` — every slot invokes `on_complete` with `ErrorCode::Unsupported` (use as the starting point for backend layers, then patch in the slots you handle).

A wrapper Layer copies the pass-through table and patches the slots it decorates:

```c
static OvStorage_LayerVTable AUDIT_VTABLE;
__attribute__((constructor))
static void audit_init(void) {
    AUDIT_VTABLE = OVSTORAGE_PASSTHROUGH_VTABLE;
    AUDIT_VTABLE.read = audit_read;
}
```

A backend Layer copies the unsupported table and patches the slots its kind handles:

```c
static OvStorage_LayerVTable S3_VTABLE;
__attribute__((constructor))
static void s3_init(void) {
    S3_VTABLE = OVSTORAGE_UNSUPPORTED_VTABLE;
    S3_VTABLE.stat   = s3_stat;
    S3_VTABLE.read   = s3_read;
    S3_VTABLE.write  = s3_write;
    /* ... */
    S3_VTABLE.add_connection = s3_add_connection;
    S3_VTABLE.list_address_roots = s3_list_address_roots;
}
```

## Multi-language Stack examples

Three concrete host-language scenarios. Each shows how Layer instances sourced
from different languages compose, and where FFI hops fall in the resulting
Stack.

The construction-time rule: each wrapper Layer's `inner` reference, and each
router Layer's `children`, are set up when the Stack is built. After that, each
Layer holds its outgoing references as the type its own language understands
(Rust trait object, Python class reference, C++ `shared_ptr`, or
`OvStorage_LayerHandle` for cross-language adapters). The runtime dispatch path
doesn't choose between "native" and "FFI" per call — that decision was baked in
at construction. Same-language wrapper paths can be arbitrarily deep without
FFI overhead, even when the Stack crosses through a foreign-language Layer
earlier.

### Python host

```python
from ovstorage import Stack, LayerBase
from ovstorage.cache import MetadataCacheWrapper, ByteCacheWrapper    # Rust-backed
from ovstorage.router import Router                          # Rust-backed
from ovstorage.s3 import S3Backend                                  # Rust-backed
from ovstorage.c_plugin import load_plugin                         # opens any cdylib

class AuditWrapper(LayerBase):
    """Pure Python — defined inline in the application."""
    def __init__(self, inner, log_path):
        super().__init__(inner=inner)
        self._log = open(log_path, "a")

    async def read(self, req):
        self._log.write(f"read {req.address}\n")
        return await self._inner.read(req)

fuse_plugin = load_plugin("/path/to/libfuse_layer.so")       # C cdylib, ships "fuse" layer
s3_plugin   = load_plugin("/path/to/libovstorage_s3.so")     # Rust cdylib, ships "s3"
registry = PluginRegistry([fuse_plugin, s3_plugin])

stack = (Stack()
    .with_registry(registry)
    .layer(AuditWrapper, log_path="/tmp/audit.log")              # pure Python (outermost)
    .layer(MetadataCacheWrapper)                                 # Rust-backed Python wrapper
    .layer(ByteCacheWrapper, cache_dir="/tmp/cache")             # Rust-backed Python wrapper
    .router(Router, children=[
        ovstorage.fuse.FuseBackend(),                          # C cdylib
        ovstorage.s3.S3Backend(),                              # Rust cdylib
    ])
    .build())

data, info = await stack.read_bytes("s3://prod/file")
```

What happens on `read_bytes`:

1. **Python**: `AuditWrapper.read()` logs, calls `self._inner.read()`.
2. **Python → Rust** (FFI hop): the `MetadataCacheWrapper` Python wrapper delegates to its Rust implementation. The Rust implementation was constructed with `inner.vtable()` at build time, so it already holds a C-ABI handle for the next Layer.
3. **Rust → Rust** (native vtable call): the `ByteCacheWrapper`'s Rust implementation handles the next link. Same Rust runtime, no GIL, no extra FFI hop.
4. **Rust → Rust** (native): the Rust-implemented `Router` dispatches by URL to the matching child.
5. **Rust → Rust** (native): `S3Backend`'s Rust runtime handles the call. (Had this resolved to the C FUSE plugin instead, this step would be an FFI hop.)

Total FFI hops for this path: 1 (Py→Rust). Once we're inside Rust, dispatch stays inside Rust through the cache Layers, the Router, and the S3Backend — they're all Rust-backed. A path that routes to the C FUSE backend layer instead would add one Rust→C hop.

Pure-Python wrapper paths pay zero FFI hops between Python Layers.

### C++ host

```cpp
#include <ovstorage.hpp>
#include "my_audit.hpp"   // application's own C++ layer

auto s3_plugin = ovstorage::load_plugin("/path/to/libovstorage_s3.so");
auto registry = ovstorage::PluginRegistry{}
    .add(std::move(s3_plugin));

auto stack = ovstorage::Stack{}
    .with_registry(registry)
    .layer<MyAudit>("/tmp/audit.log")                                   // pure C++
    .layer<ovstorage::MetadataCacheWrapper>()                             // C++ class, C-ABI backed
    .layer<ovstorage::ByteCacheWrapper>("/tmp/cache")                     // C++ class, C-ABI backed
    .router<ovstorage::Router>(/* children = */ { "s3" })         // Router with S3 child
    .build();

auto [bytes, info] = co_await stack.read_bytes("s3://prod/file");
```

The C++ class hierarchy is a thin wrapper over the vtable; C++ classes don't introduce a separate language runtime. So:

1. **C++**: `MyAudit::read()` logs, calls `inner_->read()`.
2. **C++ → C** (not an FFI hop — the C++ wrapper sits directly on the C vtable): `MetadataCacheWrapper` and `ByteCacheWrapper` are C-backed Layers exposed as C++ classes. The call passes through the vtable but stays in the same runtime.
3. **C → C** (still no FFI hop): the C-implemented Router dispatches to its child.
4. **C → Rust** (one FFI hop): the `S3Backend` handles via its Rust runtime.

Total FFI hops: 1. C++ → C is not a language boundary in this design; both share the vtable as their native dispatch surface.

### Rust host

```rust
use ovstorage::{Layer, LayerFactory, Stack};
use ovstorage::cache::{MetadataCacheWrapper, ByteCacheWrapper};

struct MyAudit { inner: Arc<dyn Layer>, log: File }

#[async_trait]
impl Layer for MyAudit {
    async fn read(&self, req: Request<ReadRequest>) -> Result<ReadResult> {
        writeln!(self.log, "read {}", req.message.addr)?;
        self.inner.read(req).await
    }
    /* other methods default to pass-through */
}

let fuse_plugin = load_plugin("/path/to/libfuse_backend.so")?;  // C cdylib (one backend kind: "fuse")
let s3_plugin = load_plugin("/path/to/libovstorage_s3.so")?;    // Rust cdylib (one backend kind: "s3")
let registry = PluginRegistry::from_plugins([fuse_plugin, s3_plugin])?;

let stack = Stack::builder()
    .with_registry(registry)
    .layer(MyAudit::new("/tmp/audit.log"))                          // pure Rust
    .layer(MetadataCacheWrapper::new())                               // pure Rust
    .layer(ByteCacheWrapper::new("/tmp/cache"))                       // pure Rust
    .router(Router::new(vec![
        registry.layer("fuse")?,
        registry.layer("s3")?,
    ]))
    .build();

let (bytes, info) = stack.read_bytes("s3://prod/file", opts, None).await?;
```

For a read of `s3://prod/file`:

1. **Pure Rust trait dispatch**: three Rust virtual calls (`MyAudit` → `MetadataCacheWrapper` → `ByteCacheWrapper`) and then the Router's dispatch. Zero FFI hops.
2. **Rust → Rust** (still no FFI): Router routes to the S3 child.
3. **Rust → Rust** via the loaded S3 cdylib — but **this still crosses the C ABI**. Rust ABI is unstable between independently compiled binaries, so cdylib boundaries are always C-shaped. One FFI hop here.

Total FFI hops for the S3 read: 1. A read of `fuse://...` would instead route through the FUSE child, adding one Rust→C hop.

### Cost summary

| Host | Local Layers | Loaded plugins | FFI hops on a single-backend path |
|---|---|---|---|
| Python | 1 pure-Py Layer + 2 Rust-backed Layers + Router | 1 C cdylib (FUSE backend layer) + 1 Rust cdylib (S3 backend layer) | 1-2 (Py→Rust always; +Rust→C if path routes to C plugin) |
| C++ | 1 pure-C++ Layer + 2 C-ABI Layers + Router | 1 Rust cdylib (S3) | 1 (C→Rust at the S3 leaf) |
| Rust | 3 pure-Rust Layers + Router | 1 C cdylib (FUSE) + 1 Rust cdylib (S3) | 1 (host→cdylib boundary, C-shaped) |

Rust-only Stacks with no cdylib loads cost zero FFI. C++ → C is free. Python
→ anything-else is the only mandatory FFI hop for Python hosts. cdylib loads
always cross C, even when the cdylib's internals are Rust.

## Dynamic Stack construction

A Stack specification is mutable. A built Stack is not.

Applications normally load one Stack specification at startup, build it once,
and keep the resulting root handle for the process lifetime. Tools can load a
specification, edit it, build a Stack for one operation, and save the edited
specification back out for application use.

Stack specifications are portable between hosts. A user can build and test a
Stack with the `ovstorage` CLI, save the TOML file, and load that same file in a
Rust, Python, C++, REST-gateway, or broker host. Each host may still choose a
different set of built-in Layer factories or plugin search paths, but the Layer
names, edge fields (`inner` / `children`), per-Layer config, and persisted
connection declarations live in the shared config file.

A live-built Stack root is portable across languages by a separate,
complementary mechanism: cross-language live handoff
(`export_handle`/`import_handle`, see "Cross-language live handoff") moves
an already-built subtree — including its connection state, live caches, and
any interpreted-leaf instance state — directly between binaries, with no
config file involved. Spec-file portability above reproduces a
*composition* on a new host from scratch; live handoff transfers a
*running* composition as-is. The two are independent: a host can load a
spec file, build locally, and separately export or import live subtrees.

### CLI tool example

```sh
$ ovstorage stack edit app.toml
ovstorage> show
ovstorage> insert-layer audit:audit.toml at top
ovstorage> remove-layer byte_cache
ovstorage> test read s3://prod/file
ovstorage> write app-with-audit.toml
ovstorage> quit
```

The same edits can be scripted when automation is preferable:

```sh
$ ovstorage stack edit app.toml \
      --insert-layer audit:audit.toml@top \
      --remove-layer byte_cache \
      --test-read s3://prod/file \
      --write app-with-audit.toml
```

The CLI loads a Stack specification, applies edits, and builds a Stack only for
test operations such as `test read`. Nothing persists unless the user writes the
edited specification to disk.

Applications load saved specifications directly:

```python
stack = ovstorage.StackSpec.from_config_file("app-with-audit.toml").build()
```

```rust
let stack = ovstorage::StackSpec::from_path("app-with-audit.toml")?.build()?;
```

### Rebuild semantics

A long-lived host that wants to apply a replacement Stack specification does a complete rebuild:

1. Load and validate the replacement specification.
2. Build a fresh Stack following the full "Build order" above — instantiate Layers, apply persisted connections, *then* build Router routing tables. The order matters for the same reason it does at first start: a Router's table is only correct once its children's connections are registered.
3. Atomically swap the host's top-level root handle.
4. Let in-flight operations finish on the retired Stack, then drop it.

Connection state lives in backend layers and connection-owning wrapper Layers.
Rebuilding a Stack resets in-memory connection and auth state unless those
connections are persisted in configuration and can be rehydrated. Streams in
flight continue on the Stack they started on until exhausted or cancelled.

Persistent byte-cache storage is outside any one built Stack's Layer instance.
A rebuilt Stack may reuse an existing byte-cache row only when the new operation
resolves to the same policy partition, canonical post-alias URL, and etag.
Because `backend_id` is intentionally not part of the key, changing or
overlapping backend routes during a rebuild does not by itself invalidate a row;
lacking an etag still makes the object ineligible for byte-cache reuse.

The design does not support in-place splicing of new children into an
already-built Stack: mutating a live root's `inner` / `children` links
post-build would require every language binding and the C ABI to expose
those links with well-defined thread-safety, and the first version keeps
that complexity out of the runtime path. What *is* supported is **build-time
composition over an imported foreign subtree**: a Router's or Wrapper's
build step can take an already-built foreign Layer — obtained via
`import_handle`, see "Cross-language live handoff" — as one of its
`inner` / `children` inputs and compose over it exactly as over a native
child, because an imported foreign layer is itself an `Arc<dyn Layer>`.
That is composition at *build* time of a *new* Stack, not mutation of an
existing one; the built-Stack-is-immutable invariant above is unchanged.

## Request extensions

Every request object that crosses the layer boundary carries an
`OvStorage_Extensions*` immediately after `struct_size`. That includes object
operations (`OvStorage_ReadRequest`, `OvStorage_WriteRequest`, ...),
connection/auth requests (`OvStorage_ConnectionRequest`,
`OvStorage_AuthenticateRequest`, ...), and plugin construction requests
(`OvStorage_CreateWrapperRequest`). Extensions are for cross-cutting per-request
data that must travel with the operation but is not part of the operation's
semantic payload: trace context, audit correlation, deadlines, and host policy
hints. A layer may also use extensions to record facts it already resolved
while handling the operation, such as the selected route, resolved target,
principal, policy partition, retry attempt, or connection key.

```c
typedef struct OvStorage_Extensions OvStorage_Extensions;

typedef struct OvStorage_ExtensionKey {
    size_t struct_size;
    const char* namespace_uri;  /* e.g. "org.omniverse.ovstorage" */
    const char* name;           /* e.g. "trace_context" */
    uint32_t version;
    void* _reserved[8];
} OvStorage_ExtensionKey;

typedef struct OvStorage_ReadRequest {
    size_t struct_size;
    OvStorage_Extensions* extensions;
    const char* address;
    const OvStorage_ReadOptions* options;
    void* _reserved[16];
} OvStorage_ReadRequest;
```

At the C ABI, `OvStorage_Extensions` is opaque. Language bindings expose typed
accessors; raw key/value insertion is reserved for low-level adapters and tests.
The map itself has the same lifetime as the request struct unless a language
binding explicitly clones it into a new child request.

### Rust `Request<T>`

Rust code passes a request envelope, not loose `(addr, opts, cancel)` tuples:

```rust
pub struct Request<T> {
    pub message: T,
    pub extensions: Extensions,
    pub cancel: Option<CancellationToken>,
}

pub trait RequestExtension: Send + Sync + 'static {
    type Value: Clone + Send + Sync + 'static;
    const KEY: ExtensionKey;
}

impl<T> Request<T> {
    pub fn extension<E: RequestExtension>(&self) -> Option<&E::Value> {
        self.extensions.get::<E>()
    }

    pub fn insert_extension<E: RequestExtension>(&mut self, value: E::Value) {
        self.extensions.insert::<E>(value);
    }

    pub fn trace_context(&self) -> Option<&TraceContext> {
        self.extension::<TraceContextExt>()
    }

    pub fn set_trace_context(&mut self, ctx: TraceContext) {
        self.insert_extension::<TraceContextExt>(ctx);
    }
}
```

Layer methods consume `Request<T>` and pass a fresh `Request<T>` to inner
layers when they change cross-cutting state. For example, a tracing Layer
reads `req.trace_context()` as its parent, starts a span, then passes inner a
request whose trace-context extension contains the new span context.

### Extension-trait pattern and well-known registry

Every extension key is represented by a zero-sized marker type implementing
`RequestExtension`. Well-known extensions live in a central registry in the
public crate so all languages agree on the key name, value shape, ownership,
and absence semantics:

| Marker type | Key | Value newtype | Absence means |
|---|---|---|---|
| `TraceContextExt` | `org.omniverse.ovstorage/trace_context@1` | `TraceContext` | No parent context was supplied; a layer that starts a span starts a root span. |
| `AuditIdExt` | `org.omniverse.ovstorage/audit_id@1` | `AuditId` | No host audit correlation ID was supplied; layers do not synthesize one unless they are the host entry point. |
| `RequestDeadlineExt` | `org.omniverse.ovstorage/deadline@1` | `RequestDeadline` | No deadline beyond cancellation was supplied. |
| `ResolvedTargetExt` | `org.omniverse.ovstorage/resolved_target@1` | `ResolvedTargetView` | Recompute from the address and inner Stack when possible; otherwise surface `Internal` if structurally required. |
| `RouteInfoExt` | `org.omniverse.ovstorage/route_info@1` | `RouteInfoView` | Recompute when possible; routing-aware layers that cannot recompute treat absence as `Internal`. |
| `PrincipalExt` | `org.omniverse.ovstorage/principal@1` | `PrincipalView` | Anonymous / unauthenticated when the Stack permits anonymous access. |
| `UpstreamAuthAddressExt` | `org.omniverse.ovstorage/upstream-auth-address@1` | `UpstreamAuthAddress` | Not a brokered-upstream auth request. |
| `ResolvedOAuthCredentialExt` | `org.omniverse.ovstorage/resolved-oauth-credential@1` | `ResolvedOAuthCredentialRef` | No per-request OAuth keyring reference was resolved. |
| `AttributedModifiedByExt` | `org.omniverse.ovstorage/attributed_modified_by@1` | `AttributedModifiedBy` | No host attribution overlay spoke for this request. A plugin leaves any writer identity already present in its own state — a redirect continuation, say — exactly as it found it, and does not derive one from `PrincipalExt`: whether a branch attributes at all is the host's composition decision. |
| `PolicyPartitionExt` | `org.omniverse.ovstorage/policy_partition@1` | `PolicyPartition` | Use the Stack default; policy-enforcing hosts surface `Internal` if no default exists. |
| `RetryAttemptExt` | `org.omniverse.ovstorage/retry_attempt@1` | `RetryAttempt` | Attempt zero. |
| `ConnectionKeyExt` | `org.omniverse.ovstorage/connection_key@1` | `ConnectionKey` | Recompute from the selected connection when possible; otherwise surface `Internal` if required for credential/cache lookup. |

Additions to the well-known registry require a doc update here and matching
typed accessors in the Rust, Python, C++, and C helper surfaces. Private
extensions use a reverse-DNS namespace owned by the plugin or host.

**Implementation status of this table.** None of it is built yet. There is no
`RequestExtension` trait, no marker type and no value newtype anywhere in the
tree; `Extensions` is a `BTreeMap<String, Vec<u8>>` and a key is read with
`Extensions::get`. Only two of the keys above are defined at all —
`org.omniverse.ovstorage/principal@1` and
`org.omniverse.ovstorage/attributed_modified_by@1`, both as bare `&str`
constants in `ovstorage-layer/src/ext.rs` — and neither has a typed accessor in
Rust, Python, C++ or C. The remaining eight rows name keys no code references.
Two of the names in the `Value newtype` column, `PrincipalView` and
`ConnectionKey`, do exist as types in the tree but serve other purposes and are
not extension values.

So read the first and third columns as the shape the extension-trait registry
will introduce, and the requirement above — a doc update here plus matching
typed accessors — as binding on whoever builds that registry rather than as a
description of anything that ships today.

The authentication entries are the exception and already meet that
cross-language requirement. The C plugin SDK publishes
`OVSTORAGE_EXT_AUTH_CREDENTIAL` and
`OVSTORAGE_EXT_PRINCIPAL_DISPLAY_NAME`, plus the typed
`ovstorage_plugin_auth_credential_decode` / `_free` pair. The Python SDK
publishes `EXT_AUTH_CREDENTIAL` and `EXT_PRINCIPAL_DISPLAY_NAME`, and
`AuthCredential.decode()` exposes the credential's transport, peer identity,
forwarded headers, and bearer bytes. `PRINCIPAL_DISPLAY_NAME` remains UTF-8
bytes in an extension bag in both SDKs; absence means that no display name was
resolved.

The C decoder pair is plugin-owned support code rather than a global host
export. A C auth wrapper compiles the shipped `auth_credential.c`,
`plugin_values.c`, `plat.c`, and `utf8.c` sources into its cdylib; a Rust plugin
links the equivalent implementation from `ovstorage-plugin`. The host provides
the credential bytes through the request extension and does not participate in
resolving those helper symbols.

**Newtype-wrap rule.** Extension values are never stored as bare primitives,
generic maps, or SDK-native catch-alls (`String`, `bool`, `HeaderMap`,
`serde_json::Value`, etc.) under a well-known key. Wrap them in a domain type
(`AuditId`, `RequestDeadline`, `TraceContext`) so type identity, redaction, FFI
ownership, and future schema evolution stay explicit.

**Absence semantics.** Missing is not false, empty, denied, or defaulted. Missing
means "not supplied." A layer that reads an extension picks one of three
documented patterns: recompute the value locally, surface `Internal` when the
value is structurally required and cannot be recomputed, or treat absence as a
real value when the registry says so (`PrincipalView = None` for anonymous,
`RetryAttempt = 0`, no trace parent). Intermediate layers must not infer policy
from absence unless the specific well-known extension says so. This keeps
extension rollout additive: older callers that do not know a key do not
accidentally change authorization, caching, or tracing behavior.

**Facts, not instructions.** An extension value describes the request's
context (trace parent, deadline, principal, policy partition) or records a
fact a layer already resolved (selected route, retry attempt). It must never
be a behavior selector addressed to a specific layer kind — "don't follow this
redirect," "skip your cache." A caller that wants different behavior composes
a different Stack (the REST-gateway idiom: omit `RedirectFollowerWrapper` to
see raw redirects). Behavior-selector extensions couple callers to a Stack's
composition, which is exactly what the uniform Layer surface exists to
prevent. Every entry in the well-known registry above complies; the
transitional `RAW_READ_EXTENSION` in the 0.x facade predates this rule and is
being replaced by sub-stack composition (issue #169).

## Memory ownership and async at the C ABI

This is an I/O library. Memory-ownership and async-callback rules at the FFI boundary are load-bearing — getting them wrong leaks secrets, dangles pointers, or deadlocks runtimes. Every Layer implementation in every language inherits these rules verbatim.

### Pointer ownership across a vtable call

| Pointer kind | Ownership | Plugin obligation |
|---|---|---|
| Request structs (`OvStorage_StatRequest*`, `OvStorage_ReadRequest*`, ...) | Caller-owned; valid only during the synchronous prologue of the vtable call | Plugin must extract every field it needs synchronously into plugin-owned storage before returning from the prologue. After the vtable function returns (even before `on_complete` fires), the request pointer is invalid. |
| `OvStorage_Extensions*` inside requests | Caller-owned; valid for the request's synchronous prologue unless cloned by a language binding | Plugin may read extension values synchronously. To carry extensions into async work or an inner request, clone through the host/language helper so extension value ownership stays typed. |
| String pointers inside requests (URLs, IDs) | Caller-owned; same lifetime as the parent request | Plugin clones strings it needs to retain. |
| Byte buffers in requests (`OvStorage_Bytes`) | Caller-owned; same lifetime as the parent request | Plugin clones (or moves into a tokio task) before returning. |
| Result structs (`OvStorage_ObjectInfo*`, `OvStorage_ReadResult*`, ...) | Plugin-allocated, host-owned after `on_complete` | Host calls the matching `_destroy` function when done. |
| Error pointers (`OvStorage_Error*`) | Plugin-allocated when present; host-owned | Host calls `ovstorage_error_destroy`. |
| Streams (`OvStorage_AsyncByteStream*` for byte reads, `OvStorage_Stream*` for item/event streams) | Plugin-allocated; host-owned, drained until exhaustion or cancellation | Host calls `_destroy` (byte stream) / `drop` (item stream) after exhaustion or cancellation. |
| `OvStorage_LayerHandle.state` | Plugin-allocated per Layer instance; host-owned while that built Stack is alive | Host calls `vtable.drop` exactly once when the Layer instance is dropped. |
| `plugin_state` | Plugin-allocated per loaded cdylib; host-owned while any Layer created from that plugin is alive | Host calls `plugin_vtable.drop` after all handles from that plugin are dropped. |
| `OvStorage_SecretBytes` | Heap-allocated, zeroize-on-drop. Crossing the ABI **moves** ownership; receivers do not copy. | Receivers either store (into secret store / connection state) or drop. Never log, never serialize, never copy without intent. |
| `OvStorage_HostCallbacks*` | Host-owned for the cdylib's lifetime | Plugin may stash but must not free. |
| `OvStorage_CancelToken*` | `Arc<CancellationToken>` semantics. Holders take a ref count. | Plugin drops when done. |

The plugin's responsibility, summarized: **read the request synchronously, drop the borrow, do async work, allocate the result in plugin memory, fire `on_complete`**. Any plugin that retains a borrow across an `.await` is buggy.

### Async callback shape

Every async vtable slot has the same shape:

```c
void (*method)(void* state,
               const OvStorage_Request* req,           /* caller-owned */
               OvStorage_CancelToken* cancel,           /* nullable */
               OvStorage_OnComplete on_complete,
               void* user_data);
```

```c
typedef void (*OvStorage_OnComplete)(
    int32_t status,                  /* 0 = success, -1 = error */
    void* result,                    /* type per method; NULL on error */
    OvStorage_Error* error,          /* NULL on success */
    void* user_data
);
```

Rules:

1. **`on_complete` is called exactly once.** Calling it twice, or never, is undefined behavior.
2. **Outcome dispatch is by pointer presence**, not status code. `error == NULL` is success, `error != NULL` is failure. Status exists only for tooling that prefers an integer signal.
3. **`on_complete` may be invoked synchronously from the vtable call's prologue** (e.g. a cache hit that resolves immediately). Callers must tolerate synchronous completion without reentering their runtime.
4. **`on_complete` may be invoked from any thread the plugin chooses.** Callers must not assume same-thread completion.

### Panic and unwinding discipline

- The Rust workspace keeps the default `panic = "unwind"`. Every `extern "C"` entry point wraps Rust execution in `std::panic::catch_unwind` and converts an escaped panic to `ErrorCode::Internal`, so the FFI never unwinds across a C frame. A panic that escapes an `extern "C"` fn uncaught is force-aborted by rustc (≥ 1.81, guaranteed on edition 2024) as a backstop.
- These `catch_unwind` walls are the recoverable-error path: layer authors return typed `ErrorCode::Internal` for internal failures, and a single operation's panic does not tear down the host — a task panic does not abort a broker/REST process, and pyo3 surfaces it as a catchable `PanicException` rather than a `SIGABRT`.
- Pure-C / pure-C++ layers must not `throw` exceptions across the FFI. C++ vtable methods are `noexcept` by convention.

### Runtime-context rule

The Rust runtime is tokio; the C runtime is a thread pool; the Python runtime is asyncio. **An async vtable callback (`on_complete`) must not re-enter the calling thread's runtime context.** Specifically:

- A tokio worker invoking `on_complete` must not synchronously call a method that re-enters tokio's executor (e.g. building a `reqwest::blocking::Client` which spins its own runtime).
- A pure-C thread-pool worker invoking `on_complete` must not call a vtable method that expects to run on the caller's runtime.
- A Python PyO3 thunk invoking `on_complete` must hold the GIL appropriately and not block on async work without releasing it.

The standard pattern at every FFI seam: use `std::thread::spawn` (or its equivalent) to sever the runtime context, plus a oneshot / channel to route the result back. This is the same rule that's in today's `plugin-development/README.md` § Hard invariants; it carries forward verbatim.

### Unload ordering

Plugin unload is reverse-topology:

1. Drain all in-flight calls and let their `on_complete` callbacks fire.
2. Drop all returned streams and `LocalDelegate` handles.
3. Drop all Layer instances (call each `vtable.drop`).
4. Drop the cdylib's `plugin_state` through `plugin_vtable.drop`.
5. `dlclose` the shared library.

A host that closes a cdylib with in-flight calls or live streams risks crashes — every in-flight callback may end up pointing at unmapped memory. The host's `Library::drop` enforces this order; applications never call `dlclose` directly.

## Observability host callbacks

`OvStorage_HostCallbacks` carries logging, metrics, and tracing sinks the plugin
uses to emit observability without depending on a specific library. Plugins emit
through these callbacks; the host adapts to its observability tooling.

### Compliance context

ovstorage is part of Omniverse, which is governed by two PLC-L1 SRDs in this
space:

- [Omniverse Logging SRD](https://docs.google.com/document/d/1teJFU7TjPWKb_tCDoaBJNqZDrHxff2tJ5juqqRrvh-0/edit?tab=t.0)
- [Omniverse Metrics SRD](https://docs.google.com/document/d/1Hmp8FBSAg0Is-Kn_XiY8xJXyiX_yxmVPoa_Ke3ouSFw/edit?tab=t.0)

Both align plugin-emitted observability with OpenTelemetry (OTel) concepts.
The default host adapter emits OTel-shaped logs, metrics, and traces into the
host's configured OTel SDK / OTLP pipeline; Prometheus, statsd, or in-process
tallying are exporter or adapter choices layered behind that host adapter, not
separate plugin-facing defaults.

The callback shapes below are OTel-shaped, but plugins do not configure or
depend on an OTel SDK. The host adapter owns SDK configuration and export:
env-var contract, resource attributes, exporter selection, export cadence,
sampling, Views, and NVCF/GCP enrichment. This section specifies the
host↔plugin ABI; SDK configuration is out of scope.

Naming conventions plugin authors must follow:

- Metric, span, and log names follow OTel semantic conventions
  (`ovstorage.s3.request.duration`); the OTel collector handles any
  Prometheus-form rename on export.
- Units follow UCUM (`s` for seconds, `By` for bytes, etc.).

**Data hygiene (P0).** All observability payloads — log messages and fields,
metric labels, span attributes, and span events — must comply with the
Logging SRD's data-hygiene rule:

- **Never emit:** secrets, PII, intellectual property (IP), result payloads
  (the bytes/body of reads or writes), user data, cache keys, signed-URL
  query strings, credential material.
- **Always permitted:** operational outcomes — error codes, status codes,
  span statuses, `cache.hit`, retry counts, redirect kinds, attempt numbers,
  layer-internal state transitions. Logs and metrics carry *what happened to
  the operation*, not *what the operation operated on*.
- **Redacted by convention:** object addresses (`s3://prod/bucket/****`).

Layer authors construct payload values with this in mind; the host does not
filter post-hoc.

Trace correlation across the host↔plugin boundary flows through the request's
`extensions` slot (see "Request extensions" above); each
observability callback that needs correlation accepts the trace context as an
explicit parameter.

### Pointer lifetimes for observability callbacks

Every observability callback (logger `log`; metrics `add` / `observe` / `set`;
tracer `span_start` / `span_add_event` / `span_set_attribute` /
`span_set_status` / `inject_trace_context`) takes pointer-backed arguments:
strings, `OvStorage_KeyValue` arrays, span-link arrays, source-location
structs, trace-context handles, and so on. The host MUST either copy or
fully consume all such pointer-backed data before the callback returns.
After return, the plugin may free or invalidate the underlying stack.

This lets host adapters queue records to async log / metric / trace exporters
internally without retaining plugin-owned pointers, and lets plugins build
callback arguments on the stack with lifetimes that match a single call.

Two exceptions, both spec'd at their respective sites:

- **`register_instrument` (Metrics)** — the host copies descriptor data
  including `name`, `unit`, `description`, and `histogram_advice.boundaries`
  at registration time, because the host retains it for idempotency checks
  across subsequent calls. Same stack-allocation flexibility for the plugin.
- **`OvStorage_TraceContext*` handles** — host-allocated and host-owned;
  the plugin releases via `trace_context_destroy` when done (see Tracer
  section).

### Logger

```c
typedef enum OvStorage_LogLevel {
    OVSTORAGE_LOG_TRACE = 0,
    OVSTORAGE_LOG_DEBUG = 1,
    OVSTORAGE_LOG_INFO  = 2,
    OVSTORAGE_LOG_WARN  = 3,
    OVSTORAGE_LOG_ERROR = 4,
} OvStorage_LogLevel;

typedef struct OvStorage_KeyValue {
    const char* key;
    OvStorage_Value value;            /* tagged union: str / int / bool / f64 */
} OvStorage_KeyValue;

typedef struct OvStorage_SourceLocation {
    size_t struct_size;
    const char* file;        /* OTel code.filepath */
    uint32_t    line;        /* OTel code.lineno */
    const char* function;    /* OTel code.function; may be NULL */
    void* _reserved[8];
} OvStorage_SourceLocation;

typedef struct OvStorage_Logger {
    /* Fast filter. The host returns false when (target, level) is suppressed
       by the global log-level or a per-module override (e.g. the Logging
       SRD's LOGS_MODULES). Plugins call this before formatting to skip
       suppressed records cheaply. */
    bool (*enabled)(void* ctx, const char* target, OvStorage_LogLevel level);

    /* Emit a structured log event.

       `trace_context` is optional; when non-NULL, the host attaches the
       active span's trace_id and span_id to the emitted record for OTel
       LogRecord correlation. The plugin reads it from the current Request's
       extensions.

       `source` is required for every record (the Logging SRD's metadata
       rule mandates file/line on every log line, not just errors).
       Language wrappers capture file/line/function at the call site
       automatically (Rust's `Location::caller()`, Python's `inspect`,
       C++'s `__builtin_FILE` / `__builtin_LINE` / `__builtin_FUNCTION`),
       so plugin authors don't write source explicitly. */
    void (*log)(void* ctx,
                OvStorage_LogLevel level,
                const char* target,
                const char* message,
                const OvStorage_KeyValue* fields,
                size_t field_count,
                const OvStorage_TraceContext* trace_context,
                const OvStorage_SourceLocation* source);
    void* ctx;
} OvStorage_Logger;
```

`target` is the module-shaped name (e.g. `"ovstorage_s3::write"`). `message`
is the un-rendered template body; `fields` carries the structured key-value
pairs separately so OTel serialization is lossless — pre-formatted strings on
the hot path are not permitted. `trace_context` is the in-process trace
context for correlation (see "Trace context propagation" below).

### Metrics sink

OTel metric instruments are typed objects with declared kind, unit, and
description. The sink registers instruments once (at startup, or first use) and
emits values against the resulting handles. Per-call ad-hoc metric creation is
not supported — that's a structural mismatch with the OTel model.
Only synchronous instruments cross the plugin ABI. OTel asynchronous
instruments / observers are host-internal, if a host uses them at all; plugins
do not register callbacks for the SDK to poll.

```c
typedef enum OvStorage_InstrumentKind {
    OVSTORAGE_INSTRUMENT_COUNTER         = 0,  /* monotonic add */
    OVSTORAGE_INSTRUMENT_UP_DOWN_COUNTER = 1,  /* any-sign add */
    OVSTORAGE_INSTRUMENT_HISTOGRAM       = 2,  /* observe */
    OVSTORAGE_INSTRUMENT_GAUGE           = 3,  /* set */
} OvStorage_InstrumentKind;

/* Histogram bucket-boundary advisory. Per OTel's instrument-advisory
   mechanism, the SDK MAY use these as the default aggregation boundaries
   for a Histogram-kind instrument. SDK Views can override. `boundaries`
   is an ascending sequence of doubles; `count` is the number of entries
   (which produces `count + 1` buckets). NULL on the descriptor means "no
   advice — let the SDK Views decide." */
typedef struct OvStorage_HistogramAdvice {
    size_t struct_size;
    const double* boundaries;
    size_t count;
    void* _reserved[8];
} OvStorage_HistogramAdvice;

typedef struct OvStorage_InstrumentDescriptor {
    size_t struct_size;
    const char* name;        /* OTel semconv form, e.g. "ovstorage.s3.request.duration" */
    OvStorage_InstrumentKind kind;
    const char* unit;        /* UCUM, e.g. "s" / "By" / "{request}" */
    const char* description; /* required by the Metrics SRD's P0 documentation rule */
    /* Histogram-only; ignored for other kinds. May be NULL. */
    const OvStorage_HistogramAdvice* histogram_advice;
    void* _reserved[8];
} OvStorage_InstrumentDescriptor;

typedef struct OvStorage_MetricsSink {
    /* Register a synchronous instrument. Returns an opaque handle the
       plugin uses for subsequent observations. Idempotent on (name, kind):
       repeated registration with matching descriptors returns the same
       handle; mismatched descriptors are an error. */
    OvStorage_Instrument* (*register_instrument)(
        void* ctx,
        const OvStorage_InstrumentDescriptor*,
        OvStorage_Error** err);

    /* Counter and UpDownCounter add. Counter-kind handles reject
       negative values; UpDownCounter accepts any sign. */
    void (*add)(void* ctx,
                OvStorage_Instrument* instrument,
                double value,
                const OvStorage_KeyValue* labels,
                size_t label_count,
                const OvStorage_TraceContext* trace_context); /* optional, for exemplars */

    /* Histogram observation. trace_context, when present, becomes the
       exemplar the OTel SDK may sample (P1 in the Metrics SRD). */
    void (*observe)(void* ctx,
                    OvStorage_Instrument* instrument,
                    double value,
                    const OvStorage_KeyValue* labels,
                    size_t label_count,
                    const OvStorage_TraceContext* trace_context);

    /* Gauge set. */
    void (*set)(void* ctx,
                OvStorage_Instrument* instrument,
                double value,
                const OvStorage_KeyValue* labels,
                size_t label_count);

    void* ctx;
} OvStorage_MetricsSink;
```

**Descriptor pointer lifetimes.** `register_instrument` takes a
`const OvStorage_InstrumentDescriptor*`. The host copies all pointer-backed
descriptor data — `name`, `unit`, `description`, and (when present)
`histogram_advice` including its `boundaries` array — into host-owned storage
during the call. The plugin may allocate descriptors on the stack and let
them go out of scope after the call returns; the host's idempotency /
mismatch checks across registrations operate on its copies, not on the
plugin's pointers. The returned `OvStorage_Instrument*` handle is the only
thing the plugin retains.

Layer authors choose metric names following OTel semantic conventions
(`ovstorage.s3.request.duration`, not Prometheus
`ovstorage_s3_request_duration_seconds_total` — the OTel collector handles the
rename on export). Units follow UCUM. Label cardinality is the layer author's
responsibility — high-cardinality labels (per-request, per-object IDs) are a
known cost trap that the Metrics SRD calls out as a P0 don't.

Every histogram instrument must have a defined bucket schema. Plugin
authors set `histogram_advice` to one of the Metrics SRD's well-known
boundary arrays (latency, extended latency, byte-size) or to a custom
array. If `histogram_advice` is NULL, the host's OTel SDK MUST have a
configured View covering the instrument name; hosts treat a histogram
with neither advice nor a matching View as a registration error. Per
OTel's instrument-advisory mechanism, advice is the default boundaries
and a configured View overrides — typically the SRD-aligned advice and
the host's standard Views agree, and the View override exists for
deployment-specific tuning.

The `observe` call itself carries no bucket data — boundaries are an
instrument-level property, set once at registration.

### Tracer

```c
typedef enum OvStorage_SpanKind {
    OVSTORAGE_SPAN_INTERNAL = 0,
    OVSTORAGE_SPAN_SERVER   = 1,
    OVSTORAGE_SPAN_CLIENT   = 2,
    OVSTORAGE_SPAN_PRODUCER = 3,
    OVSTORAGE_SPAN_CONSUMER = 4,
} OvStorage_SpanKind;

typedef enum OvStorage_SpanStatus {
    OVSTORAGE_SPAN_STATUS_UNSET = 0,
    OVSTORAGE_SPAN_STATUS_OK    = 1,
    OVSTORAGE_SPAN_STATUS_ERROR = 2,
} OvStorage_SpanStatus;

typedef struct OvStorage_SpanLink {
    size_t struct_size;
    const OvStorage_TraceContext* context;
    const OvStorage_KeyValue* attrs;
    size_t attr_count;
    void* _reserved[8];
} OvStorage_SpanLink;

typedef struct OvStorage_SpanStartRequest {
    size_t struct_size;
    const char* name;
    OvStorage_SpanKind kind;
    /* Parent context. NULL = root span. Plugins typically pass the
       trace context from the current Request's extensions. */
    const OvStorage_TraceContext* parent;
    const OvStorage_KeyValue* attrs;
    size_t attr_count;
    const OvStorage_SpanLink* links;
    size_t link_count;
    void* _reserved[8];
} OvStorage_SpanStartRequest;

typedef struct OvStorage_TracerProvider {
    /* Start a span. The returned Span is the only handle used for
       subsequent operations on this span. */
    OvStorage_Span* (*span_start)(void* ctx,
                                  const OvStorage_SpanStartRequest*);

    /* Get the trace context from an active span. Used to insert the
       span's context into a downstream Request's extensions, or to
       inject into outgoing headers. The returned handle must be
       released with trace_context_destroy. */
    OvStorage_TraceContext* (*span_context)(void* ctx,
                                            OvStorage_Span* span);

    /* Get the host's current OTel context. Used by the library facade
       at the call entry point to capture the application's active
       span (or NULL if none) into the Request's extensions. After
       capture, propagation runs through extensions, not thread-local. */
    OvStorage_TraceContext* (*current_context)(void* ctx);

    void (*span_add_event)(void* ctx,
                           OvStorage_Span* span,
                           const char* name,
                           const OvStorage_KeyValue* attrs,
                           size_t attr_count);
    void (*span_set_attribute)(void* ctx,
                               OvStorage_Span* span,
                               const OvStorage_KeyValue* attr);

    /* Set the span's outcome. Call at most once before span_end. */
    void (*span_set_status)(void* ctx,
                            OvStorage_Span* span,
                            OvStorage_SpanStatus status,
                            const char* description); /* NULL or "" for none */

    /* End the span. Subsequent operations on the handle are UB. */
    void (*span_end)(void* ctx, OvStorage_Span* span);

    /* W3C trace-context propagation. inject writes traceparent + tracestate
       and any active baggage into the header map; extract reads them back.
       Implementations handle both headers as a pair. */
    void (*inject_trace_context)(void* ctx,
                                 const OvStorage_TraceContext* trace_context,
                                 OvStorage_HeaderMap* headers);
    OvStorage_TraceContext* (*extract_trace_context)(void* ctx,
                                                     const OvStorage_HeaderMap* headers);

    /* Release a TraceContext handle returned by extract_trace_context,
       current_context, or span_context. */
    void (*trace_context_destroy)(void* ctx,
                                  OvStorage_TraceContext* trace_context);

    void* ctx;
} OvStorage_TracerProvider;
```

`span_start` always takes an explicit parent context (or `NULL` for a root
span). The plugin reads the parent from the current Request's extensions —
typically populated by the host from incoming headers or by the calling layer.
After `span_start`, the plugin calls `span_context(span)` to get the new span's
context and writes it back into the Request it passes to inner layers, so the
downstream sees this span as its parent.

`SpanKind` is required at start. Storage plugins making outgoing HTTP/SDK calls
use `CLIENT`; broker servers handling incoming gRPC use `SERVER`; most internal
spans are `INTERNAL`. `span_set_status(span, status, description)` sets the
span outcome — OK on success, ERROR with a description on failure. `SpanLink`s
carry references to other related spans for fan-out / scatter-gather (e.g.
`copy(src, dest)` linking both src and dest reads, multipart uploads with N
parallel parts).

Trace context lifetimes are explicit: handles returned by
`extract_trace_context`, `current_context`, and `span_context` are
host-allocated and the plugin must release each via `trace_context_destroy`.

### Trace context propagation

Trace context (W3C traceparent + tracestate + baggage) is the spine of OTel
correlation. Propagation has two halves: how the context enters the Stack
(host-side) and how it flows through the Stack (layer-side).

#### Entry: the library facade captures the OTel current context

The library's user-facing methods (the facade — `library.read_bytes(addr, opts, cancel)`
and equivalents in each language binding) capture the host's OTel current
context at the entry point and insert it into the request's extensions:

```rust
impl Library {
    pub async fn read_bytes(&self, addr: Url, opts: ReadOptions, cancel: Option<CancellationToken>)
        -> Result<(Vec<u8>, ObjectInfo)>
    {
        let mut req = Request {
            message: ReadBytesRequest { addr, opts },
            extensions: Extensions::new(),
            cancel,
        };

        // Capture the host's current OTel context at the facade entry point.
        // This is the ONE place we read from thread-local; everything below
        // reads from extensions, not thread-local. That keeps propagation
        // intact across runtime hops within the Stack.
        if let Some(ctx) = self.host_callbacks.tracer.current_context() {
            req.set_trace_context(ctx);
        }

        self.root.read_bytes(req).await
    }
}
```

This is the only place the design relies on thread-local OTel state. By
capturing once at the facade and threading through extensions afterward, the
Stack propagation stays correct across runtime boundaries — the plugin's tokio task
severed from the caller's runtime per the runtime-context rule sees the
context as data on the request, not as state on a thread that doesn't exist
anymore.

#### Host integration patterns

Hosts don't need to know about the request-extensions mechanism. They use the
OTel SDK normally; the facade picks up whatever the SDK considers current. The
host's responsibility differs by deployment shape:

**Desktop application, no operation-level spans.** Most casual library use. The
application doesn't open spans for individual operations; OTel current context
is empty when the library is called. The library's first internal span becomes
a root span; subsequent layers nest under it.

```rust
async fn on_open_file_clicked() {
    let (bytes, info) = library.read_bytes("s3://my/file.usd", opts, None).await?;
    // Library's spans are rooted at the outermost layer's span.
}
```

**Desktop application with operation-level spans.** Larger apps that wrap
user-facing operations in their own spans.

```rust
async fn on_open_file_clicked() {
    let span = global::tracer("desktop-app").start("ui.open_file");
    let _guard = mark_span_active(&span);
    // OTel current context = "ui.open_file" span

    let (bytes, info) = library.read_bytes("s3://my/file.usd", opts, None).await?;
    // Library's spans nest under "ui.open_file".

    span.end();
}
```

**Server handling incoming requests** (REST gateway, broker daemon, gRPC
service). The host extracts trace context from incoming headers, opens a
SERVER span as a child of the extracted context, sets it as current, then
calls the library.

```rust
async fn handle_get_object(req: HttpRequest) -> HttpResponse {
    let parent_context = global::propagator().extract(&req.headers);
    let span = global::tracer("rest-gateway")
        .span_builder("GET /v1/objects")
        .with_kind(SpanKind::Server)
        .with_parent_context(&parent_context)
        .start();
    let _guard = mark_span_active(&span);
    // OTel current context = SERVER span with upstream parent

    let addr = parse_url(&req.path)?;
    let (bytes, info) = library.read_bytes(addr, opts, None).await?;
    // Library's spans nest under the SERVER span,
    // which is itself a child of the upstream client.

    span.end();
    bytes_response(bytes, info)
}
```

The library facade is identical in all three. The host's choice of whether and
how to set up the current OTel context determines what the library inherits.

| Host type | What the host does |
|---|---|
| Desktop app, uninstrumented | Nothing. Library's spans are roots. |
| Desktop app with UI spans | Open span; set as current. Library inherits. |
| REST gateway | Extract from HTTP headers, open SERVER span, set as current. Library inherits. |
| gRPC service | Extract from metadata, open SERVER span, set as current. Library inherits. |
| Broker daemon | Extract from broker protocol, open SERVER span, set as current. Library inherits. |

#### Through the Layer Stack

Once trace context is in `req.extensions`, the propagation pattern is uniform
across logs, metrics, and traces:

1. **At each layer.** Layers wanting to open a span call `span_start` with
   `parent = request.extensions.trace_context()`. They obtain the new span's
   context via `span_context(new_span)` and write it back into the request's
   extensions (replacing the parent) before passing the request to inner.
   They also pass the same trace context to any `log` / `add` / `observe`
   call so the host can correlate.
2. **Outbound at the leaf.** Backend layers making outgoing network calls
   inject the current trace context into outgoing headers via
   `inject_trace_context`. The downstream receiver extracts it and the Stack
   continues.
3. **On span end.** The layer calls `span_set_status` with OK or ERROR, then
   `span_end`. Spans nest naturally because each layer's `span_context` is
   the next layer's `parent`.

The design survives the runtime-context rule (plugins severing the caller's
runtime context via `std::thread::spawn` or equivalent) because the trace
context is data on the request, not thread-local state. Each layer's span
inherits its parent from the explicit context in the request, not from
whatever happens to be on the calling thread.

### Language wrappers

The C ABI definitions above are the wire format — the contract between the
host's SDK and any plugin's wrapper layer. Plugin authors in Rust, Python,
and C++ don't write to this surface directly; idiomatic wrappers ship with
the per-language SDKs (see "Per-language idiomatic surfaces" earlier).

In Rust this means RAII via `Drop` impls so spans and trace-context handles
auto-clean on scope exit; in Python it means async context managers
(`async with host.tracer.span(...) as span:`); in C++ it means
destructor-based cleanup. The contrast at the call site:

```rust
// Raw C ABI shape (illustrative — plugin authors don't write this):
let span = host.tracer.span_start(&SpanStartRequest { ... });
let span_ctx = host.tracer.span_context(span);
/* ... do work ... */
host.tracer.span_set_status(span, SpanStatus::Ok, None);
host.tracer.span_end(span);
host.tracer.trace_context_destroy(span_ctx);

// Idiomatic Rust wrapper (what plugin authors actually write):
let span = host.tracer.span("s3.GetObject")
    .kind(SpanKind::Client)
    .parent(req.trace_context())
    .start();
/* ... do work, span.ok() / span.error(...) to set status ... */
// span dropped at scope end → span_end + trace_context_destroy in Drop.
```

The pure-C distribution ships `ovstorage_observability.h` with
cleanup-attribute macros (`OVSTORAGE_SPAN_SCOPE(...)`) that emit the same
cleanup pattern. C authors who prefer raw vtable calls can write them —
the ABI is exposed directly.

## TOML configuration

A Stack config is a serializable specification: named Layer instances,
persisted Connection declarations, and a root Layer reference. Hosts and CLIs
use the same format. The host loads the config file once and hands each instance
its nested config table during the matching `create_*` factory call.

The worked example in "Stack and routing" shows the canonical shape. The
reference below documents the schema in detail.

### Top-level structure

```toml
[ovstorage]
root = "alias"                      # name of the root Layer

[ovstorage.layers.<name>]           # one table per Layer instance:
# ...                               #   backend, wrapper, or router

[[ovstorage.connections]]           # persisted Connections — one flat array,
# ...                               #   each addressed to its owner by `target`
```

### Layers

Each `[ovstorage.layers.<name>]` table is one Layer instance; the table key is
its instance name. The Stack builder resolves `kind` through the manifest
registry populated from built-ins, `plugin_dirs`, and any explicitly loaded
plugin paths. The manifest descriptor for `kind` supplies `layer_type =
"backend" | "wrapper" | "router"` and determines which edge fields are valid.

```toml
# table key = the instance name (which one); `kind` = the type (what it is).
# A `kind` is a manifest kind: it selects the implementation, construction
# factory, and config/credential schema. Many instances can share one kind,
# each a distinct Layer with its own Connections and Stack placement — so the
# name is never derivable from the kind.
[ovstorage.layers.s3-prod-backend]
kind = "s3"                         # manifest kind, layer_type = "backend"
# Optional Layer-level settings only. Optional `plugin = "libovstorage_s3"`
# disambiguates when multiple plugins export the same kind.

[ovstorage.layers.metadata_cache]
kind = "metadata_cache"             # layer_type = "wrapper"
inner = "main-router"
config = { ttl_seconds = 60, max_entries = 10000 }

[ovstorage.layers.main-router]
kind = "router"                     # layer_type = "router"
children = ["s3-prod-byte-cache", "s3-secrets-permission", "s3-staging-backend", "file-backend"]
# Each child name resolves to a Layer.
```

Backend layers carry only Layer-level config. Buckets, regions, credentials,
and alias rules are Connections (see below), per the kind / connection / root
scope split.

Wrapper layers use `inner = "<name>"`:

```toml
[ovstorage.layers.audit-prod]
kind = "audit"                      # layer_type = "wrapper"
inner = "s3-prod-backend"
config = { log_path = "/var/log/ovstorage-audit.log" }
```

Routers use `children = [...]`. Wrappers use `inner`. Backend layers use
neither. The host rejects a config whose edge fields do not match the kind's
`layer_type`.

Two Layer instances of the same kind are allowed — different names with
different nested configs. The same kind can be reused in different parts of the
Stack with different tuning:

```toml
[ovstorage.layers.s3_aggressive_retry]
kind = "retry"
config = { max_attempts = 10, initial_delay_ms = 200 }

[ovstorage.layers.default_retry]
kind = "retry"
config = { max_attempts = 3, initial_delay_ms = 50 }
```

Per-route policy nests under the named Layer that owns it. Because
`byte_cache` is a name-keyed table (not an array element), the nested `routes`
array-of-tables addresses it unambiguously:

```toml
[ovstorage.layers.byte_cache]
kind = "byte_cache"
config = { cache_dir = "${XDG_CACHE_HOME}/ovstorage", max_bytes = "16 GiB" }

[[ovstorage.layers.byte_cache.routes]]
prefix              = "s3://prod/large/"
max_object_bytes    = "1 GiB"

[[ovstorage.layers.byte_cache.routes]]
prefix              = "s3://prod/secrets/"
disabled            = true
```

The Layer parses its own per-route policy and applies it to matching URLs.

### Connections

Connections are a single flat array. Each declaration names its owning
connection-owning Layer with `target` (a Layer name — not a kind name, and not
a router indirection); the connection's **kind is inherited from that Layer**,
so it is not repeated on the connection. Identity is `(target, id)` — `id` is
unique within the owning Layer, and for an S3 Layer it doubles as the URL
authority the connection serves (`s3://<id>/`). A single Layer may own several
connections, each a distinct `id` (the `s3-prod-backend` Layer in "Stack
and routing" owns both `prod` and `prod-archive`). This is the one canonical home
for buckets, credentials, and alias rules, and the sink a runtime
`add_connection` serializes back to.

```toml
[[ovstorage.connections]]
target = "alias"                    # the Layer that owns this connection (an AliasWrapper)
id     = "my-stuff"
config = { from = "my://stuff", to = "s3://prod/users/me" }   # `to` = rewrite dest

[[ovstorage.connections]]
target = "s3-prod-backend"          # the backend layer that owns this connection
id     = "prod"                     # unique within the Layer; for S3, the s3://prod/* authority
config = { bucket = "ov-prod", region = "us-west-2" }
credentials = { source = "keyring" }
```

### Schema rules

- TOML keys are lowercase. Schema field names (`kind`, `config`, `inner`,
  `children`, …) use `snake_case`; Layer names — the table keys under
  `[ovstorage.layers.*]` — may use `-` or `_` (both are valid TOML bare keys;
  pick one convention and keep it consistent).
- Layer names are the table keys under `[ovstorage.layers.*]`. They share a
  single namespace because Router `children`, wrapper `inner`, connection
  `target`, and top-level `root` are all resolved *by Layer name*.
- `layer_type` is not repeated in TOML. It comes from the resolved factory
  descriptor. This keeps the config from having two sources of truth.
- A backend Layer table must not declare `inner` or `children`.
- A wrapper Layer table must declare exactly one `inner = "<layer-name>"`.
- A router Layer table uses `children = [...]`; each child name resolves to a
  Layer.
- The `root` name must resolve to an `[ovstorage.layers.*]` table. The host
  builds that Layer and uses its handle as the application-facing entry point.
- The reference relation (`root`, wrapper `inner`, router `children`) must be
  acyclic. A connection-owning Layer must be referenced from exactly one place
  so connection `target` names one runtime instance.
- `[[ovstorage.connections]]` is the only array-of-tables; every other entity
  is a name-keyed table so nested policy (e.g. `byte_cache.routes`) addresses
  its owner unambiguously rather than attaching to whichever array element came
  last.
- Sizes are strings parsed by `humansize` (`"16 GiB"`, `"5 MB"`).
- Durations are integer milliseconds.
- Secret references use `${ENV_VAR}` substitution or `{ source = "keyring", key = "..." }` indirection.

This shape replaces today's `LibraryConfig` / `RouteConfig` / etc. schema.
Instance tables map to manifest kinds by `kind`; the table key (the Layer name)
gives applications, CLIs, Router children, and connection declarations a stable
handle for editing and serialization. The CLI writes the same shape it reads, so
"configure in the CLI, load in an app" is a supported workflow rather than an
export path with a different schema.

## C/C++ source distribution

A small source set that compiles standalone:

```
ovstorage-c-source/
├── include/
│   ├── ovstorage_backend.h  # C ABI vtable, types, error model
│   ├── ovstorage.h          # C public API
│   └── ovstorage.hpp        # C++17 thin wrapper (header-only)
└── src/
    ├── dispatch.c           # default vtables (PASSTHROUGH / UNSUPPORTED),
    │                        #   Stack construction, Layer instantiation
    ├── file_backend.c       # pure-C FileBackend implementation
    ├── cancel.c             # OvStorage_CancelToken impl (atomic flag
    │                        #   + condvar; no async runtime needed)
    └── runtime.c            # thread-pool-backed async dispatch
                             #   (callback invocation, no tokio)
```

Dependencies: standard C library, POSIX `pthread` / `pread` / `pwrite` on Unix, Win32 equivalents. No libuv, libcurl, OpenSSL, or other third-party C library.

The pure-C `file_backend.c` is the embedded default fallback for applications
that link nothing else. An application that wants more schemes calls
`ovstorage_load_plugin("/path/to/libovstorage_http.so", &err)`, registers the
plugin, then sets it as the terminal Layer (or a Router child) with
`ovstorage_stack_add_layer(stack, registry, "http", "http", config, &err)`,
then finalizes with `ovstorage_stack_build(stack, &err)`.

Customers consume the source in one of two ways:

1. **Include the source files directly** in their build.
2. **Build a static library themselves** (`ar rcs libovstorage.a src/*.o`).

`Makefile.example` and `CMakeLists.txt.example` ship as reference; we don't maintain a blessed build system for the customer.

The pure-C runtime is a thread pool. Async vtable slots dispatch onto worker threads and invoke `on_complete` when the work finishes. This is simple, portable, and adequate for the C/C++ default-fallback use case.

## What this breaks

No backwards compatibility is preserved.

1. **Plugin C ABI 1.0 break.** The storage plugin ABI becomes an ABI-v2 surface with separate `create_backend`, `create_wrapper`, and `create_router` factories. Every existing first-party plugin recompiles.
2. **Public Rust API redesign.** The current `ovstorage::Storage` trait is replaced by one operational `Layer` trait plus factory shapes for backend, wrapper, and router construction. `Library::open()` becomes a Stack builder that constructs Stacks.
3. **`Factory` SPI changes shape.** Static descriptor data moves into the manifest; per-Stack instance creation moves to the three `create_*` factories; connection management and auth lifecycle move onto the Layer vtable.
4. **`read_raw` disappears.** Its only role was to bypass the cache; under layering, callers that want no cache simply don't include one. The "see unfollowed `Redirect`" use case is served by composing a Stack without `RedirectFollowerWrapper` (canonical example: the REST gateway).
5. **`Library` becomes a thin facade — and the facade is transitional.** Its current role splits across explicit Layer instances. The default Stack is constructible piecewise; specialized hosts (REST gateway, broker daemon, broker client) compose different Stacks from the same backend-layer binaries. The facade exists so v1 hosts and tests stay green during the migration; it is deleted together with the v1 surface once every host constructs Stacks directly (implementation plan Decision #8; issue #168).
6. **No separate alias registry, no visibility registry.** Aliases are
   credentialless, auth-delegating Connections owned by `AliasWrapper` (each
   targeting its `alias` Layer instance); backend credentials and auth state
   remain owned by the downstream backend Connection selected after alias
   resolution. Visibility is a field on per-root `RootInfo`. Today's
   `add_alias` / `set_address_visibility` API surface collapses into normal
   connection management and root introspection.
7. **C/C++ header rewrite.** Replacement `ovstorage_backend.h`, `ovstorage.h`, `ovstorage.hpp`. The plugin-author C surface disappears.
8. **Python wheel surface rewrite.** `ovstorage.Library` becomes one composer among many; the canonical class is `LayerBase` with `layer_type` metadata; every in-tree backend, wrapper, and router is a Layer class.
9. **No precompiled C static library.** We ship source. Customers build their own.
10. **Conformance harness rebase.** Today's `ScenarioRegistry` tests SPI methods; under the new model it tests `OvStorage_LayerVTable` slots. Scenario names stay stable.
11. **Persona doc rewrite.** Every doc that talks about "API vs SPI" collapses. The `library-rust`, `library-python`, `library-cpp`, `library-web`, `plugin-storage`, `plugin-development`, `broker-operator`, and `agent` personas all touch this.
12. **Broker re-types in place.** The broker server becomes a host adapter over a configured Stack; `BrokerClientBackend` is a backend layer applications mount when talking to a remote broker.
13. **Config becomes a Stack.** The old separate backend/layer namespaces are replaced by named Layer instances, a root Layer, wrapper `inner` edges, and router `children` edges. Backend layers have 0 children, wrapper layers have one `inner`, and router layers have `children`; `layer_type` comes from factory metadata rather than being repeated in TOML.
14. **Authority-form object addressing disappears.** A 0.x-valid object address spelled with the name in the URL authority and an empty path (`mock://team`, `assets://Object.TXT`) is canonicalized at the `Stack` entry (empty-authority-path slash, host lowercasing for non-special schemes) before any layer sees it, so such spellings now address the slash-form directory / lowercased host. The backend-owned exact-object-first `stat` probe is consequently unreachable for authority-form spellings (see "URL ownership"). Any facade or host must canonicalize before its own address logic (`is_directory`, alias checks) so it agrees with the Stack.

## Migration ordering

This is an ABI-v2 host rewrite, not a mechanical rename. Ordered milestones. Each milestone leaves the tree buildable.

Before implementation work starts, land the workspace foundation (merged as #112) so
the cross-cutting rewrite starts from one root Cargo workspace and one lockfile.
Large Layer implementation work before that foundation risks avoidable path and
lockfile churn.

### Milestone: design freeze

- Land this document.
- Resolve open questions below.
- Update `AGENTS.md` to route layer-design tasks through the redesign.

### Milestone: Rust trait core + in-tree Layer factories

- Define the operational `Layer` trait and the backend / wrapper / router factory traits in an `ovstorage-layer` crate.
- Implement immutable Rust Stack construction (`.layer(...).build()` from a declarative spec) and the in-tree Layer factories:
  - Backend layers: `FileBackend`.
  - Router layers: `Router`.
  - Wrapper layers: `CopyRenameFallbackWrapper`, `AliasWrapper`, `ByteCacheWrapper`, `MetadataCacheWrapper`, `RetryWrapper`, `RedirectFollowerWrapper`.
- Wire `Library::builder()` to produce the default root Stack and support full Stack rebuild from a specification. `make test` runs.

### Milestone: compatibility adapter for today's plugins

- Wrap the current `Factory` / `Backend` SPI as Layer instances so existing
  first-party plugins can run under a Stack before every plugin is ported.
- Reuse the current conformance harness through the adapter path to prove the
  new Layer composition can preserve direct-mode behavior.

### Milestone: unified C vtable + cdylib loader

- Define `OvStorage_LayerVTable`, `OvStorage_LayerHandle`, the manifest / init symbol pair, and the three-way factory split (`create_backend` / `create_wrapper` / `create_router`).
- Define `OVSTORAGE_PASSTHROUGH_VTABLE` (wrapper default) and `OVSTORAGE_UNSUPPORTED_VTABLE` (backend default).
- Migrate the cdylib loader to the new symbols.
- Migrate `http`, `services-client`, `broker-client`, and `conformance` cdylibs to the new ABI. Conformance harness rebase at the end.

### Milestone: C/C++ source distribution

- Land `ovstorage-c-source/` with headers, pure-C dispatch, pure-C `file_backend`, thread-pool runtime.
- Land `Makefile.example` and `CMakeLists.txt.example`.
- Document in the `library-cpp` persona.

### Milestone: Python rewrite

- Reshape the `ovstorage` Python module around `LayerBase`, `layer_type`, and per-layer classes.
- Native Python dispatch within a Python wrapper path.
- PyO3 vtable bridge for Rust-backed Python layers.
- Update agent skills to use the layer-composition pattern.

### Milestone: broker re-type

- Broker server host adapter and `BrokerClientBackend`.
- Update `broker-operator` and `plugin-broker` personas.

### Milestone: doc and skill rewrite

- Rewrite the eight affected persona docs.
- Rewrite skills that mention "plugin" or "SPI" to use "layer" vocabulary.
- Update `AGENTS.md`'s persona table.

## Open questions

These were open at proposal and are **resolved at the design freeze** (the
PR that merges this RFC); each resolution is recorded inline below.

1. **Pure-C thread pool tuning.** *Resolved:* a fixed-size pool sized to `available_parallelism()` clamped to `[2, 32]`, overridable by the `OVSTORAGE_C_RUNTIME_THREADS` environment variable and, when present, a host-callback field that takes precedence over the env var. No work-stealing in v1 — a single shared FIFO queue with condvar wakeups is sufficient for the C default-fallback workload.
2. **`update_connection_attributes` shape.** *Resolved:* the slot takes an `OvStorage_AttributePatch` of independently-optional fields (absent = leave unchanged): `display_name`, `access_mode`, `visible`, and `user_metadata` (a key-value patch where a null value deletes the key). Credentials are never in this patch — they flow only through `update_connection_credentials`. Changing `access_mode` invalidates cached `root_info_for` for the affected roots so capability gates re-derive.
3. **Cross-language stream ownership.** *Resolved:* **one** `OvStorage_Stream` type for every item/event stream — `watch_directory`, the `list_address_roots` / `list_connections` update channels, and `authenticate_connection`'s `AuthEvent` stream — modeled as the streaming twin of `OvStorage_OnComplete`:

   ```c
   typedef struct OvStorage_Stream {
       void* state;
       const OvStorage_StreamVTable* vtable;   /* the producing binary owns it */
   } OvStorage_Stream;

   /* Streaming twin of OvStorage_OnComplete: `item` is the next element
      (concrete type per the slot that produced the stream), NULL at
      end-of-stream; `error` non-NULL on failure. */
   typedef void (*OvStorage_OnStreamItem)(int32_t status, void* item,
                                          OvStorage_Error* error, void* user_data);

   typedef struct OvStorage_StreamVTable {
       size_t struct_size;
       void (*next)(void* state, OvStorage_CancelToken*,
                    OvStorage_OnStreamItem on_item, void* user_data);
       void (*drop)(void* state);   /* close + release; idempotent */
   } OvStorage_StreamVTable;
   ```

   There are **no per-kind handle aliases** — exactly as `OvStorage_OnComplete` is one type for every async object op, with the concrete result conveyed by which slot was called plus a comment (`/* type per method */`). The stream slots use `OvStorage_Stream` the same way, documenting the item type per slot (`/* items: RootInfo changes */`, etc.); typing is recovered in each language's generic `Stream<T>` wrapper, so the `void*` cast lives in exactly one site per kind. The producer owns the stream until `drop`; the host drains to end-of-stream or `drop`s early; cancellation rides the shared `OvStorage_CancelToken`. The raw byte-read stream (`OvStorage_AsyncByteStream`, from `read`) is a separate byte-oriented primitive, out of scope here. (Chosen over per-kind vtables — which multiply layouts and bindings — and over a shared tagged-union `OvStorage_AsyncIter` — which is less type-safe and forces every consumer to match a union.)
4. **Connection identity across the Stack.** *Resolved:* a connection is identified by `(target, id)` — `id` is unique within its owning Layer and the `target` Layer name disambiguates across the Stack. Layer names are single-instance by construction (the builder rejects more than one reference to any configured Layer name), so `target` names exactly one owner and `list_connections()` returns globally distinct `(target, id)` keys without a `(kind, id)` pair. Every connection op carries `target`.
5. **SecretStore default for headless services.** *Resolved:* an **ephemeral per-process key** — a random key minted at startup, held only in memory, never persisted. Persisted secrets therefore do not survive a restart; headless principals re-authenticate each run (device-code / non-interactive flow), the intended posture for stateless workers. The OS keyring stays the default where present (secrets persist across sessions); the broker-mediated store stays the option for deployments needing persistence without a local keyring. This deliberately keeps a host-master-key management surface out of v1.
6. **OAuth helper packaging.** *Resolved:* one canonical Rust implementation in an `ovstorage-oauth` crate (PKCE, device-code, refresh rotation, OIDC `.well-known` discovery, loopback listener bind/capture). Python and C consume it through thin bindings — a PyO3 wrapper and a small `extern "C"` shim exported from the same crate — not parallel reimplementations; the protocol logic has exactly one home. The helper is not part of the plugin ABI; a backend may still bring its own flow when an SDK requires it.
7. **Background refresh task ownership.** *Resolved:* the refresh task runs on the owning backend layer's Rust tokio runtime (one task per auth-bearing connection). Other-language hosts do not own a refresh loop; they observe credential and `ConnectionAuthState` transitions via the `list_connections` connection-change stream. Cross-process refresh coalescing stays a `SecretStore.begin_refresh` / `finish_refresh` responsibility.
8. **Conformance harness registry field mapping.** *Resolved:* `ScenarioRegistry`'s `spi_methods` becomes `vtable_slots`; recorded call names are unchanged (bare method names coincide between the SPI and the vtable slots), so snapshots stay byte-identical. `allowed_hosts` (library / broker / both), `expected_calls` (with negative assertions), `failure_contract`, and `report_tags` keep their semantics; `ExpectedCall.method`, `FailureContract::Errors.method`, and `ObservedCall::method_name()` remain the slot-name surface.

### Resolved during adversarial review

These were flagged in review and resolved inline (the doc above now reflects the resolution):

- Authz is an internal implementation detail of the broker server, not a storage Layer.
- `read_raw` is replaced by the "compose a Stack without `RedirectFollowerWrapper`" idiom (REST gateway is the canonical example).
- Plugins receive resolved (post-alias, post-rewrite) URLs. Differential-addressing language (`relative_key`, `version_selector`) was already removed from the code; the current `docs/public/plugin-development/README.md` carries outdated language that needs a cleanup pass.
- Multipart layers buffer one part at a time as a documented streaming-invariant exception.
- `materialize` is a top-level vtable method. `FileBackend` and `ByteCacheWrapper` implement it; everything else passes through.
- `AuthEvent::Succeeded` carries `Option<SecretBundle>` for install-on-success token handoff.
- `SecretStore` owns cross-process refresh coalescing. A replacement store's cross-process safety is the replacer's responsibility.
- Backwards compatibility is not preserved (project is pre-1.0).
- Each backend layer does longest-prefix routing internally across its own connections; a `Router` dispatches across its child roots by longest-prefix URL match (and routes connection ops by `target` Layer name).
- Each layer instance reads its own TOML config table.
- `write`, `write_stream`, `write_redirect`, and `continue_write` are separate vtable slots.
- `RootInfo` is per-root and includes `capabilities`, `visible`, `source`, and `alias_state` fields.
- Vtable slots are always populated (`PASSTHROUGH` / `UNSUPPORTED` thunks); no nullable slots.
- One cdylib may export multiple kinds when they share dependencies and lifecycle. Loading is registry-resolved in the common path: `ovstorage_load_plugin(path)` opens the cdylib and creates plugin-scoped state; `ovstorage_registry_add_plugin(registry, plugin)` registers its manifest kinds; then the builder calls the create function matching each kind's `layer_type` (`create_backend`, `create_wrapper`, or `create_router`) and adds the fresh Layer instance to the Stack. Explicit `*_from_plugin` escape hatches exist for tests and ambiguous providers.
- Kind descriptors live in the **manifest** (static, readable before init) so introspection — what kinds does this plugin provide? what's their config schema? — works without instantiating anything. `ovstorage_inspect_plugin(path)` reads only the manifest. The CLI uses this for lazy plugin loading (parse URL, find the plugin that provides the scheme, load only it).
- Information about a Layer lives at three distinct scopes that the design carefully keeps separate: **kind** (in the manifest, static, describes "all instances of this kind"), **connection** (in the Layer's internal state, dynamic, describes "this specific configured instance"), **root** (returned by `root_info_for(url)`, dynamic per URL, describes "this specific prefix"). Earlier drafts conflated all three into one "descriptor" — the manifest now only carries kind info; connection and root info are runtime-queried.
- Authz plugins have their own separate ABI (`ovstorage_authz_plugin_manifest_v1` / `ovstorage_authz_plugin_init_v1` with a dedicated authz vtable), distinct from the storage plugin ABI. The broker server loads authz cdylibs internally and consults them before forwarding. Authz is **not** a kind of storage Layer; it's a parallel plugin surface that the broker daemon happens to consume.
- `RootInfo` (with a nested `Capabilities` struct) is the single per-root introspection answer. It subsumes `capabilities_for`, which mixed operation bits with presentation and provenance.
- Layer instances are created per Stack through the relevant `create_*` factory; plugin init creates only plugin-scoped state. A loaded cdylib can therefore back multiple independent Stacks without sharing layer instance state by accident.
- Built Stacks are immutable. CLIs and config tools dynamically edit Stack specifications, then build a Stack or save the specification. Long-lived hosts apply changes by rebuilding a complete Stack and atomically swapping the top-level handle.
- `list_address_roots()` and `list_connections()` are always-async, cancellable vtable slots; each fires its `OnComplete` with a result pairing a complete snapshot with an optional update stream. `list_address_roots()` uses `RootInfo` for both snapshots and updates, so there is no separate `AddressRoot` metadata struct. A caller that only needs a one-shot list ignores the paired stream (dropping it ends the subscription).
- Capabilities are effective caller-visible capabilities at the point where `root_info_for` returns. Layers may preserve, mask, or synthesize capabilities according to their own implementation.
- Single-object `copy` / `rename` emulation belongs in `CopyRenameFallbackWrapper` below aliases, so it transfers already-rewritten addresses. It delegates inward whenever the source root reports the operation available, falls back to read/write whenever the layer below declines with `Unsupported`, and implements the emulated rename as non-atomic copy-then-delete. Differing roots are one reason a layer declines, not the trigger itself.
- Async vtable methods take an explicit `OvStorage_CancelToken*`.
- The workspace keeps `panic = "unwind"`; every `extern "C"` boundary wraps a `catch_unwind` wall that converts an escaped panic to `ErrorCode::Internal`, with rustc's force-abort on an uncaught escape as the backstop.
- Plugin-scoped state has an explicit `plugin_vtable.drop`.

### Resolved during post-implementation review (2026-07)

Recorded after the PR-Q–PR-U implementation review (PR #149 and the design
discussion around it); the doc above reflects each resolution:

- **Capabilities are hints, not enforcement.** Backend layers self-gate
  ("behave sensibly" — typed error, no side effects, when called past a false
  bit); masking bits in a wrapper changes presentation only, enforcement
  intercepts ops; the v1 compat adapter host-gates on behalf of v1 plugins,
  which were written against the inverse contract. Conformance: issue #170.
- **Suppressed roots are never returned.** `RootInfo.visible` stays a
  presentation-only bool (`false` = hidden but directly usable). Suppression
  is an `AliasWrapper` configuration directive, not a `RootInfo` state: the
  wrapper omits the suppressed namespace (v1 `rewrite_to` mounts suppress
  their physical target by construction) from projected introspection results
  entirely, and refuses direct operations into it with `NoRoute` —
  **projection and enforcement must agree**, and anything more specific than
  `NoRoute` would leak the suppressed configuration.
- **Write-protocol selection is owned by `RedirectFollowerWrapper`'s write
  path**, consuming the `supports_write_redirect` / `redirect_size_threshold`
  hints with `Unsupported` fall-through; explicit `write_redirect` calls are
  never threshold-gated. `write_redirect` / `continue_write` are first-class
  cooperative-protocol slots on the uniform surface (API = SPI holds); the
  read/write redirect asymmetry is forced by body ownership across the ABI.
- **Per-slot contract:** mutations flowing through the redirect protocol
  commit at `continue_write → Done` (mutation-observing wrappers hook `Done`);
  `RetryWrapper` never retries `continue_write`; protocol slots default to
  pass-through. Conformance: issue #170.
- **Request extensions carry facts, never instructions** — no behavior
  selectors addressed to a layer kind; behavior is selected by composition.
  `RAW_READ_EXTENSION` is replaced by sub-stack composition (issue #169).
- **Layers may query what `inner` can do (`root_info_for`), never what it
  is** (no kind-sniffing or downcasting). Driving a bare Layer without a
  `Stack` transfers the canonical-spelling obligation to the caller.
- **Authority-form object addressing is a declared break** (#14 above), a
  consequence of Stack-entry canonicalization.
- **Connection lifecycle is backend-owned via a generic embeddable library**
  (`ConnectionSet` over a validate/refresh/interactive/classify driver, issue
  #166); there is no connection-manager Layer. Data-path credential recovery
  for headless hosts lives in that machinery (issue #167).
- **The `Library` facade is transitional** and is deleted with the v1 surface
  (break #5; implementation plan Decision #8; issue #168).
- **Alias resolution is bounded multi-hop** (supersedes the #148
  review-response's single-pass framing; the fold of `rewrite_to` into one
  rule set stands). Per hop, a longer-matching real root wins over any rule
  (#162), else the longest-prefix rule applies; fixed hop cap (8) + cycle
  detection; `ChainTooLong` now means cap-exceeded/cycle and is raised eagerly
  at `create_alias`; reverse projection iterates symmetrically. Restores v1
  alias→`rewrite_to` as the N=2 case and lets user aliases compose against
  caller-visible names instead of hard-coding suppressed physical namespaces
  (issue #172).

### Resolved at the PR-N host re-type design (2026-07)

Recorded when the broker/REST host re-type was designed (implementation plan
§PR-N); refinements to the §"Specialized host Stacks" rows:

- **"No `RedirectFollower`" in the REST and broker rows describes the read
  path.** Both host stacks include `RedirectFollowerWrapper` for
  **body-bearing writes** (`write` / `write_stream`): once the caller's body
  is at the host, a backend's multi-step `WriteStep::Redirects` continuation
  (e.g. S3 multipart) can only be executed there — it cannot be expressed as
  one HTTP 307 or one forwarded redirect. Redirect-returning write surfaces
  are unaffected: the bodyless `write_redirect` / `continue_write` protocol
  slots pass through the follower (per the protocol-slot pass-through
  resolution above), so clients that drive the redirect-write protocol still
  receive backend batches unfollowed, and the broker's route-policy write
  redirects are manufactured host-side before dispatch. The read/write
  asymmetry is composition-time follower configuration, not a request
  extension — the facts-not-instructions law holds.
- **The broker daemon keeps an opt-in byte cache, in-stack.** The broker
  row's "No ByteCache (per-tenant data must not co-cache)" hazard does not
  apply: the broker is single-tenant by design (separate trust scopes are
  separate deployments). v1's size-gated behavior carries forward — reads on
  cache-admitted routes are followed and cached only within the route's size
  cap; larger reads forward the redirect — expressed as per-policy-class
  Router children (the §"Anatomy of a Stack" per-backend composition
  pattern).
- **The landed wrapper order supersedes the host-row diagrams' ordering.**
  Every composed host chain is alias-outermost with `byte_cache` above
  `metadata_cache` (the validator-keyed byte cache's stat-first lookup is
  served by the metadata cache below it) and `redirect_follower` above
  `retry`. The §Specialized-host-Stacks rows' layer *sets* remain
  authoritative; their left-to-right ordering predates this.

### Resolved at the PR-W cross-language handoff design (2026-07)

Recorded when PR-W (issue #218) designed cross-language live Layer/Stack
handoff; "The Layer vtable" §"Cross-language live handoff" above reflects
the resolution. Three decisions from the PR-W design, plus every deviation
flagged against the original PR-W ticket text during implementation
planning:

- **ABI-mismatch behavior reuses the plugin-load error path.**
  `import_handle` raises the same `ErrorCode::IncompatibleType` a bad plugin
  load raises today, with no new error variant — but the check is
  **exact-match, not banded**: the ticket text cited an `abi_version_supported`
  banded-check helper that does not exist in the plugin crate, and the v2
  Layer ABI is deliberately single-version (unlike the v1 init-result band,
  which is where that kind of helper actually lives). A future host that can
  validate more than one Layer ABI is when banding arrives, not this design.
  Failure disposal is normative (see "Cross-language live handoff" above): a
  version-mismatch handle is dropped through its own `drop` slot; a
  null/undersized-header handle is returned undisposed because it carries no
  trustworthy `drop` slot.
- **The C surface exposes both the opaque application-handle wrapper and the
  raw vtable**, as designed: both `ovstorage_export_handle` /
  `ovstorage_import_handle` and documented direct use of the raw
  `OvStoragePlugin_LayerHandle` vtable are supported, the latter with its
  own callback-shape / drop-obligation / thread-contract guide.
- **Live-handle handoff is a permanent, first-class capability**, not a
  provisional bridge superseded by spec-transfer — this section and the
  "Dynamic Stack construction" clarification above record that commitment.

Deviations from the PR-W ticket text, resolved during implementation
planning:

- **D0 — sequencing vs. PR-V.** The ticket assumed PR-W lands *after* PR-V
  (facade retirement, issue #168) so it targets a Stack-only surface with no
  v1 `Library` to mirror. #168 was still open when PR-W's implementation
  started; PR-W lands first. The only facade-coupled surface this leaves
  behind is the Python export path's owner-retaining wrapper around
  `Arc<FacadeOwner>` (D9 below), marked `// PR-V:` as interim, facade-era
  machinery for PR-V to revisit or simplify once it lands.
- **D2 — versioning is exact-match, not banded.** See "ABI-mismatch
  behavior" above.
- **D3 — the Rust surface is free functions, not a `Layer` trait default.**
  `ovstorage-layer` (where `Layer` lives) does not depend on
  `ovstorage-plugin` (where `LAYER_VTABLE` lives), so a trait default method
  could not name the vtable it needs; the vtable slot-order freeze test also
  rejects any new trait method that is not explicitly exempted. The surface
  is `ovstorage::export_handle(Arc<dyn Layer>)` /
  `unsafe fn ovstorage::import_handle(...)` — free functions, re-exported
  from `ovstorage-plugin` — plus the optional `LayerExportExt` sugar trait
  for `.export_handle()` method syntax without touching `Layer`.
- **D4 — the C wire type is `OvStoragePlugin_LayerHandle`, not
  `OvStorage_LayerHandle`.** `OvStorage_LayerHandle` is already the
  application C API's opaque built-Stack handle (`ovstorage.h`); the
  vtable-bearing interchange struct this document describes is named
  `OvStoragePlugin_LayerHandle` in the plugin crate's generated header to
  avoid a cbindgen identifier collision (the capi's cbindgen run sees two
  different types under the `LayerHandle` name and does not parse the
  plugin crate's definition). The application C API's
  `ovstorage_export_handle` / `ovstorage_import_handle` convert between the
  two; both the wrapper and direct raw-vtable use are documented (decision
  2 above).
- **D5 — handles are move-only; re-export double-bridges, documented.** The
  vtable has no clone slot, so each `export_handle` call mints exactly one
  owned reference; a second consumer needs a second `export_handle` call.
  Re-exporting an already-imported foreign layer adds one extra FFI hop at
  that boundary — correct, just slower. Failure disposal on import follows
  the single normative statement above; no other prose overrides it.
- **D9 — Python naming: `export_handle` / `import_handle` live on
  `LayerBase`, not `Stack`.** The `Stack` pyclass is the pre-build composer;
  `Stack.build()` returns a `LayerBase`. Both verbs are `LayerBase` methods,
  covering both built stacks and direct projections. Export leaks a
  forwarding layer that retains `Arc<FacadeOwner>` — not just the inner
  `Arc<Stack>` — so the credential substrate the facade owns survives the
  Python object's export; this is interim, facade-era machinery marked
  `// PR-V:` per D0, to be revisited once PR-V retires the facade.

Universal-path changes disclosed here so a reader trusting this record knows the
shared `dlopen` plugin-load path changed alongside the new handoff primitive:

- **Request `extensions` now cross to every v2 plugin.** The pre-PR-W v2 op
  builders hard-coded `extensions: null` on every crossing; the extracted
  `consume_v2` builders marshal the request's real extensions
  (`extensions_to_ffi`), so every v2 op on the dlopen path now carries the
  non-empty extensions the plugin never previously saw (freed once after the
  synchronous prologue).
- **The plugin-load path now runs the per-handle vtable `abi_version` exact
  check.** Foreign-vtable construction validates `vtable.abi_version` against the
  supported Layer ABI, where previously only `struct_size` was checked at this
  layer — unobservable for a normal plugin load (init already rejects an ABI
  mismatch), but the load-bearing gate for a bare imported handle.
- **Undersized-header disposal flipped to an error return.** A handle whose
  `vtable.struct_size` is below `LayerVTableV1` is now returned as an error
  *without invoking any of its (untrusted) foreign pointers*; it carries no
  trustworthy `drop` slot, so it is left undisposed.

## Appendix: naming

Lock-in choices:

- **The Rust traits**: `Layer` is the operational trait. `BackendFactory`, `WrapperFactory`, and `RouterFactory` are construction shapes. There is no separate operational `Storage` trait; `Storage` was the 0.x app-facing name and is retired (see "What this breaks").
- **The C vtable**: `OvStorage_LayerVTable`.
- **The C handle**: `OvStorage_LayerHandle`.
- **A plugin's cdylib**: just "a plugin" (informal). Layer is the runtime unit; the Stack is the built composition; plugin is the packaging concept.
- **Init symbols**: `ovstorage_plugin_manifest_v1`, `ovstorage_plugin_init_v1`. The init result carries the plugin's implemented `abi_version`; the host decides whether it can load that ABI. The manifest names the *cdylib* (the plugin); the init function returns plugin-scoped state and the three factory entry points (`create_backend` / `create_wrapper` / `create_router`).
- **Default vtables**: `OVSTORAGE_PASSTHROUGH_VTABLE`, `OVSTORAGE_UNSUPPORTED_VTABLE`.
- **In-tree type suffixes**: `Backend` for backend layers (`FileBackend`, `S3Backend`), `Wrapper` for wrapper layers (`AliasWrapper`, `ByteCacheWrapper`), and `Router` for routers (`Router`). The suffix signals the layer type and disambiguates from unrelated `File` / `Cache` types.

## Addendum: authz is a storage Layer (RFC-0066 PR-N6, 2026-07)

PR-N6 re-architected authentication and authorization into an **auth-as-a-Layer**
model. This addendum records the shipped design; it **supersedes** the earlier
inline framing that authorization is broker-internal and "not a storage Layer."
The narrative above is left intact for provenance — read it through this
addendum.

### Superseded statements

The following inline statements are superseded and no longer describe the code:

- **§"What lives where" table (~line 1571)** — "Brokered authorization | broker
  server internal logic (loads authz cdylibs …); not a storage Layer." Authz is
  now a storage Layer.
- **§"Resolved during adversarial review" (~line 3585)** — "Authz is an internal
  implementation detail of the broker server, not a storage Layer."
- **§"Resolved during adversarial review" (~line 3601)** — "Authz plugins have
  their own separate ABI … The broker server loads authz cdylibs internally and
  consults them before forwarding. Authz is **not** a kind of storage Layer …"
  The separate authz plugin ABI (`ovstorage_authz_plugin_manifest_v1` /
  `ovstorage_authz_plugin_init_v1`) is gone; authz rides the ordinary Layer
  plugin ABI. ABI-v14 wrapper kinds marked `auth_capable` may serve as
  third-party `.so` auth Layers.
- **`PermissionCheckWrapper` references (~lines 236, 724, 1165, 1468)** — the
  hypothetical host-supplied `PermissionCheckWrapper` / `PermissionCheckLayer`
  does not exist. Its role is filled by the shipped built-in auth Layer
  (`BuiltinAuthLayer`, kind `builtin-auth`), which does authn **and** authz.

### The shipped model

- **One combined auth Layer per listener does authn + authz.** The built-in
  `BuiltinAuthLayer` (`kind = "builtin-auth"`, crate `ovstorage-authz-layer`) is
  composed **over** a shared, auth-free inner `Stack` (backends, caches, router,
  alias, cross-root, attribution) via the new core primitive
  `StackBuilder::attach(name, handle)`, which mounts a pre-built `LayerHandle` as
  a wrapper's single `inner` child.
- **Opaque credential flow.** The host gathers transport-level credential
  material — a bearer token (undecoded) plus the transport tag (`Tcp` /
  `Uds` / `NamedPipe`) with its peer credentials — and stamps it DOWN as
  `ext::AUTH_CREDENTIAL` on a **fresh** `Extensions` bag (the host never merges
  client-supplied extensions, so a network client cannot forge identity). The
  auth Layer decodes it (wire codec: `ovstorage-authz-context`), resolves a
  principal (OIDC bearer JWT for `Tcp`; OS peer-credential / dev-current-user for
  `Uds`/`NamedPipe`), evaluates the fresh policy, and on **allow** stamps
  `ext::PRINCIPAL_ID` DOWN to the inner (never back up to the host); on **deny**
  returns `PermissionDenied` / `AuthRequired`. Extension keys moved into an `ext`
  module and dropped the `_EXTENSION` suffix.
- **Attribution** is an in-stack Layer (top of the shared inner) reading the
  down-stamped `ext::PRINCIPAL_ID`.
- **Fail-closed per-listener config.** Each listener declares `auth = { kind,
  config }` (broker: under `[listener]`; REST: under `[server]`). Absent `auth`
  ⇒ the host refuses to start; explicit `auth = "anonymous"` ⇒ an allow-all
  built-in. A plugin kind is accepted only when its loaded descriptor is a
  wrapper with `auth_capable = true`; unknown, non-wrapper, and non-auth-capable
  kinds fail closed. Auth decisions emit `ovstorage_auth_decisions_total`
  (`outcome = allow|deny|error`).
- **Removed.** The host-side authn middleware, the `[authz]`-plugin-per-process
  model, the `SYSTEM_PRINCIPAL` marker and its build-time stamp, and the entire
  **policy-epoch** system (`PolicyEpochState` / `POLICY_EPOCH_EXTENSION`) are
  removed. Build-time / SIGHUP connection apply runs on the shared inner
  directly, below auth, so it never traverses an auth gate — which is why the
  SYSTEM bypass is obsolete. `PolicyEpochStale` survives only as a wire error
  code. Management slots are config-time and ungated.

### Y-graph reality (N=1 today)

`attach` + the shared inner make it **possible** for multiple per-listener auth
Layers to share one inner Stack — the design's "separate instances per listener"
Y. That capability is **latent, not instantiated**: both hosts are
single-listener today. The broker runs one listener per process (multi-transport
= multiple broker processes), and REST is a single TCP server. So **N=1**: each
host composes exactly **one** shared auth Layer over one inner. The auth Layer's
authn is transport-branched internally (peer credentials for `Uds`/`NamedPipe`;
signed JWT, trusted-proxy identity, or mTLS for `Tcp`), but there are no
per-listener policy *instances* realized. The mechanism
supports N>1; it is forward-looking infrastructure.

### Delivery and deferral

- **#261 (delivered).** `.so` / FFI plugin auth Layers. What landed: loaded
  wrapper kinds whose `LayerKindDescriptor` sets `auth_capable = true` (the
  ABI-v14 field) may serve as listener auth Layers; the DOWN-direction request
  context now reaches the asynchronous per-principal introspection slots
  (`extensions_to_ffi_ptr` no longer drops the stamped context); and the C and
  Python SDKs expose the well-known auth keys and typed `AUTH_CREDENTIAL`
  decode accessors (additive SDK surface). There is no up-channel:
  `ext::PRINCIPAL_ID` travels DOWN only, exactly as §"Opaque credential flow"
  describes — the "cross-FFI `PRINCIPAL_ID` up-marshaling" item originally
  tracked under #261 was withdrawn as a non-requirement, not deferred.
- **OAuth tier-2/3 upstream credentials (delivered with #217).** The broker's
  streaming `Auth` and unary `RegisterCredential` RPCs are implemented
  end-to-end: the daemon drives per-principal upstream OAuth, persists
  successful credentials daemon-side, and the mandatory `upstream_credential`
  boundary stamps per-request credential references. Independent of plugin
  listener auth; neither item blocks the other.

## Addendum: the C/C++ surface is the source distribution (2026-07)

The C and C++ surface consolidated onto a single implementation: the
hand-written C sources in `ovstorage-c-source/`, with one C++20 coroutine
wrapper over them. The Rust `ovstorage-capi` crate that had shipped a second
implementation of the same C ABI — with its own copies of `ovstorage.h` and
`ovstorage.hpp`, and its own cdylib — is deleted. This addendum records the
shipped shape; the narrative above is left intact for provenance.

### Superseded statements

- **§"Repo layout" (~line 3601)** — the tree diagram lists
  `include/ovstorage_backend.h  # C ABI vtable, types, error model`.
  `ovstorage_backend.h` is not adopted. It was a 20-line file whose entire
  body was `#include "ovstorage_plugin.h"`, so it gave the plugin-author
  surface a second name without adding a declaration, and obliged every
  include directory to carry both for the relative include to resolve. The
  shipped headers are `ovstorage.h` (application C API), `ovstorage_plugin.h`
  (plugin ABI), `ovstorage_defaults.h` (default vtables for C plugin
  authors), and `ovstorage.hpp`.
- **§"Migration inventory" item 7 (~line 3649)** — "Replacement
  `ovstorage_backend.h`, `ovstorage.h`, `ovstorage.hpp`." Same correction:
  no `ovstorage_backend.h`. The plugin-author C surface did not disappear
  either; it is `ovstorage_plugin.h`, named for the crate that generates it.
- **§"Repo layout" (~line 3603)** — `ovstorage.hpp  # C++17 thin wrapper
  (header-only)`. The shipped wrapper is C++20 and async-only: every
  long-running method returns `ovstorage::task<T>`, a coroutine type, and
  `ovstorage::sync_wait` drives one from a non-coroutine caller. It requires
  GCC 13+, Clang 17+ or MSVC 19.40+, which both shipped example build files
  enforce with a capability probe that compiles the header itself. The C
  sources still need only C99, so a consumer below the C++ floor can build
  and use the C API.
- **§D4 (~line 3922)** — the `OvStoragePlugin_LayerHandle` name is explained
  as avoiding "a cbindgen identifier collision (the capi's cbindgen run sees
  two different types under the `LayerHandle` name…)". There is no capi
  cbindgen run. The name stands on its own terms: `OvStorage_LayerHandle` is
  the application API's opaque built-Stack handle and
  `OvStoragePlugin_LayerHandle` is the vtable-bearing interchange struct, and
  the two are genuinely different types that must not share a name.

### Reinforced, not superseded

**§Design principles item 5 (~line 91)** — "C/C++ ships as source. No
precompiled `libovstorage_static.a` from us." That is now literally true. The
release archive had drifted from it: it shipped an `ovstorage` cdylib in
`dist/lib/` and a flat `dist/include/`, which together describe exactly the
consumption model the principle rules out — headers to include against a
prebuilt library to link. Both are gone. `dist/c-source/` is the whole C/C++
surface, self-contained: sources, headers, and example build files for `make`
and CMake.

### One implementation, and what that costs

The design principle above was always satisfied by the C sources. What
existed alongside them was a second implementation of the same ABI in Rust,
kept in sync by hand across two copies of every header. Deleting it removes
that duplication.

The trade is that `ovstorage.h` is now hand-maintained. It had been generated
by cbindgen from the capi crate and byte-copied into the source tree, so a
Rust change that altered the C surface was mechanically reflected in the
header and the verify gate caught drift. That check is gone, deliberately:
with the C API distributed as source there is no second definition to derive
the header from, and no binary boundary between the header and the
implementation it declares — consumers compile them together. What holds them
in agreement instead is the link-completeness gate, which parses `ovstorage.h`
for declarations and fails if the C source set does not define every one.

`ovstorage_plugin.h` is the exception and stays cbindgen-generated from the
`ovstorage-plugin` crate, with its byte-copy into the source tree gated. It
has to be: plugins are prebuilt cdylibs the host `dlopen`s at runtime, so host
and plugin compile separately and must agree on struct layout. That is a real
binary contract, and it is the one place a generated header earns its cost.
