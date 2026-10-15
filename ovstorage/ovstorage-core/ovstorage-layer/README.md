# ovstorage-layer

`ovstorage-layer` is the lowest-level Rust crate for the layered storage
architecture. It defines the shared `Layer` trait, stack-construction contracts,
error model, and public type vocabulary that higher crates project into plugin
ABI, host dispatch, bindings, and service integrations.

This crate intentionally has no dependency on plugin loading, C ABI layout,
runtime dispatch policy, or concrete storage backends. Those pieces build on
top of this Rust contract.

## What Lives Here

- `Layer`: the async operational surface for object operations, root
  introspection, connection management, and interactive authentication.
- `BackendFactory`, `WrapperFactory`, and `RouterFactory`: construction
  contracts used by `StackBuilder`.
- `Stack` and `StackBuilder`: immutable layer composition with graph validation,
  cycle rejection, bottom-up instantiation, and single-owner connection
  application.
- `Request<T>` and `Extensions`: the per-call envelope that preserves opaque
  host/layer metadata while forwarding operation inputs.
- Domain types used across the storage surface: object metadata, read/write/list
  options, redirects, capabilities, connection/config/auth descriptors, root
  metadata, streams, and result pages.
- `Error`, `ErrorCode`, and `ErrorContext`: the shared error vocabulary. Error
  construction redacts signed URLs and bearer tokens before messages or recovery
  hints can escape through public surfaces.

## Module Layout

- `types.rs`: all public data shapes and type aliases.
- `traits.rs`: the `Layer` trait, factory traits, `Stack`, `StackBuilder`, and
  graph/build validation.
- `errors.rs`: error types and redacted error construction.
- `redact.rs`: public URL/message redaction helpers used by layer errors and
  higher-level crates.
- `lib.rs`: crate root and reexports.

## Compatibility Role

`ovstorage-plugin` reexports this crate's public types so existing plugin-facing
imports continue to compile while the architecture migrates toward `Layer` and
`Stack`. New shared Rust storage vocabulary should live here instead of in the
plugin crate; plugin-specific ABI and loading code remains in `ovstorage-plugin`.

## Contract Notes

- `Layer` is object-safe behind `Arc<dyn Layer + Send + Sync>`.
- Most `Layer` methods have unsupported defaults so implementations can expose
  only the operations they actually support while still satisfying the full
  trait.
- `Layer::owned_targets()` is static construction metadata: backends and other
  connection-owning layers include their own names, wrappers forward inner
  targets, and routers union child targets for deterministic connection routing.
- `Request<T>` should be forwarded intact through wrappers and routers unless a
  layer intentionally transforms the envelope.
- `StackBuilder` rejects cycles and rejects any layer referenced more than once;
  a stack topology is a tree of configured layer names.
- Redirect/result continuation helpers validate cardinality before accepting
  host-supplied redirect results.
