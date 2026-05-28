# nucleus-codegen (`nucleus-codegen`)

## Purpose

Build-time IDL→Rust generator for the Nucleus IDL files (`omni1.idl.ts`, `OmniAuth.idl.ts`, `Discovery.idl.ts`). Each downstream crate ([nucleus-client](../nucleus-client/README.md), [nucleus-auth](../nucleus-auth/README.md), [nucleus-discovery](../nucleus-discovery/README.md)) calls this crate from its `build.rs` to emit a `pub mod types` block plus a trait per IDL `interface`, with one impl per `Transport` implementor in [nucleus-transport](../nucleus-transport/README.md).

Without this crate the only way to consume Nucleus's surface from Rust is by hand-rolling JSON-RPC envelopes against `Transport::send`. Codegen is the single source of truth for type and method signatures; the deprecated-method filter and the IDL subset accepted are this crate's documented contract.

## Public surface

- `pub fn generate_from_file(path: impl AsRef<Path>) -> anyhow::Result<String>` — read an IDL file, parse it, generate Rust source, pretty-print with `prettyplease`. Used by every downstream `build.rs`.
- `pub fn generate_from_str(source: &str) -> anyhow::Result<String>` — same, but from an in-memory string. Useful for tests.
- `pub fn preprocess_source(source: &str) -> String` — pre-parse pass that rewrites bare `type Foo` lines to `type Foo =` so the AST parser doesn't need to handle the bare form. Exposed for tooling that wants to apply just the rewrite.
- `pub fn init_logging()` — opt-in `tracing_subscriber` initializer that fires when either `NUCLEUS_CODEGEN_LOG` or `RUST_LOG` is set in the build environment. Build scripts call it before `generate_from_file` to surface generator logs at compile time.
- `pub mod ast` / `pub mod codegen` / `pub mod generator` / `pub mod parser` are re-exported for tooling and tests; downstream crates only need the four free functions above.

## What it generates

For each IDL file `Foo.idl.ts`, the generator emits a `String` containing:

1. A `pub mod types { ... }` block holding every IDL `type` / `interface` body declaration translated to a Rust struct or enum (`#[derive(Serialize, Deserialize, Debug, Clone)]` shape, `serde` rename rules to match the wire form).
2. One Rust trait per IDL `interface`, named identically (`Connection`, `Tokens`, `DiscoverySearch`, …) with one async method per *non-deprecated* IDL method.
3. A `<Transport>: Trait` blanket impl that dispatches each method through `Transport::send(interface, method, params, binary)`. Streaming methods (`subscribe_*`, `read_with_subscription`) return `anyhow::Result<Subscription>` directly; non-streaming methods return `anyhow::Result<RetType>` and call `.recv::<RetType>().await` on the subscription internally.

The output is valid Rust that the downstream crate's `mod generated { include!(...) }` block consumes verbatim.

## IDL subset accepted

The parser handles a deliberate subset of `.idl.ts`:

- `type Foo = ...;` aliases, including primitive aliases, struct shapes (`{ field: T, ... }`), discriminated unions, `Array<T>`, `Map<K, V>`, optional fields (`field?: T`).
- `interface Foo { method(args: T): R; ... }` blocks, with the optional `@deprecated` JSDoc tag on individual methods.
- `enum Foo { Variant1, Variant2 = 5, ... }` with explicit numeric tags. Rust enums emit `#[serde(rename_all = "snake_case")]` matching Nucleus's wire convention.
- Bare `type Foo` (no `=`) lines, which `preprocess_source` rewrites to `type Foo =` before the parser sees them.
- Intersection types (`type Extended = Base & { extra: T }`) are flattened: fields from each base in `extends` are merged into the generated struct, with first-wins shadowing on duplicate field names.
- Unions are emitted as untagged enums with synthesized Rust-valid variant idents (`String(String)`, `U64(u64)`, …) for primitive variants and `Variant(Struct)` for named-struct variants. Pure string-literal unions (`"read" | "write"`) collapse to `pub type X = String;`. Mixed primitive + literal + named-struct unions collapse to `pub type X = serde_json::Value;`.

Unsupported TypeScript constructs (non-identifier method/property keys, non-binding-identifier param patterns, unrecognized type forms) emit `tracing::warn!` and are skipped or widened to `serde_json::Value` rather than failing the build.

## Required-field deserialization

Required fields (those declared without `?` in the IDL) are emitted without `#[serde(default)]`. Missing required fields therefore fail `serde_json::from_str`/`from_value` with a `missing field` error rather than silently populating Rust defaults. This closes a fail-open hazard for protocol fields like `Auth.status`/`AuthStatus` whose first variant (`OK`) would otherwise deserialize from `{}`.

`#[derive(Default)]` is retained on every generated struct because callers in `ovstorage-plugin-nucleus/src/handshake.rs` construct values via `..Default::default()`. The `#[default]` attribute on the first enum variant is similarly retained — it is consumed only by explicit `Default::default()` calls, not by serde during deserialization.

Optional fields (`field?: T`) keep `#[serde(default, skip_serializing_if = "Option::is_none")]`, preserving the missing-field-as-`None` behavior that downstream tests rely on.

## Deprecated-method filter

`generator::active_methods(iface)` returns `iface.methods.iter().filter(|m| !m.deprecated)`. Methods marked `@deprecated` in the IDL are skipped when building the trait. The matching types they exchange are still emitted (`mod types` is not filtered), so a downstream crate can still call the deprecated method by talking to `Transport::send` directly with the raw `interface.method` strings.

The `nucleus-client::deprecated_methods` module is the canonical home for that direct-dispatch escape hatch — see [nucleus-client](../nucleus-client/README.md) for the four operations it covers and the hand-edit-on-IDL-change contract.

## Downstream consumers

The crate is `[build-dependencies]` for every other in-workspace crate that needs a generated trait:

- `nucleus-discovery/build.rs` — generates from `Discovery.idl.ts`.
- `nucleus-auth/build.rs` — generates from `OmniAuth.idl.ts`.
- `nucleus-client/build.rs` — generates from `omni1.idl.ts`.

Each `build.rs` calls `nucleus_codegen::generate_from_file(...)` and writes the output into `OUT_DIR/generated.rs`. The crate's `pub mod generated { include!(concat!(env!("OUT_DIR"), "/generated.rs")) }` is the single seam.

## Cross-links

- [nucleus-client](../nucleus-client/README.md) / [nucleus-auth](../nucleus-auth/README.md) / [nucleus-discovery](../nucleus-discovery/README.md) — the three crates whose `mod generated` blocks come from this generator.
- [nucleus-transport](../nucleus-transport/README.md) — the trait the generated impls dispatch over.

## Implementation gaps

- Codegen errors surface as `anyhow::Error` chains rather than typed errors with span information; downstream `build.rs` failures can be hard to localize on a malformed `.idl.ts`.
- The generator emits a fixed `#[serde(rename_all = "snake_case")]` policy. IDL-level overrides (`@serde(rename = "...")` annotations) are not parsed; the few rename cases in the IDLs are handled by post-codegen patches in the consuming crates.
- Generated structs derive `Debug` uniformly, including auth/token envelopes whose fields may carry secrets. The transport crates avoid payload-level logging, but developers must not log generated values containing credentials. The generator does not provide field-level redaction or redacted `Debug` support.
