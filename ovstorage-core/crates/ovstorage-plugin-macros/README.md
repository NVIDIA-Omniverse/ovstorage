# ovstorage-plugin-macros (`ovstorage-plugin-macros`)

> The canonical reference for the `ovstorage_plugin!` proc macro lives
> in [`docs/public/plugin-development/README.md` § Plugin macros](../../../docs/public/plugin-development/README.md#plugin-macros).

## Purpose (crate-local)

Proc-macro crate that emits the two `#[unsafe(no_mangle)]` symbols a
host loader looks up when loading a backend plugin:
`ovstorage_plugin_manifest_v1` and `ovstorage_plugin_init_v1`. The
expansion wires the plugin author's factory constructor into the
static `FACTORY_VTABLE` exported by
[ovstorage-plugin](../ovstorage-plugin/README.md), so a plugin author
writes a `Factory` impl plus one macro invocation and the C-ABI
surface is generated for them.

## Contributor notes

This README covers contributor-internal details only. Plugin authors
should read the public reference linked above for the macro's public
contract, generated symbols, banded handshake, panic-safety story,
and migration roadmap.

### Implementation choices

The macro builds its expansion via `format!` + `TokenStream::from_str`
rather than `quote!` so the crate has zero `proc-macro2` / `syn` /
`quote` dependencies. This is an internal detail subject to change —
plugin authors should not depend on the textual shape of the
expansion.

Argument parsing walks `proc_macro::TokenTree` directly: it scans
the input for the last top-level `,` while tracking angle-bracket
depth, so commas inside turbofish generics (`Type::<A, B>::ctor`)
are not mistaken for the optional-flag separator. Commas inside
parens, square brackets, and braces already nest under
`TokenTree::Group` and so are invisible to the top-level scan; that
means closure-literal arguments like `|| Factory::new("a", "b")`
parse cleanly. A non-empty tail after the split must be exactly one
`Ident("test_only")`; anything else is a `compile_error!` naming
the rejected flag.

## Cross-links

- [ovstorage-plugin](../ovstorage-plugin/README.md) — the host-side
  contract this macro targets, including the C-ABI surface and the
  `FACTORY_VTABLE` thunks the expansion references.
- [ovstorage-plugin-test](../ovstorage-plugin-test/README.md) —
  conformance harness covering plugins built with this macro (the
  harness loads the cdylib through the same
  `ovstorage_plugin_manifest_v1` / `ovstorage_plugin_init_v1`
  symbols a production host uses).

## Implementation gaps

None known. The macro is feature-complete for the backend-plugin
kind. ABI band widening is the only forward-compat surface that
touches this crate, and it lives downstream in `ovstorage-plugin`.
