// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![doc = include_str!("../README.md")]

use std::str::FromStr;

use proc_macro::{Spacing, TokenStream, TokenTree};

#[proc_macro]
pub fn ovstorage_plugin(input: TokenStream) -> TokenStream {
    let tokens: Vec<TokenTree> = input.into_iter().collect();
    if tokens.is_empty() {
        return compile_error(
            "ovstorage_plugin!(...) requires a factory constructor expression, \
             e.g. `ovstorage_plugin!(MyFactory::default);`"
                .to_string(),
        );
    }

    let (factory_ctor, test_only) = match split_top_level_flag(&tokens) {
        Ok(parts) => parts,
        Err(message) => return compile_error(message),
    };
    let test_only_lit = if test_only { "true" } else { "false" };

    let name = std::env::var("CARGO_PKG_NAME").unwrap_or_else(|_| "ovstorage-plugin".into());
    let version = std::env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.0.0".into());
    let name_lit = rust_string_literal(&name);
    let version_lit = rust_string_literal(&version);

    let generated = format!(
        r#"
#[doc(hidden)]
static OVSTORAGE_PLUGIN_NAME: &[u8] = concat!({name_lit}, "\0").as_bytes();

#[doc(hidden)]
static OVSTORAGE_PLUGIN_VERSION: &[u8] = concat!({version_lit}, "\0").as_bytes();

#[unsafe(no_mangle)]
pub static ovstorage_plugin_manifest_v1: ::ovstorage_plugin::PluginManifestV1 =
    ::ovstorage_plugin::PluginManifestV1 {{
        struct_size: ::std::mem::size_of::<::ovstorage_plugin::PluginManifestV1>(),
        abi_version: ::ovstorage_plugin::OVSTORAGE_PLUGIN_ABI_VERSION,
        name: OVSTORAGE_PLUGIN_NAME.as_ptr() as *const ::std::os::raw::c_char,
        version: OVSTORAGE_PLUGIN_VERSION.as_ptr() as *const ::std::os::raw::c_char,
        test_only: {test_only_lit},
    }};

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_plugin_init_v1(
    host: *const ::ovstorage_plugin::ffi::HostCallbacks,
) -> ::ovstorage_plugin::BackendPluginInitResultV1 {{
    // Per-call methods have no callbacks pointer; they fetch it from this slot.
    ::ovstorage_plugin::shim::register_host(host);
    // Wire `tracing` events emitted inside this cdylib through the host's
    // log callback. Plugins compile against their own copy of the
    // `tracing` global subscriber; without this bridge, RUST_LOG never
    // sees any plugin events. Idempotent.
    ::ovstorage_plugin::log_layer::install();
    // Leaked `Box<dyn Factory>`; host releases via `FACTORY_VTABLE.drop` at unload.
    let plugin_state = ::ovstorage_plugin::thunks::leak_factory(({factory_ctor})());
    ::ovstorage_plugin::BackendPluginInitResultV1 {{
        struct_size: ::std::mem::size_of::<::ovstorage_plugin::BackendPluginInitResultV1>(),
        abi_version: ::ovstorage_plugin::OVSTORAGE_PLUGIN_ABI_VERSION,
        // 0.x: one ABI version per plugin, so min == max == abi_version.
        min_supported_abi_version: ::ovstorage_plugin::OVSTORAGE_PLUGIN_ABI_VERSION,
        max_supported_abi_version: ::ovstorage_plugin::OVSTORAGE_PLUGIN_ABI_VERSION,
        plugin_state,
        factory_vtable: &::ovstorage_plugin::thunks::FACTORY_VTABLE,
    }}
}}
"#
    );
    TokenStream::from_str(&generated).unwrap_or_else(|error| {
        compile_error(format!(
            "failed to generate ovstorage_plugin output: {error}"
        ))
    })
}

fn rust_string_literal(value: &str) -> String {
    format!("{value:?}")
}

fn compile_error(message: String) -> TokenStream {
    let message = rust_string_literal(&message);
    TokenStream::from_str(&format!("compile_error!({message});")).unwrap()
}

fn split_top_level_flag(tokens: &[TokenTree]) -> Result<(String, bool), String> {
    let mut angle_depth: i32 = 0;
    let mut split_at: Option<usize> = None;
    for (index, token) in tokens.iter().enumerate() {
        if let TokenTree::Punct(punct) = token {
            match punct.as_char() {
                '<' => angle_depth += 1,
                '>' if punct.spacing() == Spacing::Alone && angle_depth > 0 => angle_depth -= 1,
                ',' if angle_depth == 0 => split_at = Some(index),
                _ => {}
            }
        }
    }

    match split_at {
        Some(index) => {
            let head = &tokens[..index];
            let tail = &tokens[index + 1..];
            if head.is_empty() {
                return Err(
                    "ovstorage_plugin!(...) requires a factory constructor expression \
                     before the flag separator"
                        .to_string(),
                );
            }
            let test_only = match tail {
                [] => false,
                [TokenTree::Ident(ident)] if ident.to_string() == "test_only" => true,
                _ => {
                    let rendered: String = tail
                        .iter()
                        .map(|t| t.to_string())
                        .collect::<Vec<_>>()
                        .join(" ");
                    return Err(format!(
                        "ovstorage_plugin!(): unrecognized flag '{rendered}'; \
                         accepted: 'test_only'"
                    ));
                }
            };
            Ok((token_slice_to_string(head), test_only))
        }
        None => Ok((token_slice_to_string(tokens), false)),
    }
}

fn token_slice_to_string(tokens: &[TokenTree]) -> String {
    tokens.iter().cloned().collect::<TokenStream>().to_string()
}
