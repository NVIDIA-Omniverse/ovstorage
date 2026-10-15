// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![doc = include_str!("../README.md")]

use std::str::FromStr;

use proc_macro::{Spacing, TokenStream, TokenTree};

/// Declare an ABI-v2 (Layer) storage plugin. Emits the stable
/// `ovstorage_plugin_manifest_v1` / `ovstorage_plugin_init_v1` symbol names
/// with `abi_version` set to the Layer ABI
/// (`OVSTORAGE_PLUGIN_ABI_V2_VERSION`).
///
/// ```ignore
/// ovstorage_layer_plugin!(backend, MyBackendFactory::default);
/// ovstorage_layer_plugin!(backend, MyBackendFactory::default, test_only);
/// ovstorage_layer_plugin!((
///     (backend, MyBackendFactory::default),
///     (wrapper, MyWrapperFactory::default),
/// ));
/// ```
///
/// The first argument is the layer-type tag (`backend` / `wrapper` /
/// `router`); the second is a factory constructor expression that yields
/// a value implementing the matching `BackendFactory` /
/// `WrapperFactory` / `RouterFactory` trait. The bundled form accepts one or
/// more `(tag, constructor)` entries. Both forms accept an optional trailing
/// `test_only` flag.
#[proc_macro]
pub fn ovstorage_layer_plugin(input: TokenStream) -> TokenStream {
    let tokens: Vec<TokenTree> = input.into_iter().collect();
    let segments = split_top_level_commas(&tokens);
    let (factories, test_only) = match parse_invocation(&segments) {
        Ok(parsed) => parsed,
        Err(error) => return compile_error(error),
    };
    let test_only_lit = if test_only { "true" } else { "false" };
    let factory_entries = factories
        .iter()
        .map(|(variant, ctor)| {
            format!(
                "::ovstorage_plugin::thunks_v2::LayerFactory::{variant}(\
                 ::std::sync::Arc::new(({ctor})()))"
            )
        })
        .collect::<Vec<_>>()
        .join(",");

    let name = std::env::var("CARGO_PKG_NAME").unwrap_or_else(|_| "ovstorage-plugin".into());
    let version = std::env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.0.0".into());
    let name_lit = rust_string_literal(&name);
    let version_lit = rust_string_literal(&version);

    let generated = format!(
        r#"
#[doc(hidden)]
static OVSTORAGE_LAYER_PLUGIN_NAME: &[u8] = concat!({name_lit}, "\0").as_bytes();

#[doc(hidden)]
static OVSTORAGE_LAYER_PLUGIN_VERSION: &[u8] = concat!({version_lit}, "\0").as_bytes();

// The Layer ABI uses the frozen `PluginManifestV1` wire struct and symbol name;
// the `abi_version` field discriminates (the host peeks it before
// choosing how to read the init result).
#[unsafe(no_mangle)]
pub static ovstorage_plugin_manifest_v1: ::ovstorage_plugin::PluginManifestV1 =
    ::ovstorage_plugin::PluginManifestV1 {{
        struct_size: ::std::mem::size_of::<::ovstorage_plugin::PluginManifestV1>(),
        abi_version: ::ovstorage_plugin::ffi::OVSTORAGE_PLUGIN_ABI_V2_VERSION,
        name: OVSTORAGE_LAYER_PLUGIN_NAME.as_ptr() as *const ::std::os::raw::c_char,
        version: OVSTORAGE_LAYER_PLUGIN_VERSION.as_ptr() as *const ::std::os::raw::c_char,
        test_only: {test_only_lit},
    }};

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_plugin_init_v1(
    host: *const ::ovstorage_plugin::ffi::HostCallbacks,
) -> ::ovstorage_plugin::ffi::PluginInitResultV1 {{
    ::ovstorage_plugin::marshal::register_host(host);
    ::ovstorage_plugin::log_layer::install();
    let factories = ::std::vec![{factory_entries}];
    ::ovstorage_plugin::thunks_v2::install_plugin(
        ::ovstorage_plugin::thunks_v2::LayerPlugin::new(factories),
    )
}}
"#
    );
    TokenStream::from_str(&generated).unwrap_or_else(|error| {
        compile_error(format!(
            "failed to generate ovstorage_layer_plugin output: {error}"
        ))
    })
}

fn parse_invocation(segments: &[&[TokenTree]]) -> Result<(Vec<(String, String)>, bool), String> {
    if let Some([TokenTree::Group(group)]) = segments.first()
        && group.delimiter() == proc_macro::Delimiter::Parenthesis
    {
        if segments.len() > 2 {
            return Err(usage());
        }
        let test_only = parse_test_only(segments.get(1))?;
        let bundle_tokens: Vec<TokenTree> = group.stream().into_iter().collect();
        let entries = split_top_level_commas(&bundle_tokens);
        if entries.is_empty() {
            return Err(
                "ovstorage_layer_plugin!(): a factory bundle must not be empty".to_string(),
            );
        }
        let mut factories = Vec::with_capacity(entries.len());
        for entry in entries {
            let [TokenTree::Group(entry)] = entry else {
                return Err(
                    "ovstorage_layer_plugin!(): every bundled factory must be written as \
                     `(tag, constructor)`"
                        .to_string(),
                );
            };
            if entry.delimiter() != proc_macro::Delimiter::Parenthesis {
                return Err(
                    "ovstorage_layer_plugin!(): every bundled factory must be written as \
                     `(tag, constructor)`"
                        .to_string(),
                );
            }
            let entry_tokens: Vec<TokenTree> = entry.stream().into_iter().collect();
            let fields = split_top_level_commas(&entry_tokens);
            if fields.len() != 2 {
                return Err(
                    "ovstorage_layer_plugin!(): every bundled factory takes exactly \
                     `(tag, constructor)`"
                        .to_string(),
                );
            }
            factories.push(parse_factory(fields[0], fields[1])?);
        }
        return Ok((factories, test_only));
    }

    if segments.len() < 2 || segments.len() > 3 {
        return Err(usage());
    }
    let factory = parse_factory(segments[0], segments[1])?;
    let test_only = parse_test_only(segments.get(2))?;
    Ok((vec![factory], test_only))
}

fn parse_factory(tag: &[TokenTree], ctor: &[TokenTree]) -> Result<(String, String), String> {
    let variant = match tag {
        [TokenTree::Ident(ident)] => match ident.to_string().as_str() {
            "backend" => "Backend",
            "wrapper" => "Wrapper",
            "router" => "Router",
            other => {
                return Err(format!(
                    "ovstorage_layer_plugin!(): factory tag must be backend, wrapper, or router; \
                     got '{other}'"
                ));
            }
        },
        _ => {
            return Err(
                "ovstorage_layer_plugin!(): factory tag must be a single identifier \
                 (backend / wrapper / router)"
                    .to_string(),
            );
        }
    };
    if ctor.is_empty() {
        return Err(
            "ovstorage_layer_plugin!(): a factory constructor expression is required".to_string(),
        );
    }
    Ok((variant.to_string(), token_slice_to_string(ctor)))
}

fn parse_test_only(segment: Option<&&[TokenTree]>) -> Result<bool, String> {
    match segment {
        None => Ok(false),
        Some([TokenTree::Ident(ident)]) if ident.to_string() == "test_only" => Ok(true),
        Some(other) => {
            let rendered = token_slice_to_string(other);
            Err(format!(
                "ovstorage_layer_plugin!(): unrecognized flag '{rendered}'; accepted: 'test_only'"
            ))
        }
    }
}

fn usage() -> String {
    "ovstorage_layer_plugin!(...) takes either `<tag>, <factory ctor>[, test_only]` \
     or `((<tag>, <factory ctor>), ...)[, test_only]`"
        .to_string()
}

/// Split a token stream into top-level comma-separated segments,
/// respecting `<...>` generic-argument nesting (so a `,` inside generics
/// does not split).
fn split_top_level_commas(tokens: &[TokenTree]) -> Vec<&[TokenTree]> {
    let mut angle_depth: i32 = 0;
    let mut segments = Vec::new();
    let mut start = 0usize;
    for (index, token) in tokens.iter().enumerate() {
        if let TokenTree::Punct(punct) = token {
            match punct.as_char() {
                '<' => angle_depth += 1,
                '>' if punct.spacing() == Spacing::Alone && angle_depth > 0 => angle_depth -= 1,
                ',' if angle_depth == 0 => {
                    segments.push(&tokens[start..index]);
                    start = index + 1;
                }
                _ => {}
            }
        }
    }
    if start < tokens.len() {
        segments.push(&tokens[start..]);
    } else if start == tokens.len() && !tokens.is_empty() {
        // trailing comma: ignore the empty final segment
    }
    segments
}

fn rust_string_literal(value: &str) -> String {
    format!("{value:?}")
}

fn compile_error(message: String) -> TokenStream {
    let message = rust_string_literal(&message);
    TokenStream::from_str(&format!("compile_error!({message});")).unwrap()
}

fn token_slice_to_string(tokens: &[TokenTree]) -> String {
    tokens.iter().cloned().collect::<TokenStream>().to_string()
}
