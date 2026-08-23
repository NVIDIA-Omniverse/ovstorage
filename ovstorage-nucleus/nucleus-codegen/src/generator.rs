// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::{HashMap, HashSet};

use proc_macro2::TokenStream;
use quote::{format_ident, quote};

use crate::ast::*;

pub fn generate(file: &IdlFile, origin: &str) -> TokenStream {
    resolve_plugin_imports(file);

    let type_map = build_type_map(file);

    let mut type_tokens = TokenStream::new();
    let mut iface_tokens = TokenStream::new();

    for item in &file.items {
        match item {
            Item::TypeAlias(ta) => {
                let name = match ta {
                    TypeAlias::Struct(s) => &s.name,
                    TypeAlias::Alias(a) => &a.name,
                    TypeAlias::Union(u) => &u.name,
                    TypeAlias::Literal(l) => &l.name,
                    TypeAlias::IndexMap(m) => &m.name,
                };
                tracing::debug!(item_type = "type_alias", name = %name, "generating item");
                type_tokens.extend(generate_type_alias(ta, &type_map));
            }
            Item::Enum(e) => {
                tracing::debug!(item_type = "enum", name = %e.name, "generating item");
                type_tokens.extend(generate_enum(e));
            }
            Item::Interface(iface) => {
                tracing::debug!(
                    item_type = "interface",
                    name = %iface.name,
                    n = iface.methods.len(),
                    "interface with n methods"
                );
                iface_tokens.extend(generate_interface(iface, &type_map, origin));
            }
            Item::Import(_) => {}
        }
    }

    quote! {
        pub mod types {
            #[allow(unused_imports)]
            use std::collections::HashMap;
            use serde::{Serialize, Deserialize};
            #type_tokens
        }
        #[allow(unused_imports)]
        use std::collections::HashMap;
        use types::*;
        #iface_tokens
    }
}

fn build_type_map(file: &IdlFile) -> HashMap<String, &StructDef> {
    let mut map = HashMap::new();
    for item in &file.items {
        if let Item::TypeAlias(TypeAlias::Struct(s)) = item {
            map.insert(s.name.clone(), s);
        }
    }
    map
}

struct PluginTypes {
    version_types: HashSet<String>,
    capability_types: HashSet<String>,
}

fn resolve_plugin_imports(file: &IdlFile) -> PluginTypes {
    let mut pt = PluginTypes {
        version_types: HashSet::new(),
        capability_types: HashSet::new(),
    };
    for item in &file.items {
        if let Item::Import(import) = item {
            if import.from.contains("versions") {
                for name in &import.items {
                    pt.version_types.insert(name.clone());
                }
            } else if import.from.contains("capabilities") {
                for name in &import.items {
                    pt.capability_types.insert(name.clone());
                }
            }
        }
    }
    PLUGIN_TYPES.with(|c| {
        *c.borrow_mut() = pt
            .version_types
            .union(&pt.capability_types)
            .cloned()
            .collect()
    });
    VERSION_TYPES.with(|c| *c.borrow_mut() = pt.version_types.clone());
    CAPABILITY_TYPES.with(|c| *c.borrow_mut() = pt.capability_types.clone());
    tracing::trace!(
        versions = pt.version_types.len(),
        capabilities = pt.capability_types.len(),
        "plugin types"
    );
    pt
}

std::thread_local! {
    static PLUGIN_TYPES: std::cell::RefCell<HashSet<String>> = std::cell::RefCell::new(HashSet::new());
    static VERSION_TYPES: std::cell::RefCell<HashSet<String>> = std::cell::RefCell::new(HashSet::new());
    static CAPABILITY_TYPES: std::cell::RefCell<HashSet<String>> = std::cell::RefCell::new(HashSet::new());
}

fn is_bytes_type(ty: &TypeRef) -> bool {
    matches!(ty, TypeRef::Named(n) if n == "bytes" || n == "Blob")
}

fn find_bytes_param(method: &Method) -> Option<&Param> {
    method.params.iter().find(|p| is_bytes_type(&p.ty))
}

fn return_type_has_content_bytes(
    return_type: &TypeRef,
    type_map: &HashMap<String, &StructDef>,
) -> bool {
    let name = match return_type {
        TypeRef::Named(n) => n.as_str(),
        _ => return false,
    };
    if let Some(struct_def) = type_map.get(name) {
        return struct_def
            .fields
            .iter()
            .any(|f| f.name == "content" && is_bytes_type(&f.ty));
    }
    false
}

// ── Type mapping ──

fn map_type_ref(ty: &TypeRef) -> TokenStream {
    match ty {
        TypeRef::Named(name) => map_named_type(name),
        TypeRef::Array(inner) => {
            let inner_ts = map_type_ref(inner);
            quote! { Vec<#inner_ts> }
        }
        TypeRef::Generic(name, args) => {
            if name == "__union" {
                if let Some(first) = args.first() {
                    return map_type_ref(first);
                }
                tracing::warn!(name, "unmapped type, using serde_json::Value");
                quote! { serde_json::Value }
            } else if name == "Promise" || name == "AsyncGenerator" {
                if let Some(first) = args.first() {
                    map_type_ref(first)
                } else {
                    quote! { () }
                }
            } else if (name == "Map" || name == "Record") && args.len() == 2 {
                let k = map_type_ref(&args[0]);
                let v = map_type_ref(&args[1]);
                quote! { HashMap<#k, #v> }
            } else if name == "Partial" {
                if let Some(first) = args.first() {
                    map_type_ref(first)
                } else {
                    tracing::warn!(name, "unmapped type, using serde_json::Value");
                    quote! { serde_json::Value }
                }
            } else if is_version_type(name) {
                quote! { u64 }
            } else if is_capability_type(name) || is_plugin_type(name) {
                quote! { HashMap<String, u64> }
            } else {
                tracing::warn!(name, "unmapped type, using serde_json::Value");
                quote! { serde_json::Value }
            }
        }
    }
}

fn map_named_type(name: &str) -> TokenStream {
    match name {
        "string" => quote! { String },
        "boolean" | "bool" => quote! { bool },
        "number" | "float" | "float32" => quote! { f32 },
        "double" | "float64" => quote! { f64 },
        "int8" => quote! { i8 },
        "int16" => quote! { i16 },
        "int32" | "int" => quote! { i32 },
        "int64" => quote! { i64 },
        "uint8" => quote! { u8 },
        "uint16" => quote! { u16 },
        "uint32" | "uint" => quote! { u32 },
        "uint64" => quote! { u64 },
        "bytes" | "Blob" => quote! { Vec<u8> },
        "void" | "undefined" | "null" => quote! { () },
        "any" | "unknown" | "object" => quote! { serde_json::Value },
        "Date" => quote! { String },
        other => {
            if is_version_type(other) {
                quote! { u64 }
            } else if is_capability_type(other) {
                quote! { HashMap<String, u64> }
            } else if other.starts_with('"') || other.starts_with('\'') {
                quote! { String }
            } else {
                let ident = format_ident!("{}", other);
                quote! { #ident }
            }
        }
    }
}

fn is_plugin_type(name: &str) -> bool {
    PLUGIN_TYPES.with(|c| c.borrow().contains(name))
}

fn is_version_type(name: &str) -> bool {
    VERSION_TYPES.with(|c| c.borrow().contains(name))
}

fn is_capability_type(name: &str) -> bool {
    CAPABILITY_TYPES.with(|c| c.borrow().contains(name))
}

fn is_version_param(p: &Param) -> bool {
    matches!(&p.ty, TypeRef::Named(n) if is_version_type(n))
        || matches!(&p.ty, TypeRef::Generic(n, _) if is_version_type(n))
}

// ── Type alias / struct / enum generation ──

fn generate_type_alias(ta: &TypeAlias, type_map: &HashMap<String, &StructDef>) -> TokenStream {
    match ta {
        TypeAlias::Struct(s) => generate_struct(s, type_map),
        TypeAlias::IndexMap(m) => generate_index_map(m),
        TypeAlias::Alias(a) => generate_alias(a),
        TypeAlias::Union(u) => generate_union(u),
        TypeAlias::Literal(l) => generate_literal(l),
    }
}

fn flatten_fields(s: &StructDef, type_map: &HashMap<String, &StructDef>) -> Vec<Field> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for base_name in &s.extends {
        match type_map.get(base_name) {
            Some(base) => {
                for f in flatten_fields(base, type_map) {
                    if seen.insert(f.name.clone()) {
                        out.push(f);
                    }
                }
            }
            None => {
                tracing::warn!(struct_name = %s.name, base = %base_name, "intersection extends unknown type, skipping");
            }
        }
    }
    for f in &s.fields {
        if seen.insert(f.name.clone()) {
            out.push(f.clone());
        }
    }
    out
}

fn generate_struct(s: &StructDef, type_map: &HashMap<String, &StructDef>) -> TokenStream {
    let name = format_ident!("{}", &s.name);
    let merged = flatten_fields(s, type_map);
    let fields: Vec<_> = merged
        .iter()
        .map(|f| {
            let rust_name = sanitize_field_name(&to_snake_case(&f.name));
            let field_name = format_ident!("{}", rust_name);
            let ty = map_type_ref(&f.ty);
            let rename = if rust_name != f.name {
                let original = &f.name;
                quote! { #[serde(rename = #original)] }
            } else {
                quote! {}
            };

            if f.optional {
                quote! {
                    #rename
                    #[serde(default, skip_serializing_if = "Option::is_none")]
                    pub #field_name: Option<#ty>,
                }
            } else {
                quote! {
                    #rename
                    pub #field_name: #ty,
                }
            }
        })
        .collect();

    quote! {
        #[derive(Debug, Clone, Default, Serialize, Deserialize)]
        pub struct #name {
            #(#fields)*
        }
    }
}

fn generate_index_map(m: &IndexMapDef) -> TokenStream {
    let name = format_ident!("{}", &m.name);
    let key = map_type_ref(&m.key_type);
    let val = map_type_ref(&m.value_type);
    quote! {
        pub type #name = HashMap<#key, #val>;
    }
}

fn generate_alias(a: &AliasDef) -> TokenStream {
    let name = format_ident!("{}", &a.name);
    let target = map_type_ref(&a.target);
    quote! {
        pub type #name = #target;
    }
}

fn is_primitive_keyword(name: &str) -> bool {
    matches!(
        name,
        "string"
            | "boolean"
            | "bool"
            | "number"
            | "float"
            | "float32"
            | "double"
            | "float64"
            | "int8"
            | "int16"
            | "int32"
            | "int"
            | "int64"
            | "uint8"
            | "uint16"
            | "uint32"
            | "uint"
            | "uint64"
            | "bytes"
            | "Blob"
            | "void"
            | "undefined"
            | "null"
            | "any"
            | "unknown"
            | "object"
            | "Date"
    )
}

fn is_string_literal(name: &str) -> bool {
    name.starts_with('"') || name.starts_with('\'')
}

fn primitive_variant_ident(name: &str) -> Option<&'static str> {
    match name {
        "string" | "Date" => Some("String"),
        "boolean" | "bool" => Some("Bool"),
        "number" | "float" | "float32" => Some("F32"),
        "double" | "float64" => Some("F64"),
        "int8" => Some("I8"),
        "int16" => Some("I16"),
        "int32" | "int" => Some("I32"),
        "int64" => Some("I64"),
        "uint8" => Some("U8"),
        "uint16" => Some("U16"),
        "uint32" | "uint" => Some("U32"),
        "uint64" => Some("U64"),
        "bytes" | "Blob" => Some("Bytes"),
        _ => None,
    }
}

fn union_variant_for(ty: &TypeRef) -> Option<(proc_macro2::Ident, TokenStream)> {
    if let TypeRef::Named(n) = ty {
        if is_string_literal(n) {
            return None;
        }
        if let Some(ident) = primitive_variant_ident(n) {
            let id = format_ident!("{}", ident);
            let payload = map_named_type(n);
            return Some((id, payload));
        }
        let id = format_ident!("{}", n);
        let payload = quote! { #id };
        return Some((id, payload));
    }
    None
}

fn generate_union(u: &UnionDef) -> TokenStream {
    let name = format_ident!("{}", &u.name);

    if u.variants.is_empty() {
        return quote! { pub type #name = (); };
    }

    let mut has_primitive = false;
    let mut has_literal = false;
    let mut has_named_struct = false;
    for v in &u.variants {
        match v {
            TypeRef::Named(n) if is_string_literal(n) => has_literal = true,
            TypeRef::Named(n) if is_primitive_keyword(n) => has_primitive = true,
            TypeRef::Named(_) => has_named_struct = true,
            _ => has_named_struct = true,
        }
    }

    if has_literal && !has_primitive && !has_named_struct {
        return quote! { pub type #name = String; };
    }

    let mixed =
        (has_literal && (has_primitive || has_named_struct)) || (has_primitive && has_named_struct);
    if mixed {
        return quote! { pub type #name = serde_json::Value; };
    }

    let mut variants = Vec::new();
    let mut seen = HashSet::new();
    for v in &u.variants {
        if let Some((ident, payload)) = union_variant_for(v) {
            let key = ident.to_string();
            if seen.insert(key) {
                variants.push(quote! { #ident(#payload), });
            }
        }
    }

    if variants.is_empty() {
        return quote! { pub type #name = serde_json::Value; };
    }

    quote! {
        #[derive(Debug, Clone, Serialize, Deserialize)]
        #[serde(untagged)]
        pub enum #name {
            #(#variants)*
        }
    }
}

fn generate_literal(l: &LiteralDef) -> TokenStream {
    let name = format_ident!("{}", &l.name);
    let const_name = format_ident!("{}", to_snake_case(&l.name).to_uppercase());
    match &l.value {
        LiteralValue::String(s) => {
            quote! {
                pub type #name = String;
                pub const #const_name: &str = #s;
            }
        }
        LiteralValue::Number(n) => {
            let lit = proc_macro2::Literal::f64_unsuffixed(*n);
            quote! {
                pub type #name = f64;
                pub const #const_name: f64 = #lit;
            }
        }
    }
}

fn generate_enum(e: &Enum) -> TokenStream {
    let name = format_ident!("{}", &e.name);
    if e.variants.is_empty() {
        return quote! { pub type #name = (); };
    }
    let is_string_enum = e
        .variants
        .iter()
        .any(|v| matches!(&v.value, EnumValue::String(_)));

    let variants: Vec<_> = e
        .variants
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let vname = format_ident!("{}", &v.name);
            let default_attr = if i == 0 {
                quote! { #[default] }
            } else {
                quote! {}
            };
            match &v.value {
                EnumValue::String(s) => {
                    quote! {
                        #[serde(rename = #s)]
                        #default_attr
                        #vname,
                    }
                }
                EnumValue::Integer(n) => {
                    let lit = proc_macro2::Literal::i64_unsuffixed(*n);
                    quote! { #default_attr #vname = #lit, }
                }
                EnumValue::Auto => {
                    quote! { #default_attr #vname, }
                }
            }
        })
        .collect();

    if is_string_enum {
        quote! {
            #[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
            pub enum #name {
                #(#variants)*
            }
        }
    } else {
        quote! {
            #[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
            #[repr(i64)]
            pub enum #name {
                #(#variants)*
            }
        }
    }
}

// ── Interface generation (trait + blanket impl) ──

fn generate_interface(
    iface: &Interface,
    type_map: &HashMap<String, &StructDef>,
    origin: &str,
) -> TokenStream {
    let trait_def = generate_interface_trait(iface);
    let blanket_impl = generate_blanket_impl(iface, type_map);
    let constants = generate_interface_constants(iface, origin);
    quote! {
        #trait_def
        #blanket_impl
        #constants
    }
}

fn generate_interface_constants(iface: &Interface, origin: &str) -> TokenStream {
    let mod_name = format_ident!("{}", to_snake_case(&iface.name));
    let iface_name = &iface.name;

    let cap_entries: Vec<_> = active_methods(iface)
        .map(|m| {
            let name = &m.name;
            let version = m.version.unwrap_or(0) as u64;
            quote! { map.insert(#name.to_string(), #version); }
        })
        .collect();

    let cap_count = cap_entries.len();

    quote! {
        pub mod #mod_name {
            pub const ORIGIN: &str = #origin;
            pub const INTERFACE: &str = #iface_name;

            pub fn capabilities() -> std::collections::HashMap<String, u64> {
                let mut map = std::collections::HashMap::with_capacity(#cap_count);
                #(#cap_entries)*
                map
            }
        }
    }
}

fn method_param_tokens(m: &Method) -> Vec<TokenStream> {
    m.params
        .iter()
        .filter(|p| !is_version_param(p))
        .map(|p| {
            let pname = format_ident!("{}", sanitize_field_name(&to_snake_case(&p.name)));
            let pty = map_type_ref(&p.ty);
            if p.optional {
                quote! { #pname: Option<#pty> }
            } else {
                quote! { #pname: #pty }
            }
        })
        .collect()
}

fn method_return_type(m: &Method) -> TokenStream {
    if m.is_streaming {
        quote! { anyhow::Result<nucleus_transport::Subscription> }
    } else {
        let ret = map_type_ref(&m.return_type);
        quote! { anyhow::Result<#ret> }
    }
}

fn active_methods(iface: &Interface) -> impl Iterator<Item = &Method> {
    iface.methods.iter().filter(|m| !m.deprecated)
}

fn generate_interface_trait(iface: &Interface) -> TokenStream {
    let trait_name = format_ident!("{}", &iface.name);

    let methods: Vec<_> = active_methods(iface)
        .map(|m| {
            let method_name = format_ident!("{}", to_snake_case(&m.name));
            let params = method_param_tokens(m);
            let ret_type = method_return_type(m);

            let doc = m.doc_comment.as_ref().map(|d| {
                let lines: Vec<_> = d
                    .lines()
                    .map(|line| {
                        // Escape leading `- ` to prevent markdown list interpretation
                        let escaped = if line.starts_with("- ") {
                            format!(" \\{line}")
                        } else {
                            format!(" {line}")
                        };
                        quote! { #[doc = #escaped] }
                    })
                    .collect();
                quote! { #(#lines)* }
            });

            quote! {
                #doc
                #[allow(clippy::too_many_arguments)]
                async fn #method_name(&self, #(#params),*) -> #ret_type;
            }
        })
        .collect();

    quote! {
        #[allow(async_fn_in_trait)]
        pub trait #trait_name: Send {
            #(#methods)*
        }
    }
}

fn generate_blanket_impl(iface: &Interface, type_map: &HashMap<String, &StructDef>) -> TokenStream {
    let trait_name = format_ident!("{}", &iface.name);
    let iface_name = &iface.name;

    let methods: Vec<_> = active_methods(iface)
        .map(|m| generate_impl_method(m, iface_name, type_map))
        .collect();

    quote! {
        impl<__T: nucleus_transport::Transport> #trait_name for __T {
            #(#methods)*
        }
    }
}

fn generate_param_setup(method: &Method) -> TokenStream {
    let mut stmts: Vec<TokenStream> = vec![quote! {
        let mut __params = serde_json::json!({});
    }];

    for p in &method.params {
        if is_bytes_type(&p.ty) {
            continue;
        }

        let json_key = &p.name;

        if is_version_param(p) {
            let version_val = method.version.unwrap_or(0) as u64;
            stmts.push(quote! {
                __params[#json_key] = serde_json::json!(#version_val);
            });
            continue;
        }

        let rust_name = format_ident!("{}", sanitize_field_name(&to_snake_case(&p.name)));

        if p.optional {
            stmts.push(quote! {
                if let Some(ref __val) = #rust_name {
                    __params[#json_key] = serde_json::to_value(__val)
                        .map_err(|e| anyhow::anyhow!(e))?;
                }
            });
        } else {
            stmts.push(quote! {
                __params[#json_key] = serde_json::to_value(#rust_name)
                    .map_err(|e| anyhow::anyhow!(e))?;
            });
        }
    }

    quote! { #(#stmts)* }
}

fn generate_impl_method(
    method: &Method,
    iface_name: &str,
    type_map: &HashMap<String, &StructDef>,
) -> TokenStream {
    let method_name = format_ident!("{}", to_snake_case(&method.name));
    let wire_name = &method.name;
    let params = method_param_tokens(method);
    let ret_type = method_return_type(method);
    let param_setup = generate_param_setup(method);

    let bytes_param = find_bytes_param(method);

    let binary_arg = if let Some(bp) = bytes_param {
        let bp_rust = format_ident!("{}", sanitize_field_name(&to_snake_case(&bp.name)));
        if bp.optional {
            quote! { #bp_rust }
        } else {
            quote! { Some(#bp_rust) }
        }
    } else {
        quote! { None }
    };

    let body = if method.is_streaming {
        quote! {
            #param_setup
            self.send(#iface_name, #wire_name, __params, #binary_arg).await
        }
    } else {
        let ret = map_type_ref(&method.return_type);
        let has_binary_response = return_type_has_content_bytes(&method.return_type, type_map);

        if has_binary_response {
            quote! {
                #param_setup
                let mut __sub = self.send(#iface_name, #wire_name, __params, #binary_arg).await?;
                let (mut __resp, __blob): (#ret, _) = __sub.recv().await?;
                if let Some(__data) = __blob {
                    __resp.content = Some(__data);
                }
                Ok(__resp)
            }
        } else {
            quote! {
                #param_setup
                let mut __sub = self.send(#iface_name, #wire_name, __params, #binary_arg).await?;
                let (__resp, _): (#ret, _) = __sub.recv().await?;
                Ok(__resp)
            }
        }
    };

    quote! {
        #[allow(clippy::too_many_arguments)]
        async fn #method_name(&self, #(#params),*) -> #ret_type {
            #body
        }
    }
}

// ── Utilities ──

fn to_snake_case(s: &str) -> String {
    let mut result = String::with_capacity(s.len() + 4);
    for (i, ch) in s.chars().enumerate() {
        if ch.is_uppercase() && i > 0 {
            let prev = s.as_bytes()[i - 1] as char;
            if prev.is_lowercase() {
                result.push('_');
            }
        }
        result.push(ch.to_lowercase().next().unwrap());
    }
    result
}

fn sanitize_field_name(name: &str) -> String {
    let s = name.replace('-', "_");
    match s.as_str() {
        "type" | "ref" | "self" | "move" | "match" | "mod" | "use" | "fn" | "impl" | "trait"
        | "struct" | "enum" | "pub" | "let" | "mut" | "const" | "static" | "async" | "await"
        | "loop" | "break" | "continue" | "return" | "where" | "for" | "in" | "if" | "else"
        | "while" | "super" | "crate" | "extern" | "unsafe" | "dyn" | "abstract" | "become"
        | "box" | "do" | "final" | "macro" | "override" | "priv" | "typeof" | "unsized"
        | "virtual" | "yield" | "try" => {
            format!("r#{s}")
        }
        _ => s,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_snake_case() {
        assert_eq!(to_snake_case("fooBar"), "foo_bar");
        assert_eq!(to_snake_case("FooBar"), "foo_bar");
        assert_eq!(to_snake_case("foo"), "foo");
        assert_eq!(to_snake_case("listItems"), "list_items");
    }

    #[test]
    fn to_snake_case_all_uppercase() {
        assert_eq!(to_snake_case("URL"), "url");
    }

    #[test]
    fn to_snake_case_single_char() {
        assert_eq!(to_snake_case("A"), "a");
    }

    #[test]
    fn to_snake_case_empty() {
        assert_eq!(to_snake_case(""), "");
    }

    #[test]
    fn to_snake_case_already_snake() {
        assert_eq!(to_snake_case("already_snake"), "already_snake");
    }

    #[test]
    fn sanitize_preserves_normal_names() {
        assert_eq!(sanitize_field_name("foo_bar"), "foo_bar");
        assert_eq!(sanitize_field_name("name"), "name");
    }

    #[test]
    fn sanitize_escapes_rust_keywords() {
        assert_eq!(sanitize_field_name("type"), "r#type");
        assert_eq!(sanitize_field_name("ref"), "r#ref");
        assert_eq!(sanitize_field_name("self"), "r#self");
        assert_eq!(sanitize_field_name("match"), "r#match");
        assert_eq!(sanitize_field_name("async"), "r#async");
        assert_eq!(sanitize_field_name("await"), "r#await");
    }

    #[test]
    fn sanitize_replaces_dashes_with_underscores() {
        assert_eq!(sanitize_field_name("content-type"), "content_type");
        assert_eq!(sanitize_field_name("x-custom-header"), "x_custom_header");
    }

    #[test]
    fn map_named_type_primitives() {
        let ts = map_named_type("string");
        assert_eq!(ts.to_string(), "String");

        let ts = map_named_type("boolean");
        assert_eq!(ts.to_string(), "bool");

        let ts = map_named_type("void");
        assert_eq!(ts.to_string(), "()");

        let ts = map_named_type("any");
        assert_eq!(ts.to_string(), "serde_json :: Value");
    }

    #[test]
    fn map_named_type_integers() {
        assert_eq!(map_named_type("uint8").to_string(), "u8");
        assert_eq!(map_named_type("uint16").to_string(), "u16");
        assert_eq!(map_named_type("uint32").to_string(), "u32");
        assert_eq!(map_named_type("uint64").to_string(), "u64");
        assert_eq!(map_named_type("int8").to_string(), "i8");
        assert_eq!(map_named_type("int16").to_string(), "i16");
        assert_eq!(map_named_type("int32").to_string(), "i32");
        assert_eq!(map_named_type("int64").to_string(), "i64");
    }

    #[test]
    fn map_named_type_floats() {
        assert_eq!(map_named_type("float").to_string(), "f32");
        assert_eq!(map_named_type("float32").to_string(), "f32");
        assert_eq!(map_named_type("double").to_string(), "f64");
        assert_eq!(map_named_type("float64").to_string(), "f64");
    }

    #[test]
    fn map_named_type_bytes() {
        assert_eq!(map_named_type("bytes").to_string(), "Vec < u8 >");
        assert_eq!(map_named_type("Blob").to_string(), "Vec < u8 >");
    }

    #[test]
    fn map_type_ref_array() {
        let ty = TypeRef::Array(Box::new(TypeRef::Named("string".into())));
        assert_eq!(map_type_ref(&ty).to_string(), "Vec < String >");
    }

    #[test]
    fn map_type_ref_generic_promise() {
        let ty = TypeRef::Generic("Promise".into(), vec![TypeRef::Named("string".into())]);
        assert_eq!(map_type_ref(&ty).to_string(), "String");
    }

    #[test]
    fn map_type_ref_generic_map() {
        let ty = TypeRef::Generic(
            "Map".into(),
            vec![
                TypeRef::Named("string".into()),
                TypeRef::Named("uint64".into()),
            ],
        );
        assert_eq!(map_type_ref(&ty).to_string(), "HashMap < String , u64 >");
    }

    #[test]
    fn map_type_ref_generic_record() {
        let ty = TypeRef::Generic(
            "Record".into(),
            vec![
                TypeRef::Named("string".into()),
                TypeRef::Named("boolean".into()),
            ],
        );
        assert_eq!(map_type_ref(&ty).to_string(), "HashMap < String , bool >");
    }

    #[test]
    fn is_bytes_type_identifies_bytes_and_blob() {
        assert!(is_bytes_type(&TypeRef::Named("bytes".into())));
        assert!(is_bytes_type(&TypeRef::Named("Blob".into())));
        assert!(!is_bytes_type(&TypeRef::Named("string".into())));
    }

    #[test]
    fn return_type_has_content_bytes_true_when_struct_has_bytes_content() {
        let s = StructDef {
            name: "TestStruct".into(),
            fields: vec![Field {
                name: "content".into(),
                ty: TypeRef::Named("bytes".into()),
                optional: true,
            }],
            extends: vec![],
        };
        let mut type_map = HashMap::new();
        type_map.insert("TestStruct".to_string(), &s);
        assert!(return_type_has_content_bytes(
            &TypeRef::Named("TestStruct".into()),
            &type_map
        ));
    }

    #[test]
    fn return_type_has_content_bytes_false_no_content_field() {
        let s = StructDef {
            name: "NoContent".into(),
            fields: vec![Field {
                name: "data".into(),
                ty: TypeRef::Named("bytes".into()),
                optional: false,
            }],
            extends: vec![],
        };
        let mut type_map = HashMap::new();
        type_map.insert("NoContent".to_string(), &s);
        assert!(!return_type_has_content_bytes(
            &TypeRef::Named("NoContent".into()),
            &type_map
        ));
    }

    #[test]
    fn return_type_has_content_bytes_false_for_non_named_type() {
        let type_map = HashMap::new();
        let ty = TypeRef::Array(Box::new(TypeRef::Named("bytes".into())));
        assert!(!return_type_has_content_bytes(&ty, &type_map));
    }
}
