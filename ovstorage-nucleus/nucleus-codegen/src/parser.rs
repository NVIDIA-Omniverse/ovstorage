// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Result, bail};
use oxc_allocator::Allocator;
use oxc_ast::ast::*;
use oxc_parser::{ParseOptions, Parser};
use oxc_span::SourceType;

use crate::ast::*;

pub fn parse(source: &str) -> Result<IdlFile> {
    tracing::trace!(len = source.len(), "parsing");
    let allocator = Allocator::default();
    let source_type = SourceType::ts();
    let parser_return = Parser::new(&allocator, source, source_type)
        .with_options(ParseOptions::default())
        .parse();

    if !parser_return.errors.is_empty() {
        let errors: Vec<String> = parser_return.errors.iter().map(|e| e.to_string()).collect();
        let err_str = errors.join("; ");
        tracing::error!(errors = %err_str, "parse errors");
        bail!("parse errors: {}", err_str);
    }

    let program = &parser_return.program;
    let mut items = Vec::new();

    for stmt in &program.body {
        match stmt {
            Statement::TSInterfaceDeclaration(decl) => {
                items.push(Item::Interface(convert_interface(decl, source)?));
            }
            Statement::TSTypeAliasDeclaration(decl) => {
                if let Some(item) = convert_type_alias(decl)? {
                    items.push(Item::TypeAlias(item));
                }
            }
            Statement::TSEnumDeclaration(decl) => {
                items.push(Item::Enum(convert_enum(decl)?));
            }
            Statement::ImportDeclaration(decl) => {
                items.push(Item::Import(convert_import(decl)?));
            }
            Statement::ExportNamedDeclaration(export) => {
                if let Some(ref inner) = export.declaration {
                    match inner {
                        Declaration::TSInterfaceDeclaration(decl) => {
                            let iface = convert_interface(decl, source)?;
                            tracing::debug!(name = %iface.name, n = iface.methods.len(), "interface with methods");
                            items.push(Item::Interface(iface));
                        }
                        Declaration::TSTypeAliasDeclaration(decl) => {
                            if let Some(item) = convert_type_alias(decl)? {
                                let name = match &item {
                                    crate::ast::TypeAlias::Struct(s) => &s.name,
                                    crate::ast::TypeAlias::Alias(a) => &a.name,
                                    crate::ast::TypeAlias::Union(u) => &u.name,
                                    crate::ast::TypeAlias::Literal(l) => &l.name,
                                    crate::ast::TypeAlias::IndexMap(m) => &m.name,
                                };
                                tracing::debug!(name = %name, "type alias");
                                items.push(Item::TypeAlias(item));
                            }
                        }
                        Declaration::TSEnumDeclaration(decl) => {
                            let e = convert_enum(decl)?;
                            tracing::debug!(name = %e.name, "enum");
                            items.push(Item::Enum(e));
                        }
                        _ => {
                            tracing::trace!("skipped statement");
                        }
                    }
                }
            }
            _ => {
                tracing::trace!("skipped statement");
            }
        }
    }

    Ok(IdlFile { items })
}

fn convert_interface(decl: &TSInterfaceDeclaration, source: &str) -> Result<Interface> {
    let name = decl.id.name.to_string();
    let mut methods = Vec::new();

    for sig in &decl.body.body {
        if let TSSignature::TSMethodSignature(method) = sig {
            let method_name = match &method.key {
                PropertyKey::StaticIdentifier(id) => id.name.to_string(),
                _ => {
                    tracing::warn!(interface = %name, "skipping method with non-identifier key");
                    continue;
                }
            };

            let mut params = Vec::new();
            for param in &method.params.items {
                let param_name = match &param.pattern {
                    BindingPattern::BindingIdentifier(id) => id.name.to_string(),
                    _ => {
                        tracing::warn!(interface = %name, method = %method_name, "skipping param with non-identifier pattern");
                        continue;
                    }
                };
                let ty = param
                    .type_annotation
                    .as_ref()
                    .map(|ann| convert_ts_type(&ann.type_annotation))
                    .unwrap_or(TypeRef::Named("unknown".into()));
                params.push(Param {
                    name: param_name,
                    ty,
                    optional: param.optional,
                });
            }

            let (return_type, is_streaming) = if let Some(ref ret_ann) = method.return_type {
                let ty = &ret_ann.type_annotation;
                match ty {
                    TSType::TSArrayType(arr) => (convert_ts_type(&arr.element_type), true),
                    _ => (convert_ts_type(ty), false),
                }
            } else {
                (TypeRef::Named("void".into()), false)
            };

            let (version, deprecated, doc_comment) = extract_jsdoc(method.span, source);

            methods.push(Method {
                name: method_name,
                params,
                return_type,
                is_streaming,
                version,
                deprecated,
                doc_comment,
            });
        }
    }

    Ok(Interface { name, methods })
}

fn extract_jsdoc(span: oxc_span::Span, source: &str) -> (Option<u32>, bool, Option<String>) {
    let before = &source[..span.start as usize];
    let trimmed = before.trim_end();

    if !trimmed.ends_with("*/") {
        return (None, false, None);
    }

    let comment_start = match trimmed.rfind("/*") {
        Some(pos) => pos,
        None => return (None, false, None),
    };

    // Only JSDoc `/** ... */`, skip plain `/* ... */`.
    if !trimmed[comment_start..].starts_with("/**") {
        return (None, false, None);
    }

    let comment_block = &trimmed[comment_start + 3..trimmed.len() - 2];
    let mut version = None;
    let mut deprecated = false;
    let mut doc_lines = Vec::new();

    for line in comment_block.lines() {
        let line = line.trim().trim_start_matches('*').trim();
        if line.starts_with("@version") {
            if let Some(v) = line
                .strip_prefix("@version")
                .and_then(|s| s.trim().parse::<u32>().ok())
            {
                version = Some(v);
            }
        } else if line.starts_with("@deprecated") {
            deprecated = true;
        } else if line.starts_with("@param") || line.starts_with("@returns") {
            // Redundant with Rust signature.
        } else if !line.is_empty() {
            doc_lines.push(line.to_string());
        }
    }

    let doc = if doc_lines.is_empty() {
        None
    } else {
        Some(doc_lines.join("\n"))
    };

    (version, deprecated, doc)
}

fn convert_type_alias(decl: &TSTypeAliasDeclaration) -> Result<Option<TypeAlias>> {
    let name = decl.id.name.to_string();
    let ty = &decl.type_annotation;

    match ty {
        TSType::TSTypeLiteral(lit) => {
            if let Some(index_map) = try_convert_index_map(&name, lit) {
                return Ok(Some(index_map));
            }

            let mut fields = Vec::new();
            for member in &lit.members {
                if let TSSignature::TSPropertySignature(prop) = member {
                    let field_name = match &prop.key {
                        PropertyKey::StaticIdentifier(id) => id.name.to_string(),
                        _ => {
                            tracing::warn!(struct_name = %name, "skipping struct property with non-identifier key");
                            continue;
                        }
                    };
                    let field_ty = prop
                        .type_annotation
                        .as_ref()
                        .map(|ann| convert_ts_type(&ann.type_annotation))
                        .unwrap_or(TypeRef::Named("unknown".into()));
                    fields.push(Field {
                        name: field_name,
                        ty: field_ty,
                        optional: prop.optional,
                    });
                }
            }
            Ok(Some(TypeAlias::Struct(StructDef {
                name,
                fields,
                extends: vec![],
            })))
        }
        TSType::TSUnionType(union) => {
            let variants: Vec<TypeRef> = union.types.iter().map(|t| convert_ts_type(t)).collect();
            Ok(Some(TypeAlias::Union(UnionDef { name, variants })))
        }
        TSType::TSIntersectionType(inter) => {
            let mut fields = Vec::new();
            let mut extends = Vec::new();
            for ty in &inter.types {
                match ty {
                    TSType::TSTypeReference(r) => {
                        extends.push(type_name_from_ref(r));
                    }
                    TSType::TSTypeLiteral(lit) => {
                        for member in &lit.members {
                            if let TSSignature::TSPropertySignature(prop) = member {
                                let field_name = match &prop.key {
                                    PropertyKey::StaticIdentifier(id) => id.name.to_string(),
                                    _ => {
                                        tracing::warn!(struct_name = %name, "skipping intersection property with non-identifier key");
                                        continue;
                                    }
                                };
                                let field_ty = prop
                                    .type_annotation
                                    .as_ref()
                                    .map(|ann| convert_ts_type(&ann.type_annotation))
                                    .unwrap_or(TypeRef::Named("unknown".into()));
                                fields.push(Field {
                                    name: field_name,
                                    ty: field_ty,
                                    optional: prop.optional,
                                });
                            }
                        }
                    }
                    _ => {
                        tracing::warn!(struct_name = %name, "skipping unsupported intersection member type");
                    }
                }
            }
            Ok(Some(TypeAlias::Struct(StructDef {
                name,
                fields,
                extends,
            })))
        }
        TSType::TSLiteralType(lit) => {
            let value = match &lit.literal {
                TSLiteral::StringLiteral(s) => LiteralValue::String(s.value.to_string()),
                TSLiteral::NumericLiteral(n) => LiteralValue::Number(n.value),
                _ => return Ok(None),
            };
            Ok(Some(TypeAlias::Literal(LiteralDef { name, value })))
        }
        TSType::TSTypeReference(_) | TSType::TSArrayType(_) => {
            let target = convert_ts_type(ty);
            Ok(Some(TypeAlias::Alias(AliasDef { name, target })))
        }
        _ => {
            let target = convert_ts_type(ty);
            Ok(Some(TypeAlias::Alias(AliasDef { name, target })))
        }
    }
}

fn try_convert_index_map(name: &str, lit: &TSTypeLiteral) -> Option<TypeAlias> {
    if lit.members.len() == 1
        && let TSSignature::TSIndexSignature(idx) = &lit.members[0]
    {
        let key_type = idx
            .parameters
            .first()
            .map(|p| convert_ts_type(&p.type_annotation.type_annotation))
            .unwrap_or(TypeRef::Named("String".into()));
        let value_type = convert_ts_type(&idx.type_annotation.type_annotation);
        return Some(TypeAlias::IndexMap(IndexMapDef {
            name: name.to_string(),
            key_type,
            value_type,
        }));
    }
    None
}

fn convert_enum(decl: &TSEnumDeclaration) -> Result<Enum> {
    let name = decl.id.name.to_string();
    let mut variants = Vec::new();

    for member in &decl.body.members {
        let variant_name = match &member.id {
            TSEnumMemberName::Identifier(id) => id.name.to_string(),
            TSEnumMemberName::String(s) => s.value.to_string(),
            _ => continue,
        };
        let value = match &member.initializer {
            Some(expr) => match expr {
                Expression::StringLiteral(s) => EnumValue::String(s.value.to_string()),
                Expression::NumericLiteral(n) => EnumValue::Integer(n.value as i64),
                Expression::UnaryExpression(u) => {
                    if let Expression::NumericLiteral(n) = &u.argument {
                        EnumValue::Integer(-(n.value as i64))
                    } else {
                        EnumValue::Auto
                    }
                }
                _ => EnumValue::Auto,
            },
            None => EnumValue::Auto,
        };
        variants.push(EnumVariant {
            name: variant_name,
            value,
        });
    }

    Ok(Enum { name, variants })
}

fn convert_import(decl: &ImportDeclaration) -> Result<Import> {
    let from = decl.source.value.to_string();
    let mut items = Vec::new();

    if let Some(specifiers) = &decl.specifiers {
        for spec in specifiers {
            match spec {
                ImportDeclarationSpecifier::ImportSpecifier(s) => {
                    items.push(s.local.name.to_string());
                }
                ImportDeclarationSpecifier::ImportDefaultSpecifier(s) => {
                    items.push(s.local.name.to_string());
                }
                ImportDeclarationSpecifier::ImportNamespaceSpecifier(s) => {
                    items.push(s.local.name.to_string());
                }
            }
        }
    }

    Ok(Import { items, from })
}

fn convert_ts_type(ty: &TSType) -> TypeRef {
    match ty {
        TSType::TSTypeReference(r) => {
            let name = type_name_from_ref(r);
            if let Some(type_args) = &r.type_arguments {
                let params: Vec<TypeRef> = type_args
                    .params
                    .iter()
                    .map(|t| convert_ts_type(t))
                    .collect();
                TypeRef::Generic(name, params)
            } else {
                TypeRef::Named(name)
            }
        }
        TSType::TSArrayType(arr) => TypeRef::Array(Box::new(convert_ts_type(&arr.element_type))),
        TSType::TSStringKeyword(_) => TypeRef::Named("string".into()),
        TSType::TSNumberKeyword(_) => TypeRef::Named("number".into()),
        TSType::TSBooleanKeyword(_) => TypeRef::Named("boolean".into()),
        TSType::TSVoidKeyword(_) => TypeRef::Named("void".into()),
        TSType::TSAnyKeyword(_) => TypeRef::Named("any".into()),
        TSType::TSLiteralType(lit) => match &lit.literal {
            TSLiteral::StringLiteral(s) => TypeRef::Named(format!("\"{}\"", s.value)),
            TSLiteral::NumericLiteral(_) => TypeRef::Named("number".into()),
            TSLiteral::BooleanLiteral(_) => TypeRef::Named("boolean".into()),
            _ => {
                tracing::warn!("unknown TS literal type, mapping to serde_json::Value");
                TypeRef::Named("unknown".into())
            }
        },
        _ => {
            tracing::warn!("unknown TS type, mapping to serde_json::Value");
            TypeRef::Named("unknown".into())
        }
    }
}

fn type_name_from_ref(r: &TSTypeReference) -> String {
    type_name_from_ts_name(&r.type_name)
}

fn type_name_from_ts_name(name: &TSTypeName) -> String {
    match name {
        TSTypeName::IdentifierReference(id) => id.name.to_string(),
        TSTypeName::QualifiedName(q) => {
            format!("{}.{}", type_name_from_ts_name(&q.left), q.right.name)
        }
        _ => "unknown".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_struct() {
        let src = r#"type Foo = { bar: string; baz?: uint64; }"#;
        let result = parse(src).unwrap();
        assert_eq!(result.items.len(), 1);
        if let Item::TypeAlias(TypeAlias::Struct(s)) = &result.items[0] {
            assert_eq!(s.name, "Foo");
            assert_eq!(s.fields.len(), 2);
            assert_eq!(s.fields[0].name, "bar");
            assert!(!s.fields[0].optional);
            assert_eq!(s.fields[1].name, "baz");
            assert!(s.fields[1].optional);
        } else {
            panic!("expected struct");
        }
    }

    #[test]
    fn parse_enum() {
        let src = r#"enum Status { OK = "OK", Error = "ERROR" }"#;
        let result = parse(src).unwrap();
        assert_eq!(result.items.len(), 1);
        if let Item::Enum(e) = &result.items[0] {
            assert_eq!(e.name, "Status");
            assert_eq!(e.variants.len(), 2);
            assert_eq!(e.variants[0].name, "OK");
        } else {
            panic!("expected enum");
        }
    }

    #[test]
    fn parse_interface_with_methods() {
        let src = r#"
            interface Svc {
                ping(): Response;
                list(path: string): Item[];
            }
        "#;
        let result = parse(src).unwrap();
        assert_eq!(result.items.len(), 1);
        if let Item::Interface(iface) = &result.items[0] {
            assert_eq!(iface.name, "Svc");
            assert_eq!(iface.methods.len(), 2);
            assert_eq!(iface.methods[0].name, "ping");
            assert!(!iface.methods[0].is_streaming);
            assert_eq!(iface.methods[1].name, "list");
            assert!(iface.methods[1].is_streaming);
        } else {
            panic!("expected interface");
        }
    }

    #[test]
    fn parse_jsdoc_annotations() {
        let src = r#"
            interface Svc {
                /**
                 * Does something cool.
                 * @version 2
                 * @deprecated
                 */
                doThing(x: string): Result;
            }
        "#;
        let result = parse(src).unwrap();
        if let Item::Interface(iface) = &result.items[0] {
            let m = &iface.methods[0];
            assert_eq!(m.version, Some(2));
            assert!(m.deprecated);
            assert!(m.doc_comment.as_ref().unwrap().contains("cool"));
        } else {
            panic!("expected interface");
        }
    }

    #[test]
    fn parse_index_signature() {
        let src = r#"type ACL = { [user: string]: string[]; }"#;
        let result = parse(src).unwrap();
        if let Item::TypeAlias(TypeAlias::IndexMap(m)) = &result.items[0] {
            assert_eq!(m.name, "ACL");
        } else {
            panic!("expected index map, got: {:?}", result.items[0]);
        }
    }

    #[test]
    fn parse_literal_type() {
        let src = r#"type Version = "1.19""#;
        let result = parse(src).unwrap();
        if let Item::TypeAlias(TypeAlias::Literal(l)) = &result.items[0] {
            assert_eq!(l.name, "Version");
            if let LiteralValue::String(s) = &l.value {
                assert_eq!(s, "1.19");
            } else {
                panic!("expected string literal");
            }
        } else {
            panic!("expected literal, got: {:?}", result.items[0]);
        }
    }

    #[test]
    fn parse_type_alias() {
        let src = r#"type JSONString = string"#;
        let result = parse(src).unwrap();
        if let Item::TypeAlias(TypeAlias::Alias(a)) = &result.items[0] {
            assert_eq!(a.name, "JSONString");
        } else {
            panic!("expected alias, got: {:?}", result.items[0]);
        }
    }

    #[test]
    fn parse_optional_method_params() {
        let src = r#"
            interface Svc {
                doThing(required: string, opt1?: uint64, opt2?: boolean): Result;
            }
        "#;
        let result = parse(src).unwrap();
        if let Item::Interface(iface) = &result.items[0] {
            let m = &iface.methods[0];
            assert_eq!(m.params.len(), 3);
            assert!(!m.params[0].optional);
            assert!(m.params[1].optional);
            assert!(m.params[2].optional);
        } else {
            panic!("expected interface");
        }
    }

    #[test]
    fn parse_streaming_return() {
        let src = r#"
            interface Svc {
                subscribe(): Event[];
                single(): Event;
            }
        "#;
        let result = parse(src).unwrap();
        if let Item::Interface(iface) = &result.items[0] {
            assert!(iface.methods[0].is_streaming);
            assert!(!iface.methods[1].is_streaming);
        } else {
            panic!("expected interface");
        }
    }

    #[test]
    fn parse_union_type() {
        let src = r#"type Auth = string | uint64"#;
        let result = parse(src).unwrap();
        if let Item::TypeAlias(TypeAlias::Union(u)) = &result.items[0] {
            assert_eq!(u.name, "Auth");
            assert_eq!(u.variants.len(), 2);
        } else {
            panic!("expected union, got: {:?}", result.items[0]);
        }
    }

    #[test]
    fn parse_intersection_type() {
        let src = r#"type Extended = Base & { extra: string; }"#;
        let result = parse(src).unwrap();
        if let Item::TypeAlias(TypeAlias::Struct(s)) = &result.items[0] {
            assert_eq!(s.name, "Extended");
            assert_eq!(s.extends, vec!["Base"]);
            assert_eq!(s.fields.len(), 1);
            assert_eq!(s.fields[0].name, "extra");
        } else {
            panic!("expected struct with extends, got: {:?}", result.items[0]);
        }
    }

    #[test]
    fn parse_number_literal_type() {
        let src = r#"type Port = 3009"#;
        let result = parse(src).unwrap();
        if let Item::TypeAlias(TypeAlias::Literal(l)) = &result.items[0] {
            assert_eq!(l.name, "Port");
            if let LiteralValue::Number(n) = l.value {
                assert!((n - 3009.0).abs() < f64::EPSILON);
            } else {
                panic!("expected number literal");
            }
        } else {
            panic!("expected literal, got: {:?}", result.items[0]);
        }
    }

    #[test]
    fn parse_import() {
        let src = r#"import { Foo, Bar } from "@some/package""#;
        let result = parse(src).unwrap();
        if let Item::Import(import) = &result.items[0] {
            assert_eq!(import.items, vec!["Foo", "Bar"]);
            assert_eq!(import.from, "@some/package");
        } else {
            panic!("expected import, got: {:?}", result.items[0]);
        }
    }

    #[test]
    fn parse_export_keyword() {
        let src = r#"export type Foo = { x: string; }"#;
        let result = parse(src).unwrap();
        assert_eq!(result.items.len(), 1);
        if let Item::TypeAlias(TypeAlias::Struct(s)) = &result.items[0] {
            assert_eq!(s.name, "Foo");
        } else {
            panic!("expected struct, got: {:?}", result.items[0]);
        }
    }

    #[test]
    fn parse_multiple_interfaces() {
        let src = r#"
            interface A { ping(): Result; }
            interface B { pong(): Result; }
        "#;
        let result = parse(src).unwrap();
        let interface_count = result
            .items
            .iter()
            .filter(|i| matches!(i, Item::Interface(_)))
            .count();
        assert_eq!(interface_count, 2);
    }

    #[test]
    fn parse_generic_type_in_params() {
        let src = r#"
            interface Svc {
                auth(version: string, client_capabilities?: SomeType): Response;
            }
        "#;
        let result = parse(src).unwrap();
        if let Item::Interface(iface) = &result.items[0] {
            assert_eq!(iface.methods[0].params.len(), 2);
            assert_eq!(iface.methods[0].params[1].name, "client_capabilities");
            assert!(iface.methods[0].params[1].optional);
        } else {
            panic!("expected interface");
        }
    }

    #[test]
    fn parse_array_type_field() {
        let src = r#"type Foo = { items: string[]; }"#;
        let result = parse(src).unwrap();
        if let Item::TypeAlias(TypeAlias::Struct(s)) = &result.items[0] {
            assert!(matches!(&s.fields[0].ty, TypeRef::Array(_)));
        } else {
            panic!("expected struct");
        }
    }

    #[test]
    fn parse_emoji_in_jsdoc() {
        let src = r#"
            interface Svc {
                /** 📁 Path **/
                /**
                 * Stat a path
                 * @version 2
                 **/
                stat2(path: string): Result;
            }
        "#;
        let result = parse(src).unwrap();
        if let Item::Interface(iface) = &result.items[0] {
            assert_eq!(iface.methods[0].name, "stat2");
            assert_eq!(iface.methods[0].version, Some(2));
        } else {
            panic!("expected interface");
        }
    }

    #[test]
    fn parse_enum_with_negative_value() {
        let src = r#"enum Signed { Neg = -1, Zero = 0, Pos = 1 }"#;
        let result = parse(src).unwrap();
        if let Item::Enum(e) = &result.items[0] {
            assert_eq!(e.variants.len(), 3);
            assert!(matches!(e.variants[0].value, EnumValue::Integer(-1)));
            assert!(matches!(e.variants[1].value, EnumValue::Integer(0)));
            assert!(matches!(e.variants[2].value, EnumValue::Integer(1)));
        } else {
            panic!("expected enum");
        }
    }

    #[test]
    fn parse_enum_with_auto_values() {
        let src = r#"enum Color { Red, Green, Blue }"#;
        let result = parse(src).unwrap();
        if let Item::Enum(e) = &result.items[0] {
            assert_eq!(e.variants.len(), 3);
            assert!(matches!(e.variants[0].value, EnumValue::Auto));
        } else {
            panic!("expected enum");
        }
    }

    #[test]
    fn parse_void_return_type() {
        let src = r#"
            interface Svc {
                fire(): void;
            }
        "#;
        let result = parse(src).unwrap();
        if let Item::Interface(iface) = &result.items[0] {
            assert!(matches!(&iface.methods[0].return_type, TypeRef::Named(n) if n == "void"));
        } else {
            panic!("expected interface");
        }
    }

    #[test]
    fn parse_no_return_annotation_defaults_to_void() {
        let src = r#"
            interface Svc {
                fire();
            }
        "#;
        let result = parse(src).unwrap();
        if let Item::Interface(iface) = &result.items[0] {
            assert!(matches!(&iface.methods[0].return_type, TypeRef::Named(n) if n == "void"));
        } else {
            panic!("expected interface");
        }
    }

    #[test]
    fn parse_exported_interface() {
        let src = r#"export interface Svc { ping(): Result; }"#;
        let result = parse(src).unwrap();
        assert_eq!(result.items.len(), 1);
        if let Item::Interface(iface) = &result.items[0] {
            assert_eq!(iface.name, "Svc");
        } else {
            panic!("expected interface");
        }
    }

    #[test]
    fn parse_exported_enum() {
        let src = r#"export enum Dir { Up = "UP", Down = "DOWN" }"#;
        let result = parse(src).unwrap();
        assert_eq!(result.items.len(), 1);
        if let Item::Enum(e) = &result.items[0] {
            assert_eq!(e.name, "Dir");
        } else {
            panic!("expected enum");
        }
    }

    #[test]
    fn parse_jsdoc_version_only() {
        let src = r#"
            interface Svc {
                /** @version 5 */
                method(): Result;
            }
        "#;
        let result = parse(src).unwrap();
        if let Item::Interface(iface) = &result.items[0] {
            assert_eq!(iface.methods[0].version, Some(5));
            assert!(!iface.methods[0].deprecated);
            assert!(iface.methods[0].doc_comment.is_none());
        } else {
            panic!("expected interface");
        }
    }

    #[test]
    fn parse_jsdoc_deprecated_only() {
        let src = r#"
            interface Svc {
                /** @deprecated */
                method(): Result;
            }
        "#;
        let result = parse(src).unwrap();
        if let Item::Interface(iface) = &result.items[0] {
            assert!(iface.methods[0].deprecated);
            assert_eq!(iface.methods[0].version, None);
        } else {
            panic!("expected interface");
        }
    }

    #[test]
    fn parse_method_without_jsdoc() {
        let src = r#"
            interface Svc {
                method(): Result;
            }
        "#;
        let result = parse(src).unwrap();
        if let Item::Interface(iface) = &result.items[0] {
            assert_eq!(iface.methods[0].version, None);
            assert!(!iface.methods[0].deprecated);
            assert!(iface.methods[0].doc_comment.is_none());
        } else {
            panic!("expected interface");
        }
    }

    #[test]
    fn parse_generic_type_reference() {
        let src = r#"type Foo = { items: Map<string, uint64>; }"#;
        let result = parse(src).unwrap();
        if let Item::TypeAlias(TypeAlias::Struct(s)) = &result.items[0] {
            assert!(
                matches!(&s.fields[0].ty, TypeRef::Generic(name, args) if name == "Map" && args.len() == 2)
            );
        } else {
            panic!("expected struct");
        }
    }

    #[test]
    fn parse_empty_interface() {
        let src = r#"interface Empty {}"#;
        let result = parse(src).unwrap();
        if let Item::Interface(iface) = &result.items[0] {
            assert_eq!(iface.name, "Empty");
            assert!(iface.methods.is_empty());
        } else {
            panic!("expected interface");
        }
    }

    #[test]
    fn parse_mixed_items() {
        let src = r#"
            import { Foo } from "@pkg"
            type Bar = { x: string; }
            enum Baz { A = "A" }
            interface Svc { ping(): Bar; }
        "#;
        let result = parse(src).unwrap();
        assert_eq!(result.items.len(), 4);
        assert!(matches!(&result.items[0], Item::Import(_)));
        assert!(matches!(&result.items[1], Item::TypeAlias(_)));
        assert!(matches!(&result.items[2], Item::Enum(_)));
        assert!(matches!(&result.items[3], Item::Interface(_)));
    }

    #[test]
    fn parse_invalid_syntax_returns_err() {
        let result = parse("type Foo = { bar: ");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("parse errors"),
            "expected 'parse errors' in: {msg}"
        );
    }

    #[test]
    fn parse_import_default_specifier() {
        let result = parse(r#"import Default from "pkg""#).unwrap();
        assert_eq!(result.items.len(), 1);
        if let Item::Import(import) = &result.items[0] {
            assert_eq!(import.items, vec!["Default"]);
            assert_eq!(import.from, "pkg");
        } else {
            panic!("expected import, got: {:?}", result.items[0]);
        }
    }

    #[test]
    fn parse_import_namespace_specifier() {
        let result = parse(r#"import * as ns from "pkg""#).unwrap();
        assert_eq!(result.items.len(), 1);
        if let Item::Import(import) = &result.items[0] {
            assert_eq!(import.items, vec!["ns"]);
        } else {
            panic!("expected import, got: {:?}", result.items[0]);
        }
    }

    #[test]
    fn parse_import_side_effect() {
        let result = parse(r#"import "side-effect""#).unwrap();
        assert_eq!(result.items.len(), 1);
        if let Item::Import(import) = &result.items[0] {
            assert!(import.items.is_empty());
            assert_eq!(import.from, "side-effect");
        } else {
            panic!("expected import, got: {:?}", result.items[0]);
        }
    }
}
