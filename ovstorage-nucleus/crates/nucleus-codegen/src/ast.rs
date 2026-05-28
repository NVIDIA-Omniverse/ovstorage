// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#[derive(Debug, Clone)]
pub struct IdlFile {
    pub items: Vec<Item>,
}

#[derive(Debug, Clone)]
pub enum Item {
    Interface(Interface),
    TypeAlias(TypeAlias),
    Enum(Enum),
    Import(Import),
}

#[derive(Debug, Clone)]
pub struct Interface {
    pub name: String,
    pub methods: Vec<Method>,
}

#[derive(Debug, Clone)]
pub struct Method {
    pub name: String,
    pub params: Vec<Param>,
    pub return_type: TypeRef,
    pub is_streaming: bool,
    pub version: Option<u32>,
    pub deprecated: bool,
    pub doc_comment: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Param {
    pub name: String,
    pub ty: TypeRef,
    pub optional: bool,
}

#[derive(Debug, Clone)]
pub enum TypeAlias {
    Struct(StructDef),
    IndexMap(IndexMapDef),
    Alias(AliasDef),
    Union(UnionDef),
    Literal(LiteralDef),
}

#[derive(Debug, Clone)]
pub struct StructDef {
    pub name: String,
    pub fields: Vec<Field>,
    pub extends: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Field {
    pub name: String,
    pub ty: TypeRef,
    pub optional: bool,
}

#[derive(Debug, Clone)]
pub struct IndexMapDef {
    pub name: String,
    pub key_type: TypeRef,
    pub value_type: TypeRef,
}

#[derive(Debug, Clone)]
pub struct AliasDef {
    pub name: String,
    pub target: TypeRef,
}

#[derive(Debug, Clone)]
pub struct UnionDef {
    pub name: String,
    pub variants: Vec<TypeRef>,
}

#[derive(Debug, Clone)]
pub struct LiteralDef {
    pub name: String,
    pub value: LiteralValue,
}

#[derive(Debug, Clone)]
pub enum LiteralValue {
    String(String),
    Number(f64),
}

#[derive(Debug, Clone)]
pub struct Enum {
    pub name: String,
    pub variants: Vec<EnumVariant>,
}

#[derive(Debug, Clone)]
pub struct EnumVariant {
    pub name: String,
    pub value: EnumValue,
}

#[derive(Debug, Clone)]
pub enum EnumValue {
    String(String),
    Integer(i64),
    Auto,
}

#[derive(Debug, Clone)]
pub struct Import {
    pub items: Vec<String>,
    pub from: String,
}

#[derive(Debug, Clone)]
pub enum TypeRef {
    Named(String),
    Array(Box<TypeRef>),
    Generic(String, Vec<TypeRef>),
}
