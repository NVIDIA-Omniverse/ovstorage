// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use nucleus_codegen::generate_from_str;

fn assert_compiles(src: &str) -> String {
    let out = generate_from_str(src).unwrap();
    syn::parse_str::<syn::File>(&out)
        .unwrap_or_else(|e| panic!("generated code failed to parse:\n{out}\nerror: {e}"));
    out
}

// --- Struct generation ---

#[test]
fn test_generate_simple_struct() {
    let input = r#"type Foo = { bar: string; baz?: uint64; }"#;
    let output = generate_from_str(input).unwrap();
    assert!(output.contains("struct Foo"));
    assert!(output.contains("bar"));
    assert!(output.contains("Option"));
}

#[test]
fn test_struct_with_all_primitive_types() {
    let input = r#"type AllTypes = {
        a: string;
        b: boolean;
        c: uint8;
        d: uint16;
        e: uint32;
        f: uint64;
        g: int8;
        h: int16;
        i: int32;
        j: int64;
        k: float;
        l: double;
        m: bytes;
    }"#;
    let output = generate_from_str(input).unwrap();
    assert!(output.contains("struct AllTypes"));
    assert!(output.contains("String"));
    assert!(output.contains("bool"));
    assert!(output.contains("u8"));
    assert!(output.contains("u16"));
    assert!(output.contains("u32"));
    assert!(output.contains("u64"));
    assert!(output.contains("i8"));
    assert!(output.contains("i16"));
    assert!(output.contains("i32"));
    assert!(output.contains("i64"));
    assert!(output.contains("f32"));
    assert!(output.contains("f64"));
    assert!(output.contains("Vec<u8>"));
}

#[test]
fn test_struct_with_array_field() {
    let input = r#"type Items = { entries: Item[]; }"#;
    let output = generate_from_str(input).unwrap();
    assert!(output.contains("Vec<"));
}

#[test]
fn test_struct_with_nested_type_ref() {
    let input = r#"
    type Inner = { x: uint32; }
    type Outer = { inner: Inner; opt_inner?: Inner; }
    "#;
    let output = generate_from_str(input).unwrap();
    assert!(output.contains("struct Inner"));
    assert!(output.contains("struct Outer"));
    assert!(output.contains("inner: Inner"));
    assert!(output.contains("Option<Inner>"));
}

#[test]
fn test_struct_optional_fields_have_skip_serializing() {
    let input = r#"type Foo = { required: string; optional?: uint64; }"#;
    let output = generate_from_str(input).unwrap();
    assert!(output.contains("skip_serializing_if"));
}

#[test]
fn test_struct_reserved_field_name() {
    let input = r#"type Foo = { type: string; }"#;
    let output = generate_from_str(input).unwrap();
    assert!(output.contains("r#type"));
}

// --- Enum generation ---

#[test]
fn test_generate_string_enum() {
    let input = r#"enum Status { OK = "OK", Error = "ERROR" }"#;
    let output = generate_from_str(input).unwrap();
    assert!(output.contains("enum Status"));
    assert!(output.contains("OK"));
    assert!(output.contains("Error"));
    assert!(output.contains("serde"));
}

#[test]
fn test_generate_integer_enum() {
    let input = r#"enum Code { Any = 0, Asset = 1, Folder = 2 }"#;
    let output = generate_from_str(input).unwrap();
    assert!(output.contains("enum Code"));
    assert!(output.contains("Any"));
    assert!(output.contains("Asset"));
    assert!(output.contains("Folder"));
}

#[test]
fn test_enum_with_many_string_variants() {
    let input = r#"
    enum StatusType {
        OK = "OK",
        Done = "DONE",
        Idle = "IDLE",
        Denied = "DENIED",
        Latest = "LATEST",
        InvalidCommand = "INVALID_COMMAND",
        InvalidPath = "INVALID_URI",
        Unauthenticated = "UNAUTHENTICATED"
    }
    "#;
    let output = generate_from_str(input).unwrap();
    assert!(output.contains("enum StatusType"));
    assert!(output.contains("OK"));
    assert!(output.contains("DONE"));
    assert!(output.contains("DENIED"));
    assert!(output.contains("rename"));
}

// --- Type aliases ---

#[test]
fn test_type_alias_to_builtin() {
    let input = r#"type JSONString = string"#;
    let output = generate_from_str(input).unwrap();
    assert!(output.contains("JSONString"));
    assert!(output.contains("String"));
}

#[test]
fn test_type_alias_to_another_type() {
    let input = r#"
    type StringPair = { key: string; value: string; }
    type SourceDestinationPair = StringPair
    "#;
    let output = generate_from_str(input).unwrap();
    assert!(output.contains("struct StringPair"));
    assert!(output.contains("SourceDestinationPair"));
}

#[test]
fn test_literal_string_type() {
    let input = r#"type Version = "1.19""#;
    let output = generate_from_str(input).unwrap();
    assert!(output.contains("pub type Version = String"));
    assert!(output.contains(r#"pub const VERSION: &str = "1.19""#));
}

#[test]
fn test_literal_number_type() {
    let input = r#"type DefaultPort = 3009"#;
    let output = generate_from_str(input).unwrap();
    assert!(output.contains("pub type DefaultPort = f64"));
    assert!(output.contains("pub const DEFAULT_PORT: f64 = 3009"));
}

#[test]
fn test_empty_string_literal_type() {
    let input = r#"type FullUpdateEtag = """#;
    let output = generate_from_str(input).unwrap();
    assert!(output.contains("FullUpdateEtag"));
}

// --- Index map ---

#[test]
fn test_generate_index_map() {
    let input = r#"type ACL = { [user: string]: string[]; }"#;
    let output = generate_from_str(input).unwrap();
    assert!(output.contains("HashMap"));
}

#[test]
fn test_index_map_with_uint64_value() {
    let input = r#"type Timestamps = { [key: string]: uint64; }"#;
    let output = generate_from_str(input).unwrap();
    assert!(output.contains("HashMap"));
    assert!(output.contains("u64"));
}

// --- Union types ---

#[test]
fn test_union_type() {
    let input = r#"type AuthMethod = string | uint64"#;
    let output = generate_from_str(input).unwrap();
    assert!(output.contains("AuthMethod"));
}

// --- Intersection types (extends) ---

#[test]
fn test_intersection_type() {
    let input = r#"
    type Base = { status: string; }
    type Extended = Base & { extra: uint64; }
    "#;
    let output = generate_from_str(input).unwrap();
    assert!(output.contains("struct Base"));
    assert!(output.contains("struct Extended"));
    assert!(output.contains("extra"));
}

// --- Interface / trait generation ---

#[test]
fn test_interface_generates_trait() {
    let input = r#"
    interface MyService {
        ping(): Response;
        list(path: string): Item[];
    }
    type Response = { status: string; }
    type Item = { name: string; }
    "#;
    let output = generate_from_str(input).unwrap();
    assert!(output.contains("trait MyService"));
    assert!(output.contains("async fn ping"));
    assert!(output.contains("async fn list"));
    assert!(output.contains("struct Response"));
    assert!(output.contains("struct Item"));
}

#[test]
fn test_interface_streaming_return_type() {
    let input = r#"
    interface Svc {
        subscribe(): Event[];
    }
    type Event = { kind: string; }
    "#;
    let output = generate_from_str(input).unwrap();
    assert!(output.contains("nucleus_transport::Subscription"));
}

#[test]
fn test_interface_optional_params() {
    let input = r#"
    interface Svc {
        doThing(required: string, optional?: uint64): Response;
    }
    type Response = { status: string; }
    "#;
    let output = generate_from_str(input).unwrap();
    assert!(output.contains("required: String"));
    assert!(output.contains("Option<u64>"));
}

#[test]
fn test_interface_deprecated_method_skipped() {
    let input = r#"
    interface Svc {
        /** @deprecated */
        oldMethod(): Response;
        currentMethod(): Response;
    }
    type Response = { status: string; }
    "#;
    let output = generate_from_str(input).unwrap();
    assert!(!output.contains("old_method"));
    assert!(output.contains("current_method"));
}

#[test]
fn test_interface_versioned_method() {
    let input = r#"
    interface Svc {
        /** @version 3 */
        newMethod(): Response;
    }
    type Response = { status: string; }
    "#;
    let output = generate_from_str(input).unwrap();
    assert!(output.contains("new_method"));
}

#[test]
fn test_non_jsdoc_comment_does_not_leak_version() {
    let input = r#"
    interface Svc {
        /** @version 4 */
        versionedMethod(): Response;
        /* not jsdoc */
        plainMethod(): Response;
        undecorated(): Response;
    }
    type Response = { status: string; }
    "#;
    let output = generate_from_str(input).unwrap();
    // versionedMethod should have version 4 in the capabilities
    assert!(output.contains("\"versionedMethod\""));
    assert!(output.contains("4u64"));
    // plainMethod and undecorated should have version 0
    assert!(output.contains("\"plainMethod\""));
    assert!(output.contains("\"undecorated\""));
    // version 4 should appear exactly once (for versionedMethod only)
    assert_eq!(output.matches("4u64").count(), 1);
}

#[test]
fn test_interface_method_name_snake_case() {
    let input = r#"
    interface Svc {
        getCheckpoints(): Response;
        readAssetVersion(): Response;
        subscribeReadObject(): Response;
    }
    type Response = { status: string; }
    "#;
    let output = generate_from_str(input).unwrap();
    assert!(output.contains("get_checkpoints"));
    assert!(output.contains("read_asset_version"));
    assert!(output.contains("subscribe_read_object"));
}

// --- Import handling ---

#[test]
fn test_import_only_generates_no_types_or_interfaces() {
    let input = r#"import { Foo, Bar } from "@some/package""#;
    let output = generate_from_str(input).unwrap();
    assert!(
        !output.contains("struct "),
        "should not generate any structs"
    );
    assert!(!output.contains("enum "), "should not generate any enums");
    assert!(!output.contains("trait "), "should not generate any traits");
}

#[test]
fn test_capability_import_maps_to_hashmap() {
    let input = r#"
    import { ClientCapabilities, ServerCapabilities, Capabilities } from "@omniverse/idl/plugin/capabilities"

    type Auth = {
        server_capabilities?: ServerCapabilities;
    }
    "#;
    let output = generate_from_str(input).unwrap();
    assert!(output.contains("HashMap<String, u64>"));
}

#[test]
fn test_capability_generic_maps_to_hashmap() {
    let input = r#"
    import { ClientCapabilities, ServerCapabilities, Capabilities } from "@omniverse/idl/plugin/capabilities"

    interface Svc {
        auth(caps: ClientCapabilities): Response;
    }
    type Response = {
        server_caps: ServerCapabilities;
    }
    "#;
    let output = generate_from_str(input).unwrap();
    assert!(output.contains("HashMap<String, u64>"));
}

#[test]
fn test_non_capability_import_does_not_map() {
    let input = r#"
    import { SomeType } from "@some/other/package"

    type Foo = { bar: SomeType; }
    "#;
    let output = generate_from_str(input).unwrap();
    assert!(output.contains("SomeType"));
    assert!(!output.contains("HashMap < String , u64 >"));
}

// --- preprocess_source ---

#[test]
fn test_preprocess_multiline_type_gets_equals() {
    let input = "type Foo\n{ bar: string; }";
    let output = nucleus_codegen::preprocess_source(input);
    assert!(output.contains("type Foo ="));
}

#[test]
fn test_preprocess_already_has_equals() {
    let input = "type Foo = { bar: string; }\n";
    let output = nucleus_codegen::preprocess_source(input);
    assert_eq!(
        output.lines().next().unwrap(),
        "type Foo = { bar: string; }"
    );
}

// --- Empty enum ---

#[test]
fn test_empty_enum_generates_unit_type() {
    let input = r#"enum Empty {}"#;
    let output = generate_from_str(input).unwrap();
    assert!(output.contains("Empty"));
}

// --- Struct with camelCase field names ---

#[test]
fn test_struct_camel_case_field_renamed() {
    let input = r#"type Foo = { camelCase: string; }"#;
    let output = generate_from_str(input).unwrap();
    assert!(output.contains("camel_case"));
    assert!(output.contains("rename"));
    assert!(output.contains("camelCase"));
}

// --- Interface generates capabilities map ---

#[test]
fn test_interface_capabilities_map() {
    let input = r#"
    interface Svc {
        /** @version 3 */
        methodA(): Response;
        methodB(): Response;
    }
    type Response = { status: string; }
    "#;
    let output = generate_from_str(input).unwrap();
    assert!(output.contains("fn capabilities"));
    assert!(output.contains("\"methodA\""));
    assert!(output.contains("3u64"));
    assert!(output.contains("\"methodB\""));
    assert!(output.contains("0u64"));
}

// --- Interface generates ORIGIN and INTERFACE constants ---

#[test]
fn test_interface_constants_generated() {
    let input = r#"
    interface Svc {
        ping(): Response;
    }
    type Response = { status: string; }
    "#;
    let output = generate_from_str(input).unwrap();
    assert!(output.contains("ORIGIN"));
    assert!(output.contains("INTERFACE"));
    assert!(output.contains("\"Svc\""));
}

// --- Union with named type variants generates enum ---

#[test]
fn test_union_named_variants_generates_enum() {
    let input = r#"
    type A = { x: string; }
    type B = { y: uint32; }
    type Either = A | B
    "#;
    let output = generate_from_str(input).unwrap();
    assert!(output.contains("enum Either"));
    assert!(output.contains("untagged"));
}

// --- Method with bytes param ---

#[test]
fn test_interface_method_with_bytes_param() {
    let input = r#"
    interface Svc {
        upload(path: string, data: bytes): Response;
    }
    type Response = { status: string; }
    "#;
    let output = generate_from_str(input).unwrap();
    assert!(output.contains("async fn upload"));
    assert!(output.contains("Vec<u8>"));
}

// --- Version import maps to u64 ---

#[test]
fn test_version_import_maps_to_u64() {
    let input = r#"
    import { Version } from "@omniverse/idl/plugin/versions"

    interface Svc {
        auth(version: Version): Response;
    }
    type Response = { status: string; }
    "#;
    let output = generate_from_str(input).unwrap();
    assert!(output.contains("fn auth"));
    assert!(
        !output.contains("version: u64"),
        "version param should be filtered from trait signature"
    );
}

// --- Struct with multiple reserved words ---

#[test]
fn test_struct_multiple_reserved_fields() {
    let input = r#"type Foo = { type: string; ref: uint64; match: boolean; }"#;
    let output = generate_from_str(input).unwrap();
    assert!(output.contains("r#type"));
    assert!(output.contains("r#ref"));
    assert!(output.contains("r#match"));
}

#[test]
fn generate_from_file_success() {
    let dir = std::env::temp_dir().join("nucleus_codegen_test_gen_file");
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("test.idl.ts");
    std::fs::write(&path, "type Foo = { bar: string; }").unwrap();

    let output = nucleus_codegen::generate_from_file(&path).unwrap();
    assert!(output.contains("struct Foo"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn generate_from_file_not_found() {
    let path = std::path::PathBuf::from("/tmp/nucleus_codegen_nonexistent_file.idl.ts");
    let result = nucleus_codegen::generate_from_file(&path);
    assert!(result.is_err());
}

#[test]
fn test_interface_binary_response() {
    let input = r#"
    type ReadResponse = { content?: bytes; size: uint64; }
    interface Svc {
        read(path: string): ReadResponse;
    }
    "#;
    let output = generate_from_str(input).unwrap();
    assert!(output.contains("__resp.content = Some(__data)"));
}

#[test]
fn test_required_field_has_no_serde_default() {
    let input = r#"type Resp = { status: string; count: uint64; }"#;
    let output = assert_compiles(input);
    let status_idx = output.find("pub status").expect("status field present");
    let preceding = &output[..status_idx];
    let last_default = preceding.rfind("#[serde(default)]");
    if let Some(d) = last_default {
        let between = &output[d..status_idx];
        assert!(
            between.contains("pub "),
            "required field should not have #[serde(default)]:\n{output}"
        );
    }
}

#[test]
fn test_required_field_missing_fails_to_deserialize_via_serde_path() {
    let input = r#"type Resp = { status: string; }"#;
    let output = assert_compiles(input);
    assert!(
        output.contains("pub status: String"),
        "expected required field 'pub status: String' in:\n{output}"
    );
    let status_idx = output.find("pub status").unwrap();
    let preceding = &output[..status_idx];
    assert!(
        !preceding.trim_end().ends_with("#[serde(default)]"),
        "required field should not have #[serde(default)] immediately before it:\n{output}"
    );
}

#[test]
fn test_primitive_union_compiles() {
    let input = r#"type AuthMethod = string | uint64"#;
    let output = assert_compiles(input);
    assert!(output.contains("enum AuthMethod"));
    assert!(output.contains("String(String)"));
    assert!(output.contains("U64(u64)"));
}

#[test]
fn test_string_literal_union_compiles() {
    let input = r#"type Mode = "read" | "write""#;
    let output = assert_compiles(input);
    assert!(output.contains("pub type Mode = String"));
}

#[test]
fn test_mixed_primitive_and_literal_union_falls_back_to_value() {
    let input = r#"type Either = string | "fixed""#;
    let output = assert_compiles(input);
    assert!(output.contains("pub type Either = serde_json::Value"));
}

#[test]
fn test_named_struct_union_compiles() {
    let input = r#"
    type A = { x: string; }
    type B = { y: uint32; }
    type Either = A | B
    "#;
    let output = assert_compiles(input);
    assert!(output.contains("enum Either"));
    assert!(output.contains("A(A)"));
    assert!(output.contains("B(B)"));
}

#[test]
fn test_intersection_flattens_base_fields() {
    let input = r#"
    type Base = { status: string; }
    type Extended = Base & { extra: uint64; }
    "#;
    let output = assert_compiles(input);
    let extended_start = output.find("struct Extended").unwrap();
    let extended_slice = &output[extended_start..];
    let end = extended_slice.find('}').unwrap();
    let body = &extended_slice[..end];
    assert!(
        body.contains("pub status: String"),
        "Extended should include inherited status field:\n{output}"
    );
    assert!(
        body.contains("pub extra: u64"),
        "Extended should include local extra field:\n{output}"
    );
}

#[test]
fn test_intersection_local_field_overrides_inherited_duplicate() {
    let input = r#"
    type Base = { value: string; }
    type Extended = Base & { value: uint64; }
    "#;
    let output = assert_compiles(input);
    let extended_start = output.find("struct Extended").unwrap();
    let extended_slice = &output[extended_start..];
    let end = extended_slice.find('}').unwrap();
    let body = &extended_slice[..end];
    assert_eq!(
        body.matches("pub value").count(),
        1,
        "duplicate field should appear exactly once:\n{output}"
    );
    assert!(
        body.contains("pub value: String"),
        "first-wins: base field type should be retained:\n{output}"
    );
}
