// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Verifies the generated `ovstorage_plugin.h` C header.
//!
//! Two tests:
//!
//! - `header_naming_conventions` — parses the header and asserts the
//!   naming contract: every emitted type starts with `OvStoragePlugin_`,
//!   every emitted function starts with `ovstorage_plugin_`, no
//!   `Ovs` / `ovs_` shorthand prefixes appear, no double-`Plugin_Plugin`
//!   regressions. Runs everywhere; doesn't need a C toolchain.
//!
//! - `c_header_compiles` — invokes `cc` on a minimal translation unit
//!   that includes the generated header.
//!   Skips with a warning if `cc` isn't on PATH, so the test passes on
//!   minimal CI runners while still catching breakage where a compiler
//!   is available.

use std::path::PathBuf;

fn header_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("include")
        .join("ovstorage_plugin.h")
}

fn read_header() -> String {
    std::fs::read_to_string(header_path())
        .expect("ovstorage_plugin.h must exist; run `cargo build -p ovstorage-plugin` first")
}

fn macro_value<'a>(header: &'a str, name: &str) -> Option<&'a str> {
    header.lines().find_map(|line| {
        let definition = line.trim().strip_prefix("#define")?.trim_start();
        let name_end = definition.find(char::is_whitespace)?;
        let (actual_name, value) = definition.split_at(name_end);
        (actual_name == name).then(|| value.trim())
    })
}

#[test]
fn auth_credential_macros_are_visible_in_generated_header() {
    let header = read_header();
    for (name, expected) in [
        (
            "OVSTORAGE_EXT_AUTH_CREDENTIAL",
            "\"org.omniverse.ovstorage/auth-credential@1\"",
        ),
        (
            "OVSTORAGE_EXT_PRINCIPAL_ID",
            "\"org.omniverse.ovstorage/principal@1\"",
        ),
        (
            "OVSTORAGE_EXT_PRINCIPAL_DISPLAY_NAME",
            "\"org.omniverse.ovstorage/principal-display-name@1\"",
        ),
        ("OVSTORAGE_AUTH_CREDENTIAL_WIRE_VERSION", "2u"),
        ("OVSTORAGE_AUTH_CREDENTIAL_TRANSPORT_TCP", "0u"),
        ("OVSTORAGE_AUTH_CREDENTIAL_TRANSPORT_UDS", "1u"),
        ("OVSTORAGE_AUTH_CREDENTIAL_TRANSPORT_NAMED_PIPE", "2u"),
    ] {
        assert_eq!(
            macro_value(&header, name),
            Some(expected),
            "generated C header has the wrong `{name}` contract",
        );
    }
}

#[test]
fn header_naming_conventions() {
    let header = read_header();

    // Sanity check: the current Layer ABI version is published under the
    // concise C-facing name (via `[export.rename]`).
    assert!(
        header.contains("#define OVSTORAGE_PLUGIN_ABI_VERSION"),
        "expected unprefixed `OVSTORAGE_PLUGIN_ABI_VERSION` define",
    );

    let mut typedef_violations = Vec::new();
    let mut function_violations = Vec::new();

    for line in header.lines() {
        let trimmed = line.trim();

        // Skip comment lines. cbindgen renders Rust doc comments as
        // `/** ... */` blocks where every continuation line starts
        // with ` * `; ignoring those keeps prose like
        // `Optional::some(value)` from looking like a function
        // declaration. Preprocessor lines are skipped too: the
        // cpp_compat guards contain `defined(...)`, which would
        // otherwise parse as a function named `defined`.
        if trimmed.starts_with('*')
            || trimmed.starts_with("//")
            || trimmed.starts_with("/*")
            || trimmed.starts_with('#')
        {
            continue;
        }

        // `typedef ... NAME;` — both `typedef enum/struct { ... } NAME;`
        // closing lines and one-line `typedef X NAME;` aliases. The
        // shared shape is a line ending in `<NAME>;` where `<NAME>` is
        // the last identifier on the line.
        if let Some(name) = parse_typedef_name(trimmed)
            && !name.starts_with("OvStoragePlugin_")
        {
            typedef_violations.push(name.to_string());
        }

        // Function declarations. cbindgen emits them as
        // `ReturnType name(params);` on a single line (or the first
        // line of a multi-line declaration). Look for an identifier
        // followed immediately by `(` with no preceding space — that
        // distinguishes `name(` from `(*name)(` (function pointer in
        // a typedef, which is matched by the typedef branch above).
        if let Some(name) = parse_function_name(trimmed)
            && !name.starts_with("ovstorage_plugin_")
        {
            function_violations.push(name.to_string());
        }
    }

    assert!(
        typedef_violations.is_empty(),
        "type names must start with `OvStoragePlugin_`; offenders: {typedef_violations:?}",
    );
    assert!(
        function_violations.is_empty(),
        "function names must start with `ovstorage_plugin_`; offenders: {function_violations:?}",
    );

    // Forbidden short prefixes — make sure we never abbreviate.
    let forbidden_prefixes = [
        ("Ovs", "Ovs[A-Z] PascalCase abbreviation"),
        ("ovs_", "ovs_ snake-case abbreviation"),
    ];
    for (needle, label) in forbidden_prefixes {
        for (line_no, line) in header.lines().enumerate() {
            if let Some(pos) = line.find(needle) {
                // Allow occurrences inside doc comments (lines that
                // start with `*` or `/*`/` *`/`//`). The naming
                // convention is about emitted identifiers, not
                // documentation prose.
                let trimmed = line.trim_start();
                if trimmed.starts_with('*') || trimmed.starts_with("//") {
                    continue;
                }
                // Allow if this is part of a longer word like
                // `OvStorage` — only flag when the next char isn't
                // alphanumeric (suggesting the abbreviation form).
                let after = &line[pos + needle.len()..];
                let next_is_word = after
                    .chars()
                    .next()
                    .map(|c| c.is_ascii_alphanumeric() || c == '_')
                    .unwrap_or(false);
                let before_is_word = if pos == 0 {
                    false
                } else {
                    line[..pos]
                        .chars()
                        .next_back()
                        .map(|c| c.is_ascii_alphanumeric() || c == '_')
                        .unwrap_or(false)
                };
                // Reject only when this looks like the start of an
                // identifier (not preceded by a word char) followed
                // by what would be a continuation.
                if !before_is_word && next_is_word {
                    panic!("forbidden {label} on line {}: {trimmed}", line_no + 1,);
                }
            }
        }
    }

    // No `OvStoragePluginPlugin*` (no underscore) regression. The
    // intentional `OvStoragePlugin_Plugin*` form (with underscore —
    // e.g. `OvStoragePlugin_PluginManifestV1`) is fine and reads
    // cleanly. The without-underscore form is what cbindgen produced
    // before we added the trailing `_` to `[export] prefix`.
    assert!(
        !header.contains("OvStoragePluginPlugin"),
        "header has an `OvStoragePluginPlugin*` (no separator) regression. The \
         `[export] prefix = \"OvStoragePlugin_\"` should produce \
         `OvStoragePlugin_Plugin*` instead.",
    );
}

/// Parse `typedef ... NAME;` and return `NAME`. Recognizes:
///
/// - `} OvStoragePlugin_Foo;`        (closing line of `typedef enum/struct {...} NAME;`)
/// - `typedef OvStoragePlugin_X OvStoragePlugin_Y;`
/// - `typedef ReturnType (*OvStoragePlugin_FnPtrAlias)(...);`
fn parse_typedef_name(line: &str) -> Option<&str> {
    if !line.ends_with(';') {
        return None;
    }
    let body = &line[..line.len() - 1];
    if let Some(stripped) = body.strip_prefix("typedef ") {
        // Function-pointer typedef: `typedef R (*NAME)(...)`. The
        // pointer's name is between `(*` and `)`.
        if let Some(start) = stripped.find("(*")
            && let Some(end) = stripped[start + 2..].find(')')
        {
            let candidate = &stripped[start + 2..start + 2 + end];
            if is_identifier(candidate) {
                return Some(candidate);
            }
        }
        // Plain alias: last whitespace-separated token is the name.
        let candidate = stripped.split_whitespace().last()?;
        if is_identifier(candidate) {
            return Some(candidate);
        }
    }
    if let Some(rest) = body.strip_prefix("} ") {
        let candidate = rest.trim();
        if is_identifier(candidate) {
            return Some(candidate);
        }
    }
    None
}

/// Parse a function declaration line and return the function name.
/// Recognizes `ReturnType name(...);` and `ReturnType *name(...);`.
fn parse_function_name(line: &str) -> Option<&str> {
    let trimmed = line.trim_end_matches(';');
    let open = trimmed.find('(')?;
    if open == 0 {
        return None;
    }
    // Function-pointer typedefs always have a space-then-`(` pattern
    // (`typedef R (*NAME)(...)`); reject those by requiring that the
    // char immediately before `(` be an identifier char.
    let preceding = trimmed[..open].chars().next_back()?;
    if !preceding.is_ascii_alphanumeric() && preceding != '_' {
        return None;
    }
    // Walk back from `open` until we hit a non-identifier char; that
    // window is the function name.
    let bytes = trimmed.as_bytes();
    let mut start = open;
    while start > 0 {
        let prev = bytes[start - 1];
        if (prev as char).is_ascii_alphanumeric() || prev == b'_' {
            start -= 1;
        } else {
            break;
        }
    }
    let candidate = &trimmed[start..open];
    if !is_identifier(candidate) {
        return None;
    }
    // Filter out keywords and types we know aren't function names.
    // The cbindgen output format emits one function per declaration
    // line, so anything reaching here that starts with a lowercase
    // letter and isn't a control-flow keyword is a function.
    let first_char = candidate.chars().next()?;
    if !first_char.is_ascii_lowercase() {
        return None;
    }
    Some(candidate)
}

fn is_identifier(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let mut chars = s.chars();
    let first = chars.next().unwrap();
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[test]
fn c_header_compiles() {
    use std::process::Command;

    // Skip if no C compiler is on PATH. Done by running `cc --version`
    // and checking the exit status.
    let probe = Command::new("cc").arg("--version").output();
    let probe = match probe {
        Ok(out) => out,
        Err(_) => {
            eprintln!("skipping c_header_compiles: `cc` not found on PATH");
            return;
        }
    };
    if !probe.status.success() {
        eprintln!("skipping c_header_compiles: `cc --version` failed");
        return;
    }

    let include_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("include");
    let temp_dir = std::env::temp_dir();
    let suffix = std::process::id();
    let source = temp_dir.join(format!("ovstorage_plugin_header_verification_{suffix}.c"));
    let object = temp_dir.join(format!("ovstorage_plugin_header_verification_{suffix}.o"));
    std::fs::write(
        &source,
        "#include <ovstorage_plugin.h>\n\
         #ifndef OVSTORAGE_EXT_AUTH_CREDENTIAL\n\
         #error OVSTORAGE_EXT_AUTH_CREDENTIAL is missing\n\
         #endif\n\
         #ifndef OVSTORAGE_EXT_PRINCIPAL_ID\n\
         #error OVSTORAGE_EXT_PRINCIPAL_ID is missing\n\
         #endif\n\
         #ifndef OVSTORAGE_EXT_PRINCIPAL_DISPLAY_NAME\n\
         #error OVSTORAGE_EXT_PRINCIPAL_DISPLAY_NAME is missing\n\
         #endif\n\
         _Static_assert(OVSTORAGE_AUTH_CREDENTIAL_WIRE_VERSION == 2u, \"wire version\");\n\
         _Static_assert(OVSTORAGE_AUTH_CREDENTIAL_TRANSPORT_TCP == 0u, \"TCP tag\");\n\
         _Static_assert(OVSTORAGE_AUTH_CREDENTIAL_TRANSPORT_UDS == 1u, \"UDS tag\");\n\
         _Static_assert(OVSTORAGE_AUTH_CREDENTIAL_TRANSPORT_NAMED_PIPE == 2u, \"named-pipe tag\");\n\
         static const char *auth_credential_key = OVSTORAGE_EXT_AUTH_CREDENTIAL;\n\
         static const char *principal_id_key = OVSTORAGE_EXT_PRINCIPAL_ID;\n\
         static const char *principal_display_name_key = OVSTORAGE_EXT_PRINCIPAL_DISPLAY_NAME;\n\
         int main(void) {\n\
             return auth_credential_key[0] == '\\0' || principal_id_key[0] == '\\0' ||\n\
                    principal_display_name_key[0] == '\\0';\n\
         }\n",
    )
    .expect("write header verification C source");
    let _ = std::fs::remove_file(&object);

    let output = Command::new("cc")
        .arg("-c")
        .arg("-fPIC")
        .arg("-Werror=implicit-function-declaration")
        .arg("-Wall")
        .arg("-I")
        .arg(&include_dir)
        .arg("-o")
        .arg(&object)
        .arg(&source)
        .output()
        .expect("failed to invoke cc");

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        panic!(
            "cc failed to compile a translation unit against the generated header.\n\
             --- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
        );
    }
    let _ = std::fs::remove_file(&source);
    let _ = std::fs::remove_file(&object);
}
