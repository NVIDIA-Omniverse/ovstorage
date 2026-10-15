// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use anyhow::Result;

use crate::{generator, parser};

pub fn preprocess_source(source: &str) -> String {
    let mut result = String::with_capacity(source.len());
    for line in source.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("type ")
            && !trimmed.contains('=')
            && !trimmed.contains('{')
            && !trimmed.contains(';')
        {
            result.push_str(&line.replace(trimmed, &format!("{trimmed} =")));
        } else {
            result.push_str(line);
        }
        result.push('\n');
    }
    result
}

pub fn generate_from_str(source: &str) -> Result<String> {
    generate(source, "")
}

pub fn generate_from_file(path: &Path) -> Result<String> {
    let path_str = path.display().to_string();
    tracing::info!(path = %path_str, "generating from path");
    let source = std::fs::read_to_string(path)?;
    let origin = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    generate(&source, origin)
}

fn generate(source: &str, origin: &str) -> Result<String> {
    let source = preprocess_source(source);
    let ast = parser::parse(&source)?;
    tracing::info!(n = ast.items.len(), "parsed n items");
    let tokens = generator::generate(&ast, origin);
    let syntax_tree = syn::parse2(tokens).map_err(|e| {
        tracing::error!(error = %e, "generated Rust failed to parse");
        e
    })?;
    tracing::info!("generated Rust");
    Ok(prettyplease::unparse(&syntax_tree))
}

#[cfg(test)]
mod preprocess_tests {
    use super::*;

    #[test]
    fn adds_equals_sign_to_bare_type_declaration() {
        let input = "type Foo\n{ bar: string; }";
        let output = preprocess_source(input);
        assert!(output.contains("type Foo ="));
    }

    #[test]
    fn leaves_type_alias_with_equals_unchanged() {
        let input = "type Foo = string\n";
        let output = preprocess_source(input);
        assert_eq!(output, "type Foo = string\n");
    }

    #[test]
    fn leaves_inline_object_type_unchanged() {
        let input = "type Foo = { bar: string; }\n";
        let output = preprocess_source(input);
        assert_eq!(output, "type Foo = { bar: string; }\n");
    }

    #[test]
    fn preserves_non_type_lines() {
        let input = "interface Svc {\n  ping(): void;\n}\n";
        let output = preprocess_source(input);
        assert_eq!(output, input);
    }

    #[test]
    fn handles_empty_input() {
        assert_eq!(preprocess_source(""), "");
    }
}
