// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Validation for repo-root agent skills.

use anyhow::{Context, Result};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

const ALLOWED_PREFIXES: &[&str] = &[
    "ovstorage-user-",
    "ovstorage-operator-",
    "ovstorage-contributor-",
];
const SKILL_LICENSE: &str = "CC-BY-4.0";
const ALLOWED_TOOLS: &[&str] = &["Read", "Write", "Edit", "Bash", "Grep", "Glob", "Shell"];
const REQUIRED_FIELDS: &[&str] = &[
    "name",
    "description",
    "license",
    "version",
    "author",
    "tags",
    "tools",
    "compatibility",
];

pub(crate) fn validate() -> Result<()> {
    let root = crate::repo_root()?;
    validate_at(&root)
}

fn validate_at(root: &Path) -> Result<()> {
    let skills = root.join("skills");
    if !skills.exists() {
        println!("skills/: not present, nothing to validate");
        return Ok(());
    }

    let mut checked = 0usize;
    let mut errors = Vec::new();
    for entry in fs::read_dir(&skills).with_context(|| format!("read_dir {}", skills.display()))? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }

        let slug = entry.file_name().to_string_lossy().to_string();
        let skill_md = entry.path().join("SKILL.md");
        if !skill_md.exists() {
            continue;
        }

        checked += 1;
        if let Err(err) = validate_skill(&slug, &skill_md) {
            errors.push(format!("{}: {err:#}", skill_md.display()));
        }
    }

    if !errors.is_empty() {
        anyhow::bail!("skill validation failed:\n{}", errors.join("\n"));
    }
    println!("validated {checked} skill(s)");
    Ok(())
}

fn validate_skill(slug: &str, skill_md: &Path) -> Result<()> {
    if !ALLOWED_PREFIXES
        .iter()
        .any(|prefix| slug.starts_with(prefix))
    {
        anyhow::bail!(
            "skill directory slug must start with one of {}",
            ALLOWED_PREFIXES.join(", ")
        );
    }

    let body =
        fs::read_to_string(skill_md).with_context(|| format!("read {}", skill_md.display()))?;
    let frontmatter = parse_frontmatter(&body)?;
    let name = frontmatter
        .get("name")
        .ok_or_else(|| anyhow::anyhow!("missing frontmatter `name:`"))?;
    if name != slug {
        anyhow::bail!("frontmatter `name:` is {name:?}, expected {slug:?}");
    }
    if !is_valid_skill_slug(name) {
        anyhow::bail!("frontmatter `name:` must be lowercase kebab-case, 1-64 chars");
    }

    let description = frontmatter
        .get("description")
        .ok_or_else(|| anyhow::anyhow!("missing frontmatter `description:`"))?;
    if description.trim().is_empty() {
        anyhow::bail!("frontmatter `description:` must be non-empty");
    }
    if description.chars().count() > 1024 {
        anyhow::bail!("frontmatter `description:` must be 1024 chars or shorter");
    }

    for field in REQUIRED_FIELDS {
        let Some(value) = frontmatter.get(*field) else {
            anyhow::bail!("missing frontmatter `{field}:`");
        };
        if value.trim().is_empty() {
            anyhow::bail!("frontmatter `{field}:` must be non-empty");
        }
    }

    let version = frontmatter
        .get("version")
        .expect("checked by REQUIRED_FIELDS");
    if !is_semver(version) {
        anyhow::bail!("frontmatter `version:` must be semver such as \"0.1.0\"");
    }

    let license = frontmatter
        .get("license")
        .expect("checked by REQUIRED_FIELDS");
    if license != SKILL_LICENSE {
        anyhow::bail!("frontmatter `license:` must be {SKILL_LICENSE}");
    }

    let author = frontmatter
        .get("author")
        .expect("checked by REQUIRED_FIELDS");
    if !author.starts_with("NVIDIA ") || author.trim() == "NVIDIA" {
        anyhow::bail!("frontmatter `author:` must use `NVIDIA <team>` format");
    }

    let tags = frontmatter.get("tags").expect("checked by REQUIRED_FIELDS");
    let tags = inline_list_entries(tags)
        .ok_or_else(|| anyhow::anyhow!("frontmatter `tags:` must be an inline YAML list"))?;
    if !(1..=5).contains(&tags.len()) {
        anyhow::bail!("frontmatter `tags:` must contain 1-5 entries");
    }

    let tools = frontmatter
        .get("tools")
        .expect("checked by REQUIRED_FIELDS");
    let tools = inline_list_entries(tools)
        .ok_or_else(|| anyhow::anyhow!("frontmatter `tools:` must be an inline YAML list"))?;
    if tools.is_empty() {
        anyhow::bail!("frontmatter `tools:` must contain at least one entry");
    }
    for tool in tools {
        if !ALLOWED_TOOLS.contains(&tool.as_str()) {
            anyhow::bail!(
                "unsupported frontmatter `tools:` entry {tool:?}; use one of {}",
                ALLOWED_TOOLS.join(", ")
            );
        }
    }

    let compatibility = frontmatter
        .get("compatibility")
        .expect("checked by REQUIRED_FIELDS");
    if compatibility.chars().count() > 500 {
        anyhow::bail!("frontmatter `compatibility:` must be 500 chars or shorter");
    }
    Ok(())
}

fn is_valid_skill_slug(value: &str) -> bool {
    !value.is_empty()
        && value.chars().count() <= 64
        && !value.starts_with('-')
        && !value.ends_with('-')
        && !value.contains("--")
        && value
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
}

fn is_semver(value: &str) -> bool {
    let core = value.split_once('-').map_or(value, |(core, _)| core);
    let mut parts = core.split('.');
    let Some(major) = parts.next() else {
        return false;
    };
    let Some(minor) = parts.next() else {
        return false;
    };
    let Some(patch) = parts.next() else {
        return false;
    };
    parts.next().is_none()
        && [major, minor, patch]
            .iter()
            .all(|part| !part.is_empty() && part.chars().all(|ch| ch.is_ascii_digit()))
}

fn inline_list_entries(value: &str) -> Option<Vec<String>> {
    let inner = value.strip_prefix('[')?.strip_suffix(']')?.trim();
    if inner.is_empty() {
        return Some(Vec::new());
    }
    Some(
        inner
            .split(',')
            .map(str::trim)
            .map(unquote_yaml_scalar)
            .filter(|entry| !entry.is_empty())
            .collect(),
    )
}

fn parse_frontmatter(body: &str) -> Result<BTreeMap<String, String>> {
    let mut lines = body.lines();
    if lines.next() != Some("---") {
        anyhow::bail!("missing opening YAML frontmatter fence");
    }

    let mut fields = BTreeMap::new();
    for line in lines {
        if line == "---" {
            return Ok(fields);
        }
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            anyhow::bail!("frontmatter line is not `key: value`: {line:?}");
        };
        fields.insert(key.trim().to_string(), unquote_yaml_scalar(value.trim()));
    }
    anyhow::bail!("missing closing YAML frontmatter fence")
}

fn unquote_yaml_scalar(value: &str) -> String {
    if value.len() >= 2 {
        let bytes = value.as_bytes();
        let first = bytes[0];
        let last = bytes[value.len() - 1];
        if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
            return value[1..value.len() - 1].to_string();
        }
    }
    value.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_frontmatter_scalars() {
        let parsed = parse_frontmatter(
            "---\nname: ovstorage-user-read-bytes\ndescription: \"Read one object\"\ntags: [ovstorage]\n---\n# Body\n",
        )
        .unwrap();
        assert_eq!(parsed.get("name").unwrap(), "ovstorage-user-read-bytes");
        assert_eq!(parsed.get("description").unwrap(), "Read one object");
        assert_eq!(parsed.get("tags").unwrap(), "[ovstorage]");
    }

    #[test]
    fn rejects_skill_slug_without_allowed_prefix() {
        let temp = temp_test_dir("bad-prefix");
        write_skill(
            &temp,
            "admin-secret-thing",
            "---\nname: admin-secret-thing\ndescription: nope\n---\n",
        );

        let err = validate_at(&temp).unwrap_err().to_string();

        assert!(err.contains("must start with one of"));
        fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn rejects_frontmatter_name_that_differs_from_slug() {
        let temp = temp_test_dir("bad-name");
        write_skill(
            &temp,
            "ovstorage-user-read-bytes",
            &skill_body("ovstorage-user-write-safely", "wrong name"),
        );

        let err = validate_at(&temp).unwrap_err().to_string();

        assert!(err.contains("expected \"ovstorage-user-read-bytes\""));
        fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn rejects_missing_frontmatter_closing_fence() {
        let err = parse_frontmatter("---\nname: ovstorage-user-read-bytes\ndescription: Read\n")
            .unwrap_err()
            .to_string();
        assert!(err.contains("missing closing"));
    }

    #[test]
    fn rejects_missing_publication_frontmatter() {
        let temp = temp_test_dir("missing-publication-frontmatter");
        write_skill(
            &temp,
            "ovstorage-user-read-bytes",
            "---\nname: ovstorage-user-read-bytes\ndescription: Read\nlicense: CC-BY-4.0\n---\n",
        );

        let err = validate_at(&temp).unwrap_err().to_string();

        assert!(err.contains("missing frontmatter `version:`"));
        fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn rejects_non_cc_by_skill_license() {
        let temp = temp_test_dir("bad-license");
        write_skill(
            &temp,
            "ovstorage-user-read-bytes",
            &skill_body(
                "ovstorage-user-read-bytes",
                "Read one object with ovstorage",
            )
            .replace("license: CC-BY-4.0", "license: Apache-2.0"),
        );

        let err = validate_at(&temp).unwrap_err().to_string();

        assert!(err.contains("frontmatter `license:` must be CC-BY-4.0"));
        fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn rejects_non_standard_tool_name() {
        let temp = temp_test_dir("bad-tool");
        write_skill(
            &temp,
            "ovstorage-user-read-bytes",
            &skill_body(
                "ovstorage-user-read-bytes",
                "Read one object with ovstorage",
            )
            .replace("tools: [Read]", "tools: [MCP]"),
        );

        let err = validate_at(&temp).unwrap_err().to_string();

        assert!(err.contains("unsupported frontmatter `tools:` entry"));
        fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn accepts_publication_ready_frontmatter() {
        let temp = temp_test_dir("publication-ready");
        write_skill(
            &temp,
            "ovstorage-user-read-bytes",
            &skill_body(
                "ovstorage-user-read-bytes",
                "Read one object with ovstorage",
            ),
        );

        validate_at(&temp).unwrap();

        fs::remove_dir_all(temp).unwrap();
    }

    fn write_skill(root: &Path, slug: &str, body: &str) {
        let dir = root.join("skills").join(slug);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("SKILL.md"), body).unwrap();
    }

    fn skill_body(name: &str, description: &str) -> String {
        format!(
            concat!(
                "---\n",
                "name: {}\n",
                "description: {}\n",
                "license: CC-BY-4.0\n",
                "version: \"0.1.0\"\n",
                "author: NVIDIA Omniverse\n",
                "tags: [ovstorage]\n",
                "tools: [Read]\n",
                "compatibility: Requires ovstorage MCP tools.\n",
                "---\n",
                "# Skill\n",
            ),
            name, description
        )
    }

    fn temp_test_dir(label: &str) -> std::path::PathBuf {
        let unique = format!(
            "ovstorage-xtask-skills-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let path = std::env::temp_dir().join(unique);
        fs::create_dir_all(&path).unwrap();
        path
    }
}
