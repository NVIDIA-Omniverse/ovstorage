// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Declarative `[ovstorage]` Stack schema. A deployment describes its
//! Stack as data: a `root` layer name, a set of named
//! `[ovstorage.layers.<name>]` tables, and its `connections`.
//!
//! The stack shape is 100% layer config: `kind`, `inner`, and
//! `children` are the only structural keys in a layer table; every other
//! key is flat layer config captured by `#[serde(flatten)]` and marshaled
//! to [`ovstorage_plugin::ConfigValue`] on conversion to a [`StackSpec`].

use std::collections::HashMap;
use std::path::Path;

use ovstorage_plugin::{Error, ErrorCode, Result};

use crate::config::{config_value_from_toml, default_config_paths};
use crate::{ConnectionConfig, LayerSpec, LayerType, StackSpec};

/// The `[ovstorage]` table: an explicit Stack + its connections.
#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize, PartialEq)]
pub struct StackConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root: Option<String>,
    // `layers` is a `HashMap`, whose iteration order is nondeterministic.
    // Serialize the `[ovstorage.layers.*]` tables in sorted layer-name order so
    // re-emitting the same stack (e.g. a committed config) is byte-stable and
    // does not churn the git diff.
    #[serde(
        default,
        skip_serializing_if = "HashMap::is_empty",
        serialize_with = "serialize_layers_sorted"
    )]
    pub layers: HashMap<String, LayerTable>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub connections: Vec<ConnectionConfig>,
}

/// Serialize the layer tables in sorted layer-name order so `to_toml_string`
/// output is deterministic regardless of `HashMap` iteration order.
fn serialize_layers_sorted<S>(
    layers: &HashMap<String, LayerTable>,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    use serde::ser::SerializeMap;
    let mut entries: Vec<(&String, &LayerTable)> = layers.iter().collect();
    entries.sort_by_key(|(a, _)| *a);
    let mut map = serializer.serialize_map(Some(entries.len()))?;
    for (name, table) in entries {
        map.serialize_entry(name, table)?;
    }
    map.end()
}

/// One `[ovstorage.layers.<name>]` table. `kind`/`inner`/`children` are
/// structural; every other key is flat layer config.
#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize, PartialEq)]
pub struct LayerTable {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inner: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub children: Vec<String>,
    #[serde(flatten)]
    pub config: HashMap<String, toml::Value>,
}

/// A migration message for a layer kind this release REMOVED, as opposed to one
/// that never existed.
///
/// A deployed broker or REST gateway is upgraded in place against its existing
/// config file, so a removed kind is the shape most likely to be met by an
/// operator who did nothing wrong — and `unknown layer kind '…'` is
/// indistinguishable from a typo, which sends them looking for the wrong
/// problem. The kind is not silently accepted: what the wrapper used to do now
/// happens inside each backend, so a stanza left in place is stale
/// configuration, and starting anyway would leave the operator believing a
/// layer is in the chain that is not.
fn removed_layer_kind_help(kind: &str) -> Option<&'static str> {
    match kind {
        "directory_normalize" => Some(
            "layer kind 'directory_normalize' was removed: every backend now derives the \
             directory form of an address itself, so the wrapper has nothing left to do. \
             Delete the [ovstorage.layers.directory_normalize] table and repoint whichever \
             layer named it as `inner` at what it wrapped",
        ),
        _ => None,
    }
}

/// Resolve a [`StackConfig`] into a [`StackSpec`].
///
/// `factory_types` maps a resolved layer `kind` to its [`LayerType`]
/// (built from the loaded factories in `build_stack`). For each named
/// layer this resolves `kind` (default = the layer name), looks up
/// `layer_type` from `factory_types`, and marshals every flat config
/// value via [`config_value_from_toml`].
///
/// Returns `Ok(None)` when `config.layers` is empty (the empty stack).
/// Connections are resolved to concrete targets when the Stack is built,
/// so the returned [`StackSpec`] carries no connections yet.
///
/// # Errors
///
/// - [`ErrorCode::InvalidArgument`] — the `layers` set is non-empty but
///   no `root` is specified, an unknown `kind` is not in `factory_types`,
///   or a nested config value cannot be reserialized.
pub fn stack_config_to_spec(
    config: &StackConfig,
    factory_types: &HashMap<String, LayerType>,
) -> Result<Option<StackSpec>> {
    if config.layers.is_empty() {
        return Ok(None);
    }

    let root = config.root.clone().ok_or_else(|| {
        Error::new(
            ErrorCode::InvalidArgument,
            "stack has layers but no root is set",
        )
    })?;

    let mut layers = Vec::with_capacity(config.layers.len());
    for (name, table) in &config.layers {
        let kind = table.kind.clone().unwrap_or_else(|| name.clone());
        let layer_type = *factory_types.get(&kind).ok_or_else(|| {
            Error::new(
                ErrorCode::InvalidArgument,
                removed_layer_kind_help(&kind)
                    .map_or_else(|| format!("unknown layer kind '{kind}'"), str::to_string),
            )
        })?;

        let mut layer_config = HashMap::with_capacity(table.config.len());
        for (key, value) in &table.config {
            layer_config.insert(key.clone(), config_value_from_toml(key, value)?);
        }

        layers.push(LayerSpec {
            name: name.clone(),
            kind,
            layer_type,
            config: layer_config,
            inner: table.inner.clone(),
            children: table.children.clone(),
        });
    }

    Ok(Some(StackSpec {
        root,
        layers,
        connections: Vec::new(),
    }))
}

/// Serialization wrapper so the stack nests under `[ovstorage]`.
#[derive(serde::Serialize)]
struct OvstorageWrapper<'a> {
    ovstorage: &'a StackConfig,
}

/// Does this TOML document declare a top-level `[ovstorage]` table?
///
/// Doubles as a syntax guard: a syntactically invalid document is an error, so
/// callers can treat `Ok(false)` as "valid TOML, but no `[ovstorage]` table"
/// (⇒ the empty stack) rather than swallowing a malformed file.
fn toml_declares_ovstorage(s: &str) -> Result<bool> {
    let doc: toml::Table = toml::from_str(s).map_err(|err| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("invalid ovstorage config: {err}"),
        )
    })?;
    Ok(doc.contains_key("ovstorage"))
}

/// Map a `figment` `OVSTORAGE__`-prefixed env key (already prefix-stripped by
/// [`Env::prefixed`](figment::providers::Env::prefixed)) to its dotted
/// `[ovstorage]` config path: `ROOT` -> `ovstorage.root`,
/// `LAYERS__FILE__ROOT` -> `ovstorage.layers.file.root`. Targeting the
/// `[ovstorage]` sub-table is what makes a SINGLE prefix work
/// (`OVSTORAGE__ROOT`, not `OVSTORAGE__OVSTORAGE__ROOT`), aligned with the
/// `extract_inner("ovstorage")` in [`StackConfig::from_toml_path`]. Split out
/// as a pure function so its behavior is unit-tested without mutating the
/// process environment (a `set_var` that races another thread's `getenv` is UB
/// on glibc).
fn env_key_to_config_path(key: &str) -> String {
    format!("ovstorage.{}", key.to_lowercase().replace("__", "."))
}

impl StackConfig {
    /// Parse the `[ovstorage]` table from a TOML string (no env overlay;
    /// test/programmatic path). Foreign top-level tables are ignored.
    ///
    /// A document with **no** `[ovstorage]` table deserializes to
    /// [`StackConfig::default`] (the empty stack), consistent with "no config →
    /// empty stack"; a syntactically invalid document, or a malformed
    /// `[ovstorage]` table, still errors.
    ///
    /// # Errors
    ///
    /// - [`ErrorCode::InvalidArgument`] — the TOML is syntactically invalid
    ///   or the `[ovstorage]` table contains invalid fields or types.
    pub fn from_toml_str(s: &str) -> Result<Self> {
        use figment::{
            Figment,
            providers::{Format, Toml},
        };
        // A missing `[ovstorage]` key would make figment's `extract_inner`
        // error before `#[serde(default)]` can apply; treat its absence as the
        // empty stack instead.
        if !toml_declares_ovstorage(s)? {
            return Ok(Self::default());
        }
        // Env-var overlay is intentionally skipped here so unit tests with
        // explicit configs don't pick up developer environments.
        // Operator-facing parsing goes through `from_toml_path`.
        Figment::new()
            .merge(Toml::string(s))
            .extract_inner::<Self>("ovstorage")
            .map_err(|err| {
                Error::new(
                    ErrorCode::InvalidArgument,
                    format!("invalid ovstorage config: {err}"),
                )
            })
    }

    /// Load the `[ovstorage]` table from a file, with the `OVSTORAGE__`
    /// env overlay (operator path).
    ///
    /// A file with **no** `[ovstorage]` table (a foreign-only or legacy pre-0.2
    /// config) and no `OVSTORAGE__` overlay yields [`StackConfig::default`] (the
    /// empty stack) rather than a hard parse error; a syntactically invalid file
    /// still errors.
    ///
    /// # Errors
    ///
    /// - [`ErrorCode::NotFound`] — the file does not exist or cannot be read.
    /// - [`ErrorCode::InvalidArgument`] — the file is syntactically invalid TOML
    ///   or the `[ovstorage]` table contains invalid fields or types.
    pub fn from_toml_path(path: &Path) -> Result<Self> {
        use figment::{
            Figment,
            providers::{Env, Format, Toml},
        };
        if !path.is_file() {
            return Err(Error::new(
                ErrorCode::NotFound,
                format!("could not read {}: file does not exist", path.display()),
            ));
        }
        // Absent an `[ovstorage]` table (and any `OVSTORAGE__` overlay that would
        // inject one), `extract_inner` errors on the missing key; return the
        // empty stack instead. Reading the file here also surfaces syntax errors
        // as `InvalidArgument` rather than silently falling through to default.
        let contents = std::fs::read_to_string(path).map_err(|err| {
            Error::new(
                ErrorCode::NotFound,
                format!("could not read {}: {err}", path.display()),
            )
        })?;
        let env_supplies_ovstorage = std::env::vars_os()
            .filter_map(|(key, _)| key.into_string().ok())
            .any(|key| key.starts_with("OVSTORAGE__"));
        if !toml_declares_ovstorage(&contents)? && !env_supplies_ovstorage {
            return Ok(Self::default());
        }
        let env = Env::prefixed("OVSTORAGE__")
            .map(|key| env_key_to_config_path(key.as_str()).into())
            .split(".");
        Figment::new()
            .merge(Toml::file(path))
            .merge(env)
            .extract_inner::<Self>("ovstorage")
            .map_err(|err| {
                Error::new(
                    ErrorCode::InvalidArgument,
                    format!("invalid ovstorage config '{}': {err}", path.display()),
                )
            })
    }

    /// Try `./ovstorage.toml`, then
    /// `$XDG_CONFIG_HOME/ovstorage/ovstorage.toml`. `Ok(None)` when
    /// neither exists.
    ///
    /// # Errors
    ///
    /// - [`ErrorCode::InvalidArgument`] — a discovered file is syntactically
    ///   invalid TOML or the `[ovstorage]` table contains invalid fields or types.
    pub fn from_default_path() -> Result<Option<Self>> {
        for candidate in default_config_paths() {
            if candidate.is_file() {
                return Self::from_toml_path(&candidate).map(Some);
            }
        }
        Ok(None)
    }

    /// Serialize back to TOML with the stack nested under `[ovstorage]`.
    /// Round-trips with [`from_toml_str`](Self::from_toml_str).
    ///
    /// # Errors
    ///
    /// - [`ErrorCode::Internal`] — serialization to TOML fails (unlikely with
    ///   valid stack config).
    pub fn to_toml_string(&self) -> Result<String> {
        toml::to_string_pretty(&OvstorageWrapper { ovstorage: self }).map_err(|err| {
            Error::new(
                ErrorCode::Internal,
                format!("failed to serialize ovstorage config: {err}"),
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    use ovstorage_plugin::ConfigValue;

    /// A minimal `[ovstorage]` wrapper so TOML tables nest correctly.
    #[derive(Debug, serde::Deserialize, serde::Serialize, PartialEq)]
    struct Wrapper {
        ovstorage: StackConfig,
    }

    fn factory_types() -> HashMap<String, LayerType> {
        HashMap::from([
            ("alias".to_string(), LayerType::Wrapper),
            ("file".to_string(), LayerType::Backend),
        ])
    }

    #[test]
    fn layer_tables_round_trip_through_toml() {
        let toml_str = r#"
            [ovstorage]
            root = "alias"

            [ovstorage.layers.alias]
            inner = "file"

            [ovstorage.layers.file]
            kind = "file"
            root = "/srv/data"
            follow_reads = false
        "#;
        let parsed: Wrapper = toml::from_str(toml_str).unwrap();
        let cfg = &parsed.ovstorage;

        assert_eq!(cfg.root.as_deref(), Some("alias"));
        assert_eq!(cfg.layers.len(), 2);

        let alias = cfg.layers.get("alias").unwrap();
        assert_eq!(alias.kind, None);
        assert_eq!(alias.inner.as_deref(), Some("file"));
        assert!(alias.config.is_empty());

        let file = cfg.layers.get("file").unwrap();
        assert_eq!(file.kind.as_deref(), Some("file"));

        // Re-serialize and parse again for a full round trip.
        let reser = toml::to_string(&parsed).unwrap();
        let reparsed: Wrapper = toml::from_str(&reser).unwrap();
        assert_eq!(reparsed, parsed);
    }

    #[test]
    fn flat_keys_land_in_config_structural_keys_do_not() {
        let toml_str = r#"
            [ovstorage.layers.file]
            kind = "file"
            inner = "other"
            children = ["a", "b"]
            follow_reads = false
            root = "/srv/data"
        "#;
        let parsed: Wrapper = toml::from_str(toml_str).unwrap();
        let file = parsed.ovstorage.layers.get("file").unwrap();

        // Structural keys are typed fields, not config.
        assert_eq!(file.kind.as_deref(), Some("file"));
        assert_eq!(file.inner.as_deref(), Some("other"));
        assert_eq!(file.children, vec!["a".to_string(), "b".to_string()]);
        assert!(!file.config.contains_key("kind"));
        assert!(!file.config.contains_key("inner"));
        assert!(!file.config.contains_key("children"));

        // Flat keys are captured in config.
        assert_eq!(
            file.config.get("follow_reads"),
            Some(&toml::Value::Boolean(false))
        );
        assert_eq!(
            file.config.get("root"),
            Some(&toml::Value::String("/srv/data".into()))
        );
    }

    #[test]
    fn kind_defaults_to_layer_name() {
        let toml_str = r#"
            [ovstorage]
            root = "file"

            [ovstorage.layers.file]
            follow_reads = false
        "#;
        let cfg = toml::from_str::<Wrapper>(toml_str).unwrap().ovstorage;
        let spec = stack_config_to_spec(&cfg, &factory_types())
            .unwrap()
            .unwrap();

        assert_eq!(spec.root, "file");
        assert_eq!(spec.layers.len(), 1);
        let layer = &spec.layers[0];
        assert_eq!(layer.name, "file");
        assert_eq!(layer.kind, "file"); // defaulted from the layer name
        assert_eq!(layer.layer_type, LayerType::Backend);
        assert_eq!(
            layer.config.get("follow_reads"),
            Some(&ConfigValue::Bool(false))
        );
        assert!(spec.connections.is_empty());
    }

    #[test]
    fn empty_layers_yields_none() {
        let cfg = StackConfig::default();
        assert!(
            stack_config_to_spec(&cfg, &factory_types())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn non_empty_layers_without_root_errs() {
        let cfg = StackConfig {
            root: None,
            layers: HashMap::from([("file".to_string(), LayerTable::default())]),
            connections: Vec::new(),
        };
        let err = stack_config_to_spec(&cfg, &factory_types()).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    #[test]
    fn to_toml_string_round_trips_and_nests_under_ovstorage() {
        let cfg = StackConfig {
            root: Some("alias".into()),
            layers: HashMap::from([
                (
                    "alias".to_string(),
                    LayerTable {
                        inner: Some("file".into()),
                        ..Default::default()
                    },
                ),
                (
                    "file".to_string(),
                    LayerTable {
                        kind: Some("file".into()),
                        config: HashMap::from([(
                            "root".to_string(),
                            toml::Value::String("/srv/data".into()),
                        )]),
                        ..Default::default()
                    },
                ),
            ]),
            connections: vec![ConnectionConfig {
                backend_kind: "file".into(),
                target: None,
                display_name: None,
                config: HashMap::new(),
                credentials: HashMap::new(),
            }],
        };

        let emitted = cfg.to_toml_string().unwrap();
        assert!(emitted.contains("[ovstorage]"), "emitted: {emitted}");
        let reparsed = StackConfig::from_toml_str(&emitted).unwrap();
        assert_eq!(reparsed, cfg);
    }

    #[test]
    fn to_toml_string_emits_layers_in_deterministic_sorted_order() {
        // Two configs with the same layers inserted in opposite orders must
        // serialize byte-identically, with `[ovstorage.layers.*]` tables in
        // sorted name order — otherwise a committed config churns its diff.
        let names = ["zebra", "alpha", "mango"];
        let make = |order: &[&str]| StackConfig {
            root: Some("alpha".into()),
            layers: order
                .iter()
                .map(|n| {
                    (
                        n.to_string(),
                        LayerTable {
                            kind: Some("file".into()),
                            ..Default::default()
                        },
                    )
                })
                .collect(),
            connections: Vec::new(),
        };

        let forward = make(&names).to_toml_string().unwrap();
        let reversed = {
            let mut rev = names;
            rev.reverse();
            make(&rev).to_toml_string().unwrap()
        };
        assert_eq!(forward, reversed, "serialization is not order-stable");

        let a = forward.find("layers.alpha").expect("alpha table");
        let m = forward.find("layers.mango").expect("mango table");
        let z = forward.find("layers.zebra").expect("zebra table");
        assert!(a < m && m < z, "layers not in sorted order:\n{forward}");
    }

    #[test]
    fn from_toml_str_ignores_foreign_top_level_tables() {
        let toml_str = r#"
            [listener]
            bind = "0.0.0.0:8080"

            [ovstorage]
            root = "file"

            [ovstorage.layers.file]
            kind = "file"
            root = "/srv/data"
        "#;
        let cfg = StackConfig::from_toml_str(toml_str).unwrap();
        assert_eq!(cfg.root.as_deref(), Some("file"));
        assert_eq!(cfg.layers.len(), 1);
        assert!(cfg.layers.contains_key("file"));
    }

    #[test]
    fn from_toml_str_missing_ovstorage_table_is_empty_stack() {
        // A doc with only foreign tables (or a legacy pre-0.2 top-level config)
        // has no `[ovstorage]` table: yield the empty stack, not a parse error.
        for doc in [
            "[listener]\nbind = \"0.0.0.0:8080\"\n",
            "[[connections]]\nbackend_kind = \"file\"\n",
            "", // wholly empty file
        ] {
            let cfg = StackConfig::from_toml_str(doc)
                .unwrap_or_else(|e| panic!("expected empty stack for {doc:?}, got {e:?}"));
            assert_eq!(cfg, StackConfig::default(), "doc: {doc:?}");
        }
    }

    #[test]
    fn from_toml_str_malformed_ovstorage_table_still_errors() {
        // A *present* `[ovstorage]` table with the wrong shape must still fail —
        // the missing-table fallback does not mask real config errors.
        let err =
            StackConfig::from_toml_str("[ovstorage]\nlayers = \"not-a-table\"\n").unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    #[test]
    fn from_toml_str_syntactically_invalid_errors() {
        // A syntax error is not "no [ovstorage] table" — it must error, not
        // silently deserialize to the empty stack.
        let err = StackConfig::from_toml_str("this is not = = toml").unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    #[test]
    fn from_toml_path_missing_ovstorage_table_is_empty_stack() {
        let _env_guard = ENV_LOCK.lock().unwrap();
        let path = std::env::temp_dir().join(format!("ovstorage-noov-{}.toml", std::process::id()));
        std::fs::write(&path, "[listener]\nbind = \"0.0.0.0:8080\"\n").unwrap();
        let cfg = StackConfig::from_toml_path(&path);
        std::fs::remove_file(&path).ok();
        assert_eq!(cfg.unwrap(), StackConfig::default());
    }

    #[test]
    fn from_toml_path_missing_file_is_not_found() {
        let path = std::path::Path::new("/nonexistent/does/not/exist/ovstorage.toml");
        let err = StackConfig::from_toml_path(path).unwrap_err();
        assert_eq!(err.code(), ErrorCode::NotFound);
    }

    /// A REMOVED kind must say so, not read as a typo.
    ///
    /// This is the shape an operator meets by doing nothing wrong: a deployed
    /// broker upgraded in place against its existing config file. `unknown
    /// layer kind '…'` sends them looking for a spelling mistake.
    #[test]
    fn a_removed_layer_kind_explains_the_migration() {
        let cfg = StackConfig {
            root: Some("directory_normalize".into()),
            layers: HashMap::from([("directory_normalize".to_string(), LayerTable::default())]),
            connections: Vec::new(),
        };
        let error = stack_config_to_spec(&cfg, &HashMap::new())
            .expect_err("a removed kind still fails to load");
        assert_eq!(error.code(), ErrorCode::InvalidArgument);
        assert!(
            error.message().contains("was removed"),
            "the message must name the removal, got: {}",
            error.message()
        );
        assert!(
            error.message().contains("Delete the"),
            "and must say what to do about it, got: {}",
            error.message()
        );
    }

    #[test]
    fn unknown_kind_errs() {
        let cfg = StackConfig {
            root: Some("mystery".into()),
            layers: HashMap::from([("mystery".to_string(), LayerTable::default())]),
            connections: Vec::new(),
        };
        let err = stack_config_to_spec(&cfg, &factory_types()).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert!(err.message().contains("unknown layer kind 'mystery'"));
    }

    #[test]
    fn env_key_maps_to_single_ovstorage_prefix() {
        // The `OVSTORAGE__` env overlay targets the `[ovstorage]` sub-table with a
        // SINGLE prefix: `OVSTORAGE__ROOT` overrides `ovstorage.root`, not
        // `ovstorage.ovstorage.root`. `figment` strips the `OVSTORAGE__` prefix
        // before the mapper runs, so the mapper sees the bare `ROOT`.
        //
        // Tested on the pure mapping rather than through `from_toml_path` so the
        // suite never mutates the process environment — a `set_var` racing another
        // parallel test's `getenv` is UB on glibc (the flake this guards against).
        assert_eq!(env_key_to_config_path("ROOT"), "ovstorage.root");
        assert_eq!(
            env_key_to_config_path("LAYERS__FILE__ROOT"),
            "ovstorage.layers.file.root"
        );
        // A double `__` only ever collapses to a `.` — no path picks up a second
        // `ovstorage.` segment, which is exactly the single-prefix guarantee.
        assert!(!env_key_to_config_path("ROOT").contains("ovstorage.ovstorage"));
    }
}
