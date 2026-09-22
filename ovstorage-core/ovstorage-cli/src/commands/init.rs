// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Initialize a session with the canonical minimal layer graph.

use std::collections::HashMap;
use std::path::Path;

use ovstorage::{CancellationToken, Error, ErrorCode, LayerTable, LoadedLayerFactory, StackConfig};

use crate::commands::util::stack_is_unconfigured;
use crate::commands::write_config::write_config_atomic;
use crate::session::SessionState;

/// The canonical minimal stack: one built-in `file` backend and no connections.
pub(crate) fn default_stack_config() -> StackConfig {
    let mut layers = HashMap::new();
    layers.insert("file".to_string(), LayerTable::default());
    StackConfig {
        root: Some("file".to_string()),
        layers,
        connections: Vec::new(),
    }
}

/// Initializes without loading runtime plugins or the auth substrate because
/// [`default_stack_config`] names only the host's built-in `file` backend. This
/// invariant requires this wrapper to load runtime factories whenever the
/// canonical graph names a plugin-provided layer.
pub(crate) async fn run(
    state: &mut SessionState,
    path: &Path,
    force: bool,
    cancel: &CancellationToken,
) -> ovstorage::Result<()> {
    run_with_factories(state, path, force, Vec::new(), cancel).await
}

pub(crate) async fn run_with_factories(
    state: &mut SessionState,
    path: &Path,
    force: bool,
    factories: Vec<LoadedLayerFactory>,
    cancel: &CancellationToken,
) -> ovstorage::Result<()> {
    if !stack_is_unconfigured(state.stack.spec()) {
        return Err(Error::new(
            ErrorCode::AlreadyExists,
            "cannot init an already configured stack; --force only replaces the destination \
             file, not the loaded stack. Re-run with the global `--no-config` flag to write a \
             fresh minimal graph, or edit the loaded config (see docs/public/configuration.md)",
        ));
    }

    let config = default_stack_config();
    let stack =
        ovstorage::host::build_stack_with_cancel(&config, factories, Some(cancel.clone())).await?;
    let contents = config.to_toml_string()?;
    write_config_atomic(path, &contents, force, false)?;

    state.stack = stack;
    state.connections.clear();

    println!("wrote {}", path.display());
    for line in next_step_lines(path, state.interactive) {
        println!("{line}");
    }
    Ok(())
}

fn next_step_lines(path: &Path, interactive: bool) -> Vec<String> {
    let path = path.to_string_lossy();
    let write_config = shell_words::join(["write-config", path.as_ref(), "--force"]);
    if interactive {
        vec![
            "next: connect file <dir>".to_string(),
            format!("then: {write_config}"),
        ]
    } else {
        let reopen = shell_words::join(["ovstorage", "--config", path.as_ref()]);
        vec![
            format!("next: {reopen}"),
            "then in that shell: connect file <dir>".to_string(),
            format!("then in that shell: {write_config}"),
        ]
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ovstorage::ext::LayerExt;
    use ovstorage::{
        BackendFactory, LayerConfig, LayerHandle, LayerKindDescriptor, LayerType, StackConfig, Url,
    };

    use super::*;
    use crate::session::SessionConnection;

    async fn empty_state() -> SessionState {
        let config = StackConfig::default();
        let stack = ovstorage::host::build_stack(&config, crate::commands::test_layer_factories())
            .await
            .unwrap();
        SessionState::build(stack, config).await.unwrap()
    }

    #[test]
    fn default_config_is_file_layer_only() {
        let config = default_stack_config();
        assert_eq!(config.root.as_deref(), Some("file"));
        assert_eq!(config.layers.len(), 1);
        assert_eq!(config.layers.get("file"), Some(&LayerTable::default()));
        assert!(config.connections.is_empty());

        let emitted = config.to_toml_string().unwrap();
        assert!(emitted.contains("[ovstorage.layers.file]"));
        assert!(!emitted.contains("[[ovstorage.connections]]"));
    }

    #[test]
    fn interactive_next_steps_keep_connection_and_write_in_current_session() {
        assert_eq!(
            next_step_lines(Path::new("custom.toml"), true),
            [
                "next: connect file <dir>",
                "then: write-config custom.toml --force",
            ]
        );
    }

    #[test]
    fn one_shot_next_steps_reopen_custom_path_in_persistent_shell() {
        assert_eq!(
            next_step_lines(Path::new("custom.toml"), false),
            [
                "next: ovstorage --config custom.toml",
                "then in that shell: connect file <dir>",
                "then in that shell: write-config custom.toml --force",
            ]
        );
    }

    #[test]
    fn next_step_commands_shell_quote_the_config_path() {
        let path = Path::new("my config's $files.toml");
        let lines = next_step_lines(path, false);

        assert_eq!(
            shell_words::split(lines[0].strip_prefix("next: ").unwrap()).unwrap(),
            ["ovstorage", "--config", path.to_str().unwrap()]
        );
        assert_eq!(
            shell_words::split(lines[2].strip_prefix("then in that shell: ").unwrap()).unwrap(),
            ["write-config", path.to_str().unwrap(), "--force"]
        );
    }

    #[tokio::test]
    async fn init_opens_connect_gate_and_enables_write_config() {
        let tmp = tempfile::tempdir().unwrap();
        let init_path = tmp.path().join("ovstorage.toml");
        let written_path = tmp.path().join("written.toml");
        let mut state = empty_state().await;
        assert_eq!(state.stack.spec().root, "empty");

        run_with_factories(
            &mut state,
            &init_path,
            false,
            crate::commands::test_layer_factories(),
            &CancellationToken::new(),
        )
        .await
        .unwrap();

        let emitted = std::fs::read_to_string(&init_path).unwrap();
        let parsed = StackConfig::from_toml_str(&emitted).unwrap();
        assert_eq!(parsed.root.as_deref(), Some("file"));
        assert_eq!(parsed.layers.get("file"), Some(&LayerTable::default()));
        assert!(parsed.connections.is_empty());

        assert_eq!(state.stack.spec().root, "file");
        let backend_kinds = LayerExt::list_backend_kinds(state.stack.as_ref()).unwrap();
        assert!(
            backend_kinds
                .iter()
                .any(|descriptor| descriptor.kind == "file"),
            "init must make the built-in file backend visible to connect"
        );

        crate::commands::write_config::run(&state, &written_path, false, None).unwrap();
        assert!(written_path.exists());
    }

    #[tokio::test]
    async fn init_emitted_file_rebuilds_from_path() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("ovstorage.toml");
        let mut state = empty_state().await;

        run_with_factories(
            &mut state,
            &path,
            false,
            crate::commands::test_layer_factories(),
            &CancellationToken::new(),
        )
        .await
        .unwrap();

        let reparsed = StackConfig::from_toml_path(&path).unwrap();
        let rebuilt =
            ovstorage::host::build_stack(&reparsed, crate::commands::test_layer_factories())
                .await
                .unwrap();
        assert_eq!(rebuilt.spec().root, "file");
        assert_eq!(rebuilt.spec().layers.len(), 1);
        assert_eq!(rebuilt.spec().layers[0].kind, "file");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn init_writes_and_loads_minimal_stack_preserving_session_fields() {
        use std::os::unix::fs::PermissionsExt as _;

        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("ovstorage.toml");
        let mut state = empty_state().await;
        state.pwd = Some(Url::parse("file:///work/").unwrap());
        state.interactive = true;
        state.connections.push(SessionConnection {
            backend_kind: "stale".to_string(),
            target: None,
            display_name: None,
            config: HashMap::new(),
            credentials: HashMap::new(),
        });

        run_with_factories(
            &mut state,
            &path,
            false,
            crate::commands::test_layer_factories(),
            &CancellationToken::new(),
        )
        .await
        .unwrap();

        assert_eq!(state.stack.spec().root, "file");
        assert_eq!(state.stack.spec().layers[0].kind, "file");
        assert!(state.connections.is_empty());
        assert_eq!(state.pwd.as_ref().map(Url::as_str), Some("file:///work/"));
        assert!(state.interactive);

        let emitted = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            StackConfig::from_toml_str(&emitted).unwrap(),
            default_stack_config()
        );
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[tokio::test]
    async fn init_refuses_configured_stack_without_writing_or_mutating() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("ovstorage.toml");
        let config = default_stack_config();
        let stack = ovstorage::host::build_stack(&config, crate::commands::test_layer_factories())
            .await
            .unwrap();
        let mut state = SessionState::build(Arc::clone(&stack), config)
            .await
            .unwrap();
        state.pwd = Some(Url::parse("file:///configured/").unwrap());
        state.interactive = true;

        let err = run_with_factories(
            &mut state,
            &path,
            false,
            crate::commands::test_layer_factories(),
            &CancellationToken::new(),
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), ErrorCode::AlreadyExists);
        assert!(err.message().contains("--force"));
        assert!(err.message().contains("--no-config"));
        assert!(err.message().contains("docs/public/configuration.md"));
        assert!(!path.exists());
        assert!(Arc::ptr_eq(&state.stack, &stack));
        assert_eq!(
            state.pwd.as_ref().map(Url::as_str),
            Some("file:///configured/")
        );
        assert!(state.interactive);
    }

    #[tokio::test]
    async fn init_refuses_existing_file_without_swapping_stack() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("ovstorage.toml");
        std::fs::write(&path, "sentinel\n").unwrap();
        let mut state = empty_state().await;
        let original = Arc::clone(&state.stack);

        let err = run_with_factories(
            &mut state,
            &path,
            false,
            crate::commands::test_layer_factories(),
            &CancellationToken::new(),
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), ErrorCode::AlreadyExists);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "sentinel\n");
        assert!(Arc::ptr_eq(&state.stack, &original));
    }

    #[tokio::test]
    async fn init_force_replaces_existing_file_and_swaps_stack() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("ovstorage.toml");
        std::fs::write(&path, "sentinel\n").unwrap();
        let mut state = empty_state().await;
        let original = Arc::clone(&state.stack);

        run_with_factories(
            &mut state,
            &path,
            true,
            crate::commands::test_layer_factories(),
            &CancellationToken::new(),
        )
        .await
        .unwrap();

        let emitted = std::fs::read_to_string(&path).unwrap();
        assert_ne!(emitted, "sentinel\n");
        assert_eq!(
            StackConfig::from_toml_str(&emitted).unwrap(),
            default_stack_config()
        );
        assert!(!Arc::ptr_eq(&state.stack, &original));
        assert_eq!(state.stack.spec().root, "file");
    }

    struct DuplicateFileFactory;

    #[async_trait::async_trait]
    impl BackendFactory for DuplicateFileFactory {
        fn descriptor(&self) -> LayerKindDescriptor {
            LayerKindDescriptor {
                kind: "file".to_string(),
                layer_type: LayerType::Backend,
                display_name: "duplicate file".to_string(),
                description: None,
                config_schema: Vec::new(),
                credential_schema: Vec::new(),
                credential_methods: Vec::new(),
                icon: None,
                accepts_connections: false,
                auth_capable: false,
                supports_user_metadata: false,
            }
        }

        async fn create_backend(
            &self,
            _name: &str,
            _config: &LayerConfig,
            _cancel: Option<CancellationToken>,
        ) -> ovstorage::Result<LayerHandle> {
            unreachable!("duplicate factory must be rejected before construction")
        }
    }

    #[tokio::test]
    async fn failed_build_writes_nothing_and_keeps_session_stack() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("ovstorage.toml");
        let mut state = empty_state().await;
        let original = Arc::clone(&state.stack);
        let factories = vec![LoadedLayerFactory::Backend(Arc::new(DuplicateFileFactory))];

        let err = run_with_factories(
            &mut state,
            &path,
            false,
            factories,
            &CancellationToken::new(),
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert!(!path.exists());
        assert!(Arc::ptr_eq(&state.stack, &original));
    }
}
