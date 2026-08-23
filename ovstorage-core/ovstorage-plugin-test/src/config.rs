// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Connection-config parser and capability presets.

use std::collections::HashMap;

use ovstorage_plugin::{
    Capabilities, ChangeKindSet, ConfigField, ConfigFieldKind, ConfigValue, ConnectionRequest,
    Error, ErrorCode, RedirectCredential, Result, Url, address,
};

pub const BACKEND_KIND: &str = "test";
pub const ADDRESS_SCHEME: &str = "test";

/// Parsed `ConnectionRequest.config` map.
#[derive(Clone, Debug)]
pub struct TestConfig {
    pub root: Url,
    pub capabilities: Capabilities,

    pub redirect_url: Option<String>,
    pub multipart_parts: u32,
    pub continue_write_loops: u32,
    /// `Some(0)` emits already-expired redirects so tests cover the
    /// broker's "fetch fresh, cache survives expiry" path.
    pub redirect_ttl_seconds: Option<u64>,
    /// What this backend declares its redirects' credentials authorize, on both
    /// the read and the write path. Defaults to
    /// [`RedirectCredential::None`] — the test plugin's redirects carry no
    /// credential at all, since they point at a plain loopback responder.
    ///
    /// A host cannot recover this by inspecting a redirect, so it is the
    /// backend's declaration that drives a host's disclosure policy; this knob
    /// is how a test puts a host's gate in front of a declaration it would
    /// refuse.
    pub redirect_credential: RedirectCredential,
    pub write_returns_unsupported: bool,
    pub write_stream_returns_unsupported: bool,
    pub write_redirect_returns_unsupported: bool,

    pub auth_flow: AuthFlow,
    pub auth_drives_host_callbacks: bool,

    pub watch_event_count: u32,
    pub watch_lapsed_at: i32,
    /// Blocks after emitted events instead of returning `None`. Real
    /// backends never close watches naturally; broker-fanout tests
    /// need this to keep the fanout alive across subscribers.
    pub watch_keep_alive: bool,
    /// Pause this many ms before each emitted event (default 0 = emit
    /// immediately). A non-zero value gives concurrent subscribers a
    /// realistic registration window before event 0 lands, mirroring
    /// how real backends pace event emission.
    pub watch_emit_interval_ms: u64,

    /// Credential-gate mode: when set, `stat`/`read` of
    /// non-`__test_meta` paths fail `AuthRequired` unless the connection's
    /// stored bundle carries a `token` credential equal to this value.
    pub require_token: Option<String>,
    /// String knob `"true"`: `update_credentials` rejects with
    /// `Unsupported` (the gcs/azure/opendal "fixed at connection time"
    /// shape), forcing hosts onto the remove + re-add fallback.
    pub reject_credential_swap: bool,
    /// String knob `"true"`: connection add (`install_connection` /
    /// `instantiate`) rejects with `AuthRequired` when the incoming
    /// bundle's token mismatches `require_token` — enforced BEFORE any
    /// state mutation, so a rejected re-add leaves no ghost state.
    pub reject_bad_token_at_add: bool,
    /// String knob `"true"`: the layer's `probe` slot validates the probe
    /// request's OWN bundle against `require_token`, failing `AuthRequired`
    /// before any other probe behavior. Scripts the fail-safe
    /// "probe with candidate credentials" branch.
    pub probe_validates_token: bool,
    /// When set, `update_credentials` fails with this code instead of
    /// swapping the stored bundle (checked AFTER `reject_credential_swap`).
    /// Scripts the fail-safe error-mapping branches. Parsed
    /// eagerly so a typo'd code name fails loudly at connection add.
    pub update_credentials_error_code: Option<ErrorCode>,

    pub inject_error_on: Option<String>,
    pub inject_error_code: ErrorCode,
    pub inject_error_count: i32,

    pub watch_event_kind: WatchEventKind,

    pub check_access_decision: CheckAccessDecision,

    pub read_delay_ms: u64,
    /// `read` returns `Internal` when the target object key matches.
    /// Knob name predates the switch from panic to Err; see lib.rs.
    pub panic_on_read_key: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WatchEventKind {
    Created,
    Modified,
    Deleted,
    MetadataChanged,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckAccessDecision {
    Allow,
    DenyAll,
    ReadOnly,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthFlow {
    Succeed,
    Fail,
    Cancel,
    ProgressThenSucceed,
    OpenBrowserThenSucceed,
    DeviceCodeThenSucceed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapsPreset {
    Minimal,
    Full,
    ReadOnly,
    RedirectHeavy,
}

impl TestConfig {
    pub fn from_request(request: &ConnectionRequest) -> Result<Self> {
        let cfg = &request.config;
        let root_str = require_string(cfg, "test_root")?;
        let root = address::parse(&root_str).map_err(|err| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!("test_root '{root_str}' is not a valid address: {err}"),
            )
        })?;
        let scheme_prefix = format!("{ADDRESS_SCHEME}:");
        if !root.as_str().starts_with(&scheme_prefix) {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "test_root scheme must be '{ADDRESS_SCHEME}://', got '{}'",
                    root.as_str()
                ),
            ));
        }
        if !address::is_directory(&root) {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "test_root '{}' must be directory-form (trailing '/')",
                    root.as_str()
                ),
            ));
        }

        let preset = parse_caps_preset(cfg)?;
        let mut capabilities = capabilities_for_preset(preset);
        apply_caps_overrides(&mut capabilities, cfg)?;

        let redirect_url = optional_string(cfg, "test_redirect_url")?;
        let multipart_parts = optional_int(cfg, "test_multipart_parts")?
            .unwrap_or(0)
            .max(0) as u32;
        let continue_write_loops = optional_int(cfg, "test_continue_write_loops")?
            .unwrap_or(1)
            .max(1) as u32;
        let redirect_ttl_seconds =
            optional_int(cfg, "test_redirect_ttl_seconds")?.map(|n| n.max(0) as u64);
        let redirect_credential = parse_redirect_credential(cfg)?;
        let write_returns_unsupported =
            optional_bool(cfg, "test_write_returns_unsupported")?.unwrap_or(false);
        let write_stream_returns_unsupported =
            optional_bool(cfg, "test_write_stream_returns_unsupported")?.unwrap_or(false);
        let write_redirect_returns_unsupported =
            optional_bool(cfg, "test_write_redirect_returns_unsupported")?.unwrap_or(false);

        let auth_flow = parse_auth_flow(cfg)?;
        let auth_drives_host_callbacks =
            optional_bool(cfg, "test_auth_drives_host_callbacks")?.unwrap_or(false);

        let watch_event_count = optional_int(cfg, "test_watch_event_count")?
            .unwrap_or(0)
            .max(0) as u32;
        let watch_lapsed_at = optional_int(cfg, "test_watch_lapsed_at")?
            .unwrap_or(-1)
            .clamp(-1, i32::MAX as i64) as i32;
        let watch_keep_alive = optional_bool(cfg, "test_watch_keep_alive")?.unwrap_or(false);
        let watch_emit_interval_ms = optional_int(cfg, "test_watch_emit_interval_ms")?
            .unwrap_or(0)
            .max(0) as u64;

        let require_token = optional_string(cfg, "test_require_token")?;
        // String-typed knobs (not Bool): the pytest conftest coerces Python
        // `True` to `Int`, which `optional_bool` rejects — strings keep the
        // knobs reachable from every host. Strict parse so typos fail loud.
        let reject_credential_swap = optional_string_flag(cfg, "test_reject_credential_swap")?;
        let reject_bad_token_at_add = optional_string_flag(cfg, "test_reject_bad_token_at_add")?;
        let probe_validates_token = optional_string_flag(cfg, "test_probe_validates_token")?;
        let update_credentials_error_code =
            match optional_string(cfg, "test_update_credentials_error_code")? {
                Some(name) => Some(parse_error_code(&name)?),
                None => None,
            };

        let inject_error_on =
            optional_string(cfg, "test_inject_error_on")?.map(|s| s.to_lowercase());
        let inject_error_code = match optional_string(cfg, "test_inject_error_code")? {
            Some(name) => parse_error_code(&name)?,
            None => ErrorCode::Internal,
        };
        let inject_error_count = optional_int(cfg, "test_inject_error_count")?.unwrap_or(-1) as i32;
        let watch_event_kind = parse_watch_event_kind(cfg)?;
        let check_access_decision = parse_check_access_decision(cfg)?;
        let read_delay_ms = optional_int(cfg, "test_read_delay_ms")?.unwrap_or(0).max(0) as u64;
        let panic_on_read_key = optional_string(cfg, "test_panic_on_read_key")?;

        Ok(TestConfig {
            root,
            capabilities,
            redirect_url,
            multipart_parts,
            continue_write_loops,
            redirect_ttl_seconds,
            redirect_credential,
            write_returns_unsupported,
            write_stream_returns_unsupported,
            write_redirect_returns_unsupported,
            auth_flow,
            auth_drives_host_callbacks,
            require_token,
            reject_credential_swap,
            reject_bad_token_at_add,
            probe_validates_token,
            update_credentials_error_code,
            watch_event_count,
            watch_lapsed_at,
            watch_keep_alive,
            watch_emit_interval_ms,
            inject_error_on,
            inject_error_code,
            inject_error_count,
            watch_event_kind,
            check_access_decision,
            read_delay_ms,
            panic_on_read_key,
        })
    }
}

fn parse_watch_event_kind(cfg: &HashMap<String, ConfigValue>) -> Result<WatchEventKind> {
    match optional_string(cfg, "test_watch_event_kind")?.as_deref() {
        None | Some("created") => Ok(WatchEventKind::Created),
        Some("modified") => Ok(WatchEventKind::Modified),
        Some("deleted") => Ok(WatchEventKind::Deleted),
        Some("metadata-changed") | Some("metadata_changed") => Ok(WatchEventKind::MetadataChanged),
        Some(other) => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("unknown test_watch_event_kind: '{other}'"),
        )),
    }
}

fn parse_check_access_decision(cfg: &HashMap<String, ConfigValue>) -> Result<CheckAccessDecision> {
    match optional_string(cfg, "test_check_access_decision")?.as_deref() {
        None | Some("allow") => Ok(CheckAccessDecision::Allow),
        Some("deny-all") | Some("deny_all") => Ok(CheckAccessDecision::DenyAll),
        Some("read-only") | Some("read_only") => Ok(CheckAccessDecision::ReadOnly),
        Some(other) => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("unknown test_check_access_decision: '{other}'"),
        )),
    }
}

pub fn config_schema() -> Vec<ConfigField> {
    vec![
        ConfigField {
            key: "test_root".into(),
            display_name: "Test root".into(),
            kind: ConfigFieldKind::Url,
            required: true,
            default: None,
            help: Some("Address root, e.g. test://demo/".into()),
            example: Some("test://demo/".into()),
            group: Some("test".into()),
            advanced: false,
        },
        ConfigField {
            key: "test_caps".into(),
            display_name: "Capability preset".into(),
            kind: ConfigFieldKind::Text,
            required: false,
            default: Some(ConfigValue::String("minimal".into())),
            help: Some("One of: minimal | full | read-only | redirect-heavy".into()),
            example: Some("full".into()),
            group: Some("test".into()),
            advanced: false,
        },
        // Other knobs are accepted by the parser but tests build the map directly.
    ]
}

pub fn capabilities_for_preset(preset: CapsPreset) -> Capabilities {
    let mut caps = Capabilities::empty();
    // Universal baseline for every preset: every test plugin can do the
    // basic CRUD ops because the in-memory store backing it supports
    // them trivially. Optional / advanced bits (no-overwrite, version-
    // listing, server-side copy, etc.) are preset-specific. The
    // ReadOnly preset overrides this baseline to genuinely refuse
    // mutating ops.
    caps.supports_write = true;
    caps.supports_write_stream = true;
    caps.supports_write_redirect = true;
    caps.supports_delete = true;
    // Availability, not mechanism: the layer implements copy/rename for every
    // preset. `Full` additionally advertises the server-side mechanism bits.
    caps.supports_copy = true;
    caps.supports_rename = true;
    caps.supports_list = true;
    caps.supports_create_directory = true;
    caps.supports_delete_directory = true;
    match preset {
        CapsPreset::Minimal => {}
        CapsPreset::Full => {
            caps.supports_no_overwrite_write = true;
            caps.supports_if_match_write = true;
            caps.supports_native_metadata_patch = true;
            caps.writes_are_atomic = true;
            caps.supports_write = true;
            caps.supports_write_stream = true;
            caps.supports_write_redirect = true;
            caps.supports_delete = true;
            caps.supports_server_side_copy = true;
            caps.supports_server_side_rename = true;
            caps.supports_atomic_rename = true;
            caps.has_real_directories = true;
            caps.supports_list = true;
            caps.supports_recursive_list = true;
            caps.supports_create_directory = true;
            caps.supports_delete_directory = true;
            caps.populates_subdirectory_metadata = true;
            caps.supports_access_check = true;
            caps.supports_version_listing = true;
            caps.supports_watch_directory = true;
            caps.watch_directory_kinds = ChangeKindSet {
                created: true,
                modified: true,
                deleted: true,
                metadata_changed: true,
            };
        }
        CapsPreset::ReadOnly => {
            // Override the universal baseline above: a true read-only
            // preset must NOT advertise the write / delete / directory-
            // mutation bits. Callers using this preset rely on the
            // dispatcher gating those calls. supports_write_redirect
            // must be cleared too — otherwise the dispatcher would
            // still enter write_redirect / continue_write, and if a
            // redirect endpoint is configured the test plugin can
            // complete a write against the read-only contract.
            caps.supports_write = false;
            caps.supports_write_stream = false;
            caps.supports_write_redirect = false;
            caps.supports_delete = false;
            caps.supports_copy = false;
            caps.supports_rename = false;
            caps.supports_create_directory = false;
            caps.supports_delete_directory = false;
            caps.supports_recursive_list = true;
            caps.supports_list = true;
        }
        CapsPreset::RedirectHeavy => {
            caps.supports_recursive_list = true;
            caps.supports_list = true;
            caps.supports_write_redirect = true;
        }
    }
    caps
}

fn parse_caps_preset(cfg: &HashMap<String, ConfigValue>) -> Result<CapsPreset> {
    match optional_string(cfg, "test_caps")?.as_deref() {
        None | Some("minimal") => Ok(CapsPreset::Minimal),
        Some("full") => Ok(CapsPreset::Full),
        Some("read-only") | Some("read_only") => Ok(CapsPreset::ReadOnly),
        Some("redirect-heavy") | Some("redirect_heavy") => Ok(CapsPreset::RedirectHeavy),
        Some(other) => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("unknown test_caps preset: '{other}'"),
        )),
    }
}

fn apply_caps_overrides(caps: &mut Capabilities, cfg: &HashMap<String, ConfigValue>) -> Result<()> {
    if let Some(v) = optional_bool(cfg, "test_caps_versioning")? {
        caps.supports_version_listing = v;
    }
    if let Some(v) = optional_bool(cfg, "test_caps_server_copy")? {
        caps.supports_server_side_copy = v;
    }
    // Independent of the mechanism knob, so a scenario can express the shape
    // this vocabulary exists for: available but not server-side.
    if let Some(v) = optional_bool(cfg, "test_caps_copy")? {
        caps.supports_copy = v;
    }
    if let Some(v) = optional_bool(cfg, "test_caps_server_rename")? {
        caps.supports_server_side_rename = v;
    }
    if let Some(v) = optional_bool(cfg, "test_caps_rename")? {
        caps.supports_rename = v;
    }
    if let Some(v) = optional_bool(cfg, "test_caps_watch")? {
        caps.supports_watch_directory = v;
        if v && caps.watch_directory_kinds == ChangeKindSet::empty() {
            caps.watch_directory_kinds = ChangeKindSet {
                created: true,
                modified: true,
                deleted: true,
                metadata_changed: false,
            };
        }
    }
    // Comma-separated slot names whose capability bits flip off AFTER the
    // preset — the knob behind the `capability-gate-<op>-unsupported`
    // scenarios: advertise everything except one op, then prove the
    // backend self-gates that op with a typed `Unsupported`.
    if let Some(list) = optional_string(cfg, "test_caps_disable")? {
        for op in list.split(',').map(str::trim).filter(|op| !op.is_empty()) {
            match op {
                "write" => caps.supports_write = false,
                "write_stream" => caps.supports_write_stream = false,
                "write_redirect" => caps.supports_write_redirect = false,
                "delete" => caps.supports_delete = false,
                "list" => caps.supports_list = false,
                "list_versions" => caps.supports_version_listing = false,
                "create_directory" => caps.supports_create_directory = false,
                "delete_directory" => caps.supports_delete_directory = false,
                "update_metadata" => {
                    caps.supports_native_metadata_patch = false;
                    caps.supports_metadata_rewrite_emulation = false;
                }
                "check_access" => caps.supports_access_check = false,
                "watch_directory" => caps.supports_watch_directory = false,
                other => {
                    return Err(Error::new(
                        ErrorCode::InvalidArgument,
                        format!("unknown test_caps_disable op: '{other}'"),
                    ));
                }
            }
        }
    }
    Ok(())
}

fn parse_auth_flow(cfg: &HashMap<String, ConfigValue>) -> Result<AuthFlow> {
    match optional_string(cfg, "test_auth_flow")?.as_deref() {
        None | Some("succeed") => Ok(AuthFlow::Succeed),
        Some("fail") => Ok(AuthFlow::Fail),
        Some("cancel") => Ok(AuthFlow::Cancel),
        Some("progress-then-succeed") => Ok(AuthFlow::ProgressThenSucceed),
        Some("open-browser-then-succeed") => Ok(AuthFlow::OpenBrowserThenSucceed),
        Some("device-code-then-succeed") => Ok(AuthFlow::DeviceCodeThenSucceed),
        Some(other) => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("unknown test_auth_flow: '{other}'"),
        )),
    }
}

/// Parse `test_redirect_credential` into the declaration this backend stamps on
/// every redirect it mints. Absent means [`RedirectCredential::None`]: the test
/// plugin's redirects point at a plain loopback responder and carry nothing
/// reusable.
fn parse_redirect_credential(cfg: &HashMap<String, ConfigValue>) -> Result<RedirectCredential> {
    match optional_string(cfg, "test_redirect_credential")?.as_deref() {
        None | Some("none") => Ok(RedirectCredential::None),
        Some("unspecified") => Ok(RedirectCredential::Unspecified),
        Some("request") => Ok(RedirectCredential::Request),
        Some("connection") => Ok(RedirectCredential::Connection),
        Some(other) => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("unknown test_redirect_credential: '{other}'"),
        )),
    }
}

fn parse_error_code(name: &str) -> Result<ErrorCode> {
    use ErrorCode::*;
    let code = match name {
        "NotFound" => NotFound,
        "AlreadyExists" => AlreadyExists,
        "PermissionDenied" => PermissionDenied,
        "PreconditionFailed" => PreconditionFailed,
        "Conflict" => Conflict,
        "DirectoryNotEmpty" => DirectoryNotEmpty,
        "Unsupported" => Unsupported,
        "InvalidArgument" => InvalidArgument,
        "IncompatibleType" => IncompatibleType,
        "Locked" => Locked,
        "Cancelled" => Cancelled,
        "DeadlineExceeded" => DeadlineExceeded,
        "Transient" => Transient,
        "ResourceExhausted" => ResourceExhausted,
        "IntegrityFailure" => IntegrityFailure,
        "Internal" => Internal,
        "BrokerUnavailable" => BrokerUnavailable,
        "BrokerRequired" => BrokerRequired,
        "RedirectExpired" => RedirectExpired,
        "PolicyEpochStale" => PolicyEpochStale,
        "AuthorizationLeaseExpired" => AuthorizationLeaseExpired,
        "CacheCorrupt" => CacheCorrupt,
        "StagingExpired" => StagingExpired,
        "CommitAmbiguous" => CommitAmbiguous,
        "CacheLockContention" => CacheLockContention,
        "StateRootUnavailable" => StateRootUnavailable,
        "NetworkFilesystemRefused" => NetworkFilesystemRefused,
        "ObjectModified" => ObjectModified,
        "NoRoute" => NoRoute,
        "RouteConflict" => RouteConflict,
        "NotConfigured" => NotConfigured,
        "AliasChainTooLong" => AliasChainTooLong,
        "CredentialExpired" => CredentialExpired,
        "CredentialUnavailable" => CredentialUnavailable,
        "AuthRequired" => AuthRequired,
        "AuthCancelled" => AuthCancelled,
        "AuthExpired" => AuthExpired,
        "ContentMismatch" => ContentMismatch,
        "ContentChecksumMismatch" => ContentChecksumMismatch,
        other => {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!("unknown test_inject_error_code: '{other}'"),
            ));
        }
    };
    Ok(code)
}

fn require_string(cfg: &HashMap<String, ConfigValue>, key: &str) -> Result<String> {
    match cfg.get(key) {
        Some(ConfigValue::String(s)) => Ok(s.clone()),
        Some(other) => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("{key} must be a String, got {other:?}"),
        )),
        None => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("{key} is required"),
        )),
    }
}

fn optional_string(cfg: &HashMap<String, ConfigValue>, key: &str) -> Result<Option<String>> {
    match cfg.get(key) {
        Some(ConfigValue::String(s)) => Ok(Some(s.clone())),
        Some(other) => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("{key} must be a String, got {other:?}"),
        )),
        None => Ok(None),
    }
}

/// A String-typed boolean knob: `"true"`/`"false"` (absent = false). Kept
/// String rather than Bool so it survives hosts that coerce Python bools to
/// `Int` (see `from_request`); any other value is a loud typo error.
fn optional_string_flag(cfg: &HashMap<String, ConfigValue>, key: &str) -> Result<bool> {
    match optional_string(cfg, key)?.as_deref() {
        None | Some("false") => Ok(false),
        Some("true") => Ok(true),
        Some(other) => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("{key} must be \"true\" or \"false\", got \"{other}\""),
        )),
    }
}

fn optional_bool(cfg: &HashMap<String, ConfigValue>, key: &str) -> Result<Option<bool>> {
    match cfg.get(key) {
        Some(ConfigValue::Bool(b)) => Ok(Some(*b)),
        Some(other) => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("{key} must be a Bool, got {other:?}"),
        )),
        None => Ok(None),
    }
}

fn optional_int(cfg: &HashMap<String, ConfigValue>, key: &str) -> Result<Option<i64>> {
    match cfg.get(key) {
        Some(ConfigValue::Int(n)) => Ok(Some(*n)),
        Some(other) => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("{key} must be an Int, got {other:?}"),
        )),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ovstorage_plugin::SecretBundle;

    fn req(config: HashMap<String, ConfigValue>) -> ConnectionRequest {
        ConnectionRequest {
            backend_kind: BACKEND_KIND.into(),
            config,
            credentials: SecretBundle::default(),
            persist: false,
            display_name: None,
        }
    }

    fn with_root() -> HashMap<String, ConfigValue> {
        let mut c = HashMap::new();
        c.insert(
            "test_root".into(),
            ConfigValue::String("test://demo/".into()),
        );
        c
    }

    #[test]
    fn rejects_missing_root() {
        let err = TestConfig::from_request(&req(HashMap::new())).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    #[test]
    fn rejects_wrong_scheme() {
        let mut c = HashMap::new();
        c.insert("test_root".into(), ConfigValue::String("file:///x".into()));
        let err = TestConfig::from_request(&req(c)).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    #[test]
    fn rejects_non_directory_root() {
        let mut c = HashMap::new();
        c.insert(
            "test_root".into(),
            ConfigValue::String("test://demo/foo".into()),
        );
        let err = TestConfig::from_request(&req(c)).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    #[test]
    fn parses_a_nested_directory_root() {
        // The directory-form requirement at `from_request` is spelling-based,
        // so it is sensitive to the path-canonicalization rule — but only for
        // a root BELOW the authority. An authority root (`test://demo/`) has
        // path `/`, which the trailing-slash rule leaves alone; a nested root
        // loses its slash and would stop satisfying `address::is_directory`.
        // Pinned here so that flip is visible in the diff rather than silent.
        let mut c = HashMap::new();
        c.insert(
            "test_root".into(),
            ConfigValue::String("test://demo/sub/".into()),
        );
        let cfg = TestConfig::from_request(&req(c)).unwrap();
        assert_eq!(cfg.root.as_str(), "test://demo/sub/");
    }

    #[test]
    fn parses_minimal_config_with_just_root() {
        let cfg = TestConfig::from_request(&req(with_root())).unwrap();
        assert_eq!(cfg.root.as_str(), "test://demo/");
        assert_eq!(cfg.multipart_parts, 0);
        assert_eq!(cfg.continue_write_loops, 1);
        assert_eq!(cfg.auth_flow, AuthFlow::Succeed);
        assert_eq!(cfg.inject_error_count, -1);
    }

    #[test]
    fn parses_full_caps_preset_with_overrides() {
        let mut c = with_root();
        c.insert("test_caps".into(), ConfigValue::String("full".into()));
        c.insert("test_caps_versioning".into(), ConfigValue::Bool(false));
        let cfg = TestConfig::from_request(&req(c)).unwrap();
        assert!(cfg.capabilities.supports_server_side_copy);
        assert!(!cfg.capabilities.supports_version_listing);
    }

    #[test]
    fn parses_redirect_and_multipart_knobs() {
        let mut c = with_root();
        c.insert(
            "test_redirect_url".into(),
            ConfigValue::String("https://test.example/".into()),
        );
        c.insert("test_multipart_parts".into(), ConfigValue::Int(3));
        c.insert("test_continue_write_loops".into(), ConfigValue::Int(2));
        let cfg = TestConfig::from_request(&req(c)).unwrap();
        assert_eq!(cfg.redirect_url.as_deref(), Some("https://test.example/"));
        assert_eq!(cfg.multipart_parts, 3);
        assert_eq!(cfg.continue_write_loops, 2);
        assert_eq!(cfg.redirect_credential, RedirectCredential::None);
    }

    /// The declaration a host's disclosure policy reads. Absent means `None`
    /// rather than `Unspecified`: this plugin's redirects point at a plain
    /// loopback responder, so the honest declaration is that they carry no
    /// credential — and a test that wants a host to refuse must say so out
    /// loud rather than getting a refusal from an unset field.
    #[test]
    fn parses_the_redirect_credential_declaration() {
        for (spelling, expected) in [
            ("none", RedirectCredential::None),
            ("unspecified", RedirectCredential::Unspecified),
            ("request", RedirectCredential::Request),
            ("connection", RedirectCredential::Connection),
        ] {
            let mut c = with_root();
            c.insert(
                "test_redirect_credential".into(),
                ConfigValue::String(spelling.into()),
            );
            assert_eq!(
                TestConfig::from_request(&req(c))
                    .unwrap()
                    .redirect_credential,
                expected,
                "test_redirect_credential = {spelling:?}"
            );
        }

        let mut c = with_root();
        c.insert(
            "test_redirect_credential".into(),
            ConfigValue::String("broad".into()),
        );
        assert_eq!(
            TestConfig::from_request(&req(c)).unwrap_err().code(),
            ErrorCode::InvalidArgument,
        );
    }

    #[test]
    fn parses_inject_error_knobs() {
        let mut c = with_root();
        c.insert(
            "test_inject_error_on".into(),
            ConfigValue::String("read".into()),
        );
        c.insert(
            "test_inject_error_code".into(),
            ConfigValue::String("Transient".into()),
        );
        c.insert("test_inject_error_count".into(), ConfigValue::Int(2));
        let cfg = TestConfig::from_request(&req(c)).unwrap();
        assert_eq!(cfg.inject_error_on.as_deref(), Some("read"));
        assert_eq!(cfg.inject_error_code, ErrorCode::Transient);
        assert_eq!(cfg.inject_error_count, 2);
    }

    #[test]
    fn rejects_unknown_error_code() {
        let mut c = with_root();
        c.insert(
            "test_inject_error_code".into(),
            ConfigValue::String("Bogus".into()),
        );
        let err = TestConfig::from_request(&req(c)).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    #[test]
    fn read_only_preset_clears_every_mutating_bit() {
        let caps = capabilities_for_preset(CapsPreset::ReadOnly);
        // Read paths stay on.
        assert!(caps.supports_list, "ReadOnly must keep supports_list");
        // Every mutating bit must be cleared so the dispatcher gating
        // refuses the call before it reaches the plugin. Notably
        // supports_write_redirect — if left set, the plugin's
        // write_redirect / continue_write path could complete a write
        // against the read-only contract when test_redirect_url is
        // configured.
        assert!(!caps.supports_write, "ReadOnly must clear supports_write");
        assert!(
            !caps.supports_write_stream,
            "ReadOnly must clear supports_write_stream"
        );
        assert!(
            !caps.supports_write_redirect,
            "ReadOnly must clear supports_write_redirect"
        );
        assert!(!caps.supports_delete, "ReadOnly must clear supports_delete");
        assert!(
            !caps.supports_create_directory,
            "ReadOnly must clear supports_create_directory"
        );
        assert!(
            !caps.supports_delete_directory,
            "ReadOnly must clear supports_delete_directory"
        );
        assert!(
            !caps.supports_server_side_copy,
            "ReadOnly must not advertise server-side copy"
        );
        assert!(
            !caps.supports_server_side_rename,
            "ReadOnly must not advertise server-side rename"
        );
        assert!(
            !caps.supports_native_metadata_patch,
            "ReadOnly must not advertise metadata patch"
        );
    }

    #[test]
    fn parses_each_auth_flow() {
        for (name, expected) in [
            ("succeed", AuthFlow::Succeed),
            ("fail", AuthFlow::Fail),
            ("cancel", AuthFlow::Cancel),
            ("progress-then-succeed", AuthFlow::ProgressThenSucceed),
            (
                "open-browser-then-succeed",
                AuthFlow::OpenBrowserThenSucceed,
            ),
            ("device-code-then-succeed", AuthFlow::DeviceCodeThenSucceed),
        ] {
            let mut c = with_root();
            c.insert("test_auth_flow".into(), ConfigValue::String(name.into()));
            let cfg = TestConfig::from_request(&req(c)).unwrap();
            assert_eq!(cfg.auth_flow, expected, "auth_flow={name}");
        }
    }
}
