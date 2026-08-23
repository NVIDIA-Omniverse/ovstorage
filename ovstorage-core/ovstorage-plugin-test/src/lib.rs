// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![doc = include_str!("../README.md")]

mod config;
pub mod layer;
pub mod recorder;
pub mod responder;
pub mod runner;
pub mod scenarios;
pub mod scripted_http;
mod store;
pub mod streaming;

pub use layer::{TEST_LAYER_NO_ROUTE_NEXT_ACTION, TestLayer, TestLayerFactory};
pub use recorder::{ObservedCall, Recorder};
pub use responder::{CapturedRequest, Responder, Route, ScriptedResponse};
pub use scripted_http::{CannedHttpResponse, ScriptedHttpServer, request_has_header};

/// Start a loopback [`Responder`] and return it with the
/// `(config-key, config-value)` pair that points the test backend's
/// redirect emission at the responder.
pub fn start_responder_with_redirect(
    routes: Vec<Route>,
) -> std::io::Result<(Responder, (&'static str, ConfigValue))> {
    let responder = Responder::start(routes)?;
    let url = responder.base_url();
    Ok((responder, ("test_redirect_url", ConfigValue::String(url))))
}
pub use runner::{ConformanceReport, ScenarioOutcome, ScenarioReport, ScenarioRunner};
pub use scenarios::{
    CAPABILITY_GATE_SCENARIOS, CONFORMANCE_ADDRESS_SCHEME, ExpectedCall, FailureContract, Profile,
    Scenario, ScenarioRegistry,
};

use std::sync::{Arc, Mutex};

use ovstorage_plugin::address;
use ovstorage_plugin::*;

pub use crate::config::{ADDRESS_SCHEME, BACKEND_KIND, TestConfig};
use crate::store::{StoredObject, TestStore};

const META_PREFIX: &str = "__test_meta/";
const META_METHOD_CALLS: &str = "method_calls.json";
// Ordered observation log for negative assertions ("must NOT call X");
// the counter map only knows totals.
const META_CALLS: &str = "calls.json";
const META_REDIRECT_EXPIRED: &str = "redirect_expired";

/// Factory for the test backend. Per-root state survives
/// reinstantiation so config knobs can change between calls without
/// dropping the in-memory store.
pub struct TestFactory {
    instances: Mutex<std::collections::HashMap<String, Arc<TestInstance>>>,
}

pub(crate) struct TestInstance {
    pub cfg: Mutex<TestConfig>,
    pub store: Mutex<TestStore>,
    pub recorder: Recorder,
    /// The connection's current `SecretBundle` — what the
    /// `test_require_token` gate reads. Per-root, like the
    /// instance itself: connection add overwrites it unconditionally
    /// (the instance survives `remove_connection`, so a re-add must not
    /// inherit a stale bundle) and `update_credentials` swaps it.
    pub credentials: Mutex<SecretBundle>,
}

impl TestInstance {
    fn new(cfg: TestConfig) -> Self {
        Self {
            cfg: Mutex::new(cfg),
            store: Mutex::new(TestStore::new()),
            recorder: Recorder::new(),
            credentials: Mutex::new(SecretBundle::default()),
        }
    }
}

/// The comparable byte content of a credential value, for the
/// `test_require_token` gate's equality check.
fn secret_value_token_bytes(value: &SecretValue) -> &[u8] {
    match value {
        SecretValue::Bytes(bytes) | SecretValue::File(bytes) => &bytes.0,
        SecretValue::OAuthToken { token, .. } => &token.0,
        SecretValue::MtlsCertPair { cert_pem, .. } => &cert_pem.0,
        SecretValue::SystemIdentity => &[],
    }
}

/// Does `credentials` satisfy `cfg`'s `test_require_token` gate? Vacuously
/// true when the gate is not configured.
fn token_matches(cfg: &TestConfig, credentials: &SecretBundle) -> bool {
    let Some(expected) = cfg.require_token.as_deref() else {
        return true;
    };
    credentials
        .fields
        .get("token")
        .is_some_and(|value| secret_value_token_bytes(value) == expected.as_bytes())
}

impl TestFactory {
    pub fn new() -> Self {
        Self {
            instances: Mutex::new(std::collections::HashMap::new()),
        }
    }

    // Most-recent cfg wins; bytes and counters survive.
    fn shared_instance(&self, cfg: TestConfig) -> Arc<TestInstance> {
        let mut map = self.instances.lock().expect("test-plugin instance map");
        let key = cfg.root.as_str().to_string();
        if let Some(existing) = map.get(&key).cloned() {
            *existing.cfg.lock().expect("instance cfg") = cfg;
            existing
        } else {
            let inst = Arc::new(TestInstance::new(cfg));
            map.insert(key, inst.clone());
            inst
        }
    }

    fn lookup_instance(&self, root: &Url) -> Option<Arc<TestInstance>> {
        self.instances.lock().ok()?.get(root.as_str()).cloned()
    }

    /// Clone the [`Recorder`] for `root`, or `None` if no instance has
    /// been minted yet.
    pub fn recorder_for(&self, root: &Url) -> Option<Recorder> {
        self.lookup_instance(root).map(|i| i.recorder.clone())
    }
}

impl Default for TestFactory {
    fn default() -> Self {
        Self::new()
    }
}

impl TestFactory {
    fn descriptor(&self) -> StorageBackendKindDescriptor {
        StorageBackendKindDescriptor {
            kind: BACKEND_KIND.into(),
            display_name: "Test backend".into(),
            description: Some(
                "Configurable in-memory backend for ovstorage SPI edge-case tests \
                 (redirects, multipart, auth flows, watch streams, error injection)."
                    .into(),
            ),
            config_schema: config::config_schema(),
            credential_schema: vec![],
            credential_methods: Vec::new(),
            icon: None,
            supports_runtime_add: true,
            // For an ordinary object key, the buffered and streaming write
            // paths keep a write's `user_metadata` and `stat` returns it, so
            // this kind declares `true`: a host that attributes composes its
            // attribution layer over a declaring kind's branches. (A
            // `__test_meta/...` write is the knob channel rather than an object
            // write, and stores none.)
            // The declaration answers for the kind, not for one write slot, and
            // this backend's slots disagree — the redirect path does not keep
            // the key: `write_redirect` does not read its options and
            // `continue_write` commits an object rebuilt from the
            // continuation's bytes. Dropping the key rather than refusing the
            // write is the part that breaks the conformance rule, and it is
            // tracked separately. Declaring `false` would not fix it; it would
            // give up attribution on the two slots that do keep the key.
            supports_user_metadata: true,
        }
    }

    #[cfg(test)]
    async fn instantiate(
        &self,
        request: &ConnectionRequest,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let _ = &cancel; // conformance plugin op: this method body has no async work to cancel.
        let cfg = TestConfig::from_request(request)?;
        // Add-time gate, enforced BEFORE any state mutation (the instance
        // map included): a rejected add must leave no ghost state.
        if cfg.reject_bad_token_at_add && !token_matches(&cfg, &request.credentials) {
            return Err(Error::new(
                ErrorCode::AuthRequired,
                "test-plugin: test_reject_bad_token_at_add: connection credentials do not \
                 carry the required 'token'",
            ));
        }
        let instance = self.shared_instance(cfg);
        // The connection's live bundle — unconditionally overwritten so a
        // re-add cannot inherit a stale bundle from the surviving instance.
        *instance.credentials.lock().expect("instance credentials") = request.credentials.clone();
        Ok(())
    }

    async fn update_credentials(
        &self,
        connection: &Connection,
        credentials: SecretBundle,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let _ = &cancel; // conformance plugin op: this method body has no async work to cancel.
        let root = connection.current_addresses.first().ok_or_else(|| {
            Error::new(
                ErrorCode::InvalidArgument,
                "test-plugin: update_credentials called without a current address",
            )
        })?;
        let instance = self.lookup_instance(root).ok_or_else(|| {
            Error::new(
                ErrorCode::NotFound,
                format!("test-plugin: no instance for root '{root}'"),
            )
        })?;
        let cfg = instance.cfg.lock().expect("instance cfg").clone();
        if cfg.reject_credential_swap {
            // The gcs/azure/opendal shape: credentials are fixed at
            // connection time; hosts must remove and re-add.
            return Err(Error::new(
                ErrorCode::Unsupported,
                "test-plugin: test_reject_credential_swap: credentials are fixed at \
                 connection time; remove the connection and re-add it",
            ));
        }
        if let Some(code) = cfg.update_credentials_error_code {
            // Scripted failure with an arbitrary code, so hosts can exercise
            // their update_credentials error mapping (fail-safe
            // branches) without a real backend fault.
            return Err(Error::new(
                code,
                "test-plugin: test_update_credentials_error_code: scripted \
                 update_credentials failure",
            ));
        }
        *instance.credentials.lock().expect("instance credentials") = credentials;
        Ok(())
    }

    async fn authenticate(
        &self,
        connection: Connection,
        _capability: InteractiveAuthCapability,
        cancel: Option<CancellationToken>,
    ) -> Result<AuthEventStream> {
        let _ = &cancel; // conformance plugin op: this method body has no async work to cancel.
        let root = connection
            .current_addresses
            .first()
            .ok_or_else(|| {
                Error::new(
                    ErrorCode::InvalidArgument,
                    "test-plugin: authenticate called without a current address",
                )
            })?
            .clone();
        let Some(instance) = self.lookup_instance(&root) else {
            // No prior instantiate: emit `Succeeded` to drive the HOST's
            // success path, which is what this fixture exists to exercise.
            //
            // This is deliberately NOT the pattern
            // `ConnectionAuthDriver::interactive` prescribes for a real driver
            // with no interactive flow — that one answers
            // `ErrorCode::Unsupported`, because a terminal `Succeeded` promotes
            // the connection to `Authenticated`. A backend plugin copying this
            // line would launder a refused credential; a host harness asserting
            // on the promotion needs it.
            return Ok(Box::new(std::iter::once(Ok(AuthEvent::Succeeded {
                connection: Box::new(connection),
                credentials: None,
            }))));
        };
        let cfg = instance.cfg.lock().expect("instance cfg").clone();
        instance.store.lock().expect("store").bump("authenticate");
        if cfg.auth_drives_host_callbacks {
            drive_host_callbacks(&connection)?;
        }
        Ok(synthesize_auth_stream(cfg.auth_flow, connection))
    }
}

/// Backend handle.
pub struct TestBackend {
    instance: Arc<TestInstance>,
}

impl TestBackend {
    fn cfg(&self) -> TestConfig {
        self.instance.cfg.lock().expect("instance cfg").clone()
    }

    /// The `test_require_token` credential gate. Callers
    /// exempt `__test_meta/*` paths BEFORE this check — the observability
    /// channel must survive gating.
    fn check_credential_gate(&self) -> Result<()> {
        let cfg = self.cfg();
        if token_matches(
            &cfg,
            &self
                .instance
                .credentials
                .lock()
                .expect("instance credentials"),
        ) {
            return Ok(());
        }
        Err(Error::new(
            ErrorCode::AuthRequired,
            "test-plugin: test_require_token: connection credentials do not carry the \
             required 'token'",
        ))
    }

    fn relative_key(&self, address: &Url) -> Result<String> {
        let cfg = self.cfg();
        match ovstorage_plugin::address::relative_suffix(address, &cfg.root) {
            Some(rest) => Ok(rest.to_string()),
            None => Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "test-plugin: target {} is outside the configured root {}",
                    address.as_str(),
                    cfg.root.as_str()
                ),
            )),
        }
    }

    fn meta_payload(&self, key: &str) -> Option<Vec<u8>> {
        let suffix = key.strip_prefix(META_PREFIX)?;
        match suffix {
            META_METHOD_CALLS => {
                let store = self.instance.store.lock().ok()?;
                Some(store.counters.as_json().into_bytes())
            }
            META_CALLS => Some(render_calls_json(&self.instance.recorder.snapshot())),
            META_REDIRECT_EXPIRED => {
                let store = self.instance.store.lock().ok()?;
                Some(if store.redirect_force_expired {
                    b"true".to_vec()
                } else {
                    b"false".to_vec()
                })
            }
            _ => None,
        }
    }

    /// Apply a buffered write to a `__test_meta/...` control path. The caller
    /// buffers the body first (a `Body::Bytes` write already has it; a streamed
    /// write drains its chunks) so the knob fires regardless of how the host
    /// framed the body. Only called for keys under [`META_PREFIX`].
    fn meta_write(&self, key: &str, bytes: Vec<u8>, address: Url) -> Result<WriteResult> {
        let suffix = key
            .strip_prefix(META_PREFIX)
            .expect("meta_write called only for __test_meta paths");
        if suffix == META_REDIRECT_EXPIRED {
            let value = std::str::from_utf8(&bytes).map(str::trim).unwrap_or("");
            let new_state = matches!(value, "true" | "1");
            let mut store = self.instance.store.lock().expect("store");
            store.redirect_force_expired = new_state;
            let info = StoredObject::new(bytes).info(address);
            return Ok(WriteResult { info });
        }
        Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("test-plugin: {META_PREFIX}{suffix} is read-only"),
        ))
    }

    // Recorder append happens before injection so injected errors still
    // leave a recorded call.
    fn enter_recorded(&self, method: &str, observation: Option<ObservedCall>) -> Result<()> {
        if let Some(call) = observation {
            self.instance.recorder.observe(call);
        }
        self.bump_and_inject(method)
    }

    fn bump_and_inject(&self, method: &str) -> Result<()> {
        let cfg = self.cfg();
        let mut store = self.instance.store.lock().expect("store");
        store.bump(method);
        let Some(target) = cfg.inject_error_on.as_deref() else {
            return Ok(());
        };
        if target != method {
            return Ok(());
        }
        let count = store.injections.entry(method.to_string()).or_insert(0);
        if cfg.inject_error_count >= 0 && *count >= cfg.inject_error_count as u64 {
            return Ok(());
        }
        *count += 1;
        Err(Error::new(
            cfg.inject_error_code,
            format!(
                "test-plugin: injected {:?} on {method} (#{count})",
                cfg.inject_error_code
            ),
        ))
    }

    fn commit_bytes(
        &self,
        address: Url,
        key: String,
        bytes: Vec<u8>,
        opts: WriteOptions,
    ) -> Result<WriteResult> {
        let mut store = self.instance.store.lock().expect("store");
        match &opts.if_dest {
            IfDestExists::Overwrite => {}
            IfDestExists::Fail => {
                if store.current(&key).is_some() {
                    return Err(Error::new(
                        ErrorCode::AlreadyExists,
                        "test-plugin: if_dest=Fail: write target already exists",
                    ));
                }
            }
            IfDestExists::MatchEtag(expected) => match store.current(&key) {
                Some(existing) => check_etag(expected, &existing.etag())?,
                None => {
                    return Err(Error::new(
                        ErrorCode::NotFound,
                        "test-plugin: if_dest=MatchEtag: write target does not exist",
                    ));
                }
            },
        }
        let object =
            StoredObject::new(bytes).with_user_metadata(opts.user_metadata.unwrap_or_default());
        let info = object.info(address);
        store.put(key, object);
        Ok(WriteResult { info })
    }
}

impl TestBackend {
    async fn stat(
        &self,
        target: ResolvedTarget,
        _opts: StatOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        let _ = &cancel; // conformance plugin op: this method body has no async work to cancel.
        self.enter_recorded(
            "stat",
            Some(ObservedCall::Stat {
                target: target.resolved_address.clone(),
            }),
        )?;
        let key = self.relative_key(&target.resolved_address)?;
        if let Some(bytes) = self.meta_payload(&key) {
            let synthetic = StoredObject::new(bytes);
            return Ok(synthetic.info(target.resolved_address));
        }
        self.check_credential_gate()?;
        let store = self.instance.store.lock().expect("store");
        store
            .current(&key)
            .map(|obj| obj.info(target.resolved_address.clone()))
            .ok_or_else(|| Error::new(ErrorCode::NotFound, format!("test://.../{key}")))
    }

    async fn read(
        &self,
        target: ResolvedTarget,
        opts: ReadOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ReadResult> {
        let key = self.relative_key(&target.resolved_address)?;
        // Returns Err rather than panicking: the host-error-handling
        // contract is exercised deterministically via Err. A genuine
        // panic here would surface as Internal too (the FFI thunk's
        // `catch_unwind` wall converts it), so this stays an Err knob.
        // Knob name kept for source compat.
        if let Some(panic_key) = self.cfg().panic_on_read_key.as_deref()
            && key == panic_key
        {
            return Err(Error::new(
                ErrorCode::Internal,
                "test-plugin: panic_on_read_key triggered",
            ));
        }
        // Cooperatively delays so a host-side cancel can race the work.
        let delay_ms = self.cfg().read_delay_ms;
        if delay_ms > 0 {
            let delay = std::time::Duration::from_millis(delay_ms);
            if let Some(token) = &cancel {
                tokio::select! {
                    biased;
                    _ = token.cancelled() => {
                        return Err(Error::new(ErrorCode::Cancelled, "test-plugin: cancelled by host"));
                    }
                    _ = tokio::time::sleep(delay) => {}
                }
            } else {
                tokio::time::sleep(delay).await;
            }
        }
        // Introspection reads bypass injection; bump before materializing
        // so the payload includes this very read.
        if key.starts_with(META_PREFIX) {
            self.instance.store.lock().expect("store").bump("read");
            let bytes = self.meta_payload(&key).ok_or_else(|| {
                Error::new(
                    ErrorCode::NotFound,
                    format!("test-plugin: unknown {META_PREFIX} path: {key}"),
                )
            })?;
            let synthetic = StoredObject::new(bytes.clone());
            return Ok(ReadResult::Bytes {
                bytes,
                info: synthetic.info(target.resolved_address),
            });
        }
        self.enter_recorded(
            "read",
            Some(ObservedCall::Read {
                target: target.resolved_address.clone(),
            }),
        )?;
        // After the `__test_meta` branch above: the observability channel
        // must survive gating.
        self.check_credential_gate()?;
        let cfg = self.cfg();
        // Real-directories mode mirrors the file backend's read semantics:
        // reading a directory (explicit or an implicit parent of stored
        // objects) with the object op is a type mismatch with guidance, not
        // NotFound and not a handle the caller cannot open. Directory
        // identities are stored slash-free, so fold both spellings onto the
        // slash-free leaf — `FileBackend` refuses either one. Ahead of the
        // redirect branch: the contract holds on every configuration, so a
        // redirect-enabled connection must not answer a directory with a
        // redirect (nor `materialize`, which rides this read, with the
        // Unsupported that follows one). The lock is short-lived so the
        // redirect below still builds without holding it.
        if cfg.capabilities.has_real_directories
            && self
                .instance
                .store
                .lock()
                .expect("store")
                .is_directory(key.trim_end_matches('/'))
        {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "test-plugin: read target is a directory; use list()",
            ));
        }
        if let Some(base) = cfg.redirect_url.as_deref() {
            let force_expired = self
                .instance
                .store
                .lock()
                .map(|s| s.redirect_force_expired)
                .unwrap_or(false);
            let ttl = if force_expired {
                Some(0)
            } else {
                cfg.redirect_ttl_seconds
            };
            return Ok(ReadResult::Redirect(build_read_redirect(
                base,
                &target.resolved_address,
                &key,
                ttl,
                cfg.redirect_credential,
            )));
        }
        let store = self.instance.store.lock().expect("store");
        let obj = store
            .current(&key)
            .ok_or_else(|| Error::new(ErrorCode::NotFound, format!("test://.../{key}")))?;
        if let Some(expected) = opts.if_match.as_deref() {
            check_etag(expected, &obj.etag())?;
        }
        let bytes = match opts.range {
            Some(range) => slice_range(&obj.bytes, &range)?,
            None => obj.bytes.clone(),
        };
        Ok(ReadResult::Bytes {
            bytes,
            info: obj.info(target.resolved_address),
        })
    }

    async fn write(
        &self,
        target: ResolvedTarget,
        bytes: Vec<u8>,
        opts: WriteOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        let _ = &cancel; // conformance plugin op: this method body has no async work to cancel.
        self.enter_recorded(
            "write",
            Some(ObservedCall::Write {
                target: target.resolved_address.clone(),
                byte_len: bytes.len(),
            }),
        )?;
        if self.cfg().write_returns_unsupported {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "test-plugin: write returns Unsupported (test_write_returns_unsupported=true)",
            ));
        }
        let key = self.relative_key(&target.resolved_address)?;
        if key.starts_with(META_PREFIX) {
            return self.meta_write(&key, bytes, target.resolved_address);
        }
        self.commit_bytes(target.resolved_address, key, bytes, opts)
    }

    async fn write_stream(
        &self,
        target: ResolvedTarget,
        stream: BodyStream,
        opts: WriteOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        let _ = &cancel; // conformance plugin op: this method body has no async work to cancel.
        self.bump_and_inject("write_stream")?;
        if self.cfg().write_stream_returns_unsupported {
            self.instance.recorder.observe(ObservedCall::WriteStream {
                target: target.resolved_address,
                byte_len: 0,
            });
            return Err(Error::new(
                ErrorCode::Unsupported,
                "test-plugin: write_stream returns Unsupported \
                 (test_write_stream_returns_unsupported=true)",
            ));
        }
        let key = self.relative_key(&target.resolved_address)?;
        let mut bytes = Vec::new();
        for chunk in stream {
            bytes.extend_from_slice(&chunk?);
        }
        self.instance.recorder.observe(ObservedCall::WriteStream {
            target: target.resolved_address.clone(),
            byte_len: bytes.len(),
        });
        // A `__test_meta/...` control write must fire on the streamed slot too,
        // so callers may use the control path through either body shape.
        if key.starts_with(META_PREFIX) {
            return self.meta_write(&key, bytes, target.resolved_address);
        }
        self.commit_bytes(target.resolved_address, key, bytes, opts)
    }

    async fn write_redirect(
        &self,
        target: ResolvedTarget,
        _opts: WriteOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteRedirectBatch> {
        let _ = &cancel; // conformance plugin op: this method body has no async work to cancel.
        self.enter_recorded(
            "write_redirect",
            Some(ObservedCall::WriteRedirect {
                target: target.resolved_address.clone(),
            }),
        )?;
        let cfg = self.cfg();
        if cfg.write_redirect_returns_unsupported {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "test-plugin: write_redirect returns Unsupported \
                 (test_write_redirect_returns_unsupported=true)",
            ));
        }
        let key = self.relative_key(&target.resolved_address)?;
        if key.starts_with(META_PREFIX) {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "test-plugin: __test_meta paths don't support write_redirect",
            ));
        }
        let parts = cfg.multipart_parts.max(1);
        let base = cfg.redirect_url.as_deref().ok_or_else(|| {
            Error::new(
                ErrorCode::Unsupported,
                "test-plugin: write_redirect requires test_redirect_url",
            )
        })?;
        let continuation = encode_continuation(&MultipartCont {
            key: key.clone(),
            bytes: Vec::new(),
            loops_remaining: cfg.continue_write_loops.saturating_sub(1),
        });
        let redirects = build_multipart_redirects(
            base,
            &key,
            parts,
            cfg.redirect_ttl_seconds,
            cfg.redirect_credential,
        );
        Ok(WriteRedirectBatch {
            continuation,
            redirects,
        })
    }

    async fn continue_write(
        &self,
        target: ResolvedTarget,
        redirects: WriteRedirectBatch,
        results: RedirectResultBatch,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteStep> {
        let _ = &cancel; // conformance plugin op: this method body has no async work to cancel.
        self.enter_recorded(
            "continue_write",
            Some(ObservedCall::ContinueWrite {
                target: target.resolved_address.clone(),
            }),
        )?;
        validate_redirect_results(&redirects, &results)?;
        // A non-2xx result is a failed upload, not a commit. Only the broker's
        // `continue_write` RPC screens these; no follower route does, so a
        // plugin that skips the check stores an object for a redirect that
        // failed. Mapping the status to a typed code rather than a blanket
        // `Transient` is the contract `CONFORMANCE.md` states under
        // *Post-redirect failure mapping*, and this is the plugin third-party
        // authors copy.
        for (index, result) in results.results.iter().enumerate() {
            if !(200..300).contains(&result.status_code) {
                return Err(Error::new(
                    map_redirect_status(result.status_code),
                    format!(
                        "test-plugin: redirect {} of {} returned HTTP {}",
                        index + 1,
                        results.results.len(),
                        result.status_code
                    ),
                ));
            }
        }
        let mut cont = decode_continuation(&redirects.continuation)?;
        // Derive the key from the authorized request address rather than
        // reading it back out of the continuation. This plugin is what a
        // third-party author copies, so it has to demonstrate the rule it is
        // testing them against: on the broker's client-driven route the blob is
        // echoed back by the remote caller, and only the address has been
        // through an authorization check.
        cont.key = self.relative_key(&target.resolved_address)?;
        if cont.key.starts_with(META_PREFIX) {
            // `write_redirect` refuses these, so a derived target that names one
            // has to be refused here for the same reason.
            return Err(Error::new(
                ErrorCode::Unsupported,
                "test-plugin: __test_meta paths don't support continue_write",
            ));
        }
        if cont.loops_remaining > 0 {
            cont.loops_remaining -= 1;
            let cfg = self.cfg();
            let base = cfg.redirect_url.as_deref().ok_or_else(|| {
                Error::new(
                    ErrorCode::Internal,
                    "test-plugin: continue_write without test_redirect_url",
                )
            })?;
            let next_redirects = build_multipart_redirects(
                base,
                &cont.key,
                cfg.multipart_parts.max(1),
                cfg.redirect_ttl_seconds,
                cfg.redirect_credential,
            );
            let continuation = encode_continuation(&cont);
            return Ok(WriteStep::Redirects(WriteRedirectBatch {
                continuation,
                redirects: next_redirects,
            }));
        }
        // Redirected writes flow bytes through the URL, not the plugin;
        // commit an empty placeholder so stat/list see the address.
        let object = StoredObject::new(cont.bytes);
        let info = object.info(target.resolved_address);
        let mut store = self.instance.store.lock().expect("store");
        store.put(cont.key, object);
        Ok(WriteStep::Done(WriteResult { info }))
    }

    async fn delete(
        &self,
        target: ResolvedTarget,
        opts: DeleteOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let _ = &cancel; // conformance plugin op: this method body has no async work to cancel.
        self.enter_recorded(
            "delete",
            Some(ObservedCall::Delete {
                target: target.resolved_address.clone(),
            }),
        )?;
        let key = self.relative_key(&target.resolved_address)?;
        let mut store = self.instance.store.lock().expect("store");
        // Real-directories mode mirrors the file backend's delete semantics:
        // deleting a directory (explicit or an implicit parent of stored
        // objects) with the object op is a type mismatch with guidance,
        // not NotFound. Directory identities are stored slash-free, so fold
        // both spellings onto the slash-free leaf.
        if self.cfg().capabilities.has_real_directories
            && store.is_directory(key.trim_end_matches('/'))
        {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "test-plugin: delete target is a directory; use delete_directory()",
            ));
        }
        let existing = store
            .current(&key)
            .ok_or_else(|| Error::new(ErrorCode::NotFound, format!("test://.../{key}")))?;
        if let Some(expected) = opts.if_match.as_deref() {
            check_etag(expected, &existing.etag())?;
        }
        store.remove(&key);
        Ok(())
    }

    async fn list(
        &self,
        prefix: ResolvedTarget,
        opts: ListOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<Vec<ObjectInfo>> {
        let _ = &cancel; // conformance plugin op: this method body has no async work to cancel.
        self.enter_recorded(
            "list",
            Some(ObservedCall::List {
                prefix: prefix.resolved_address.clone(),
                recursive: opts.recursive,
            }),
        )?;
        if opts.max_results.is_some() || opts.page_token.is_some() {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "test-plugin: list pagination knobs are not implemented",
            ));
        }
        // Derive the directory form here. The host does not rewrite a
        // directory-verb address to match the slot — `docs` and `docs/` name
        // one node, and on a flat namespace they may be two objects, so
        // choosing would be choosing which object the caller gets. Listing on
        // the key verbatim would return `docsx/secret` for a listing of
        // `docs`, which is a disclosure and cannot be undone.
        let prefix_key = address::directory_key(&self.relative_key(&prefix.resolved_address)?);
        let cfg = self.cfg();
        let root = cfg.root;
        let store = self.instance.store.lock().expect("store");
        // Real-directories mode mirrors the file backend's list semantics:
        // listing a file is a type mismatch, not NotFound / empty. Fold the
        // directory form back onto the slash-free leaf before consulting the
        // store, which keys objects without one.
        let list_leaf = prefix_key.trim_end_matches('/');
        if cfg.capabilities.has_real_directories
            && !list_leaf.is_empty()
            && store.current(list_leaf).is_some()
            && !store.is_directory(list_leaf)
        {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "test-plugin: list prefix is a file, not a directory",
            ));
        }
        let mut out = Vec::new();
        for (key, chain) in store.objects.range(prefix_key.clone()..) {
            if !key.starts_with(&prefix_key) {
                break;
            }
            let Some(obj) = chain.last() else { continue };
            let relative = key.strip_prefix(&prefix_key).unwrap_or(key);
            if !opts.recursive && relative.contains('/') {
                continue;
            }
            let address = address::join_relative(&root, key)?;
            out.push(obj.info(address));
        }
        Ok(out)
    }

    async fn watch_directory(
        &self,
        prefix: ResolvedTarget,
        opts: WatchDirectoryOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendChangeStream> {
        let base_address = prefix.resolved_address.clone();
        self.enter_recorded(
            "watch_directory",
            Some(ObservedCall::WatchDirectory {
                prefix: prefix.resolved_address,
            }),
        )?;
        let cfg = self.cfg();
        // Plugin advertises watch_directory_resumable = false; per the
        // SPI contract, a `since: Some(...)` request against a
        // non-resumable backend yields Lapsed first.
        Ok(synthesize_watch_stream(WatchStreamConfig {
            base_address,
            event_count: cfg.watch_event_count,
            lapsed_at: cfg.watch_lapsed_at,
            kind: cfg.watch_event_kind,
            keep_alive: cfg.watch_keep_alive,
            emit_interval_ms: cfg.watch_emit_interval_ms,
            resume_lapsed: opts.since.is_some(),
            cancel,
        }))
    }

    async fn create_directory(
        &self,
        target: ResolvedTarget,
        _opts: CreateDirectoryOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendItemInfo> {
        let _ = &cancel; // conformance plugin op: this method body has no async work to cancel.
        self.enter_recorded(
            "create_directory",
            Some(ObservedCall::CreateDirectory {
                target: target.resolved_address.clone(),
            }),
        )?;
        // Real-directories mode tracks explicit directories so the type-
        // mismatch contract scenarios have entities to hit.
        // A directory address arrives spelled as the caller wrote it, and
        // both spellings name one node; objects are stored slash-free, so
        // store the slash-free leaf and the two agree on identity.
        if self.cfg().capabilities.has_real_directories {
            let key = self.relative_key(&target.resolved_address)?;
            self.instance
                .store
                .lock()
                .expect("store")
                .directories
                .insert(key.trim_end_matches('/').to_string());
        }
        // Directories are otherwise implicit in the in-memory store; return a
        // minimal BackendItemInfo so capability-gated callers don't see Unsupported.
        Ok(BackendItemInfo {
            kind: ObjectKind::Directory,
            etag: None,
            version: None,
            size: None,
            mtime: None,
            checksums: ChecksumSet::default(),
            effective_permissions: None,
            system_metadata: None,
            user_metadata: None,
            modified_by: None,
        })
    }

    async fn delete_directory(
        &self,
        target: ResolvedTarget,
        _opts: DeleteDirectoryOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let _ = &cancel; // conformance plugin op: this method body has no async work to cancel.
        self.enter_recorded(
            "delete_directory",
            Some(ObservedCall::DeleteDirectory {
                target: target.resolved_address.clone(),
            }),
        )?;
        let prefix_key = self.relative_key(&target.resolved_address)?;
        // A directory address arrives spelled as the caller wrote it, and
        // both spellings name one node; objects are stored slash-free, so
        // fold onto the slash-free leaf and the checks below agree on
        // identity.
        let leaf = prefix_key.trim_end_matches('/').to_string();
        let child_prefix = if leaf.is_empty() {
            String::new()
        } else {
            format!("{leaf}/")
        };
        let real_directories = self.cfg().capabilities.has_real_directories;
        let mut store = self.instance.store.lock().expect("store");
        // Real-directories mode mirrors the file backend's delete_directory
        // semantics: delete_directory on a file is a type mismatch with guidance.
        if real_directories && store.current(&leaf).is_some() && !store.is_directory(&leaf) {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "test-plugin: delete_directory target is a file; use delete()",
            ));
        }
        // Matching objects: the leaf itself (or its slash-terminated
        // marker spelling) plus everything under the child prefix.
        let matching: Vec<String> = store
            .objects
            .range(leaf.clone()..)
            .take_while(|(k, _)| k.starts_with(leaf.as_str()))
            .filter(|(k, _)| *k == &leaf || k.starts_with(&child_prefix))
            .map(|(k, _)| k.clone())
            .collect();
        // Explicit child directories count toward non-emptiness too
        // (real-filesystem semantics): an empty subdirectory still makes
        // the parent non-empty, and refusing here means no orphaned
        // `directories` entries survive a successful delete.
        let has_child_dir = store
            .directories
            .range(child_prefix.clone()..)
            .take_while(|d| d.starts_with(child_prefix.as_str()))
            .any(|d| d != &leaf);
        if matching.iter().any(|k| k != &leaf && k != &child_prefix) || has_child_dir {
            return Err(Error::new(
                ErrorCode::DirectoryNotEmpty,
                "test-plugin: delete on a non-empty directory",
            ));
        }
        for k in matching {
            store.remove(&k);
        }
        store.directories.remove(&leaf);
        Ok(())
    }

    async fn list_versions(
        &self,
        target: ResolvedTarget,
        opts: ListVersionsOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<Vec<ObjectInfo>> {
        let _ = &cancel; // conformance plugin op: this method body has no async work to cancel.
        self.enter_recorded(
            "list_versions",
            Some(ObservedCall::ListVersions {
                target: target.resolved_address.clone(),
            }),
        )?;
        if opts.max_results.is_some() || opts.page_token.is_some() {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "test-plugin: list_versions pagination knobs are not implemented",
            ));
        }
        // Drop any version pin in the input address — list_versions returns
        // the object's full history regardless of which version the caller's
        // URL points at. The pin is a read selector, not a list filter.
        let mut path_only = target.resolved_address;
        path_only.set_query(None);
        let key = self.relative_key(&path_only)?;
        let store = self.instance.store.lock().expect("store");
        let chain = store
            .objects
            .get(&key)
            .ok_or_else(|| Error::new(ErrorCode::NotFound, format!("test://.../{key}")))?;
        chain
            .iter()
            .enumerate()
            .map(|(i, obj)| {
                let mut info = obj.info(test_version_address(&path_only, i)?);
                info.version = Some(format!("v{i}"));
                Ok(info)
            })
            .collect()
    }

    async fn get_latest_version(
        &self,
        target: ResolvedTarget,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        let _ = &cancel; // conformance plugin op: this method body has no async work to cancel.
        let mut path_only = target.resolved_address.clone();
        path_only.set_query(None);
        path_only.set_fragment(None);
        let key = self.relative_key(&path_only)?;
        let store = self.instance.store.lock().expect("store");
        let chain = store
            .objects
            .get(&key)
            .ok_or_else(|| Error::new(ErrorCode::NotFound, format!("test://.../{key}")))?;
        let index = match test_version_index(&target.resolved_address)? {
            Some(index) => index,
            None => chain.len().checked_sub(1).ok_or_else(|| {
                Error::new(
                    ErrorCode::NotFound,
                    format!("test://.../{key} has no versions"),
                )
            })?,
        };
        let obj = chain.get(index).ok_or_else(|| {
            Error::new(
                ErrorCode::NotFound,
                format!("test://.../{key}?version=v{index}"),
            )
        })?;
        let mut info = obj.info(test_version_address(&path_only, index)?);
        info.version = Some(format!("v{index}"));
        Ok(info)
    }

    async fn copy(
        &self,
        src: ResolvedTarget,
        dest: ResolvedTarget,
        opts: CopyOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteStep> {
        let _ = &cancel; // conformance plugin op: this method body has no async work to cancel.
        self.enter_recorded(
            "copy",
            Some(ObservedCall::Copy {
                src: src.resolved_address.clone(),
                dest: dest.resolved_address.clone(),
            }),
        )?;
        let src_key = self.relative_key(&src.resolved_address)?;
        let dest_key = self.relative_key(&dest.resolved_address)?;
        let mut store = self.instance.store.lock().expect("store");
        let cloned = store
            .current(&src_key)
            .ok_or_else(|| Error::new(ErrorCode::NotFound, format!("test://.../{src_key}")))?
            .clone();
        if let Some(expected) = opts.if_source.as_deref() {
            check_etag(expected, &cloned.etag())?;
        }
        match &opts.if_dest {
            IfDestExists::Overwrite => {}
            IfDestExists::Fail => {
                if store.current(&dest_key).is_some() {
                    return Err(Error::new(
                        ErrorCode::AlreadyExists,
                        "test-plugin: if_dest=Fail: copy destination already exists",
                    ));
                }
            }
            IfDestExists::MatchEtag(expected) => match store.current(&dest_key) {
                Some(existing) => check_etag(expected, &existing.etag())?,
                None => {
                    return Err(Error::new(
                        ErrorCode::NotFound,
                        "test-plugin: if_dest=MatchEtag: copy destination does not exist",
                    ));
                }
            },
        }
        let info = cloned.info(dest.resolved_address);
        store.put(dest_key, cloned);
        Ok(WriteStep::Done(WriteResult { info }))
    }

    async fn rename(
        &self,
        src: ResolvedTarget,
        dest: ResolvedTarget,
        opts: RenameOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let _ = &cancel; // conformance plugin op: this method body has no async work to cancel.
        self.enter_recorded(
            "rename",
            Some(ObservedCall::Rename {
                src: src.resolved_address.clone(),
                dest: dest.resolved_address.clone(),
            }),
        )?;
        let src_key = self.relative_key(&src.resolved_address)?;
        let dest_key = self.relative_key(&dest.resolved_address)?;
        let mut store = self.instance.store.lock().expect("store");
        if let Some(expected) = opts.if_source.as_deref() {
            let current = store
                .current(&src_key)
                .ok_or_else(|| Error::new(ErrorCode::NotFound, format!("test://.../{src_key}")))?;
            check_etag(expected, &current.etag())?;
        }
        match &opts.if_dest {
            IfDestExists::Overwrite => {}
            IfDestExists::Fail => {
                if store.current(&dest_key).is_some() {
                    return Err(Error::new(
                        ErrorCode::AlreadyExists,
                        "test-plugin: if_dest=Fail: rename destination already exists",
                    ));
                }
            }
            IfDestExists::MatchEtag(expected) => match store.current(&dest_key) {
                Some(existing) => check_etag(expected, &existing.etag())?,
                None => {
                    return Err(Error::new(
                        ErrorCode::NotFound,
                        "test-plugin: if_dest=MatchEtag: rename destination does not exist",
                    ));
                }
            },
        }
        let chain = store
            .objects
            .remove(&src_key)
            .ok_or_else(|| Error::new(ErrorCode::NotFound, format!("test://.../{src_key}")))?;
        store.objects.insert(dest_key, chain);
        Ok(())
    }

    async fn update_metadata(
        &self,
        target: ResolvedTarget,
        opts: UpdateMetadataOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendItemInfo> {
        let _ = &cancel; // conformance plugin op: this method body has no async work to cancel.
        self.enter_recorded(
            "update_metadata",
            Some(ObservedCall::UpdateMetadata {
                target: target.resolved_address.clone(),
            }),
        )?;
        let key = self.relative_key(&target.resolved_address)?;
        let mut store = self.instance.store.lock().expect("store");
        let chain = store
            .objects
            .get_mut(&key)
            .ok_or_else(|| Error::new(ErrorCode::NotFound, format!("test://.../{key}")))?;
        let object = chain
            .last_mut()
            .ok_or_else(|| Error::new(ErrorCode::NotFound, format!("test://.../{key}")))?;
        if let Some(expected) = opts.if_match.as_deref() {
            check_etag(expected, &object.etag())?;
        }
        for k in &opts.user_metadata_remove {
            object.user_metadata.remove(k);
        }
        for (k, v) in &opts.user_metadata_set {
            object.user_metadata.insert(k.clone(), v.clone());
        }
        if let Some(message) = opts.message.as_deref().filter(|m| !m.is_empty()) {
            object
                .user_metadata
                .insert("x-ov-message".to_string(), message.to_string());
        }
        Ok(object.item_info())
    }

    async fn check_access(
        &self,
        target: ResolvedTarget,
        ops: AccessOps,
        cancel: Option<CancellationToken>,
    ) -> Result<AccessDecision> {
        let _ = &cancel; // conformance plugin op: this method body has no async work to cancel.
        self.enter_recorded(
            "check_access",
            Some(ObservedCall::CheckAccess {
                target: target.resolved_address,
            }),
        )?;
        let cfg = self.cfg();
        let (policy_denials, reason) = match cfg.check_access_decision {
            config::CheckAccessDecision::Allow => (AccessOps::default(), None),
            config::CheckAccessDecision::DenyAll => (
                AccessOps {
                    read: true,
                    write: true,
                    delete: true,
                    update_metadata: true,
                },
                Some("test-plugin: deny-all".to_string()),
            ),
            config::CheckAccessDecision::ReadOnly => (
                AccessOps {
                    read: false,
                    write: true,
                    delete: true,
                    update_metadata: true,
                },
                Some("test-plugin: read-only".to_string()),
            ),
        };
        let denied_ops = AccessOps {
            read: ops.read && policy_denials.read,
            write: ops.write && policy_denials.write,
            delete: ops.delete && policy_denials.delete,
            update_metadata: ops.update_metadata && policy_denials.update_metadata,
        };
        let allowed = !(denied_ops.read
            || denied_ops.write
            || denied_ops.delete
            || denied_ops.update_metadata);
        Ok(AccessDecision {
            allowed,
            denied_ops,
            reason: if allowed { None } else { reason },
        })
    }
}

fn slice_range(bytes: &[u8], range: &ByteRange) -> Result<Vec<u8>> {
    if let Some(end_inclusive) = range.end_inclusive
        && end_inclusive < range.start
    {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "test-plugin: range end_inclusive {end_inclusive} \
                 precedes start {}",
                range.start
            ),
        ));
    }
    let start = usize::try_from(range.start).map_err(|_| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("test-plugin: range start {} exceeds usize", range.start),
        )
    })?;
    if start > bytes.len() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "test-plugin: range start {} exceeds object length {}",
                range.start,
                bytes.len()
            ),
        ));
    }
    let end = match range.end_inclusive {
        Some(end_inclusive) => {
            let exclusive = end_inclusive.checked_add(1).ok_or_else(|| {
                Error::new(
                    ErrorCode::InvalidArgument,
                    "test-plugin: range end_inclusive overflows u64",
                )
            })?;
            let end = usize::try_from(exclusive).unwrap_or(usize::MAX);
            end.min(bytes.len())
        }
        None => bytes.len(),
    };
    Ok(bytes[start..end].to_vec())
}

fn check_etag(expected: &str, actual: &str) -> Result<()> {
    if expected != actual {
        return Err(Error::new(
            ErrorCode::PreconditionFailed,
            "test-plugin: if_match etag mismatch",
        ));
    }
    Ok(())
}

fn test_version_address(base: &Url, index: usize) -> Result<Url> {
    let mut path_only = base.clone();
    path_only.set_query(None);
    path_only.set_fragment(None);
    address::with_query_pair(&path_only, "version", &format!("v{index}"))
}

fn test_version_index(addr: &Url) -> Result<Option<usize>> {
    for (key, value) in addr.query_pairs() {
        if key == "version" {
            let raw = value.strip_prefix('v').ok_or_else(|| {
                Error::new(
                    ErrorCode::InvalidArgument,
                    "test-plugin: version selector must have shape vN",
                )
            })?;
            let index = raw.parse::<usize>().map_err(|_| {
                Error::new(
                    ErrorCode::InvalidArgument,
                    "test-plugin: version selector must have shape vN",
                )
            })?;
            return Ok(Some(index));
        }
    }
    Ok(None)
}

fn synthesize_auth_stream(flow: config::AuthFlow, connection: Connection) -> AuthEventStream {
    use config::AuthFlow as F;
    let now = std::time::SystemTime::now();
    let later = now + std::time::Duration::from_secs(120);
    let events: Vec<Result<AuthEvent>> = match flow {
        F::Succeed => vec![Ok(AuthEvent::Succeeded {
            connection: Box::new(connection),
            credentials: None,
        })],
        F::Fail => vec![Ok(AuthEvent::Failed {
            error: Error::new(
                ErrorCode::AuthRequired,
                "test-plugin: simulated auth failure",
            ),
        })],
        F::Cancel => vec![Ok(AuthEvent::Cancelled)],
        F::ProgressThenSucceed => vec![
            Ok(AuthEvent::Progress {
                message: "test-plugin: progress".into(),
            }),
            Ok(AuthEvent::Succeeded {
                connection: Box::new(connection),
                credentials: None,
            }),
        ],
        F::OpenBrowserThenSucceed => vec![
            Ok(AuthEvent::OpenBrowser {
                url: "https://test.example/auth".into(),
                expires_at: later,
            }),
            Ok(AuthEvent::Succeeded {
                connection: Box::new(connection),
                credentials: None,
            }),
        ],
        F::DeviceCodeThenSucceed => vec![
            Ok(AuthEvent::DeviceCode {
                user_code: "TEST-CODE".into(),
                verification_url: "https://test.example/device".into(),
                expires_at: later,
                interval: std::time::Duration::from_secs(5),
            }),
            Ok(AuthEvent::Succeeded {
                connection: Box::new(connection),
                credentials: None,
            }),
        ],
    };
    Box::new(events.into_iter())
}

struct WatchStreamConfig {
    base_address: Url,
    event_count: u32,
    lapsed_at: i32,
    kind: config::WatchEventKind,
    keep_alive: bool,
    emit_interval_ms: u64,
    resume_lapsed: bool,
    cancel: Option<CancellationToken>,
}

fn synthesize_watch_stream(config: WatchStreamConfig) -> BackendChangeStream {
    let WatchStreamConfig {
        base_address,
        event_count,
        lapsed_at,
        kind,
        keep_alive,
        emit_interval_ms,
        resume_lapsed,
        cancel,
    } = config;
    let now = std::time::SystemTime::now();
    let change_kind = match kind {
        config::WatchEventKind::Created => ChangeKind::Created,
        config::WatchEventKind::Modified => ChangeKind::Modified,
        config::WatchEventKind::Deleted => ChangeKind::Deleted,
        config::WatchEventKind::MetadataChanged => ChangeKind::MetadataChanged,
    };
    let mut events: Vec<Result<BackendChangeEvent>> = (0..event_count)
        .map(|i| {
            let relative_key = format!("watch-event-{i}");
            Ok(BackendChangeEvent::Object {
                address: address::join_relative(&base_address, &relative_key)?,
                kind: change_kind,
                etag: None,
                version: None,
                size: None,
                mtime: None,
                at: now + std::time::Duration::from_millis(i as u64 * 10),
                cursor: WatchDirectoryCursor(vec![i as u8]),
            })
        })
        .collect();
    if resume_lapsed {
        events.insert(
            0,
            Ok(BackendChangeEvent::Lapsed {
                since: None,
                cursor: WatchDirectoryCursor(Vec::new()),
            }),
        );
    }
    if lapsed_at >= 0 && (lapsed_at as usize) <= events.len() {
        events.insert(
            lapsed_at as usize,
            Ok(BackendChangeEvent::Lapsed {
                since: Some(now),
                cursor: WatchDirectoryCursor(vec![0xFF]),
            }),
        );
    }
    if keep_alive {
        Box::new(KeepAliveWatchStream {
            events: events.into_iter(),
            cancel,
            emit_interval: std::time::Duration::from_millis(emit_interval_ms),
        })
    } else {
        Box::new(events.into_iter())
    }
}

// Models real-backend watches (file polls forever, cloud stays
// subscribed); blocks on the cancel token rather than leaking a thread.
struct KeepAliveWatchStream {
    events: std::vec::IntoIter<Result<BackendChangeEvent>>,
    cancel: Option<CancellationToken>,
    /// Pause before each emitted event. Zero emits as fast as the
    /// consumer pulls. Non-zero mirrors real backends' natural event
    /// pacing — useful for tests with concurrent subscribers that
    /// need both to register before event 0 lands.
    emit_interval: std::time::Duration,
}

impl KeepAliveWatchStream {
    /// Sleep for `dur` in 50ms slices, bailing out early if the cancel
    /// token fires. Returns `false` if cancelled.
    fn sleep_with_cancel(&self, dur: std::time::Duration) -> bool {
        let deadline = std::time::Instant::now() + dur;
        let slice = std::time::Duration::from_millis(50);
        while std::time::Instant::now() < deadline {
            if let Some(token) = &self.cancel
                && token.is_cancelled()
            {
                return false;
            }
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            std::thread::sleep(slice.min(remaining));
        }
        true
    }
}

impl Iterator for KeepAliveWatchStream {
    type Item = Result<BackendChangeEvent>;
    fn next(&mut self) -> Option<Self::Item> {
        if !self.emit_interval.is_zero() && !self.sleep_with_cancel(self.emit_interval) {
            return None;
        }
        if let Some(event) = self.events.next() {
            return Some(event);
        }
        loop {
            if let Some(token) = &self.cancel
                && token.is_cancelled()
            {
                return None;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }
}

// Exercises the host keyring + auth-refresh substrate from the plugin
// side so tests can see what would have failed in production.
fn drive_host_callbacks(connection: &Connection) -> Result<()> {
    let host = marshal::host().ok_or_else(|| {
        Error::new(
            ErrorCode::Internal,
            "test-plugin: host callbacks not registered (call register_host)",
        )
    })?;
    host.secret_put(
        BACKEND_KIND,
        &connection.id,
        "auth_drives_test",
        &SecretBytes(b"under-test".to_vec()),
    )?;
    let _round_trip = host.secret_get(BACKEND_KIND, &connection.id, "auth_drives_test")?;
    host.secret_delete(BACKEND_KIND, &connection.id, "auth_drives_test")?;
    host.auth_refresh_lock_with_refresh(
        BACKEND_KIND,
        &connection.id,
        std::time::Duration::from_secs(0),
        || Ok(()),
    )?;
    Ok(())
}

const DEFAULT_REDIRECT_TTL_SECS: u64 = 300;

// `Some(0)` returns 1s in the past so tests exercise the broker's
// "redirect expired but cache still serves" path.
fn compute_redirect_expiry(ttl_seconds: Option<u64>) -> std::time::SystemTime {
    let now = std::time::SystemTime::now();
    match ttl_seconds {
        Some(0) => now - std::time::Duration::from_secs(1),
        Some(secs) => now + std::time::Duration::from_secs(secs),
        None => now + std::time::Duration::from_secs(DEFAULT_REDIRECT_TTL_SECS),
    }
}

fn build_read_redirect(
    base: &str,
    address: &Url,
    key: &str,
    ttl_seconds: Option<u64>,
    credential: RedirectCredential,
) -> ReadRedirect {
    let url = format!("{}{}", normalize_base(base), key);
    let expires = compute_redirect_expiry(ttl_seconds);
    ReadRedirect {
        request: HttpRequest {
            method: "GET".into(),
            url,
            headers: vec![("user-agent".into(), "ovstorage-plugin-test".into())],
        },
        response_parsing: ResponseParsing::default(),
        expires_at: expires,
        scope: RedirectScope {
            physical_url_prefix: normalize_base(base),
            operations: AccessOps {
                read: true,
                ..AccessOps::default()
            },
            expires_at: expires,
            credential,
        },
        audit_id: format!("test-read:{}", address.as_str()),
        policy_epoch: 0,
    }
}

fn build_multipart_redirects(
    base: &str,
    key: &str,
    parts: u32,
    ttl_seconds: Option<u64>,
    credential: RedirectCredential,
) -> Vec<WriteRedirect> {
    let expires = compute_redirect_expiry(ttl_seconds);
    (0..parts)
        .map(|i| WriteRedirect {
            request: HttpRequest {
                method: "PUT".into(),
                url: format!("{}{}?partNumber={}", normalize_base(base), key, i + 1),
                headers: vec![],
            },
            body_source: RedirectBodySource::UserBytes { offset: 0, len: 0 },
            result_capture: ResultCapture::default(),
            expires_at: expires,
            scope: RedirectScope {
                physical_url_prefix: normalize_base(base),
                operations: AccessOps {
                    write: true,
                    ..AccessOps::default()
                },
                expires_at: expires,
                credential,
            },
            audit_id: format!("test-write-part:{key}:{}", i + 1),
            policy_epoch: 0,
        })
        .collect()
}

fn normalize_base(base: &str) -> String {
    if base.ends_with('/') {
        base.to_string()
    } else {
        format!("{base}/")
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
struct MultipartCont {
    /// The object key. Written to the encoded form but never read back from it
    /// — `continue_write` recomputes it from the authorized request address —
    /// so a caller-supplied key cannot steer the commit. It stays on the wire
    /// only so a peer still running an earlier build can decode a continuation
    /// minted here.
    #[serde(skip_deserializing)]
    key: String,
    #[serde(with = "base64_bytes")]
    bytes: Vec<u8>,
    loops_remaining: u32,
}

/// Typed mapping for a non-2xx redirect result. Deliberately not a blanket
/// `Transient`: a plugin author reading this file should see the shape they are
/// expected to implement. It maps every status `CONFORMANCE.md` requires, and
/// additionally draws the two distinctions that page marks recommended rather
/// than required — `408`/`504` to `DeadlineExceeded` and `429`/`503` to
/// `ResourceExhausted` instead of the `Transient` the 5xx default would give.
/// In-tree backends agree on `429` and differ on the rest: S3, Azure and GCS
/// map `408`/`504` to `DeadlineExceeded` and `503` to `ResourceExhausted`,
/// while OpenDAL and the services client send `408` and `503` to `Transient`
/// and Nucleus has no `408` arm at all. Both shapes are conformant, and this
/// exemplar shows the fuller form. The match-arm order
/// matters — the two carve-outs must precede the `500..=599` catch-all.
fn map_redirect_status(status: u16) -> ErrorCode {
    match status {
        401 => ErrorCode::AuthRequired,
        403 => ErrorCode::PermissionDenied,
        404 | 410 => ErrorCode::NotFound,
        409 => ErrorCode::Conflict,
        412 => ErrorCode::PreconditionFailed,
        416 => ErrorCode::InvalidArgument,
        408 | 504 => ErrorCode::DeadlineExceeded,
        429 | 503 => ErrorCode::ResourceExhausted,
        500..=599 => ErrorCode::Transient,
        _ => ErrorCode::Internal,
    }
}

fn encode_continuation(cont: &MultipartCont) -> Vec<u8> {
    serde_json::to_vec(cont).expect("MultipartCont serialization is infallible")
}

fn decode_continuation(raw: &[u8]) -> Result<MultipartCont> {
    serde_json::from_slice(raw).map_err(|err| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("test-plugin: invalid continuation: {err}"),
        )
    })
}

// Renders the recorder log as the JSON read out of
// `__test_meta/calls.json` for ordered/negative-sequence assertions.
fn render_calls_json(calls: &[ObservedCall]) -> Vec<u8> {
    let mut out = String::from("[");
    for (i, call) in calls.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        match call {
            ObservedCall::Stat { target } => {
                out.push_str(&format!(
                    "{{\"method\":\"stat\",\"target\":{}}}",
                    json_string(target.as_str())
                ));
            }
            ObservedCall::Read { target } => {
                out.push_str(&format!(
                    "{{\"method\":\"read\",\"target\":{}}}",
                    json_string(target.as_str())
                ));
            }
            ObservedCall::Write { target, byte_len } => {
                out.push_str(&format!(
                    "{{\"method\":\"write\",\"target\":{},\"byte_len\":{byte_len}}}",
                    json_string(target.as_str())
                ));
            }
            ObservedCall::WriteStream { target, byte_len } => {
                out.push_str(&format!(
                    "{{\"method\":\"write_stream\",\"target\":{},\"byte_len\":{byte_len}}}",
                    json_string(target.as_str())
                ));
            }
            ObservedCall::WriteRedirect { target } => {
                out.push_str(&format!(
                    "{{\"method\":\"write_redirect\",\"target\":{}}}",
                    json_string(target.as_str())
                ));
            }
            ObservedCall::ContinueWrite { target } => {
                out.push_str(&format!(
                    "{{\"method\":\"continue_write\",\"target\":{}}}",
                    json_string(target.as_str())
                ));
            }
            ObservedCall::Delete { target } => {
                out.push_str(&format!(
                    "{{\"method\":\"delete\",\"target\":{}}}",
                    json_string(target.as_str())
                ));
            }
            ObservedCall::List { prefix, recursive } => {
                out.push_str(&format!(
                    "{{\"method\":\"list\",\"prefix\":{},\"recursive\":{recursive}}}",
                    json_string(prefix.as_str())
                ));
            }
            ObservedCall::ListVersions { target } => {
                out.push_str(&format!(
                    "{{\"method\":\"list_versions\",\"target\":{}}}",
                    json_string(target.as_str())
                ));
            }
            ObservedCall::WatchDirectory { prefix } => {
                out.push_str(&format!(
                    "{{\"method\":\"watch_directory\",\"prefix\":{}}}",
                    json_string(prefix.as_str())
                ));
            }
            ObservedCall::WatchAddressRoots => {
                out.push_str("{\"method\":\"watch_address_roots\"}");
            }
            ObservedCall::ListAddressRoots => {
                out.push_str("{\"method\":\"list_address_roots\"}");
            }
            ObservedCall::CreateDirectory { target } => {
                out.push_str(&format!(
                    "{{\"method\":\"create_directory\",\"target\":{}}}",
                    json_string(target.as_str())
                ));
            }
            ObservedCall::DeleteDirectory { target } => {
                out.push_str(&format!(
                    "{{\"method\":\"delete_directory\",\"target\":{}}}",
                    json_string(target.as_str())
                ));
            }
            ObservedCall::Copy { src, dest } => {
                out.push_str(&format!(
                    "{{\"method\":\"copy\",\"src\":{},\"dest\":{}}}",
                    json_string(src.as_str()),
                    json_string(dest.as_str())
                ));
            }
            ObservedCall::Rename { src, dest } => {
                out.push_str(&format!(
                    "{{\"method\":\"rename\",\"src\":{},\"dest\":{}}}",
                    json_string(src.as_str()),
                    json_string(dest.as_str())
                ));
            }
            ObservedCall::UpdateMetadata { target } => {
                out.push_str(&format!(
                    "{{\"method\":\"update_metadata\",\"target\":{}}}",
                    json_string(target.as_str())
                ));
            }
            ObservedCall::CheckAccess { target } => {
                out.push_str(&format!(
                    "{{\"method\":\"check_access\",\"target\":{}}}",
                    json_string(target.as_str())
                ));
            }
        }
    }
    out.push(']');
    out.into_bytes()
}

// Hand-rolled to avoid pulling serde_json into render_calls_json for
// one helper; test target URLs are ASCII so escaping is minimal.
fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Despite the name, this does **not** produce base64: it widens each byte to a
/// `u16` and serialises the result, so the encoded form is a JSON array of
/// numbers rather than a string. Worth knowing before reasoning about what the
/// encoded continuation contains — `key` is the only string field in it.
mod base64_bytes {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> std::result::Result<S::Ok, S::Error> {
        let encoded: Vec<u16> = bytes.iter().map(|b| *b as u16).collect();
        encoded.serialize(s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<Vec<u8>, D::Error> {
        let v: Vec<u16> = Vec::deserialize(d)?;
        Ok(v.into_iter().map(|w| w as u8).collect())
    }
}

// No plugin-export macro here: the fixed-name ABI entry points would land
// in this crate's rlib too, colliding with other plugins' own exports when
// they link the harness into their test binaries. The ABI-v2 cdylib export
// lives in `ovstorage-plugin-test-abi`.

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn fixture(extra: &[(&str, ConfigValue)]) -> TestBackend {
        let mut config = HashMap::new();
        config.insert(
            "test_root".into(),
            ConfigValue::String("test://demo/".into()),
        );
        for (k, v) in extra {
            config.insert((*k).into(), v.clone());
        }
        let request = ConnectionRequest {
            backend_kind: BACKEND_KIND.into(),
            config,
            credentials: SecretBundle::default(),
            persist: false,
            display_name: None,
        };
        let cfg = TestConfig::from_request(&request).unwrap();
        TestBackend {
            instance: Arc::new(TestInstance::new(cfg)),
        }
    }

    fn target(key: &str) -> ResolvedTarget {
        ResolvedTarget {
            backend_id: BackendId("test".into()),
            resolved_address: address::parse(&format!("test://demo/{key}")).unwrap(),
        }
    }

    #[tokio::test]
    async fn round_trips_bytes_through_in_memory_store() {
        let backend = fixture(&[]);
        let _ = backend
            .write(
                target("hello.txt"),
                b"hello".to_vec(),
                WriteOptions::default(),
                None,
            )
            .await
            .unwrap();
        let info = backend
            .stat(target("hello.txt"), StatOptions::default(), None)
            .await
            .unwrap();
        assert_eq!(info.size, Some(5));
        let read = backend
            .read(target("hello.txt"), ReadOptions::default(), None)
            .await
            .unwrap();
        let ReadResult::Bytes { bytes, .. } = read else {
            panic!("expected Bytes");
        };
        assert_eq!(bytes, b"hello");
    }

    #[tokio::test]
    async fn round_trips_streamed_body_chunk_by_chunk() {
        let backend = fixture(&[]);
        let chunks: Vec<Result<Vec<u8>>> = vec![
            Ok(b"alpha-".to_vec()),
            Ok(b"beta-".to_vec()),
            Ok(b"gamma".to_vec()),
        ];
        let stream = BodyStream::from_iter(chunks.into_iter());
        let _ = backend
            .write_stream(
                target("streamed.bin"),
                stream,
                WriteOptions::default(),
                None,
            )
            .await
            .unwrap();
        let info = backend
            .stat(target("streamed.bin"), StatOptions::default(), None)
            .await
            .unwrap();
        assert_eq!(info.size, Some(16));
        let read = backend
            .read(target("streamed.bin"), ReadOptions::default(), None)
            .await
            .unwrap();
        let ReadResult::Bytes { bytes, .. } = read else {
            panic!("expected Bytes");
        };
        assert_eq!(bytes, b"alpha-beta-gamma");
    }

    #[tokio::test]
    async fn streamed_body_propagates_chunk_error() {
        let backend = fixture(&[]);
        let chunks: Vec<Result<Vec<u8>>> = vec![
            Ok(b"first".to_vec()),
            Err(Error::new(ErrorCode::Internal, "synthetic chunk failure")),
        ];
        let stream = BodyStream::from_iter(chunks.into_iter());
        let err = backend
            .write_stream(target("broken.bin"), stream, WriteOptions::default(), None)
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Internal);
        assert!(
            backend
                .stat(target("broken.bin"), StatOptions::default(), None)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn missing_key_returns_not_found() {
        let backend = fixture(&[]);
        let err = backend
            .read(target("missing.txt"), ReadOptions::default(), None)
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::NotFound);
    }

    #[tokio::test]
    async fn no_overwrite_rejects_existing_key() {
        let backend = fixture(&[]);
        backend
            .write(
                target("existing.txt"),
                b"v1".to_vec(),
                WriteOptions::default(),
                None,
            )
            .await
            .unwrap();
        let err = backend
            .write(
                target("existing.txt"),
                b"v2".to_vec(),
                WriteOptions {
                    if_dest: IfDestExists::Fail,
                    ..WriteOptions::default()
                },
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::AlreadyExists);
    }

    #[tokio::test]
    async fn list_returns_objects_under_prefix() {
        let backend = fixture(&[]);
        for key in ["a.txt", "nested/b.txt", "nested/c.txt"] {
            backend
                .write(target(key), b"x".to_vec(), WriteOptions::default(), None)
                .await
                .unwrap();
        }
        let recursive = backend
            .list(
                target(""),
                ListOptions {
                    recursive: true,
                    ..ListOptions::default()
                },
                None,
            )
            .await
            .unwrap();
        assert_eq!(recursive.len(), 3);
        let one_level = backend
            .list(target(""), ListOptions::default(), None)
            .await
            .unwrap();
        assert_eq!(one_level.len(), 1);
    }

    #[tokio::test]
    async fn introspection_path_returns_method_call_counts() {
        let backend = fixture(&[]);
        backend
            .write(target("a"), b"1".to_vec(), WriteOptions::default(), None)
            .await
            .unwrap();
        backend
            .read(target("a"), ReadOptions::default(), None)
            .await
            .unwrap();
        backend
            .read(target("a"), ReadOptions::default(), None)
            .await
            .unwrap();

        let read = backend
            .read(
                target("__test_meta/method_calls.json"),
                ReadOptions::default(),
                None,
            )
            .await
            .unwrap();
        let ReadResult::Bytes { bytes, .. } = read else {
            panic!("expected Bytes");
        };
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        // Introspection read bumps the counter: 2 real + 1 meta = 3.
        assert_eq!(json["read"], 3);
        assert_eq!(json["write"], 1);
    }

    #[tokio::test]
    async fn introspection_path_is_write_protected() {
        let backend = fixture(&[]);
        let err = backend
            .write(
                target("__test_meta/method_calls.json"),
                b"oops".to_vec(),
                WriteOptions::default(),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    #[tokio::test]
    async fn unbounded_error_injection_fails_every_call() {
        let backend = fixture(&[
            ("test_inject_error_on", ConfigValue::String("read".into())),
            (
                "test_inject_error_code",
                ConfigValue::String("Transient".into()),
            ),
        ]);
        backend
            .write(
                target("hello.txt"),
                b"hi".to_vec(),
                WriteOptions::default(),
                None,
            )
            .await
            .unwrap();
        for _ in 0..3 {
            let err = backend
                .read(target("hello.txt"), ReadOptions::default(), None)
                .await
                .unwrap_err();
            assert_eq!(err.code(), ErrorCode::Transient);
        }
    }

    #[tokio::test]
    async fn bounded_error_injection_lets_retry_succeed() {
        let backend = fixture(&[
            ("test_inject_error_on", ConfigValue::String("read".into())),
            (
                "test_inject_error_code",
                ConfigValue::String("Transient".into()),
            ),
            ("test_inject_error_count", ConfigValue::Int(2)),
        ]);
        backend
            .write(
                target("hello.txt"),
                b"hi".to_vec(),
                WriteOptions::default(),
                None,
            )
            .await
            .unwrap();
        assert_eq!(
            backend
                .read(target("hello.txt"), ReadOptions::default(), None)
                .await
                .unwrap_err()
                .code(),
            ErrorCode::Transient
        );
        assert_eq!(
            backend
                .read(target("hello.txt"), ReadOptions::default(), None)
                .await
                .unwrap_err()
                .code(),
            ErrorCode::Transient
        );
        let read = backend
            .read(target("hello.txt"), ReadOptions::default(), None)
            .await
            .unwrap();
        let ReadResult::Bytes { bytes, .. } = read else {
            panic!("expected Bytes after retry");
        };
        assert_eq!(bytes, b"hi");

        let meta = backend
            .read(
                target("__test_meta/method_calls.json"),
                ReadOptions::default(),
                None,
            )
            .await
            .unwrap();
        let ReadResult::Bytes { bytes, .. } = meta else {
            panic!("expected Bytes");
        };
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        // 3 user reads + 1 meta read = 4; meta read bypasses injection
        // but still bumps the counter.
        assert_eq!(json["read"], 4);
    }

    #[tokio::test]
    async fn read_returns_redirect_when_url_configured() {
        let backend = fixture(&[(
            "test_redirect_url",
            ConfigValue::String("https://test.example".into()),
        )]);
        // No bytes needed; the host follower would fetch them.
        let read = backend
            .read(target("hello.txt"), ReadOptions::default(), None)
            .await
            .unwrap();
        let ReadResult::Redirect(redirect) = read else {
            panic!("expected Redirect");
        };
        assert_eq!(redirect.request.method, "GET");
        assert!(redirect.request.url.ends_with("/hello.txt"));
        assert!(redirect.scope.operations.read);
    }

    // The directory type mismatch outranks the redirect: a redirect-enabled
    // connection must not hand back a redirect (nor, through `materialize`,
    // the Unsupported that follows one) for a directory.
    #[tokio::test]
    async fn read_on_directory_refuses_before_the_redirect_branch() {
        let backend = fixture(&[
            ("test_caps", ConfigValue::String("full".into())),
            (
                "test_redirect_url",
                ConfigValue::String("https://test.example".into()),
            ),
        ]);
        backend
            .create_directory(target("readdir/"), CreateDirectoryOptions::default(), None)
            .await
            .expect("create_directory");

        for key in ["readdir", "readdir/"] {
            let err = backend
                .read(target(key), ReadOptions::default(), None)
                .await
                .map(|_| ())
                .expect_err("a directory read must refuse, not redirect");
            assert_eq!(err.code(), ErrorCode::InvalidArgument, "{key}: {err}");
            assert!(err.message().contains("use list()"), "{key}: {err}");
        }
    }

    #[tokio::test]
    async fn read_redirect_points_at_loopback_responder() {
        let (responder, redirect_kv) = crate::start_responder_with_redirect(vec![Route::new(
            "GET",
            "/",
            ScriptedResponse::ok(b"ignored-by-this-test"),
        )])
        .expect("loopback responder binds");
        let backend = fixture(&[(redirect_kv.0, redirect_kv.1.clone())]);

        let read = backend
            .read(target("hello.txt"), ReadOptions::default(), None)
            .await
            .unwrap();
        let ReadResult::Redirect(redirect) = read else {
            panic!("expected Redirect");
        };
        let base = responder.base_url();
        assert!(
            redirect.request.url.starts_with(&base),
            "redirect URL {} should start with responder base {}",
            redirect.request.url,
            base
        );
        assert!(redirect.request.url.ends_with("/hello.txt"));
        assert_eq!(redirect.request.method, "GET");
    }

    #[tokio::test]
    async fn introspection_path_bypasses_redirect_config() {
        let backend = fixture(&[(
            "test_redirect_url",
            ConfigValue::String("https://test.example".into()),
        )]);
        let read = backend
            .read(
                target("__test_meta/method_calls.json"),
                ReadOptions::default(),
                None,
            )
            .await
            .unwrap();
        match read {
            ReadResult::Bytes { .. } => {}
            other => panic!("introspection should return bytes, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn multipart_write_emits_redirect_batch_then_done() {
        let backend = fixture(&[
            (
                "test_redirect_url",
                ConfigValue::String("https://test.example".into()),
            ),
            ("test_multipart_parts", ConfigValue::Int(3)),
        ]);
        let batch = backend
            .write_redirect(target("big.bin"), WriteOptions::default(), None)
            .await
            .unwrap();
        assert_eq!(batch.redirects.len(), 3);
        let results = RedirectResultBatch {
            results: batch
                .redirects
                .iter()
                .map(|_| RedirectResult {
                    status_code: 200,
                    captured_headers: vec![("etag".into(), "abc".into())],
                    captured_body: vec![],
                })
                .collect(),
        };
        let step = backend
            .continue_write(target("big.bin"), batch, results, None)
            .await
            .unwrap();
        let WriteStep::Done(_) = step else {
            panic!("expected Done from continue_write");
        };
        let store = backend.instance.store.lock().unwrap();
        assert!(store.current("big.bin").is_some());
    }

    /// Substitution, not modification: a caller holding a genuine continuation
    /// minted for `minted.bin` presents it against the authorized request
    /// address `victim.bin`. The commit must land on the authorized object.
    /// This plugin is what a third-party author copies, so the rule it tests
    /// them against has to hold in it.
    #[tokio::test]
    async fn continue_write_commits_to_the_authorized_key_not_the_continuations() {
        let backend = fixture(&[
            (
                "test_redirect_url",
                ConfigValue::String("https://test.example".into()),
            ),
            ("test_multipart_parts", ConfigValue::Int(2)),
        ]);
        let batch = backend
            .write_redirect(target("minted.bin"), WriteOptions::default(), None)
            .await
            .unwrap();
        let results = RedirectResultBatch {
            results: batch
                .redirects
                .iter()
                .map(|_| RedirectResult {
                    status_code: 200,
                    captured_headers: vec![("etag".into(), "abc".into())],
                    captured_body: vec![],
                })
                .collect(),
        };
        let step = backend
            .continue_write(target("victim.bin"), batch, results, None)
            .await
            .unwrap();
        let WriteStep::Done(_) = step else {
            panic!("expected Done from continue_write");
        };
        // Only the store assertion can fail: the reported address has always
        // come from the request target, so asserting on it would pin nothing.
        let store = backend.instance.store.lock().unwrap();
        assert!(
            store.current("victim.bin").is_some(),
            "the commit must land on the authorized key"
        );
    }

    /// A redirect that failed is not a commit. Only the broker's
    /// `continue_write` RPC screens non-2xx results, and no follower route
    /// does, so the plugin has to.
    #[tokio::test]
    async fn continue_write_refuses_a_failed_redirect_result() {
        let backend = fixture(&[
            (
                "test_redirect_url",
                ConfigValue::String("https://test.example".into()),
            ),
            ("test_multipart_parts", ConfigValue::Int(1)),
        ]);
        let batch = backend
            .write_redirect(target("big.bin"), WriteOptions::default(), None)
            .await
            .unwrap();
        let results = RedirectResultBatch {
            results: vec![RedirectResult {
                status_code: 500,
                captured_headers: vec![],
                captured_body: vec![],
            }],
        };
        let err = backend
            .continue_write(target("big.bin"), batch, results, None)
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Transient);
        let store = backend.instance.store.lock().unwrap();
        assert!(
            store.current("big.bin").is_none(),
            "a failed redirect must not leave an object behind"
        );
    }

    /// The typed arms, driven through `continue_write` rather than by calling
    /// the mapper directly. A single 500 case would hold identically under a
    /// blanket `|_| Transient`, which is the mapping this function exists to
    /// replace, so it could not distinguish the two.
    #[tokio::test]
    async fn continue_write_maps_redirect_failure_statuses_to_typed_codes() {
        for (status, expected) in [
            (401, ErrorCode::AuthRequired),
            (403, ErrorCode::PermissionDenied),
            (404, ErrorCode::NotFound),
            (410, ErrorCode::NotFound),
            (409, ErrorCode::Conflict),
            (412, ErrorCode::PreconditionFailed),
            (416, ErrorCode::InvalidArgument),
            (408, ErrorCode::DeadlineExceeded),
            (504, ErrorCode::DeadlineExceeded),
            (429, ErrorCode::ResourceExhausted),
            (503, ErrorCode::ResourceExhausted),
            (500, ErrorCode::Transient),
        ] {
            let backend = fixture(&[
                (
                    "test_redirect_url",
                    ConfigValue::String("https://test.example".into()),
                ),
                ("test_multipart_parts", ConfigValue::Int(1)),
            ]);
            let batch = backend
                .write_redirect(target("big.bin"), WriteOptions::default(), None)
                .await
                .unwrap();
            let results = RedirectResultBatch {
                results: vec![RedirectResult {
                    status_code: status,
                    captured_headers: vec![],
                    captured_body: vec![],
                }],
            };
            let err = backend
                .continue_write(target("big.bin"), batch, results, None)
                .await
                .unwrap_err();
            assert_eq!(err.code(), expected, "HTTP {status}");
            assert!(
                backend
                    .instance
                    .store
                    .lock()
                    .unwrap()
                    .current("big.bin")
                    .is_none(),
                "HTTP {status} must not leave an object behind"
            );
        }
    }

    /// The multi-round loop is the only decode-then-re-encode path in the tree.
    /// What this pins is that round two re-encodes the *derived* key rather than
    /// an empty one — the re-encoded blob has to stay decodable by a peer
    /// running an earlier build, which reads that field. It does not pin
    /// substitution-resistance: `#[serde(skip_deserializing)]` already makes the
    /// caller's key unreachable, so a negative assertion here could not fail.
    #[tokio::test]
    async fn continue_write_loop_rederives_on_every_round() {
        let backend = fixture(&[
            (
                "test_redirect_url",
                ConfigValue::String("https://test.example".into()),
            ),
            ("test_multipart_parts", ConfigValue::Int(1)),
            ("test_continue_write_loops", ConfigValue::Int(2)),
        ]);
        let batch1 = backend
            .write_redirect(target("minted.bin"), WriteOptions::default(), None)
            .await
            .unwrap();
        let results = || RedirectResultBatch {
            results: vec![RedirectResult {
                status_code: 200,
                captured_headers: vec![("etag".into(), "abc".into())],
                captured_body: vec![],
            }],
        };
        let step = backend
            .continue_write(target("victim.bin"), batch1, results(), None)
            .await
            .unwrap();
        let WriteStep::Redirects(batch2) = step else {
            panic!("expected a second redirect round");
        };
        // `key` is the only string field in this blob, so a match can only be
        // the key itself.
        let json = String::from_utf8(batch2.continuation.clone()).unwrap();
        assert!(json.contains("victim.bin"), "{json}");

        let step = backend
            .continue_write(target("victim.bin"), batch2, results(), None)
            .await
            .unwrap();
        let WriteStep::Done(_) = step else {
            panic!("expected Done after the final round");
        };
        let store = backend.instance.store.lock().unwrap();
        assert!(store.current("victim.bin").is_some());
    }

    #[tokio::test]
    async fn multipart_with_two_continue_loops_emits_two_redirect_rounds() {
        let backend = fixture(&[
            (
                "test_redirect_url",
                ConfigValue::String("https://test.example".into()),
            ),
            ("test_multipart_parts", ConfigValue::Int(2)),
            ("test_continue_write_loops", ConfigValue::Int(2)),
        ]);
        let batch1 = backend
            .write_redirect(target("two-stage.bin"), WriteOptions::default(), None)
            .await
            .unwrap();
        let results1 = synthesize_results(&batch1);
        let step = backend
            .continue_write(target("two-stage.bin"), batch1, results1, None)
            .await
            .unwrap();
        let WriteStep::Redirects(batch2) = step else {
            panic!("expected a second Redirects batch");
        };
        let results2 = synthesize_results(&batch2);
        let step = backend
            .continue_write(target("two-stage.bin"), batch2, results2, None)
            .await
            .unwrap();
        let WriteStep::Done(_) = step else {
            panic!("expected Done after second continue");
        };
    }

    fn synthesize_results(batch: &WriteRedirectBatch) -> RedirectResultBatch {
        RedirectResultBatch {
            results: batch
                .redirects
                .iter()
                .map(|_| RedirectResult {
                    status_code: 200,
                    captured_headers: vec![],
                    captured_body: vec![],
                })
                .collect(),
        }
    }

    #[tokio::test]
    async fn auth_flow_succeed_emits_one_event() {
        let factory = TestFactory::new();
        let req = ConnectionRequest {
            backend_kind: BACKEND_KIND.into(),
            config: {
                let mut c = HashMap::new();
                c.insert(
                    "test_root".into(),
                    ConfigValue::String("test://demo/".into()),
                );
                c
            },
            credentials: SecretBundle::default(),
            persist: false,
            display_name: None,
        };
        factory.instantiate(&req, None).await.unwrap();
        let conn = mock_connection("test://demo/");
        let stream = factory
            .authenticate(conn, InteractiveAuthCapability::Browser, None)
            .await
            .unwrap();
        let events: Vec<_> = stream.collect();
        assert_eq!(events.len(), 1);
        match events[0].as_ref().unwrap() {
            AuthEvent::Succeeded { .. } => {}
            other => panic!("expected Succeeded, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn auth_flow_progress_then_succeed_emits_two_events() {
        let factory = TestFactory::new();
        let mut config = HashMap::new();
        config.insert(
            "test_root".into(),
            ConfigValue::String("test://demo/".into()),
        );
        config.insert(
            "test_auth_flow".into(),
            ConfigValue::String("progress-then-succeed".into()),
        );
        factory
            .instantiate(
                &ConnectionRequest {
                    backend_kind: BACKEND_KIND.into(),
                    config,
                    credentials: SecretBundle::default(),
                    persist: false,
                    display_name: None,
                },
                None,
            )
            .await
            .unwrap();
        let stream = factory
            .authenticate(
                mock_connection("test://demo/"),
                InteractiveAuthCapability::Browser,
                None,
            )
            .await
            .unwrap();
        let events: Vec<_> = stream.collect();
        assert_eq!(events.len(), 2);
        assert!(matches!(
            events[0].as_ref().unwrap(),
            AuthEvent::Progress { .. }
        ));
        assert!(matches!(
            events[1].as_ref().unwrap(),
            AuthEvent::Succeeded { .. }
        ));
    }

    #[tokio::test]
    async fn auth_flow_fail_emits_failed_event() {
        let factory = TestFactory::new();
        let mut config = HashMap::new();
        config.insert(
            "test_root".into(),
            ConfigValue::String("test://demo/".into()),
        );
        config.insert("test_auth_flow".into(), ConfigValue::String("fail".into()));
        factory
            .instantiate(
                &ConnectionRequest {
                    backend_kind: BACKEND_KIND.into(),
                    config,
                    credentials: SecretBundle::default(),
                    persist: false,
                    display_name: None,
                },
                None,
            )
            .await
            .unwrap();
        let stream = factory
            .authenticate(
                mock_connection("test://demo/"),
                InteractiveAuthCapability::Browser,
                None,
            )
            .await
            .unwrap();
        let events: Vec<_> = stream.collect();
        match events[0].as_ref().unwrap() {
            AuthEvent::Failed { error } => assert_eq!(error.code(), ErrorCode::AuthRequired),
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn watch_directory_emits_n_events_with_lapsed_at_index() {
        let backend = fixture(&[
            ("test_caps_watch", ConfigValue::Bool(true)),
            ("test_watch_event_count", ConfigValue::Int(3)),
            ("test_watch_lapsed_at", ConfigValue::Int(2)),
        ]);
        let stream = backend
            .watch_directory(target(""), WatchDirectoryOptions::default(), None)
            .await
            .unwrap();
        let events: Vec<_> = stream.collect();
        // 3 Object events + 1 inserted Lapsed at index 2 = 4 total.
        assert_eq!(events.len(), 4);
        match events[2].as_ref().unwrap() {
            BackendChangeEvent::Lapsed { .. } => {}
            other => panic!("expected Lapsed at index 2, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn list_versions_returns_full_chain_with_current_at_end() {
        let backend = fixture(&[]);
        for v in 0..3 {
            backend
                .write(
                    target("doc.txt"),
                    format!("v{v}").into_bytes(),
                    WriteOptions::default(),
                    None,
                )
                .await
                .unwrap();
        }
        let versions = backend
            .list_versions(target("doc.txt"), ListVersionsOptions::default(), None)
            .await
            .unwrap();
        assert_eq!(versions.len(), 3);
        for (i, v) in versions.iter().enumerate() {
            assert_eq!(
                v.address.as_str(),
                format!("test://demo/doc.txt?version=v{i}")
            );
        }
    }

    /// Pinning the input address must not filter the result. `list_versions`
    /// always returns full history (the version pin is a read selector, not a
    /// list filter); callers asking "does this version exist" use `stat` or
    /// `get_latest_version` instead.
    #[tokio::test]
    async fn list_versions_ignores_pin_in_input_address() {
        let backend = fixture(&[]);
        for v in 0..3 {
            backend
                .write(
                    target("doc.txt"),
                    format!("v{v}").into_bytes(),
                    WriteOptions::default(),
                    None,
                )
                .await
                .unwrap();
        }
        let pinned = ResolvedTarget {
            backend_id: BackendId("test".into()),
            resolved_address: address::parse("test://demo/doc.txt?version=v1").unwrap(),
        };
        let versions = backend
            .list_versions(pinned, ListVersionsOptions::default(), None)
            .await
            .unwrap();
        assert_eq!(versions.len(), 3, "pinned input must not shrink the list");
        for (i, v) in versions.iter().enumerate() {
            assert_eq!(
                v.address.as_str(),
                format!("test://demo/doc.txt?version=v{i}")
            );
        }
    }

    #[tokio::test]
    async fn get_latest_version_returns_pinned_current_address() {
        let backend = fixture(&[]);
        for v in 0..2 {
            backend
                .write(
                    target("doc.txt"),
                    format!("v{v}").into_bytes(),
                    WriteOptions::default(),
                    None,
                )
                .await
                .unwrap();
        }
        let latest = backend
            .get_latest_version(target("doc.txt"), None)
            .await
            .unwrap();
        assert_eq!(latest.address.as_str(), "test://demo/doc.txt?version=v1");
    }

    #[tokio::test]
    async fn copy_preserves_source_and_creates_destination() {
        let backend = fixture(&[]);
        backend
            .write(
                target("src.txt"),
                b"data".to_vec(),
                WriteOptions::default(),
                None,
            )
            .await
            .unwrap();
        backend
            .copy(
                target("src.txt"),
                target("dst.txt"),
                CopyOptions::default(),
                None,
            )
            .await
            .unwrap();
        let src_read = backend
            .read(target("src.txt"), ReadOptions::default(), None)
            .await
            .unwrap();
        let dst_read = backend
            .read(target("dst.txt"), ReadOptions::default(), None)
            .await
            .unwrap();
        let ReadResult::Bytes {
            bytes: src_bytes, ..
        } = src_read
        else {
            panic!()
        };
        let ReadResult::Bytes {
            bytes: dst_bytes, ..
        } = dst_read
        else {
            panic!()
        };
        assert_eq!(src_bytes, b"data");
        assert_eq!(dst_bytes, b"data");
    }

    #[tokio::test]
    async fn rename_moves_chain_atomically() {
        let backend = fixture(&[]);
        for v in 0..2 {
            backend
                .write(
                    target("old.txt"),
                    format!("v{v}").into_bytes(),
                    WriteOptions::default(),
                    None,
                )
                .await
                .unwrap();
        }
        backend
            .rename(
                target("old.txt"),
                target("new.txt"),
                RenameOptions::default(),
                None,
            )
            .await
            .unwrap();
        let err = backend
            .read(target("old.txt"), ReadOptions::default(), None)
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::NotFound);
        let new_versions = backend
            .list_versions(target("new.txt"), ListVersionsOptions::default(), None)
            .await
            .unwrap();
        assert_eq!(new_versions.len(), 2);
    }

    #[tokio::test]
    async fn read_with_range_slices_bytes() {
        let backend = fixture(&[]);
        backend
            .write(
                target("ranged.txt"),
                b"abcdefghij".to_vec(),
                WriteOptions::default(),
                None,
            )
            .await
            .unwrap();
        let read = backend
            .read(
                target("ranged.txt"),
                ReadOptions {
                    range: Some(ByteRange {
                        start: 2,
                        end_inclusive: Some(5),
                    }),
                    ..ReadOptions::default()
                },
                None,
            )
            .await
            .unwrap();
        let ReadResult::Bytes { bytes, .. } = read else {
            panic!()
        };
        assert_eq!(bytes, b"cdef");
    }

    #[tokio::test]
    async fn read_with_range_open_end_returns_to_eof() {
        let backend = fixture(&[]);
        backend
            .write(
                target("ranged.txt"),
                b"abcdefghij".to_vec(),
                WriteOptions::default(),
                None,
            )
            .await
            .unwrap();
        let read = backend
            .read(
                target("ranged.txt"),
                ReadOptions {
                    range: Some(ByteRange {
                        start: 7,
                        end_inclusive: None,
                    }),
                    ..ReadOptions::default()
                },
                None,
            )
            .await
            .unwrap();
        let ReadResult::Bytes { bytes, .. } = read else {
            panic!()
        };
        assert_eq!(bytes, b"hij");
    }

    #[tokio::test]
    async fn write_round_trips_user_metadata_through_stat() {
        let backend = fixture(&[]);
        let mut metadata = UserMetadata::default();
        metadata.insert("project".into(), "ovstorage".into());
        backend
            .write(
                target("with-meta.txt"),
                b"data".to_vec(),
                WriteOptions {
                    user_metadata: Some(metadata.clone()),
                    ..WriteOptions::default()
                },
                None,
            )
            .await
            .unwrap();
        let info = backend
            .stat(target("with-meta.txt"), StatOptions::default(), None)
            .await
            .unwrap();
        assert_eq!(
            info.user_metadata.as_ref().unwrap().get("project").unwrap(),
            "ovstorage"
        );
    }

    /// The streamed slot keeps `user_metadata` too. Pinned separately from the
    /// buffered case because the two arms reach `commit_bytes` down different
    /// paths, and this kind's `supports_user_metadata` declaration answers for
    /// both at once: a host reads it per kind, not per write slot.
    #[tokio::test]
    async fn write_stream_round_trips_user_metadata_through_stat() {
        let backend = fixture(&[]);
        let mut metadata = UserMetadata::default();
        metadata.insert("project".into(), "ovstorage".into());
        let chunks: Vec<Result<Vec<u8>>> = vec![Ok(b"al".to_vec()), Ok(b"pha".to_vec())];
        backend
            .write_stream(
                target("streamed-meta.bin"),
                BodyStream::from_iter(chunks.into_iter()),
                WriteOptions {
                    user_metadata: Some(metadata.clone()),
                    ..WriteOptions::default()
                },
                None,
            )
            .await
            .unwrap();
        let info = backend
            .stat(target("streamed-meta.bin"), StatOptions::default(), None)
            .await
            .unwrap();
        assert_eq!(
            info.user_metadata.as_ref().unwrap().get("project").unwrap(),
            "ovstorage"
        );
    }

    #[tokio::test]
    async fn update_metadata_sets_and_removes_keys() {
        let backend = fixture(&[]);
        let mut initial = UserMetadata::default();
        initial.insert("a".into(), "1".into());
        initial.insert("b".into(), "2".into());
        backend
            .write(
                target("meta.txt"),
                b"x".to_vec(),
                WriteOptions {
                    user_metadata: Some(initial),
                    ..WriteOptions::default()
                },
                None,
            )
            .await
            .unwrap();
        let mut set = HashMap::new();
        set.insert("a".into(), "rewritten".into());
        let info = backend
            .update_metadata(
                target("meta.txt"),
                UpdateMetadataOptions {
                    user_metadata_set: set,
                    user_metadata_remove: vec!["b".into()],
                    ..UpdateMetadataOptions::default()
                },
                None,
            )
            .await
            .unwrap();
        let metadata = info.user_metadata.as_ref().unwrap();
        assert_eq!(metadata.get("a").unwrap(), "rewritten");
        assert!(!metadata.contains_key("b"));
    }

    #[tokio::test]
    async fn check_access_default_allows_everything() {
        let backend = fixture(&[]);
        let all_ops = AccessOps {
            read: true,
            write: true,
            delete: true,
            update_metadata: true,
        };
        let decision = backend
            .check_access(target(""), all_ops, None)
            .await
            .unwrap();
        assert!(decision.allowed);
        assert_eq!(decision.denied_ops, AccessOps::default());
    }

    #[tokio::test]
    async fn check_access_deny_all_marks_every_op_denied() {
        let backend = fixture(&[(
            "test_check_access_decision",
            ConfigValue::String("deny-all".into()),
        )]);
        let all_ops = AccessOps {
            read: true,
            write: true,
            delete: true,
            update_metadata: true,
        };
        let decision = backend
            .check_access(target(""), all_ops, None)
            .await
            .unwrap();
        assert!(!decision.allowed);
        assert!(decision.denied_ops.read);
        assert!(decision.denied_ops.write);
    }

    #[tokio::test]
    async fn check_access_read_only_marks_writes_denied() {
        let backend = fixture(&[(
            "test_check_access_decision",
            ConfigValue::String("read-only".into()),
        )]);
        let all_ops = AccessOps {
            read: true,
            write: true,
            delete: true,
            update_metadata: true,
        };
        let decision = backend
            .check_access(target(""), all_ops, None)
            .await
            .unwrap();
        assert!(!decision.allowed);
        assert!(!decision.denied_ops.read);
        assert!(decision.denied_ops.write);
        assert!(decision.denied_ops.delete);
    }

    #[tokio::test]
    async fn check_access_read_only_allows_read_only_request() {
        let backend = fixture(&[(
            "test_check_access_decision",
            ConfigValue::String("read-only".into()),
        )]);
        let read_only = AccessOps {
            read: true,
            write: false,
            delete: false,
            update_metadata: false,
        };
        let decision = backend
            .check_access(target(""), read_only, None)
            .await
            .unwrap();
        assert!(decision.allowed);
        assert_eq!(decision.denied_ops, AccessOps::default());
    }

    #[tokio::test]
    async fn check_access_only_returns_requested_ops_in_denied() {
        let backend = fixture(&[(
            "test_check_access_decision",
            ConfigValue::String("read-only".into()),
        )]);
        let write_only = AccessOps {
            read: false,
            write: true,
            delete: false,
            update_metadata: false,
        };
        let decision = backend
            .check_access(target(""), write_only, None)
            .await
            .unwrap();
        assert!(!decision.allowed);
        assert!(decision.denied_ops.write);
        assert!(!decision.denied_ops.delete);
        assert!(!decision.denied_ops.update_metadata);
    }

    #[tokio::test]
    async fn watch_event_kind_modified_propagates_into_events() {
        let backend = fixture(&[
            ("test_caps_watch", ConfigValue::Bool(true)),
            ("test_watch_event_count", ConfigValue::Int(2)),
            (
                "test_watch_event_kind",
                ConfigValue::String("modified".into()),
            ),
        ]);
        let stream = backend
            .watch_directory(target(""), WatchDirectoryOptions::default(), None)
            .await
            .unwrap();
        let events: Vec<_> = stream.collect();
        for event in &events {
            match event.as_ref().unwrap() {
                BackendChangeEvent::Object { kind, .. } => {
                    assert_eq!(*kind, ChangeKind::Modified);
                }
                other => panic!("expected Object, got {other:?}"),
            }
        }
    }

    fn mock_connection(root: &str) -> Connection {
        Connection {
            id: ConnectionId("test-conn".into()),
            backend_kind: BACKEND_KIND.into(),
            display_name: "test".into(),
            source: ConnectionSource::Static {
                layer: ConfigLayer::User,
            },
            capabilities: Capabilities::empty(),
            current_addresses: vec![address::parse(root).unwrap()],
            auth_state: ConnectionAuthState::Anonymous,
            last_probed: None,
            user_metadata: UserMetadata::default(),
        }
    }

    #[tokio::test]
    async fn rejects_address_outside_configured_root() {
        let backend = fixture(&[]);
        let off_root = ResolvedTarget {
            backend_id: BackendId("test".into()),
            resolved_address: address::parse("test://other/x").unwrap(),
        };
        let err = backend
            .read(off_root, ReadOptions::default(), None)
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    #[tokio::test]
    async fn read_with_reversed_range_returns_invalid_argument() {
        let backend = fixture(&[]);
        backend
            .write(
                target("r.txt"),
                b"abcdef".to_vec(),
                WriteOptions::default(),
                None,
            )
            .await
            .unwrap();
        let err = backend
            .read(
                target("r.txt"),
                ReadOptions {
                    range: Some(ByteRange {
                        start: 5,
                        end_inclusive: Some(2),
                    }),
                    ..ReadOptions::default()
                },
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    #[tokio::test]
    async fn read_with_u64_max_end_inclusive_returns_invalid_argument() {
        let backend = fixture(&[]);
        backend
            .write(
                target("r.txt"),
                b"abcdef".to_vec(),
                WriteOptions::default(),
                None,
            )
            .await
            .unwrap();
        let err = backend
            .read(
                target("r.txt"),
                ReadOptions {
                    range: Some(ByteRange {
                        start: 0,
                        end_inclusive: Some(u64::MAX),
                    }),
                    ..ReadOptions::default()
                },
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    #[tokio::test]
    async fn root_is_segment_aware_against_lookalike_address() {
        let backend = fixture(&[]);
        let lookalike = ResolvedTarget {
            backend_id: BackendId("test".into()),
            resolved_address: address::parse("test://demofoo/bar").unwrap(),
        };
        let err = backend
            .read(lookalike, ReadOptions::default(), None)
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    #[tokio::test]
    async fn copy_if_match_mismatch_returns_precondition_failed() {
        let backend = fixture(&[]);
        backend
            .write(target("a"), b"data".to_vec(), WriteOptions::default(), None)
            .await
            .unwrap();
        let err = backend
            .copy(
                target("a"),
                target("b"),
                CopyOptions {
                    if_source: Some("nope".into()),
                    ..Default::default()
                },
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::PreconditionFailed);
        let store = backend.instance.store.lock().unwrap();
        assert!(store.current("b").is_none());
    }

    #[tokio::test]
    async fn rename_if_match_mismatch_returns_precondition_failed() {
        let backend = fixture(&[]);
        backend
            .write(target("a"), b"data".to_vec(), WriteOptions::default(), None)
            .await
            .unwrap();
        let err = backend
            .rename(
                target("a"),
                target("b"),
                RenameOptions {
                    if_source: Some("nope".into()),
                    ..Default::default()
                },
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::PreconditionFailed);
        let store = backend.instance.store.lock().unwrap();
        assert!(store.current("a").is_some());
        assert!(store.current("b").is_none());
    }

    #[tokio::test]
    async fn list_with_max_results_returns_unsupported() {
        let backend = fixture(&[]);
        let err = backend
            .list(
                target(""),
                ListOptions {
                    max_results: Some(1),
                    ..ListOptions::default()
                },
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Unsupported);
    }

    #[tokio::test]
    async fn list_versions_with_page_token_returns_unsupported() {
        let backend = fixture(&[]);
        backend
            .write(target("v"), b"x".to_vec(), WriteOptions::default(), None)
            .await
            .unwrap();
        let err = backend
            .list_versions(
                target("v"),
                ListVersionsOptions {
                    page_token: Some("cursor".into()),
                    ..ListVersionsOptions::default()
                },
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Unsupported);
    }

    #[tokio::test]
    async fn write_stream_records_write_stream_observation_with_real_byte_len() {
        let backend = fixture(&[]);
        let chunks: Vec<Result<Vec<u8>>> = vec![Ok(b"abc".to_vec()), Ok(b"defgh".to_vec())];
        let stream = BodyStream::from_iter(chunks.into_iter());
        backend
            .write_stream(target("s.bin"), stream, WriteOptions::default(), None)
            .await
            .unwrap();
        let log = backend.instance.recorder.snapshot();
        let last = log.last().unwrap();
        match last {
            ObservedCall::WriteStream { byte_len, .. } => assert_eq!(*byte_len, 8),
            other => panic!("expected WriteStream, got {other:?}"),
        }
        assert_eq!(last.method_name(), "write_stream");
    }

    #[tokio::test]
    async fn keep_alive_watch_exits_on_cancellation() {
        let backend = fixture(&[
            ("test_caps_watch", ConfigValue::Bool(true)),
            ("test_watch_event_count", ConfigValue::Int(0)),
            ("test_watch_keep_alive", ConfigValue::Bool(true)),
        ]);
        let token = CancellationToken::new();
        let stream = backend
            .watch_directory(
                target(""),
                WatchDirectoryOptions::default(),
                Some(token.clone()),
            )
            .await
            .unwrap();
        let exit = std::thread::Builder::new()
            .name("ovs-test-stream".into())
            .spawn(move || stream.collect::<Vec<_>>())
            .expect("failed to spawn thread");
        std::thread::sleep(std::time::Duration::from_millis(80));
        token.cancel();
        let result = tokio::task::spawn_blocking(move || exit.join())
            .await
            .unwrap()
            .expect("watch thread joined");
        assert!(result.is_empty());
    }
}

#[cfg(test)]
mod user_metadata_declaration_tests {
    use super::*;

    /// This kind's `supports_user_metadata` declaration is what a host reads to
    /// decide whether to compose its attribution layer over this backend's
    /// branch. Asserted here, in the crate that owns the answer, because a host
    /// crate cannot reach it: a plugin crate may not depend on a host-side
    /// crate, and two plugin rlibs in one test binary are a duplicate-symbol
    /// link error under `rust-lld`.
    ///
    /// **`true` is the coarse answer, and this backend is the shape that makes
    /// it coarse.** The buffered and streaming write slots store what they are
    /// handed and `stat` returns it; the redirect slot flows bytes through the
    /// URL and commits a placeholder built from the continuation alone, so a
    /// `user_metadata` map handed to `write_redirect` is not persisted. A
    /// declaration answers for the kind rather than for one write path, so a
    /// backend whose paths disagree has to pick one answer for all of them.
    /// This one picks `true`; `opendal` faces the same disagreement across its
    /// drivers and picks `false`.
    #[test]
    fn the_conformance_backend_declares_its_user_metadata_support() {
        let descriptor = TestFactory::new().descriptor();
        assert!(
            descriptor.supports_user_metadata,
            "the conformance backend's buffered write stores user metadata and \
             stat returns it, so a host composes its attribution layer over \
             that branch"
        );
    }
}
