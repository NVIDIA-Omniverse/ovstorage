// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![doc = include_str!("../README.md")]

mod driver;
mod layer;

use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use opendal::{EntryMode, ErrorKind as OpenDalErrorKind, Metadata, Metakey, Operator, Scheme};
use tracing::{Instrument as _, debug_span};

struct RedactedUrl<'a>(&'a Url);

impl std::fmt::Display for RedactedUrl<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}://{}{}",
            self.0.scheme(),
            self.0.host_str().unwrap_or(""),
            self.0.path()
        )
    }
}

use ovstorage_plugin::{
    AccessOps, ByteRange, CancellationToken, Capabilities, ChecksumSet, ConfigField,
    ConfigFieldKind, ConfigValue, ConnectionId, ConnectionRequest, CopyOptions,
    CreateDirectoryOptions, CredentialField, CredentialMethod, DeleteDirectoryOptions,
    DeleteOptions, EnumSource, Error, ErrorCode, ErrorContext, HttpRequest, IfDestExists,
    ListOptions, ObjectInfo, ObjectKind, ReadOptions, RedirectBodySource, RedirectCredential,
    RedirectResultBatch, RedirectScope, RenameOptions, ResolvedTarget, Result, ResultCapture,
    SecretValue, StatOptions, StorageBackendKindDescriptor, Url, WriteOptions, WriteRedirect,
    WriteRedirectBatch, WriteResult, address, race_cancel, reject_pinned_for_mutation,
    validate_redirect_results,
};

const PINNED_VERSION_KEYS: &[&str] = &[
    "versionId",
    "generation",
    "versionid",
    "version",
    "checkpoint",
];
use ovstorage_plugin::{BackendItemInfo, ReadResult, WriteStep};

const PRESIGN_LIFETIME_SECS: u64 = 5 * 60;

/// User-metadata key under which `WriteOptions::message` is persisted on
/// drivers that support custom user metadata.
const OV_MESSAGE_KEY: &str = "x-ov-message";

// Including signed-query parameters in `RedirectScope.physical_url_prefix`
// would make every prefix unique and defeat host-side scope checks.
fn scope_prefix_from_url(raw: &str) -> String {
    if let Ok(parsed) = Url::parse(raw) {
        let scheme = parsed.scheme();
        let authority = parsed
            .host_str()
            .map(|host| match parsed.port() {
                Some(port) => format!("{host}:{port}"),
                None => host.to_string(),
            })
            .unwrap_or_default();
        return format!("{scheme}://{authority}{}", parsed.path());
    }
    raw.split_once('?')
        .map(|(prefix, _)| prefix.to_string())
        .unwrap_or_else(|| raw.to_string())
}

fn monotonic_id() -> u128 {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    nanos ^ ((n as u128) << 64)
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum DriverCapabilityProfile {
    Fs,
    S3,
    Webdav,
}

#[derive(Copy, Clone, Debug)]
struct DriverSpec {
    service: &'static str,
    display_name: &'static str,
    profile: DriverCapabilityProfile,
    scheme: Scheme,
    /// Name of the OpenDAL workspace feature this driver requires; instantiate
    /// reports it by name when `Scheme::enabled()` does not include it.
    required_feature: Option<&'static str>,
    supports_server_side_copy: bool,
    supports_server_side_rename: bool,
}

static DRIVER_SPECS: &[DriverSpec] = &[
    DriverSpec {
        service: "fs",
        display_name: "OpenDAL fs",
        profile: DriverCapabilityProfile::Fs,
        scheme: Scheme::Fs,
        required_feature: None,
        supports_server_side_copy: true,
        supports_server_side_rename: true,
    },
    DriverSpec {
        service: "s3",
        display_name: "OpenDAL S3-compatible",
        profile: DriverCapabilityProfile::S3,
        scheme: Scheme::S3,
        required_feature: None,
        supports_server_side_copy: false,
        supports_server_side_rename: false,
    },
    DriverSpec {
        service: "webdav",
        display_name: "OpenDAL WebDAV",
        profile: DriverCapabilityProfile::Webdav,
        scheme: Scheme::Webdav,
        required_feature: None,
        supports_server_side_copy: true,
        supports_server_side_rename: false,
    },
];

fn driver_capabilities(spec: &DriverSpec) -> Capabilities {
    let mut caps = Capabilities::empty();
    caps.supports_write = true;
    caps.supports_write_stream = true;
    caps.supports_delete = true;
    caps.supports_create_directory = true;
    caps.supports_delete_directory = true;
    match spec.profile {
        DriverCapabilityProfile::Fs => {
            caps.has_real_directories = true;
            caps.supports_recursive_list = true;
            caps.supports_list = true;
            caps.populates_subdirectory_metadata = true;
            // NOT writes_are_atomic: OpenDAL's `Fs` writer (0.50.2) writes the
            // target file in place unless `atomic_write_dir` is configured
            // (which this adapter does not set), so a concurrent reader can
            // observe a partial object.
        }
        DriverCapabilityProfile::S3 => {
            caps.supports_recursive_list = true;
            caps.supports_list = true;
            caps.supports_no_overwrite_write = true;
            caps.supports_write_redirect = true;
            // S3 object writes are atomic at the API level: a single-part PUT
            // or a CompleteMultipartUpload publishes the object all at once —
            // a reader never observes a partial object.
            caps.writes_are_atomic = true;
        }
        DriverCapabilityProfile::Webdav => {
            caps.has_real_directories = true;
            caps.supports_recursive_list = true;
            caps.supports_list = true;
            caps.populates_subdirectory_metadata = true;
        }
    }
    caps.supports_server_side_copy = spec.supports_server_side_copy;
    caps.supports_server_side_rename = spec.supports_server_side_rename;
    caps.supports_copy = spec.supports_server_side_copy;
    caps.supports_rename = spec.supports_server_side_rename;
    caps.supports_atomic_rename =
        spec.supports_server_side_rename && matches!(spec.profile, DriverCapabilityProfile::Fs);
    caps
}

#[derive(Clone, Debug)]
struct OpenDalConnectionConfig {
    driver: &'static DriverSpec,
    prefix: Url,
}

pub struct OpenDalBackend {
    service: &'static str,
    operator: Operator,
    prefix: Url,
    capabilities: Capabilities,
}

/// The static backend descriptor; converted to the v2 `LayerKindDescriptor`
/// via `descriptor_to_layer_kind` at the factory/layer surface.
pub(crate) fn kind_descriptor() -> StorageBackendKindDescriptor {
    StorageBackendKindDescriptor {
            kind: "opendal".into(),
            display_name: "OpenDAL".into(),
            description: Some(
                "Native ovstorage adapter over Apache OpenDAL service drivers.".into(),
            ),
            config_schema: vec![
                ConfigField {
                    key: "service".into(),
                    display_name: "Service".into(),
                    kind: ConfigFieldKind::Enum {
                        source: EnumSource::Static(
                            DRIVER_SPECS
                                .iter()
                                .map(|driver| driver.service.to_string())
                                .collect(),
                        ),
                    },
                    required: true,
                    default: Some(ConfigValue::String("fs".into())),
                    help: Some("OpenDAL service driver to configure for this connection".into()),
                    example: Some("s3".into()),
                    group: Some("provider".into()),
                    advanced: false,
                },
                ConfigField {
                    key: "endpoint".into(),
                    display_name: "Endpoint".into(),
                    kind: ConfigFieldKind::Text,
                    required: false,
                    default: None,
                    help: Some(
                        "Service endpoint passed to the chosen OpenDAL driver (s3 / webdav)"
                            .into(),
                    ),
                    example: Some("http://127.0.0.1:9000".into()),
                    group: Some("provider".into()),
                    advanced: true,
                },
                ConfigField {
                    key: "config_json".into(),
                    display_name: "Config JSON".into(),
                    kind: ConfigFieldKind::Text,
                    required: false,
                    default: Some(ConfigValue::String("{}".into())),
                    help: Some(
                        "JSON object of additional driver-specific options merged into the OpenDAL configuration."
                            .into(),
                    ),
                    example: Some("{\"root\":\"/tmp/data\"}".into()),
                    group: Some("provider".into()),
                    advanced: true,
                },
                ConfigField {
                    key: "prefix".into(),
                    display_name: "Address prefix".into(),
                    kind: ConfigFieldKind::Url,
                    required: false,
                    default: None,
                    help: Some(
                        "Optional caller-facing route prefix; defaults to opendal://<service>/"
                            .into(),
                    ),
                    example: Some("opendal://s3/".into()),
                    group: Some("routing".into()),
                    advanced: true,
                },
            ],
            credential_schema: vec![
                CredentialField {
                    key: "access_key_id".into(),
                    display_name: "Access key ID".into(),
                    default: None,
                    help: Some("S3 access key id passed through to the OpenDAL S3 driver".into()),
                    advanced: false,
                },
                CredentialField {
                    key: "secret_access_key".into(),
                    display_name: "Secret access key".into(),
                    default: None,
                    help: Some(
                        "S3 secret access key passed through to the OpenDAL S3 driver".into(),
                    ),
                    advanced: false,
                },
                CredentialField {
                    key: "password".into(),
                    display_name: "Password".into(),
                    default: None,
                    help: Some(
                        "WebDAV / HTTP basic-auth password passed to the OpenDAL driver".into(),
                    ),
                    advanced: false,
                },
                CredentialField {
                    key: "private_key".into(),
                    display_name: "SSH private key".into(),
                    default: None,
                    help: Some(
                        "PEM-encoded SSH private key passed to the OpenDAL SFTP driver".into(),
                    ),
                    advanced: false,
                },
            ],
            credential_methods: vec![CredentialMethod {
                key: "credentials".into(),
                display_name: "Driver credentials".into(),
                fields: vec![
                    "access_key_id".into(),
                    "secret_access_key".into(),
                    "password".into(),
                    "private_key".into(),
                ],
                help: Some(
                    "Pass driver-specific credentials through to OpenDAL. \
                     Empty bundle yields anonymous access where the driver supports it."
                        .into(),
                ),
                advanced: false,
            }],
            icon: None,
            supports_runtime_add: true,
            // Whether a write's `user_metadata` survives is a per-connection
            // fact here: the buffered and streaming slots keep it when the
            // driver advertises `write_with_user_metadata` and refuse the write
            // when it does not, and a presigned write rejects it outright. One
            // kind fronts drivers that disagree, so declaring support would cost
            // the presigned write path to every connection whose driver presigns
            // at all, and fail outright on a driver without metadata support.
            // Picking an answer for all of them is the plugin's call, and this
            // one declines. Declining costs a
            // metadata-capable driver the host's stamp, which is the quieter of
            // the two.
            supports_user_metadata: false,
        }
}

/// The OpenDAL object/data operations used by the native Layer slots.
/// `crate::layer::OpenDalLayer` delegates its operation slots here.
impl OpenDalBackend {
    pub async fn stat(
        &self,
        target: ResolvedTarget,
        _opts: StatOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        let span = debug_span!(
            "opendal.stat",
            op = "stat",
            plugin = "opendal",
            object.address = %RedactedUrl(&target.resolved_address),
        );
        let key = self.relative_key(&target.resolved_address)?;
        race_cancel(
            cancel.as_ref(),
            async {
                let metadata = self.operator.stat(&key).await.map_err(map_opendal_error)?;
                Ok(object_info_from_metadata(
                    target.resolved_address,
                    &metadata,
                ))
            }
            .instrument(span),
        )
        .await
    }

    pub async fn read(
        &self,
        target: ResolvedTarget,
        opts: ReadOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ReadResult> {
        let span = debug_span!(
            "opendal.read",
            op = "read",
            plugin = "opendal",
            object.address = %RedactedUrl(&target.resolved_address),
        );
        use futures::StreamExt;
        let key = self.relative_key(&target.resolved_address)?;
        race_cancel(
            cancel.as_ref(),
            async {
                const DIRECTORY_GUIDANCE: &str = "read target is a directory; use list()";
                // A directory leaf reaches this stat in either spelling:
                // OpenDAL addresses directories with a trailing slash, so a
                // stat of the slash-less key either succeeds with
                // `EntryMode::DIR` or fails with a directory-shaped error.
                // The success arm answers from metadata already in hand; the
                // failure arm probes the other spelling only on a stat that
                // already failed non-retryably, so a successful read costs
                // nothing extra. Both arms are gated on `has_real_directories` like
                // `delete` and like `list`'s kind verdict: flat profiles pay
                // no probe round trip, keep reading a zero-byte directory
                // marker, and never reclassify a genuine `NotFound`.
                let metadata = match self.operator.stat(&key).await {
                    Ok(metadata)
                        if metadata.mode() == EntryMode::DIR
                            && self.capabilities.has_real_directories =>
                    {
                        return Err(Error::new(ErrorCode::InvalidArgument, DIRECTORY_GUIDANCE));
                    }
                    Ok(metadata) => metadata,
                    Err(err) => {
                        // Only a stat that failed for a non-retryable reason is
                        // worth probing. A network profile (hdfs/webhdfs) whose
                        // stat times out maps to `Transient`; probing there
                        // would let a stale-but-successful `key/` stat rewrite a
                        // healthy file's transient fault into a permanent
                        // `InvalidArgument` the route retry cannot clear, and
                        // would cost a second round trip on every failing read.
                        // The probe stays check-then-act — a kind swap between
                        // the two stats can still slip through — so callers only
                        // ever gain from it (see `leaf_type_mismatch`).
                        let mapped = map_opendal_error(err);
                        if self.capabilities.has_real_directories
                            && !mapped.code().retryable()
                            && let Some(mismatch) = self
                                .leaf_type_mismatch(&key, false, DIRECTORY_GUIDANCE)
                                .await
                        {
                            return Err(mismatch);
                        }
                        return Err(mapped);
                    }
                };
                if let Some(expected) = opts.if_match.as_deref() {
                    let actual = metadata.etag().map(str::to_string);
                    if actual.as_deref() != Some(expected) {
                        return Err(Error::new(ErrorCode::ObjectModified, "object etag changed")
                            .with_context(ErrorContext::Identity { new_etag: actual }));
                    }
                }
                let info = object_info_from_metadata(target.resolved_address, &metadata);
                let reader = self
                    .operator
                    .reader(&key)
                    .await
                    .map_err(map_opendal_error)?;
                let byte_stream = if let Some(range) = opts.range {
                    let opendal_range = opendal_range(&range)?;
                    reader
                        .into_bytes_stream(opendal_range)
                        .await
                        .map_err(map_opendal_error)?
                } else {
                    reader
                        .into_bytes_stream(..)
                        .await
                        .map_err(map_opendal_error)?
                };
                let stream: ovstorage_plugin::ReadStream =
                    Box::pin(byte_stream.map(|item| item.map_err(map_io_error)));
                Ok(ReadResult::Stream { stream, info })
            }
            .instrument(span),
        )
        .await
    }

    pub async fn write(
        &self,
        target: ResolvedTarget,
        bytes: Vec<u8>,
        opts: WriteOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        reject_pinned_for_mutation(
            &target.resolved_address,
            "opendal write",
            PINNED_VERSION_KEYS,
        )?;
        let span = debug_span!(
            "opendal.write",
            op = "write",
            plugin = "opendal",
            object.address = %RedactedUrl(&target.resolved_address),
            size_bytes = bytes.len() as u64,
        );
        let key = self.relative_key(&target.resolved_address)?;
        race_cancel(
            cancel.as_ref(),
            async {
                self.preflight_write(&opts)?;
                let mut builder = self.operator.write_with(&key, bytes);
                if matches!(opts.if_dest, IfDestExists::Fail) {
                    if !self
                        .operator
                        .info()
                        .full_capability()
                        .write_with_if_none_match
                    {
                        return Err(Error::new(
                            ErrorCode::Unsupported,
                            format!(
                                "OpenDAL service '{}' does not support atomic if_dest=Fail write",
                                self.service
                            ),
                        ));
                    }
                    builder = builder.if_none_match("*");
                }
                let user_meta = self.write_user_metadata("write", &opts)?;
                if !user_meta.is_empty() {
                    builder = builder.user_metadata(user_meta);
                }
                builder.await.map_err(map_no_overwrite_error)?;
                let metadata = self.operator.stat(&key).await.map_err(map_opendal_error)?;
                let info = object_info_from_metadata(target.resolved_address, &metadata);
                Ok(WriteResult { info })
            }
            .instrument(span),
        )
        .await
    }

    pub async fn write_stream(
        &self,
        target: ResolvedTarget,
        stream: ovstorage_plugin::BodyStream,
        opts: WriteOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        reject_pinned_for_mutation(
            &target.resolved_address,
            "opendal write_stream",
            PINNED_VERSION_KEYS,
        )?;
        let span = debug_span!(
            "opendal.write_stream",
            op = "write",
            plugin = "opendal",
            object.address = %RedactedUrl(&target.resolved_address),
            // size_bytes omitted: streaming body — unknown at entry
        );
        async move {
            let key = self.relative_key(&target.resolved_address)?;
            self.preflight_write(&opts)?;
            // OpenDAL 0.50 `writer_with` lacks `if_none_match`; streamed if_dest=Fail cannot be atomic.
            if matches!(opts.if_dest, IfDestExists::Fail) {
                return Err(Error::new(
                    ErrorCode::Unsupported,
                    format!(
                        "OpenDAL service '{}' does not support if_dest=Fail streaming write",
                        self.service
                    ),
                ));
            }
            let mut builder = self.operator.writer_with(&key);
            let user_meta = self.write_user_metadata("write_stream", &opts)?;
            if !user_meta.is_empty() {
                builder = builder.user_metadata(user_meta);
            }
            let mut writer = race_cancel(cancel.as_ref(), async {
                builder.await.map_err(map_opendal_error)
            })
            .await?;
            for chunk in stream {
                if let Some(token) = cancel.as_ref()
                    && token.is_cancelled()
                {
                    return Err(Error::new(ErrorCode::Cancelled, "cancelled by host"));
                }
                let bytes = chunk?;
                writer.write(bytes).await.map_err(map_opendal_error)?;
            }
            writer.close().await.map_err(map_opendal_error)?;
            let metadata = self.operator.stat(&key).await.map_err(map_opendal_error)?;
            let info = object_info_from_metadata(target.resolved_address, &metadata);
            Ok(WriteResult { info })
        }
        .instrument(span)
        .await
    }

    pub async fn write_redirect(
        &self,
        target: ResolvedTarget,
        opts: WriteOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteRedirectBatch> {
        reject_pinned_for_mutation(
            &target.resolved_address,
            "opendal write_redirect",
            PINNED_VERSION_KEYS,
        )?;
        let span = debug_span!(
            "opendal.write",
            op = "write",
            plugin = "opendal",
            object.address = %RedactedUrl(&target.resolved_address),
            size_bytes = opts.size_hint,
        );
        async move {
            // Gate before size-hint check so drivers without presign fall through to write_stream / write.
            if !self.operator.info().full_capability().presign_write {
                return Err(Error::new(
                    ErrorCode::Unsupported,
                    format!(
                        "OpenDAL service '{}' does not support presigned writes",
                        self.service
                    ),
                ));
            }
            // OpenDAL 0.50 `presign_write_with` carries no conditional headers or user metadata.
            if !matches!(opts.if_dest, IfDestExists::Overwrite) {
                return Err(Error::new(
                    ErrorCode::Unsupported,
                    "presigned writes cannot enforce destination preconditions",
                ));
            }
            if has_user_metadata(&opts) {
                return Err(Error::new(
                    ErrorCode::Unsupported,
                    "presigned writes cannot carry user_metadata",
                ));
            }
            // `opts.message` is discarded on this path rather than refused: a
            // presigned PUT has nowhere to carry the `x-ov-message` stash, and
            // the contract lets a backend drop a per-operation annotation. A
            // refusal would instead send every annotated write back through the
            // host, which is what the redirect exists to avoid.
            let advertised_len = opts.size_hint.ok_or_else(|| {
                Error::new(
                    ErrorCode::Unsupported,
                    "presigned writes require WriteOptions.size_hint",
                )
            })?;
            let key = self.relative_key(&target.resolved_address)?;
            self.preflight_write(&opts)?;
            let presigned = race_cancel(cancel.as_ref(), async {
                self.operator
                    .presign_write(&key, Duration::from_secs(PRESIGN_LIFETIME_SECS))
                    .await
                    .map_err(map_opendal_error)
            })
            .await?;
            let mut headers: Vec<(String, String)> = Vec::with_capacity(presigned.header().len());
            for (name, value) in presigned.header().iter() {
                let value = value.to_str().map_err(|e| {
                    Error::new(
                        ErrorCode::Internal,
                        format!("OpenDAL presigned header {name} is non-ASCII: {e}"),
                    )
                })?;
                headers.push((name.as_str().to_string(), value.to_string()));
            }
            let now = SystemTime::now();
            let expires_at = now + Duration::from_secs(PRESIGN_LIFETIME_SECS);
            let redirect = WriteRedirect {
                request: HttpRequest {
                    method: presigned.method().as_str().to_string(),
                    url: presigned.uri().to_string(),
                    headers,
                },
                body_source: RedirectBodySource::UserBytes {
                    offset: 0,
                    len: advertised_len,
                },
                result_capture: ResultCapture {
                    headers: vec!["etag".into(), "last-modified".into()],
                    body_max_bytes: 1024,
                },
                expires_at,
                scope: RedirectScope {
                    physical_url_prefix: scope_prefix_from_url(&presigned.uri().to_string()),
                    operations: AccessOps {
                        write: true,
                        ..AccessOps::default()
                    },
                    expires_at,
                    // The headers above are copied verbatim out of
                    // `presigned.header()`; OpenDAL's operator minted them and
                    // this plugin cannot tell a per-object presign from a
                    // forwarded connection credential.
                    credential: RedirectCredential::Unspecified,
                },
                audit_id: format!("opendal-presign-{}", monotonic_id()),
                policy_epoch: 0,
            };
            Ok(WriteRedirectBatch {
                // The key is still emitted, but only so a continuation minted
                // here stays decodable by a peer replica running an earlier
                // build while an upload is in flight. `continue_write` re-derives
                // the key and never reads this copy.
                continuation: key.into_bytes(),
                redirects: vec![redirect],
            })
        }
        .instrument(span)
        .await
    }

    pub async fn continue_write(
        &self,
        target: ResolvedTarget,
        redirects: WriteRedirectBatch,
        results: RedirectResultBatch,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteStep> {
        let span = debug_span!(
            "opendal.continue_write",
            op = "write",
            plugin = "opendal",
            object.address = %RedactedUrl(&target.resolved_address),
        );
        // A pinned-version address is refused here too, though not for the
        // reason the mutating verbs refuse it — the caller's presigned PUT has
        // already committed, and this method only stats. What it would get
        // wrong is the report: the selector is dropped when the key is derived,
        // so the stat would describe the current object while authorization was
        // decided on the frozen-version URL.
        reject_pinned_for_mutation(
            &target.resolved_address,
            "opendal continue_write",
            PINNED_VERSION_KEYS,
        )?;
        validate_redirect_results(&redirects, &results)?;
        for (i, result) in results.results.iter().enumerate() {
            if !(200..300).contains(&result.status_code) {
                return Err(map_redirect_status(result.status_code, i));
            }
        }
        // Derive the object from the authorized request address, and never
        // decode `redirects.continuation`. Under the broker's client-driven
        // route the blob arrives from the remote caller, and this plugin's blob
        // is the bare object key: any UTF-8 it sent would otherwise be the key
        // this stat probes.
        let key = self.relative_key(&target.resolved_address)?;
        race_cancel(
            cancel.as_ref(),
            async {
                let metadata = self.operator.stat(&key).await.map_err(map_opendal_error)?;
                let info = object_info_from_metadata(target.resolved_address, &metadata);
                Ok(WriteStep::Done(WriteResult { info }))
            }
            .instrument(span),
        )
        .await
    }

    /// Mirror of `FileBackend`'s leaf probe: `map_opendal_error`
    /// folds wrong-shape failures into `Transient`/`NotFound`, but when the
    /// operation's own leaf exists with the other kind the caller used the
    /// wrong operation — surface `InvalidArgument` with guidance instead.
    /// Genuine absence and mid-path wrong-shape components keep the mapped
    /// error (the probe returns `None`).
    ///
    /// BEST-EFFORT, deliberately fail-open: every probe `stat` failure is
    /// folded to `None` (proceed with the op's own outcome). Failing closed
    /// is not portable — on fs a probe of `file.txt/` surfaces the same
    /// ENOTDIR-shaped error as a transient fault, so propagating probe
    /// errors would break every plain-file delete. The probe-then-act
    /// sequence is also check-then-act: a concurrent kind swap between the
    /// probe and the operation can still slip through — OpenDAL has no
    /// atomic kind-conditional ops to close it (the same honesty as the
    /// `if_match` refusal in `delete`). Callers therefore only ever gain
    /// protection from the probe; they must not rely on it as a guarantee.
    async fn leaf_type_mismatch(
        &self,
        key: &str,
        wants_directory: bool,
        guidance: &str,
    ) -> Option<Error> {
        // Probe the other kind's spelling: OpenDAL addresses directories
        // with a trailing slash and files without one.
        let probe_key = if wants_directory {
            key.trim_end_matches('/').to_string()
        } else {
            format!("{}/", key.trim_end_matches('/'))
        };
        if probe_key.is_empty() || probe_key == "/" {
            return None;
        }
        let metadata = self.operator.stat(&probe_key).await.ok()?;
        let mismatched = if wants_directory {
            metadata.mode() == EntryMode::FILE
        } else {
            metadata.mode() == EntryMode::DIR
        };
        mismatched.then(|| Error::new(ErrorCode::InvalidArgument, guidance))
    }

    pub async fn delete(
        &self,
        target: ResolvedTarget,
        opts: DeleteOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        reject_pinned_for_mutation(
            &target.resolved_address,
            "opendal delete",
            PINNED_VERSION_KEYS,
        )?;
        let span = debug_span!(
            "opendal.delete",
            op = "delete",
            plugin = "opendal",
            object.address = %RedactedUrl(&target.resolved_address),
        );
        let key = self.relative_key(&target.resolved_address)?;
        race_cancel(
            cancel.as_ref(),
            async {
                // SPI contract: `if_match: None` (or `Some("")`) is
                // equivalent to no precondition. Only refuse a
                // populated etag, since OpenDAL's delete has no
                // atomic conditional.
                if let Some(id) = &opts.if_match
                    && !id.is_empty()
                {
                    return Err(Error::new(
                        ErrorCode::Unsupported,
                        "OpenDAL delete cannot enforce if_match atomically",
                    ));
                }
                // Real-directories profiles delete a directory leaf
                // *successfully* (no error to hook), so the type-mismatch
                // probe must run before the destructive call. This
                // is one extra `stat` per delete on these profiles — a
                // local metadata read on fs, a network PROPFIND on WebDAV
                // — accepted deliberately: the alternative is silent
                // directory loss on a mistyped delete.
                if self.capabilities.has_real_directories
                    && let Some(mismatch) = self
                        .leaf_type_mismatch(
                            &key,
                            false,
                            "delete target is a directory; use delete_directory()",
                        )
                        .await
                {
                    return Err(mismatch);
                }
                self.operator.delete(&key).await.map_err(map_opendal_error)
            }
            .instrument(span),
        )
        .await
    }

    pub async fn list(
        &self,
        prefix: ResolvedTarget,
        opts: ListOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<Vec<ObjectInfo>> {
        let span = debug_span!(
            "opendal.list",
            op = "list",
            plugin = "opendal",
            object.address = %RedactedUrl(&prefix.resolved_address),
        );
        let listed_prefix = address::directory_key(&self.relative_key(&prefix.resolved_address)?);
        let prefix_address = prefix.resolved_address.clone();
        let recursive = opts.recursive;
        let page_token = opts.page_token.clone();
        let max_results = opts.max_results;
        race_cancel(
            cancel.as_ref(),
            async {
                let entries = {
                    let mut builder = self.operator.list_with(&listed_prefix).recursive(recursive);
                    if let Some(token) = page_token.as_deref() {
                        builder = builder.start_after(token);
                    }
                    match builder
                        .metakey(Metakey::ContentLength | Metakey::LastModified | Metakey::Etag)
                        .await
                    {
                        Ok(entries) => entries,
                        Err(err) => {
                            // Only the prefix itself is probed, and
                            // only on real-directories profiles: a
                            // wrong-shaped component deeper in a recursive
                            // descent still surfaces the mapped error, and
                            // on a flat namespace an object `data` and a
                            // prefix `data/` legitimately coexist — a
                            // transient/denied list there must not be
                            // reclassified as a type mismatch.
                            if self.capabilities.has_real_directories
                                && let Some(mismatch) = self
                                    .leaf_type_mismatch(
                                        &listed_prefix,
                                        true,
                                        "list prefix is a file, not a directory",
                                    )
                                    .await
                            {
                                return Err(mismatch);
                            }
                            return Err(map_opendal_error(err));
                        }
                    }
                };
                let mut out = Vec::with_capacity(entries.len());
                for entry in entries {
                    let raw_entry_path = entry.path();
                    let entry_path = raw_entry_path.trim_start_matches('/');
                    let relative_key = entry_path
                        .strip_prefix(listed_prefix.as_str())
                        .ok_or_else(|| {
                            Error::new(
                                ErrorCode::Internal,
                                format!(
                                    "OpenDAL list entry '{raw_entry_path}' is outside requested prefix '{listed_prefix}'"
                                ),
                            )
                        })?;
                    if relative_key.is_empty() {
                        // The entry is the prefix leaf itself. Some services
                        // (fs included) "list" a file by returning the file
                        // as its own single entry instead of erroring; on a
                        // real-directories profile that means the caller
                        // listed a file leaf — the wrong operation.
                        if self.capabilities.has_real_directories
                            && entry.metadata().mode() != EntryMode::DIR
                            && let Some(mismatch) = self
                                .leaf_type_mismatch(
                                    &listed_prefix,
                                    true,
                                    "list prefix is a file, not a directory",
                                )
                                .await
                        {
                            return Err(mismatch);
                        }
                        continue;
                    }
                    let Ok(address) = address::join_relative(&prefix_address, relative_key)
                    else {
                        tracing::warn!(
                            target: "ovstorage.opendal.backend",
                            plugin = "opendal",
                            key = %relative_key,
                            "opendal: key is not addressable as a URI path; omitted from listing",
                        );
                        continue;
                    };
                    let _ =
                        address::relative_suffix(&address, &prefix_address).ok_or_else(|| {
                            Error::new(
                                ErrorCode::Internal,
                                format!(
                                    "OpenDAL list entry '{raw_entry_path}' could not be projected under '{}'",
                                    prefix_address
                                ),
                            )
                        })?;
                    let mut info = object_info_from_metadata(address, entry.metadata());
                    match entry.metadata().mode() {
                        EntryMode::DIR if self.capabilities.has_real_directories => {
                            info.kind = ObjectKind::Directory;
                        }
                        EntryMode::DIR => {
                            info.kind = ObjectKind::DirectoryInferred;
                            info.size = None;
                        }
                        EntryMode::FILE | EntryMode::Unknown => {
                            if relative_key.ends_with('/') && info.size.unwrap_or(0) == 0 {
                                info.kind = ObjectKind::DirectoryMarker;
                                info.size = None;
                            }
                        }
                    };
                    out.push(info);
                    if let Some(max) = max_results
                        && out.len() >= max as usize
                    {
                        break;
                    }
                }
                Ok(out)
            }
            .instrument(span),
        )
        .await
    }

    pub async fn create_directory(
        &self,
        target: ResolvedTarget,
        _opts: CreateDirectoryOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendItemInfo> {
        reject_pinned_for_mutation(
            &target.resolved_address,
            "opendal create_directory",
            PINNED_VERSION_KEYS,
        )?;
        let mut key = self.relative_key(&target.resolved_address)?;
        if !key.ends_with('/') {
            key.push('/');
        }
        race_cancel(cancel.as_ref(), async {
            self.operator
                .create_dir(&key)
                .await
                .map_err(map_opendal_error)?;
            let metadata = self.operator.stat(&key).await.map_err(map_opendal_error)?;
            Ok(item_info_from_metadata(&metadata))
        })
        .await
    }

    pub async fn delete_directory(
        &self,
        target: ResolvedTarget,
        _opts: DeleteDirectoryOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        reject_pinned_for_mutation(
            &target.resolved_address,
            "opendal delete_directory",
            PINNED_VERSION_KEYS,
        )?;
        let mut key = self.relative_key(&target.resolved_address)?;
        if !key.ends_with('/') {
            key.push('/');
        }
        race_cancel(cancel.as_ref(), async {
            // SPI contract: flat profiles drop the marker only and leave descendants intact.
            if !self.capabilities.has_real_directories {
                return self.operator.delete(&key).await.map_err(map_opendal_error);
            }
            let entries = match self
                .operator
                .list_with(&key)
                .recursive(false)
                .metakey(Metakey::Mode)
                .await
            {
                Ok(entries) => entries,
                Err(err) => {
                    if let Some(mismatch) = self
                        .leaf_type_mismatch(
                            &key,
                            true,
                            "delete_directory target is a file; use delete()",
                        )
                        .await
                    {
                        return Err(mismatch);
                    }
                    return Err(map_opendal_error(err));
                }
            };
            for entry in &entries {
                let entry_path = entry.path();
                let stripped = entry_path.strip_prefix(key.as_str()).unwrap_or(entry_path);
                if !stripped.is_empty() {
                    return Err(Error::new(
                        ErrorCode::DirectoryNotEmpty,
                        "directory is not empty",
                    ));
                }
            }
            self.operator.delete(&key).await.map_err(map_opendal_error)
        })
        .await
    }

    pub async fn copy(
        &self,
        src: ResolvedTarget,
        dest: ResolvedTarget,
        opts: CopyOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteStep> {
        reject_pinned_for_mutation(
            &src.resolved_address,
            "opendal copy(src)",
            PINNED_VERSION_KEYS,
        )?;
        reject_pinned_for_mutation(
            &dest.resolved_address,
            "opendal copy(dst)",
            PINNED_VERSION_KEYS,
        )?;
        let span = debug_span!(
            "opendal.copy",
            op = "copy",
            plugin = "opendal",
            object.address = %RedactedUrl(&dest.resolved_address),
        );
        if opts.if_source.is_some() {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "OpenDAL copy cannot enforce if_source atomically",
            ));
        }
        if !matches!(opts.if_dest, IfDestExists::Overwrite) {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "OpenDAL copy cannot enforce destination preconditions atomically",
            ));
        }
        if !self.capabilities.supports_server_side_copy {
            return Err(Error::new(
                ErrorCode::Unsupported,
                format!(
                    "OpenDAL service '{}' does not support server-side copy",
                    self.service
                ),
            ));
        }
        let src_key = self.relative_key(&src.resolved_address)?;
        let dest_key = self.relative_key(&dest.resolved_address)?;
        race_cancel(
            cancel.as_ref(),
            async {
                self.operator
                    .copy(&src_key, &dest_key)
                    .await
                    .map_err(map_opendal_error)?;
                let metadata = self
                    .operator
                    .stat(&dest_key)
                    .await
                    .map_err(map_opendal_error)?;
                let info = object_info_from_metadata(dest.resolved_address, &metadata);
                Ok(WriteStep::Done(WriteResult { info }))
            }
            .instrument(span),
        )
        .await
    }

    pub async fn rename(
        &self,
        src: ResolvedTarget,
        dest: ResolvedTarget,
        opts: RenameOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        reject_pinned_for_mutation(
            &src.resolved_address,
            "opendal rename(src)",
            PINNED_VERSION_KEYS,
        )?;
        reject_pinned_for_mutation(
            &dest.resolved_address,
            "opendal rename(dst)",
            PINNED_VERSION_KEYS,
        )?;
        let span = debug_span!(
            "opendal.rename",
            op = "rename",
            plugin = "opendal",
            object.address = %RedactedUrl(&dest.resolved_address),
        );
        if opts.if_source.is_some() {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "OpenDAL rename cannot enforce if_source atomically",
            ));
        }
        if !matches!(opts.if_dest, IfDestExists::Overwrite) {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "OpenDAL rename cannot enforce destination preconditions atomically",
            ));
        }
        if !self.capabilities.supports_server_side_rename {
            return Err(Error::new(
                ErrorCode::Unsupported,
                format!(
                    "OpenDAL service '{}' does not support server-side rename",
                    self.service
                ),
            ));
        }
        let src_key = self.relative_key(&src.resolved_address)?;
        let dest_key = self.relative_key(&dest.resolved_address)?;
        race_cancel(
            cancel.as_ref(),
            async {
                self.operator
                    .rename(&src_key, &dest_key)
                    .await
                    .map_err(map_opendal_error)
            }
            .instrument(span),
        )
        .await
    }

    pub async fn check_access(
        &self,
        _target: ResolvedTarget,
        _ops: AccessOps,
        cancel: Option<CancellationToken>,
    ) -> Result<ovstorage_plugin::AccessDecision> {
        let _ = &cancel; // returns Unsupported synchronously; nothing to interrupt.
        Err(Error::new(
            ErrorCode::Unsupported,
            "OpenDAL adapter does not implement access checks",
        ))
    }
}

impl OpenDalBackend {
    fn relative_key(&self, addr: &Url) -> Result<String> {
        // OpenDAL wants decoded path bytes; compare decoded keys so the route-prefix match is encoding-agnostic.
        if !address::is_ancestor_or_self(&self.prefix, addr) {
            return Err(Error::new(
                ErrorCode::NoRoute,
                "address is not under the selected route prefix",
            ));
        }
        // `key_utf8`: every OpenDAL `Operator` method takes `path: &str`, so
        // there is nowhere for a non-UTF-8 key to go. Refusing it keeps the
        // matcher and the backend on the same bytes.
        let addr_key = address::key_utf8(addr)?;
        let prefix_key = address::key_utf8(&self.prefix)?;
        // Both keys are decoded PATHS, so the query is already out of the
        // picture and the only difference left is the prefix's trailing slash.
        // Dropping it makes the two comparable, and the node itself then has an
        // empty key rather than falling through.
        let prefix_key = prefix_key.strip_suffix('/').unwrap_or(&prefix_key);
        let suffix = if addr_key == prefix_key {
            String::new()
        } else {
            // **Never guess.** A whole-key fallback returned `root` for prefix
            // `…/root/` and address `…/root`, which passes validation and
            // addresses `root/root` — on `delete`, a different object. If
            // containment said yes and the strip says no, the two disagree and
            // that is a defect, not an input to accommodate.
            let rest = addr_key
                .strip_prefix(prefix_key)
                .and_then(|rest| {
                    if prefix_key.is_empty() {
                        Some(rest)
                    } else {
                        rest.strip_prefix('/')
                    }
                })
                .ok_or_else(|| {
                    Error::new(
                        ErrorCode::Internal,
                        "address is under the route prefix but its key is not",
                    )
                })?;
            rest.to_string()
        };
        validate_relative_key(&suffix)?;
        Ok(suffix)
    }

    fn preflight_write(&self, opts: &WriteOptions) -> Result<()> {
        match &opts.if_dest {
            IfDestExists::Overwrite => Ok(()),
            IfDestExists::Fail => {
                if !self.capabilities.supports_no_overwrite_write {
                    return Err(Error::new(
                        ErrorCode::Unsupported,
                        format!(
                            "OpenDAL service '{}' does not support if_dest=Fail writes",
                            self.service
                        ),
                    ));
                }
                Ok(())
            }
            IfDestExists::MatchEtag(_) => Err(Error::new(
                ErrorCode::Unsupported,
                "OpenDAL adapter does not promise pass-through if_dest=MatchEtag writes",
            )),
        }
    }

    /// The user metadata to attach to this write, or `Unsupported` when the
    /// caller asked for metadata the resolved driver cannot keep.
    ///
    /// `write_with_user_metadata` is a per-connection fact — in the pinned
    /// OpenDAL 0.50 `s3` sets it and neither `fs` nor `webdav` does — so the
    /// decision belongs at write time,
    /// which is where both body-typed slots call this. The decision itself is
    /// [`resolve_user_metadata`], which takes the capability as an argument so
    /// both of its arms are reachable without a live driver.
    fn write_user_metadata(&self, op: &str, opts: &WriteOptions) -> Result<Vec<(String, String)>> {
        resolve_user_metadata(
            self.operator
                .info()
                .full_capability()
                .write_with_user_metadata,
            opts,
            self.service,
            op,
        )
    }
}

/// Whether the caller asked for user metadata on this write.
///
/// The predicate every refusal shares: `opts.message` does not count, because
/// only the caller's own map carries the reject-rather-than-drop obligation.
fn has_user_metadata(opts: &WriteOptions) -> bool {
    opts.user_metadata.as_ref().is_some_and(|m| !m.is_empty())
}

/// The metadata a write should carry given whether its driver can store any.
///
/// A driver that cannot persist metadata refuses a non-empty
/// `opts.user_metadata` rather than writing the bytes without it: a caller's
/// `--metadata foo=bar` must not vanish behind a successful write (plugin
/// CONFORMANCE, `write, write_stream, write_redirect, continue_write` →
/// *Edge cases*).
///
/// `opts.message` is weaker by contract — a per-operation annotation a backend
/// may drop when it has nowhere to put one — so it alone never fails a write.
/// It is stashed under [`OV_MESSAGE_KEY`] where the driver can keep it, and
/// discarded here otherwise.
fn resolve_user_metadata(
    supports_user_metadata: bool,
    opts: &WriteOptions,
    service: &str,
    op: &str,
) -> Result<Vec<(String, String)>> {
    if supports_user_metadata {
        return Ok(collect_user_metadata(opts));
    }
    if has_user_metadata(opts) {
        return Err(Error::new(
            ErrorCode::Unsupported,
            format!(
                "OpenDAL {op}: service '{service}' cannot store user_metadata; \
                 drop opts.user_metadata or target a driver that supports it"
            ),
        ));
    }
    Ok(Vec::new())
}

/// The percent-DECODED key is what flows to `operator.stat/read/write/...`,
/// and OpenDAL's services do no containment of their own (fs `root.join`s;
/// s3/webdav splice the key into the request URL). The route-prefix check ran
/// on the ENCODED URL, so an encoded-slash spelling like `a%2F..%2F..%2Fetc`
/// passes it as one opaque segment and only becomes a real `../..` here —
/// reject escapes on the decoded bytes, the last point that sees them.
fn validate_relative_key(key: &str) -> Result<()> {
    // `\` is a separator for the fs profile on Windows and is never required
    // by a well-formed opendal key's dot-segment spelling, so treat both
    // separators uniformly — for the dot-segment check AND the absolute-path
    // check (`\windows\...` is drive-relative absolute on Windows, where
    // `root.join` discards the root's non-prefix component).
    //
    // A drive prefix (`C:\...` / `C:foo`, absolute or drive-relative) escapes
    // the same way without containing any separator at all, so a leading
    // `<ascii-alpha>:` is rejected too. That also refuses a hypothetical
    // remote object key spelled `x:...`; keys with a colon that early are not
    // worth an fs containment hole.
    let drive_prefixed = {
        let mut chars = key.chars();
        matches!(
            (chars.next(), chars.next()),
            (Some(letter), Some(':')) if letter.is_ascii_alphabetic()
        )
    };
    let escapes = key.starts_with('/')
        || key.starts_with('\\')
        || drive_prefixed
        || key.contains('\0')
        || key
            .split('/')
            .flat_map(|segment| segment.split('\\'))
            .any(|segment| segment == ".." || segment == ".");
    if escapes {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "object key must not contain '.'/'..' segments or an absolute path",
        ));
    }
    Ok(())
}

/// Construct the connection's `Operator` WITHOUT a reachability probe:
/// `Operator::via_iter` validates config shape only, so construction is
/// deterministic for a given connection request. The reachability/credential
/// `Operator::check()` lives in
/// `OpenDalDriver`'s `verify` slot, where a failure PARKS the
/// connection instead of hard-failing the add and aborting the rebuild.
fn build_operator(
    spec: &DriverSpec,
    config: &HashMap<String, ConfigValue>,
    creds: &HashMap<String, SecretValue>,
) -> Result<Operator> {
    if let Some(feature) = spec.required_feature
        && !Scheme::enabled().contains(&spec.scheme)
    {
        return Err(Error::new(
            ErrorCode::Unsupported,
            format!(
                "OpenDAL service '{}' is allow-listed but the workspace opendal pin does not enable the '{}' feature",
                spec.service, feature
            ),
        ));
    }
    let map = build_operator_map(spec, config, creds)?;
    Operator::via_iter(spec.scheme, map).map_err(map_opendal_error)
}

/// The credential fields each profile consumes — the same keys
/// [`build_operator_map`] reads from the secret bundle. Anything else in a
/// bundle is a caller mistake the driver's `obtain` refuses.
fn allowed_credential_fields(spec: &DriverSpec) -> &'static [&'static str] {
    match spec.profile {
        DriverCapabilityProfile::Fs => &[],
        DriverCapabilityProfile::S3 => &["access_key_id", "secret_access_key"],
        DriverCapabilityProfile::Webdav => &["password"],
    }
}

/// The non-secret OpenDAL options `config_json` may carry, per profile.
/// OpenDAL builders accept auth-bearing options through the generic config
/// map — webdav `token` (a bearer credential that overrides the supplied
/// basic-auth password), s3 `session_token`/role-assumption fields, SSE-C
/// keys — so a denylist of this adapter's own credential keys is not enough:
/// the map is ALLOWLISTED, and anything not named here is rejected, keeping
/// every authentication source inside the `SecretBundle` pipeline
/// (redaction/zeroization included). fs excludes `atomic_write_dir` on
/// purpose: the `writes_are_atomic` capability hint and the probe's
/// no-side-effect contract both assume it is unset.
fn allowed_config_json_keys(spec: &DriverSpec) -> &'static [&'static str] {
    match spec.profile {
        DriverCapabilityProfile::Fs => &["root"],
        DriverCapabilityProfile::S3 => &[
            "root",
            "bucket",
            "region",
            "endpoint",
            "enable_virtual_host_style",
        ],
        DriverCapabilityProfile::Webdav => &["root", "endpoint", "username"],
    }
}

fn build_operator_map(
    spec: &DriverSpec,
    cfg: &HashMap<String, ConfigValue>,
    creds: &HashMap<String, SecretValue>,
) -> Result<Vec<(String, String)>> {
    let mut map = parse_extra_config_json(cfg)?;
    let allowed = allowed_config_json_keys(spec);
    if let Some((key, _)) = map.iter().find(|(key, _)| !allowed.contains(&key.as_str())) {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            if allowed_credential_fields(spec).contains(&key.as_str()) {
                // The secret pipeline is authoritative for credentials: a
                // plaintext `config_json` entry must not shadow (or
                // substitute for) a `SecretValue`-sourced field.
                format!(
                    "config_json must not carry credential key '{key}'; \
                     supply it via the connection credentials"
                )
            } else {
                format!(
                    "config_json key '{key}' is not an allow-listed OpenDAL option for \
                     service '{}' (allowed: {}); credentials and tokens must be supplied \
                     via the connection credentials",
                    spec.service,
                    allowed.join(", ")
                )
            },
        ));
    }
    let mut push = |key: &str, value: String| {
        if !map.iter().any(|(existing, _)| existing == key) {
            map.push((key.to_string(), value));
        }
    };
    match spec.profile {
        DriverCapabilityProfile::Fs => {
            let root = required_string(cfg, "root")?;
            push("root", root);
        }
        DriverCapabilityProfile::S3 => {
            if let Some(value) = optional_string(cfg, "bucket")? {
                push("bucket", value);
            }
            if let Some(value) = optional_string(cfg, "region")? {
                push("region", value);
            }
            if let Some(value) = optional_string(cfg, "endpoint")? {
                push("endpoint", value);
            }
            if let Some(value) = optional_string(cfg, "root")? {
                push("root", value);
            }
            if let Some(value) = secret_string(creds, "access_key_id")? {
                push("access_key_id", value);
            }
            if let Some(value) = secret_string(creds, "secret_access_key")? {
                push("secret_access_key", value);
            }
            // This adapter is static-credential only: without these, reqsign's
            // default chain falls through to the environment / shared profile /
            // web-identity / IMDS loaders, and a connection could authenticate
            // ambiently at daemon privilege while its lifecycle reports
            // `Anonymous`. Unsigned access is granted only for the documented
            // empty-bundle case — explicitly, never as a fallback.
            push("disable_config_load", "true".into());
            push("disable_ec2_metadata", "true".into());
            if !creds.contains_key("access_key_id") {
                push("allow_anonymous", "true".into());
            }
        }
        DriverCapabilityProfile::Webdav => {
            if let Some(value) = optional_string(cfg, "endpoint")? {
                push("endpoint", value);
            }
            if let Some(value) = optional_string(cfg, "username")? {
                push("username", value);
            }
            if let Some(value) = optional_string(cfg, "root")? {
                push("root", value);
            }
            if let Some(value) = secret_string(creds, "password")? {
                push("password", value);
            }
        }
    }
    Ok(map)
}

fn parse_extra_config_json(config: &HashMap<String, ConfigValue>) -> Result<Vec<(String, String)>> {
    let Some(raw) = optional_string(config, "config_json")? else {
        return Ok(Vec::new());
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed == "{}" {
        return Ok(Vec::new());
    }
    // Hand-rolled to avoid pulling serde_json just for a flat string map.
    parse_flat_string_map(trimmed)
        .map_err(|message| Error::new(ErrorCode::InvalidArgument, message))
}

fn parse_flat_string_map(raw: &str) -> std::result::Result<Vec<(String, String)>, String> {
    // Walk by char (not byte) so multi-byte UTF-8 keys/values are not corrupted.
    let chars: Vec<char> = raw.chars().collect();
    let mut idx = 0usize;
    let len = chars.len();
    fn skip_ws(idx: &mut usize, chars: &[char]) {
        while *idx < chars.len() && chars[*idx].is_whitespace() {
            *idx += 1;
        }
    }
    fn parse_unicode_escape(idx: &mut usize, chars: &[char]) -> std::result::Result<char, String> {
        if *idx + 4 > chars.len() {
            return Err("truncated \\u escape in config_json".into());
        }
        let mut code = 0u32;
        for _ in 0..4 {
            let digit = chars[*idx]
                .to_digit(16)
                .ok_or_else(|| "invalid \\u hex digit in config_json".to_string())?;
            code = (code << 4) | digit;
            *idx += 1;
        }
        char::from_u32(code).ok_or_else(|| "invalid \\u codepoint in config_json".into())
    }
    fn parse_string(idx: &mut usize, chars: &[char]) -> std::result::Result<String, String> {
        if *idx >= chars.len() || chars[*idx] != '"' {
            return Err("expected string in config_json".into());
        }
        *idx += 1;
        let mut out = String::new();
        while *idx < chars.len() {
            match chars[*idx] {
                '"' => {
                    *idx += 1;
                    return Ok(out);
                }
                '\\' if *idx + 1 < chars.len() => {
                    let escaped = chars[*idx + 1];
                    *idx += 2;
                    match escaped {
                        '"' => out.push('"'),
                        '\\' => out.push('\\'),
                        '/' => out.push('/'),
                        'n' => out.push('\n'),
                        't' => out.push('\t'),
                        'r' => out.push('\r'),
                        'b' => out.push('\u{0008}'),
                        'f' => out.push('\u{000C}'),
                        'u' => out.push(parse_unicode_escape(idx, chars)?),
                        _ => return Err("unsupported escape in config_json string".into()),
                    }
                }
                ch => {
                    out.push(ch);
                    *idx += 1;
                }
            }
        }
        Err("unterminated string in config_json".into())
    }
    skip_ws(&mut idx, &chars);
    if idx >= len || chars[idx] != '{' {
        return Err("config_json must be a JSON object of strings".into());
    }
    idx += 1;
    let mut out = Vec::new();
    loop {
        skip_ws(&mut idx, &chars);
        if idx < len && chars[idx] == '}' {
            idx += 1;
            skip_ws(&mut idx, &chars);
            if idx != len {
                return Err("unexpected trailing content in config_json".into());
            }
            return Ok(out);
        }
        let key = parse_string(&mut idx, &chars)?;
        skip_ws(&mut idx, &chars);
        if idx >= len || chars[idx] != ':' {
            return Err("expected ':' in config_json".into());
        }
        idx += 1;
        skip_ws(&mut idx, &chars);
        let value = parse_string(&mut idx, &chars)?;
        out.push((key, value));
        skip_ws(&mut idx, &chars);
        if idx < len && chars[idx] == ',' {
            idx += 1;
            continue;
        }
    }
}

fn parse_connection_config(request: &ConnectionRequest) -> Result<OpenDalConnectionConfig> {
    let service = required_string(&request.config, "service")?;
    let service = service.trim().to_ascii_lowercase();
    if service.is_empty() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "OpenDAL service must not be empty",
        ));
    }
    let driver = find_driver(&service).ok_or_else(|| {
        Error::new(
            ErrorCode::Unsupported,
            format!("OpenDAL service '{service}' is not allow-listed"),
        )
    })?;
    Ok(OpenDalConnectionConfig {
        driver,
        prefix: connection_prefix(&request.config, driver.service)?,
    })
}

fn find_driver(service: &str) -> Option<&'static DriverSpec> {
    DRIVER_SPECS.iter().find(|driver| driver.service == service)
}

fn connection_prefix(config: &HashMap<String, ConfigValue>, service: &str) -> Result<Url> {
    match optional_string(config, "prefix")? {
        Some(value) => {
            // The published prefix is a configuration address, so it is refused
            // for carrying a query or a fragment on the one rule every config
            // loader in the workspace shares. The check is on the raw string
            // because `address::parse` strips a fragment — after it there is
            // nothing left to see, and a dropped component has to fail loudly.
            //
            // The value is not echoed: a query is where a signature or an API
            // key lives, and this message reaches a startup log.
            if let Some(component) = address::refused_config_component(&value) {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    format!(
                        "config field 'prefix' must not carry a {}; the prefix is the \
                         address space this connection publishes, and routing reads its \
                         scheme, authority and path alone",
                        component.name()
                    ),
                ));
            }
            let prefix = address::parse(&value)?;
            // A prefix that SELECTS addresses may not carry credentials, the
            // rule `address::config_prefix_carries_credentials` documents and
            // five other loaders already applied. `relative_key` decides
            // membership with `address::is_ancestor_or_self`, which compares
            // scheme, host, port and node path and never the userinfo — so
            // `prefix = "opendal://tenant:secret@fs/private/"` accepts the
            // anonymous `opendal://fs/private/x`, derives the key `x`, and
            // serves it under this connection's configured driver credentials.
            // On 0.2.0 the serialized comparison answered `NoRoute` for that
            // address, so this is a live widening in the permissive direction.
            //
            // Not echoed, for the same reason as the component refusal above.
            if address::config_prefix_carries_credentials(&prefix) {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    "config field 'prefix' must not carry credentials; the prefix is the \
                     address space this connection publishes and routing reads its scheme, \
                     authority and path alone, so it would publish that space for every \
                     credential rather than the one written. Write it without them",
                ));
            }
            address::to_directory(&prefix)
        }
        None => address::parse(&format!("opendal://{service}/")),
    }
}

fn required_string(config: &HashMap<String, ConfigValue>, key: &str) -> Result<String> {
    match config.get(key) {
        Some(ConfigValue::String(value)) => Ok(value.clone()),
        Some(_) => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("config field '{key}' must be a string"),
        )),
        None => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("missing required config field '{key}'"),
        )),
    }
}

fn optional_string(config: &HashMap<String, ConfigValue>, key: &str) -> Result<Option<String>> {
    match config.get(key) {
        Some(ConfigValue::String(value)) => {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                Ok(None)
            } else {
                Ok(Some(value.clone()))
            }
        }
        Some(_) => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("config field '{key}' must be a string"),
        )),
        None => Ok(None),
    }
}

fn secret_string(credentials: &HashMap<String, SecretValue>, key: &str) -> Result<Option<String>> {
    let Some(value) = credentials.get(key) else {
        return Ok(None);
    };
    match value {
        SecretValue::Bytes(bytes) => std::str::from_utf8(&bytes.0)
            .map(|value| Some(value.to_string()))
            .map_err(|_| {
                Error::new(
                    ErrorCode::InvalidArgument,
                    format!("credential field '{key}' is not valid UTF-8"),
                )
            }),
        SecretValue::OAuthToken { token, .. } => std::str::from_utf8(&token.0)
            .map(|value| Some(value.to_string()))
            .map_err(|_| {
                Error::new(
                    ErrorCode::InvalidArgument,
                    format!("credential field '{key}' OAuth token is not valid UTF-8"),
                )
            }),
        SecretValue::File(bytes) => std::str::from_utf8(&bytes.0)
            .map(|value| Some(value.to_string()))
            .map_err(|_| {
                Error::new(
                    ErrorCode::InvalidArgument,
                    format!("credential field '{key}' file contents are not valid UTF-8"),
                )
            }),
        SecretValue::MtlsCertPair { .. } | SecretValue::SystemIdentity => Err(Error::new(
            ErrorCode::Unsupported,
            format!("credential field '{key}' kind is not supported by the OpenDAL adapter"),
        )),
    }
}

/// Map `if_none_match("*")` failures to `Conflict` so the no-overwrite race outcome is uniform across drivers.
// Merge caller-supplied user_metadata with `opts.message` stashed under
// `x-ov-message`; later entries win on key collision so a caller-supplied
// `x-ov-message` overrides an opts.message of the same write call.
fn collect_user_metadata(opts: &WriteOptions) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    if let Some(message) = opts.message.as_deref().filter(|m| !m.is_empty()) {
        out.push((OV_MESSAGE_KEY.to_string(), message.to_string()));
    }
    if let Some(meta) = opts.user_metadata.as_ref() {
        for (k, v) in meta {
            out.push((k.clone(), v.clone()));
        }
    }
    out
}

fn map_no_overwrite_error(error: opendal::Error) -> Error {
    if matches!(
        error.kind(),
        OpenDalErrorKind::ConditionNotMatch | OpenDalErrorKind::AlreadyExists
    ) {
        return Error::new(
            ErrorCode::Conflict,
            "no-overwrite write target already exists",
        );
    }
    map_opendal_error(error)
}

/// Recover typed kinds from streamed-read `io::Error`s instead of collapsing every chunk failure to `Transient`.
fn map_io_error(error: std::io::Error) -> Error {
    use std::io::ErrorKind as IoKind;
    let code = match error.kind() {
        IoKind::NotFound => ErrorCode::NotFound,
        IoKind::PermissionDenied => ErrorCode::PermissionDenied,
        IoKind::AlreadyExists => ErrorCode::AlreadyExists,
        IoKind::InvalidInput | IoKind::InvalidData => ErrorCode::InvalidArgument,
        IoKind::Unsupported => ErrorCode::Unsupported,
        IoKind::Interrupted => ErrorCode::Cancelled,
        _ => ErrorCode::Transient,
    };
    Error::new(code, error.to_string())
}

/// Reject inverted ranges (`end_inclusive < start`) before they reach
/// the byte-stream slicing path, where a slice on an inverted index
/// would panic. Surface `InvalidArgument` so the caller sees a clean
/// error rather than a `catch_unwind`-converted `Internal`.
fn opendal_range(range: &ByteRange) -> Result<std::ops::Range<u64>> {
    if let Some(end) = range.end_inclusive
        && end < range.start
    {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "inverted byte range: start={} end_inclusive={}",
                range.start, end,
            ),
        ));
    }
    let start = range.start;
    let end_exclusive = match range.end_inclusive {
        Some(end) => end.saturating_add(1),
        None => u64::MAX,
    };
    Ok(start..end_exclusive)
}

/// 401 -> `AuthRequired` so the host invalidates the presign and retries once;
/// 403 -> `PermissionDenied` (final). Other codes split so the retry policy
/// does not blanket-retry auth and precondition failures.
fn map_redirect_status(status: u16, index: usize) -> Error {
    if status == 401 {
        return Error::new(
            ErrorCode::AuthRequired,
            format!("OpenDAL presigned write #{index} returned HTTP 401"),
        )
        .with_context(ErrorContext::Auth {
            connection_id: ConnectionId(String::new()),
            reason: Some("opendal_redirect_unauthorized".into()),
            expired_at: None,
        });
    }
    let code = match status {
        403 => ErrorCode::PermissionDenied,
        404 | 410 => ErrorCode::NotFound,
        408 => ErrorCode::Transient,
        412 => ErrorCode::PreconditionFailed,
        416 => ErrorCode::InvalidArgument,
        429 => ErrorCode::ResourceExhausted,
        500..=599 => ErrorCode::Transient,
        _ => ErrorCode::Internal,
    };
    Error::new(
        code,
        format!("OpenDAL presigned write #{index} returned HTTP {status}"),
    )
}

fn map_opendal_error(error: opendal::Error) -> Error {
    let code = match error.kind() {
        OpenDalErrorKind::NotFound => ErrorCode::NotFound,
        OpenDalErrorKind::PermissionDenied => ErrorCode::PermissionDenied,
        OpenDalErrorKind::IsADirectory | OpenDalErrorKind::NotADirectory => {
            ErrorCode::IncompatibleType
        }
        OpenDalErrorKind::AlreadyExists => ErrorCode::AlreadyExists,
        OpenDalErrorKind::IsSameFile => ErrorCode::Conflict,
        OpenDalErrorKind::ConditionNotMatch => ErrorCode::PreconditionFailed,
        OpenDalErrorKind::RangeNotSatisfied => ErrorCode::InvalidArgument,
        OpenDalErrorKind::Unsupported => ErrorCode::Unsupported,
        OpenDalErrorKind::ConfigInvalid => ErrorCode::InvalidArgument,
        OpenDalErrorKind::RateLimited => ErrorCode::ResourceExhausted,
        _ => ErrorCode::Transient,
    };
    Error::new(code, error.to_string())
}

struct OpenDalFields {
    etag: Option<String>,
    version: Option<String>,
    size: Option<u64>,
    mtime: Option<SystemTime>,
}

fn fields_from_metadata(metadata: &Metadata) -> OpenDalFields {
    OpenDalFields {
        etag: metadata.etag().map(|value| value.to_string()),
        version: metadata.version().map(|value| value.to_string()),
        // Directory sizes are `None` by contract. OpenDAL marks directory
        // metadata `Metakey::Complete` (with `content_length` at its zero
        // default), so a directory would otherwise report `Some(0)`.
        size: (!metadata.is_dir() && metakey_present(metadata, Metakey::ContentLength))
            .then(|| metadata.content_length()),
        mtime: metadata.last_modified().map(|dt| {
            let secs = dt.timestamp();
            let nanos = dt.timestamp_subsec_nanos();
            if secs >= 0 {
                UNIX_EPOCH + Duration::from_secs(secs as u64) + Duration::from_nanos(nanos as u64)
            } else {
                UNIX_EPOCH - Duration::from_secs(secs.unsigned_abs())
                    + Duration::from_nanos(nanos as u64)
            }
        }),
    }
}

fn object_info_from_metadata(address: Url, metadata: &Metadata) -> ObjectInfo {
    let fields = fields_from_metadata(metadata);
    let kind = if metadata.is_dir() {
        ObjectKind::Directory
    } else {
        ObjectKind::File
    };
    ObjectInfo {
        address,
        kind,
        etag: fields.etag,
        version: fields.version,
        size: fields.size,
        mtime: fields.mtime,
        checksums: ChecksumSet::default(),
        effective_permissions: None,
        system_metadata: None,
        user_metadata: metadata.user_metadata().cloned(),
        modified_by: None,
    }
}

fn item_info_from_metadata(metadata: &Metadata) -> BackendItemInfo {
    let fields = fields_from_metadata(metadata);
    let kind = if metadata.is_dir() {
        ObjectKind::Directory
    } else {
        ObjectKind::File
    };
    BackendItemInfo {
        kind,
        etag: fields.etag,
        version: fields.version,
        size: fields.size,
        mtime: fields.mtime,
        checksums: ChecksumSet::default(),
        effective_permissions: None,
        system_metadata: None,
        user_metadata: metadata.user_metadata().cloned(),
        modified_by: None,
    }
}

/// Gate `Metadata::content_length` etc., which panic when the metakey was not retrieved.
fn metakey_present(metadata: &Metadata, key: Metakey) -> bool {
    // `Complete` is OpenDAL's marker flag for "this entry already contains
    // all metadata" (the webdav PROPFIND parser sets ONLY it), not a bitmask
    // superset of the per-field keys — honor it explicitly.
    let keys = metadata.metakey();
    keys.contains(Metakey::Complete) || keys.contains(key)
}

pub use crate::layer::OpenDalLayerFactory;

ovstorage_plugin::ovstorage_layer_plugin!(backend, OpenDalLayerFactory::default);

#[cfg(test)]
mod tests {
    use super::*;
    use ovstorage_plugin::{
        AddressRoot, AddressVisibility, BackendId, ConfigLayer, RouteSource, UserMetadata,
    };
    use std::sync::Arc;

    /// Test helper that builds the same configured instance shape as the
    /// production `layer::OpenDalLayer` path.
    struct TestInstance {
        backend: Arc<OpenDalBackend>,
        address_roots: Vec<AddressRoot>,
        backend_id: BackendId,
    }

    async fn instantiate(request: &ConnectionRequest) -> Result<TestInstance> {
        let config = parse_connection_config(request)?;
        let capabilities = driver_capabilities(config.driver);
        let operator = build_operator(config.driver, &request.config, &request.credentials.fields)?;
        let backend = Arc::new(OpenDalBackend {
            service: config.driver.service,
            operator,
            prefix: config.prefix.clone(),
            capabilities: capabilities.clone(),
        });
        Ok(TestInstance {
            backend,
            backend_id: BackendId(format!(
                "opendal:{}:{}",
                config.driver.service, config.prefix
            )),
            address_roots: vec![AddressRoot {
                address: config.prefix,
                display_name: None,
                backend_kind: "opendal".into(),
                connection_id: None,
                capabilities,
                source: RouteSource::Static {
                    layer: ConfigLayer::Programmatic,
                },
                visibility: AddressVisibility::Visible,
                user_metadata: UserMetadata::new(),
            }],
        })
    }
    use ovstorage_plugin::SecretBundle;
    use tempfile::TempDir;

    #[test]
    fn descriptor_reports_opendal_kind_and_schema() {
        let descriptor = kind_descriptor();
        assert_eq!(descriptor.kind, "opendal");
        assert!(descriptor.supports_runtime_add);

        let keys: Vec<_> = descriptor
            .config_schema
            .iter()
            .map(|field| field.key.as_str())
            .collect();
        assert_eq!(keys, vec!["service", "endpoint", "config_json", "prefix"]);

        let service_field = descriptor
            .config_schema
            .iter()
            .find(|field| field.key == "service")
            .expect("service field");
        let ConfigFieldKind::Enum {
            source: EnumSource::Static(services),
        } = &service_field.kind
        else {
            panic!("service field should be a static enum");
        };
        for expected in ["fs", "webdav", "s3"] {
            assert!(services.iter().any(|service| service == expected));
        }
        for absent in ["sftp", "hdfs"] {
            assert!(
                !services.iter().any(|service| service == absent),
                "{absent} should not be advertised when the workspace does not enable services-{absent}",
            );
        }

        let credential_keys: Vec<_> = descriptor
            .credential_schema
            .iter()
            .map(|field| field.key.as_str())
            .collect();
        for expected in [
            "access_key_id",
            "secret_access_key",
            "password",
            "private_key",
        ] {
            assert!(credential_keys.contains(&expected));
        }
    }

    #[test]
    fn descriptor_service_enum_omits_disabled_services() {
        let descriptor = kind_descriptor();
        let service_field = descriptor
            .config_schema
            .iter()
            .find(|f| f.key == "service")
            .expect("service config field present");

        let variants: Vec<String> = match &service_field.kind {
            ConfigFieldKind::Enum {
                source: EnumSource::Static(values),
            } => values.clone(),
            other => panic!("expected service to be a static Enum, got {other:?}"),
        };

        assert!(
            !variants.contains(&"sftp".to_string()),
            "sftp variant must be removed (workspace does not enable services-sftp)",
        );
        assert!(
            !variants.contains(&"hdfs".to_string()),
            "hdfs variant must be removed (workspace does not enable services-hdfs)",
        );
        for expected in ["fs", "s3", "webdav"] {
            assert!(
                variants.iter().any(|v| v == expected),
                "expected service enum to advertise '{expected}', got {variants:?}",
            );
        }
    }

    #[test]
    fn allow_list_capabilities_match_per_driver_shape() {
        for driver in DRIVER_SPECS {
            let caps = driver_capabilities(driver);
            match driver.profile {
                DriverCapabilityProfile::Fs => {
                    assert!(caps.has_real_directories);
                    assert!(caps.supports_recursive_list);
                    assert!(caps.supports_list);
                    // OpenDAL's Fs writer is in-place without
                    // `atomic_write_dir` (unset here) — not atomic.
                    assert!(!caps.writes_are_atomic);
                    assert!(!caps.supports_no_overwrite_write);
                    assert!(caps.supports_server_side_copy);
                    assert!(caps.supports_server_side_rename);
                    assert!(caps.supports_atomic_rename);
                    assert!(!caps.supports_version_listing);
                }
                DriverCapabilityProfile::S3 => {
                    assert!(!caps.has_real_directories);
                    assert!(caps.supports_recursive_list);
                    assert!(caps.supports_list);
                    assert!(caps.supports_no_overwrite_write);
                    // Single-part PUT / CompleteMultipartUpload publish
                    // all-at-once.
                    assert!(caps.writes_are_atomic);
                    assert!(!caps.supports_if_match_write);
                    assert!(!caps.supports_native_metadata_patch);
                    assert!(!caps.supports_version_listing);
                    assert!(!caps.supports_server_side_copy);
                    assert!(!caps.supports_server_side_rename);
                }
                DriverCapabilityProfile::Webdav => {
                    assert!(caps.has_real_directories);
                    assert!(caps.supports_recursive_list);
                    assert!(caps.supports_list);
                    assert!(caps.supports_server_side_copy);
                    assert!(!caps.supports_server_side_rename);
                }
            }
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn configured_prefix_overrides_service_default_prefix() {
        let temp = TempDir::new().unwrap();
        let mut request = request_for_fs(&temp);
        request.config.insert(
            "prefix".into(),
            ConfigValue::String("opendal://team/fs".into()),
        );

        let instance = instantiate(&request).await.unwrap();
        assert_eq!(
            instance.address_roots[0].address.as_str(),
            "opendal://team/fs/"
        );
    }

    /// A `prefix` carrying a query or a fragment is an error at load.
    ///
    /// The two components fail differently and neither is what the operator
    /// wrote. `address::parse` strips a fragment, so
    /// `opendal://team/fs#note` publishes `opendal://team/fs/` with nothing
    /// said. A query is not stripped — it pins routing to that exact
    /// spelling — so the prefix publishes an address space almost nothing can
    /// enter. The rule has no per-key exception, so both are refused.
    ///
    /// The good input is the sibling test
    /// `configured_prefix_overrides_service_default_prefix`, which still
    /// publishes `opendal://team/fs/`; the last block here repeats it inline so
    /// a reader of this test can see that the refusal is about the component
    /// and not about the address.
    ///
    /// Load-bearing line: the `refused_config_component` block in
    /// `connection_prefix`.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_prefix_carrying_a_query_or_a_fragment_is_refused() {
        for (spelling, component) in [
            ("opendal://team/fs#SECRET", "fragment"),
            ("opendal://team/fs?v=SECRET", "query"),
        ] {
            let temp = TempDir::new().unwrap();
            let mut request = request_for_fs(&temp);
            request
                .config
                .insert("prefix".into(), ConfigValue::String(spelling.into()));
            let Err(error) = instantiate(&request).await else {
                panic!("{spelling} must be refused");
            };
            assert_eq!(error.code(), ErrorCode::InvalidArgument, "{spelling}");
            assert!(
                error.message().contains(component),
                "{spelling}: the refusal must name what it refused: {}",
                error.message()
            );
            assert!(
                !error.message().contains("SECRET"),
                "{spelling}: the refusal echoed the value: {}",
                error.message()
            );
        }

        // The same prefix without either component still publishes.
        let temp = TempDir::new().unwrap();
        let mut request = request_for_fs(&temp);
        request.config.insert(
            "prefix".into(),
            ConfigValue::String("opendal://team/fs".into()),
        );
        let instance = instantiate(&request).await.expect("the plain prefix loads");
        assert_eq!(
            instance.address_roots[0].address.as_str(),
            "opendal://team/fs/"
        );
    }

    /// A `prefix` carrying credentials is an error at load.
    ///
    /// The prefix is the address space this connection publishes, and
    /// `relative_key` decides membership with `address::is_ancestor_or_self`,
    /// which compares scheme, host, port and node path and never the userinfo.
    /// So `opendal://tenant:secret@fs/private/` publishes `/private/` for
    /// **every** credential including none: an anonymous
    /// `opendal://fs/private/x` matches, derives the key `x`, and is served
    /// under this connection's configured driver credentials. On 0.2.0 the
    /// serialized comparison answered `NoRoute` for that spelling, so this
    /// closes a widening rather than adding a restriction.
    ///
    /// The password carries a comma so the no-echo assertion is about this
    /// refusal not interpolating the value, rather than about `Error`'s own
    /// redactor, whose URL scan ends at punctuation.
    ///
    /// The good input is asserted to ROUTE, not merely to load: the same
    /// prefix without the credential publishes its root, and an anonymous
    /// address under it resolves to the key the operator meant.
    ///
    /// Load-bearing line: the `config_prefix_carries_credentials` block in
    /// `connection_prefix`.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_prefix_carrying_credentials_is_refused() {
        let temp = TempDir::new().unwrap();
        let mut request = request_for_fs(&temp);
        request.config.insert(
            "prefix".into(),
            ConfigValue::String("opendal://tenant:hunt,er2@team/fs".into()),
        );
        let Err(error) = instantiate(&request).await else {
            panic!("a credential-bearing prefix must be refused");
        };
        assert_eq!(error.code(), ErrorCode::InvalidArgument);
        assert!(
            error.message().contains("must not carry credentials"),
            "the refusal must say what it refused: {}",
            error.message()
        );
        assert!(
            !error.message().contains("hunt,er2"),
            "the password must not survive into the startup error: {}",
            error.message()
        );

        // The good input, and it must still select its own subtree — the
        // refusal is about the credential, not about the prefix.
        let temp = TempDir::new().unwrap();
        let mut request = request_for_fs(&temp);
        request.config.insert(
            "prefix".into(),
            ConfigValue::String("opendal://team/fs".into()),
        );
        let instance = instantiate(&request)
            .await
            .expect("the credential-free prefix loads");
        let root = &instance.address_roots[0].address;
        assert_eq!(root.as_str(), "opendal://team/fs/");
        assert!(
            address::is_ancestor_or_self(root, &Url::parse("opendal://team/fs/private/x").unwrap()),
            "and must still publish its own subtree"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn unsupported_service_is_rejected() {
        let mut request = empty_request();
        request
            .config
            .insert("service".into(), ConfigValue::String("ftp".into()));
        let err = instantiate(&request)
            .await
            .err()
            .expect("unsupported service should fail instantiation");
        assert_eq!(err.code(), ErrorCode::Unsupported);
    }

    #[test]
    fn descriptor_is_native_provider_shaped() {
        let descriptor = kind_descriptor();
        assert!(
            !descriptor
                .config_schema
                .iter()
                .any(|field| field.key == "root")
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn sftp_service_is_not_advertised() {
        let mut request = empty_request();
        request
            .config
            .insert("service".into(), ConfigValue::String("sftp".into()));
        let err = instantiate(&request)
            .await
            .err()
            .expect("sftp should fail to instantiate; the workspace does not enable services-sftp");
        assert_eq!(err.code(), ErrorCode::Unsupported);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn hdfs_service_is_not_advertised() {
        let mut request = empty_request();
        request
            .config
            .insert("service".into(), ConfigValue::String("hdfs".into()));
        let err = instantiate(&request)
            .await
            .err()
            .expect("hdfs should fail to instantiate; the workspace does not enable services-hdfs");
        assert_eq!(err.code(), ErrorCode::Unsupported);
    }

    /// The route prefix's own node has an empty relative key, not the whole key.
    ///
    /// The two spellings of the prefix name one node, so an address equal to
    /// the prefix addresses the root of this connection. Stripping decoded keys
    /// with a whole-key fallback returned `root` for prefix `…/root/` and
    /// address `…/root`, which passes `validate_relative_key` and addresses
    /// `root/root` — a different object, and on `delete` the wrong one.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_prefix_node_itself_has_an_empty_relative_key() {
        let temp = TempDir::new().unwrap();
        let mut request = request_for_fs(&temp);
        request.config.insert(
            "prefix".into(),
            ConfigValue::String("opendal://fs/root/".into()),
        );
        let instance = instantiate(&request).await.unwrap();
        let backend: Arc<OpenDalBackend> = instance.backend.clone();
        let prefix = instance.address_roots[0].address.clone();
        assert_eq!(prefix.as_str(), "opendal://fs/root/");
        let slashless = address::parse("opendal://fs/root").unwrap();

        for spelling in [&prefix, &slashless] {
            assert_eq!(
                backend.relative_key(spelling).unwrap(),
                "",
                "{spelling} names the prefix node and has no key below it"
            );
        }

        // The control: a genuine child still yields its own key.
        let child = address::join_relative(&prefix, "nested/hello.txt").unwrap();
        assert_eq!(backend.relative_key(&child).unwrap(), "nested/hello.txt");
    }

    /// The prefix node carrying a modifier is still the prefix node.
    ///
    /// Containment ignores a prefix with no query while node identity includes
    /// one, so an address naming the route node **plus a pin** passed the gate
    /// and missed a guard written in terms of node identity. It then fell into
    /// a whole-key fallback and produced `root`, addressing `root/root` — and
    /// this key feeds `delete`.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_prefix_node_with_a_modifier_still_has_an_empty_relative_key() {
        let temp = TempDir::new().unwrap();
        let mut request = request_for_fs(&temp);
        request.config.insert(
            "prefix".into(),
            ConfigValue::String("opendal://fs/root/".into()),
        );
        let instance = instantiate(&request).await.unwrap();
        let backend: Arc<OpenDalBackend> = instance.backend;

        for spelling in [
            "opendal://fs/root?versionId=1",
            "opendal://fs/root/?versionId=1",
            "opendal://fs/root?a=1&b=2",
        ] {
            assert_eq!(
                backend
                    .relative_key(&address::parse(spelling).unwrap())
                    .unwrap(),
                "",
                "{spelling} names the prefix node and has no key below it"
            );
        }

        // A pinned child still yields its own key, and a sibling whose name
        // merely starts with the prefix's is still outside the route.
        assert_eq!(
            backend
                .relative_key(&address::parse("opendal://fs/root/a?versionId=1").unwrap())
                .unwrap(),
            "a"
        );
        assert_eq!(
            backend
                .relative_key(&address::parse("opendal://fs/rootx").unwrap())
                .unwrap_err()
                .code(),
            ErrorCode::NoRoute
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn fs_round_trip_through_operator() {
        let temp = TempDir::new().unwrap();
        let request = request_for_fs(&temp);
        let instance = instantiate(&request).await.unwrap();
        let backend: Arc<OpenDalBackend> = instance.backend.clone();
        let prefix = instance.address_roots[0].address.clone();
        let backend_id = instance.backend_id.clone();

        let object = address::join_relative(&prefix, "nested/hello.txt").unwrap();
        let dir = address::join_relative(&prefix, "nested/").unwrap();

        backend
            .create_directory(
                target_for(&backend_id, dir.clone()),
                CreateDirectoryOptions::default(),
                None,
            )
            .await
            .unwrap();

        let write_result = backend
            .write(
                target_for(&backend_id, object.clone()),
                b"hello opendal".to_vec(),
                WriteOptions::default(),
                None,
            )
            .await
            .unwrap();
        assert_eq!(write_result.info.address, object);
        assert_eq!(write_result.info.size, Some(13));

        let unsupported = backend
            .write(
                target_for(&backend_id, object.clone()),
                b"second".to_vec(),
                WriteOptions {
                    if_dest: IfDestExists::Fail,
                    ..WriteOptions::default()
                },
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(unsupported.code(), ErrorCode::Unsupported);

        let stat_info = backend
            .stat(
                target_for(&backend_id, object.clone()),
                StatOptions::default(),
                None,
            )
            .await
            .unwrap();
        assert_eq!(stat_info.size, Some(13));

        let read = backend
            .read(
                target_for(&backend_id, object.clone()),
                ReadOptions::default(),
                None,
            )
            .await
            .unwrap();
        match read {
            ReadResult::Stream { stream, info } => {
                use futures::StreamExt;
                let mut stream = stream;
                let mut bytes = Vec::new();
                while let Some(chunk) = stream.next().await {
                    bytes.extend_from_slice(&chunk.unwrap());
                }
                assert_eq!(bytes, b"hello opendal");
                assert_eq!(info.size, Some(13));
            }
            other => panic!("expected ReadResult::Stream, got {other:?}"),
        }

        let range = backend
            .read(
                target_for(&backend_id, object.clone()),
                ReadOptions {
                    range: Some(ByteRange {
                        start: 6,
                        end_inclusive: Some(12),
                    }),
                    ..ReadOptions::default()
                },
                None,
            )
            .await
            .unwrap();
        match range {
            ReadResult::Stream { stream, .. } => {
                use futures::StreamExt;
                let mut stream = stream;
                let mut bytes = Vec::new();
                while let Some(chunk) = stream.next().await {
                    bytes.extend_from_slice(&chunk.unwrap());
                }
                assert_eq!(bytes, b"opendal");
            }
            other => panic!("expected ReadResult::Stream for range, got {other:?}"),
        }

        let listed = backend
            .list(
                target_for(&backend_id, dir.clone()),
                ListOptions::default(),
                None,
            )
            .await
            .unwrap();
        assert!(
            listed
                .iter()
                .any(|item| item.kind == ObjectKind::File && item.address == object)
        );

        let recursive = backend
            .list(
                target_for(&backend_id, prefix.clone()),
                ListOptions {
                    recursive: true,
                    ..ListOptions::default()
                },
                None,
            )
            .await
            .unwrap();
        assert!(
            recursive
                .iter()
                .any(|item| item.kind == ObjectKind::File && item.address == object)
        );

        backend
            .delete(
                target_for(&backend_id, object.clone()),
                DeleteOptions::default(),
                None,
            )
            .await
            .unwrap();
        assert_eq!(
            backend
                .stat(
                    target_for(&backend_id, object.clone()),
                    StatOptions::default(),
                    None,
                )
                .await
                .unwrap_err()
                .code(),
            ErrorCode::NotFound
        );

        backend
            .delete_directory(target_for(&backend_id, dir), DeleteDirectoryOptions, None)
            .await
            .unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn fs_copy_and_rename_succeed() {
        let temp = TempDir::new().unwrap();
        let request = request_for_fs(&temp);
        let instance = instantiate(&request).await.unwrap();
        let backend = instance.backend.clone();
        let prefix = instance.address_roots[0].address.clone();
        let backend_id = instance.backend_id.clone();

        let src = address::join_relative(&prefix, "src.txt").unwrap();
        let copy = address::join_relative(&prefix, "copy.txt").unwrap();
        let renamed = address::join_relative(&prefix, "renamed.txt").unwrap();

        backend
            .write(
                target_for(&backend_id, src.clone()),
                b"payload".to_vec(),
                WriteOptions::default(),
                None,
            )
            .await
            .unwrap();

        backend
            .copy(
                target_for(&backend_id, src.clone()),
                target_for(&backend_id, copy.clone()),
                CopyOptions::default(),
                None,
            )
            .await
            .unwrap();
        match backend
            .read(
                target_for(&backend_id, copy.clone()),
                ReadOptions::default(),
                None,
            )
            .await
            .unwrap()
        {
            ReadResult::Stream { stream, .. } => {
                use futures::StreamExt;
                let mut stream = stream;
                let mut bytes = Vec::new();
                while let Some(chunk) = stream.next().await {
                    bytes.extend_from_slice(&chunk.unwrap());
                }
                assert_eq!(bytes, b"payload");
            }
            other => panic!("expected ReadResult::Stream, got {other:?}"),
        }

        backend
            .rename(
                target_for(&backend_id, copy.clone()),
                target_for(&backend_id, renamed.clone()),
                RenameOptions::default(),
                None,
            )
            .await
            .unwrap();
        assert_eq!(
            backend
                .stat(target_for(&backend_id, copy), StatOptions::default(), None,)
                .await
                .unwrap_err()
                .code(),
            ErrorCode::NotFound
        );
        match backend
            .read(
                target_for(&backend_id, renamed),
                ReadOptions::default(),
                None,
            )
            .await
            .unwrap()
        {
            ReadResult::Stream { stream, .. } => {
                use futures::StreamExt;
                let mut stream = stream;
                let mut bytes = Vec::new();
                while let Some(chunk) = stream.next().await {
                    bytes.extend_from_slice(&chunk.unwrap());
                }
                assert_eq!(bytes, b"payload");
            }
            other => panic!("expected ReadResult::Stream, got {other:?}"),
        }
    }

    #[test]
    fn s3_rejects_server_side_copy_per_allow_list() {
        let caps = driver_capabilities(&DRIVER_SPECS[1]);
        assert!(!caps.supports_server_side_copy);
        assert!(!caps.supports_server_side_rename);
    }

    fn empty_request() -> ConnectionRequest {
        ConnectionRequest {
            backend_kind: "opendal".into(),
            config: HashMap::new(),
            credentials: SecretBundle::default(),
            persist: false,
            display_name: None,
        }
    }

    fn request_for_fs(temp: &TempDir) -> ConnectionRequest {
        let mut request = empty_request();
        request
            .config
            .insert("service".into(), ConfigValue::String("fs".into()));
        request.config.insert(
            "root".into(),
            ConfigValue::String(temp.path().to_string_lossy().into_owned()),
        );
        request
    }

    fn target_for(backend_id: &BackendId, address: Url) -> ResolvedTarget {
        ResolvedTarget {
            backend_id: backend_id.clone(),
            resolved_address: address,
        }
    }

    #[test]
    fn scope_prefix_strips_query_and_fragment() {
        let presigned = "https://my-bucket.s3.us-west-2.amazonaws.com/path/to/object.bin?\
             X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature=abc123&X-Amz-Date=20260502T000000Z";
        let prefix = scope_prefix_from_url(presigned);
        assert_eq!(
            prefix,
            "https://my-bucket.s3.us-west-2.amazonaws.com/path/to/object.bin"
        );
        assert!(!prefix.contains('?'), "prefix must not include query");
    }

    #[test]
    fn scope_prefix_preserves_port_and_strips_fragment() {
        let url = "http://localhost:9000/bucket/key.bin?sig=zz#section";
        let prefix = scope_prefix_from_url(url);
        assert_eq!(prefix, "http://localhost:9000/bucket/key.bin");
        assert!(!prefix.contains('#'));
    }

    #[test]
    fn scope_prefix_falls_back_to_truncate_for_unparsable_input() {
        let raw = "::garbage::?foo=bar";
        let prefix = scope_prefix_from_url(raw);
        assert!(!prefix.contains('?'), "fallback must still strip query");
    }

    #[test]
    fn map_redirect_status_distinguishes_auth_precondition_and_range() {
        assert_eq!(map_redirect_status(401, 0).code(), ErrorCode::AuthRequired);
        assert_eq!(
            map_redirect_status(403, 0).code(),
            ErrorCode::PermissionDenied
        );
        assert_eq!(map_redirect_status(404, 0).code(), ErrorCode::NotFound);
        assert_eq!(map_redirect_status(410, 0).code(), ErrorCode::NotFound);
        assert_eq!(map_redirect_status(408, 0).code(), ErrorCode::Transient);
        assert_eq!(
            map_redirect_status(412, 0).code(),
            ErrorCode::PreconditionFailed
        );
        assert_eq!(
            map_redirect_status(416, 0).code(),
            ErrorCode::InvalidArgument
        );
        assert_eq!(
            map_redirect_status(429, 0).code(),
            ErrorCode::ResourceExhausted
        );
        assert_eq!(map_redirect_status(500, 0).code(), ErrorCode::Transient);
        assert_eq!(map_redirect_status(503, 0).code(), ErrorCode::Transient);
        assert_eq!(map_redirect_status(599, 0).code(), ErrorCode::Transient);
        // Unmapped goes to Internal so it surfaces, not Transient (which would retry).
        assert_eq!(map_redirect_status(418, 0).code(), ErrorCode::Internal);
    }

    /// 401 carries `ErrorContext::Auth` so the host distinguishes credential-stale failures from generic permission errors.
    #[test]
    fn map_redirect_status_401_populates_auth_context() {
        let err = map_redirect_status(401, 3);
        assert_eq!(err.code(), ErrorCode::AuthRequired);
        match err.context() {
            Some(ErrorContext::Auth {
                reason, expired_at, ..
            }) => {
                assert_eq!(reason.as_deref(), Some("opendal_redirect_unauthorized"));
                assert!(expired_at.is_none());
            }
            other => panic!("expected Auth context, got {other:?}"),
        }
    }

    /// 403 stays `PermissionDenied` with no Auth context; retrying would not help.
    #[test]
    fn map_redirect_status_403_omits_auth_context() {
        let err = map_redirect_status(403, 0);
        assert_eq!(err.code(), ErrorCode::PermissionDenied);
        assert!(err.context().is_none());
    }

    #[test]
    fn map_redirect_status_includes_index_in_message() {
        let err = map_redirect_status(412, 7);
        assert!(err.message().contains("#7"));
        assert!(err.message().contains("412"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn write_redirect_rejects_missing_size_hint() {
        let temp = TempDir::new().unwrap();
        let request = request_for_fs(&temp);
        let instance = instantiate(&request).await.unwrap();
        let backend = instance.backend.clone();
        let prefix = instance.address_roots[0].address.clone();
        let object = address::join_relative(&prefix, "blob.bin").unwrap();
        let target = target_for(&instance.backend_id, object);
        let err = backend
            .write_redirect(target, WriteOptions::default(), None)
            .await
            .expect_err("write_redirect must fail on the fs driver");
        // Capability gate runs before the size-hint check, so fs returns Unsupported, not InvalidArgument.
        assert_eq!(err.code(), ErrorCode::Unsupported);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn fs_percent_encoded_keys_round_trip() {
        let temp = TempDir::new().unwrap();
        let request = request_for_fs(&temp);
        let instance = instantiate(&request).await.unwrap();
        let backend = instance.backend.clone();
        let prefix = instance.address_roots[0].address.clone();
        let backend_id = instance.backend_id.clone();

        let object = address::join_relative(&prefix, "dir/a b%c.txt").unwrap();
        backend
            .write(
                target_for(&backend_id, object.clone()),
                b"hi".to_vec(),
                WriteOptions::default(),
                None,
            )
            .await
            .unwrap();
        let info = backend
            .stat(
                target_for(&backend_id, object.clone()),
                StatOptions::default(),
                None,
            )
            .await
            .unwrap();
        assert_eq!(info.size, Some(2));

        let dir_prefix = address::join_relative(&prefix, "dir/").unwrap();
        let listed = backend
            .list(
                target_for(&backend_id, dir_prefix.clone()),
                ListOptions::default(),
                None,
            )
            .await
            .unwrap();
        assert!(
            listed
                .iter()
                .any(|item| item.kind == ObjectKind::File && item.address == object),
            "got {listed:?}"
        );
    }

    /// No spelling of a parent-escaping path may reach a file outside the
    /// configured root. Two mechanisms cover this between them, and the test
    /// asserts the property rather than either mechanism:
    ///
    /// - `address::parse` canonicalizes, which decodes `%2F` to a real
    ///   separator and then resolves the dot segments it exposes — clamped at
    ///   the root, so the escape is neutralized into an ordinary in-root
    ///   address rather than refused. The encoded spelling therefore behaves
    ///   exactly like the plain one, which is the point.
    /// - Everything canonicalization leaves intact — `\` stays escaped, and a
    ///   decoded leading `/` makes the key absolute — is refused by
    ///   `relative_key`, which must reject before the operator sees it (fs
    ///   `root.join`s with no containment of its own).
    #[tokio::test(flavor = "multi_thread")]
    async fn fs_traversal_spellings_cannot_reach_outside_the_root() {
        let outside = TempDir::new().unwrap();
        let root = TempDir::new_in(outside.path()).unwrap();
        let request = request_for_fs(&root);
        let instance = instantiate(&request).await.unwrap();
        let backend = instance.backend.clone();
        let prefix = instance.address_roots[0].address.clone();
        let backend_id = instance.backend_id.clone();

        let secret_path = outside.path().join("secret.txt");
        std::fs::write(&secret_path, b"do-not-read").unwrap();

        // Canonicalization resolves this one into an in-root address, so it is
        // no longer refused — it names `<root>/secret.txt`, an ordinary object
        // that happens not to exist. The escape is gone rather than caught,
        // which is why the "nothing outside was touched" assertion below is the
        // one that carries the security claim.
        for (spelling, expected) in [
            // The traversal clamps at the root.
            ("a%2F..%2F..%2Fsecret.txt", "secret.txt"),
            // The decoded leading separator made this look like an absolute
            // path; collapsing the empty segment leaves an ordinary key.
            ("%2Fetc%2Fhostname", "etc/hostname"),
        ] {
            let resolved = address::parse(&format!("{prefix}{spelling}")).unwrap();
            assert_eq!(
                resolved.as_str(),
                format!("{prefix}{expected}"),
                "{spelling} must resolve to an in-root address"
            );
            let err = backend
                .stat(
                    target_for(&backend_id, resolved),
                    StatOptions::default(),
                    None,
                )
                .await
                .unwrap_err();
            assert_eq!(
                err.code(),
                ErrorCode::NotFound,
                "{spelling}: in-root, absent"
            );
        }

        for spelling in [
            // Windows-separator spelling (fs joins with the OS semantics).
            // `canonicalize` escapes `\` rather than decoding it, precisely so
            // the crate cannot rewrite it to `/` and name a different file.
            "a%5C..%5C..%5Csecret.txt",
            // Encoded leading backslash: no dot-segments at all, but
            // drive-relative absolute on Windows.
            "%5Cwindows%5Csystem32",
            // Drive prefix: absolute on Windows with no separator needed.
            "c:%5Cwindows%5Csystem32",
        ] {
            let object = address::parse(&format!("{prefix}{spelling}")).unwrap();
            let err = backend
                .stat(
                    target_for(&backend_id, object.clone()),
                    StatOptions::default(),
                    None,
                )
                .await
                .unwrap_err();
            assert_eq!(err.code(), ErrorCode::InvalidArgument, "stat {spelling}");
            let err = backend
                .write(
                    target_for(&backend_id, object),
                    b"clobber".to_vec(),
                    WriteOptions::default(),
                    None,
                )
                .await
                .unwrap_err();
            assert_eq!(err.code(), ErrorCode::InvalidArgument, "write {spelling}");
        }
        assert_eq!(
            std::fs::read(&secret_path).unwrap(),
            b"do-not-read",
            "nothing outside the root was touched"
        );
    }

    /// Plain dot-segments in a decoded key are rejected for every profile
    /// (s3/webdav splice the key into a request URL where the server would
    /// resolve `..` out of the configured root).
    #[test]
    fn validate_relative_key_rejects_escapes_and_accepts_normal_keys() {
        for bad in [
            "../up.txt",
            "a/../../b.txt",
            "a/./b.txt",
            ".",
            "..",
            "/absolute.txt",
            "\\windows\\system32",
            "c:\\windows\\system32",
            "C:config",
            "a\\..\\b.txt",
            "nul\0byte",
        ] {
            assert!(
                validate_relative_key(bad).is_err(),
                "{bad:?} must be rejected"
            );
        }
        for good in [
            "a.txt",
            "dir/a b%c.txt",
            "deep/nested/key",
            "..double-dot-name",
            "a..b",
        ] {
            assert!(validate_relative_key(good).is_ok(), "{good:?} must pass");
        }
    }

    /// The secret pipeline is authoritative: a plaintext `config_json` entry
    /// must not shadow a `SecretValue`-sourced credential field.
    #[test]
    fn config_json_credential_keys_are_rejected() {
        let spec = find_driver("s3").unwrap();
        let mut cfg = HashMap::new();
        cfg.insert("bucket".into(), ConfigValue::String("bkt".into()));
        cfg.insert(
            "config_json".into(),
            ConfigValue::String("{\"access_key_id\":\"AKIAPLAINTEXT\"}".into()),
        );
        let err = build_operator_map(spec, &cfg, &HashMap::new()).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert!(err.message().contains("access_key_id"));

        // Allow-listed non-credential config_json keys still merge.
        cfg.insert(
            "config_json".into(),
            ConfigValue::String("{\"enable_virtual_host_style\":\"true\"}".into()),
        );
        let map = build_operator_map(spec, &cfg, &HashMap::new()).unwrap();
        assert!(
            map.iter()
                .any(|(key, value)| key == "enable_virtual_host_style" && value == "true")
        );
    }

    /// OpenDAL consumes auth-bearing options through the generic config map
    /// (webdav `token`, s3 `session_token`/role fields, SSE-C keys), so
    /// `config_json` is allow-listed per profile: anything not named —
    /// credential-bearing or merely unknown — is rejected, keeping every
    /// authentication source inside the `SecretBundle` pipeline.
    #[test]
    fn config_json_is_allowlisted_per_profile() {
        for (service, key) in [
            ("s3", "session_token"),
            ("s3", "role_arn"),
            ("s3", "server_side_encryption_customer_key"),
            ("webdav", "token"),
            ("fs", "atomic_write_dir"),
            ("s3", "not_a_real_option"),
        ] {
            let spec = find_driver(service).unwrap();
            let mut cfg = HashMap::new();
            cfg.insert(
                "config_json".into(),
                ConfigValue::String(format!("{{\"{key}\":\"x\"}}")),
            );
            let err = build_operator_map(spec, &cfg, &HashMap::new()).unwrap_err();
            assert_eq!(err.code(), ErrorCode::InvalidArgument, "{service}:{key}");
            assert!(err.message().contains(key), "{service}:{key}");
        }
    }

    /// The s3 profile must never fall back to ambient credentials
    /// (environment / shared profile / web-identity / IMDS): the loaders are
    /// forced off, and unsigned access is enabled ONLY for the documented
    /// empty-bundle case.
    #[test]
    fn s3_ambient_credential_loaders_are_disabled() {
        let spec = find_driver("s3").unwrap();
        let mut cfg = HashMap::new();
        cfg.insert("bucket".into(), ConfigValue::String("bkt".into()));
        cfg.insert("region".into(), ConfigValue::String("us-east-1".into()));

        let has = |map: &[(String, String)], key: &str, value: &str| {
            map.iter().any(|(k, v)| k == key && v == value)
        };
        // Anonymous: loaders off, explicitly unsigned.
        let map = build_operator_map(spec, &cfg, &HashMap::new()).unwrap();
        assert!(has(&map, "disable_config_load", "true"));
        assert!(has(&map, "disable_ec2_metadata", "true"));
        assert!(has(&map, "allow_anonymous", "true"));

        // Credentialed: loaders still off, unsigned fallback NOT enabled.
        let mut creds = HashMap::new();
        creds.insert(
            "access_key_id".into(),
            SecretValue::Bytes(ovstorage_plugin::SecretBytes(b"AKIATEST".to_vec())),
        );
        creds.insert(
            "secret_access_key".into(),
            SecretValue::Bytes(ovstorage_plugin::SecretBytes(b"secret".to_vec())),
        );
        let map = build_operator_map(spec, &cfg, &creds).unwrap();
        assert!(has(&map, "disable_config_load", "true"));
        assert!(has(&map, "disable_ec2_metadata", "true"));
        assert!(!map.iter().any(|(k, _)| k == "allow_anonymous"));
        assert!(has(&map, "access_key_id", "AKIATEST"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn fs_recursive_list_includes_real_directories() {
        let temp = TempDir::new().unwrap();
        let request = request_for_fs(&temp);
        let instance = instantiate(&request).await.unwrap();
        let backend = instance.backend.clone();
        let prefix = instance.address_roots[0].address.clone();
        let backend_id = instance.backend_id.clone();
        let nested = address::join_relative(&prefix, "a/b/c.txt").unwrap();
        backend
            .write(
                target_for(&backend_id, nested),
                b"x".to_vec(),
                WriteOptions::default(),
                None,
            )
            .await
            .unwrap();

        let recursive = backend
            .list(
                target_for(&backend_id, prefix.clone()),
                ListOptions {
                    recursive: true,
                    ..ListOptions::default()
                },
                None,
            )
            .await
            .unwrap();
        assert!(
            recursive.iter().any(|item| {
                item.kind == ObjectKind::Directory && item.address.as_str().ends_with("/a/")
            }),
            "recursive list should include real directory entries: {recursive:?}"
        );
    }

    /// The accept arm as a decision: a driver that CAN store metadata must
    /// receive the caller's map and the `x-ov-message` stash. A resolver that
    /// refused nothing and returned nothing would satisfy every `fs` test in
    /// this module while dropping metadata on S3, which is the very defect
    /// being fixed. [`s3_backend_resolves_metadata_through_the_driver_capability`]
    /// pins the other half — that a real capable connection reaches this arm.
    #[test]
    fn resolve_user_metadata_attaches_everything_a_capable_driver_can_keep() {
        let mut meta = ovstorage_plugin::UserMetadata::new();
        meta.insert("project".into(), "ovstorage".into());
        let opts = WriteOptions {
            user_metadata: Some(meta),
            message: Some("commit note".into()),
            ..WriteOptions::default()
        };
        let resolved =
            resolve_user_metadata(true, &opts, "s3", "write").expect("a capable driver accepts");
        assert_eq!(
            resolved,
            vec![
                (OV_MESSAGE_KEY.to_string(), "commit note".to_string()),
                ("project".to_string(), "ovstorage".to_string()),
            ]
        );
    }

    /// The refuse arm and its boundary, as a decision rather than a round
    /// trip: a caller's map is refused, a message alone is not, and an empty
    /// map is not a request for metadata.
    #[test]
    fn resolve_user_metadata_refuses_only_a_callers_map() {
        let mut meta = ovstorage_plugin::UserMetadata::new();
        meta.insert("project".into(), "ovstorage".into());
        assert_eq!(meta.len(), 1, "fixture must carry the metadata under test");
        let err = resolve_user_metadata(
            false,
            &WriteOptions {
                user_metadata: Some(meta),
                ..WriteOptions::default()
            },
            "fs",
            "write",
        )
        .expect_err("an incapable driver refuses a caller's map");
        assert_eq!(err.code(), ErrorCode::Unsupported);
        assert!(
            err.message().contains("OpenDAL write: ")
                && err.message().contains("cannot store user_metadata"),
            "{err:?}"
        );

        assert_eq!(
            resolve_user_metadata(
                false,
                &WriteOptions {
                    message: Some("commit note".into()),
                    ..WriteOptions::default()
                },
                "fs",
                "write",
            )
            .expect("a message alone is droppable"),
            Vec::new()
        );

        assert_eq!(
            resolve_user_metadata(
                false,
                &WriteOptions {
                    user_metadata: Some(ovstorage_plugin::UserMetadata::new()),
                    ..WriteOptions::default()
                },
                "fs",
                "write",
            )
            .expect("an empty map asks for nothing"),
            Vec::new()
        );
    }

    /// The wiring, on a driver that CAN store metadata. `build_operator` runs
    /// no reachability probe, so an `s3` connection is constructible in-process
    /// against no server, and reading the capability touches nothing remote —
    /// which is enough to pin what the decision tests cannot: that
    /// `write_user_metadata` passes the driver's real
    /// `write_with_user_metadata` rather than a constant. Hardcoding `false`
    /// there would break every metadata-carrying S3 write while leaving the
    /// whole `fs` suite green.
    #[tokio::test(flavor = "multi_thread")]
    async fn s3_backend_resolves_metadata_through_the_driver_capability() {
        let mut request = empty_request();
        request
            .config
            .insert("service".into(), ConfigValue::String("s3".into()));
        request
            .config
            .insert("bucket".into(), ConfigValue::String("bkt".into()));
        request
            .config
            .insert("region".into(), ConfigValue::String("us-east-1".into()));
        let instance = instantiate(&request).await.unwrap();
        assert!(
            instance
                .backend
                .operator
                .info()
                .full_capability()
                .write_with_user_metadata,
            "the s3 driver is the capable one these assertions rest on"
        );

        let mut meta = UserMetadata::new();
        meta.insert("project".into(), "ovstorage".into());
        assert_eq!(meta.len(), 1, "fixture must carry the metadata under test");
        let resolved = instance
            .backend
            .write_user_metadata(
                "write",
                &WriteOptions {
                    user_metadata: Some(meta),
                    ..WriteOptions::default()
                },
            )
            .expect("a capable driver must accept the caller's map");
        assert_eq!(
            resolved,
            vec![("project".to_string(), "ovstorage".to_string())]
        );
    }

    /// The premise the three tests below rest on: the `fs` driver cannot
    /// persist user metadata. If a future OpenDAL release gives it that
    /// capability those tests stop exercising the refusal, and this one says
    /// so instead of letting them pass vacuously.
    #[tokio::test(flavor = "multi_thread")]
    async fn fs_driver_cannot_store_user_metadata() {
        let temp = TempDir::new().unwrap();
        let request = request_for_fs(&temp);
        let instance = instantiate(&request).await.unwrap();
        assert!(
            !instance
                .backend
                .operator
                .info()
                .full_capability()
                .write_with_user_metadata,
            "fs is the no-metadata driver these tests rely on"
        );
    }

    /// A driver that cannot persist `user_metadata` must refuse a non-empty
    /// map rather than write the bytes and drop it: a caller's
    /// `--metadata foo=bar` vanishing behind a successful write is the failure
    /// the conformance rule exists to prevent.
    #[tokio::test(flavor = "multi_thread")]
    async fn fs_write_refuses_user_metadata_it_cannot_store() {
        let temp = TempDir::new().unwrap();
        let request = request_for_fs(&temp);
        let instance = instantiate(&request).await.unwrap();
        let backend = instance.backend.clone();
        let prefix = instance.address_roots[0].address.clone();
        let backend_id = instance.backend_id.clone();
        let object = address::join_relative(&prefix, "meta.txt").unwrap();
        let mut meta = ovstorage_plugin::UserMetadata::new();
        meta.insert("project".into(), "ovstorage".into());
        assert_eq!(meta.len(), 1, "fixture must carry the metadata under test");

        let err = backend
            .write(
                target_for(&backend_id, object.clone()),
                b"payload".to_vec(),
                WriteOptions {
                    user_metadata: Some(meta),
                    ..WriteOptions::default()
                },
                None,
            )
            .await
            .expect_err("fs cannot store user metadata, so the write must refuse");
        assert_eq!(err.code(), ErrorCode::Unsupported, "{err:?}");
        // Name the refusal: `write` has three other `Unsupported` returns
        // (the `if_none_match` gate and both `preflight_write` arms), and a
        // bare code assertion would stay green if one of those started firing
        // first.
        assert!(
            err.message().contains("OpenDAL write: ")
                && err.message().contains("cannot store user_metadata"),
            "{err:?}"
        );
        // The refusal precedes the commit: no object is left behind carrying
        // the payload without its metadata.
        let stat = backend
            .stat(
                target_for(&backend_id, object),
                StatOptions::default(),
                None,
            )
            .await;
        assert_eq!(
            stat.expect_err("refused write must not have committed bytes")
                .code(),
            ErrorCode::NotFound
        );
    }

    /// The streaming slot carries the same refusal as the buffered one — the
    /// two paths resolve the driver's capability through one helper, and a
    /// caller that streams loses metadata just as completely.
    #[tokio::test(flavor = "multi_thread")]
    async fn fs_write_stream_refuses_user_metadata_it_cannot_store() {
        let temp = TempDir::new().unwrap();
        let request = request_for_fs(&temp);
        let instance = instantiate(&request).await.unwrap();
        let backend = instance.backend.clone();
        let prefix = instance.address_roots[0].address.clone();
        let backend_id = instance.backend_id.clone();
        let object = address::join_relative(&prefix, "meta-stream.txt").unwrap();
        let mut meta = ovstorage_plugin::UserMetadata::new();
        meta.insert("project".into(), "ovstorage".into());
        assert_eq!(meta.len(), 1, "fixture must carry the metadata under test");

        let chunks: Vec<Result<Vec<u8>>> = vec![Ok(b"payload".to_vec())];
        let err = backend
            .write_stream(
                target_for(&backend_id, object.clone()),
                ovstorage_plugin::BodyStream::from_iter(chunks.into_iter()),
                WriteOptions {
                    user_metadata: Some(meta),
                    ..WriteOptions::default()
                },
                None,
            )
            .await
            .expect_err("fs cannot store user metadata, so the write must refuse");
        assert_eq!(err.code(), ErrorCode::Unsupported, "{err:?}");
        // Name the refusal: `write_stream` reaches three other `Unsupported`
        // returns first — both `preflight_write` arms and its own
        // `if_dest=Fail` refusal — and a bare code assertion would stay green
        // if one of those started firing on this input.
        assert!(
            err.message().contains("OpenDAL write_stream: ")
                && err.message().contains("cannot store user_metadata"),
            "{err:?}"
        );
        let stat = backend
            .stat(
                target_for(&backend_id, object),
                StatOptions::default(),
                None,
            )
            .await;
        assert_eq!(
            stat.expect_err("refused write must not have committed bytes")
                .code(),
            ErrorCode::NotFound
        );
    }

    /// `opts.message` is a per-operation annotation the plugin contract lets a
    /// backend drop, and this adapter carries it only as a convenience — it is
    /// stashed under the reserved `x-ov-message` key where the driver can keep
    /// it. So a write carrying a message and no caller metadata still succeeds
    /// on a driver that stores neither. This pins the rejected design: keying
    /// the refusal on the merged map `collect_user_metadata` produces would
    /// turn every `--message` write to `fs` or `webdav` into a hard failure.
    #[tokio::test(flavor = "multi_thread")]
    async fn fs_write_accepts_a_message_without_user_metadata() {
        let temp = TempDir::new().unwrap();
        let request = request_for_fs(&temp);
        let instance = instantiate(&request).await.unwrap();
        let backend = instance.backend.clone();
        let prefix = instance.address_roots[0].address.clone();
        let backend_id = instance.backend_id.clone();
        let object = address::join_relative(&prefix, "annotated.txt").unwrap();

        let annotated = WriteOptions {
            message: Some("commit note".into()),
            ..WriteOptions::default()
        };
        assert!(
            annotated.message.is_some() && annotated.user_metadata.is_none(),
            "the fixture must carry a message and no caller metadata"
        );
        let result = backend
            .write(
                target_for(&backend_id, object),
                b"payload".to_vec(),
                annotated.clone(),
                None,
            )
            .await;
        assert!(result.is_ok(), "{result:?}");

        // Both slots, so a refusal keyed on the merged map in the streaming
        // slot alone cannot ship green.
        let streamed = address::join_relative(&prefix, "annotated-stream.txt").unwrap();
        let chunks: Vec<Result<Vec<u8>>> = vec![Ok(b"payload".to_vec())];
        let result = backend
            .write_stream(
                target_for(&backend_id, streamed),
                ovstorage_plugin::BodyStream::from_iter(chunks.into_iter()),
                annotated,
                None,
            )
            .await;
        assert!(result.is_ok(), "{result:?}");
    }

    /// `?versionId=` and friends are dropped when the key is derived, so a
    /// continuation presented against a version-pinned address would stat the
    /// current object while authorization was decided on the frozen-version
    /// URL. The other mutating verbs refuse such an address; so must this one.
    #[tokio::test(flavor = "multi_thread")]
    async fn continue_write_refuses_a_version_pinned_address() {
        let temp = TempDir::new().unwrap();
        let request = request_for_fs(&temp);
        let instance = instantiate(&request).await.unwrap();
        let backend = instance.backend.clone();
        let prefix = instance.address_roots[0].address.clone();
        let backend_id = instance.backend_id.clone();

        let authorized = address::join_relative(&prefix, "authorized.txt").unwrap();
        backend
            .write(
                target_for(&backend_id, authorized.clone()),
                b"payload".to_vec(),
                WriteOptions::default(),
                None,
            )
            .await
            .unwrap();

        let pinned = address::parse(&format!("{}?versionId=frozen", authorized.as_str())).unwrap();
        let redirects = WriteRedirectBatch {
            continuation: b"authorized.txt".to_vec(),
            redirects: vec![WriteRedirect {
                request: HttpRequest {
                    method: "PUT".into(),
                    url: "http://127.0.0.1/presigned".into(),
                    headers: Vec::new(),
                },
                body_source: RedirectBodySource::UserBytes { offset: 0, len: 7 },
                result_capture: ResultCapture::default(),
                expires_at: SystemTime::now() + Duration::from_secs(60),
                scope: RedirectScope {
                    physical_url_prefix: "http://127.0.0.1/".into(),
                    operations: AccessOps {
                        write: true,
                        ..AccessOps::default()
                    },
                    expires_at: SystemTime::now() + Duration::from_secs(60),
                    credential: RedirectCredential::Unspecified,
                },
                audit_id: "fixture".into(),
                policy_epoch: 0,
            }],
        };
        let results = RedirectResultBatch {
            results: vec![ovstorage_plugin::RedirectResult {
                status_code: 200,
                captured_headers: Vec::new(),
                captured_body: Vec::new(),
            }],
        };

        let err = backend
            .continue_write(target_for(&backend_id, pinned), redirects, results, None)
            .await
            .expect_err("a version-pinned address must be refused");
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    /// Substitution, not modification: the OpenDAL continuation is the bare
    /// object key with no tag and no structure, so under the broker's
    /// client-driven route any UTF-8 the caller sends would be the key this
    /// plugin probes. `continue_write` must derive the key from the authorized
    /// request address instead.
    #[tokio::test(flavor = "multi_thread")]
    async fn continue_write_stats_the_authorized_key_not_the_continuations() {
        let temp = TempDir::new().unwrap();
        let request = request_for_fs(&temp);
        let instance = instantiate(&request).await.unwrap();
        let backend = instance.backend.clone();
        let prefix = instance.address_roots[0].address.clone();
        let backend_id = instance.backend_id.clone();

        // Only the authorized object exists; the continuation names one that
        // does not, so a plugin reading the blob cannot accidentally pass.
        let authorized = address::join_relative(&prefix, "authorized.txt").unwrap();
        backend
            .write(
                target_for(&backend_id, authorized.clone()),
                b"payload".to_vec(),
                WriteOptions::default(),
                None,
            )
            .await
            .unwrap();

        let redirects = WriteRedirectBatch {
            continuation: b"minted-elsewhere.txt".to_vec(),
            redirects: vec![WriteRedirect {
                request: HttpRequest {
                    method: "PUT".into(),
                    url: "http://127.0.0.1/presigned".into(),
                    headers: Vec::new(),
                },
                body_source: RedirectBodySource::UserBytes { offset: 0, len: 7 },
                result_capture: ResultCapture::default(),
                expires_at: SystemTime::now() + Duration::from_secs(60),
                scope: RedirectScope {
                    physical_url_prefix: "http://127.0.0.1/".into(),
                    operations: AccessOps {
                        write: true,
                        ..AccessOps::default()
                    },
                    expires_at: SystemTime::now() + Duration::from_secs(60),
                    credential: RedirectCredential::Unspecified,
                },
                audit_id: "fixture".into(),
                policy_epoch: 0,
            }],
        };
        let results = RedirectResultBatch {
            results: vec![ovstorage_plugin::RedirectResult {
                status_code: 200,
                captured_headers: Vec::new(),
                captured_body: Vec::new(),
            }],
        };

        let step = backend
            .continue_write(
                target_for(&backend_id, authorized.clone()),
                redirects,
                results,
                None,
            )
            .await
            .expect("continue_write must stat the authorized key, which exists");
        match step {
            WriteStep::Done(result) => {
                assert_eq!(result.info.address, authorized);
                assert_eq!(result.info.size, Some(7));
            }
            WriteStep::Redirects(_) => panic!("expected Done"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn fs_read_returns_cancelled_when_token_pre_fired() {
        let temp = TempDir::new().unwrap();
        let request = request_for_fs(&temp);
        let instance = instantiate(&request).await.unwrap();
        let backend = instance.backend.clone();
        let prefix = instance.address_roots[0].address.clone();
        let backend_id = instance.backend_id.clone();
        let object = address::join_relative(&prefix, "x.txt").unwrap();
        backend
            .write(
                target_for(&backend_id, object.clone()),
                b"x".to_vec(),
                WriteOptions::default(),
                None,
            )
            .await
            .unwrap();
        let token = CancellationToken::new();
        token.cancel();
        let err = backend
            .read(
                target_for(&backend_id, object),
                ReadOptions::default(),
                Some(token),
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Cancelled);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn write_redirect_no_overwrite_returns_unsupported() {
        let temp = TempDir::new().unwrap();
        let request = request_for_fs(&temp);
        let instance = instantiate(&request).await.unwrap();
        let backend = instance.backend.clone();
        let prefix = instance.address_roots[0].address.clone();
        let object = address::join_relative(&prefix, "blob.bin").unwrap();
        let err = backend
            .write_redirect(
                target_for(&instance.backend_id, object),
                WriteOptions {
                    if_dest: IfDestExists::Fail,
                    size_hint: Some(10),
                    ..WriteOptions::default()
                },
                None,
            )
            .await
            .unwrap_err();
        // Capability gate fires before the no-overwrite check, so fs returns Unsupported, not InvalidArgument.
        assert_eq!(err.code(), ErrorCode::Unsupported);
    }

    #[test]
    fn parse_flat_string_map_handles_unicode_and_escapes() {
        let raw = r#"{ "name": "café", "emoji": "🎉", "newline": "a\nb" }"#;
        let pairs = parse_flat_string_map(raw).unwrap();
        let map: HashMap<String, String> = pairs.into_iter().collect();
        assert_eq!(map.get("name").map(String::as_str), Some("café"));
        assert_eq!(map.get("emoji").map(String::as_str), Some("🎉"));
        assert_eq!(map.get("newline").map(String::as_str), Some("a\nb"));
    }

    #[test]
    fn parse_flat_string_map_rejects_truncated_unicode_escape() {
        let raw = r#"{"k":"\u00"}"#;
        assert!(parse_flat_string_map(raw).is_err());
    }

    #[test]
    fn fs_no_overwrite_capability_is_not_advertised() {
        // OpenDAL 0.50 fs has no atomic `write_with_if_none_match`; withhold the cap to avoid a TOCTOU race.
        let caps = driver_capabilities(&DRIVER_SPECS[0]);
        assert!(!caps.supports_no_overwrite_write);
    }

    // === Regression coverage: range validation, copy if_match,
    //     streaming source-error propagation, and post-stat if_match
    //     enforcement. ===

    /// An inverted `ByteRange` (`start > end_inclusive`) would fall
    /// through to `Bytes` slicing, which panics, so the plugin rejects
    /// the read with `InvalidArgument` — the caller gets a precise
    /// error rather than a `catch_unwind`-converted `Internal`.
    #[tokio::test(flavor = "multi_thread")]
    async fn read_range_inverted_returns_invalid_argument() {
        let temp = TempDir::new().unwrap();
        let request = request_for_fs(&temp);
        let instance = instantiate(&request).await.unwrap();
        let backend = instance.backend.clone();
        let prefix = instance.address_roots[0].address.clone();
        let backend_id = instance.backend_id.clone();
        let object = address::join_relative(&prefix, "inverted.bin").unwrap();
        backend
            .write(
                target_for(&backend_id, object.clone()),
                b"0123456789".to_vec(),
                WriteOptions::default(),
                None,
            )
            .await
            .unwrap();
        let err = backend
            .read(
                target_for(&backend_id, object),
                ReadOptions {
                    range: Some(ByteRange {
                        start: 100,
                        end_inclusive: Some(50),
                    }),
                    ..ReadOptions::default()
                },
                None,
            )
            .await
            .expect_err("inverted range must error");
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    /// OpenDAL `copy` cannot atomically enforce a source-side
    /// `if_match` precondition (no opendal `copy_with` conditional
    /// header exists in 0.50), so the plugin refuses any
    /// `CopyOptions.if_match` up front with `Unsupported`.
    #[tokio::test(flavor = "multi_thread")]
    async fn copy_with_if_match_returns_unsupported() {
        let temp = TempDir::new().unwrap();
        let request = request_for_fs(&temp);
        let instance = instantiate(&request).await.unwrap();
        let backend = instance.backend.clone();
        let prefix = instance.address_roots[0].address.clone();
        let backend_id = instance.backend_id.clone();

        let src = address::join_relative(&prefix, "src.txt").unwrap();
        let dst = address::join_relative(&prefix, "dst.txt").unwrap();
        backend
            .write(
                target_for(&backend_id, src.clone()),
                b"payload".to_vec(),
                WriteOptions::default(),
                None,
            )
            .await
            .unwrap();

        let err = backend
            .copy(
                target_for(&backend_id, src),
                target_for(&backend_id, dst),
                CopyOptions {
                    if_source: Some("abc".into()),
                    ..CopyOptions::default()
                },
                None,
            )
            .await
            .expect_err("copy with if_source must be refused");
        assert_eq!(err.code(), ErrorCode::Unsupported);
    }

    /// A `BodyStream` that yields a chunk then errors must surface
    /// the error from `write_stream` rather than silently truncating
    /// the upload to the bytes already seen. Mirrors the
    /// services-client regression where `filter_map(|i| i.ok())`
    /// dropped mid-upload errors.
    #[tokio::test(flavor = "multi_thread")]
    async fn write_stream_propagates_source_error() {
        let temp = TempDir::new().unwrap();
        let request = request_for_fs(&temp);
        let instance = instantiate(&request).await.unwrap();
        let backend = instance.backend.clone();
        let prefix = instance.address_roots[0].address.clone();
        let backend_id = instance.backend_id.clone();
        let object = address::join_relative(&prefix, "partial.bin").unwrap();

        let chunks: Vec<Result<Vec<u8>>> = vec![
            Ok(b"first chunk".to_vec()),
            Err(Error::new(ErrorCode::Transient, "synthetic source error")),
        ];
        let body = ovstorage_plugin::BodyStream::from_iter(chunks.into_iter());

        let err = backend
            .write_stream(
                target_for(&backend_id, object),
                body,
                WriteOptions::default(),
                None,
            )
            .await
            .expect_err("body-stream error must propagate, not be silently dropped");
        // Don't pin the exact code — the plugin may map it. Just
        // assert the upload didn't silently succeed.
        assert_ne!(err.code(), ErrorCode::Cancelled);
    }

    /// OpenDAL is the one cloud plugin that DOES honor compound
    /// `if_match` preconditions: `check_identity` runs after stat, so
    /// a matching expected identity passes through and a mismatched
    /// one surfaces `ObjectModified`. This regression test pins both
    /// branches. The fs driver does not emit an etag, so for the
    /// "match" side we use the size field (which fs does populate);
    /// for the "mismatch" side a fabricated etag suffices because
    /// `check_identity` flags any populated field that differs from
    /// the observed metadata.
    #[tokio::test(flavor = "multi_thread")]
    async fn read_with_if_match_etag_passes_through_to_post_stat_compare() {
        let temp = TempDir::new().unwrap();
        let request = request_for_fs(&temp);
        let instance = instantiate(&request).await.unwrap();
        let backend = instance.backend.clone();
        let prefix = instance.address_roots[0].address.clone();
        let backend_id = instance.backend_id.clone();
        let object = address::join_relative(&prefix, "identity.bin").unwrap();
        backend
            .write(
                target_for(&backend_id, object.clone()),
                b"payload".to_vec(),
                WriteOptions::default(),
                None,
            )
            .await
            .unwrap();

        let observed = backend
            .stat(
                target_for(&backend_id, object.clone()),
                StatOptions::default(),
                None,
            )
            .await
            .unwrap();
        let _observed_size = observed
            .size
            .expect("fs driver should populate ObjectInfo.size");

        // Mismatched etag: read fails with ObjectModified.
        // The fs driver does not emit an etag, so any concrete expected
        // etag triggers the mismatch.
        let err = backend
            .read(
                target_for(&backend_id, object),
                ReadOptions {
                    if_match: Some("WRONG".into()),
                    ..ReadOptions::default()
                },
                None,
            )
            .await
            .expect_err("mismatched if_match etag must fail");
        assert_eq!(err.code(), ErrorCode::ObjectModified);
    }

    // === Empty if_dest is no-op ===
    //
    // SPI contract: `IfDestExists::Overwrite` (the default) is a no-op.
    // For backends that don't support `IfDestExists::MatchEtag`, that
    // variant surfaces `Unsupported`.

    #[tokio::test(flavor = "multi_thread")]
    async fn mutation_accepts_default_if_dest() {
        let temp = TempDir::new().unwrap();
        let request = request_for_fs(&temp);
        let instance = instantiate(&request).await.unwrap();
        let backend = instance.backend.clone();
        let prefix = instance.address_roots[0].address.clone();
        let backend_id = instance.backend_id.clone();
        let object = address::join_relative(&prefix, "default-if-dest.bin").unwrap();
        backend
            .write(
                target_for(&backend_id, object.clone()),
                b"payload".to_vec(),
                WriteOptions {
                    if_dest: IfDestExists::Overwrite,
                    ..Default::default()
                },
                None,
            )
            .await
            .expect("OpenDAL must accept IfDestExists::Overwrite (the default)");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn mutation_refuses_if_dest_match_etag() {
        let temp = TempDir::new().unwrap();
        let request = request_for_fs(&temp);
        let instance = instantiate(&request).await.unwrap();
        let backend = instance.backend.clone();
        let prefix = instance.address_roots[0].address.clone();
        let backend_id = instance.backend_id.clone();
        let object = address::join_relative(&prefix, "match-if-dest.bin").unwrap();
        let err = backend
            .write(
                target_for(&backend_id, object),
                b"payload".to_vec(),
                WriteOptions {
                    if_dest: IfDestExists::MatchEtag("not-empty".into()),
                    ..Default::default()
                },
                None,
            )
            .await
            .expect_err(
                "IfDestExists::MatchEtag must surface Unsupported (OpenDAL can't enforce it)",
            );
        assert_eq!(err.code(), ErrorCode::Unsupported);
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
    /// Flipping it is a behaviour change for every host that loads this plugin —
    /// rejects it on presigned writes outright, and keeps it elsewhere only
    /// when the connection's driver advertises support — a per-connection fact
    /// one kind cannot settle.
    #[test]
    fn opendal_declares_its_user_metadata_support() {
        let descriptor = kind_descriptor();
        assert_eq!(descriptor.kind, "opendal");
        assert!(
            !descriptor.supports_user_metadata,
            "opendal's user-metadata declaration changed; a host composes its \
             attribution layer from it"
        );
    }
}
