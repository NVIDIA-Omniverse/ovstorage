// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `RedirectFollowerWrapper` provides read- and write-path redirect following. On
//! `read`, a [`ReadResult::Redirect`] is fetched via the streaming follower
//! (`follow_read_redirect_streaming`) and surfaced as a
//! [`ReadResult::Stream`]. On `write`/`write_stream`, it attempts
//! `write_redirect` and, when the backend redirects, drives the
//! `follow_write_redirects` → `continue_write` multi-round loop (replaying
//! the body across rounds); otherwise it falls back to the body-typed slot.
//! See the [module docs](super) for the default-Stack order; the `follow_reads`
//! config knob passes read redirects up unfollowed for hosts that surface them
//! (REST as HTTP 307, the broker by forwarding).

use std::sync::Arc;

use async_trait::async_trait;

use crate::layers::{REDIRECT_FOLLOWER_KIND, descriptor};
use crate::retry::RetryConfig;
use crate::*;

use super::retry::retry_config_from;
use super::{cache_config_field, config_u64};

/// Default threshold above which a replayable `Body::Bytes` write body is
/// spooled to a temp file instead of retained + re-cloned in memory each
/// redirect round (64 MiB — matches the broker ingress hard cap
/// `WRITE_BODY_BYTE_CAP`).
///
/// Crossing the threshold changes only *where the body lives*, not its redirect
/// semantics: both the in-memory buffered path and the spooled path drive parts
/// via seek + bounded read (the spool through `WriteBody::SeekableFile` →
/// `follow_seekable_write_redirects`), so per-part HTTP retry AND arbitrary
/// (non-contiguous) part offsets are preserved on both sides. The spool trades
/// a large in-memory clone per round for on-disk bytes read O(chunk) at a time.
const DEFAULT_REPLAY_SPOOL_THRESHOLD_BYTES: u64 = 64 * 1024 * 1024;

enum ReplayBody {
    Buffered(Arc<Vec<u8>>),
    Other(Body),
}

impl ReplayBody {
    fn into_body(self) -> Body {
        match self {
            Self::Buffered(bytes) => {
                Body::Bytes(Arc::try_unwrap(bytes).unwrap_or_else(|bytes| (*bytes).clone()))
            }
            Self::Other(body) => body,
        }
    }
}

/// Config key: when `false`, read redirects pass up unfollowed instead of being
/// fetched server-side — except a redirect the disclosure policy will not let
/// cross the host boundary, which is followed locally and returned as a
/// `Stream`. Default `true`. Set via
/// `[ovstorage.layers.redirect_follower]` on the single global follower — the
/// REST gateway pins it `false` (surfaces read redirects as HTTP 307), the broker
/// follows small reads into its byte cache.
pub(crate) const FOLLOW_READS_KEY: &str = "follow_reads";
/// Config key: when set, a read redirect is followed only if the object's wire
/// size fits the cap; otherwise a delegable `Redirect` is returned unfollowed
/// and a non-delegable one is streamed through this host instead. Default
/// absent (unbounded — always follow). Set for the same bespoke-Stack reason as
/// [`FOLLOW_READS_KEY`].
pub(crate) const FOLLOW_READS_MAX_BYTES_KEY: &str = "follow_reads_max_bytes";
/// Config key: whether a redirect carrying a credential broader than the
/// redirected request may be handed to a caller outside this process.
///
/// **Hosts set this from their own operator config, not operators directly** —
/// the broker's top-level `redirect_credential_disclosure` is stamped onto
/// every follower in the graph at stack-build time. It is a layer key only
/// because this is where the read path can refuse *gracefully*, by fetching the
/// bytes itself. The guarantee lives at the host's out-edge, which no graph can
/// compose away.
///
/// Default `false` — refuse. A host stamps this from its own top-level
/// `redirect_credential_disclosure`, which on the broker governs the write path
/// with the same value.
pub const DISCLOSE_CREDENTIALS_KEY: &str = "disclose_redirect_credentials";

/// [`WrapperFactory`] for the `redirect_follower` wrapper kind
/// ([`REDIRECT_FOLLOWER_KIND`]).
pub struct RedirectFollowerWrapperFactory;

#[async_trait]
impl WrapperFactory for RedirectFollowerWrapperFactory {
    fn descriptor(&self) -> LayerKindDescriptor {
        let mut descriptor = descriptor(REDIRECT_FOLLOWER_KIND, LayerType::Wrapper, false);
        descriptor.config_schema = vec![
            cache_config_field(
                "replay_spool_threshold_bytes",
                "Replay spool threshold",
                ConfigFieldKind::Integer,
                false,
                "Byte threshold above which a replayable buffered write body is \
                 spooled to a temp file for redirect replay instead of retained + \
                 re-cloned in memory (default 64 MiB)",
            ),
            follower_config_field(
                FOLLOW_READS_KEY,
                "Follow read redirects",
                ConfigFieldKind::Bool,
                "When false, a read `Redirect` passes up unfollowed (the host surfaces it — \
                 REST as HTTP 307, the broker by forwarding). Body-bearing writes always \
                 follow regardless. Default true.",
            ),
            follower_config_field(
                FOLLOW_READS_MAX_BYTES_KEY,
                "Follow reads up to size",
                ConfigFieldKind::Integer,
                "When set, a read `Redirect` is followed only if the object's wire size fits \
                 this cap (decided from the headers-phase Content-Length before any body byte \
                 is read); an oversize or unknown-size object returns the `Redirect` \
                 unfollowed. Default unbounded.",
            ),
            follower_config_field(
                DISCLOSE_CREDENTIALS_KEY,
                "Disclose redirect credentials",
                ConfigFieldKind::Bool,
                "Whether a redirect carrying a credential broader than the redirected request \
                 may be handed to a caller outside this process. Hosts set this from their own \
                 operator config rather than operators setting it here. Default false (refuse: \
                 this host moves the bytes instead).",
            ),
        ];
        descriptor
    }

    async fn create_wrapper(
        &self,
        name: &str,
        config: &LayerConfig,
        inner: LayerHandle,
        _cancel: Option<CancellationToken>,
    ) -> Result<LayerHandle> {
        // The follower's internal HTTP retry (buffered write-redirect parts)
        // reuses the same `RetryConfig` shape as `RetryWrapper`.
        let retry = retry_config_from(config)?;
        let replay_spool_threshold_bytes = match config.get("replay_spool_threshold_bytes") {
            Some(value) => config_u64(value, "replay_spool_threshold_bytes")?,
            None => DEFAULT_REPLAY_SPOOL_THRESHOLD_BYTES,
        };
        let follow_reads = match config.get(FOLLOW_READS_KEY) {
            Some(ConfigValue::Bool(value)) => *value,
            Some(_) => {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    format!("redirect_follower config `{FOLLOW_READS_KEY}` must be a bool"),
                ));
            }
            None => true,
        };
        let follow_reads_max_bytes = match config.get(FOLLOW_READS_MAX_BYTES_KEY) {
            Some(value) => Some(super::config_u64(value, FOLLOW_READS_MAX_BYTES_KEY)?),
            None => None,
        };
        let disclose_credentials = match config.get(DISCLOSE_CREDENTIALS_KEY) {
            Some(ConfigValue::Bool(value)) => *value,
            Some(_) => {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    format!("redirect_follower config `{DISCLOSE_CREDENTIALS_KEY}` must be a bool"),
                ));
            }
            None => false,
        };
        // The size gate lives inside the follow arm, so a cap is unreachable when
        // reads aren't followed — reject the contradictory combination rather
        // than silently ignoring the cap.
        if !follow_reads && follow_reads_max_bytes.is_some() {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "`{FOLLOW_READS_MAX_BYTES_KEY}` has no effect with \
                     `{FOLLOW_READS_KEY} = false` (the size gate only applies when \
                     read redirects are followed)"
                ),
            ));
        }
        Ok(Arc::new(RedirectFollowerWrapper {
            name: name.to_string(),
            descriptor: self.descriptor(),
            inner,
            retry,
            replay_spool_threshold_bytes,
            follow_reads,
            follow_reads_max_bytes,
            disclose_credentials,
        }))
    }
}

/// One discoverable [`ConfigField`] for the redirect follower.
fn follower_config_field(
    key: &str,
    display_name: &str,
    kind: ConfigFieldKind,
    help: &str,
) -> ConfigField {
    ConfigField {
        key: key.to_string(),
        display_name: display_name.to_string(),
        kind,
        required: false,
        default: None,
        help: Some(help.to_string()),
        example: None,
        group: None,
        advanced: false,
    }
}

/// Follows redirects on the read and write paths. On `read`, a
/// [`ReadResult::Redirect`] is fetched via the streaming follower and returned
/// as [`ReadResult::Stream`]. On `write`/`write_stream`, the wrapper attempts
/// `write_redirect` and, when the backend redirects, drives the
/// `follow_write_redirects` → `continue_write` multi-round loop;
/// otherwise it falls back to the body-typed slot. `materialize` delegates
/// first and then falls back to redirect-following `read` plus local staging.
struct RedirectFollowerWrapper {
    name: String,
    descriptor: LayerKindDescriptor,
    inner: LayerHandle,
    retry: RetryConfig,
    /// Threshold above which a replayable `Body::Bytes` write body is spooled
    /// to a temp file for redirect replay instead of retained + re-cloned in
    /// memory each round. See [`DEFAULT_REPLAY_SPOOL_THRESHOLD_BYTES`] for the
    /// semantic cliff this crosses (streamed replay is not a drop-in for the
    /// buffered path).
    replay_spool_threshold_bytes: u64,
    /// When `false`, a read `Redirect` is passed up unfollowed (the one-tree
    /// read/write asymmetry primitive: REST surfaces it as HTTP 307, the broker
    /// forwards it). Writes still follow. Default `true`.
    follow_reads: bool,
    /// When `Some(cap)`, a read redirect is followed only if the object's wire
    /// size fits the cap; an oversize or unknown-size object returns the
    /// effective (possibly re-minted) `Redirect` unfollowed. Default `None`
    /// (unbounded).
    follow_reads_max_bytes: Option<u64>,
    /// Whether a redirect carrying a credential broader than the redirected
    /// request may be surfaced to a caller outside this process. Default
    /// `false`; the host sets it from operator config. See
    /// [`DISCLOSE_CREDENTIALS_KEY`].
    disclose_credentials: bool,
}

/// Outcome of [`RedirectFollowerWrapper::try_write_redirect`]: either the
/// write completed through the redirect path, or the backend declined to
/// redirect and the (possibly size-hint-populated) request must fall back to
/// the caller's body-typed slot.
#[allow(clippy::large_enum_variant)]
enum WriteRedirectOutcome {
    Done(WriteResult),
    Fallback(Request<WriteRequest>),
}

impl RedirectFollowerWrapper {
    /// Whether this redirect may be surfaced to a caller outside the process.
    ///
    /// Under the disclosing policy every valid redirect may cross; otherwise
    /// only one whose credential is no broader than the redirected request may.
    /// This forwards to the shared predicate rather than deciding anything
    /// itself, which is what keeps the follower's read arm and a host's write
    /// arm from drifting apart. The claim that they agree is asserted where
    /// both host guards are reachable, in the broker's
    /// `the_read_and_write_guards_agree_on_every_declaration`.
    fn may_delegate_read(&self, redirect: &ReadRedirect) -> bool {
        self.disclose_credentials || crate::redirect::read_redirect_is_safely_delegable(redirect)
    }

    /// Attempt the write-redirect path shared by `write`/`write_stream`.
    /// Populates `size_hint` from the body when unset (the backend plans the
    /// redirect by `size_hint`, not the body),
    /// skips a known 0-byte write, then attempts `inner.write_redirect` with an
    /// empty placeholder body (so a streamed body isn't consumed before the
    /// follow). On a batch, drives the redirect loop; on `Unsupported`, returns
    /// the reconstructed request for the caller to retry on its body-typed slot.
    async fn try_write_redirect(
        &self,
        request: Request<WriteRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteRedirectOutcome> {
        let Request { extensions, input } = request;
        let WriteRequest {
            address,
            body,
            options,
        } = input;

        let body = match body {
            Body::Bytes(bytes) => ReplayBody::Buffered(Arc::new(bytes)),
            body => ReplayBody::Other(body),
        };

        let size_hint = match options.size_hint {
            Some(hint) => Some(hint),
            None => match &body {
                ReplayBody::Buffered(bytes) => Some(bytes.len() as u64),
                ReplayBody::Other(Body::LocalFile(path)) => {
                    tokio::fs::metadata(path).await.ok().map(|m| m.len())
                }
                ReplayBody::Other(Body::Stream(_)) => None,
                ReplayBody::Other(Body::Bytes(_)) => unreachable!("bytes are promoted above"),
            },
        };
        let options = WriteOptions {
            size_hint,
            ..options
        };

        // A known 0-byte write never
        // redirects (pure round-trip overhead), and a sized write below the
        // owning root's `redirect_size_threshold` goes straight to the
        // body-typed slot. The threshold lives here; explicit callers driving the
        // redirect protocol always get the batch), so the explicit op below
        // this wrapper must not re-check it. Unknown size always tries; the
        // backend declines via `Unsupported`.
        let skip_redirect = match options.size_hint {
            Some(0) => true,
            Some(n) => self
                .inner
                .root_info_for(&address, &Extensions::new(), cancel.clone())
                .await
                .ok()
                .and_then(|root| root.capabilities.redirect_size_threshold)
                .is_some_and(|threshold| n < threshold),
            None => false,
        };
        if skip_redirect {
            return Ok(WriteRedirectOutcome::Fallback(Request {
                extensions,
                input: WriteRequest {
                    address,
                    body: body.into_body(),
                    options,
                },
            }));
        }

        let probe = Request {
            extensions: extensions.clone(),
            input: WriteRequest {
                address: address.clone(),
                body: Body::Bytes(Vec::new()),
                options: options.clone(),
            },
        };
        match self.inner.write_redirect(probe, cancel.clone()).await {
            Ok(batch) => {
                let result = self
                    .drive_write_redirects(address, extensions, body, batch, cancel)
                    .await?;
                Ok(WriteRedirectOutcome::Done(result))
            }
            Err(error) if error.code() == ErrorCode::Unsupported => {
                Ok(WriteRedirectOutcome::Fallback(Request {
                    extensions,
                    input: WriteRequest {
                        address,
                        body: body.into_body(),
                        options,
                    },
                }))
            }
            Err(error) => Err(error),
        }
    }

    /// Drive a `write_redirect` batch to completion, replaying the body across
    /// multi-round batches:
    /// buffered bodies are refcount-shared each round, `Body::LocalFile` is
    /// re-opened as a stream each round (never buffered), and `Body::Stream` is
    /// consumed once — a second round errors.
    ///
    /// `extensions` is the caller's original request context; it is attached to
    /// every `continue_write` round so the two halves of one logical write see
    /// the same `Request` extensions (matching the `write_redirect` probe and
    /// the `Unsupported` fallback in `try_write_redirect`).
    async fn drive_write_redirects(
        &self,
        address: Url,
        extensions: Extensions,
        body: ReplayBody,
        mut batch: WriteRedirectBatch,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        // Per-round replay source, owned up front so the original body isn't
        // retained twice. A small buffered body is held behind an `Arc`, so
        // every redirect round and the outer post-write byte cache can alias
        // the same allocation. A large one (over `replay_spool_threshold_bytes`)
        // is spooled to a temp file and driven as a seekable file (per-part
        // seek + bounded read), so a big replayable body is never retained +
        // re-cloned in memory. `Body::LocalFile` is driven the same way — a
        // seekable file, never buffered whole. `Body::Stream` is taken once — a
        // second round finds it gone.
        let mut buffered: Option<Arc<Vec<u8>>> = None;
        let mut local_path: Option<std::path::PathBuf> = None;
        let mut consumed_body: Option<Body> = None;
        // Keeps a spooled temp file alive across rounds (removed on drop); a
        // caller-supplied `Body::LocalFile` is left untouched.
        let mut _spool_guard: Option<SpooledReplayBody> = None;
        match body {
            ReplayBody::Buffered(bytes)
                if bytes.len() as u64 > self.replay_spool_threshold_bytes =>
            {
                let spool = SpooledReplayBody::write(bytes).await?;
                local_path = Some(spool.path().to_path_buf());
                _spool_guard = Some(spool);
            }
            ReplayBody::Buffered(bytes) => buffered = Some(bytes),
            // Both LocalFile and the large-bytes spool are seekable files:
            // per-part seek+read gives retry and arbitrary offsets, matching
            // the buffered path without holding the full body in memory.
            ReplayBody::Other(Body::LocalFile(path)) => local_path = Some(path),
            ReplayBody::Other(other) => consumed_body = Some(other),
        }
        loop {
            let redirect_body = if let Some(bytes) = &buffered {
                crate::redirect::WriteBody::Buffered(Arc::clone(bytes))
            } else if let Some(path) = &local_path {
                crate::redirect::WriteBody::SeekableFile(path.clone())
            } else {
                match consumed_body.take() {
                    Some(body) => crate::redirect::write_body_from(body).await?,
                    None => {
                        return Err(Error::new(
                            ErrorCode::Unsupported,
                            "nested write redirects against a streaming body \
                             (the stream was consumed in the first redirect round)",
                        ));
                    }
                }
            };
            let results =
                crate::redirect::follow_write_redirects(redirect_body, &batch, &self.retry).await?;
            let continue_request = Request {
                extensions: extensions.clone(),
                input: ContinueWriteRequest {
                    address: address.clone(),
                    redirects: batch,
                    results,
                },
            };
            match self
                .inner
                .continue_write(continue_request, cancel.clone())
                .await?
            {
                WriteStep::Done(mut result) => {
                    result.info.address = address.clone();
                    return Ok(result);
                }
                WriteStep::Redirects(next_batch) => batch = next_batch,
            }
        }
    }
}

/// A replayable write body spooled to a temp file, so a large buffered body is
/// driven as a seekable file (per-part seek + bounded read) each redirect round
/// instead of retained + cloned in memory. Backed by a
/// [`tempfile::NamedTempFile`] (created 0600, unlike a hand-rolled path under a
/// world-readable temp dir) and removed on drop / best-effort on process exit.
struct SpooledReplayBody {
    file: tempfile::NamedTempFile,
}

impl SpooledReplayBody {
    /// Spool `bytes` to a private temp file. The blocking file write (a body up
    /// to the 64 MiB threshold) runs on the blocking pool so it never stalls an
    /// async worker.
    async fn write(bytes: Arc<Vec<u8>>) -> Result<Self> {
        let file = tokio::task::spawn_blocking(move || -> Result<tempfile::NamedTempFile> {
            let mut file = tempfile::NamedTempFile::new().map_err(crate::redirect::io_error)?;
            std::io::Write::write_all(file.as_file_mut(), bytes.as_slice())
                .map_err(crate::redirect::io_error)?;
            file.as_file()
                .sync_all()
                .map_err(crate::redirect::io_error)?;
            Ok(file)
        })
        .await
        .map_err(|error| Error::new(ErrorCode::Internal, error.to_string()))??;
        Ok(Self { file })
    }

    fn path(&self) -> &std::path::Path {
        self.file.path()
    }
}

/// Stamp the caller-facing `address` onto every terminal [`ReadResult`]'s
/// `info.address`. This keeps the wrapper's
/// projection uniform across the redirect-follow arm (which already stamps the
/// address via the follower) and the non-redirect pass-through arm, so a
/// backend whose `info.address` differs from the caller URL never leaks the
/// physical address on one arm while the other masks it. A
/// [`ReadResult::Redirect`] carries no terminal `info` (the follower owns it),
/// so it is returned unchanged.
fn stamp_read_address(result: ReadResult, address: Url) -> ReadResult {
    match result {
        ReadResult::Bytes { bytes, mut info } => {
            info.address = address;
            ReadResult::Bytes { bytes, info }
        }
        ReadResult::Stream { stream, mut info } => {
            info.address = address;
            ReadResult::Stream { stream, info }
        }
        ReadResult::LocalDelegate(mut delegate) => {
            delegate.info.address = address;
            ReadResult::LocalDelegate(delegate)
        }
        ReadResult::Redirect(redirect) => ReadResult::Redirect(redirect),
    }
}

#[async_trait]
impl Layer for RedirectFollowerWrapper {
    fn name(&self) -> &str {
        &self.name
    }

    fn descriptor(&self) -> LayerKindDescriptor {
        self.descriptor.clone()
    }

    /// Slots with no redirect concern delegate to `inner` via the trait
    /// defaults — including the explicit `write_redirect`/`continue_write`
    /// protocol ops, which callers driving the redirect protocol themselves
    /// expect to reach the backend untouched.
    fn inner_layer(&self) -> Option<&LayerHandle> {
        Some(&self.inner)
    }

    // --- redirect-following read --------------------------------------------

    async fn read(
        &self,
        request: Request<ReadRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ReadResult> {
        // Capture redirect-follow inputs before the request moves into the
        // inner call: the original caller-facing address (for `info.address`),
        // the if-match flag (for redirect status mapping), the range (the
        // follower re-issues it as an HTTP `Range:` header and slices a 200),
        // and the full options + extensions (the re-mint closure re-issues the
        // whole backend read to obtain a fresh redirect).
        let address = request.input.address.clone();
        let if_match_was_set = request.input.options.if_match.is_some();
        let range = request.input.options.range.clone();
        let options = request.input.options.clone();
        let extensions = request.extensions.clone();
        // The `follow_reads=false` config knob makes every read redirect pass
        // through unfollowed (the host — REST/broker — surfaces it, falling to
        // the `other` arm below). When `follow_reads=true` with a size gate, a
        // read is followed only while its wire size fits `follow_reads_max_bytes`;
        // an oversize read surfaces unfollowed. Both behaviors are composition
        // choices on the single global follower, not a request-extension selector.
        let passthrough = !self.follow_reads;
        // Re-acquire a fresh redirect from the backend when the presigned
        // request expires or is rejected as invalid — the follower calls this
        // instead of replaying a stale URL. Both the follow arm and the
        // pass-through arm's local-follow fallback drive the same mint.
        let mint: crate::redirect::RedirectMint = {
            let inner = Arc::clone(&self.inner);
            let extensions = extensions.clone();
            let address = address.clone();
            let options = options.clone();
            let cancel = cancel.clone();
            Arc::new(move || {
                let inner = Arc::clone(&inner);
                let request = Request {
                    extensions: extensions.clone(),
                    input: ReadRequest {
                        address: address.clone(),
                        options: options.clone(),
                    },
                };
                let cancel = cancel.clone();
                Box::pin(async move {
                    match inner.read(request, cancel).await? {
                        ReadResult::Redirect(fresh) => Ok(fresh),
                        _ => Err(Error::new(
                            ErrorCode::Transient,
                            "backend stopped redirecting during a redirected read",
                        )),
                    }
                })
            })
        };
        match self.inner.read(request, cancel.clone()).await? {
            ReadResult::Redirect(redirect) if !passthrough => {
                let streamed = crate::redirect::follow_read_redirect_streaming(
                    address,
                    &redirect,
                    if_match_was_set,
                    range.as_ref(),
                    &self.retry,
                    Some(mint),
                )
                .await?;
                // Size gate: with `follow_reads_max_bytes` set, follow only when
                // the object's wire size fits the cap — decided from the
                // headers-phase Content-Length BEFORE any body byte is consumed
                // (the stream is lazy). An oversize or unknown-size object
                // returns the *effective* safely delegable `Redirect` unfollowed
                // — the one that worked in the header phase (re-minted if it
                // re-minted), not the caller's possibly-stale original. Ambient
                // credentials fail closed. The aborted fetch never drains the
                // response body.
                match self.follow_reads_max_bytes {
                    Some(cap) if streamed.content_length.is_none_or(|len| len > cap) => {
                        // Delegability is decided on the redirect that actually
                        // worked in the header phase, not the caller's original:
                        // `follow_read_redirect_streaming` re-mints on expiry or
                        // a 403, and a re-minted redirect carries its own
                        // declaration.
                        //
                        // When the policy will not let it cross the boundary,
                        // serve the bytes rather than failing. The stream is
                        // already open and already fetched with the credential
                        // in this process, so streaming it discloses nothing —
                        // it is the same local follow the pass-through arm does.
                        // The size cap decides whether an object is worth
                        // *caching*, and must not turn into a read outage for
                        // every connection whose redirects are non-delegable.
                        if !self.may_delegate_read(&streamed.effective_redirect) {
                            return Ok(ReadResult::Stream {
                                stream: streamed.stream,
                                info: streamed.info,
                            });
                        }
                        crate::redirect::ensure_read_redirect_valid(&streamed.effective_redirect)?;
                        // Surface the redirect that actually worked in the header
                        // phase — `follow_read_redirect_streaming` may have
                        // re-minted (on expiry or a 403 rejection), and the caller's
                        // original `redirect` could be expired or already 403'd.
                        Ok(ReadResult::Redirect(streamed.effective_redirect))
                    }
                    _ => Ok(ReadResult::Stream {
                        stream: streamed.stream,
                        info: streamed.info,
                    }),
                }
            }
            ReadResult::Redirect(redirect) => {
                // Validity (freshness, method, scope) is a hard requirement: an
                // invalid redirect has no bytes behind it either way.
                crate::redirect::ensure_read_redirect_valid(&redirect)?;
                // A redirect the disclosure policy will not let cross the host
                // boundary still has reachable bytes. Follow it locally and
                // return the stream instead of failing closed —
                // `follow_reads=false` says "don't hand the caller a followed
                // stream by default", not "make credentialed backends
                // unreadable". The in-tree Nucleus LFT read is exactly this
                // shape, and a broker without a byte cache runs with
                // `follow_reads=false`.
                if !self.may_delegate_read(&redirect) {
                    let streamed = crate::redirect::follow_read_redirect_streaming(
                        address,
                        &redirect,
                        if_match_was_set,
                        range.as_ref(),
                        &self.retry,
                        Some(mint),
                    )
                    .await?;
                    return Ok(ReadResult::Stream {
                        stream: streamed.stream,
                        info: streamed.info,
                    });
                }
                Ok(ReadResult::Redirect(redirect))
            }
            // Non-redirect results: stamp the caller-facing address so the
            // pass-through arm projects it the same way the follow arm does.
            other => Ok(stamp_read_address(other, address)),
        }
    }

    async fn write(
        &self,
        request: Request<WriteRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        match self.try_write_redirect(request, cancel.clone()).await? {
            WriteRedirectOutcome::Done(result) => Ok(result),
            // Body-typed fallback: stamp the caller-facing address so it matches
            // the redirect path (`drive_write_redirects`).
            WriteRedirectOutcome::Fallback(request) => {
                let address = request.input.address.clone();
                let mut result = self.inner.write(request, cancel).await?;
                result.info.address = address;
                Ok(result)
            }
        }
    }

    async fn write_stream(
        &self,
        request: Request<WriteRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        match self.try_write_redirect(request, cancel.clone()).await? {
            WriteRedirectOutcome::Done(result) => Ok(result),
            WriteRedirectOutcome::Fallback(request) => {
                let address = request.input.address.clone();
                let mut result = self.inner.write_stream(request, cancel).await?;
                result.info.address = address;
                Ok(result)
            }
        }
    }

    async fn materialize(
        &self,
        request: Request<ReadRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<LocalDelegate> {
        // Try the inner materialize first: the built-in `file://` backend and
        // other native layers may stage locally. A backend that exposes a
        // large object only as a `read` `Redirect` returns `Unsupported` here —
        // fall back to a redirect-following read staged to a temp file, so
        // materialize reads, follows redirects, and stages locally for those
        // backends too.
        let address = request.input.address.clone();
        let address_for_stage = address.clone();
        let options = request.input.options.clone();
        let extensions = request.extensions.clone();
        // Captured before `options` moves into the `ReadRequest` below. The
        // follow needs all three, exactly as the read path's two call sites do:
        // the range because `send_streaming_request` injects `Range:` only when
        // it is `Some` and backends deliberately leave it unsigned on the
        // contract that the host adds it, so dropping it stages the whole object
        // under a name that says otherwise; and the if-match flag because it
        // selects `ObjectModified` over `PreconditionFailed` for a 412.
        let if_match_was_set = options.if_match.is_some();
        let range = options.range.clone();
        match self.inner.materialize(request, cancel.clone()).await {
            Ok(local) => Ok(local),
            Err(error) if error.code() == ErrorCode::Unsupported => {
                let read = Request {
                    extensions: extensions.clone(),
                    input: ReadRequest {
                        address: address.clone(),
                        options: options.clone(),
                    },
                };
                // Re-acquire a fresh redirect when the presigned request expires
                // or is rejected, rather than failing the stage on a stale URL.
                // The read path does this and staging has the same need — more
                // so, because there is no caller to hand a retry to.
                let mint: crate::redirect::RedirectMint = {
                    let inner = Arc::clone(&self.inner);
                    let cancel = cancel.clone();
                    Arc::new(move || {
                        let inner = Arc::clone(&inner);
                        let request = Request {
                            extensions: extensions.clone(),
                            input: ReadRequest {
                                address: address.clone(),
                                options: options.clone(),
                            },
                        };
                        let cancel = cancel.clone();
                        Box::pin(async move {
                            match inner.read(request, cancel).await? {
                                ReadResult::Redirect(fresh) => Ok(fresh),
                                _ => Err(Error::new(
                                    ErrorCode::Transient,
                                    "backend stopped redirecting during a redirected read",
                                )),
                            }
                        })
                    })
                };
                // `self.read` can hand back an unfollowed `Redirect` — that is
                // what the pass-through arm exists for, and the disclosure
                // policy widens the set of redirects it applies to. Staging
                // needs bytes on this host, and there is no caller to delegate
                // to, so follow one here rather than surfacing the helper's
                // `Unsupported`.
                let result = match self.read(read, cancel.clone()).await? {
                    ReadResult::Redirect(redirect) => {
                        let streamed = crate::redirect::follow_read_redirect_streaming(
                            address_for_stage,
                            &redirect,
                            if_match_was_set,
                            range.as_ref(),
                            &self.retry,
                            Some(mint),
                        )
                        .await?;
                        ReadResult::Stream {
                            stream: streamed.stream,
                            info: streamed.info,
                        }
                    }
                    other => other,
                };
                crate::read_helpers::stage_read_result_to_local_delegate(result, cancel).await
            }
            Err(error) => Err(error),
        }
    }
}
