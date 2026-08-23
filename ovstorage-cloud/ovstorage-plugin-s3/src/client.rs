// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! AWS SDK client construction for the S3 backend.
//!
//! Builds the per-connection `aws_sdk_s3::Client` on top of a rustls+ring
//! HTTP client (`aws-smithy-http-client` with `default-features = false` +
//! `rustls-ring`, reusing the rustls/ring/webpki-roots already in the tree;
//! the SDK's default `aws-lc` crypto is never pulled).
//!
//! Credentials are **static only**: [`SharedAwsCredentials`] reads the same
//! `Arc<Mutex<Option<AwsCredentials>>>` the backend mutates via
//! `store_credentials`, and the SDK identity cache is disabled
//! (`IdentityCache::no_cache()`) so a host-driven credential refresh after a
//! `401 -> AuthRequired` is picked up on the next request without rebuilding
//! the client — each request reads the current credential from the cell.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use aws_credential_types::Credentials;
use aws_credential_types::provider::error::CredentialsError;
use aws_credential_types::provider::future::ProvideCredentials as ProvideCredentialsFuture;
use aws_credential_types::provider::{ProvideCredentials, SharedCredentialsProvider};
use aws_sdk_s3::config::interceptors::BeforeDeserializationInterceptorContextRef;
use aws_sdk_s3::config::retry::RetryConfig;
use aws_sdk_s3::config::timeout::TimeoutConfig;
use aws_sdk_s3::config::{
    BehaviorVersion, ConfigBag, IdentityCache, Intercept, Region, RequestChecksumCalculation,
    ResponseChecksumValidation, RuntimeComponents, SharedHttpClient,
};
use aws_sdk_s3::error::BoxError;
use aws_smithy_http_client::proxy::ProxyConfig;
use aws_smithy_http_client::tls;
use aws_smithy_http_client::tls::rustls_provider::CryptoMode;
use aws_smithy_http_client::{Builder as HttpBuilder, Connector as HttpConnector};
use ovstorage_plugin::connection::promotion::{self, EvidenceScope};
// Re-exported so the rest of the crate names these through `crate::client`.
pub(crate) use ovstorage_plugin::connection::promotion::{OperationEvidence, RefusalEpoch};
use ovstorage_plugin::{Error, ErrorCode, Result};

use crate::config::{S3Config, sdk_endpoint_url};
use crate::credentials::AwsCredentials;

/// HTTP timeouts: 60s request, 15s connect. With SDK retries disabled the
/// operation timeout is the per-attempt timeout.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// A static credential source backed by the backend's live credential cell.
///
/// The SDK consults this on every request (identity caching is disabled), so
/// updates made through `S3Backend::store_credentials` take effect without
/// rebuilding the client.
#[derive(Clone, Debug)]
pub(crate) struct SharedAwsCredentials {
    cell: Arc<Mutex<Option<AwsCredentials>>>,
}

impl SharedAwsCredentials {
    pub(crate) fn new(cell: Arc<Mutex<Option<AwsCredentials>>>) -> Self {
        Self { cell }
    }

    fn load(&self) -> std::result::Result<Credentials, CredentialsError> {
        match self
            .cell
            .lock()
            .expect("credential mutex poisoned")
            .as_ref()
        {
            Some(creds) => Ok(Credentials::new(
                creds.access_key_id.clone(),
                creds.secret_access_key.clone(),
                creds.session_token.clone(),
                // Static keys never expire on their own; a host-driven refresh
                // replaces the cell contents instead.
                None,
                "ovstorage-s3-secretbundle",
            )),
            None => Err(CredentialsError::not_loaded(
                "S3 backend has no credentials configured",
            )),
        }
    }
}

impl ProvideCredentials for SharedAwsCredentials {
    fn provide_credentials<'a>(&'a self) -> ProvideCredentialsFuture<'a>
    where
        Self: 'a,
    {
        ProvideCredentialsFuture::ready(self.load())
    }
}

/// The provider-origin headers an S3 response carries. A response with neither
/// was composed by something that is not an S3 or S3-compatible store: a WAF
/// answering an unrecognized path with a bare 404, or a captive portal or SSO
/// front door answering its own 200.
///
/// The AWS SDK itself treats these two as S3's response metadata
/// (`aws_sdk_s3::operation::RequestIdExt`, which reads `x-amz-id-2`, alongside
/// the `x-amz-request-id` every request id comes from), and MinIO, Ceph RGW,
/// R2 and B2 all stamp `x-amz-request-id`.
///
/// What it does NOT exclude is a CACHE. An HTTP cache replays the upstream
/// response headers verbatim, request id included, so a cache hit is
/// indistinguishable here from a fresh answer — and no header check could tell
/// them apart. It also does not exclude adversaries: anything able to answer
/// for the endpoint's hostname is already terminating TLS and can add a header,
/// and from there it could serve the verify probe and produce `Authenticated`
/// directly.
///
/// The residual runs the other way too. A store that stamps neither header —
/// one whose request id rides under a vendor prefix of its own — never has a
/// connection promoted, so a connection of theirs parked by a refused probe
/// stays parked. That is where it is today, so the check regresses nothing, and
/// it is the recoverable direction:
/// a connection parked in error keeps working and clears itself on its next
/// accepted operation, while a connection promoted in error has no path back
/// short of an operator rotating credentials.
const ORIGIN_HEADERS: &[&str] = &["x-amz-request-id", "x-amz-id-2"];

/// Whether a response could only have been produced for a request the store
/// AUTHENTICATED — the evidence `S3Layer::recover` promotes a parked connection
/// on.
///
/// This is not the negation of [`vetoes_promotion`], and collapsing the two
/// would be wrong in a way that matters. They are duals with opposite biases:
/// `S3Driver::verify` asks whether the credential was REFUTED and is
/// deliberately lenient, so an outage or a restricted IAM policy leaves a
/// connection usable. This asks whether the credential was PROVEN, and has to
/// be strict for the mirror-image reason — a 503 from a front door, a throttle,
/// or a request rejected before anything looked at the signature says nothing
/// about the credential.
///
/// `origin_stamped` is whether the response carried one of [`ORIGIN_HEADERS`];
/// it is passed in rather than read here because naming the smithy header type
/// would make this crate depend on the SDK's transport crate directly.
///
/// The origin gate is asked FIRST, so a response from something that is not the
/// store is refused acceptance whatever status it carries. The status half is
/// [`promotion::status_is_routed_verdict`], shared with the azure and gcs
/// plugins, which is also where the deliberate exclusion of `404` is argued.
/// Everything it excludes proves nothing here either — including `403`, which
/// is a refusal of some kind either way.
fn proves_credentials(status: u16, origin_stamped: bool) -> bool {
    if !origin_stamped {
        tracing::debug!(
            plugin = "s3",
            status,
            "s3: response carries no x-amz-request-id or x-amz-id-2; not \
             counting it as acceptance"
        );
        return false;
    }
    promotion::status_is_routed_verdict(status)
}

/// Whether a response should VETO a promotion, judged from the status line
/// alone: any `400`, `401` or `403`.
///
/// `400` is there because S3 puts three of its definitive credential rejections
/// behind it. `S3Driver::verify` parks on `ExpiredToken`, `InvalidToken` and
/// `TokenRefreshRequired`, and the service answers all three with `400` — so
/// without this arm a session-token expiry mid-operation would leave an earlier
/// request's acceptance free to promote a credential that had just died.
///
/// The cost is not exotic and is worth naming: `copy` and `rename` issue a
/// single `CopyObject`, which AWS refuses with `400 InvalidRequest` for a source
/// over 5 GiB — routine in an asset store — and an S3-compatible store answers
/// `400` for parameters it does not implement. Each withholds promotion for
/// operations overlapping it, until one runs clear of one. That is the
/// recoverable direction; a session token that expires mid-operation and
/// promotes on an earlier request's acceptance is not.
///
/// Deliberately BROADER than the rule `S3Driver::verify` parks on — the two are
/// not interchangeable, and a new call site has to pick between them on the
/// question being asked. They lean opposite ways on purpose. `verify` asks "was
/// this credential definitively REFUTED?" and is lenient, so an ambiguous
/// refusal does not park a connection that works. This asks "might this
/// credential have been refused?" and is conservative, because its only power is
/// to WITHHOLD a promotion.
///
/// The azure and gcs siblings do not veto on an authorization-SCOPE 403 — azure
/// reads the verdict from `x-ms-error-code`, and gcs's mapping makes 403 mean
/// "identified, then scoped" outright. This deliberately does veto, because on
/// S3 that discrimination is not available where it would have to be made. S3 carries its error code in the
/// response BODY, so reading it means waiting for deserialization — and the
/// smithy orchestrator runs its attempt finalizer INSIDE the attempt-timeout
/// future, so a `403` whose body stalls past the timeout would never be judged
/// at all. A refusal lost that way lets an earlier request of the same operation
/// promote a credential that has just died. Judging on the status line cannot
/// lose one.
///
/// Two further things a carve-out would have got wrong even when it did run:
/// `S3Driver::verify`'s own doc records that some stores report a DISABLED key
/// as plain `AccessDenied`, and an S3-compatible store may spell its codes its
/// own way or sit behind a proxy that strips them.
///
/// **The cost is real and it is not bounded, and that is the deliberate trade.**
/// A host rendering permission badges provokes `403 AccessDenied` continuously
/// — `check_access`'s object arm is a `HeadObject` the principal may not read —
/// and those DO count: [`EVIDENCE_SUPPRESSED`] suppresses only the probe's
/// successes. On such a host the connection-wide epoch may never hold still
/// long enough for a concurrent operation to find it unchanged, so promotion can
/// be unreachable for as long as that workload runs, and `refresh` being
/// `Unsupported` means nothing retries it.
///
/// It is still the right way round. That connection stays exactly where it was
/// before this mechanism existed — parked, and fully working — whereas dropping
/// those refusals lets a concurrent operation's earlier acceptance promote a
/// credential the store has since refused, which nothing can undo. Withholding
/// is the recoverable direction even when the withholding does not end.
fn vetoes_promotion(status: u16) -> bool {
    matches!(status, 400 | 401 | 403)
}

tokio::task_local! {
    /// Set while a request's SUCCESSES must not be counted as evidence.
    ///
    /// `check_access` is the only user. It exists to ASK the store what the
    /// caller may do, and it asks by provoking the answer — its bucket arm calls
    /// `GetBucketPolicyStatus`, its object arm a `HeadObject` the principal may
    /// not read — so a `200` it receives is the answer to its own question
    /// rather than evidence the connection earned. It must not promote on that.
    ///
    /// **Only acceptance is suppressed. Every refusal still counts.** Dropping
    /// them was tried and is wrong: a refusal this probe hears is one the
    /// CONNECTION heard, and dropping it lets a concurrent operation's earlier
    /// acceptance promote a credential that has since died — a key disabled
    /// mid-sweep is answered `403` to the probe, dropped, and the ordinary
    /// operation still in flight finds the epoch unchanged and promotes. Nothing
    /// demotes it afterwards: `refresh` is `Unsupported` and no data-path
    /// operation parks a connection.
    ///
    /// The price is stated at [`vetoes_promotion`] and it is not small: a
    /// permission-rendering host provokes a `403` per visible row, which can
    /// keep the epoch moving continuously, so promotion may never happen while
    /// that workload runs.
    ///
    /// The azure sibling's `send_advisory` makes the OPPOSITE trade on what
    /// looks like the same question — it drops ambiguous refusals and keeps
    /// acceptance — and the difference is what the two are for. That path is a
    /// best-effort request whose failure the caller ignores, so its answer is
    /// incidental to an operation that is doing something else; this one IS the
    /// operation, and its whole output is a verdict about permissions.
    static EVIDENCE_SUPPRESSED: ();

    /// The evidence sink belonging to the operation running on this task.
    ///
    /// Installed by `S3Layer`'s witness around the operation future and read by
    /// the `PromotionEvidence` interceptor's `read_after_transmit`. Absent for
    /// work that belongs to no operation — the SQS watch poller, which runs on a
    /// task of its own — and a verdict recorded nowhere can vindicate nothing,
    /// which is the safe way round.
    static OPERATION_EVIDENCE: Arc<OperationEvidence>;
}

/// This plugin's acceptance sink, naming [`OPERATION_EVIDENCE`] for the shared
/// [`promotion`] machinery.
///
/// The sink is scoped this tightly because a connection is one set of SDK
/// clients shared by every operation running against it, and under the broker
/// those are unrelated remote callers. A connection-wide tally would let a
/// caller whose own operation never reached the service — a `read`, which only
/// presigns a URL — be vindicated by a neighbour's request. A wrong promotion
/// is unrecoverable: `S3Driver::refresh` is `Unsupported`, and no data-path
/// operation parks a connection.
///
/// Refusal is not recorded in the sink at all. It belongs to the connection —
/// see [`RefusalEpoch`] — because the credential is one object and a refusal
/// answered to anyone condemns it for everyone.
pub(crate) struct S3Evidence;

impl EvidenceScope for S3Evidence {
    fn sink() -> &'static tokio::task::LocalKey<Arc<OperationEvidence>> {
        &OPERATION_EVIDENCE
    }
}

/// Run `future` with the ACCEPTANCES its requests earn discarded. Its refusals
/// still count — see [`EVIDENCE_SUPPRESSED`] for why they are not the
/// operation's to drop.
pub(crate) async fn without_promotion_evidence<T>(
    future: impl std::future::Future<Output = T>,
) -> T {
    EVIDENCE_SUPPRESSED.scope((), future).await
}

/// Run `future` with `evidence` installed as the operation's acceptance sink.
pub(crate) async fn with_operation_evidence<T>(
    evidence: Arc<OperationEvidence>,
    future: impl std::future::Future<Output = T>,
) -> T {
    promotion::with_operation_evidence::<S3Evidence, _>(evidence, future).await
}

/// Records each response's verdict for the connection promotion rule: an
/// acceptance to the operation that earned it, a refusal to the whole
/// connection.
///
/// An SDK interceptor rather than a wrapper around a send function — the shape
/// the gcs sibling uses — because the AWS SDK owns the transport here and this
/// is the seam it offers. It also reaches every operation the plugin calls
/// without a call site having to remember.
///
/// This plugin needs no redirect guard, unlike its azure and gcs siblings,
/// which both withhold evidence for a response fetched after one. The reason is
/// the transport: `aws-smithy-http-client` has no follow-redirect layer, so a
/// `3xx` is returned to the caller rather than chased, and every response judged
/// here is the answer to the request this process signed.
///
/// `read_after_transmit` is the hook, and the choice is load-bearing: smithy
/// invokes it the moment the response arrives, with the status and headers
/// available and the body still unread. Everything here is judged from those,
/// so no verdict can be lost to a body that stalls or a stream that fails
/// mid-flight — which the later `read_after_attempt` could not promise, because
/// smithy runs its attempt finalizer inside the attempt-timeout future.
///
/// Reading the failure arm is deliberate: a 412 for a lost precondition is a
/// request the store authenticated, and a workload made of them would otherwise
/// leave a working connection parked for ever.
///
/// Anonymous connections never reach here: their client is built by
/// [`build_anonymous_s3_client`], which attaches no interceptor, so an unsigned
/// request records no evidence for a connection that has no credential to
/// prove.
#[derive(Debug)]
struct PromotionEvidence {
    /// The connection's refusal epoch.
    ///
    /// What "refuses the credential" means here is narrower than "answers an
    /// error" and broader than certainty. A `403` DOES advance it, because at
    /// the status line a policy denial and a refused signature are the same
    /// response — see [`vetoes_promotion`] for why that ambiguity is resolved
    /// conservatively — and it advances even for an evidence-suppressed
    /// operation, because a refusal that probe hears is one the connection
    /// heard. It is not evidence FOR the credential either:
    /// [`proves_credentials`] excludes every `403`.
    ///
    /// The SQS client carries no interceptor, so a watch poller's refusals do
    /// not reach it. See [`build_sqs_client`] for why. A watch-only connection
    /// therefore contributes evidence in neither direction and simply stays as
    /// it is.
    refusals: RefusalEpoch,
}

impl Intercept for PromotionEvidence {
    fn name(&self) -> &'static str {
        "ovstorage-s3-promotion-evidence"
    }

    fn read_after_transmit(
        &self,
        context: &BeforeDeserializationInterceptorContextRef<'_>,
        _components: &RuntimeComponents,
        _cfg: &mut ConfigBag,
    ) -> std::result::Result<(), BoxError> {
        let response = context.response();
        let status = response.status().as_u16();
        let suppressed = EVIDENCE_SUPPRESSED.try_with(|()| ()).is_ok();
        // One judgment, two scopes: a refusal condemns the credential for the
        // whole connection, while an acceptance vindicates only the operation
        // that earned it.
        if vetoes_promotion(status) {
            self.refusals.bump();
        } else if !suppressed
            && proves_credentials(
                status,
                ORIGIN_HEADERS
                    .iter()
                    .any(|name| response.headers().get(*name).is_some()),
            )
        {
            // Credit the operation running on this task, if any. Work that
            // belongs to no operation — the SQS watch poller — credits nothing,
            // and an acceptance recorded nowhere vindicates nobody. Refusals
            // are not routed through here at all: they go to the
            // connection-wide epoch, so the ones this task-local would have
            // dropped still veto.
            promotion::credit_operation_acceptance::<S3Evidence>();
        }
        Ok(())
    }
}

/// Build the shared rustls+ring HTTP client. One per backend instance, cloned
/// into each service client so a connection keeps its own connection pool /
/// trust scope. Proxy routing is process-scoped: the connector snapshots the
/// standard `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` / `NO_PROXY`
/// environment when it is built, matching the reqwest-backed plugins.
///
/// `build_with_connector_fn` is `#[doc(hidden)]` in `aws-smithy-http-client`,
/// so it can change without a semver signal; it is the only entry point that
/// accepts a proxy config alongside the rustls provider. The closure receives
/// the connector settings and components but not the outer `HttpBuilder`, so a
/// future `HttpBuilder::pool_idle_timeout()` on the builder below would not
/// reach the connector — set such knobs inside the closure instead.
pub(crate) fn build_http_client() -> SharedHttpClient {
    let proxy_config = ProxyConfig::from_env();
    HttpBuilder::new().build_with_connector_fn(move |settings, components| {
        let mut builder = HttpConnector::builder().proxy_config(proxy_config.clone());
        builder.set_connector_settings(settings.cloned());
        if let Some(components) = components {
            builder.set_sleep_impl(components.sleep_impl());
        }
        builder
            .tls_provider(tls::Provider::Rustls(CryptoMode::Ring))
            .build()
    })
}

/// The transport and endpoint settings both client shapes share.
///
/// - region carries the SigV4 credential-scope region (`signing_region()`,
///   which is the literal `auto` for R2/B2);
/// - `force_path_style` and `endpoint_url` come straight from the config's
///   compatibility profile;
/// - retries are disabled (the host owns retry, via `ConnectionSet::with_recovery`
///   and the route-level retry Layer);
/// - request/response checksum calculation is `WhenRequired` so no default
///   `x-amz-checksum-*` headers are emitted (S3-compatible stores such as
///   MinIO/R2/B2 can reject unexpected checksum headers).
///
/// The region is set on the anonymous client too. It reaches the wire only
/// through the SigV4 credential scope, which an unsigned request has none of,
/// but the SDK's endpoint rules read it to build the virtual-hosted host name
/// for AWS-shaped buckets — so omitting it would break address construction
/// rather than remove a signature.
fn s3_config_builder(config: &S3Config, http: SharedHttpClient) -> aws_sdk_s3::config::Builder {
    aws_sdk_s3::Config::builder()
        .behavior_version(BehaviorVersion::latest())
        .http_client(http)
        .region(Region::new(config.signing_region().to_string()))
        .force_path_style(config.use_path_style())
        .retry_config(RetryConfig::disabled())
        .timeout_config(
            TimeoutConfig::builder()
                .operation_timeout(REQUEST_TIMEOUT)
                .operation_attempt_timeout(REQUEST_TIMEOUT)
                .connect_timeout(CONNECT_TIMEOUT)
                .build(),
        )
        .request_checksum_calculation(RequestChecksumCalculation::WhenRequired)
        .response_checksum_validation(ResponseChecksumValidation::WhenRequired)
}

/// Build the per-connection signing `aws_sdk_s3::Client`.
pub(crate) fn build_s3_client(
    config: &S3Config,
    credentials: SharedAwsCredentials,
    http: SharedHttpClient,
    refusals: RefusalEpoch,
) -> Result<aws_sdk_s3::Client> {
    let mut builder = s3_config_builder(config, http)
        .interceptor(PromotionEvidence { refusals })
        .credentials_provider(SharedCredentialsProvider::new(credentials))
        .identity_cache(IdentityCache::no_cache());

    if let Some(endpoint) = sdk_endpoint_url(config)? {
        builder = builder.endpoint_url(endpoint);
    }

    Ok(aws_sdk_s3::Client::from_conf(builder.build()))
}

/// Build the per-connection UNSIGNED `aws_sdk_s3::Client` for an anonymous
/// connection.
///
/// The whole of the difference is that no credentials provider is registered.
/// The SigV4 auth scheme then has no identity resolver, so the orchestrator
/// skips it and takes the next option the resolver offers, which for S3 is
/// `smithy.api#noAuth`: the service's own model lists it, so
/// `aws_sdk_s3::config::auth::DefaultAuthSchemeResolver` returns it among the
/// defaults. The request leaves carrying no `Authorization` header and no
/// `X-Amz-*` signature, and S3 evaluates it as the anonymous principal, which
/// is who a public bucket's policy grants to. This is what `aws_config`'s
/// `no_credentials()` amounts to, expressed on the service config because this
/// plugin never loads an `SdkConfig`.
///
/// `Config::allow_no_auth()` is deliberately NOT set. It exists to add that
/// option for a service whose model does **not** offer it, and S3's does — it
/// was measured here to change nothing, the wire form being identical with and
/// without it, so it would be one more line to keep in step for no effect.
///
/// The dependency this rests on is therefore the resolver's default list, plus
/// nobody calling `set_auth_scheme_resolver` on the anonymous builder. Neither
/// is a compile error to break, so what holds the property is
/// `tests/anonymous_public_bucket.rs`, which asserts the absence of
/// `Authorization` on the wire against a control that asserts its presence for
/// a credentialed connection.
///
/// Deliberately carries NO [`PromotionEvidence`] interceptor. That mechanism
/// exists to decide whether a CREDENTIAL was proven or refused, and an
/// anonymous connection has none: it is `ConnectionAuthState::Anonymous`
/// permanently, never parked and so never awaiting promotion. Attaching the
/// interceptor would record verdicts about a credential that does not exist.
/// This matches [`build_sqs_client`], which omits it for its own reason.
pub(crate) fn build_anonymous_s3_client(
    config: &S3Config,
    http: SharedHttpClient,
) -> Result<aws_sdk_s3::Client> {
    let mut builder = s3_config_builder(config, http);

    if let Some(endpoint) = sdk_endpoint_url(config)? {
        builder = builder.endpoint_url(endpoint);
    }

    Ok(aws_sdk_s3::Client::from_conf(builder.build()))
}

/// Build the `aws_sdk_sqs::Client` used for `watch_directory`. Shares the
/// backend's HTTP client + static credentials, signs with the same region, and
/// targets the queue's own host (works for AWS `sqs.<region>.amazonaws.com` and
/// custom/S3-compatible SQS endpoints alike); the queue URL is passed per
/// operation. Retries are disabled (the watch loop owns its own retry cadence).
///
/// Deliberately carries NO [`PromotionEvidence`] interceptor, unlike the S3
/// client, and for two reasons that both point the same way.
///
/// The queue is a separate resource with its own policy, and often a separate
/// account: an SQS `403` is evidence about the queue, not about the object-store
/// credential. And [`vetoes_promotion`] judges the status line alone, so every
/// SQS `403` would advance the refusal epoch with nothing to distinguish a
/// denying queue policy from a refused signature — while the watch loop polls
/// continuously, which would leave the connection effectively unpromotable for
/// as long as the watch runs. That is the condition this mechanism exists to
/// end. A credential that is genuinely dead is refused on the S3 client too,
/// where it is seen.
pub(crate) fn build_sqs_client(
    config: &S3Config,
    credentials: SharedAwsCredentials,
    http: SharedHttpClient,
    queue_url: &str,
) -> Result<aws_sdk_sqs::Client> {
    let endpoint = sqs_endpoint_url(queue_url)?;
    let builder = aws_sdk_sqs::Config::builder()
        .behavior_version(BehaviorVersion::latest())
        .http_client(http)
        .region(Region::new(config.signing_region().to_string()))
        .credentials_provider(SharedCredentialsProvider::new(credentials))
        .identity_cache(IdentityCache::no_cache())
        .retry_config(RetryConfig::disabled())
        .timeout_config(
            TimeoutConfig::builder()
                .operation_timeout(REQUEST_TIMEOUT)
                .operation_attempt_timeout(REQUEST_TIMEOUT)
                .connect_timeout(CONNECT_TIMEOUT)
                .build(),
        )
        .endpoint_url(endpoint);
    Ok(aws_sdk_sqs::Client::from_conf(builder.build()))
}

/// The `scheme://host[:port]` origin of an SQS queue URL, for the SDK endpoint.
fn sqs_endpoint_url(queue_url: &str) -> Result<String> {
    let parsed = url::Url::parse(queue_url).map_err(|err| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("S3 sqs_queue_url is not a valid URL: {err}"),
        )
    })?;
    let scheme = parsed.scheme();
    let host = parsed.host_str().ok_or_else(|| {
        Error::new(
            ErrorCode::InvalidArgument,
            "S3 sqs_queue_url must include a host",
        )
    })?;
    match parsed.port() {
        Some(port) => Ok(format!("{scheme}://{host}:{port}")),
        None => Ok(format!("{scheme}://{host}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Acceptance is scoped to the operation that earned it, which is the whole
    /// reason the sink is a task-local rather than connection state.
    ///
    /// Asserted on the sinks directly rather than on `auth_state`, because that
    /// is what separates the two scopings: an accepted neighbour promotes the
    /// connection either way, so no state assertion can tell a per-operation
    /// sink from a connection-wide tally. Replacing this with connection-wide
    /// state would let a caller whose own operation never left the process — a
    /// `read`, which only presigns a URL — be vindicated by a neighbour's
    /// request, and under the broker those two are unrelated remote clients.
    #[tokio::test]
    async fn acceptance_does_not_cross_between_operations() {
        let earner = Arc::new(OperationEvidence::default());
        let neighbour = Arc::new(OperationEvidence::default());

        // Separate TASKS, not `join!` on one: the sink is a task-local, so two
        // futures interleaved on a single task would not exercise the isolation
        // this claims to pin. Under the broker these two are separate callers.
        let earning = tokio::spawn(with_operation_evidence(earner.clone(), async {
            tokio::task::yield_now().await;
            promotion::credit_operation_acceptance::<S3Evidence>();
        }));
        let neighbouring = tokio::spawn(with_operation_evidence(neighbour.clone(), async {
            tokio::task::yield_now().await;
            tokio::task::yield_now().await;
        }));
        earning.await.expect("the earner joins");
        neighbouring.await.expect("the neighbour joins");

        assert!(
            earner.saw_acceptance(),
            "control: the operation that made the request recorded it"
        );
        assert!(
            !neighbour.saw_acceptance(),
            "an operation that reached no request must not be vindicated by its \
             neighbour's"
        );
    }

    /// The acceptance rule and the veto rule lean deliberately opposite ways,
    /// and each arm here is a deployment that would otherwise be misjudged.
    #[test]
    fn acceptance_requires_an_origin_stamp_and_a_routed_verdict() {
        // A store answered: 2xx, and the verdicts only a routed, authenticated
        // request can reach.
        for status in [200, 204, 409, 412, 416] {
            assert!(
                proves_credentials(status, true),
                "{status} from the store proves the credential"
            );
        }
        // A WAF answering an unknown path, or a captive portal serving its own
        // page: same statuses, no S3 origin header, no proof.
        for status in [200, 409] {
            assert!(
                !proves_credentials(status, false),
                "{status} without an origin header proves nothing"
            );
        }
        // Refusals, outages, and a 404 — which S3 answers for a bucket that
        // does not exist without the signature deciding anything — prove
        // nothing however well stamped.
        for status in [401, 403, 404, 429, 500, 503] {
            assert!(
                !proves_credentials(status, true),
                "{status} is no proof of a working credential"
            );
        }
    }

    /// Every refusal shape is read from the status line, so none can be lost
    /// to a body that never arrives — and a `403` counts whether it is a
    /// refused signature or a scoped policy, because the two are not
    /// distinguishable where this judgment is made.
    #[test]
    fn any_400_401_or_403_vetoes_a_promotion() {
        assert!(vetoes_promotion(400), "S3 answers an expired token 400");
        assert!(vetoes_promotion(401), "a 401 is a refusal");
        assert!(
            vetoes_promotion(403),
            "a 403 might be a refused signature; withholding is the safe answer"
        );
        for status in [200, 204, 404, 409, 412, 416, 429, 500, 503] {
            assert!(!vetoes_promotion(status), "{status} is no refusal");
        }
        // Suppression does not narrow this set — see `EVIDENCE_SUPPRESSED` — so
        // there is no second predicate here to keep in step with it. The
        // behaviour under suppression is pinned end to end by
        // `a_refusal_heard_by_check_access_withholds_a_concurrent_promotion`.
    }
}
