// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Async Azure REST client used by `backend.rs`.
//!
//! Owns one async `reqwest::Client` per backend and applies whichever
//! credential the connection resolved to: Shared Key signing, Bearer header
//! from Entra OAuth2, or a SAS token appended to the URL. Requests outside the
//! data path (single-shot `Put Blob`, `Get Blob Properties`, `Set Blob
//! Metadata`, `List Blobs`, `Put Block List`, HNS path operations) flow
//! through here. Stage-block uploads escape this client because they are
//! delegated to the host follower as `WriteRedirect`s; only the commit hop
//! returns to this client.

use std::sync::Arc;
use std::time::Duration;

// Re-exported so the rest of the crate names it through `crate::client`.
pub(crate) use ovstorage_plugin::connection::promotion::OperationEvidence;
use ovstorage_plugin::connection::promotion::{self, EvidenceScope, RefusalEpoch};
use ovstorage_plugin::{ConnectionId, Error, ErrorCode, ErrorContext, Result};
use reqwest::header::{HeaderMap as ReqHeaderMap, HeaderName, HeaderValue};
use reqwest::{Client, Method, RequestBuilder, Response};

use crate::auth::{AuthSource, AzureAuth};
use crate::parse::HeaderMap;
use crate::signing::{
    DEFAULT_SAS_VERSION, SharedKeyRequest, shared_key_authorization_value, shared_key_signature,
    shared_key_string_to_sign,
};

const X_MS_VERSION: &str = "x-ms-version";
const X_MS_DATE: &str = "x-ms-date";

/// Azure error codes (the `x-ms-error-code` response header) that prove the
/// *credentials themselves* were rejected. Azure answers both a bad Shared
/// Key signature and a valid-but-unauthorized principal with HTTP 403, so the
/// status alone cannot distinguish them — the error code can:
/// `AuthenticationFailed` / `InvalidAuthenticationInfo` mean the signature or
/// token was refused; `AuthorizationPermissionMismatch` / RBAC denials mean
/// the caller authenticated but is scoped.
///
/// Scope of the parking guarantee (same as s3): only a
/// **cryptographically/token-rejected** credential parks. A policy-dead yet
/// valid credential (RBAC deny, scoped SAS) PASSES verify, reports
/// `Authenticated`, and fails at the data path — the deliberate
/// lenient-verify trade. A caller-supplied SAS whose `se=` expiry has passed
/// is rejected by the service with `AuthenticationFailed`, so it parks.
const CREDENTIAL_REJECTION_CODES: &[&str] = &["AuthenticationFailed", "InvalidAuthenticationInfo"];

/// Whether a response could only have been produced for a request the service
/// AUTHENTICATED — the evidence `AzureLayer::recover` promotes a parked
/// connection on.
///
/// This is not the negation of [`is_credential_rejection`], and collapsing the
/// two would be wrong in a way that matters. They are duals with opposite
/// biases: `verify` asks whether the credential was REFUTED and is
/// deliberately lenient, so an outage or a throttle leaves a connection
/// usable. This asks whether the credential was PROVEN, and has to be strict
/// for the mirror-image reason — a 503 from a front door, a throttle, or a
/// request malformed enough to be rejected before anything looked at the
/// signature says nothing about the credential, and promoting on one would
/// report `Authenticated` for a connection that has proven nothing.
fn proves_credentials(status: u16, headers: &HeaderMap) -> bool {
    let error_code = headers.first("x-ms-error-code");
    if is_credential_rejection(status, error_code) {
        return false;
    }
    // Origin evidence first. Azure Storage and Azurite stamp `x-ms-request-id`
    // on every response, success and error alike, so an answer without one did
    // not come from the service: an SSO portal or captive proxy returning its
    // own 200, a WAF in front of a private endpoint answering an unknown path
    // with a bare 404, a Front Door default page. Each would otherwise promote
    // a connection whose credential the service never saw, and for a driver
    // with no refresh nothing could undo it.
    //
    // This excludes accidents, not adversaries — anything able to answer for
    // `https://…blob.core.windows.net` is already terminating TLS and can add a
    // header. It is a sanity check on where the answer came from, not proof of
    // origin.
    if headers.first("x-ms-request-id").is_none() {
        tracing::debug!(
            plugin = "azure",
            status,
            "azure: response carries no x-ms-request-id; not counting it as \
             acceptance"
        );
        return false;
    }
    // The status half is `promotion::status_is_routed_verdict`, shared with the
    // gcs and s3 plugins, which is also where the deliberate exclusion of `404`
    // is argued — and with no refresh on this driver, a report built on a 404
    // would never correct itself. There is no 3xx arm in that set: this client
    // follows redirects, so one never surfaces here, and the conditional GETs
    // that could produce a 304 run on the host-performed SAS redirect, which
    // never reaches this judgment. Everything it excludes proves nothing here
    // either — including 403. A 403 is usually an RBAC denial, which does mean
    // the caller was identified first, but not reliably enough to authenticate
    // on: a proxy can strip `x-ms-error-code`, and Azurite reports a FAILED
    // SIGNATURE as `403 AuthorizationFailure`, which is not in the rejection
    // list and would otherwise read as proof. A connection whose every
    // operation is refused simply stays parked, which is the honest answer — we
    // have evidence of refusal, not of authentication.
    promotion::status_is_routed_verdict(status)
}

/// Whether an Entra token failure is the IdP REFUSING the grant.
///
/// One rule, and both consumers want it — `AzureDriver::verify`, which parks a
/// connection on it, and the promotion veto (`AzureAuth::credential_refused`
/// and the connection's refusal epoch), which withholds a promotion on it.
/// That is unusual in this file, where the storage pair
/// ([`is_credential_rejection`] lenient, [`vetoes_promotion`] broad) leans
/// deliberately opposite ways. **The difference is evidence, and it does not
/// generalize back to them.** A storage response carries `x-ms-error-code`,
/// which separates a refused CREDENTIAL from an authorization SCOPE verdict
/// (see [`AUTHORIZATION_SCOPE_CODES`]), so leniency there is informed and the
/// split is worth its cost. A token response carries no field that separates
/// permanent from retryable — see below — so the token path has nothing to be
/// lenient WITH.
///
/// The costs then settle which way the single rule leans, and they point the
/// same way. `ConnectionSet::note_backend_accepted` promotes a parked
/// connection as soon as one of its operations is accepted, and no operation
/// is gated on `auth_state`, so a connection parked in error stays fully usable
/// and clears itself on its next accepted request. (`AuthFailed` is latched
/// rather than healed, but the data path never reaches it: `park` is called
/// only from registration and refresh paths.) A false PASS has no path back at
/// all — `verify` returning `Ok` commits `Authenticated`, and the data path
/// never parks a connection whatever an operation returns, while `refresh` is
/// `Unsupported` and `update_connection_credentials` is refused. So a wrong
/// park costs a reporting window and a wrong pass is permanent.
///
/// **And the code cannot narrow it.** No Entra OAuth error discriminates
/// permanence: `invalid_client` carries `AADSTS700211`, a federated credential
/// that has not replicated yet and that Microsoft documents as retryable, and
/// also an expired workload assertion; `invalid_request` carries `AADSTS70021`,
/// the permanent half of that same condition. The only discriminator is the
/// `AADSTS` number in `error_description`, which is free text this plugin
/// deliberately does not parse or propagate. So the status is what is left, and
/// any refused grant counts whatever code rode along with it.
///
/// A throttle, an outage, or a transport failure is not a refusal in either
/// direction. An unreadable federated token file is.
pub(crate) fn entra_reason_is_grant_refusal(reason: &str) -> bool {
    if reason == "federated_token_file_unreadable" {
        return true;
    }
    let Some(rest) = reason.strip_prefix("entra_status_") else {
        return false;
    };
    let status = match rest.split_once('/') {
        Some((status, _code)) => status,
        None => rest,
    };
    matches!(status, "400" | "401")
}

/// Whether a response should VETO a promotion, and deliberately BROADER than
/// [`is_credential_rejection`] — the two are not interchangeable, and a new
/// call site has to pick between them on the question being asked, not on
/// which name reads better.
///
/// They lean opposite ways on purpose.
/// `verify` asks "was this credential definitively REFUTED?" and is lenient, so
/// an ambiguous refusal does not park a connection that works. This asks "might
/// this credential have been refused?" and is conservative, because its only
/// power is to WITHHOLD a promotion — the cost of a false positive is a
/// connection that stays parked until its next clean operation, and the cost of
/// a false negative is a connection reporting `Authenticated` with a dead
/// credential that nothing can clear.
///
/// So any 401 counts, and any 403 that is not an affirmative
/// authorization-SCOPE verdict counts: Azurite reports a failed signature as
/// `403 AuthorizationFailure`, and a proxy can strip `x-ms-error-code`
/// entirely, neither of which is in the rejection list `verify` uses.
fn vetoes_promotion(status: u16, error_code: Option<&str>) -> bool {
    if is_credential_rejection(status, error_code) {
        return true;
    }
    match status {
        401 => true,
        // An absent or unrecognized code is no scope verdict, so it vetoes.
        403 => !is_authorization_scope_verdict(error_code),
        _ => false,
    }
}

/// Whether a 403's `x-ms-error-code` says the caller WAS identified and then
/// found to be scoped.
fn is_authorization_scope_verdict(error_code: Option<&str>) -> bool {
    error_code.is_some_and(|code| {
        AUTHORIZATION_SCOPE_CODES
            .iter()
            .any(|scope| code.eq_ignore_ascii_case(scope))
    })
}

/// Azure error codes that mean the caller WAS identified and then found to be
/// scoped — authorization, not authentication. Only these keep a 403 from
/// vetoing a promotion.
const AUTHORIZATION_SCOPE_CODES: &[&str] = &[
    "AuthorizationPermissionMismatch",
    "AuthorizationResourceTypeMismatch",
    "AuthorizationServiceMismatch",
    "AuthorizationSourceIPMismatch",
    "AuthorizationProtocolMismatch",
    "InsufficientAccountPermissions",
];

/// Whether a response is the service refusing the CREDENTIAL itself, rather
/// than answering a request signed with it.
///
/// One function because there is one judgment, and every consumer that needs
/// "was this credential itself refused?" asks it here. Kept as one function
/// rather than several matching ones because the failure of a second copy is
/// silent — a copy that gates the code check on 403 while another applies it to
/// any status lets a `400 InvalidAuthenticationInfo` read as acceptance and
/// promote a connection whose credential has just been refused.
///
/// The status is not the discriminator: Azure answers both a bad Shared Key
/// signature and a valid-but-unauthorized principal with 403, so the
/// `x-ms-error-code` decides, whatever status carries it. A bare 401 is a
/// refusal on its own.
pub(crate) fn is_credential_rejection(status: u16, error_code: Option<&str>) -> bool {
    status == 401
        || error_code.is_some_and(|code| {
            CREDENTIAL_REJECTION_CODES
                .iter()
                .any(|rejection| code.eq_ignore_ascii_case(rejection))
        })
}

pub(crate) struct AzureRequest<'a> {
    pub method: Method,
    pub url: String,
    pub canonical_path: &'a str,
    pub canonical_query: Vec<(String, String)>,
    pub extra_headers: Vec<(String, String)>,
    pub content_type: Option<String>,
    pub content_md5: Option<String>,
    pub if_match: Option<String>,
    pub if_none_match: Option<String>,
    pub range: Option<String>,
    pub body: Option<Vec<u8>>,
}

pub(crate) struct AzureResponse {
    pub status: u16,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

impl AzureResponse {
    pub fn ok(&self) -> bool {
        self.status >= 200 && self.status < 300
    }

    pub fn body_str(&self) -> Result<&str> {
        std::str::from_utf8(&self.body).map_err(|e| {
            Error::new(
                ErrorCode::Internal,
                format!("Azure response body is not valid UTF-8: {e}"),
            )
        })
    }
}

#[derive(Clone)]
pub(crate) struct AzureClient {
    http: Client,
    auth: Arc<AzureAuth>,
    account: String,
    /// Bumped when the service refuses this connection's credential on a
    /// request this process made. Shared across clones, because a clone — the
    /// change-feed client — signs with the same credential.
    ///
    /// A refusal answered to a REDIRECT the host followed is not counted, and
    /// cannot be: on `read` the follower never reports back, and on `write` the
    /// reported status is caller-supplied, which under the broker means a
    /// remote client could type it. Honouring that would let anyone with write
    /// access hold an operator's shared connection in `AwaitingAuth` at will —
    /// the same reason a reported 2xx is not counted as acceptance. So a
    /// redirect-only operation contributes no evidence in either direction.
    ///
    /// The two halves of the evidence are deliberately scoped differently.
    /// **Acceptance is per-operation**: only a request an operation made itself
    /// may vindicate it, or a caller whose work never reached the service is
    /// promoted by a neighbour's traffic. **Refusal is per-connection**: the
    /// credential is one object, so a refusal answered to anyone condemns it
    /// for everyone, and an operation that merely avoided hearing the bad news
    /// must not be promoted on the strength of that.
    ///
    /// Being an epoch rather than a tally, it also catches refusals belonging to
    /// no operation at all — a change-feed poll's — which a per-operation sink
    /// discards by construction.
    refusal_epoch: RefusalEpoch,
}

/// Which refusal shapes on this request may veto a connection promotion.
///
/// Only [`AzureClient::send_advisory`] passes `CredentialOnly`, and only for a
/// request whose failure the caller ignores.
#[derive(Clone, Copy, PartialEq, Eq)]
enum RefusalScope {
    /// Every shape [`vetoes_promotion`] recognises. This is what an ordinary
    /// request gets, and it is the safe default: the caller read the answer.
    Any,
    /// Only the narrow [`is_credential_rejection`] rule — a `401`, or a `403`
    /// carrying `AuthenticationFailed` or `InvalidAuthenticationInfo`, which
    /// together mean the service verified the signature and rejected it. The
    /// shapes dropped relative to `Any` are a `403 AuthorizationFailure` and a
    /// `403` whose code was stripped, which is what a firewall or an
    /// unpublished private endpoint answers.
    ///
    /// (`is_credential_rejection` is a strict subset of `vetoes_promotion` —
    /// the latter opens by delegating to it — so this arm can only ever veto
    /// less, never differently.)
    CredentialOnly,
}

/// Whether this request reached its answer without being redirected at all.
///
/// Azure needs the stricter question its gcs sibling does not, because two of
/// its three credential shapes are bound to the URL rather than carried in a
/// path-independent header: `AuthSource::SharedKey` signs an HMAC over the
/// canonical path and query, and `AuthSource::Sas` puts the credential IN the
/// query string. A hop of ANY kind therefore invalidates the credential — a
/// same-origin path rewrite re-sends a `SharedKey` signature that does not cover
/// the resource it landed on, and a cross-origin hop drops the header outright.
/// (A SAS survives a cross-origin hop verbatim, being in the query rather than a
/// header, which is another way of saying the header is not what decides this.)
///
/// It is recorded per hop rather than inferred from the final URL, and that is
/// the whole point: a chain that leaves and comes back ENDS on the URL we
/// signed while having been answered to a request that carried nothing.
fn note_redirected() {
    let _ = REDIRECTED.try_with(|redirected| redirected.set(true));
}

/// Run `future` watching for any redirect; returns the outcome alongside
/// whether the request reached its answer unredirected.
async fn watching_redirects<T>(future: impl std::future::Future<Output = T>) -> (T, bool) {
    let redirected = std::cell::Cell::new(false);
    REDIRECTED
        .scope(redirected, async move {
            let outcome = future.await;
            let unredirected = !REDIRECTED.with(|redirected| redirected.get());
            (outcome, unredirected)
        })
        .await
}

tokio::task_local! {
    /// Set by the redirect policy on every hop it follows.
    static REDIRECTED: std::cell::Cell<bool>;

    /// The evidence sink belonging to the operation running on this task.
    ///
    /// Installed by `AzureLayer`'s witness around the operation future and read
    /// by [`AzureClient::send`]. Absent for work that belongs to no operation —
    /// the change-feed producer task, the background token refresh — and a
    /// verdict recorded nowhere can vindicate nothing, which is the safe way
    /// round.
    static OPERATION_EVIDENCE: Arc<OperationEvidence>;
}

/// This plugin's acceptance sink, naming [`OPERATION_EVIDENCE`] for the shared
/// [`promotion`] machinery.
///
/// The sink is scoped this tightly because a connection is one `AzureClient`
/// shared by every operation running against it, and under the broker those are
/// unrelated remote callers. A connection-wide tally would let a caller whose
/// own operation never reached the service — a flat-namespace `read` that only
/// mints a redirect — be vindicated by a neighbour's request. A wrong promotion
/// is unrecoverable: Azure has no `refresh`, and `update_connection_credentials`
/// is refused because credentials are frozen.
///
/// Refusal is not recorded in the sink at all. It belongs to the connection —
/// see [`AzureClient::refusal_epoch`] — because the credential is one object
/// and a refusal answered to anyone condemns it for everyone.
pub(crate) struct AzureEvidence;

impl EvidenceScope for AzureEvidence {
    fn sink() -> &'static tokio::task::LocalKey<Arc<OperationEvidence>> {
        &OPERATION_EVIDENCE
    }
}

/// Run `future` with `evidence` installed as the operation's acceptance sink.
pub(crate) async fn with_operation_evidence<T>(
    evidence: Arc<OperationEvidence>,
    future: impl std::future::Future<Output = T>,
) -> T {
    promotion::with_operation_evidence::<AzureEvidence, _>(evidence, future).await
}

/// Credit an acceptance to the operation running on this task, if any.
///
/// Work that belongs to no operation — the change-feed producer task, the
/// background token refresh — credits nothing, and an acceptance recorded
/// nowhere vindicates nobody. Refusals are not routed through here at all:
/// they go to the connection-wide epoch, so the ones this task-local would
/// have dropped still veto.
fn credit_operation_acceptance() {
    promotion::credit_operation_acceptance::<AzureEvidence>();
}

impl AzureClient {
    pub fn new(account: String, auth: AzureAuth) -> Result<Self> {
        let http = Client::builder()
            .timeout(Duration::from_secs(60))
            // Redirects are followed exactly as before; the policy only
            // OBSERVES them, recording that a hop happened so the promotion
            // rule declines to judge an answer the credential did not reach.
            // The limit matches `Policy::limited(10)`, the default this
            // replaces: ten hops followed, and the eleventh fails rather than
            // handing the caller an unfollowed `3xx`.
            .redirect(reqwest::redirect::Policy::custom(|attempt| {
                note_redirected();
                if attempt.previous().len() > 10 {
                    attempt.error("too many redirects")
                } else {
                    attempt.follow()
                }
            }))
            .build()
            .map_err(|e| {
                Error::new(
                    ErrorCode::Internal,
                    format!("failed to build Azure HTTP client: {e}"),
                )
            })?;
        let auth = Arc::new(auth);
        let refusal_epoch = RefusalEpoch::default();
        // Proactively refresh OAuth bearers at ~90% of TTL so
        // long-lived processes don't hit `Unauthenticated` mid-RPC.
        // No-op for SharedKey/SAS/Anonymous sources (nothing to
        // refresh). The task holds only `Weak<AzureAuth>` and aborts
        // on `Drop` of the last `Arc`.
        auth.install_background_refresh(AzureAuth::DEFAULT_REFRESH_INTERVAL);
        Ok(Self {
            http,
            auth,
            account,
            refusal_epoch,
        })
    }

    pub fn auth(&self) -> &AzureAuth {
        &self.auth
    }

    /// The connection's refusal epoch. A witness snapshots it and requires it
    /// unchanged: any refusal that lands while an operation runs vetoes that
    /// operation's promotion, whichever operation — or none — provoked it.
    pub fn refusal_epoch(&self) -> u64 {
        self.refusal_epoch.get()
    }

    fn note_refusal(&self) {
        self.refusal_epoch.bump();
    }

    /// Whether the IdP has refused a grant for this connection's credential
    /// and has not since issued one. See `AzureAuth::credential_refused`.
    pub fn credential_refused(&self) -> bool {
        self.auth.credential_refused()
    }

    /// Acquire an Entra bearer token, advancing the connection's refusal epoch
    /// when the IdP refuses the grant.
    ///
    /// **Every data-path bearer acquisition goes through here**, including the
    /// ones that mint a token for a redirect handout rather than for a request
    /// this client sends. The IdP refuses before any storage response exists,
    /// so a refusal it returns is the only trace of that refusal anywhere: an
    /// operation whose earlier request was accepted — an HNS `read`'s kind
    /// preflight, say — and whose token then fails because the client secret
    /// was rotated would otherwise look like an operation with an acceptance
    /// and no refusal, and promote a connection whose credential had just
    /// died. Routing the acquisition through one place is what stops the next
    /// call site from having to know that.
    pub async fn bearer_token(&self) -> Result<String> {
        match self.auth.bearer_token(&self.http).await {
            Ok(bearer) => Ok(bearer),
            Err(error) => {
                let reason = match error.context() {
                    Some(ErrorContext::Auth { reason, .. }) => reason.as_deref().unwrap_or(""),
                    _ => "",
                };
                if entra_reason_is_grant_refusal(reason) {
                    self.note_refusal();
                }
                Err(error)
            }
        }
    }

    #[allow(dead_code)]
    pub fn account(&self) -> &str {
        &self.account
    }

    /// Send a request, signing it with whichever auth the connection resolved to.
    ///
    /// A refusal here is evidence, in every shape [`vetoes_promotion`]
    /// recognises: this caller read the answer, so a refusal it got is a
    /// refusal that mattered. (The caller need not be an operation — the
    /// change-feed poller uses this too, and its refusals are exactly the ones
    /// a per-operation sink would drop.)
    pub async fn send(&self, req: AzureRequest<'_>) -> Result<AzureResponse> {
        self.send_with(req, RefusalScope::Any).await
    }

    /// Send an ADVISORY request — one whose failure changes nothing the caller
    /// does — and do not let its refusal veto a promotion.
    ///
    /// The distinction is not about the request, it is about the caller. A
    /// caller that proceeds identically whether the request succeeded or failed
    /// has, by construction, not depended on the answer; letting that answer
    /// condemn the connection's credential makes a request nobody needed into a
    /// verdict everybody pays for. The refusal epoch is connection-wide, so the
    /// cost lands on concurrent operations that never issued the probe.
    ///
    /// It matters most where an advisory probe reaches a DIFFERENT endpoint
    /// from the work: the HNS kind preflight signs against the `dfs` host while
    /// `read` hands back a `blob` URL, and Azure provisions private endpoints
    /// per sub-resource, so an account reachable on `blob` alone answers the
    /// public `dfs` host with `403 AuthorizationFailure`. That is a statement
    /// about which endpoints are published, not about the credential.
    ///
    /// **Only the AMBIGUOUS refusals are dropped.** A `401`, or a `403`
    /// carrying `AuthenticationFailed` or `InvalidAuthenticationInfo`, says the
    /// service verified the signature and rejected it — that is host-independent
    /// and still vetoes, because the alternative is losing the very guarantee
    /// the connection-wide epoch exists for: a credential that dies between a
    /// neighbour's acceptance and its promotion, seen by nobody but this probe.
    /// What is dropped is the wider net `vetoes_promotion` casts — a
    /// `403 AuthorizationFailure`, or a `403` whose code a proxy stripped —
    /// which is what an unpublished endpoint answers.
    ///
    /// **Acceptance is still credited.** A service that answers a signed
    /// request authenticated it, whichever host it was, and that is the same
    /// proof any other accepted request carries.
    ///
    /// **Only this caller is advisory.** `stat`'s hierarchical branch and
    /// `list` on a hierarchical namespace also reach the `dfs` host, and they
    /// keep the broad net deliberately: they read the answer, so a refusal they
    /// get is an operation that genuinely failed, and the pessimistic rule is
    /// the right one for a caller that depended on it.
    ///
    /// Three residuals, recorded rather than solved. An intermediary that strips
    /// `x-ms-error-code` turns a real `AuthenticationFailed` into a bare 403,
    /// which this drops — the same margin [`vetoes_promotion`] spends its
    /// breadth on, and the trade is that starvation is certain while this needs
    /// a header-stripping proxy AND a rotation in the same window. And Azurite
    /// reports a failed signature as `403 AuthorizationFailure`; production
    /// Azure answers that with `AuthenticationFailed` and reserves
    /// `AuthorizationFailure` for a firewall or network-rule denial, and
    /// Azurite exposes no `dfs` endpoint for this probe to reach at all outside
    /// a test override. And the probe's own caller bounds it well inside this
    /// client's timeout, so a refusal whose headers land after that deadline is
    /// one this probe gives up on rather than witnesses.
    ///
    /// All three are the same trade. This probe is one witness among a
    /// connection's traffic, not the guarantee itself: a service that refuses a
    /// credential refuses the operations that depend on it too, and those go
    /// through [`AzureClient::send`], where the broad net still catches them.
    pub async fn send_advisory(&self, req: AzureRequest<'_>) -> Result<AzureResponse> {
        self.send_with(req, RefusalScope::CredentialOnly).await
    }

    async fn send_with(
        &self,
        req: AzureRequest<'_>,
        refusal: RefusalScope,
    ) -> Result<AzureResponse> {
        let date = httpdate::fmt_http_date(std::time::SystemTime::now());
        let mut headers: Vec<(String, String)> = Vec::new();
        headers.push((X_MS_VERSION.into(), DEFAULT_SAS_VERSION.into()));
        headers.push((X_MS_DATE.into(), date));
        for (name, value) in &req.extra_headers {
            headers.push((name.clone(), value.clone()));
        }

        let body_len = req.body.as_ref().map(|b| b.len() as u64).unwrap_or(0);
        let mut url = req.url.clone();

        match self.auth.source() {
            AuthSource::Sas { sas_token } => {
                let separator = if url.contains('?') { '&' } else { '?' };
                url.push(separator);
                url.push_str(sas_token);
            }
            AuthSource::SharedKey { account_key_bytes } => {
                let signing_request = SharedKeyRequest {
                    method: req.method.as_str(),
                    account: &self.account,
                    canonical_path: req.canonical_path,
                    canonical_query: &req.canonical_query,
                    headers: &headers,
                    content_length: if body_len == 0 { None } else { Some(body_len) },
                    content_type: req.content_type.as_deref(),
                    content_md5: req.content_md5.as_deref(),
                    if_match: req.if_match.as_deref(),
                    if_none_match: req.if_none_match.as_deref(),
                    range: req.range.as_deref(),
                };
                let canonical = shared_key_string_to_sign(&signing_request);
                let signature = shared_key_signature(account_key_bytes, &canonical)?;
                let auth_value = shared_key_authorization_value(&self.account, &signature);
                headers.push(("Authorization".into(), auth_value));
            }
            AuthSource::Oauth2ClientSecret { .. } | AuthSource::Oauth2Federated { .. } => {
                let bearer = self.bearer_token().await?;
                headers.push(("Authorization".into(), format!("Bearer {bearer}")));
            }
            AuthSource::Anonymous => {}
        }

        let mut builder: RequestBuilder = self.http.request(req.method.clone(), &url);
        if let Some(content_type) = req.content_type.as_deref() {
            builder = builder.header("Content-Type", content_type);
        }
        if let Some(content_md5) = req.content_md5.as_deref() {
            builder = builder.header("Content-MD5", content_md5);
        }
        if let Some(if_match) = req.if_match.as_deref() {
            // Azure requires RFC 7232 entity-tag quoting on conditional
            // headers; the SPI documents `if_match` as the raw etag
            // value the backend handed back. `quote_etag` is a no-op
            // if the caller already supplied the quoted form.
            builder = builder.header("If-Match", crate::backend::quote_etag(if_match));
        }
        if let Some(if_none_match) = req.if_none_match.as_deref() {
            // `If-None-Match: *` is the only wildcard the no-overwrite
            // path uses; everything else is an entity-tag that must
            // round-trip through `quote_etag`.
            let value = if if_none_match == "*" {
                if_none_match.to_string()
            } else {
                crate::backend::quote_etag(if_none_match)
            };
            builder = builder.header("If-None-Match", value);
        }
        if let Some(range) = req.range.as_deref() {
            builder = builder.header("Range", range);
        }
        builder = builder.headers(to_reqwest_headers(&headers)?);
        if let Some(body) = req.body {
            builder = builder.body(body);
        }
        // The evidence below is withheld for ANY redirect — see [`note_redirected`]
        // for why azure is stricter than the gcs sibling, and why the hop is
        // observed as it happens rather than inferred from the final URL.
        //
        // Built rather than sent through the builder so the watch can wrap the
        // execution; `RequestBuilder::send` is `client.execute(self.build()?)`,
        // so nothing else changes.
        let request = builder.build().map_err(|e| {
            Error::new(
                ErrorCode::Internal,
                format!("Azure request could not be built for {}: {e}", req.url),
            )
        })?;
        let (outcome, unredirected) = watching_redirects(self.http.execute(request)).await;
        let response: Response = outcome.map_err(|e| {
            Error::new(
                ErrorCode::Transient,
                format!("Azure request failed for {}: {e}", req.url),
            )
        })?;
        let status = response.status().as_u16();
        let mut header_map = HeaderMap::new();
        for (name, value) in response.headers() {
            if let Ok(value_str) = value.to_str() {
                header_map.insert(name.as_str(), value_str);
            }
        }
        // Record the verdict from the status and headers, BEFORE draining the
        // body. The service has already delivered its answer at this point, and
        // a body that fails mid-stream — a reset connection, a proxy closing
        // early — must not discard it. Losing a REFUSAL here is the dangerous
        // half: a multi-request operation whose first request was accepted and
        // whose second was refused with a truncated body would look like an
        // operation with an acceptance and no refusal, and promote a connection
        // whose credential had just died.
        //
        // One judgment, two scopes: a refusal condemns the credential for the
        // whole connection, while an acceptance vindicates only the operation
        // that earned it.
        let error_code = header_map.first("x-ms-error-code");
        // Each arm names its own rule outright. Writing this as
        // `vetoes_promotion(..) && is_credential_rejection(..)` would mean the
        // same thing only while the second stays a subset of the first, and
        // nothing here would notice if that stopped being true.
        let refused = match refusal {
            RefusalScope::Any => vetoes_promotion(status, error_code),
            RefusalScope::CredentialOnly => is_credential_rejection(status, error_code),
        };
        if !unredirected {
            tracing::debug!(
                plugin = "azure",
                status,
                "azure: response was redirected away from the signed URL; \
                 recording no evidence in either direction"
            );
        } else if refused {
            self.note_refusal();
        } else if proves_credentials(status, &header_map) {
            credit_operation_acceptance();
        }
        let body = response.bytes().await.map_err(|e| {
            Error::new(
                ErrorCode::Transient,
                format!("Azure response body read failed: {e}"),
            )
        })?;
        Ok(AzureResponse {
            status,
            headers: header_map,
            body: body.to_vec(),
        })
    }
}

fn to_reqwest_headers(headers: &[(String, String)]) -> Result<ReqHeaderMap> {
    let mut map = ReqHeaderMap::new();
    for (name, value) in headers {
        let header_name = HeaderName::from_bytes(name.as_bytes()).map_err(|e| {
            Error::new(
                ErrorCode::Internal,
                format!("invalid header name '{name}': {e}"),
            )
        })?;
        let header_value = HeaderValue::from_str(value).map_err(|e| {
            Error::new(
                ErrorCode::Internal,
                format!("invalid header value for '{name}': {e}"),
            )
        })?;
        map.append(header_name, header_value);
    }
    Ok(map)
}

/// Translate a non-2xx Azure response into the typed error code best matching the HTTP status.
///
/// 401 → `AuthRequired`, the code the connection lifecycle treats as an auth failure rather
/// than a data error. `default_classify` reads it as `NeedsInteractive`, so the host routes the
/// caller to re-auth rather than silently retrying. 403 → `PermissionDenied` (final): the
/// principal is authenticated but the RBAC role on the container/blob lacks the operation.
///
/// The provider response body is dropped by design: an `AuthenticationFailed` body echoes the
/// request MAC and the canonical string-to-sign, so only the allowlisted provider error code
/// from [`crate::error_body::provider_detail`] and the `x-ms-request-id` correlation GUID reach
/// the message. The headers go in alongside the body because `stat` issues a HEAD, whose
/// response has no body at all — there the `x-ms-error-code` header is the only place the
/// provider code exists.
pub(crate) fn map_status_to_error(response: &AzureResponse, operation: &str) -> Error {
    let status = response.status;
    let detail = crate::error_body::provider_detail(&response.body, &response.headers);
    let request = crate::error_body::request_id(&response.headers)
        .map(|id| format!("; request_id={id}"))
        .unwrap_or_default();
    if status == 401 {
        return Error::new(
            ErrorCode::AuthRequired,
            format!("Azure {operation} requires authentication (HTTP 401; {detail}{request})"),
        )
        .with_context(ErrorContext::Auth {
            connection_id: ConnectionId(String::new()),
            reason: Some("azure_unauthorized".into()),
            expired_at: None,
        });
    }
    let code = match status {
        403 => ErrorCode::PermissionDenied,
        404 | 410 => ErrorCode::NotFound,
        409 => ErrorCode::AlreadyExists,
        412 => ErrorCode::PreconditionFailed,
        416 => ErrorCode::InvalidArgument,
        // match-arm order matters: 408/504 + 429/503 must precede the 500..=599 catchall.
        408 | 504 => ErrorCode::DeadlineExceeded,
        429 | 503 => ErrorCode::ResourceExhausted,
        500..=599 => ErrorCode::Transient,
        _ => ErrorCode::Transient,
    };
    Error::new(
        code,
        format!("Azure {operation} returned HTTP {status} ({detail}{request})"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What azure answers a `SharedKey` signature that does not cover the
    /// resource the request landed on.
    const REWRITTEN_REFUSAL: &str = "HTTP/1.1 403 Forbidden\r\n\
         x-ms-error-code: AuthenticationFailed\r\n\
         x-ms-request-id: req-1\r\ncontent-length: 0\r\nconnection: close\r\n\r\n";

    fn response_with_status(status: u16, body: &[u8]) -> AzureResponse {
        AzureResponse {
            status,
            headers: HeaderMap::default(),
            body: body.to_vec(),
        }
    }

    /// Shape of a real Shared Key 401: the `<AuthenticationErrorDetail>`
    /// element echoes the request MAC and the whole canonical string-to-sign.
    const SIGNATURE_MAC: &str = "8fN2q1vZk3pQ0rT7yXbL5cJmA9sWdE4uH6gK1nR8oI=";
    fn authentication_failed_body() -> Vec<u8> {
        format!(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
             <Error><Code>AuthenticationFailed</Code>\
             <Message>Server failed to authenticate the request. Make sure the value of \
             Authorization header is formed correctly including the signature.</Message>\
             <AuthenticationErrorDetail>The MAC signature found in the HTTP request \
             '{SIGNATURE_MAC}' is not the same as any computed signature. Server used \
             following string to sign: 'GET\n\n\n\n\n\n\n\n\n\n\n\n\
             x-ms-date:Mon, 01 Jun 2026 00:00:00 GMT\nx-ms-version:2023-11-03\n\
             /acct123/assets/secret.bin'. SharedKey acct123:{SIGNATURE_MAC}\
             </AuthenticationErrorDetail></Error>"
        )
        .into_bytes()
    }

    /// The reported defect: a 401 body carries credential-derived material, so
    /// nothing but the allowlisted `<Code>` token may reach `message()`.
    #[test]
    fn map_status_to_error_401_suppresses_signature_bearing_body() {
        let response = response_with_status(401, &authentication_failed_body());
        let err = map_status_to_error(&response, "GetBlob");
        let message = err.message();
        assert_eq!(err.code(), ErrorCode::AuthRequired);
        assert!(
            message.contains("AuthenticationFailed"),
            "provider code should survive: {message}"
        );
        assert!(!message.contains(SIGNATURE_MAC), "MAC leaked: {message}");
        assert!(!message.contains("string to sign"), "S2S leaked: {message}");
        assert!(!message.contains("StringToSign"), "S2S leaked: {message}");
        assert!(
            !message.contains("SharedKey acct123:"),
            "Authorization literal leaked: {message}"
        );
        assert!(
            !message.contains("x-ms-date"),
            "canonical headers leaked: {message}"
        );
    }

    /// The same suppression applies on the generic (non-401) arm.
    #[test]
    fn map_status_to_error_generic_arm_suppresses_body() {
        let response = response_with_status(403, &authentication_failed_body());
        let err = map_status_to_error(&response, "PutBlob");
        let message = err.message();
        assert_eq!(err.code(), ErrorCode::PermissionDenied);
        assert!(message.contains("Azure PutBlob returned HTTP 403"));
        assert!(message.contains("code=AuthenticationFailed"));
        assert!(!message.contains(SIGNATURE_MAC), "MAC leaked: {message}");
    }

    /// Byte 512 of this body lands inside a multi-byte UTF-8 sequence. The
    /// sanitizer bounds its scan by byte but never slices a `&str`, so a
    /// mid-sequence boundary is not a panic site.
    #[test]
    fn map_status_to_error_does_not_panic_on_multi_byte_boundary() {
        // 'é' is two bytes; a leading odd-length ASCII run puts the 512th byte
        // in the middle of one of them. '🔒' is four bytes, straddling it too.
        let mut body = String::from("x");
        body.push_str(&"é".repeat(400));
        body.push_str(&"🔒".repeat(64));
        assert!(body.len() > 512);
        assert!(!body.is_char_boundary(512));
        let response = response_with_status(500, body.as_bytes());
        let err = map_status_to_error(&response, "GetBlob");
        assert_eq!(err.code(), ErrorCode::Transient);
        assert!(err.message().contains("no provider error code"));
        assert!(!err.message().contains('é'));
    }

    /// Invalid UTF-8 is likewise summarized, never quoted.
    #[test]
    fn map_status_to_error_handles_non_utf8_body() {
        let response = response_with_status(500, &[0xff, 0xfe, 0x00, 0x80]);
        let err = map_status_to_error(&response, "GetBlob");
        assert_eq!(err.code(), ErrorCode::Transient);
        assert!(
            err.message()
                .contains("no provider error code; 4 byte body suppressed")
        );
    }

    /// `x-ms-request-id` is server-generated, not credential-derived: it is the
    /// correlation handle that replaces the body for operators.
    #[test]
    fn map_status_to_error_surfaces_request_id_header() {
        let response = AzureResponse {
            status: 404,
            headers: HeaderMap::from_pairs([
                ("x-ms-request-id", "1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed"),
                ("x-ms-version", "2023-11-03"),
            ]),
            body: b"<Error><Code>BlobNotFound</Code></Error>".to_vec(),
        };
        let err = map_status_to_error(&response, "GetBlob");
        assert_eq!(err.code(), ErrorCode::NotFound);
        assert_eq!(
            err.message(),
            "Azure GetBlob returned HTTP 404 (code=BlobNotFound; \
             request_id=1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed)"
        );
    }

    /// With no correlation header the message carries the detail alone — no
    /// dangling separator.
    #[test]
    fn map_status_to_error_omits_request_id_when_absent() {
        let response = response_with_status(409, b"<Error><Code>BlobAlreadyExists</Code></Error>");
        let err = map_status_to_error(&response, "PutBlob");
        assert_eq!(err.code(), ErrorCode::AlreadyExists);
        assert_eq!(
            err.message(),
            "Azure PutBlob returned HTTP 409 (code=BlobAlreadyExists)"
        );
    }

    #[test]
    fn map_status_to_error_401_is_auth_required_with_context() {
        let response = response_with_status(401, b"<Error>InvalidAuthenticationInfo</Error>");
        let err = map_status_to_error(&response, "GetBlob");
        assert_eq!(err.code(), ErrorCode::AuthRequired);
        match err.context() {
            Some(ErrorContext::Auth {
                reason, expired_at, ..
            }) => {
                assert_eq!(reason.as_deref(), Some("azure_unauthorized"));
                assert!(expired_at.is_none());
            }
            other => panic!("expected Auth context, got {other:?}"),
        }
    }

    #[test]
    fn map_status_to_error_403_is_permission_denied_no_context() {
        let response = response_with_status(403, b"<Error>AuthorizationFailure</Error>");
        let err = map_status_to_error(&response, "GetBlob");
        assert_eq!(err.code(), ErrorCode::PermissionDenied);
        assert!(err.context().is_none());
    }

    #[test]
    fn map_status_to_error_404_410_are_not_found() {
        let r404 = response_with_status(404, b"<Error>BlobNotFound</Error>");
        assert_eq!(
            map_status_to_error(&r404, "GetBlob").code(),
            ErrorCode::NotFound
        );
        let r410 = response_with_status(410, b"");
        assert_eq!(
            map_status_to_error(&r410, "GetBlob").code(),
            ErrorCode::NotFound
        );
    }

    #[test]
    fn map_status_to_error_412_is_precondition_failed() {
        let r = response_with_status(412, b"<Error>ConditionNotMet</Error>");
        assert_eq!(
            map_status_to_error(&r, "GetBlob").code(),
            ErrorCode::PreconditionFailed
        );
    }

    #[test]
    fn map_status_to_error_416_is_invalid_argument() {
        let r = response_with_status(416, b"<Error>InvalidRange</Error>");
        assert_eq!(
            map_status_to_error(&r, "GetBlob").code(),
            ErrorCode::InvalidArgument
        );
    }

    #[test]
    fn map_status_to_error_408_504_are_deadline_exceeded() {
        let r408 = response_with_status(408, b"");
        assert_eq!(
            map_status_to_error(&r408, "GetBlob").code(),
            ErrorCode::DeadlineExceeded
        );
        let r504 = response_with_status(504, b"");
        assert_eq!(
            map_status_to_error(&r504, "GetBlob").code(),
            ErrorCode::DeadlineExceeded
        );
    }

    #[test]
    fn map_status_to_error_429_503_are_resource_exhausted() {
        let r429 = response_with_status(429, b"<Error>ServerBusy</Error>");
        assert_eq!(
            map_status_to_error(&r429, "GetBlob").code(),
            ErrorCode::ResourceExhausted
        );
        let r503 = response_with_status(503, b"<Error>ServerBusy</Error>");
        assert_eq!(
            map_status_to_error(&r503, "GetBlob").code(),
            ErrorCode::ResourceExhausted
        );
    }

    #[test]
    fn map_status_to_error_500_502_are_transient() {
        let r500 = response_with_status(500, b"");
        assert_eq!(
            map_status_to_error(&r500, "GetBlob").code(),
            ErrorCode::Transient
        );
        let r502 = response_with_status(502, b"");
        assert_eq!(
            map_status_to_error(&r502, "GetBlob").code(),
            ErrorCode::Transient
        );
    }

    /// Unknown 5xx surfaces as Transient (library will retry).
    #[test]
    fn map_status_to_error_unknown_5xx_is_transient() {
        let r = response_with_status(599, b"");
        assert_eq!(
            map_status_to_error(&r, "GetBlob").code(),
            ErrorCode::Transient
        );
    }

    /// Unknown non-5xx still surfaces as Transient (proxy/gateway weirdness),
    /// never Internal — Internal is reserved for plugin-detected logic bugs.
    #[test]
    fn map_status_to_error_unknown_non_5xx_is_transient() {
        let r = response_with_status(418, b"");
        assert_eq!(
            map_status_to_error(&r, "GetBlob").code(),
            ErrorCode::Transient
        );
    }

    /// The credential-rejection judgment is status-INDEPENDENT except for a
    /// bare 401: Azure answers a refused signature with 403, but a gateway or
    /// the emulator can carry the same `x-ms-error-code` on another status, and
    /// counting that as acceptance would promote a connection whose credential
    /// had just been refused.
    #[test]
    fn credential_rejection_follows_the_error_code_whatever_the_status() {
        for status in [400, 403, 409, 500] {
            assert!(
                is_credential_rejection(status, Some("AuthenticationFailed")),
                "{status} AuthenticationFailed is a refusal"
            );
            assert!(is_credential_rejection(
                status,
                Some("InvalidAuthenticationInfo")
            ));
        }
        assert!(
            is_credential_rejection(401, None),
            "a bare 401 is a refusal"
        );
        // An accepted credential that is merely scoped, and a plain success.
        assert!(!is_credential_rejection(
            403,
            Some("AuthorizationPermissionMismatch")
        ));
        assert!(!is_credential_rejection(403, None));
        assert!(!is_credential_rejection(200, None));
        assert!(!is_credential_rejection(404, Some("BlobNotFound")));
    }

    /// A response carrying `x-ms-request-id` — every Azure Storage and Azurite
    /// response does — with a status only an authenticated request can be
    /// answered with.
    fn azure(status: u16, extra: &[(&str, &str)]) -> bool {
        let mut headers = HeaderMap::new();
        headers.insert("x-ms-request-id", "5e4d6c0e-201e-0042-3a1f-1f0b7c000000");
        for (name, value) in extra {
            headers.insert(name, value);
        }
        proves_credentials(status, &headers)
    }

    /// Acceptance is an allowlist, not "everything that is not a rejection".
    /// A throttle or an outage is not evidence about a credential, and
    /// promoting on one would authenticate a connection that proved nothing.
    #[test]
    fn only_authenticated_answers_prove_credentials() {
        for status in [200, 201, 204, 206, 409, 412, 416] {
            assert!(azure(status, &[]), "{status} is an answer");
        }
        assert!(
            !azure(404, &[]),
            "a 404 is answered for a missing container without the credential \
             deciding anything, so it proves nothing"
        );
        assert!(
            !azure(
                403,
                &[("x-ms-error-code", "AuthorizationPermissionMismatch")]
            ),
            "a 403 is not proof: the same status carries failed-signature shapes"
        );
        assert!(!azure(403, &[]), "a 403 stripped of its code is not proof");
        assert!(
            !azure(403, &[("x-ms-error-code", "AuthorizationFailure")]),
            "Azurite reports a failed signature this way"
        );
        for status in [400, 405, 411, 413, 429, 500, 503, 504] {
            assert!(
                !azure(status, &[]),
                "{status} can be raised without authenticating"
            );
        }
        for status in [400, 401, 403] {
            assert!(
                !azure(status, &[("x-ms-error-code", "AuthenticationFailed")]),
                "{status} AuthenticationFailed is a refusal"
            );
        }
        // No 3xx is an answer about a credential.
        for status in [300, 302, 304, 305, 307] {
            assert!(!azure(status, &[]), "{status} is not an answer");
        }
    }

    /// A chain that leaves the origin and COMES BACK records no evidence.
    ///
    /// This is the case a final-URL comparison cannot see, and the reason the
    /// hop is observed as it happens: the chain ends on exactly the URL that was
    /// signed, so the URLs match — while reqwest dropped the `Authorization`
    /// header on the outbound cross-origin hop and never restored it, so the
    /// answer belongs to a request that carried nothing. Against an anonymously
    /// readable container that answer is a stamped `200`, which would promote
    /// the connection on a credential the service never saw.
    #[tokio::test]
    async fn a_redirect_that_returns_to_the_signed_url_records_no_evidence() {
        use base64::Engine as _;
        use ovstorage_plugin::{SecretBundle, SecretBytes, SecretValue};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // The far side of the bounce: a different origin, which sends the
        // request straight back to where it came from.
        let away = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let away_url = format!("http://{}", away.local_addr().unwrap());
        let home = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let home_url = format!("http://{}", home.local_addr().unwrap());

        let bounce_out = format!(
            "HTTP/1.1 302 Found\r\nLocation: {away_url}/away\r\n\
             content-length: 0\r\nconnection: close\r\n\r\n"
        );
        let bounce_back = format!(
            "HTTP/1.1 302 Found\r\nLocation: {home_url}/bkt/obj.txt\r\n\
             content-length: 0\r\nconnection: close\r\n\r\n"
        );
        // The final leg: a stamped 200, as an anonymously readable blob answers.
        const PUBLIC_OK: &str = "HTTP/1.1 200 OK\r\nx-ms-request-id: req-1\r\n\
             etag: \"0x8DCF\"\r\ncontent-length: 0\r\nconnection: close\r\n\r\n";

        let carried_auth_on_final_leg = Arc::new(std::sync::Mutex::new(None::<bool>));
        let observed = Arc::clone(&carried_auth_on_final_leg);
        tokio::spawn(async move {
            for (index, reply) in [bounce_out.as_str(), PUBLIC_OK].into_iter().enumerate() {
                let Ok((mut stream, _)) = home.accept().await else {
                    return;
                };
                // Read until the head is complete rather than once: a single
                // `read` is not guaranteed to deliver it, and treating a short
                // read as "no authorization header" would make the control pass
                // for the wrong reason — its passing value is `Some(false)`.
                let mut raw = Vec::new();
                let mut buf = [0u8; 4096];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            raw.extend_from_slice(&buf[..n]);
                            if raw.windows(4).any(|w| w == b"\r\n\r\n") {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                if index == 1 {
                    let head = String::from_utf8_lossy(&raw).to_lowercase();
                    assert!(
                        head.contains("\r\n\r\n"),
                        "control: the final leg's request head must be complete"
                    );
                    *observed.lock().expect("poisoned") = Some(head.contains("authorization:"));
                }
                let _ = stream.write_all(reply.as_bytes()).await;
                let _ = stream.shutdown().await;
            }
        });
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = away.accept().await {
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf).await;
                let _ = stream.write_all(bounce_back.as_bytes()).await;
                let _ = stream.shutdown().await;
            }
        });

        let mut bundle = SecretBundle::default();
        bundle.fields.insert(
            "account_key".into(),
            SecretValue::Bytes(SecretBytes(
                base64::engine::general_purpose::STANDARD
                    .encode(b"0123456789abcdef")
                    .into_bytes(),
            )),
        );
        let auth = AzureAuth::resolve(&bundle).expect("shared key auth resolves");
        let client = AzureClient::new("acct".into(), auth).expect("client builds");

        let evidence = Arc::new(OperationEvidence::default());
        let canonical_path = "/acct/bkt/obj.txt".to_string();
        let response = with_operation_evidence(evidence.clone(), async {
            client
                .send(AzureRequest {
                    method: Method::HEAD,
                    url: format!("{home_url}/bkt/obj.txt"),
                    canonical_path: &canonical_path,
                    canonical_query: vec![],
                    extra_headers: vec![],
                    content_type: None,
                    content_md5: None,
                    if_match: None,
                    if_none_match: None,
                    range: None,
                    body: None,
                })
                .await
        })
        .await
        .expect("the chain is followed and answered");

        // Controls — the chain really did return to the signed URL with a
        // stamped 200, and really did lose the credential on the way. Without
        // both, the absent acceptance would prove nothing.
        assert_eq!(response.status, 200, "control: the final leg is served");
        assert_eq!(
            carried_auth_on_final_leg.lock().expect("poisoned").take(),
            Some(false),
            "control: reqwest must have dropped the credential on the outbound hop"
        );

        assert!(
            !evidence.saw_acceptance(),
            "an answer to a request that carried no credential is not proof of one"
        );
    }

    /// A SAME-ORIGIN redirect records no evidence, and azure diverges from the
    /// gcs sibling here on purpose.
    ///
    /// gcs credits a same-origin hop because its credential is an OAuth bearer
    /// in a header, which reqwest re-sends unchanged and which does not depend
    /// on the path. Azure's does: `SharedKey` signs an HMAC over the canonical
    /// path and query, and a SAS carries the credential IN the query. So a
    /// path-rewriting proxy re-sends a signature for the WRONG resource, the
    /// service answers `403 AuthenticationFailed`, and recording that as a
    /// refusal would advance this connection's epoch on every request and park
    /// it for ever.
    ///
    /// Asserted on the epoch directly, because that is the property: a
    /// connection-level check cannot see a single refusal, only a concurrent
    /// operation could — and the epoch is what such an operation would read.
    #[tokio::test]
    async fn a_same_origin_redirect_advances_no_refusal_epoch() {
        use base64::Engine as _;
        use ovstorage_plugin::{SecretBundle, SecretBytes, SecretValue};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // One server: the first request is bounced to another path on the SAME
        // origin, and the rewritten path answers as azure answers a signature
        // that does not cover it.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        const BOUNCE: &str = "HTTP/1.1 302 Found\r\nLocation: /v2/bkt/obj.txt\r\n\
             content-length: 0\r\nconnection: close\r\n\r\n";
        tokio::spawn(async move {
            for expected in [BOUNCE, REWRITTEN_REFUSAL] {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf).await;
                let _ = stream.write_all(expected.as_bytes()).await;
                let _ = stream.shutdown().await;
            }
        });

        let mut bundle = SecretBundle::default();
        bundle.fields.insert(
            "account_key".into(),
            SecretValue::Bytes(SecretBytes(
                base64::engine::general_purpose::STANDARD
                    .encode(b"0123456789abcdef")
                    .into_bytes(),
            )),
        );
        let auth = AzureAuth::resolve(&bundle).expect("shared key auth resolves");
        let client = AzureClient::new("acct".into(), auth).expect("client builds");
        let epoch_before = client.refusal_epoch();

        let canonical_path = "/acct/bkt/obj.txt".to_string();
        let response = client
            .send(AzureRequest {
                method: Method::HEAD,
                url: format!("{url}/bkt/obj.txt"),
                canonical_path: &canonical_path,
                canonical_query: vec![],
                extra_headers: vec![],
                content_type: None,
                content_md5: None,
                if_match: None,
                if_none_match: None,
                range: None,
                body: None,
            })
            .await
            .expect("the redirect is followed and answered");

        // Control — the redirect really was followed and really was refused, so
        // the unchanged epoch is a property of the rule and not of a request
        // that never happened.
        assert_eq!(response.status, 403, "control: the rewrite is refused");
        assert_eq!(
            client.refusal_epoch(),
            epoch_before,
            "a refusal provoked by a rewritten path must not condemn the \
             credential: the signature never covered that resource"
        );
    }

    /// Two operations sharing one connection, and the asymmetry between what
    /// each half of the evidence is allowed to see.
    ///
    /// The connection is one `AzureClient` — clones share it, and under the
    /// broker two unrelated remote callers can drive it at once. ACCEPTANCE
    /// must not cross between them: a connection-wide tally would let a caller
    /// whose own operation touched no service be vindicated by its neighbour's
    /// request, and promotion is unrecoverable here. REFUSAL must cross: the
    /// credential is one object, so the 403 answered to one caller condemns it
    /// for both, and the caller that merely avoided hearing it must not promote
    /// on that.
    ///
    /// Both requests are in flight simultaneously — each responder waits on a
    /// barrier for the other to have been reached before answering — so the two
    /// verdicts genuinely overlap rather than queueing. The assertions are read
    /// from each operation's own sink after both have finished, so a
    /// connection-wide acceptance tally fails them whichever operation lands
    /// first; the barrier buys realism, not the bite.
    #[tokio::test]
    async fn concurrent_operations_do_not_share_evidence() {
        use base64::Engine as _;
        use ovstorage_plugin::{SecretBundle, SecretBytes, SecretValue};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::sync::Barrier;

        async fn responder(response: &'static str, barrier: Arc<Barrier>) -> String {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            tokio::spawn(async move {
                if let Ok((mut stream, _)) = listener.accept().await {
                    let mut buf = [0u8; 4096];
                    let _ = stream.read(&mut buf).await;
                    // Hold the answer until BOTH requests have arrived.
                    barrier.wait().await;
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.shutdown().await;
                }
            });
            url
        }

        let barrier = Arc::new(Barrier::new(2));
        let accepting = responder(
            "HTTP/1.1 200 OK\r\nx-ms-request-id: 1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed\r\n\
             content-length: 0\r\n\r\n",
            barrier.clone(),
        )
        .await;
        let refusing = responder(
            "HTTP/1.1 403 Forbidden\r\nx-ms-error-code: AuthenticationFailed\r\n\
             x-ms-request-id: 1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed\r\n\
             content-length: 0\r\n\r\n",
            barrier.clone(),
        )
        .await;

        // One connection, one credential, shared by both operations.
        let mut bundle = SecretBundle::default();
        bundle.fields.insert(
            "account_key".into(),
            SecretValue::Bytes(SecretBytes(
                base64::engine::general_purpose::STANDARD
                    .encode(b"0123456789abcdef")
                    .into_bytes(),
            )),
        );
        let auth = AzureAuth::resolve(&bundle).expect("shared key auth resolves");
        let client = Arc::new(AzureClient::new("acct".into(), auth).expect("client builds"));

        async fn one(client: Arc<AzureClient>, url: String) -> Arc<OperationEvidence> {
            let evidence = Arc::new(OperationEvidence::default());
            let canonical_path = "/acct/bkt/obj.txt".to_string();
            with_operation_evidence(evidence.clone(), async move {
                let _ = client
                    .send(AzureRequest {
                        method: Method::HEAD,
                        url: format!("{url}/bkt/obj.txt"),
                        canonical_path: &canonical_path,
                        canonical_query: vec![],
                        extra_headers: vec![],
                        content_type: None,
                        content_md5: None,
                        if_match: None,
                        if_none_match: None,
                        range: None,
                        body: None,
                    })
                    .await;
            })
            .await;
            evidence
        }

        let epoch_before = client.refusal_epoch();
        let (accepted_op, refused_op) = tokio::join!(
            one(client.clone(), accepting),
            one(client.clone(), refusing),
        );

        assert!(
            accepted_op.saw_acceptance(),
            "the accepted operation saw its own acceptance"
        );
        assert!(
            !refused_op.saw_acceptance(),
            "the refused operation must NOT be vindicated by its neighbour's \
             acceptance — acceptance is the operation's own"
        );
        // Refusal is the connection's, so the neighbour's 403 is visible to
        // BOTH witnesses and vetoes both promotions. That asymmetry is
        // deliberate: the credential is one object, and an operation that
        // merely avoided hearing the refusal must not promote on that.
        assert_eq!(
            client.refusal_epoch(),
            epoch_before + 1,
            "a refusal answered to either caller condemns the shared credential"
        );
    }

    /// An IdP that refuses the grant does so BEFORE any storage response
    /// exists, so `send` has to record the refusal itself or the promotion veto
    /// never sees it — and an operation whose earlier request was accepted
    /// would look like one with an acceptance and no refusal.
    #[tokio::test]
    async fn a_refused_entra_grant_counts_as_a_refusal() {
        use crate::auth::AzureAuth;
        use ovstorage_plugin::{SecretBundle, SecretBytes, SecretValue};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // A token endpoint that refuses the client credentials outright.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let entra_host = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf).await;
                let body = "{\"error\":\"invalid_client\"}";
                let response = format!(
                    "HTTP/1.1 400 Bad Request\r\ncontent-type: application/json\r\n\
                     connection: close\r\ncontent-length: {}\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
            }
        });

        let mut bundle = SecretBundle::default();
        for (key, value) in [
            ("tenant_id", "tenant-uuid"),
            ("client_id", "client-uuid"),
            ("client_secret", "secret-value"),
        ] {
            bundle.fields.insert(
                key.into(),
                SecretValue::Bytes(SecretBytes(value.as_bytes().to_vec())),
            );
        }
        let mut auth = AzureAuth::resolve(&bundle).expect("oauth auth resolves");
        auth.set_entra_host_for_test(entra_host);
        let client = AzureClient::new("acct".into(), auth).expect("client builds");

        let canonical_path = "/acct/bkt/obj.txt".to_string();
        let evidence = Arc::new(OperationEvidence::default());
        let epoch_before = client.refusal_epoch();
        let outcome = with_operation_evidence(evidence.clone(), async {
            client
                .send(AzureRequest {
                    method: Method::HEAD,
                    url: "http://127.0.0.1:1/bkt/obj.txt".into(),
                    canonical_path: &canonical_path,
                    canonical_query: vec![],
                    extra_headers: vec![],
                    content_type: None,
                    content_md5: None,
                    if_match: None,
                    if_none_match: None,
                    range: None,
                    body: None,
                })
                .await
        })
        .await;
        assert!(
            outcome.is_err(),
            "the grant was refused; send must not succeed"
        );
        assert_eq!(
            client.refusal_epoch(),
            epoch_before + 1,
            "a refused Entra grant must move the connection's refusal epoch"
        );
        assert!(
            !evidence.saw_acceptance(),
            "nothing was accepted; the grant never produced a request"
        );
    }

    /// The veto is broader than the parking rule, on purpose: its cost is a
    /// delayed promotion, while the cost of missing a refusal is a connection
    /// reporting `Authenticated` on a dead credential.
    #[test]
    fn any_ambiguous_refusal_vetoes_a_promotion() {
        assert!(vetoes_promotion(401, None));
        assert!(vetoes_promotion(403, Some("AuthenticationFailed")));
        assert!(
            vetoes_promotion(403, Some("AuthorizationFailure")),
            "Azurite's failed-signature shape is not in the parking list"
        );
        assert!(
            vetoes_promotion(403, None),
            "a 403 stripped of its code could be either; withhold the promotion"
        );
        // Identified, then scoped: authorization, not authentication.
        for scope in [
            "AuthorizationPermissionMismatch",
            "AuthorizationResourceTypeMismatch",
            "AuthorizationSourceIPMismatch",
            "InsufficientAccountPermissions",
        ] {
            assert!(
                !vetoes_promotion(403, Some(scope)),
                "{scope} identified the caller first"
            );
        }
        // Not refusals at all.
        for status in [200, 404, 409, 412, 429, 500, 503] {
            assert!(!vetoes_promotion(status, None), "{status} is no verdict");
        }
    }

    /// The origin gate: a response nobody at Azure produced proves nothing,
    /// however friendly its status. This is what excludes an SSO portal or a
    /// proxy answering on the service's behalf.
    #[test]
    fn a_response_without_azure_origin_headers_is_not_proof() {
        let empty = HeaderMap::new();
        for status in [200, 204, 409, 412, 416] {
            assert!(
                !proves_credentials(status, &empty),
                "{status} without x-ms-request-id is not Azure's answer"
            );
        }
    }
}
