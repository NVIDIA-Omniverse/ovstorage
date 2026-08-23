// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Evidence that the storage service accepted a request this connection signed.
//!
//! `GcsDriver::verify` proves a credential with one bucket-scope
//! `objects.list`, the data path is a different call, and no object operation
//! consults `auth_state` — so a deployment that refuses the probe while serving
//! the data path leaves a connection reporting `AwaitingAuth` while every
//! request it signs succeeds. `GcsLayer` promotes such a connection on an
//! operation the service demonstrably accepted; this module is what "accepted"
//! means, and who it counts for.
//!
//! The two halves of the evidence are scoped differently, and the asymmetry is
//! the design. **Acceptance is per-operation** — recorded in a task-local sink
//! the layer installs around the operation — because one `GcsBackend` serves
//! every caller of a connection, and under the broker those are unrelated
//! remote callers; a connection-wide tally would let a caller whose own
//! operation never reached the service (a `read`, which only mints a signed
//! URL) be vindicated by a neighbour's request. **Refusal is per-connection**,
//! on [`crate::auth::Authenticator`], because the credential is one object and
//! a refusal answered to anyone condemns it for everyone.

use std::sync::Arc;

// Re-exported so the rest of the crate names it through `crate::promotion`.
pub(crate) use ovstorage_plugin::connection::promotion::OperationEvidence;
use ovstorage_plugin::connection::promotion::{self, EvidenceScope};

/// Whether a response could only have been produced for a request the service
/// AUTHENTICATED.
///
/// Strict on purpose, and the mirror image of the lenient rule
/// `GcsDriver::verify` parks on: a 429, a 5xx, or a request rejected before
/// anything looked at the bearer says nothing about the credential.
///
/// A Google origin header is required as well, matching what the s3 sibling
/// asks of an S3 response. A response carrying none of
/// [`ORIGIN_HEADER_PREFIXES`] was composed by something that is not Google — a
/// WAF answering an unrecognized path, a front door serving its own block page
/// — and promoting on one is permanent here: `refresh` is `Unsupported` and
/// `GcsLayer` refuses `update_connection_credentials`, so a connection has no
/// path back at all. The counter-argument that such a proxy "could serve the
/// verify probe instead" does not hold for a connection that was parked BEFORE
/// the proxy path applied, which is a host that moved networks.
///
/// The premise this rests on — that a real `storage.googleapis.com` response
/// carries one — is not checkable from this repository, and a scripted fixture
/// stamping the header would report success either way. So its failure is made
/// LOUD rather than silent: a response that would otherwise have counted, and
/// carries no marker, is warned about with the header names it did carry. A
/// deployment where this rule is wrong shows up as a connection that stays
/// parked while its log says exactly why, rather than as an unexplained
/// regression.
///
/// `404` is excluded from the status set for a separate reason, below.
pub(crate) fn proves_credentials(
    status: u16,
    headers: &reqwest::header::HeaderMap,
    warn_once: impl FnOnce() -> bool,
) -> bool {
    if !accepted_status(status) {
        return false;
    }
    if is_origin_stamped(headers) {
        return true;
    }
    // Once per connection: the condition is a property of the deployment, and
    // the site is on every response.
    if !warn_once() {
        return false;
    }
    tracing::warn!(
        plugin = "gcs",
        status,
        headers = %headers
            .keys()
            .map(|name| name.as_str())
            .collect::<Vec<_>>()
            .join(","),
        "gcs: response carries no Google origin header, so it is not counted as \
         proof of the credential; a connection behind a header-stripping proxy \
         will stay in AwaitingAuth"
    );
    false
}

/// The response header prefixes Google stamps on a storage response.
const ORIGIN_HEADER_PREFIXES: &[&str] = &["x-goog-", "x-guploader-"];

/// Whether `headers` carries a Google origin marker.
fn is_origin_stamped(headers: &reqwest::header::HeaderMap) -> bool {
    headers.keys().any(|name| {
        ORIGIN_HEADER_PREFIXES
            .iter()
            .any(|prefix| name.as_str().starts_with(prefix))
    })
}

/// The status half of [`proves_credentials`], shared with the azure and s3
/// plugins as [`promotion::status_is_routed_verdict`] — which is also where the
/// deliberate exclusion of `404` is argued.
///
/// A resumable upload's `308 Resume Incomplete` is excluded by that set and is
/// worth naming here, since it is an answer only an authorized session gets:
/// nothing at this point distinguishes it from a gateway's `308 Permanent
/// Redirect`, and crediting the latter would promote on a response the service
/// never composed. The upload's final chunk answers 200, which does count, so a
/// resumable workload promotes one chunk later rather than not at all.
fn accepted_status(status: u16) -> bool {
    promotion::status_is_routed_verdict(status)
}

/// Whether a response is the service refusing this connection's CREDENTIAL, in
/// which case no operation overlapping it may be promoted.
///
/// Only 401, and the difference from the s3 sibling — which vetoes on 403 too —
/// is about what each provider makes knowable, not about a different appetite
/// for risk.
///
/// GCS makes the split native: `map_status_to_error` maps 401 to `AuthRequired`
/// with reason `gcs_unauthorized`, and 403 to `PermissionDenied`, an identified
/// principal that IAM scopes. A 403 here therefore says the bearer was
/// ACCEPTED and then found insufficient, so treating it as a possible
/// credential refusal would be wrong on its face, and would hold a legitimately
/// scoped credential parked for as long as its workload keeps touching what it
/// may not touch.
///
/// On s3 that discrimination lives in the response body, which the judgment
/// there cannot wait for, so every `403` has to count — and `400` with it,
/// since s3 carries `ExpiredToken` and its siblings there. s3 pays for the
/// breadth in full: a permission-checking workload there can withhold promotion
/// for as long as it runs, which gcs avoids structurally by not vetoing on the
/// status such a workload provokes.
pub(crate) fn vetoes_promotion(status: u16) -> bool {
    status == 401
}

/// Whether the credential this request carried survived to the response that
/// answered it.
///
/// The question a redirect raises is not "did the URL change" but "was the
/// `Authorization` header still attached when the answer was produced".
/// reqwest strips it on a hop that changes host or port and never re-adds it
/// — `reqwest::redirect::remove_sensitive_headers` — so a chain that leaves the
/// origin and comes back delivers an answer to an UNSIGNED request while ending
/// on the URL we signed. Comparing URLs cannot see that; comparing origins
/// cannot either.
///
/// So the redirect policy records the hop instead, and this is where it lands.
/// A same-origin redirect keeps the bearer, so its verdict is genuinely ours —
/// including a `401`, which is the case a URL comparison discards and which is
/// exactly the evidence a dying credential produces.
///
/// Three tests pin it:
/// `a_redirected_response_does_not_promote_a_parked_connection` and
/// `a_concurrent_redirected_refusal_does_not_condemn_the_connection` for the
/// cross-origin halves, and `a_same_origin_redirect_still_counts_as_evidence`
/// for the sentence above.
///
/// **This predicate is right for GCS and does not generalize.** It holds because
/// the credential is an OAuth bearer in a header, independent of the path. The
/// azure sibling disqualifies ANY redirect, because two of its three credential
/// shapes are bound to the URL being signed; and the s3 plugin needs no rule at
/// all, because its transport does not follow redirects.
pub(crate) fn note_bearer_stripped() {
    let _ = BEARER_STRIPPED.try_with(|stripped| stripped.set(true));
}

/// Run `future` watching for a hop that strips the bearer; returns the outcome
/// alongside whether the credential survived every hop.
pub(crate) async fn watching_redirects<T>(
    future: impl std::future::Future<Output = T>,
) -> (T, bool) {
    let stripped = std::cell::Cell::new(false);
    BEARER_STRIPPED
        .scope(stripped, async move {
            let outcome = future.await;
            let survived = !BEARER_STRIPPED.with(|stripped| stripped.get());
            (outcome, survived)
        })
        .await
}

tokio::task_local! {
    /// Set by the redirect policy when a hop crossed host or port, which is
    /// where reqwest drops the `Authorization` header.
    static BEARER_STRIPPED: std::cell::Cell<bool>;

    /// The evidence sink belonging to the operation running on this task.
    ///
    /// Installed by `GcsLayer`'s witness around the operation future and read
    /// by `crate::send`. Absent for work that belongs to no operation — the
    /// Pub/Sub poller, the background token refresh — and a verdict recorded
    /// nowhere can vindicate nothing, which is the safe way round.
    static OPERATION_EVIDENCE: Arc<OperationEvidence>;
}

/// This plugin's acceptance sink, naming [`OPERATION_EVIDENCE`] for the shared
/// [`promotion`] machinery.
pub(crate) struct GcsEvidence;

impl EvidenceScope for GcsEvidence {
    fn sink() -> &'static tokio::task::LocalKey<Arc<OperationEvidence>> {
        &OPERATION_EVIDENCE
    }
}

/// Run `future` with `evidence` installed as the operation's acceptance sink.
pub(crate) async fn with_operation_evidence<T>(
    evidence: Arc<OperationEvidence>,
    future: impl std::future::Future<Output = T>,
) -> T {
    promotion::with_operation_evidence::<GcsEvidence, _>(evidence, future).await
}

/// Credit an acceptance to the operation running on this task, if any.
///
/// Work that belongs to no operation — the Pub/Sub poller, the background token
/// refresh — credits nothing, and an acceptance recorded nowhere vindicates
/// nobody. Refusals are not routed through here at all: they go to the
/// connection-wide epoch, so the ones this task-local would have dropped still
/// veto.
pub(crate) fn credit_operation_acceptance() {
    promotion::credit_operation_acceptance::<GcsEvidence>();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(names: &[&str]) -> reqwest::header::HeaderMap {
        let mut map = reqwest::header::HeaderMap::new();
        for name in names {
            map.insert(
                reqwest::header::HeaderName::from_bytes(name.as_bytes()).expect("header name"),
                reqwest::header::HeaderValue::from_static("x"),
            );
        }
        map
    }

    /// The warning is claimed only when it would actually be emitted: a stamped
    /// response, a non-accepting status, and a refusal must all leave the one
    /// warning unspent, or a listing sweep would burn it on the first object and
    /// a header-stripping deployment would never say so.
    #[test]
    fn only_an_unstamped_acceptable_response_spends_the_warning() {
        let claimed = std::cell::Cell::new(0);
        let claim = || {
            claimed.set(claimed.get() + 1);
            true
        };
        proves_credentials(200, &headers(&["x-goog-generation"]), claim);
        assert_eq!(claimed.get(), 0, "a stamped response spends nothing");
        proves_credentials(404, &headers(&[]), claim);
        proves_credentials(500, &headers(&[]), claim);
        assert_eq!(
            claimed.get(),
            0,
            "a status that cannot prove spends nothing"
        );
        proves_credentials(200, &headers(&[]), claim);
        assert_eq!(claimed.get(), 1, "the unstamped acceptance spends it");
    }

    /// Acceptance is scoped to the operation that earned it, which is the whole
    /// reason the sink is a task-local rather than connection state.
    ///
    /// Asserted on the sinks directly rather than on `auth_state`, because that
    /// is what separates the two scopings: an accepted neighbour promotes the
    /// connection either way, so no state assertion can tell a per-operation
    /// sink from a connection-wide tally. Replacing this with connection-wide
    /// state would let a caller whose own operation never left the process — a
    /// `read` that only mints a URL — be vindicated by a neighbour's request,
    /// and under the broker those two are unrelated remote clients.
    #[tokio::test]
    async fn acceptance_does_not_cross_between_operations() {
        let earner = Arc::new(OperationEvidence::default());
        let neighbour = Arc::new(OperationEvidence::default());

        // Separate TASKS, not `join!` on one: the sink is a task-local, so two
        // futures interleaved on a single task would not exercise the isolation
        // this claims to pin. Under the broker these two are separate callers.
        let earning = tokio::spawn(with_operation_evidence(earner.clone(), async {
            tokio::task::yield_now().await;
            credit_operation_acceptance();
        }));
        let neighbouring = tokio::spawn(with_operation_evidence(neighbour.clone(), async {
            tokio::task::yield_now().await;
            // Reaches no request of its own, and must stay unvindicated even
            // though its neighbour's acceptance lands while it is running.
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

    #[test]
    fn acceptance_requires_a_google_origin_marker() {
        assert!(proves_credentials(
            200,
            &headers(&["x-guploader-uploadid"]),
            || true
        ));
        assert!(proves_credentials(
            200,
            &headers(&["x-goog-generation"]),
            || { true }
        ));
        // A WAF or front door composing its own answer carries neither.
        assert!(!proves_credentials(
            200,
            &headers(&["content-type"]),
            || true
        ));
        assert!(!proves_credentials(200, &headers(&[]), || true));
    }

    #[test]
    fn acceptance_is_limited_to_routed_verdicts() {
        let stamped = headers(&["x-guploader-uploadid"]);
        for status in [200, 204, 409, 412, 416] {
            assert!(
                proves_credentials(status, &stamped, || true),
                "{status} from the service proves the credential"
            );
        }
        // A 404 — which a missing bucket earns without the bearer deciding
        // anything, and which is what an accidental responder answers an
        // unrecognized path with — proves nothing. Nor does a refusal or an
        // outage.
        for status in [308, 401, 403, 404, 429, 500, 503] {
            assert!(
                !proves_credentials(status, &stamped, || true),
                "{status} is no proof of a working credential"
            );
        }
    }

    /// Only a 401 vetoes. A 403 is an identified principal that IAM scopes —
    /// `GcsDriver::verify` passes it for the same reason — and vetoing on it
    /// would park a scoped credential for as long as its workload runs.
    #[test]
    fn only_a_401_vetoes_a_promotion() {
        assert!(vetoes_promotion(401));
        for status in [200, 308, 403, 404, 412, 429, 500, 503] {
            assert!(
                !vetoes_promotion(status),
                "{status} is no credential refusal"
            );
        }
    }
}
