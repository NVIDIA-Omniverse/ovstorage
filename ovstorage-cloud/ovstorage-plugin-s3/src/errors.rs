// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Maps AWS SDK `SdkError`s (and raw HTTP statuses) onto the plugin's
//! `ErrorCode` taxonomy.
//!
//! [`map_error_status`] is the status-to-`ErrorCode` contract shared by S3 and
//! SQS — notably `401 -> AuthRequired` with an `Auth` context, which the host's
//! surfaces to the caller as an auth failure rather than a data error — it is
//! NOT retried, see the note on the `401` arm below. [`map_sdk_error`]
//! classifies a typed `SdkError`:
//! modeled error code first (S3 can return HTTP 200 with an embedded `<Error>`
//! body), then raw HTTP status, then the non-HTTP transport variants.
//!
//! Provider response bodies never reach an error message. Both entry points
//! reduce a body to its `<Code>` token — allowlisted to ASCII alphanumerics
//! plus `.`, `_`, `-` and length-capped — before any message is built. An S3
//! `SignatureDoesNotMatch` document echoes back `<StringToSign>`,
//! `<CanonicalRequest>` and `<AWSAccessKeyId>`, so a body that reached an
//! exception would put credential-derived material into every log that renders
//! it.

use aws_sdk_s3::error::{ProvideErrorMetadata, SdkError};
use ovstorage_plugin::{ConnectionId, Error, ErrorCode, ErrorContext};

/// Map an AWS HTTP status to a typed `ErrorCode`.
///
/// `body` is the raw provider response. It is reduced to the provider error
/// code here, before any message is built, so every call site — present and
/// future — is leak-proof by construction. The parameter stays `&[u8]` for
/// exactly that reason: callers hand over the bytes they captured and this
/// function owns the reduction, rather than each caller being trusted to do it.
///
/// A non-empty body with no recoverable `<Code>` is reported by length alone —
/// an S3-compatible gateway or a corporate proxy answering with an HTML error
/// page is worth distinguishing from a silent endpoint, and the length says so
/// without quoting a byte of it. An empty `body` adds nothing: callers that
/// have no captured response pass `b""`, and claiming a "0 byte body" would
/// describe the call site rather than the provider.
pub(crate) fn map_error_status(status: u16, body: &[u8]) -> Error {
    let detail = match provider_code(body) {
        Some(code) => Detail::code(&code),
        None if body.is_empty() => Detail::empty(),
        None => Detail::suppressed(body.len()),
    };
    map_error_status_detail(status, &detail)
}

/// A provider error-code token that has passed the allowlist filter.
///
/// The two constructors below are the only ones, and both go through
/// `ovstorage_plugin::provider_error`. That is what lets [`Detail`] accept a
/// code without having to trust its caller: every construction site takes raw
/// provider bytes, so none of them can wrap text that skipped the filter.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SanitizedCode(String);

impl SanitizedCode {
    /// A value already isolated as the provider's error-code field — the AWS
    /// SDK's modeled code.
    fn from_field(raw: &[u8]) -> Option<Self> {
        ovstorage_plugin::provider_error::validate_code_token(raw).map(Self)
    }

    /// The code element of an XML error document.
    fn from_xml_body(body: &[u8]) -> Option<Self> {
        ovstorage_plugin::provider_error::xml_code(body).map(Self)
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

/// A message trail proven safe to interpolate into an error message.
///
/// Every constructor either routes untrusted text through [`SanitizedCode`]
/// or builds from this module's own literals, so the "already sanitized"
/// invariant behind this whole module is enforced by the type rather than by a
/// doc comment. There is deliberately no constructor — and no `From<String>` —
/// that accepts raw provider text.
struct Detail(String);

impl Detail {
    /// The status alone describes the failure; add nothing.
    fn empty() -> Self {
        Self(String::new())
    }

    /// A provider error code recovered from a response body.
    fn code(code: &SanitizedCode) -> Self {
        Self(code.as_str().to_string())
    }

    /// A body that yielded no code, described by its length alone.
    fn suppressed(len: usize) -> Self {
        Self(format!(
            "no provider error code; {len} byte body suppressed"
        ))
    }

    /// This module's own operation label, optionally followed by a code.
    ///
    /// `context` is always a caller-supplied literal (`"s3 head_object"`,
    /// `"SQS ReceiveMessage"`), never provider text.
    fn labelled(context: &str, code: Option<&SanitizedCode>) -> Self {
        match code {
            Some(code) => Self(format!("{context}: {}", code.as_str())),
            None => Self(context.to_string()),
        }
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

/// Describe a JSON decode failure without rendering the offending value.
///
/// serde's `Display` embeds it — on a type mismatch the rendering is
/// `invalid type: string "…"`, which puts a slice of the provider response
/// into the message. The classification, the position and the body length
/// keep the failure diagnosable without quoting a byte of it. The SQS
/// notification body this crate parses is provider-controlled, so it is
/// subject to the same guarantee as an error body.
pub(crate) fn decode_failure(err: &serde_json::Error, body_len: usize) -> String {
    format!(
        "{:?} at line {} column {} ({body_len} byte body suppressed)",
        err.classify(),
        err.line(),
        err.column()
    )
}

/// Mine the provider error code out of an S3 XML error document.
///
/// S3 answers with `<Error><Code>…</Code><Message>…</Message>…</Error>`. On a
/// `SignatureDoesNotMatch` that same document also carries `<StringToSign>`,
/// `<CanonicalRequest>` and `<AWSAccessKeyId>`, so only the `<Code>` child of
/// the root element is recovered, and only through
/// [`ovstorage_plugin::provider_error::validate_code_token`]. Returns `None`
/// when the document has no such terminated element.
///
/// Takes raw bytes rather than a `String::from_utf8_lossy`: the lossy
/// conversion expands each invalid byte to a three-byte U+FFFD, which inflates
/// offsets and can push a `<Code>` that sits inside the scan window past it.
fn provider_code(body: &[u8]) -> Option<SanitizedCode> {
    SanitizedCode::from_xml_body(body)
}

/// Status-to-`ErrorCode` mapping over an already-sanitized [`Detail`] trail.
///
/// Taking `Detail` rather than `&str` is what keeps raw provider text out: the
/// trail is interpolated verbatim into the message, and `Detail` has no
/// constructor that accepts unsanitized input.
fn map_error_status_detail(status: u16, detail: &Detail) -> Error {
    let trail = if detail.as_str().is_empty() {
        String::new()
    } else {
        format!(": {}", detail.as_str())
    };
    match status {
        // 401 → AuthRequired, which `default_classify` reads as
        // `NeedsInteractive`: the host does NOT silently retry it, it routes
        // the caller to an interactive re-auth. Behind the broker, the
        // broker-client driver classifies it `RecoverableCredential` when it
        // holds a silent grant, and there it does drive one refresh + retry.
        401 => Error::new(
            ErrorCode::AuthRequired,
            format!("S3 request requires authentication (HTTP 401){trail}"),
        )
        .with_context(ErrorContext::Auth {
            connection_id: ConnectionId(String::new()),
            reason: Some("s3_unauthorized".into()),
            expired_at: None,
        }),
        403 => Error::new(
            ErrorCode::PermissionDenied,
            format!("S3 request forbidden (HTTP 403){trail}"),
        ),
        404 | 410 => Error::new(
            ErrorCode::NotFound,
            format!("S3 object not found (HTTP {status}){trail}"),
        ),
        409 => Error::new(
            ErrorCode::Conflict,
            format!("S3 reported conflict (HTTP 409){trail}"),
        ),
        412 => Error::new(
            ErrorCode::PreconditionFailed,
            format!("S3 precondition failed (HTTP 412){trail}"),
        ),
        416 => Error::new(
            ErrorCode::InvalidArgument,
            format!("S3 range not satisfiable (HTTP 416){trail}"),
        ),
        // match-arm order matters: 408/504 + 429/503 must precede the 500..=599 catchall.
        408 | 504 => Error::new(
            ErrorCode::DeadlineExceeded,
            format!("S3 deadline exceeded (HTTP {status}){trail}"),
        ),
        429 | 503 => Error::new(
            ErrorCode::ResourceExhausted,
            format!("S3 rate-limited (HTTP {status}){trail}"),
        ),
        500..=599 => Error::new(
            ErrorCode::Transient,
            format!("S3 returned transient HTTP {status}{trail}"),
        ),
        status => Error::new(
            ErrorCode::Transient,
            format!("S3 returned unexpected HTTP {status}{trail}"),
        ),
    }
}

/// Map an `SdkError` from a live S3/SQS call (or a local presign) to an `Error`.
///
/// When the SDK captured a raw HTTP response, the status drives the mapping
/// through [`map_error_status`]. Otherwise the failure was local (timeout,
/// connect/TLS, request construction) and is classified by variant.
pub(crate) fn map_sdk_error<E>(context: &str, err: SdkError<E>) -> Error
where
    E: std::fmt::Debug + ProvideErrorMetadata,
{
    // S3 can reply HTTP 200 with an embedded `<Error>` body (notably on
    // CompleteMultipartUpload and CopyObject); the SDK surfaces these as a typed
    // service error whose modeled code is the only reliable signal, so check it
    // before the raw status. `InvalidPart` / `InvalidPartOrder` / `EntityTooSmall`
    // are *terminal* commit failures (`ObjectModified`), not retryable — on the
    // HTTP-200 envelope the raw status is 200, so letting them fall through to
    // `map_error_status(200, …)` would wrongly report them as `Transient` and make
    // a botched multipart commit look retryable.
    let modeled_code = err.as_service_error().and_then(|svc| svc.code());
    if let Some(code) = modeled_code {
        match code {
            "PreconditionFailed" => {
                return Error::new(ErrorCode::PreconditionFailed, format!("{context}: {code}"));
            }
            "InternalError" | "ServiceUnavailable" | "SlowDown" | "RequestTimeout"
            | "OperationAborted" => {
                return Error::new(ErrorCode::Transient, format!("{context}: {code}"));
            }
            "InvalidPart" | "InvalidPartOrder" | "EntityTooSmall" => {
                return Error::new(ErrorCode::ObjectModified, format!("{context}: {code}"));
            }
            _ => {}
        }
    }
    // Borrow the raw response for its HTTP status, and — only when the SDK
    // modeled no code — for its body.
    if let Some(raw) = err.raw_response() {
        let status = raw.status().as_u16();
        // The fallback reads the response body through the SDK's own accessor
        // rather than parsing the `Debug` rendering of the `SdkError`. `Debug`
        // output carries no stability contract, so an SDK upgrade that
        // restructures it would silently change what this mines — and what it
        // mines is attacker-influenced provider text embedded in scaffolding,
        // so the grammar being scanned is not really XML. `body().bytes()` is a
        // supported API and returns `None` for a body that was never buffered,
        // which is a plain "no code" rather than a wrong one.
        //
        // Expect that `None` to be common rather than exceptional: on the SDK's
        // STREAMING error paths the body is typically left unbuffered, so this
        // fallback contributes nothing there and the modeled code is the only
        // available source. A message carrying the context label with no code
        // on such a path is that case, NOT a sanitizer that rejected a token —
        // the filter is never reached with anything to judge.
        //
        // Either way the body is reduced to a `<Code>` token and otherwise
        // discarded; the modeled code stays the preferred source. What survives
        // is the internal `context` label plus a sanitized code.
        let code = modeled_code
            .and_then(|value| SanitizedCode::from_field(value.as_bytes()))
            .or_else(|| provider_code(raw.body().bytes().unwrap_or(&[])));
        let summary = Detail::labelled(context, code.as_ref());
        // An embedded-`<Error>` envelope (a modeled service error) carrying a
        // code we don't classify explicitly, on a 2xx status, is a terminal
        // commit failure: a success status carries no retry signal, so mapping
        // a 2xx by status would wrongly report `Transient`. Map it to
        // `Internal`. (A non-service error on a 2xx — e.g. a malformed-response
        // parse failure — still falls through to the status mapping, unchanged.)
        if modeled_code.is_some() && (200..300).contains(&status) {
            return Error::new(ErrorCode::Internal, summary.as_str());
        }
        return map_error_status_detail(status, &summary);
    }

    match err {
        // Whole-operation / attempt timeout → DeadlineExceeded (as for 408/504).
        SdkError::TimeoutError(_) => {
            Error::new(ErrorCode::DeadlineExceeded, format!("{context}: timed out"))
        }
        // Connect / TLS / I/O failure before a response → Transient.
        SdkError::DispatchFailure(inner) => Error::new(
            ErrorCode::Transient,
            format!("{context}: dispatch failure: {inner:?}"),
        ),
        // Request could not be constructed (config/credential wiring) — a
        // plugin-side problem, not an upstream failure.
        SdkError::ConstructionFailure(inner) => Error::new(
            ErrorCode::Internal,
            format!("{context}: request construction failed: {inner:?}"),
        ),
        // Response received but could not be parsed into the operation shape.
        SdkError::ResponseError(_) => Error::new(
            ErrorCode::Transient,
            format!("{context}: malformed S3 response"),
        ),
        // `ServiceError` without a raw response should not happen, but stay
        // conservative: treat unknown failures as transient.
        other => Error::new(ErrorCode::Transient, format!("{context}: {other:?}")),
    }
}

/// Restate a store refusal of an UNSIGNED request in terms an operator can act
/// on.
///
/// Applied by `S3Backend::map_store_error`, which covers the operations an
/// anonymous connection sends through the SDK: `list`, `list_versions`, and
/// the `HeadObject` and directory probe behind `stat` and
/// `get_latest_version`. It does not cover `read`, which mints a redirect and
/// issues nothing. `check_access` reaches it only through that same directory
/// probe, and only to classify: its own output is a verdict rather than an
/// error, so what the restatement changes there is which status the verdict's
/// reason names — an anonymous `401` is restated as `PermissionDenied` and so
/// reads as `403`, deliberately, since there is no credential to fix. It is a
/// no-op on a credentialed connection.
///
/// An anonymous connection sends no signature, so S3 evaluates the request as
/// the anonymous principal. A `401` or `403` back therefore says the store
/// refused THIS request from an anonymous caller — a different fact from either
/// reading the caller would otherwise take:
///
/// It is deliberately not stated more strongly than that. On a bucket that
/// grants `s3:GetObject` to `*` but not `s3:ListBucket` — the configuration
/// this plugin names as ordinary — S3 answers `403` rather than `404` for an
/// object that simply is not there, because disclosing absence would itself
/// require the list permission. So a refused `HeadObject` is not proof that the
/// grant is missing, and the remedy has to offer both readings.
///
/// - **not** "the backend cannot do this". It can, and it does against a bucket
///   whose policy allows it; the common case is a bucket that grants
///   `s3:GetObject` to `*` but not `s3:ListBucket`, where `read` succeeds and
///   `list` is refused on the same connection.
/// - **not** "your credentials are wrong". There are none, and `AuthRequired`
///   is read by machinery that assumes there are. The host classifies it
///   `AuthErrorClass::NeedsInteractive`
///   (`ovstorage-plugin/src/connection/driver.rs`, `default_classify`), which
///   points a caller at an interactive re-auth that `S3Driver::interactive`
///   answers `Unsupported`; and the broker-client driver classifies it
///   `RecoverableCredential` when the client holds a silent grant
///   (`ovstorage-plugin-broker/src/driver.rs`, `classify`), which spends a
///   token refresh and one retry on a request whose outcome cannot change.
///   `PermissionDenied` classifies as itself and is surfaced.
///
/// The `ErrorContext::Auth` payload goes with it, deliberately: it names a
/// connection whose credential is in question, and there is none.
///
/// The remedy is a `next_action` rather than more message, because the repairs
/// are the operator's and they are alternatives. Two things about its wording
/// are deliberate:
///
/// - it says **remove and re-add** the connection, not "add credentials to it".
///   `S3Layer::update_connection_credentials` refuses an
///   anonymous-to-credentialed update outright — the backend was built without
///   a signing client and the live credential cell would not reshape it — so
///   "configure credentials on this connection" is advice that cannot be
///   followed;
/// - it says **public-access controls**, not "the bucket policy". S3 Block
///   Public Access, an access point policy, an SCP, or an S3-compatible
///   gateway's own rules produce the same refusal, and the message must not
///   send an operator to edit the one document that may not be the cause.
///
/// Every other code passes through untouched — a `404` for a missing bucket, a
/// `503`, a timeout — because none of them is about the request being unsigned.
pub(crate) fn map_anonymous_refusal(err: Error) -> Error {
    if !matches!(
        err.code(),
        ErrorCode::AuthRequired | ErrorCode::PermissionDenied
    ) {
        return err;
    }
    // `err.message()` is already sanitized: everything reaching here was built
    // by `map_error_status_detail` out of this module's literals plus a
    // validated provider code token.
    Error::new(
        ErrorCode::PermissionDenied,
        format!(
            "{}; the request was unsigned because this S3 connection is \
             anonymous, and the store refused it. Note a bucket that does not \
             grant s3:ListBucket to anonymous callers also answers 403 for an \
             object that does not exist",
            err.message()
        ),
    )
    .with_next_action(
        "confirm the object exists, then remove and re-add this connection with \
         credentials, or grant the action to anonymous callers in the \
         public-access controls covering this bucket",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_sdk_s3::config::http::HttpResponse;
    use aws_sdk_s3::error::ErrorMetadata;
    use aws_sdk_s3::primitives::SdkBody;

    /// The `SignatureDoesNotMatch` document S3 actually returns. Everything
    /// after `<Code>` describes how the request was signed, which is what makes
    /// quoting this body a disclosure.
    const SIGNATURE_BODY: &str = concat!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
        "<Error><Code>SignatureDoesNotMatch</Code>",
        "<Message>The request signature we calculated does not match the signature you provided.</Message>",
        "<AWSAccessKeyId>AKIAIOSFODNN7EXAMPLE</AWSAccessKeyId>",
        "<StringToSign>GET\n\n\nTue, 27 Mar 2007 19:36:42 +0000\n/bucket/photos/puppy.jpg</StringToSign>",
        "<SignatureProvided>bWq2s1WEIj+Ydj0vQ697zp+IXMU=</SignatureProvided>",
        "<StringToSignBytes>47 45 54 0a 0a 0a</StringToSignBytes>",
        "<CanonicalRequest>GET\n/photos/puppy.jpg\n\nx-amz-date:20070327T193642Z\n</CanonicalRequest>",
        "<RequestId>0A49B4D6E2E0B0A1</RequestId></Error>",
    );

    /// No fragment of [`SIGNATURE_BODY`] may appear in a caller-visible message.
    fn assert_no_signing_material(message: &str) {
        for leaked in [
            "AKIAIOSFODNN7EXAMPLE",
            "bWq2s1WEIj",
            "StringToSign",
            "CanonicalRequest",
            "AWSAccessKeyId",
            "x-amz-date",
            "47 45 54",
            "puppy",
            "signature we calculated",
        ] {
            assert!(
                !message.contains(leaked),
                "message leaked {leaked}: {message}"
            );
        }
    }

    /// A stand-in for a modeled S3 service error. [`map_sdk_error`] is generic
    /// over `E: Debug + ProvideErrorMetadata`, so a fake carries the same two
    /// signals a real operation error does — the modeled code and the `Debug`
    /// rendering — without needing a live client.
    #[derive(Debug)]
    struct FakeServiceError(ErrorMetadata);

    impl ProvideErrorMetadata for FakeServiceError {
        fn meta(&self) -> &ErrorMetadata {
            &self.0
        }
    }

    /// Build a `ServiceError` carrying `body` as its raw response. `code` is the
    /// code the SDK managed to model, or `None` when parsing produced none and
    /// only the `Debug` blob is left to mine.
    fn service_error(
        status: u16,
        code: Option<&str>,
        body: &'static str,
    ) -> SdkError<FakeServiceError> {
        let mut meta = ErrorMetadata::builder();
        if let Some(code) = code {
            meta = meta.code(code);
        }
        let raw = HttpResponse::new(
            status.try_into().expect("valid status"),
            SdkBody::from(body),
        );
        SdkError::service_error(FakeServiceError(meta.build()), raw)
    }

    /// 401 must surface as AuthRequired: that is the code the connection
    /// lifecycle classifies as an auth failure rather than a data error.
    #[test]
    fn map_error_status_401_is_auth_required() {
        let err = map_error_status(401, b"signature mismatch");
        assert_eq!(err.code(), ErrorCode::AuthRequired);
        match err.context() {
            Some(ErrorContext::Auth {
                reason, expired_at, ..
            }) => {
                assert_eq!(reason.as_deref(), Some("s3_unauthorized"));
                assert!(expired_at.is_none());
            }
            other => panic!("expected Auth context, got {other:?}"),
        }
    }

    /// 403 stays PermissionDenied with no Auth context; reauth wouldn't change the outcome.
    #[test]
    fn map_error_status_403_is_permission_denied() {
        let err = map_error_status(403, b"AccessDenied");
        assert_eq!(err.code(), ErrorCode::PermissionDenied);
        assert!(err.context().is_none());
    }

    #[test]
    fn map_error_status_412_is_precondition_failed() {
        let err = map_error_status(412, b"PreconditionFailed");
        assert_eq!(err.code(), ErrorCode::PreconditionFailed);
    }

    #[test]
    fn map_error_status_410_is_not_found() {
        let err = map_error_status(410, b"NoSuchKey");
        assert_eq!(err.code(), ErrorCode::NotFound);
    }

    #[test]
    fn map_error_status_416_is_invalid_argument() {
        let err = map_error_status(416, b"InvalidRange");
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    #[test]
    fn map_error_status_408_504_are_deadline_exceeded() {
        assert_eq!(
            map_error_status(408, b"").code(),
            ErrorCode::DeadlineExceeded
        );
        assert_eq!(
            map_error_status(504, b"").code(),
            ErrorCode::DeadlineExceeded
        );
    }

    #[test]
    fn map_error_status_429_503_are_resource_exhausted() {
        assert_eq!(
            map_error_status(429, b"SlowDown").code(),
            ErrorCode::ResourceExhausted
        );
        assert_eq!(
            map_error_status(503, b"ServiceUnavailable").code(),
            ErrorCode::ResourceExhausted
        );
    }

    #[test]
    fn map_error_status_500_502_are_transient() {
        assert_eq!(map_error_status(500, b"").code(), ErrorCode::Transient);
        assert_eq!(map_error_status(502, b"").code(), ErrorCode::Transient);
    }

    /// Unknown statuses surface as Transient (not Internal): unknown gateway/proxy
    /// errors are still upstream failures, not plugin logic bugs.
    #[test]
    fn map_error_status_unknown_is_transient() {
        assert_eq!(map_error_status(418, b"").code(), ErrorCode::Transient);
    }

    /// The whole point of the sanitizer: a `SignatureDoesNotMatch` body hands
    /// back the string-to-sign, the canonical request and the access key id.
    /// Only the provider code may escape into the message.
    #[test]
    fn map_error_status_signature_body_yields_only_the_provider_code() {
        let err = map_error_status(403, SIGNATURE_BODY.as_bytes());
        assert_eq!(err.code(), ErrorCode::PermissionDenied);
        assert_eq!(
            err.message(),
            "S3 request forbidden (HTTP 403): SignatureDoesNotMatch"
        );
        assert_no_signing_material(err.message());
    }

    /// The modeled-code path: the SDK parsed a code, so it is used directly and
    /// the operation context is preserved next to it.
    #[test]
    fn map_sdk_error_keeps_context_and_modeled_code_only() {
        let err = service_error(403, Some("SignatureDoesNotMatch"), SIGNATURE_BODY);
        let mapped = map_sdk_error("s3 head_object", err);

        assert_eq!(mapped.code(), ErrorCode::PermissionDenied);
        assert_eq!(
            mapped.message(),
            "S3 request forbidden (HTTP 403): s3 head_object: SignatureDoesNotMatch"
        );
        assert_no_signing_material(mapped.message());
    }

    /// The fallback path: when the SDK models no code the body is read through
    /// `body().bytes()` and mined for its `<Code>`. Only that token may
    /// escape — neither the signing material beside it in the document, nor
    /// any `Debug` scaffolding, which an earlier form of this fallback parsed
    /// and which must not come back.
    #[test]
    fn map_sdk_error_without_modeled_code_mines_only_the_code_from_the_body() {
        let err = service_error(403, None, SIGNATURE_BODY);
        // Guard the premise. `bytes()` returns `None` for a body that was never
        // buffered, and the fallback would then silently have nothing to read,
        // so assert the fixture actually presents one.
        assert!(
            err.raw_response()
                .and_then(|raw| raw.body().bytes())
                .is_some_and(|bytes| bytes.starts_with(b"<?xml")),
            "the fixture must present a buffered body for the fallback to read"
        );

        let mapped = map_sdk_error("s3 put_object", err);

        assert_eq!(mapped.code(), ErrorCode::PermissionDenied);
        assert_eq!(
            mapped.message(),
            "S3 request forbidden (HTTP 403): s3 put_object: SignatureDoesNotMatch"
        );
        assert_no_signing_material(mapped.message());
        for scaffolding in ["SdkBody", "ServiceError", "raw:", "inner:", "meta:"] {
            assert!(
                !mapped.message().contains(scaffolding),
                "Debug scaffolding {scaffolding} leaked: {}",
                mapped.message()
            );
        }
    }

    /// An unparseable body leaves nothing to mine, so the context stands alone
    /// rather than the body standing in for it.
    #[test]
    fn map_sdk_error_without_any_recoverable_code_keeps_only_the_context() {
        let err = service_error(500, None, "upstream connect error: 111");
        let mapped = map_sdk_error("SQS ReceiveMessage", err);

        assert_eq!(mapped.code(), ErrorCode::Transient);
        assert_eq!(
            mapped.message(),
            "S3 returned transient HTTP 500: SQS ReceiveMessage"
        );
    }

    /// A body whose 256-byte mark lands mid-UTF-8-sequence is reduced without a
    /// byte-index slice, so it cannot panic — with or without a `<Code>`.
    #[test]
    fn map_error_status_multibyte_body_does_not_panic() {
        let mut body = "a".repeat(255);
        body.push_str(&"é".repeat(200));
        assert!(
            !body.is_char_boundary(256),
            "test body must straddle byte 256"
        );

        let err = map_error_status(500, body.as_bytes());
        assert_eq!(err.code(), ErrorCode::Transient);
        assert_eq!(
            err.message(),
            format!(
                "S3 returned transient HTTP 500: no provider error code; {} byte body suppressed",
                body.len()
            )
        );
        assert!(!err.message().contains('é'), "{}", err.message());

        let wrapped = format!("<Error><Code>SlowDown</Code><Message>{body}</Message></Error>");
        let err = map_error_status(503, wrapped.as_bytes());
        assert_eq!(err.code(), ErrorCode::ResourceExhausted);
        assert_eq!(err.message(), "S3 rate-limited (HTTP 503): SlowDown");
    }

    /// No `<Code>` element means the body is reported by length alone — never
    /// quoted as a fallback, but not silently dropped either.
    #[test]
    fn map_error_status_body_without_code_element_reports_length_only() {
        let body = b"SignatureDoesNotMatch AKIAIOSFODNN7EXAMPLE StringToSign: GET\n\n\n";
        let err = map_error_status(403, body);
        assert_eq!(
            err.message(),
            format!(
                "S3 request forbidden (HTTP 403): no provider error code; {} byte body suppressed",
                body.len()
            )
        );
        for leaked in [
            "AKIAIOSFODNN7EXAMPLE",
            "StringToSign",
            "SignatureDoesNotMatch",
        ] {
            assert!(!err.message().contains(leaked), "{}", err.message());
        }

        // An unterminated `<Code>` must not run to the end of the body either.
        let unterminated = b"<Error><Code>SignatureDoesNotMatch<StringToSign>GET</StringToSign>";
        let err = map_error_status(403, unterminated);
        assert!(
            err.message().contains("no provider error code"),
            "{}",
            err.message()
        );
        assert!(!err.message().contains("StringToSign"), "{}", err.message());
    }

    /// A call site with no captured response passes `b""`; describing that as a
    /// "0 byte body" would report the call site, not the provider, so an empty
    /// body adds no trail.
    #[test]
    fn map_error_status_empty_body_adds_no_trail() {
        assert_eq!(
            map_error_status(403, b"").message(),
            "S3 request forbidden (HTTP 403)"
        );
    }

    /// S3 routes its code extraction through the shared sanitizer rather than
    /// a local copy. The filter's own rules are covered in
    /// `ovstorage_plugin::provider_error`; what this pins is the WIRING, since
    /// a plugin that stopped calling it would still compile.
    #[test]
    fn provider_code_goes_through_the_shared_sanitizer() {
        // Accepted: a clean token inside a `<Code>` element.
        assert_eq!(
            provider_code(b"<Error><Code>SlowDown</Code></Error>").map(|c| c.as_str().to_string()),
            Some("SlowDown".to_string())
        );
        // Rejected whole: signing material sharing the element. A filtering
        // sanitizer would answer `SignatureDoesNotMatchaBcD...`.
        let padded = format!(
            "<Error><Code>SignatureDoesNotMatch {}==</Code></Error>",
            "aB+/cD+/".repeat(16)
        );
        assert!(provider_code(padded.as_bytes()).is_none());
        // Bounded: this is the behaviour S3's own copy lacked, so it is the
        // reason the extraction moved rather than being left alone.
        let far = format!(
            "<Error>{}<Code>SlowDown</Code></Error>",
            " ".repeat(ovstorage_plugin::provider_error::SCAN_LIMIT)
        );
        assert!(provider_code(far.as_bytes()).is_none());
        // Just inside the window it is still recovered, so the case above
        // measures the bound rather than a scanner that never matched.
        let inside = format!(
            "<Error>{}<Code>SlowDown</Code></Error>",
            " ".repeat(ovstorage_plugin::provider_error::SCAN_LIMIT - 64)
        );
        assert_eq!(
            provider_code(inside.as_bytes()).map(|c| c.as_str().to_string()),
            Some("SlowDown".to_string())
        );
    }

    /// The MODELED code path is the preferred source in `map_sdk_error`, and it
    /// is fed from provider-controlled text. Without this, replacing
    /// `SanitizedCode::from_field`'s body with an unfiltered wrap would leave
    /// the suite green — the regression these wiring tests exist to catch.
    #[test]
    fn the_modeled_code_path_goes_through_the_shared_sanitizer() {
        let err = service_error(
            403,
            Some("SignatureDoesNotMatch bWq2s1WEIj+Ydj0vQ697zp+IXMU="),
            SIGNATURE_BODY,
        );
        let mapped = map_sdk_error("s3 get_object", err);
        assert_no_signing_material(mapped.message());
        // The MAC welded onto the modeled code must not ride out on it. The
        // bare code may still appear — the body's own `<Code>` is a clean token
        // and the fallback recovers it — but no fragment of the MAC may.
        for leaked in ["bWq2s1WEIj", "Ydj0vQ697zp", "IXMU"] {
            assert!(
                !mapped.message().contains(leaked),
                "{leaked} survived the modeled-code path: {}",
                mapped.message()
            );
        }
    }

    /// The disclosure the validating rule exists for: signing material sharing
    /// the code element must not survive in any part.
    #[test]
    fn a_signature_inside_the_code_element_does_not_survive() {
        let body = "<Error><Code>SignatureDoesNotMatch bWq2s1WEIj+Ydj0vQ697zp+IXMU=</Code></Error>";
        let err = map_error_status(403, body.as_bytes());
        assert!(
            err.message().contains("no provider error code"),
            "a `<Code>` carrying more than one token must be suppressed: {}",
            err.message()
        );
        for leaked in ["bWq2s1WEIj", "Ydj0vQ697zp", "IXMU", "SignatureDoesNotMatch"] {
            assert!(
                !err.message().contains(leaked),
                "{leaked} survived the sanitizer: {}",
                err.message()
            );
        }
    }

    /// The shared decode formatter reports classification, position and length
    /// — never the offending value, which serde's `Display` would embed as
    /// `invalid type: string "…"`. `parse_notification_body` deserializes a
    /// provider-controlled SQS body, so it is subject to the same guarantee as
    /// an error body.
    #[test]
    fn decode_failure_reports_position_not_the_offending_value() {
        // A wrongly-TYPED field, not a wrongly-shaped document. Deserializing
        // into a type that fails at the outer shape (`invalid type: map,
        // expected a sequence`) never reads the planted string, so the
        // negative assertion below would hold even for a raw `{err}` — it must
        // be a case where serde's `Display` genuinely quotes the value.
        #[derive(Debug, serde::Deserialize)]
        #[allow(dead_code)]
        struct Notification {
            #[serde(rename = "Records")]
            records: Vec<u32>,
        }
        let body = r#"{"Records":"7hK4wQ2mZ9pR1tY6uXbN5cJfA8sVdE3o"}"#;
        let err =
            serde_json::from_str::<Notification>(body).expect_err("a string is not a sequence");
        assert!(
            err.to_string().contains("7hK4wQ"),
            "the premise: serde's Display must quote the planted value, or this \
             test cannot discriminate — got {err}"
        );
        let rendered = decode_failure(&err, body.len());
        assert!(
            rendered.contains(&format!("{} byte body suppressed", body.len())),
            "{rendered}"
        );
        assert!(
            !rendered.contains("7hK4wQ"),
            "the offending value reached the message: {rendered}"
        );
    }

    /// Only the *first* `<Code>` is mined: an `<Error>` document can carry
    /// several, and the leading one is the provider's classification.
    #[test]
    fn provider_code_takes_the_first_code_element() {
        assert_eq!(
            provider_code(b"<Error><Code>NoSuchKey</Code><Code>Ignored</Code></Error>")
                .map(|c| c.as_str().to_string()),
            Some("NoSuchKey".to_string())
        );
        assert!(provider_code(b"plain text, no markup").is_none());
        assert!(provider_code(b"<Error><Code></Code></Error>").is_none());
    }
}
