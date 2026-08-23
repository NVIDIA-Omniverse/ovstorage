// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Allowlist sanitizer for Azure provider error bodies.
//!
//! The invariant this module exists to hold: the provider response body is
//! never interpolated into error text. Only allowlisted tokens escape — the
//! `<Code>` (Blob XML) or `error.code` (ADLS Gen2 DFS JSON) value, filtered to
//! a conservative character set and length-capped, plus the server-generated
//! `x-ms-request-id` correlation GUID. An `AuthenticationFailed` body echoes
//! back the request MAC and the canonical string-to-sign inside
//! `<AuthenticationErrorDetail>`, so a body that reached an exception would put
//! credential-derived material into every log that renders it; routing the body
//! through this module means it cannot.
//!
//! Everything here works on `&[u8]` and filters to ASCII, so the length cap is
//! boundary-safe by construction — there is no `&str` byte slice anywhere in
//! this module to panic on a multi-byte sequence.

use ovstorage_plugin::provider_error;

/// Accept an `x-ms-request-id` only if it is a CANONICAL GUID: hex groups of
/// exactly 8-4-4-4-12, and nothing else.
///
/// A grammar of its own rather than [`provider_error::validate_code_token`]'s,
/// because the two answer different questions: a GUID legitimately begins with
/// a digit, which a code never does.
///
/// The shape is checked group by group rather than as "hex digits and `-`",
/// because that looser rule admits a bare hex run — and a 32-byte MAC encodes
/// as exactly 64 hex digits. This value is interpolated into `error.message`,
/// so an intermediary controlling the header could otherwise use it to carry
/// credential-derived material straight past the body redaction this module
/// performs. The canonical layout leaves 32 hex digits in fixed positions with
/// no room for a payload; a malformed id is dropped rather than reported.
pub(crate) fn correlation_token(raw: &str) -> Option<String> {
    const GROUPS: [usize; 5] = [8, 4, 4, 4, 12];
    let token = raw.trim();
    let mut groups = token.split('-');
    for width in GROUPS {
        let group = groups.next()?;
        if group.len() != width || !group.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return None;
        }
    }
    // A sixth group means it is not a GUID, whatever the first five looked like.
    groups.next().is_none().then(|| token.to_string())
}

/// Describe a provider error body without quoting it.
///
/// Returns `code=<token>` when an allowlisted provider error code is
/// recoverable — from the Blob XML `<Code>` element or the DFS JSON
/// `/error/code` pointer — and a neutral suppression note otherwise. No other
/// slice of the body is ever returned.
pub(crate) fn provider_detail(body: &[u8], headers: &crate::parse::HeaderMap) -> String {
    match header_code(headers).or_else(|| body_code(body)) {
        Some(token) => format!("code={token}"),
        None => format!(
            "no provider error code; {} byte body suppressed",
            body.len()
        ),
    }
}

/// The `x-ms-error-code` header, which Azure Storage sets on every error
/// response and which `driver.rs` already trusts to decide credential
/// rejection.
///
/// Consulted BEFORE the body, and it is the only source on a HEAD: `stat`
/// issues one, and a HEAD response carries no body at all, so without this
/// every failed `stat` reported `no provider error code; 0 byte body
/// suppressed` and an operator could not tell `AuthenticationFailed` from
/// `AuthorizationPermissionMismatch`. Server-generated and not
/// credential-derived — the same argument this module already makes for
/// `x-ms-request-id` — and it still goes through
/// [`provider_error::validate_code_token`], so an intermediary cannot widen it.
fn header_code(headers: &crate::parse::HeaderMap) -> Option<String> {
    provider_error::validate_code_token(headers.first("x-ms-error-code")?.as_bytes())
}

/// Recover the provider error code from the body, applying exactly ONE grammar:
/// the body's own format selects the parser rather than both being tried in
/// turn.
///
/// One grammar and no fallback is what makes markup inside a JSON string value
/// inert. A DFS JSON body's `message` is free-form provider text — the field an
/// echoed request lands in — so a parser that could reach a `<Code>` element
/// sitting inside it would be reporting attacker-influenced text as the
/// authoritative code, and, if the XML scan came first, in preference to the
/// legitimate `/error/code` beside it. Dispatching on the first non-whitespace
/// byte means a JSON body is only ever read through that pointer.
///
/// A body that is neither shape yields nothing, rather than being scanned as
/// XML on the chance a `<Code>` turns up in it.
///
/// `a_code_element_inside_a_json_message_is_not_echoed` holds both halves.
fn body_code(body: &[u8]) -> Option<String> {
    let window = &body[..body.len().min(provider_error::SCAN_LIMIT)];
    match window.iter().find(|byte| !byte.is_ascii_whitespace())? {
        b'{' => json_code(window),
        b'<' => provider_error::xml_code(window),
        _ => None,
    }
}

/// The `x-ms-request-id` correlation GUID Azure support asks for. It is
/// server-generated and not credential-derived, which is what makes it a safe
/// replacement for the body as the operator's debugging handle.
pub(crate) fn request_id(headers: &crate::parse::HeaderMap) -> Option<String> {
    correlation_token(headers.first("x-ms-request-id")?)
}

/// ADLS Gen2 / DFS endpoints answer with `{"error":{"code":…,"message":…}}`.
///
/// Takes the same [`provider_error::SCAN_LIMIT`] window as the XML scan. Parsing builds a whole
/// `serde_json::Value` tree, so an endpoint that answers a failed request with
/// a multi-megabyte document would otherwise allocate well beyond the already
/// buffered body on every failure — to recover a token of at most
/// [`provider_error::MAX_TOKEN_CHARS`]. A body truncated by the window simply fails to parse
/// and falls through to the length-only note, which is the right answer for an
/// error document that size.
fn json_code(window: &[u8]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(window).ok()?;
    provider_error::validate_code_token(value.pointer("/error/code")?.as_str()?.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::HeaderMap;

    #[test]
    fn xml_code_element_extracts_provider_code() {
        let body = b"<?xml version=\"1.0\"?><Error><Code>AuthenticationFailed</Code><Message>Server failed to authenticate the request.</Message></Error>";
        assert_eq!(
            provider_detail(body, &HeaderMap::new()),
            "code=AuthenticationFailed"
        );
    }

    /// A body that pads the code with signature-looking material is suppressed
    /// WHOLE, rather than filtered down to a token.
    ///
    /// A sanitizer that filtered instead of validating would answer this with
    /// `code=AuthenticationFailedaB/cD...` — the code with the ASCII of the
    /// padding welded onto it, up to the cap. Nothing resembling a MAC may ride
    /// out on the token, so a field that is not a clean code is not reported.
    #[test]
    fn signature_shaped_code_is_suppressed_whole() {
        let padded = format!(
            "<Error><Code>AuthenticationFailed {}==</Code></Error>",
            "aB+/cD+/eF+/gH+/".repeat(8)
        );
        let detail = provider_detail(padded.as_bytes(), &HeaderMap::new());
        assert!(
            detail.starts_with("no provider error code;"),
            "a `<Code>` carrying more than one token must be suppressed: {detail}"
        );
        assert!(!detail.contains("AuthenticationFailed"), "{detail}");
        assert!(!detail.contains("aB"), "{detail}");
    }

    /// The disclosure the validating rule exists for: a real MAC sharing the
    /// code element must not survive in any part.
    #[test]
    fn a_mac_inside_the_code_element_does_not_survive() {
        const MAC: &str = "7hK4wQ2mZ9pR1tY6uXbN5cJfA8sVdE3oH0gL2nT7iU=";
        let body = format!("<Error><Code>AuthenticationFailed {MAC}</Code></Error>");
        let detail = provider_detail(body.as_bytes(), &HeaderMap::new());
        for fragment in [
            "7hK4wQ2mZ9pR",
            "5cJfA8sVdE3o",
            "H0gL2nT7iU",
            "AuthenticationFailed",
        ] {
            assert!(
                !detail.contains(fragment),
                "{fragment} survived the sanitizer: {detail}"
            );
        }
    }

    /// A pretty-printed document indents the element's text, so the value is
    /// trimmed before it is judged -- otherwise every such response would be
    /// suppressed and the code lost for no reason.
    #[test]
    fn a_whitespace_padded_code_is_still_recovered() {
        let body = b"<Error>\n  <Code>\n    BlobNotFound\n  </Code>\n</Error>";
        assert_eq!(
            provider_detail(body, &HeaderMap::new()),
            "code=BlobNotFound"
        );
    }

    #[test]
    fn dfs_json_error_shape_extracts_provider_code() {
        let body =
            br#"{"error":{"code":"PathNotFound","message":"The specified path does not exist."}}"#;
        assert_eq!(
            provider_detail(body, &HeaderMap::new()),
            "code=PathNotFound"
        );
    }

    #[test]
    fn empty_body_reports_neutral_detail() {
        assert_eq!(
            provider_detail(b"", &HeaderMap::new()),
            "no provider error code; 0 byte body suppressed"
        );
    }

    #[test]
    fn non_xml_body_reports_neutral_detail_without_quoting_it() {
        let body = b"SharedKey acct:9f3d1c==\nGET\n\napplication/octet-stream";
        let detail = provider_detail(body, &HeaderMap::new());
        assert_eq!(
            detail,
            format!(
                "no provider error code; {} byte body suppressed",
                body.len()
            )
        );
        assert!(!detail.contains("SharedKey"));
    }

    /// An unterminated `<Code>` yields nothing rather than running to the end
    /// of the body.
    #[test]
    fn unterminated_code_element_reports_neutral_detail() {
        let body = b"<Error><Code>AuthenticationFailed<Message>StringToSign:GET</Message></Error>";
        assert!(provider_detail(body, &HeaderMap::new()).starts_with("no provider error code;"));
    }

    #[test]
    fn request_id_is_read_case_insensitively_and_filtered() {
        let headers =
            HeaderMap::from_pairs([("X-Ms-Request-Id", "8f2a1c4e-0000-4b1a-9c3d-0a1b2c3d4e5f")]);
        assert_eq!(
            request_id(&headers).as_deref(),
            Some("8f2a1c4e-0000-4b1a-9c3d-0a1b2c3d4e5f")
        );
    }

    /// A header value that is not GUID-shaped is not a correlation id, so it is
    /// rejected rather than stripped down to whatever characters survive — a
    /// filtering sanitizer would answer the first of these `abcscriptquoteddef`.
    #[test]
    fn request_id_rejects_a_value_that_is_not_guid_shaped() {
        let headers = HeaderMap::from_pairs([("x-ms-request-id", "abc <script>&\"quoted\" def")]);
        assert!(request_id(&headers).is_none());

        let junk_only = HeaderMap::from_pairs([("x-ms-request-id", "<<>>&&")]);
        assert!(request_id(&junk_only).is_none());
        assert!(request_id(&HeaderMap::new()).is_none());
    }

    /// The canonical 8-4-4-4-12 layout is required, not merely "hex and `-`".
    ///
    /// "Hex digits and `-`" admits a bare 64-character hex run, which is
    /// exactly how a 32-byte request MAC encodes — so under that looser rule a
    /// header-controlling intermediary can carry credential-derived material
    /// into `error.message` past the body redaction. The first case below is
    /// that payload.
    #[test]
    fn request_id_requires_the_canonical_guid_layout() {
        let mac_as_hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let smuggled = HeaderMap::from_pairs([("x-ms-request-id", mac_as_hex)]);
        assert!(
            request_id(&smuggled).is_none(),
            "a bare hex run is a MAC-shaped payload, not a request id"
        );

        for malformed in [
            // Right character set, wrong group widths.
            "1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4be",
            "1b9d6bc-bbfd-4b2d-9b5d-ab8dfbbd4bed",
            // A sixth group.
            "1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed-extra1234567",
            // Non-hex inside a correctly sized group.
            "1b9d6bcz-bbfd-4b2d-9b5d-ab8dfbbd4bed",
            "",
        ] {
            let headers = HeaderMap::from_pairs([("x-ms-request-id", malformed)]);
            assert!(
                request_id(&headers).is_none(),
                "{malformed:?} is not a canonical GUID"
            );
        }

        // The real thing still survives — this is the operator's debugging handle.
        let good =
            HeaderMap::from_pairs([("x-ms-request-id", "1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed")]);
        assert_eq!(
            request_id(&good).as_deref(),
            Some("1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed")
        );
    }

    /// A HEAD response has no body, so `x-ms-error-code` is the only place the
    /// provider code lives. `stat` issues a HEAD, so without the header every
    /// failed `stat` reported `0 byte body suppressed` and an operator could
    /// not tell an authentication failure from an authorization one.
    #[test]
    fn the_error_code_header_carries_the_code_when_there_is_no_body() {
        let headers =
            HeaderMap::from_pairs([("x-ms-error-code", "AuthorizationPermissionMismatch")]);
        assert_eq!(
            provider_detail(b"", &headers),
            "code=AuthorizationPermissionMismatch"
        );

        // Header casing is not significant, as elsewhere in this module.
        let cased = HeaderMap::from_pairs([("X-Ms-Error-Code", "AuthenticationFailed")]);
        assert_eq!(provider_detail(b"", &cased), "code=AuthenticationFailed");
    }

    /// The header goes through the same allowlist as a body code, so an
    /// intermediary cannot widen what reaches the message through it.
    #[test]
    fn the_error_code_header_is_sanitized_like_a_body_code() {
        for hostile in [
            "AuthenticationFailed 7hK4wQ2mZ9pR1tY6uXbN5cJfA8sVdE3o=",
            "<script>alert(1)</script>",
            "",
        ] {
            let headers = HeaderMap::from_pairs([("x-ms-error-code", hostile)]);
            let detail = provider_detail(b"", &headers);
            assert!(
                detail.starts_with("no provider error code;"),
                "{hostile:?} must be rejected: {detail}"
            );
        }
    }

    /// A `<Code>` element inside a JSON body's FREE-FORM message is inert.
    ///
    /// `message` is where the provider echoes the request, so a token mined out
    /// of it is attacker-influenced text reported as the authoritative provider
    /// code. A parser that reached the XML scan on a JSON body would mine this;
    /// reaching it FIRST would also let the embedded token override the
    /// legitimate `/error/code` beside it. Both cases are covered, because they
    /// fail differently — one fabricates a code where there is none, the other
    /// replaces a real one.
    #[test]
    fn a_code_element_inside_a_json_message_is_not_echoed() {
        let no_code = br#"{"error":{"message":"rejected <Code>AKIAIOSFODNN7EXAMPLE</Code>"}}"#;
        let detail = provider_detail(no_code, &HeaderMap::new());
        assert!(detail.starts_with("no provider error code;"), "{detail}");
        assert!(!detail.contains("AKIAIOSFODNN7EXAMPLE"), "{detail}");

        let with_code =
            br#"{"error":{"code":"PathNotFound","message":"see <Code>Injected</Code>"}}"#;
        let detail = provider_detail(with_code, &HeaderMap::new());
        assert_eq!(
            detail, "code=PathNotFound",
            "the JSON pointer is authoritative; markup in `message` is inert"
        );
    }

    /// A body that is neither JSON nor XML is not scanned on the chance a
    /// `<Code>` turns up somewhere inside it.
    #[test]
    fn a_body_of_neither_shape_is_not_scanned() {
        let body = b"upstream connect error <Code>Injected</Code>";
        let detail = provider_detail(body, &HeaderMap::new());
        assert!(detail.starts_with("no provider error code;"), "{detail}");
        assert!(!detail.contains("Injected"), "{detail}");
    }

    /// Azure's JSON and header paths route through the shared sanitizer rather
    /// than a local copy. The filter's own rules are covered centrally in
    /// `ovstorage_plugin::provider_error`; what this pins is the WIRING, since a
    /// path that stopped calling it would still compile.
    ///
    /// Both cases are driven through `provider_detail`, Azure's entry point —
    /// asserting against the shared function directly would pin nothing in this
    /// crate. The XML half is covered by
    /// `a_mac_inside_the_code_element_does_not_survive`.
    #[test]
    fn the_json_and_header_paths_go_through_the_shared_sanitizer() {
        // JSON `/error/code` carrying a MAC beside the code: suppressed WHOLE.
        let hostile = br#"{"error":{"code":"AuthenticationFailed 7hK4wQ2mZ9pR1tY6uXbN5cJfA8sVdE3o=","message":"nope"}}"#;
        let detail = provider_detail(hostile, &HeaderMap::new());
        assert!(detail.starts_with("no provider error code;"), "{detail}");
        for leaked in ["7hK4wQ2m", "Z9pR1tY6", "AuthenticationFailed"] {
            assert!(!detail.contains(leaked), "{leaked} survived: {detail}");
        }
        // ... and a clean one still comes through, so the case above measures
        // the filter rather than a broken parse.
        let clean = br#"{"error":{"code":"BlobNotFound","message":"nope"}}"#;
        assert_eq!(
            provider_detail(clean, &HeaderMap::new()),
            "code=BlobNotFound"
        );

        // The header path is the only source on a HEAD, so it needs the same
        // guard.
        let mut headers = HeaderMap::new();
        headers.insert("x-ms-error-code", "AuthenticationFailed sig=7hK4wQ2m");
        let detail = provider_detail(b"", &headers);
        assert!(detail.starts_with("no provider error code;"), "{detail}");
        assert!(!detail.contains("7hK4wQ2m"), "{detail}");
    }

    /// The window bounds the JSON parse as well as the XML scan, so an
    /// oversized error document is never expanded into a full `Value` tree for
    /// the sake of a token of at most [`provider_error::MAX_TOKEN_CHARS`]. The truncated body
    /// fails to parse and falls through to the length-only note.
    #[test]
    fn json_code_beyond_scan_window_is_not_extracted() {
        let padding = "p".repeat(provider_error::SCAN_LIMIT);
        let body = format!(r#"{{"error":{{"message":"{padding}","code":"PathNotFound"}}}}"#);
        assert!(body.len() > provider_error::SCAN_LIMIT);
        let detail = provider_detail(body.as_bytes(), &HeaderMap::new());
        assert!(detail.starts_with("no provider error code;"), "{detail}");
        assert!(!detail.contains("PathNotFound"), "{detail}");
    }

    /// The scan window bounds the XML search; a code pushed past it falls back
    /// to the neutral detail rather than scanning an arbitrarily large body.
    #[test]
    fn code_beyond_scan_window_is_not_extracted() {
        let mut body = vec![b' '; provider_error::SCAN_LIMIT];
        body.extend_from_slice(b"<Error><Code>BlobNotFound</Code></Error>");
        assert!(provider_detail(&body, &HeaderMap::new()).starts_with("no provider error code;"));
    }
}
