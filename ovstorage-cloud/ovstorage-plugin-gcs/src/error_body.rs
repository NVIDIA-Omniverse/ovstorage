// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Allowlist sanitizer for GCS provider error bodies.
//!
//! The invariant this module exists to hold: the provider response body is
//! never interpolated into error text. Only an allowlisted token escapes — the
//! canonical JSON `error.status`, the legacy `errors[].reason`, or the XML-API
//! `<Code>` — filtered to a conservative character set and length-capped.
//! A GCS failure body carries free-form provider text: a signed-URL rejection
//! echoes back `X-Goog-Signature` material and an OAuth failure can quote the
//! offending `Bearer ya29.…` token, so a body that reached an exception would
//! put credential-derived material into every log that renders it.
//!
//! Everything here filters by character rather than slicing by byte index, so
//! the length cap is boundary-safe on multi-byte UTF-8 bodies by construction.

use ovstorage_plugin::provider_error;

/// Describe a provider error body without quoting it.
///
/// Returns `code=<token>` when an allowlisted provider error code is
/// recoverable and a neutral suppression note otherwise. No other slice of the
/// body is ever returned: a GCS failure body carries free-form provider text —
/// a signed-URL rejection echoes back `X-Goog-Signature` query material, and an
/// OAuth failure can quote the offending `Bearer ya29.…` token — so a body that
/// reached an error message would put credential-derived material into every
/// log that renders it.
///
/// The free-form `/error/message` is deliberately not allowlisted: it is
/// exactly the field the provider fills with echoed request material.
pub(crate) fn provider_detail(body: &str) -> String {
    match extract_token(body) {
        Some(token) => format!("code={token}"),
        None => format!(
            "no provider error code; {} byte body suppressed",
            body.len()
        ),
    }
}

/// Recover the code by applying exactly ONE grammar: the body's own format
/// selects the parser rather than both being tried in turn.
///
/// One grammar and no fallback is what makes markup inside a JSON string value
/// inert. A Google JSON error's `message` is free-form provider text — the
/// field an echoed request lands in — so a parser that could fall through to
/// the XML scan would report a `<Code>` element sitting inside `message` as the
/// authoritative provider code whenever `error.status` and `errors[0].reason`
/// were absent or rejected. Dispatching on the first non-whitespace character
/// means a JSON body is only ever read through its pointers.
///
/// A body that is neither shape yields nothing, rather than being scanned as
/// XML on the chance a `<Code>` turns up in it.
///
/// `a_code_element_inside_a_json_message_is_not_echoed` holds both halves.
fn extract_token(body: &str) -> Option<String> {
    match body.trim_start().chars().next()? {
        '{' => json_error_token(body),
        '<' => xml_code_token(body),
        _ => None,
    }
}

/// Describe a JSON decode failure without rendering the offending value.
///
/// serde's `Display` embeds it — on a type mismatch the rendering is
/// `invalid type: string "…"`, which puts a slice of the provider response
/// into the message. The classification, the position and the body length
/// keep the failure diagnosable without quoting a byte of it.
///
/// Shared by every site in this crate that deserializes a provider response,
/// so the guarantee is a property of the crate rather than of one call site.
pub(crate) fn decode_failure(err: &serde_json::Error, body_len: usize) -> String {
    format!(
        "{:?} at line {} column {} ({body_len} byte body suppressed)",
        err.classify(),
        err.line(),
        err.column()
    )
}

/// Mine the provider code out of a Google JSON error document, which is
/// `{"error":{"code":…,"status":"PERMISSION_DENIED","message":…,"errors":[{"reason":"forbidden",…}]}}`.
/// The canonical `status` enum is preferred; the legacy JSON-API `reason` is the
/// fallback for the older shape that omits it.
/// Bounded to [`provider_error::SCAN_LIMIT`]: parsing builds a whole `serde_json::Value` tree,
/// so an endpoint answering a failed request with a multi-megabyte document
/// would otherwise allocate well beyond the already buffered body on every
/// failure — to recover a token of at most [`provider_error::MAX_TOKEN_CHARS`]. A body
/// truncated by the window fails to parse and falls through to the length-only
/// note, which is the right answer for an error document that size.
///
/// The window is taken over BYTES rather than by slicing the `&str`, so a limit
/// landing inside a multi-byte sequence cannot panic; `from_slice` does its own
/// UTF-8 validation and a split sequence simply fails to parse.
fn json_error_token(body: &str) -> Option<String> {
    let bytes = body.as_bytes();
    let window = bytes.get(..provider_error::SCAN_LIMIT).unwrap_or(bytes);
    let value: serde_json::Value = serde_json::from_slice(window).ok()?;
    pointer_token(&value, "/error/status")
        .or_else(|| pointer_token(&value, "/error/errors/0/reason"))
}

fn pointer_token(value: &serde_json::Value, pointer: &str) -> Option<String> {
    provider_error::validate_code_token(value.pointer(pointer)?.as_str()?.as_bytes())
}

/// The GCS XML API (and a rejected signed URL) answers with
/// `<Error><Code>…</Code><Message>…</Message></Error>`, where the message can
/// quote the offending canonical request. Only the `<Code>` child of the root
/// element is recovered, and only through
/// [`provider_error::validate_code_token`]. Hand-rolled scanning rather than a
/// parser so this crate takes on no XML dependency.
fn xml_code_token(body: &str) -> Option<String> {
    provider_error::xml_code(body.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::map_status_to_error;
    use ovstorage_plugin::{ErrorCode, ErrorContext};

    /// A Google JSON error keeps the canonical `status` enum and drops the
    /// free-form `message`, which is where the provider echoes request material.
    #[test]
    fn provider_detail_keeps_google_status_and_drops_the_message() {
        let body = r#"{"error":{"code":403,"status":"PERMISSION_DENIED",
            "message":"caller does not have storage.objects.get on gs://bucket/secret-key.bin"}}"#;
        assert_eq!(provider_detail(body), "code=PERMISSION_DENIED");

        let err = map_status_to_error(403, body);
        assert_eq!(err.code(), ErrorCode::PermissionDenied);
        assert!(err.message().contains("PERMISSION_DENIED"));
        assert!(!err.message().contains("secret-key.bin"));
    }

    /// The legacy JSON-API shape carries no `status`, so the first `errors[]`
    /// entry's `reason` is the fallback token.
    #[test]
    fn provider_detail_falls_back_to_the_first_error_reason() {
        let body = r#"{"error":{"code":403,"message":"Forbidden",
            "errors":[{"domain":"global","reason":"forbidden","message":"Access denied."}]}}"#;
        assert_eq!(provider_detail(body), "code=forbidden");
    }

    /// The XML API / signed-URL failure shape yields its `<Code>` token, and the
    /// `<StringToSign>` and `X-Goog-Signature` material alongside it does not
    /// reach the message.
    #[test]
    fn provider_detail_keeps_xml_code_and_drops_the_signature() {
        let body = concat!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error>",
            "<Code>SignatureDoesNotMatch</Code>",
            "<Message>Access denied.</Message>",
            "<StringToSign>GOOG4-RSA-SHA256\n20231114T221320Z\n</StringToSign>",
            "<SignatureProvided>X-Goog-Signature=4a7f0b91cc</SignatureProvided>",
            "</Error>",
        );
        assert_eq!(provider_detail(body), "code=SignatureDoesNotMatch");

        let message = map_status_to_error(403, body).message().to_string();
        assert!(message.contains("SignatureDoesNotMatch"));
        assert!(!message.contains("X-Goog-Signature"));
        assert!(!message.contains("GOOG4-RSA-SHA256"));
        assert!(!message.contains("4a7f0b91cc"));
    }

    /// An OAuth rejection that quotes the offending bearer token must not carry
    /// it into the 401 message, which is the arm the host logs on every
    /// credential refresh.
    #[test]
    fn provider_detail_never_leaks_a_bearer_token() {
        let body = r#"{"error":{"code":401,"status":"UNAUTHENTICATED",
            "message":"Invalid Credentials: Bearer ya29.a0AfB_secret_access_token_material"}}"#;
        let err = map_status_to_error(401, body);
        assert_eq!(err.code(), ErrorCode::AuthRequired);
        assert!(err.message().contains("UNAUTHENTICATED"));
        assert!(!err.message().contains("ya29."));
        assert!(!err.message().contains("Bearer"));
        // The Auth context is unchanged. Nothing in the connection lifecycle
        // reads it — it is carried for the broker, which serializes it across
        // the wire so a remote caller sees the same typed payload.
        match err.context() {
            Some(ErrorContext::Auth { reason, .. }) => {
                assert_eq!(reason.as_deref(), Some("gcs_unauthorized"));
            }
            other => panic!("expected Auth context, got {other:?}"),
        }
    }

    /// A body with no recoverable code is reported by length only, never quoted.
    #[test]
    fn provider_detail_suppresses_a_body_without_a_code() {
        let body = "AccessDenied: Bearer ya29.leaked / X-Goog-Signature=deadbeef";
        let detail = provider_detail(body);
        assert_eq!(
            detail,
            format!(
                "no provider error code; {} byte body suppressed",
                body.len()
            )
        );
        assert!(!detail.contains("ya29."));
        assert!(!detail.contains("X-Goog-Signature"));
    }

    /// Multi-byte and over-long values are judged, never sliced, so nothing
    /// here can panic -- and a code with foreign text appended is suppressed
    /// rather than truncated back to the code it started with.
    #[test]
    fn provider_detail_handles_multi_byte_bodies_without_panicking() {
        let padded = "é".repeat(4096);
        assert!(
            provider_detail(&padded).starts_with("no provider error code;"),
            "a body of non-allowlisted characters yields no token"
        );

        let xml =
            format!("<Error><Code>NoSuchKey{padded}</Code><Message>{padded}</Message></Error>");
        let detail = provider_detail(&xml);
        assert!(detail.starts_with("no provider error code;"), "{detail}");
        assert!(!detail.contains("NoSuchKey"), "{detail}");

        let json = format!(r#"{{"error":{{"status":"NOT_FOUND{padded}","message":"{padded}"}}}}"#);
        let detail = provider_detail(&json);
        assert!(detail.starts_with("no provider error code;"), "{detail}");
        assert!(!detail.contains("NOT_FOUND"), "{detail}");

        // Over the cap: rejected whole rather than truncated to a prefix.
        let long = format!("<Error><Code>{}</Code></Error>", "a".repeat(4096));
        assert!(provider_detail(&long).starts_with("no provider error code;"));
    }

    /// The disclosure the validating rule exists for: signature material
    /// sharing the `status` field must not survive in any part. An invalid
    /// candidate falls through to the next one rather than being patched up.
    #[test]
    fn a_signature_inside_the_status_field_does_not_survive() {
        let body = concat!(
            r#"{"error":{"code":403,"#,
            r#""status":"PERMISSION_DENIED X-Goog-Signature=4a7f0b91cc","#,
            r#""message":"Access denied."}}"#,
        );
        let detail = provider_detail(body);
        assert!(detail.starts_with("no provider error code;"), "{detail}");
        for leaked in ["4a7f0b91cc", "X-Goog-Signature", "PERMISSION_DENIED"] {
            assert!(!detail.contains(leaked), "{leaked} survived: {detail}");
        }
    }

    /// The JSON parse is bounded, so an oversized error document is never
    /// expanded into a full `Value` tree for the sake of a token of at most
    /// [`provider_error::MAX_TOKEN_CHARS`]. The truncated body fails to parse and falls
    /// through to the length-only note.
    #[test]
    fn json_token_beyond_scan_window_is_not_extracted() {
        let padding = "p".repeat(provider_error::SCAN_LIMIT);
        let body = format!(r#"{{"error":{{"message":"{padding}","status":"NOT_FOUND"}}}}"#);
        assert!(body.len() > provider_error::SCAN_LIMIT);
        let detail = provider_detail(&body);
        assert!(detail.starts_with("no provider error code;"), "{detail}");
        assert!(!detail.contains("NOT_FOUND"), "{detail}");
    }

    /// Truncating the window must never panic, even when the limit lands inside
    /// a multi-byte sequence — the window is taken over bytes for that reason.
    ///
    /// The fixture is valid JSON so the format dispatch selects
    /// `json_error_token`, which is the ONLY function that slices at
    /// `provider_error::SCAN_LIMIT`. A body starting with any other character takes the
    /// `_ => None` arm and never reaches the scanner, so it could not catch a
    /// regression that reintroduced `&body[..provider_error::SCAN_LIMIT]` there.
    #[test]
    fn a_multi_byte_body_straddling_the_scan_window_does_not_panic() {
        // Pad inside a JSON string value with two-byte 'é', sized so byte
        // provider_error::SCAN_LIMIT lands mid-sequence.
        let prefix = r#"{"error":{"message":""#;
        let padding = "é".repeat(provider_error::SCAN_LIMIT);
        let body = format!(r#"{prefix}{padding}","status":"NOT_FOUND"}}}}"#);
        assert!(
            !body.is_char_boundary(provider_error::SCAN_LIMIT),
            "the fixture only pins the panic if byte provider_error::SCAN_LIMIT is mid-sequence"
        );
        assert!(
            body.trim_start().starts_with('{'),
            "the fixture must reach `json_error_token` to pin its slicing"
        );
        // Truncated mid-sequence, so it fails to parse and falls through.
        assert!(provider_detail(&body).starts_with("no provider error code;"));
    }

    /// A `<Code>` element inside a JSON body's FREE-FORM message is inert.
    ///
    /// A parser that fell through to the XML scan would answer this
    /// `code=AKIAIOSFODNN7EXAMPLE` — provider message text presented as the
    /// authoritative code — because neither `error.status` nor
    /// `errors[0].reason` is present to satisfy the JSON grammar first.
    #[test]
    fn a_code_element_inside_a_json_message_is_not_echoed() {
        let body = r#"{"error":{"code":403,"message":"<Code>AKIAIOSFODNN7EXAMPLE</Code>"}}"#;
        let detail = provider_detail(body);
        assert!(detail.starts_with("no provider error code;"), "{detail}");
        assert!(!detail.contains("AKIAIOSFODNN7EXAMPLE"), "{detail}");

        // A real status beside the injected markup still wins, and the markup
        // contributes nothing.
        let with_status = r#"{"error":{"status":"NOT_FOUND","message":"<Code>Injected</Code>"}}"#;
        assert_eq!(provider_detail(with_status), "code=NOT_FOUND");
    }

    /// A body that is neither JSON nor XML is not scanned on the chance a
    /// `<Code>` turns up somewhere inside it.
    #[test]
    fn a_body_of_neither_shape_is_not_scanned() {
        let body = "upstream connect error <Code>Injected</Code>";
        let detail = provider_detail(body);
        assert!(detail.starts_with("no provider error code;"), "{detail}");
        assert!(!detail.contains("Injected"), "{detail}");
    }

    /// The shared decode formatter reports classification, position and length
    /// — never the offending value, which serde's `Display` would embed.
    #[test]
    fn decode_failure_reports_position_not_the_offending_value() {
        let body = r#"{"temporaryHold":"7hK4wQ2mZ9pR1tY6uXbN5cJfA8sVdE3o"}"#;
        let err = serde_json::from_str::<crate::parse::GcsObject>(body)
            .expect_err("a wrongly-typed field is an error");
        let rendered = decode_failure(&err, body.len());
        assert!(
            rendered.contains(&format!("{} byte body suppressed", body.len())),
            "{rendered}"
        );
        assert!(rendered.contains("Data"), "{rendered}");
        assert!(
            !rendered.contains("7hK4wQ"),
            "the offending value reached the message: {rendered}"
        );
    }

    /// GCS routes both of its extraction paths through the shared sanitizer
    /// rather than a local copy. The filter's own rules are covered in
    /// `ovstorage_plugin::provider_error`; what this pins is the WIRING, since
    /// a path that stopped calling it would still compile.
    #[test]
    fn both_extraction_paths_go_through_the_shared_sanitizer() {
        // JSON: the canonical status is recovered.
        assert_eq!(
            extract_token(r#"{"error":{"status":"NOT_FOUND"}}"#).as_deref(),
            Some("NOT_FOUND")
        );
        // JSON: a status carrying signing material is rejected WHOLE. A
        // filtering sanitizer would answer `PERMISSIONDENIEDXGoogSignature...`.
        assert!(
            extract_token(r#"{"error":{"status":"PERMISSION_DENIED X-Goog-Signature=4a7f"}}"#)
                .is_none()
        );
        // XML: a clean code is recovered.
        assert_eq!(
            extract_token("<Error><Code>SlowDown</Code></Error>").as_deref(),
            Some("SlowDown")
        );
        // XML: bounded now. The local scan this replaced walked the whole body,
        // so this case previously found the code however far in it sat.
        //
        // The padding sits INSIDE the root element deliberately: a bare
        // `<Code>` with no root is rejected on structure alone, which would
        // make this assertion pass with the bound removed.
        let far = format!(
            "<Error>{}<Code>SlowDown</Code></Error>",
            " ".repeat(provider_error::SCAN_LIMIT)
        );
        assert!(extract_token(&far).is_none());
        // Just inside the window it is still recovered, so the case above
        // measures the bound rather than a scanner that never matched.
        let inside = format!(
            "<Error>{}<Code>SlowDown</Code></Error>",
            " ".repeat(provider_error::SCAN_LIMIT - 64)
        );
        assert_eq!(extract_token(&inside).as_deref(), Some("SlowDown"));
    }
}
