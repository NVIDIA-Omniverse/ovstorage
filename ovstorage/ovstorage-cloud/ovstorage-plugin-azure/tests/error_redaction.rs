// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! End-to-end regression coverage for Azure provider-error redaction.
//!
//! `src/client.rs` unit-tests `map_status_to_error` directly, but the guarantee
//! that matters is the one a caller of the plugin observes. These tests drive a
//! real HTTP response — served over loopback by the fixture below — carrying a
//! realistic Azure `AuthenticationFailed` document whose
//! `<AuthenticationErrorDetail>` echoes the request MAC and the whole canonical
//! string-to-sign, then assert the `Error` that comes back out of a public
//! [`AzureBackend`] method quotes none of it. Anything that renders that error
//! — a log line, a span field, a message to the host — would otherwise be
//! writing credential-derived material.
//!
//! What must survive is the allowlisted provider error-code token: it is what
//! makes the failure diagnosable, and dropping it would trade one defect for
//! another. Both auth-failure HTTP arms are covered, each pinned to the
//! `ErrorCode` its documented contract promises: 401 → `AuthRequired` (the
//! connection lifecycle classifies it as an auth failure) and 403 →
//! `PermissionDenied`. A final case serves a >512-byte multi-byte UTF-8 body,
//! pinning that no length bound in the sanitizer can split a UTF-8 sequence.

use ovstorage_plugin::{ErrorCode, StatOptions};

mod support;
use support::{ProbeResponse, build_backend_with_endpoint, spawn_stat_probe_server, target};

// === Fixture ===

/// The server-generated correlation GUID that replaces the body as the
/// operator's debugging handle.
const REQUEST_ID_HEADER: &str = "x-ms-request-id: 1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed";

/// Distinctive fake base64 MAC. Not a real signature over anything — it exists
/// only so an assertion can prove this exact string never escapes.
const SIGNATURE_MAC: &str = "7hK4wQ2mZ9pR1tY6uXbN5cJfA8sVdE3oH0gL2nT7iU=";

/// The Shared-Key 401/403 document Azure Blob actually returns. The
/// `<AuthenticationErrorDetail>` element is the disclosure: it quotes the MAC
/// the client sent and the full canonical string-to-sign the server computed,
/// which together describe how the request was signed.
const AUTH_FAILED_BODY: &str = concat!(
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>",
    "<Error><Code>AuthenticationFailed</Code>",
    "<Message>Server failed to authenticate the request. Make sure the value of ",
    "Authorization header is formed correctly including the signature.\n",
    "RequestId:1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed\n",
    "Time:2026-06-01T00:00:00.0000000Z</Message>",
    "<AuthenticationErrorDetail>The MAC signature found in the HTTP request ",
    "'7hK4wQ2mZ9pR1tY6uXbN5cJfA8sVdE3oH0gL2nT7iU=' is not the same as any ",
    "computed signature. Server used following string to sign: 'GET\n\n\n\n\n\n\n\n\n\n\n\n",
    "x-ms-date:Mon, 01 Jun 2026 00:00:00 GMT\nx-ms-version:2023-11-03\n",
    "/acct/bkt\ncomp:list\ndelimiter:/\nprefix:missing/'. ",
    "SharedKey acct:7hK4wQ2mZ9pR1tY6uXbN5cJfA8sVdE3oH0gL2nT7iU=",
    "</AuthenticationErrorDetail></Error>"
);

/// Every assertion the disclosure fix owes a caller: the provider code is still
/// there to diagnose with, and no fragment of the signing material is.
fn assert_message_is_redacted(message: &str) {
    assert!(
        message.contains("AuthenticationFailed"),
        "provider error code must survive for diagnosis: {message}"
    );
    // `Server failed to authenticate` and `Authorization` come from the
    // free-form `<Message>` element, not the signing detail: a mapper that
    // dropped `<AuthenticationErrorDetail>` but still quoted `<Message>` would
    // be echoing provider response text, so it must fail here too.
    for leak in [
        SIGNATURE_MAC,
        "StringToSign",
        "string to sign",
        "AuthenticationErrorDetail",
        "SharedKey",
        "x-ms-date",
        "MAC signature",
        "Authorization",
        "Server failed to authenticate",
    ] {
        assert!(
            !message.contains(leak),
            "response body fragment {leak:?} reached the caller-visible error: {message}"
        );
    }
}

// === Tests ===

/// 403 keeps its documented `PermissionDenied` code while the body that carried
/// the MAC and the string-to-sign is reduced to the allowlisted token.
#[tokio::test]
async fn stat_403_error_body_never_reaches_the_caller() {
    let (endpoint, _capture) = spawn_stat_probe_server(
        ProbeResponse::failure(403, "Forbidden", AUTH_FAILED_BODY.to_string())
            .with_header(REQUEST_ID_HEADER),
    );
    let backend = build_backend_with_endpoint("acct", "bkt", &endpoint);

    let err = backend
        .stat(
            target("acct", "bkt", "missing/"),
            StatOptions::default(),
            None,
        )
        .await
        .expect_err("a 403 prefix probe must surface as an error");

    assert_eq!(err.code(), ErrorCode::PermissionDenied);
    assert_message_is_redacted(err.message());
    assert!(
        err.message()
            .contains("request_id=1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed"),
        "the correlation GUID must replace the body as the debugging handle: {}",
        err.message()
    );
}

/// 401 is the arm the issue reports, and the arm the host keys credential
/// invalidation on — `AuthRequired` must be preserved, redaction and all.
#[tokio::test]
async fn stat_401_error_body_never_reaches_the_caller() {
    let (endpoint, _capture) = spawn_stat_probe_server(
        ProbeResponse::failure(401, "Unauthorized", AUTH_FAILED_BODY.to_string())
            .with_header(REQUEST_ID_HEADER),
    );
    let backend = build_backend_with_endpoint("acct", "bkt", &endpoint);

    let err = backend
        .stat(
            target("acct", "bkt", "missing/"),
            StatOptions::default(),
            None,
        )
        .await
        .expect_err("a 401 prefix probe must surface as an error");

    assert_eq!(err.code(), ErrorCode::AuthRequired);
    assert_message_is_redacted(err.message());
}

/// A body whose 512th byte lands mid-sequence: `'é'` is two bytes and `'🔒'` is
/// four. The sanitizer filters to ASCII character by character rather than
/// slicing by byte index, so no length bound can land inside a UTF-8 sequence.
/// Driven end to end, the operation returns an error rather than unwinding, and
/// the multi-byte content stays out of the message.
#[tokio::test]
async fn stat_multi_byte_body_over_truncation_boundary_does_not_panic() {
    // A one-byte ASCII lead-in makes every following 'é' start on an odd
    // offset, so byte 512 falls inside one; the trailing four-byte '🔒' run
    // straddles the boundary too.
    let mut multi_byte_body = String::from("x");
    multi_byte_body.push_str(&"é".repeat(400));
    multi_byte_body.push_str(&"🔒".repeat(64));
    assert!(multi_byte_body.len() > 512);
    assert!(
        !multi_byte_body.is_char_boundary(512),
        "the fixture only pins the panic if byte 512 is mid-sequence"
    );

    let (endpoint, _capture) = spawn_stat_probe_server(ProbeResponse::failure(
        500,
        "Internal Server Error",
        multi_byte_body,
    ));
    let backend = build_backend_with_endpoint("acct", "bkt", &endpoint);

    let err = backend
        .stat(
            target("acct", "bkt", "missing/"),
            StatOptions::default(),
            None,
        )
        .await
        .expect_err("a 500 prefix probe must surface as an error, not a panic");

    assert_eq!(err.code(), ErrorCode::Transient);
    assert!(
        !err.message().contains('é') && !err.message().contains('🔒'),
        "body content leaked: {}",
        err.message()
    );
    assert!(
        err.message().contains("no provider error code"),
        "a body with no recoverable code must be summarized: {}",
        err.message()
    );
}
