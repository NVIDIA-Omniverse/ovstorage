// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Integration coverage for converting ovstorage errors into envelopes.

use ovstorage_envelope::{Envelope, EnvelopeError};
use ovstorage_plugin::{Error, ErrorCode};

#[test]
fn envelope_error_from_rust_error_preserves_code_and_next_action() {
    let rust_err = Error::new(ErrorCode::NotConfigured, "backend kind is not registered")
        .with_next_action("Load the backend plugin via library.load_plugin(path).");
    let env_err: EnvelopeError = (&rust_err).into();
    assert_eq!(env_err.code, "NotConfigured");
    assert!(!env_err.retryable);
    assert_eq!(
        env_err.next_action.as_deref(),
        Some("Load the backend plugin via library.load_plugin(path).")
    );
    assert!(env_err.message.contains("backend kind is not registered"));
}

#[test]
fn envelope_error_from_transient_marks_retryable() {
    let rust_err = Error::new(ErrorCode::Transient, "tcp connection reset");
    let env_err: EnvelopeError = (&rust_err).into();
    assert_eq!(env_err.code, "Transient");
    assert!(env_err.retryable);
    assert!(env_err.next_action.is_none());
}

#[test]
fn envelope_failure_with_rust_error_round_trips() {
    let rust_err = Error::new(ErrorCode::NoRoute, "no route matches address")
        .with_next_action("Call library.add_connection(...) for this prefix.");
    let env: Envelope<serde_json::Value> =
        Envelope::err("stat", (&rust_err).into()).with_resource("s3://nowhere/x");
    let json = serde_json::to_string(&env).unwrap();
    let parsed: Envelope<serde_json::Value> = serde_json::from_str(&json).unwrap();
    assert!(!parsed.ok);
    let err = parsed.error.unwrap();
    assert_eq!(err.code, "NoRoute");
    assert!(!err.retryable);
    assert_eq!(
        err.next_action.as_deref(),
        Some("Call library.add_connection(...) for this prefix.")
    );
    assert_eq!(parsed.resource.as_deref(), Some("s3://nowhere/x"));
}

#[test]
fn envelope_redacts_signed_url_in_error_message_via_error_construction() {
    let rust_err = Error::new(
        ErrorCode::Transient,
        "fetch failed from https://bucket.s3.amazonaws.com/k?X-Amz-Signature=SECRET",
    );
    let env_err: EnvelopeError = (&rust_err).into();
    assert!(
        env_err.message.contains("X-Amz-Signature=REDACTED"),
        "{}",
        env_err.message
    );
    assert!(!env_err.message.contains("SECRET"), "{}", env_err.message);
}
