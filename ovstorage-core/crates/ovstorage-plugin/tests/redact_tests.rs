// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for the redact module's public surface.

use ovstorage_plugin::{REDACTED_QUERY_KEYS, Url, redact_message, redact_url};

#[test]
fn public_api_redact_url_works() {
    let url = Url::parse("https://example.com/p?X-Amz-Signature=abc&keep=this").unwrap();
    let scrubbed = redact_url(&url);
    assert!(scrubbed.contains("X-Amz-Signature=REDACTED"));
    assert!(scrubbed.contains("keep=this"));
    assert!(!scrubbed.contains("abc"));
}

#[test]
fn public_api_redact_message_works() {
    let scrubbed = redact_message("see https://example.com/p?sig=xyz now");
    assert!(scrubbed.contains("sig=REDACTED"));
    assert!(!scrubbed.contains("xyz"));
}

#[test]
fn redacted_query_keys_contains_known_providers() {
    let names: Vec<&str> = REDACTED_QUERY_KEYS.to_vec();
    assert!(names.contains(&"X-Amz-Signature"));
    assert!(names.contains(&"sig"));
    assert!(names.contains(&"X-Goog-Signature"));
}
