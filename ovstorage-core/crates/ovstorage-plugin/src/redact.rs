// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Surgical secret redaction for URLs and arbitrary text.
//!
//! `redact_url` scrubs known secret query parameters and userinfo while
//! preserving debug-useful parameters. `redact_message` scans free-form
//! text for embedded URLs and OAuth bearer literals.

use std::borrow::Cow;
use std::sync::OnceLock;

use regex::{Captures, Regex};

use crate::Url;

/// Query-parameter names whose values are redacted by [`redact_url`].
pub const REDACTED_QUERY_KEYS: &[&str] = &[
    // S3 SigV4.
    "X-Amz-Signature",
    "X-Amz-Credential",
    "X-Amz-SignedHeaders",
    "X-Amz-Security-Token",
    "X-Amz-Date",
    "X-Amz-Expires",
    "X-Amz-Algorithm",
    // Azure SAS.
    "sig",
    "sv",
    "se",
    "st",
    "sp",
    "sip",
    "srt",
    "ss",
    "tn",
    "skoid",
    "sktid",
    "skt",
    "ske",
    "sks",
    "skv",
    // GCS V4 signed URLs.
    "X-Goog-Signature",
    "X-Goog-Credential",
    "X-Goog-SignedHeaders",
    "X-Goog-Date",
    "X-Goog-Expires",
    "X-Goog-Algorithm",
    // Generic token names.
    "signature",
    "token",
    "access_token",
    "id_token",
    "refresh_token",
];

/// Redact userinfo and known secret query values from a URL.
pub fn redact_url(url: &Url) -> String {
    let mut scrubbed = url.clone();
    let _ = scrubbed.set_username("");
    let _ = scrubbed.set_password(None);

    let needs_query_scrub = scrubbed.query_pairs().any(|(key, _)| is_redacted_key(&key));
    if needs_query_scrub {
        let scrubbed_pairs: Vec<(String, String)> = scrubbed
            .query_pairs()
            .map(|(key, value)| {
                if is_redacted_key(&key) {
                    (key.into_owned(), "REDACTED".to_string())
                } else {
                    (key.into_owned(), value.into_owned())
                }
            })
            .collect();
        scrubbed.query_pairs_mut().clear().extend_pairs(
            scrubbed_pairs
                .iter()
                .map(|(key, value)| (key.as_str(), value.as_str())),
        );
    }
    scrubbed.to_string()
}

fn is_redacted_key(key: &str) -> bool {
    REDACTED_QUERY_KEYS
        .iter()
        .any(|known| known.eq_ignore_ascii_case(key))
}

/// Scan arbitrary text for embedded URLs and bearer literals.
pub fn redact_message(text: &str) -> Cow<'_, str> {
    let has_url = text.contains("://");
    let has_bearer = contains_ignore_ascii_case(text, "bearer");
    if !has_url && !has_bearer {
        return Cow::Borrowed(text);
    }

    let url_scrubbed = if has_url {
        Cow::Owned(redact_urls_in_text(text))
    } else {
        Cow::Borrowed(text)
    };

    if has_bearer && bearer_regex().is_match(url_scrubbed.as_ref()) {
        return Cow::Owned(
            bearer_regex()
                .replace_all(url_scrubbed.as_ref(), |captures: &Captures<'_>| {
                    format!("{}REDACTED", &captures[1])
                })
                .into_owned(),
        );
    }

    url_scrubbed
}

fn redact_urls_in_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0usize;
    let bytes = text.as_bytes();

    while cursor < bytes.len() {
        if let Some(end) = scan_url_at(text, cursor) {
            let raw = &text[cursor..end];
            if let Ok(parsed) = Url::parse(raw) {
                out.push_str(&redact_url(&parsed));
            } else {
                out.push_str(raw);
            }
            cursor = end;
            continue;
        }

        let ch_end = next_char_boundary(bytes, cursor);
        out.push_str(&text[cursor..ch_end]);
        cursor = ch_end;
    }

    out
}

fn contains_ignore_ascii_case(haystack: &str, needle: &str) -> bool {
    haystack
        .as_bytes()
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle.as_bytes()))
}

fn bearer_regex() -> &'static Regex {
    static BEARER: OnceLock<Regex> = OnceLock::new();
    BEARER.get_or_init(|| {
        Regex::new(r"(?i)\b(bearer[ \t]+)[^,\s]+").expect("bearer regex should compile")
    })
}

/// If a URL starts at `start`, return the byte index one past its end.
fn scan_url_at(text: &str, start: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let scheme_end = scan_scheme(bytes, start)?;
    if bytes.get(scheme_end)? != &b':' {
        return None;
    }
    if bytes.get(scheme_end + 1)? != &b'/' || bytes.get(scheme_end + 2)? != &b'/' {
        return None;
    }

    let mut end = scheme_end + 3;
    while end < bytes.len() {
        let b = bytes[end];
        if b.is_ascii_whitespace()
            || matches!(
                b,
                b'"' | b'<' | b'>' | b'`' | b'\'' | b')' | b']' | b'}' | b',' | b';'
            )
        {
            break;
        }
        end += 1;
    }

    while end > scheme_end + 3 {
        match bytes[end - 1] {
            b'.' | b',' | b':' | b';' | b'!' | b'?' => end -= 1,
            _ => break,
        }
    }

    Some(end)
}

fn scan_scheme(bytes: &[u8], start: usize) -> Option<usize> {
    let first = *bytes.get(start)?;
    if !first.is_ascii_alphabetic() {
        return None;
    }

    let mut end = start + 1;
    while end < bytes.len() {
        let b = bytes[end];
        if b.is_ascii_alphanumeric() || matches!(b, b'+' | b'.' | b'-') {
            end += 1;
        } else {
            break;
        }
    }

    Some(end)
}

fn next_char_boundary(bytes: &[u8], cursor: usize) -> usize {
    let mut end = cursor + 1;
    while end < bytes.len() && (bytes[end] & 0b1100_0000) == 0b1000_0000 {
        end += 1;
    }
    end
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    #[test]
    fn redact_url_strips_userinfo() {
        let url = parse("https://user:pass@bucket.example.com/path/object");
        assert_eq!(redact_url(&url), "https://bucket.example.com/path/object");
    }

    #[test]
    fn redact_url_s3_sigv4_signature() {
        let url = parse(
            "https://bucket.s3.amazonaws.com/key\
             ?X-Amz-Algorithm=AWS4-HMAC-SHA256\
             &X-Amz-Credential=AKIAEXAMPLE/20260513/us-east-1/s3/aws4_request\
             &X-Amz-Date=20260513T120000Z\
             &X-Amz-Expires=900\
             &X-Amz-SignedHeaders=host\
             &X-Amz-Signature=abcdef1234567890\
             &versionId=keep-this",
        );
        let scrubbed = redact_url(&url);
        assert!(scrubbed.contains("X-Amz-Signature=REDACTED"), "{scrubbed}");
        assert!(scrubbed.contains("X-Amz-Credential=REDACTED"), "{scrubbed}");
        assert!(
            scrubbed.contains("X-Amz-SignedHeaders=REDACTED"),
            "{scrubbed}"
        );
        assert!(scrubbed.contains("versionId=keep-this"), "{scrubbed}");
        assert!(!scrubbed.contains("abcdef1234567890"), "{scrubbed}");
        assert!(!scrubbed.contains("AKIAEXAMPLE"), "{scrubbed}");
    }

    #[test]
    fn redact_url_azure_sas() {
        let url = parse(
            "https://acct.blob.core.windows.net/container/blob\
             ?sv=2022-11-02&ss=b&srt=co&sp=rwdlacx&se=2026-05-14T00:00:00Z\
             &st=2026-05-13T00:00:00Z&spr=https&sig=AbCdEf%2FGhIj",
        );
        let scrubbed = redact_url(&url);
        assert!(scrubbed.contains("sig=REDACTED"), "{scrubbed}");
        assert!(scrubbed.contains("sv=REDACTED"), "{scrubbed}");
        assert!(scrubbed.contains("se=REDACTED"), "{scrubbed}");
        assert!(scrubbed.contains("st=REDACTED"), "{scrubbed}");
        assert!(!scrubbed.contains("AbCdEf"), "{scrubbed}");
    }

    #[test]
    fn redact_url_gcs_v4() {
        let url = parse(
            "https://storage.googleapis.com/bucket/object\
             ?X-Goog-Algorithm=GOOG4-RSA-SHA256\
             &X-Goog-Credential=svc%40proj.iam.gserviceaccount.com%2F20260513%2Fauto%2Fstorage%2Fgoog4_request\
             &X-Goog-Date=20260513T120000Z\
             &X-Goog-Expires=3600\
             &X-Goog-SignedHeaders=host\
             &X-Goog-Signature=deadbeef",
        );
        let scrubbed = redact_url(&url);
        assert!(scrubbed.contains("X-Goog-Signature=REDACTED"), "{scrubbed}");
        assert!(
            scrubbed.contains("X-Goog-Credential=REDACTED"),
            "{scrubbed}"
        );
        assert!(!scrubbed.contains("deadbeef"), "{scrubbed}");
    }

    #[test]
    fn redact_url_preserves_nonsecret_query() {
        let url = parse(
            "https://example.com/path?versionId=7&prefix=foo&list-type=2&X-Amz-Signature=xyz",
        );
        let scrubbed = redact_url(&url);
        assert!(scrubbed.contains("versionId=7"), "{scrubbed}");
        assert!(scrubbed.contains("prefix=foo"), "{scrubbed}");
        assert!(scrubbed.contains("list-type=2"), "{scrubbed}");
        assert!(scrubbed.contains("X-Amz-Signature=REDACTED"), "{scrubbed}");
    }

    #[test]
    fn redact_url_case_insensitive_query_keys() {
        let url = parse("https://example.com/p?x-amz-signature=abc&X-Goog-SIGNATURE=def");
        let scrubbed = redact_url(&url);
        assert!(!scrubbed.contains("abc"), "{scrubbed}");
        assert!(!scrubbed.contains("def"), "{scrubbed}");
    }

    #[test]
    fn redact_url_no_query_unchanged_shape() {
        let url = parse("file:///tmp/object.bin");
        assert_eq!(redact_url(&url), "file:///tmp/object.bin");
    }

    #[test]
    fn redact_message_fast_path_for_plain_text() {
        let plain = "object not found at logical path";
        match redact_message(plain) {
            Cow::Borrowed(s) => assert_eq!(s, plain),
            Cow::Owned(_) => panic!("plain text should return Cow::Borrowed"),
        }
    }

    #[test]
    fn redact_message_scrubs_embedded_signed_url() {
        let msg = "broker fetch failed from \
                   https://bucket.s3.amazonaws.com/key?X-Amz-Signature=abc&versionId=7 \
                   please retry";
        let scrubbed = redact_message(msg);
        assert!(scrubbed.contains("X-Amz-Signature=REDACTED"), "{scrubbed}");
        assert!(scrubbed.contains("versionId=7"), "{scrubbed}");
        assert!(scrubbed.contains("please retry"), "{scrubbed}");
        assert!(!scrubbed.contains("abc"), "{scrubbed}");
    }

    #[test]
    fn redact_message_scrubs_bearer_literal() {
        let msg = "Authorization header was Bearer eyJhbGciOiJI... and rejected";
        let scrubbed = redact_message(msg);
        assert!(scrubbed.contains("Bearer REDACTED"), "{scrubbed}");
        assert!(!scrubbed.contains("eyJhbGciOiJI"), "{scrubbed}");
        assert!(scrubbed.contains("and rejected"), "{scrubbed}");
    }

    #[test]
    fn redact_message_handles_url_with_trailing_punctuation() {
        let msg = "see https://example.com/p?X-Amz-Signature=xyz, then retry.";
        let scrubbed = redact_message(msg);
        assert!(scrubbed.contains("X-Amz-Signature=REDACTED"), "{scrubbed}");
        assert!(scrubbed.contains(", then retry."), "{scrubbed}");
        assert!(!scrubbed.contains("xyz"), "{scrubbed}");
    }

    #[test]
    fn redact_message_handles_userinfo_in_url() {
        let msg = "connect failed to https://user:secret@example.com/path";
        let scrubbed = redact_message(msg);
        assert!(!scrubbed.contains("secret"), "{scrubbed}");
        assert!(!scrubbed.contains("user:"), "{scrubbed}");
        assert!(scrubbed.contains("https://example.com/path"), "{scrubbed}");
    }
}
