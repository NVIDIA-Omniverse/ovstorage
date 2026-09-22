// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tamper-evident envelopes for client-driven write continuations.

use hmac::{Hmac, Mac};
use ovstorage::{Error, ErrorCode, Url, WriteRedirectBatch};
use rand::{RngCore, rngs::OsRng};
use sha2::Sha256;

pub(crate) const CONTINUATION_SEAL_TAG: &str = "ovstorage-broker:continuation-seal:1";
const CONTINUATION_SEAL_ERROR: &str = "continuation seal is invalid";
const MAC_LEN: usize = 32;
pub(crate) const CONTINUATION_SEAL_HEADER_LEN: usize = CONTINUATION_SEAL_TAG.len() + MAC_LEN;

type HmacSha256 = Hmac<Sha256>;

/// Process secret used to authenticate client-driven write continuations.
///
/// This type deliberately does not implement `Debug`, so formatting surrounding
/// broker state cannot expose the key material.
#[derive(Clone)]
pub(crate) struct ContinuationSealKey([u8; 32]);

impl ContinuationSealKey {
    /// Generate a fresh key from the operating system's cryptographic RNG.
    pub(crate) fn generate() -> Self {
        let mut bytes = [0_u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Construct a key from at least 32 bytes, using the first 32 as the secret.
    pub(crate) fn from_bytes(bytes: &[u8]) -> ovstorage::Result<Self> {
        if bytes.len() < 32 {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "continuation seal key must contain at least 32 bytes",
            ));
        }

        let mut key = [0_u8; 32];
        key.copy_from_slice(&bytes[..32]);
        Ok(Self(key))
    }
}

/// Internal classification for refusal telemetry. The conversion to the public
/// error deliberately discards this detail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ContinuationSealRefusal {
    Malformed,
    Tag,
    Mac,
}

impl ContinuationSealRefusal {
    pub(crate) const ALL: [Self; 3] = [Self::Malformed, Self::Tag, Self::Mac];

    pub(crate) const fn reason(self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::Tag => "tag",
            Self::Mac => "mac",
        }
    }
}

impl From<ContinuationSealRefusal> for Error {
    fn from(_: ContinuationSealRefusal) -> Self {
        Error::new(ErrorCode::InvalidArgument, CONTINUATION_SEAL_ERROR)
    }
}

/// Replace a plugin continuation with an address-bound authenticated envelope.
pub(crate) fn seal_batch(
    key: &ContinuationSealKey,
    address: &Url,
    mut batch: WriteRedirectBatch,
) -> WriteRedirectBatch {
    let mac = mac_for(key, address, &batch.continuation)
        .finalize()
        .into_bytes();
    let mut envelope = Vec::with_capacity(CONTINUATION_SEAL_HEADER_LEN + batch.continuation.len());
    envelope.extend_from_slice(CONTINUATION_SEAL_TAG.as_bytes());
    envelope.extend_from_slice(&mac);
    envelope.extend_from_slice(&batch.continuation);
    batch.continuation = envelope;
    batch
}

/// Verify and remove an address-bound continuation envelope.
#[cfg(test)]
pub(crate) fn unseal_batch(
    key: &ContinuationSealKey,
    address: &Url,
    batch: WriteRedirectBatch,
) -> ovstorage::Result<WriteRedirectBatch> {
    unseal_batch_with_reason(key, address, batch).map_err(Error::from)
}

/// Verify and remove an envelope while retaining a bounded refusal reason for
/// broker-side telemetry.
pub(crate) fn unseal_batch_with_reason(
    key: &ContinuationSealKey,
    address: &Url,
    mut batch: WriteRedirectBatch,
) -> Result<WriteRedirectBatch, ContinuationSealRefusal> {
    if batch.continuation.len() < CONTINUATION_SEAL_HEADER_LEN {
        return Err(ContinuationSealRefusal::Malformed);
    }

    let tag_len = CONTINUATION_SEAL_TAG.len();
    if &batch.continuation[..tag_len] != CONTINUATION_SEAL_TAG.as_bytes() {
        return Err(ContinuationSealRefusal::Tag);
    }

    let supplied_mac = &batch.continuation[tag_len..CONTINUATION_SEAL_HEADER_LEN];
    let inner = &batch.continuation[CONTINUATION_SEAL_HEADER_LEN..];
    mac_for(key, address, inner)
        .verify_slice(supplied_mac)
        .map_err(|_| ContinuationSealRefusal::Mac)?;

    batch.continuation.drain(..CONTINUATION_SEAL_HEADER_LEN);
    Ok(batch)
}

fn mac_for(key: &ContinuationSealKey, address: &Url, inner: &[u8]) -> HmacSha256 {
    mac_for_tag(key, CONTINUATION_SEAL_TAG.as_bytes(), address, inner)
}

fn mac_for_tag(key: &ContinuationSealKey, tag: &[u8], address: &Url, inner: &[u8]) -> HmacSha256 {
    let mut mac = HmacSha256::new_from_slice(&key.0)
        .expect("HMAC-SHA256 accepts a key of any non-zero length");
    let tag_len = u64::try_from(tag.len()).expect("the fixed seal tag has a u64 length");
    mac.update(&tag_len.to_be_bytes());
    mac.update(tag);
    let address = address.as_str().as_bytes();
    let address_len =
        u64::try_from(address.len()).expect("a URL represented in memory has a u64 length");
    mac.update(&address_len.to_be_bytes());
    mac.update(address);
    mac.update(inner);
    mac
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(fill: u8) -> ContinuationSealKey {
        ContinuationSealKey::from_bytes(&[fill; 32]).expect("32-byte test key is valid")
    }

    fn address(value: &str) -> Url {
        Url::parse(value).expect("test URL is valid")
    }

    fn batch(continuation: &[u8]) -> WriteRedirectBatch {
        WriteRedirectBatch {
            continuation: continuation.to_vec(),
            redirects: Vec::new(),
        }
    }

    fn assert_refused(result: ovstorage::Result<WriteRedirectBatch>) {
        let error = result.expect_err("altered or foreign continuation must be refused");
        assert_eq!(error.code(), ErrorCode::InvalidArgument);
        assert_eq!(error.message(), CONTINUATION_SEAL_ERROR);
    }

    fn assert_refusal_reason(
        result: Result<WriteRedirectBatch, ContinuationSealRefusal>,
        expected: ContinuationSealRefusal,
    ) {
        assert_eq!(
            result.expect_err("altered or foreign continuation must be refused"),
            expected
        );
    }

    #[test]
    fn round_trip_restores_arbitrary_continuation_bytes() {
        let key = ContinuationSealKey::generate();
        let address = address("s3://bucket/object");
        let original = batch(&[0, 1, 2, 127, 128, 254, 255]);

        let sealed = seal_batch(&key, &address, original.clone());
        assert_ne!(sealed.continuation, original.continuation);
        assert_eq!(
            sealed.continuation.len(),
            original.continuation.len() + CONTINUATION_SEAL_HEADER_LEN,
            "the compact envelope adds only its fixed-size header"
        );
        assert_eq!(
            &sealed.continuation[..CONTINUATION_SEAL_TAG.len()],
            CONTINUATION_SEAL_TAG.as_bytes()
        );
        assert_eq!(
            unseal_batch(&key, &address, sealed).expect("valid seal verifies"),
            original
        );
    }

    #[test]
    fn one_byte_inner_tamper_is_refused() {
        let key = key(1);
        let address = address("s3://bucket/object");
        let mut sealed = seal_batch(&key, &address, batch(b"secret plugin continuation"));
        sealed.continuation[CONTINUATION_SEAL_HEADER_LEN] ^= 1;

        assert_refusal_reason(
            unseal_batch_with_reason(&key, &address, sealed),
            ContinuationSealRefusal::Mac,
        );
    }

    #[test]
    fn one_byte_mac_tamper_is_refused() {
        let key = key(2);
        let address = address("s3://bucket/object");
        let mut sealed = seal_batch(&key, &address, batch(b"plugin continuation"));
        sealed.continuation[CONTINUATION_SEAL_TAG.len()] ^= 1;

        assert_refusal_reason(
            unseal_batch_with_reason(&key, &address, sealed),
            ContinuationSealRefusal::Mac,
        );
    }

    #[test]
    fn version_tag_is_authenticated_by_the_mac() {
        let key = key(9);
        let address = address("s3://bucket/object");
        let inner = b"plugin continuation";
        let v1_mac = mac_for(&key, &address, inner).finalize().into_bytes();
        let v2_tag = b"ovstorage-broker:continuation-seal:2";

        assert!(
            mac_for_tag(&key, v2_tag, &address, inner)
                .verify_slice(&v1_mac)
                .is_err(),
            "a MAC minted for envelope version 1 must not verify as version 2"
        );
    }

    #[test]
    fn unsupported_tag_has_a_bounded_refusal_reason() {
        let key = key(10);
        let address = address("s3://bucket/object");
        let mut sealed = seal_batch(&key, &address, batch(b"plugin continuation"));
        sealed.continuation[CONTINUATION_SEAL_TAG.len() - 1] = b'2';

        assert_refusal_reason(
            unseal_batch_with_reason(&key, &address, sealed),
            ContinuationSealRefusal::Tag,
        );
    }

    #[test]
    fn wrong_address_is_refused() {
        let key = key(3);
        let issued_for = address("s3://bucket/authorized");
        let substituted = address("s3://bucket/substituted");
        let sealed = seal_batch(&key, &issued_for, batch(b"plugin continuation"));

        assert_refusal_reason(
            unseal_batch_with_reason(&key, &substituted, sealed),
            ContinuationSealRefusal::Mac,
        );
    }

    #[test]
    fn wrong_key_is_refused() {
        let address = address("s3://bucket/object");
        let sealed = seal_batch(&key(4), &address, batch(b"plugin continuation"));

        assert_refusal_reason(
            unseal_batch_with_reason(&key(5), &address, sealed),
            ContinuationSealRefusal::Mac,
        );
    }

    #[test]
    fn raw_plugin_continuation_is_refused_without_leaking_it() {
        let raw = br#"{"tag":"ovstorage-plugin-s3:multipart:1","upload_id":"do-not-echo"}"#;
        let result = unseal_batch(&key(6), &address("s3://bucket/object"), batch(raw));

        assert_refused(result);
    }

    #[test]
    fn truncated_envelope_has_a_bounded_refusal_reason() {
        let result = unseal_batch_with_reason(
            &key(11),
            &address("s3://bucket/object"),
            batch(CONTINUATION_SEAL_TAG.as_bytes()),
        );

        assert_refusal_reason(result, ContinuationSealRefusal::Malformed);
        assert_eq!(
            Error::from(ContinuationSealRefusal::Malformed).message(),
            CONTINUATION_SEAL_ERROR,
            "the client-facing error must not disclose the refusal reason"
        );
    }

    #[test]
    fn empty_inner_continuation_round_trips() {
        let key = key(7);
        let address = address("file:///tmp/object");
        let original = batch(&[]);
        let sealed = seal_batch(&key, &address, original.clone());

        assert_eq!(
            unseal_batch(&key, &address, sealed).expect("empty continuation seal verifies"),
            original
        );
    }

    #[test]
    fn address_length_prefix_prevents_boundary_ambiguity() {
        let key = key(8);
        let short_address = address("file:///a");
        let long_address = address("file:///ab");
        let short_inner = b"b-tail";
        let long_inner = b"-tail";
        assert_eq!(
            [short_address.as_str().as_bytes(), short_inner].concat(),
            [long_address.as_str().as_bytes(), long_inner].concat(),
            "the unprefixed inputs must be ambiguous for this probe"
        );

        let mut sealed = seal_batch(&key, &short_address, batch(short_inner));
        sealed
            .continuation
            .splice(CONTINUATION_SEAL_HEADER_LEN.., long_inner.iter().copied());

        assert_refused(unseal_batch(&key, &long_address, sealed));
    }

    #[test]
    fn short_key_is_refused_without_echoing_key_material() {
        let error = match ContinuationSealKey::from_bytes(b"short-secret-do-not-echo") {
            Ok(_) => panic!("short key must be refused"),
            Err(error) => error,
        };

        assert_eq!(error.code(), ErrorCode::InvalidArgument);
        assert!(error.message().contains("continuation seal"));
        assert!(!error.message().contains("do-not-echo"));
    }
}
