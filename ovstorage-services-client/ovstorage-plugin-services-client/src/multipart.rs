// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Continuation-state encoding for `write_redirect` ↔ `continue_write`.
//!
//! The plugin returns one of two flavors of `WriteRedirectBatch`:
//! - **Single redirect** (`SingleRedirect`): one HTTP PUT/POST that the host
//!   follows; finalized by `FileObjectService::CompleteRedirectUpload`.
//! - **Multipart** (`Multipart`): N pre-signed URLs that the host PUTs in
//!   parallel; finalized by `CompleteMultipartUpload` or rolled back via
//!   `AbortMultipartUpload`.
//!
//! Encoding is JSON with a tag string so a foreign-plugin continuation
//! decoded by accident surfaces `InvalidArgument` rather than silent data
//! corruption (S3 plugin does the same; see
//! `ovstorage-plugin-s3/src/multipart.rs`).

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use ovstorage_plugin::{Error, ErrorCode, Result};

const TAG: &str = "ovstorage-plugin-services-client:write-redirect:1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Continuation {
    pub tag: String,
    /// The destination this continuation was minted for. Written to the encoded
    /// form but never read back from it: on the broker's client-driven route the
    /// blob is echoed back by the remote caller, so `finalize_write_redirect`
    /// derives the destination from the authorized request address.
    /// `skip_deserializing` is what makes a caller-supplied destination
    /// unreachable rather than merely unused; it is still serialized so a
    /// continuation minted here stays decodable by a peer replica running an
    /// earlier build while an upload is in flight.
    #[serde(skip_deserializing)]
    pub destination_resource_address: String,
    // Carries opts.message across the redirect roundtrip so finalize can
    // stash it under user_metadata key `x-ov-message` after success.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    // Carries opts.user_metadata across the redirect roundtrip so finalize can
    // stash entries via the metadata service after success.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_metadata: Option<HashMap<String, String>>,
    pub kind: ContinuationKind,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ContinuationKind {
    SingleRedirect {
        completion_header_names: Vec<String>,
    },
    Multipart {
        upload_id: String,
        total_parts: u32,
    },
}

impl Continuation {
    pub fn single_redirect(
        destination_resource_address: String,
        completion_header_names: Vec<String>,
    ) -> Self {
        Self {
            tag: TAG.to_string(),
            destination_resource_address,
            message: None,
            user_metadata: None,
            kind: ContinuationKind::SingleRedirect {
                completion_header_names,
            },
        }
    }

    pub fn multipart(
        destination_resource_address: String,
        upload_id: String,
        total_parts: u32,
    ) -> Self {
        Self {
            tag: TAG.to_string(),
            destination_resource_address,
            message: None,
            user_metadata: None,
            kind: ContinuationKind::Multipart {
                upload_id,
                total_parts,
            },
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("Continuation serializes without floats")
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let parsed: Self = serde_json::from_slice(bytes).map_err(|err| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!("omniverse-storage-service continuation could not be decoded: {err}"),
            )
        })?;
        if parsed.tag != TAG {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "omniverse-storage-service continuation tag does not match this plugin",
            ));
        }
        Ok(parsed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_round_trip() {
        let c = Continuation::single_redirect(
            "omni://server/bucket/file".into(),
            vec!["etag".into(), "content-md5".into()],
        );
        let bytes = c.encode();
        // The destination is emitted for older peers but never read back, so
        // the round trip is equal in every field except that one.
        // A mirror of the shape an older build parses, not a substring match:
        // renaming or retyping the field would keep the string present while
        // breaking the peer this field exists for.
        // Every field the pre-derivation decoder required, `kind` included —
        // that is the discriminated union carrying `upload_id`/`total_parts`,
        // and a mirror without it would pin almost nothing an older peer needs.
        #[derive(Deserialize)]
        #[allow(dead_code)]
        struct LegacyContinuation {
            tag: String,
            destination_resource_address: String,
            kind: ContinuationKind,
        }
        let legacy: LegacyContinuation = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            legacy.destination_resource_address,
            "omni://server/bucket/file"
        );
        assert_eq!(legacy.tag, TAG);
        let decoded = Continuation::decode(&bytes).unwrap();
        assert_eq!(decoded.destination_resource_address, "");
        assert_eq!(
            decoded,
            Continuation {
                destination_resource_address: String::new(),
                ..c
            }
        );
    }

    /// A destination the caller writes into the blob is unreachable: `decode`
    /// never populates the field.
    #[test]
    fn a_caller_supplied_destination_is_not_decoded() {
        let bad = br#"{"tag":"ovstorage-plugin-services-client:write-redirect:1","destination_resource_address":"omni://server/victim","kind":{"type":"single_redirect","completion_header_names":[]}}"#;
        let decoded = Continuation::decode(bad).unwrap();
        assert_eq!(decoded.destination_resource_address, "");
    }

    #[test]
    fn multipart_round_trip() {
        let c = Continuation::multipart("omni://server/x".into(), "upload-id-1".into(), 4);
        let decoded = Continuation::decode(&c.encode()).unwrap();
        match decoded.kind {
            ContinuationKind::Multipart {
                upload_id,
                total_parts,
            } => {
                assert_eq!(upload_id, "upload-id-1");
                assert_eq!(total_parts, 4);
            }
            _ => panic!("expected Multipart"),
        }
    }

    #[test]
    fn rejects_foreign_tag() {
        let bad = br#"{"tag":"someone-else","destination_resource_address":"x","kind":{"type":"single_redirect","completion_header_names":[]}}"#;
        let err = Continuation::decode(bad).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }
}
