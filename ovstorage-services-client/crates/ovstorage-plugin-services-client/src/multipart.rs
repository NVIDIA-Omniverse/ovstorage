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
        let decoded = Continuation::decode(&bytes).unwrap();
        assert_eq!(decoded, c);
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
