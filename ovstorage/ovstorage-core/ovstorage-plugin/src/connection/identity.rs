// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Stable identities shared by connection caches, persistence, and refresh locks.

use crate::{ConfigValue, ConnectionId, ConnectionRequest};

/// Derive the host's stable identity for a connection request.
///
/// Credentials are deliberately excluded: rotating a secret must not move the
/// durable store entry or cross-process refresh lock. The non-secret config
/// and display name distinguish multiple configured identities for the same
/// backend endpoint.
pub fn conn_id_from_request(request: &ConnectionRequest) -> ConnectionId {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use sha2::{Digest, Sha256};

    fn field(hasher: &mut Sha256, bytes: &[u8]) {
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
    }

    let mut hasher = Sha256::new();
    hasher.update(b"ovstorage-conn-identity-v2");
    field(&mut hasher, request.backend_kind.as_bytes());
    field(
        &mut hasher,
        request.display_name.as_deref().unwrap_or("").as_bytes(),
    );
    let mut keys: Vec<&String> = request.config.keys().collect();
    keys.sort();
    for key in keys {
        field(&mut hasher, key.as_bytes());
        match &request.config[key] {
            ConfigValue::String(value) => {
                hasher.update(b"S");
                field(&mut hasher, value.as_bytes());
            }
            ConfigValue::Int(value) => {
                hasher.update(b"I");
                hasher.update(value.to_le_bytes());
            }
            ConfigValue::Bool(value) => {
                hasher.update(b"B");
                hasher.update([u8::from(*value)]);
            }
            ConfigValue::Toml(value) => {
                hasher.update(b"T");
                field(&mut hasher, value.as_bytes());
            }
        }
    }
    ConnectionId(format!(
        "{}:sha256:{}",
        request.backend_kind,
        URL_SAFE_NO_PAD.encode(hasher.finalize())
    ))
}
