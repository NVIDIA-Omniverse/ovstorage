// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared helpers for projecting backend descriptors and events onto the Layer
//! API, plus small `Body`/IO utilities. Native Layer plugins use these helpers
//! as a single source of truth instead of keeping copies that can drift.

use crate::{
    BackendChangeEvent, BodyStream, ChangeEvent, Error, ErrorCode, LayerKindDescriptor, LayerType,
    Result, StorageBackendKindDescriptor,
};

/// Project a backend `StorageBackendKindDescriptor` onto the Layer kind
/// descriptor. `supports_runtime_add` becomes `accepts_connections`;
/// `supports_user_metadata` keeps its name, because it means the same thing on
/// both sides.
pub fn descriptor_to_layer_kind(descriptor: &StorageBackendKindDescriptor) -> LayerKindDescriptor {
    LayerKindDescriptor {
        kind: descriptor.kind.clone(),
        layer_type: LayerType::Backend,
        display_name: descriptor.display_name.clone(),
        description: descriptor.description.clone(),
        config_schema: descriptor.config_schema.clone(),
        credential_schema: descriptor.credential_schema.clone(),
        credential_methods: descriptor.credential_methods.clone(),
        icon: descriptor.icon.clone(),
        accepts_connections: descriptor.supports_runtime_add,
        auth_capable: false,
        supports_user_metadata: descriptor.supports_user_metadata,
    }
}

/// Project a `LayerKindDescriptor` onto the public backend descriptor returned
/// by `list_backend_kinds` (the inverse of [`descriptor_to_layer_kind`]).
/// `accepts_connections` becomes `supports_runtime_add`; `layer_type` is not
/// exposed by the backend descriptor and is dropped.
pub fn layer_kind_to_backend_descriptor(
    descriptor: &LayerKindDescriptor,
) -> StorageBackendKindDescriptor {
    StorageBackendKindDescriptor {
        kind: descriptor.kind.clone(),
        display_name: descriptor.display_name.clone(),
        description: descriptor.description.clone(),
        config_schema: descriptor.config_schema.clone(),
        credential_schema: descriptor.credential_schema.clone(),
        credential_methods: descriptor.credential_methods.clone(),
        icon: descriptor.icon.clone(),
        supports_runtime_add: descriptor.accepts_connections,
        supports_user_metadata: descriptor.supports_user_metadata,
    }
}

/// Map a backend watch-directory event onto the Layer change-event shape.
///
/// # Errors
///
/// This function never fails; it is fallible only for protocol compatibility.
pub fn backend_change_to_change(event: BackendChangeEvent) -> Result<ChangeEvent> {
    match event {
        BackendChangeEvent::Object {
            address,
            kind,
            etag,
            version,
            size,
            mtime,
            at,
            cursor,
        } => Ok(ChangeEvent::Object {
            address,
            kind,
            etag,
            version,
            size,
            mtime,
            at,
            cursor,
        }),
        BackendChangeEvent::Lapsed { since, cursor } => Ok(ChangeEvent::Lapsed { since, cursor }),
    }
}

/// Chunked `BodyStream` over a local file, for the `Body::LocalFile` write path.
///
/// # Errors
///
/// - [`ErrorCode::NotFound`] — the file does not exist.
/// - [`ErrorCode::PermissionDenied`] — the file cannot be read due to
///   permissions.
/// - [`ErrorCode::Transient`] — a filesystem I/O error occurred.
pub fn body_stream_from_file(path: &std::path::Path) -> Result<BodyStream> {
    use std::io::Read;
    let mut file = std::fs::File::open(path).map_err(io_error)?;
    Ok(BodyStream::from_iter(std::iter::from_fn(move || {
        let mut buf = vec![0u8; 64 * 1024];
        match file.read(&mut buf) {
            Ok(0) => None,
            Ok(n) => {
                buf.truncate(n);
                Some(Ok(buf))
            }
            Err(err) => Some(Err(io_error(err))),
        }
    })))
}

/// Map a `std::io::Error` onto the crate error, classifying common kinds.
pub fn io_error(err: std::io::Error) -> Error {
    use std::io::ErrorKind;
    let code = match err.kind() {
        ErrorKind::NotFound => ErrorCode::NotFound,
        ErrorKind::PermissionDenied => ErrorCode::PermissionDenied,
        _ => ErrorCode::Transient,
    };
    Error::new(code, err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_descriptor_round_trips_through_layer_projection() {
        let descriptor = StorageBackendKindDescriptor {
            kind: "fixture".into(),
            display_name: "Fixture".into(),
            description: Some("test backend".into()),
            config_schema: Vec::new(),
            credential_schema: Vec::new(),
            credential_methods: Vec::new(),
            icon: Some(vec![1, 2, 3]),
            supports_runtime_add: true,
            supports_user_metadata: true,
        };
        assert_eq!(
            layer_kind_to_backend_descriptor(&descriptor_to_layer_kind(&descriptor)),
            descriptor
        );
    }

    /// A round trip is symmetric, so it survives a constant substituted in
    /// *both* directions. These assert each projection on its own, for both
    /// values: a backend that declares it cannot carry user metadata must not
    /// arrive at a host as one that can.
    #[test]
    fn each_projection_carries_the_user_metadata_declaration() {
        for declared in [true, false] {
            let descriptor = StorageBackendKindDescriptor {
                kind: "fixture".into(),
                display_name: "Fixture".into(),
                description: None,
                config_schema: Vec::new(),
                credential_schema: Vec::new(),
                credential_methods: Vec::new(),
                icon: None,
                supports_runtime_add: true,
                supports_user_metadata: declared,
            };
            let projected = descriptor_to_layer_kind(&descriptor);
            assert_eq!(
                projected.supports_user_metadata, declared,
                "descriptor_to_layer_kind dropped the declaration"
            );
            assert_eq!(
                layer_kind_to_backend_descriptor(&projected).supports_user_metadata,
                declared,
                "layer_kind_to_backend_descriptor dropped the declaration"
            );
        }
    }
}
