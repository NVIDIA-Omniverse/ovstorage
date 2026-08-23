// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Faithful request `Extensions` crossing over the ABI-v2 vtable.
//!
//! Every FFI hop carries the request extension bag: the host builders encode
//! a non-empty bag and the plugin decoder returns it intact, so a
//! producer-stamped extension — e.g. the broker daemon's
//! `ext::PRINCIPAL_ID` — crosses any vtable boundary rather than degrading to
//! the empty set. These tests pin the contract: non-empty bags encode as a
//! borrowed heap `ffi::Extensions` (empty stays NULL, the ABI's "none"
//! sentinel) and decode byte-faithfully on the far side, exercised over the
//! genuinely foreign path via `import_handle_force_foreign`
//! (cf. `handoff_core.rs`).

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ovstorage::wrappers::ext::{
    PRINCIPAL_ID, ResolvedOAuthCredentialRef, UPSTREAM_AUTH_ADDRESS,
    insert_resolved_oauth_credential, take_resolved_oauth_credential,
};
use ovstorage::{
    AuthEventStream, AuthenticateRequest, CancellationToken, ChecksumSet, ConnectionId,
    ConnectionKey, Error, ErrorCode, Extensions, InteractiveAuthCapability, Layer,
    LayerKindDescriptor, LayerType, ObjectInfo, ObjectKind, Request, Result, StatOptions,
    StatRequest, Url, export_handle,
};
use ovstorage_plugin::{consume_v2, ffi, import_handle_force_foreign, thunks_v2};

const ADDRESS: &str = "mem://data/object.bin";

fn object_info(address: Url) -> ObjectInfo {
    ObjectInfo {
        address,
        kind: ObjectKind::File,
        etag: None,
        version: None,
        size: Some(0),
        mtime: None,
        checksums: ChecksumSet::new(),
        effective_permissions: None,
        system_metadata: None,
        user_metadata: None,
        modified_by: None,
    }
}

/// Producer layer that records the `Extensions` each `stat` request arrives
/// with, so a test can compare what crossed the bridge against what it sent.
struct ExtensionProbe {
    seen: Arc<Mutex<Option<Extensions>>>,
}

#[async_trait]
impl Layer for ExtensionProbe {
    fn name(&self) -> &str {
        "extension-probe"
    }

    fn descriptor(&self) -> LayerKindDescriptor {
        LayerKindDescriptor {
            kind: "extension-probe".to_string(),
            layer_type: LayerType::Backend,
            display_name: "extension crossing probe".to_string(),
            description: None,
            config_schema: Vec::new(),
            credential_schema: Vec::new(),
            credential_methods: Vec::new(),
            icon: None,
            accepts_connections: false,
            auth_capable: false,
            supports_user_metadata: true,
        }
    }

    async fn stat(
        &self,
        request: Request<StatRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        *self.seen.lock().unwrap() = Some(request.extensions);
        Ok(object_info(request.input.address))
    }

    async fn remove_connection(
        &self,
        key: Request<ConnectionKey>,
        _cancel: Option<CancellationToken>,
    ) -> Result<()> {
        *self.seen.lock().unwrap() = Some(key.extensions);
        // Fail the op (and thus the test's `expect`) if the key half of the
        // new `RemoveConnectionRequest` did not cross faithfully alongside
        // the extensions.
        if key.input.target != "extension-probe" || key.input.id.0 != "c1" {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!("connection key degraded across the bridge: {:?}", key.input),
            ));
        }
        Ok(())
    }

    async fn authenticate_connection(
        &self,
        request: Request<AuthenticateRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<AuthEventStream> {
        *self.seen.lock().unwrap() = Some(request.extensions);
        Ok(Box::new(std::iter::empty()))
    }
}

/// Drive one `stat` carrying `extensions` across a forced-foreign import and
/// hand back the bag the producer received on the far side.
async fn cross_bridge_with(extensions: Extensions) -> Extensions {
    let seen = Arc::new(Mutex::new(None));
    let handle = export_handle(Arc::new(ExtensionProbe { seen: seen.clone() }));
    let imported = unsafe { import_handle_force_foreign(handle) }.expect("forced-foreign import");

    imported
        .stat(
            Request {
                extensions,
                input: StatRequest {
                    address: Url::parse(ADDRESS).unwrap(),
                    options: StatOptions::default(),
                },
            },
            None,
        )
        .await
        .expect("stat across the bridge");
    seen.lock()
        .unwrap()
        .take()
        .expect("producer observed the request")
}

/// Drive one `authenticate_connection` carrying `extensions` across the same
/// forced-foreign bridge and return the bag observed by the producer.
async fn cross_authenticate_bridge_with(extensions: Extensions) -> Extensions {
    let seen = Arc::new(Mutex::new(None));
    let handle = export_handle(Arc::new(ExtensionProbe { seen: seen.clone() }));
    let imported = unsafe { import_handle_force_foreign(handle) }.expect("forced-foreign import");

    let _stream = imported
        .authenticate_connection(
            Request {
                extensions,
                input: AuthenticateRequest {
                    key: ConnectionKey {
                        target: "extension-probe".to_string(),
                        id: ConnectionId("c1".to_string()),
                    },
                    capability: InteractiveAuthCapability::Browser,
                    auto_open_browser: false,
                },
            },
            None,
        )
        .await
        .expect("authenticate_connection across the bridge");
    seen.lock()
        .unwrap()
        .take()
        .expect("producer observed the request")
}

/// The landed `PRINCIPAL_ID` crosses the full FFI slot bridge
/// byte-faithfully instead of silently degrading to the empty set.
#[tokio::test]
async fn principal_extension_round_trips_through_a_forced_foreign_import() {
    let mut extensions = Extensions::new();
    extensions.insert(PRINCIPAL_ID, b"alice".to_vec());

    let crossed = cross_bridge_with(extensions.clone()).await;
    assert_eq!(crossed, extensions);
    assert_eq!(crossed.get(PRINCIPAL_ID), Some(b"alice".as_slice()));
}

/// The broker's non-secret OAuth keyring reference uses the ordinary
/// extension envelope to reach a production backend loaded through ABI v2.
/// Pin both byte-faithful handoff and typed decoding on the far side.
#[tokio::test]
async fn resolved_oauth_reference_crosses_a_forced_foreign_import() {
    let credential = ResolvedOAuthCredentialRef {
        backend_kind: "http".into(),
        keyring_handle: "oauth/upstream-idp".into(),
    };
    let mut extensions = Extensions::new();
    extensions.insert(PRINCIPAL_ID, b"alice".to_vec());
    insert_resolved_oauth_credential(&mut extensions, &credential).unwrap();

    let crossed = cross_bridge_with(extensions.clone()).await;

    assert_eq!(crossed, extensions);
    let mut decoded = crossed;
    assert_eq!(
        take_resolved_oauth_credential(&mut decoded).unwrap(),
        Some(credential)
    );
}

/// Authentication uses the same extension envelope as data and connection
/// operations. Both well-known keys and an opaque binary-ish payload survive
/// its dedicated ABI-v2 slot without an ABI-specific field.
#[tokio::test]
async fn authenticate_extensions_cross_a_forced_foreign_import() {
    let upstream_address = b"https://upstream.example/object.bin".to_vec();
    let binary_value = vec![0x00, 0xFF, 0x9F, 0x92, 0x80];
    let mut extensions = Extensions::new();
    extensions.insert(PRINCIPAL_ID, b"alice".to_vec());
    extensions.insert(UPSTREAM_AUTH_ADDRESS, upstream_address.clone());
    extensions.insert("org.example/auth-binary@1", binary_value.clone());

    let crossed = cross_authenticate_bridge_with(extensions.clone()).await;
    assert_eq!(crossed, extensions);
    assert_eq!(crossed.get(PRINCIPAL_ID), Some(b"alice".as_slice()));
    assert_eq!(
        crossed.get(UPSTREAM_AUTH_ADDRESS),
        Some(upstream_address.as_slice())
    );
    assert_eq!(
        crossed.get("org.example/auth-binary@1"),
        Some(binary_value.as_slice())
    );
}

/// `remove_connection` carries the request extensions like every other slot:
/// its `RemoveConnectionRequest` (ABI v6) wraps the bare `ConnectionKey` in a
/// request prefix, so a PRINCIPAL-style extension stamped on the removal
/// request survives the forced-foreign vtable hop byte-faithfully, and the
/// key itself still resolves on the far side.
#[tokio::test]
async fn remove_connection_extensions_cross_a_forced_foreign_import() {
    let mut extensions = Extensions::new();
    extensions.insert(PRINCIPAL_ID, b"alice".to_vec());

    let seen = Arc::new(Mutex::new(None));
    let handle = export_handle(Arc::new(ExtensionProbe { seen: seen.clone() }));
    let imported = unsafe { import_handle_force_foreign(handle) }.expect("forced-foreign import");

    imported
        .remove_connection(
            Request {
                extensions: extensions.clone(),
                input: ConnectionKey {
                    target: "extension-probe".to_string(),
                    id: ConnectionId("c1".to_string()),
                },
            },
            None,
        )
        .await
        .expect("remove_connection across the bridge");

    let crossed = seen
        .lock()
        .unwrap()
        .take()
        .expect("producer observed the request");
    assert_eq!(crossed, extensions);
    assert_eq!(crossed.get(PRINCIPAL_ID), Some(b"alice".as_slice()));
}

/// Extension values are raw bytes, not strings: a non-UTF-8 value crosses
/// unaltered (only keys carry the UTF-8 requirement), alongside a second
/// entry proving multi-entry bags survive intact.
#[tokio::test]
async fn binary_extension_values_round_trip() {
    let mut extensions = Extensions::new();
    extensions.insert("org.example/binary@1", vec![0x00, 0xFF, 0x9F, 0x92, 0x80]);
    extensions.insert("org.example/empty@1", Vec::new());

    let crossed = cross_bridge_with(extensions.clone()).await;
    assert_eq!(crossed, extensions);
    assert_eq!(
        crossed.get("org.example/binary@1"),
        Some([0x00, 0xFF, 0x9F, 0x92, 0x80].as_slice()),
        "non-UTF-8 bytes must cross unaltered"
    );
    assert_eq!(crossed.get("org.example/empty@1"), Some([].as_slice()));
}

/// An empty bag crosses as no bag at all: the builders encode NULL (never an
/// empty allocation), and the far side decodes NULL back to the empty set.
#[tokio::test]
async fn empty_extensions_encode_as_null() {
    let request = consume_v2::build_stat(Request::new(StatRequest {
        address: Url::parse(ADDRESS).unwrap(),
        options: StatOptions::default(),
    }));
    assert!(
        request.extensions.is_null(),
        "empty extensions must encode as the NULL sentinel"
    );
    assert_eq!(
        unsafe { thunks_v2::extensions_from_ffi(request.extensions) }.expect("NULL decodes"),
        Extensions::new()
    );
    // `request` drops here, releasing its owned payloads; there is no
    // extensions allocation to reclaim on the NULL path.

    // And the end-to-end check: an empty bag arrives empty.
    let crossed = cross_bridge_with(Extensions::new()).await;
    assert!(crossed.is_empty());
}

/// Codec-level round-trip without a vtable in the middle: the encoder mints
/// a heap `ffi::Extensions` the request merely borrows, the decoder copies
/// the entries out without consuming it, and the caller reclaims the
/// encoding via the NULL-safe exported free.
#[test]
fn encoder_and_decoder_round_trip_without_consuming_the_borrow() {
    let mut extensions = Extensions::new();
    extensions.insert("org.example/a@1", b"first".to_vec());
    extensions.insert("org.example/b@1", vec![0xC0, 0x00]);

    let encoded = consume_v2::extensions_to_ffi(extensions.clone());
    assert!(!encoded.is_null());

    // Two borrowing decodes both see the full bag: decoding must not consume.
    for _ in 0..2 {
        let decoded = unsafe { thunks_v2::extensions_from_ffi(encoded) }.expect("decode");
        assert_eq!(decoded, extensions);
    }

    unsafe { ffi::ovstorage_plugin_extensions_free(encoded as *mut ffi::Extensions) };
}
