// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Host entry points for interactive authentication of an upstream address.
//!
//! These are host helpers, not a data-path retry wrapper. They explicitly start
//! interactive authentication after an operation reports that its address
//! needs a credential; after success, the caller retries that operation. The
//! broker's provider-aware credential boundary is the owner of its
//! per-principal upstream slot. For requests minted at that boundary, it may
//! recover an `AuthRequired` from a registered consumer only after verifying
//! route ownership, conditionally invalidating the rejected credential lease,
//! and coalescing refresh; it retries the operation at most once. Other hosts
//! and backends must not assume that specialized behavior or add a generic
//! retry around every backend.

use ovstorage_layer::ext;

use crate::{
    AuthEventStream, AuthenticateRequest, CancellationToken, ConnectionKey, Error, ErrorCode,
    Extensions, InteractiveAuthCapability, Layer, Request, Result, Url,
};

/// Resolve the connection owning `address` and begin its interactive upstream
/// authentication flow.
///
/// The dispatched request carries `address` under
/// [`ext::UPSTREAM_AUTH_ADDRESS`], allowing a broker-client layer to
/// distinguish brokered upstream authentication from ordinary connection
/// authentication.
///
/// # Errors
///
/// - [`ErrorCode::NoRoute`] when no route matches `address`, or when the
///   resolved route has no connection owner or connection id.
/// - Any error returned by [`Layer::root_info_for`] or
///   [`Layer::authenticate_connection`].
pub async fn authenticate_upstream_for_address(
    layer: &dyn Layer,
    address: &Url,
    capability: InteractiveAuthCapability,
    auto_open_browser: bool,
    cancel: Option<CancellationToken>,
) -> Result<AuthEventStream> {
    let root = Layer::root_info_for(layer, address, &Extensions::new(), cancel.clone()).await?;
    let target = root.owning_target.ok_or_else(|| {
        Error::new(
            ErrorCode::NoRoute,
            "resolved root has no connection-owning layer",
        )
    })?;
    let id = root.connection_id.ok_or_else(|| {
        Error::new(
            ErrorCode::NoRoute,
            "resolved root has no connection id for upstream authentication",
        )
    })?;

    authenticate_upstream_for_address_with_connection(
        layer,
        ConnectionKey { target, id },
        address,
        capability,
        auto_open_browser,
        cancel,
    )
    .await
}

/// Begin interactive upstream authentication when the owning connection key
/// is already known, such as from an authentication error context.
///
/// # Errors
///
/// Returns any error from [`Layer::authenticate_connection`]. Flow failures
/// after dispatch are yielded by the returned [`AuthEventStream`].
pub async fn authenticate_upstream_for_address_with_connection(
    layer: &dyn Layer,
    key: ConnectionKey,
    address: &Url,
    capability: InteractiveAuthCapability,
    auto_open_browser: bool,
    cancel: Option<CancellationToken>,
) -> Result<AuthEventStream> {
    let mut extensions = Extensions::new();
    ext::insert_upstream_auth_address(&mut extensions, address);
    let request = Request {
        extensions,
        input: AuthenticateRequest {
            key,
            capability,
            auto_open_browser,
        },
    };

    Layer::authenticate_connection(layer, request, cancel).await
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;

    use super::*;
    use crate::{
        AddressVisibility, Capabilities, ConfigLayer, ConnectionId, LayerKindDescriptor, LayerType,
        RangeReadStrategy, RootInfo, RouteSource, UserMetadata,
    };

    struct ProbeLayer {
        root: RootInfo,
        request: Mutex<Option<Request<AuthenticateRequest>>>,
    }

    #[async_trait]
    impl Layer for ProbeLayer {
        fn name(&self) -> &str {
            "probe"
        }

        fn descriptor(&self) -> LayerKindDescriptor {
            LayerKindDescriptor {
                kind: "probe".to_string(),
                layer_type: LayerType::Backend,
                display_name: "Probe".to_string(),
                description: None,
                config_schema: Vec::new(),
                credential_schema: Vec::new(),
                credential_methods: Vec::new(),
                icon: None,
                accepts_connections: true,
                auth_capable: false,
                supports_user_metadata: false,
            }
        }

        async fn root_info_for(
            &self,
            _url: &Url,
            _cx: &Extensions,
            _cancel: Option<CancellationToken>,
        ) -> Result<RootInfo> {
            Ok(self.root.clone())
        }

        async fn authenticate_connection(
            &self,
            request: Request<AuthenticateRequest>,
            _cancel: Option<CancellationToken>,
        ) -> Result<AuthEventStream> {
            *self.request.lock().expect("probe request lock poisoned") = Some(request);
            Ok(Box::new(std::iter::empty()))
        }
    }

    fn probe_root(address: &Url, connection_id: Option<ConnectionId>) -> RootInfo {
        RootInfo {
            root: address.clone(),
            display_name: None,
            layer_kind: "probe".to_string(),
            connection_id: connection_id.clone(),
            owning_target: Some("upstream-backend".to_string()),
            capabilities: Capabilities::empty(),
            range_read_strategy: RangeReadStrategy::Unsupported,
            source: connection_id.map_or(
                RouteSource::Static {
                    layer: ConfigLayer::Programmatic,
                },
                |connection_id| RouteSource::ConnectionContributed { connection_id },
            ),
            visible: true,
            visibility: AddressVisibility::Visible,
            alias_state: None,
            icon: None,
            user_metadata: UserMetadata::new(),
        }
    }

    #[tokio::test]
    async fn resolves_and_dispatches_address_stamped_auth_request() {
        let address = Url::parse("s3://bucket/path/to/object.usd").unwrap();
        let connection_id = ConnectionId("upstream-connection".to_string());
        let probe = ProbeLayer {
            root: probe_root(&address, Some(connection_id.clone())),
            request: Mutex::new(None),
        };

        let _stream = authenticate_upstream_for_address(
            &probe,
            &address,
            InteractiveAuthCapability::Headless,
            false,
            None,
        )
        .await
        .unwrap();

        let request = probe
            .request
            .lock()
            .expect("probe request lock poisoned")
            .clone()
            .expect("authenticate_connection was not dispatched");
        assert_eq!(
            request.extensions.get(ext::UPSTREAM_AUTH_ADDRESS),
            Some(address.as_str().as_bytes())
        );
        assert_eq!(
            request.input.key,
            ConnectionKey {
                target: "upstream-backend".to_string(),
                id: connection_id,
            }
        );
        assert_eq!(
            request.input.capability,
            InteractiveAuthCapability::Headless
        );
        assert!(!request.input.auto_open_browser);
    }

    #[tokio::test]
    async fn missing_connection_id_is_a_typed_error() {
        let address = Url::parse("s3://bucket/path").unwrap();
        let probe = ProbeLayer {
            root: probe_root(&address, None),
            request: Mutex::new(None),
        };

        let result = authenticate_upstream_for_address(
            &probe,
            &address,
            InteractiveAuthCapability::None,
            false,
            None,
        )
        .await;
        let error = match result {
            Ok(_) => panic!("a static route has no connection to authenticate"),
            Err(error) => error,
        };

        assert_eq!(error.code(), ErrorCode::NoRoute);
        assert!(
            probe
                .request
                .lock()
                .expect("probe request lock poisoned")
                .is_none()
        );
    }

    #[tokio::test]
    async fn missing_owning_target_is_a_typed_error() {
        let address = Url::parse("s3://bucket/path").unwrap();
        let mut root = probe_root(
            &address,
            Some(ConnectionId("upstream-connection".to_string())),
        );
        root.owning_target = None;
        let probe = ProbeLayer {
            root,
            request: Mutex::new(None),
        };

        let result = authenticate_upstream_for_address(
            &probe,
            &address,
            InteractiveAuthCapability::None,
            false,
            None,
        )
        .await;
        let error = match result {
            Ok(_) => panic!("a route without an owning target cannot be authenticated"),
            Err(error) => error,
        };

        assert_eq!(error.code(), ErrorCode::NoRoute);
        assert!(
            probe
                .request
                .lock()
                .expect("probe request lock poisoned")
                .is_none()
        );
    }
}
