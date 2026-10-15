// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Brokered upstream-auth gRPC framing and lifecycle bridge.

use std::pin::Pin;

use futures_core::Stream;
use tokio_stream::wrappers::ReceiverStream;
use tonic::Status;

use super::ctx_status;
use crate::upstream_credential::RemoteAuthFailureDiagnostic;
use crate::{Error, ErrorCode, RequestContext, Url, pb, protocol};

pub(super) type GrpcAuthStream = Pin<
    Box<dyn Stream<Item = std::result::Result<pb::AuthEventEnvelope, Status>> + Send + 'static>,
>;

const REMOTE_AUTH_FAILURE_MESSAGE: &str = "upstream authentication failed";

/// Strip provider-controlled text before an authentication failure crosses
/// the daemon-to-client boundary. OAuth endpoint response bodies may contain
/// tokens, account details, or other IdP diagnostics. Only the stable error
/// code and an independently classified, configuration-derived diagnostic are
/// safe to relay.
fn redact_upstream_auth_error(
    error: Error,
    failure_diagnostic: Option<&RemoteAuthFailureDiagnostic>,
) -> Error {
    tracing::warn!(
        error.code = ?error.code(),
        "upstream authentication flow failed"
    );
    if let Some(diagnostic) = failure_diagnostic
        && diagnostic.expected_code() == error.code()
    {
        return Error::new(error.code(), diagnostic.remote_message());
    }
    Error::new(error.code(), REMOTE_AUTH_FAILURE_MESSAGE)
}

fn redact_upstream_auth_event(
    event: ovstorage::AuthEvent,
    failure_diagnostic: Option<&RemoteAuthFailureDiagnostic>,
) -> ovstorage::AuthEvent {
    match event {
        ovstorage::AuthEvent::Failed { error } => ovstorage::AuthEvent::Failed {
            error: redact_upstream_auth_error(error, failure_diagnostic),
        },
        event => event,
    }
}

struct CancelOnDropAuthStream {
    inner: ReceiverStream<std::result::Result<pb::AuthEventEnvelope, Status>>,
    cancel: ovstorage::CancellationToken,
    join: Option<std::thread::JoinHandle<()>>,
}

impl Stream for CancelOnDropAuthStream {
    type Item = std::result::Result<pb::AuthEventEnvelope, Status>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        Pin::new(&mut self.inner).poll_next(cx)
    }
}

impl Drop for CancelOnDropAuthStream {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.inner.close();
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

pub(super) fn bridge_auth_stream(
    stream: ovstorage::AuthEventStream,
    address: Url,
    context: RequestContext,
    cancel: ovstorage::CancellationToken,
    failure_diagnostic: Option<RemoteAuthFailureDiagnostic>,
) -> std::result::Result<GrpcAuthStream, Status> {
    let audit_id = context.audit_id.clone();
    let policy_epoch: Option<u64> = None;
    let (sender, receiver) = tokio::sync::mpsc::channel(16);
    let join = std::thread::Builder::new()
        .name("ovs-grpc-auth".into())
        .spawn(move || {
            for event in stream {
                let response = event
                    .map(|event| {
                        let event = redact_upstream_auth_event(event, failure_diagnostic.as_ref());
                        protocol::auth_event_to_proto_with_context(
                            &event,
                            Some(&address),
                            audit_id.as_deref(),
                            policy_epoch,
                        )
                    })
                    .map_err(|error| redact_upstream_auth_error(error, failure_diagnostic.as_ref()))
                    .map_err(|error| ctx_status(error, &context));
                if sender.blocking_send(response).is_err() {
                    break;
                }
            }
        })
        .map_err(|error| {
            Status::resource_exhausted(format!(
                "failed to allocate authentication stream worker: {error}"
            ))
        })?;
    Ok(Box::pin(CancelOnDropAuthStream {
        inner: ReceiverStream::new(receiver),
        cancel,
        join: Some(join),
    }))
}

pub(super) fn register_credential_payload_from_proto(
    request: pb::RegisterCredentialRequest,
) -> ovstorage::Result<protocol::RegisterCredentialPayload> {
    if request.access_token.is_empty() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "register_credential access_token must not be empty",
        ));
    }
    let expires_at = match request.expires_at_unix_millis {
        0 => None,
        millis => Some(
            std::time::UNIX_EPOCH
                .checked_add(std::time::Duration::from_millis(millis))
                .ok_or_else(|| {
                    Error::new(
                        ErrorCode::InvalidArgument,
                        "register_credential expires_at_unix_millis is out of range",
                    )
                })?,
        ),
    };
    Ok(protocol::RegisterCredentialPayload {
        access_token: request.access_token,
        refresh_token: (!request.refresh_token.is_empty()).then_some(request.refresh_token),
        expires_at,
    })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use futures::StreamExt as _;

    use super::*;
    use crate::address;

    struct EndlessAuthEvents {
        dropped: Option<std::sync::mpsc::Sender<()>>,
    }

    impl Iterator for EndlessAuthEvents {
        type Item = ovstorage::Result<ovstorage::AuthEvent>;

        fn next(&mut self) -> Option<Self::Item> {
            Some(Ok(ovstorage::AuthEvent::Progress {
                message: "waiting".into(),
            }))
        }
    }

    impl Drop for EndlessAuthEvents {
        fn drop(&mut self) {
            if let Some(dropped) = self.dropped.take() {
                let _ = dropped.send(());
            }
        }
    }

    #[test]
    fn dropping_grpc_auth_stream_terminates_bridge() {
        let (dropped_tx, dropped_rx) = std::sync::mpsc::channel();
        let upstream: ovstorage::AuthEventStream = Box::new(EndlessAuthEvents {
            dropped: Some(dropped_tx),
        });
        let grpc_stream = bridge_auth_stream(
            upstream,
            address::parse("test://upstream/object").unwrap(),
            RequestContext::default(),
            ovstorage::CancellationToken::new(),
            None,
        )
        .unwrap();

        drop(grpc_stream);

        dropped_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("dropping the receiver must terminate and drop the upstream iterator");
    }

    #[tokio::test]
    async fn failed_auth_event_redacts_provider_text_and_carries_context() {
        let address = address::parse("test://upstream/object").unwrap();
        let upstream: ovstorage::AuthEventStream = Box::new(
            vec![Ok(ovstorage::AuthEvent::Failed {
                error: Error::new(
                    ErrorCode::AuthRequired,
                    "token endpoint returned HTTP 400: super-secret-idp-body",
                ),
            })]
            .into_iter(),
        );
        let mut stream = bridge_auth_stream(
            upstream,
            address.clone(),
            RequestContext {
                credential: None,
                audit_id: Some("audit-auth-7".into()),
            },
            ovstorage::CancellationToken::new(),
            None,
        )
        .unwrap();

        let frame = stream.next().await.unwrap().unwrap();
        let pb::auth_event_envelope::Event::Failed(failed) = frame.event.unwrap() else {
            panic!("expected failed auth event");
        };
        let detail = failed.error.unwrap();
        assert_eq!(detail.code, "AuthRequired");
        assert_eq!(detail.message, REMOTE_AUTH_FAILURE_MESSAGE);
        assert!(!detail.message.contains("super-secret-idp-body"));
        assert_eq!(detail.address, address.as_str());
        assert_eq!(detail.audit_id, "audit-auth-7");
        assert!(detail.context.is_none());
    }

    #[test]
    fn configuration_diagnostic_discloses_only_sanitized_unknown_provider_name() {
        let address = address::parse("test://upstream/object").unwrap();
        let bindings = crate::BrokerOAuthRouteBindings::new().with_route(
            address::parse("test://upstream/").unwrap(),
            "ghost-provider",
        );
        let providers = crate::OAuthProviderRegistry::new();
        let diagnostic = RemoteAuthFailureDiagnostic::for_route(&bindings, &providers, &address)
            .expect("an unknown provider has a safe configuration diagnostic");

        let redacted = redact_upstream_auth_error(
            Error::new(
                ErrorCode::CredentialUnavailable,
                "provider failure containing super-secret-idp-body",
            ),
            Some(&diagnostic),
        );

        assert_eq!(redacted.code(), ErrorCode::CredentialUnavailable);
        assert_eq!(
            redacted.message(),
            "broker: configured OAuth provider 'ghost-provider' is not registered"
        );
        assert!(!redacted.message().contains("super-secret-idp-body"));

        let wrong_code = redact_upstream_auth_error(
            Error::new(
                ErrorCode::AuthRequired,
                "token endpoint returned super-secret-idp-body",
            ),
            Some(&diagnostic),
        );
        assert_eq!(wrong_code.message(), REMOTE_AUTH_FAILURE_MESSAGE);
    }

    #[test]
    fn configuration_diagnostic_bounds_and_sanitizes_provider_name() {
        let address = address::parse("test://upstream/object").unwrap();
        let unsafe_name = format!("ghost\nprovider/{}", "x".repeat(256));
        let bindings = crate::BrokerOAuthRouteBindings::new()
            .with_route(address::parse("test://upstream/").unwrap(), unsafe_name);
        let diagnostic = RemoteAuthFailureDiagnostic::for_route(
            &bindings,
            &crate::OAuthProviderRegistry::new(),
            &address,
        )
        .unwrap();
        let redacted = redact_upstream_auth_error(
            Error::new(ErrorCode::CredentialUnavailable, "provider-controlled"),
            Some(&diagnostic),
        );

        assert!(!redacted.message().contains('\n'));
        assert!(!redacted.message().contains('/'));
        assert!(redacted.message().contains("ghost_provider_"));
        assert!(redacted.message().len() < 200);
    }

    #[test]
    fn unbound_route_discloses_fixed_auth_required_diagnostic() {
        let address = address::parse("test://upstream/object").unwrap();
        let diagnostic = RemoteAuthFailureDiagnostic::for_route(
            &crate::BrokerOAuthRouteBindings::new(),
            &crate::OAuthProviderRegistry::new(),
            &address,
        )
        .unwrap();
        let redacted = redact_upstream_auth_error(
            Error::new(ErrorCode::AuthRequired, "provider-controlled"),
            Some(&diagnostic),
        );

        assert_eq!(
            redacted.message(),
            "broker: no upstream OAuth provider is configured for this route"
        );
    }

    #[test]
    fn register_payload_preserves_optional_wire_fields() {
        let empty = register_credential_payload_from_proto(pb::RegisterCredentialRequest {
            address: "test://upstream/object".into(),
            access_token: b"access".to_vec(),
            refresh_token: Vec::new(),
            expires_at_unix_millis: 0,
        })
        .unwrap();
        assert_eq!(empty.access_token, b"access");
        assert!(empty.refresh_token.is_none());
        assert!(empty.expires_at.is_none());

        let populated = register_credential_payload_from_proto(pb::RegisterCredentialRequest {
            address: "test://upstream/object".into(),
            access_token: b"access".to_vec(),
            refresh_token: b"refresh".to_vec(),
            expires_at_unix_millis: 1234,
        })
        .unwrap();
        assert_eq!(
            populated.refresh_token.as_deref(),
            Some(b"refresh".as_slice())
        );
        assert_eq!(
            populated
                .expires_at
                .unwrap()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap(),
            Duration::from_millis(1234)
        );

        let error = register_credential_payload_from_proto(pb::RegisterCredentialRequest {
            address: "test://upstream/object".into(),
            access_token: Vec::new(),
            refresh_token: b"must-not-land".to_vec(),
            expires_at_unix_millis: 1234,
        })
        .unwrap_err();
        assert_eq!(error.code(), ErrorCode::InvalidArgument);

        let max_millis = u64::MAX;
        let max = register_credential_payload_from_proto(pb::RegisterCredentialRequest {
            address: "test://upstream/object".into(),
            access_token: b"access".to_vec(),
            refresh_token: Vec::new(),
            expires_at_unix_millis: max_millis,
        });
        match std::time::UNIX_EPOCH.checked_add(std::time::Duration::from_millis(max_millis)) {
            Some(expected) => assert_eq!(max.unwrap().expires_at, Some(expected)),
            None => assert_eq!(max.unwrap_err().code(), ErrorCode::InvalidArgument),
        }
    }
}
