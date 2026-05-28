// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use ovstorage_plugin::{
    AuthEvent, Connection, Error, ErrorCode, ErrorContext, Result, SecretBundle, SecretValue,
};
use tracing::debug;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CredentialShape {
    /// API token, single-shot exchange against `Tokens.auth_with_api_token`.
    ApiToken,
    /// Username + password via `Credentials.auth` over OmniAuth.
    UsernameAndPassword,
    /// Triggered by a `SecretBundle` carrying an `interactive_auth = "true"` marker.
    /// Naming note: cross-plugin uniformity calls this "OAuth", but the actual
    /// Nucleus flow is URL+nonce-poll over SOWS, not OAuth.
    InteractiveAuth,
    /// Nothing the host can drive without user interaction.
    Missing,
}

pub(crate) fn classify_credentials(bundle: &SecretBundle) -> CredentialShape {
    if has_secret_field(bundle, "api_token") {
        debug!(
            plugin = "nucleus",
            shape = "api_token",
            "credential shape classified"
        );
        return CredentialShape::ApiToken;
    }
    if has_secret_field(bundle, "username") && has_secret_field(bundle, "password") {
        debug!(
            plugin = "nucleus",
            shape = "username_password",
            "credential shape classified"
        );
        return CredentialShape::UsernameAndPassword;
    }
    if has_secret_field(bundle, "interactive_auth") {
        debug!(
            plugin = "nucleus",
            shape = "interactive_auth",
            "credential shape classified"
        );
        return CredentialShape::InteractiveAuth;
    }
    debug!(
        plugin = "nucleus",
        shape = "missing",
        "credential shape classified"
    );
    CredentialShape::Missing
}

fn has_secret_field(bundle: &SecretBundle, key: &str) -> bool {
    match bundle.fields.get(key) {
        Some(SecretValue::Bytes(value)) => !value.0.is_empty(),
        Some(_) => true,
        None => false,
    }
}

/// Last-resort error-surfacing path for credential shapes that did not
/// drive through a real handshake. Returning `Succeeded` here would
/// silently fake authentication.
pub(crate) fn synthesize_auth_events(
    connection: Connection,
    bundle: Option<&SecretBundle>,
) -> Vec<Result<AuthEvent>> {
    let shape = bundle
        .map(classify_credentials)
        .unwrap_or(CredentialShape::Missing);
    match shape {
        CredentialShape::ApiToken | CredentialShape::UsernameAndPassword => {
            // Unreachable in normal operation; factory dispatches these to `establish_*` first.
            let connection_id = connection.id;
            vec![Ok(AuthEvent::Failed {
                error: Error::new(
                    ErrorCode::Internal,
                    "Nucleus authenticate fallthrough: shared backend state \
                     missing for credentials that should have driven a real handshake",
                )
                .with_context(ErrorContext::Auth {
                    connection_id,
                    reason: Some("shared_state_missing".into()),
                    expired_at: None,
                }),
            })]
        }
        CredentialShape::InteractiveAuth => {
            // Reached only when `NucleusShared` lookup fails; surface so the host re-runs `instantiate`.
            let connection_id = connection.id;
            vec![Ok(AuthEvent::Failed {
                error: Error::new(
                    ErrorCode::AuthRequired,
                    "Nucleus interactive auth requested but backend not instantiated",
                )
                .with_context(ErrorContext::Auth {
                    connection_id,
                    reason: Some("interactive_auth_no_shared".into()),
                    expired_at: None,
                }),
            })]
        }
        CredentialShape::Missing => {
            let connection_id = connection.id;
            vec![Ok(AuthEvent::Failed {
                error: Error::new(
                    ErrorCode::AuthRequired,
                    "Nucleus authentication requires `api_token` or `username`+`password`",
                )
                .with_context(ErrorContext::Auth {
                    connection_id,
                    reason: Some("missing_credentials".into()),
                    expired_at: None,
                }),
            })]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ovstorage_plugin::{
        Capabilities, ConnectionAuthState, ConnectionId, ConnectionSource, UserMetadata,
    };

    fn make_connection() -> Connection {
        Connection {
            id: ConnectionId("conn-test".into()),
            backend_kind: "nucleus".into(),
            display_name: "Test".into(),
            source: ConnectionSource::Runtime { persisted: false },
            capabilities: Capabilities::empty(),
            current_addresses: vec![],
            auth_state: ConnectionAuthState::Anonymous,
            last_probed: None,
            user_metadata: UserMetadata::new(),
        }
    }

    #[test]
    fn missing_credentials_event_carries_connection_id() {
        let connection = make_connection();
        let events = synthesize_auth_events(connection, None);
        let evt = events.into_iter().next().unwrap().unwrap();
        let AuthEvent::Failed { error } = evt else {
            panic!("expected AuthEvent::Failed");
        };
        assert_eq!(error.code(), ErrorCode::AuthRequired);
        match error.context() {
            Some(ErrorContext::Auth {
                connection_id,
                reason,
                ..
            }) => {
                assert_eq!(connection_id.0, "conn-test");
                assert_eq!(reason.as_deref(), Some("missing_credentials"));
            }
            other => panic!("expected Auth context, got {other:?}"),
        }
    }
}
