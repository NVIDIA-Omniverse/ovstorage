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
    /// A bundle that carries the SHAPE of an explicit credential but not a
    /// usable one: exactly half a username/password pair, or a present-but-
    /// empty `api_token`/`username`/`password` field. Distinct from
    /// [`Self::Missing`] because malformed explicit intent must be rejected,
    /// not silently converted into an interactive sign-in.
    Partial,
    /// A genuinely empty bundle — no credential fields at all. Interactive
    /// intent: the host drives sign-in (or warm-continues a persisted session).
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
    // Reaching here, no field satisfied the non-empty presence checks above.
    // If an explicit-credential KEY is nonetheless present, the bundle is a
    // malformed half-pair or empty-valued field — `Partial`, never `Missing`.
    // `contains_key` (not `has_secret_field`) is deliberate: an empty value
    // still reveals intended-identity shape that must not warm-continue.
    if ["api_token", "username", "password"]
        .iter()
        .any(|key| bundle.fields.contains_key(*key))
    {
        debug!(
            plugin = "nucleus",
            shape = "partial",
            "credential shape classified"
        );
        return CredentialShape::Partial;
    }
    debug!(
        plugin = "nucleus",
        shape = "missing",
        "credential shape classified"
    );
    CredentialShape::Missing
}

/// Presence with `classify_credentials` semantics: an empty value is absent.
/// `pub(crate)` so the driver's shape guards use the SAME predicate and a
/// present-but-empty field cannot pass one check and fail the other.
pub(crate) fn has_secret_field(bundle: &SecretBundle, key: &str) -> bool {
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
        CredentialShape::Partial | CredentialShape::Missing => {
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
        Capabilities, ConnectionAuthState, ConnectionId, ConnectionSource, SecretBytes,
        SecretValue, UserMetadata,
    };

    fn bundle(pairs: &[(&str, &str)]) -> SecretBundle {
        let mut b = SecretBundle::default();
        for (k, v) in pairs {
            b.fields.insert(
                (*k).into(),
                SecretValue::Bytes(SecretBytes(v.as_bytes().to_vec())),
            );
        }
        b
    }

    #[test]
    fn classify_valid_shapes() {
        assert_eq!(
            classify_credentials(&bundle(&[("api_token", "tok")])),
            CredentialShape::ApiToken
        );
        assert_eq!(
            classify_credentials(&bundle(&[("username", "u"), ("password", "p")])),
            CredentialShape::UsernameAndPassword
        );
        assert_eq!(
            classify_credentials(&bundle(&[("interactive_auth", "true")])),
            CredentialShape::InteractiveAuth
        );
        assert_eq!(classify_credentials(&bundle(&[])), CredentialShape::Missing);
    }

    #[test]
    fn malformed_bundles_classify_as_partial_not_missing() {
        // Half a username/password pair.
        assert_eq!(
            classify_credentials(&bundle(&[("username", "u")])),
            CredentialShape::Partial
        );
        assert_eq!(
            classify_credentials(&bundle(&[("password", "p")])),
            CredentialShape::Partial
        );
        // Present-but-empty explicit fields (an empty value is "absent" for
        // the non-empty presence checks, but the KEY still names an identity).
        assert_eq!(
            classify_credentials(&bundle(&[("api_token", "")])),
            CredentialShape::Partial
        );
        assert_eq!(
            classify_credentials(&bundle(&[("username", ""), ("password", "")])),
            CredentialShape::Partial
        );
    }

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
