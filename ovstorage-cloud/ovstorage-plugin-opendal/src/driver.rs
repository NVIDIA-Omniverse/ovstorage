// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `ConnectionAuthDriver` for OpenDAL credentials (RFC-0066).
//!
//! OpenDAL credentials are **static config strings** (SigV4 keys for the s3
//! profile, basic-auth password for webdav, nothing for fs) baked into an
//! immutable `Operator` at construction — the azure/gcs frozen model with no
//! live cell, no token endpoint, and nothing one-time-consuming. So
//! `activate`/`identity_gen`/`refresh` keep the trait defaults and the layer
//! rejects `update_connection_credentials` outright.
//!
//! **`verify` owns the reachability probe.** It builds an ephemeral
//! `Operator` from the connection's config plus the candidate bundle and runs
//! `Operator::check()` (one read-only RPC; built, used once, dropped). A
//! construction-time hard failure would let one momentarily-unreachable
//! endpoint prevent the connection from parking for later recovery. Verifying
//! here instead means a failed check **parks** the connection
//! (`AwaitingAuth`) — the `BRIDGE_REPLAY_SAFE_KINDS` invariant the other
//! static-credential kinds honor. The check is judged strictly (any error
//! parks): OpenDAL's error taxonomy cannot discriminate a
//! cryptographically-rejected credential from an authorization-scope denial
//! (`ErrorKind::PermissionDenied` covers both 401 and 403), so any failure
//! parks the connection for explicit recovery.

use std::collections::HashMap;

use async_trait::async_trait;

use ovstorage_plugin::connection::{ConnectionAuthDriver, GrantPolicy, Obtained};
use ovstorage_plugin::{
    AuthEventStream, CancellationToken, ConfigValue, Connection, Error, ErrorCode,
    InteractiveAuthCapability, Result, SecretBundle, race_cancel,
};

use crate::{DriverSpec, build_operator, map_opendal_error};

pub(crate) struct OpenDalDriver {
    spec: &'static DriverSpec,
    /// The connection's config map, kept so `verify` can construct the
    /// ephemeral probe operator from config + candidate credentials.
    config: HashMap<String, ConfigValue>,
}

impl OpenDalDriver {
    pub(crate) fn new(spec: &'static DriverSpec, config: HashMap<String, ConfigValue>) -> Self {
        Self { spec, config }
    }
}

#[async_trait]
impl ConnectionAuthDriver for OpenDalDriver {
    fn backend_kind(&self) -> &str {
        "opendal"
    }

    async fn obtain(
        &self,
        creds: &SecretBundle,
        _policy: GrantPolicy,
        _cancel: Option<CancellationToken>,
    ) -> Result<Obtained> {
        // Both `GrantPolicy` arms behave identically: nothing is resolved
        // over the network and nothing is consumable (static strings only),
        // so a probe never needs `WouldConsume`. "Empty bundle yields
        // anonymous access" is the descriptor's documented contract.
        if creds.fields.is_empty() {
            return Ok(Obtained::Anonymous);
        }
        // Reject fields the routed profile does not consume (sibling parity:
        // s3/azure/gcs all refuse unknown credential fields). Without this, a
        // typo'd field name would be silently dropped by the operator map and
        // the connection would run effectively anonymous while reporting
        // `Authenticated`.
        let allowed = crate::allowed_credential_fields(self.spec);
        if let Some(unknown) = creds
            .fields
            .keys()
            .find(|key| !allowed.contains(&key.as_str()))
        {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                if allowed.is_empty() {
                    format!(
                        "OpenDAL service '{}' takes no credentials; unexpected field '{unknown}'",
                        self.spec.service
                    )
                } else {
                    format!(
                        "unknown credential field '{unknown}' for OpenDAL service '{}' \
                         (expected: {})",
                        self.spec.service,
                        allowed.join(", ")
                    )
                },
            ));
        }
        // The s3 profile signs with SigV4: half a key pair can never sign a
        // request, so refuse it up front rather than let verify fail opaquely.
        if matches!(self.spec.profile, crate::DriverCapabilityProfile::S3)
            && (creds.fields.contains_key("access_key_id")
                != creds.fields.contains_key("secret_access_key"))
        {
            return Err(Error::new(
                ErrorCode::AuthRequired,
                "OpenDAL s3 profile requires both access_key_id and secret_access_key",
            ));
        }
        Ok(Obtained::Bearer {
            credentials: creds.clone(),
            expires_at: None,
        })
    }

    async fn verify(
        &self,
        credentials: &SecretBundle,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        if credentials.fields.is_empty() {
            // Anonymous connections have nothing to prove (and never reach
            // verify in practice — `obtain` reports `Anonymous`); mirror the
            // sibling drivers' no-RPC pass.
            return Ok(());
        }
        // Ephemeral operator (built, checked once, dropped): verification runs
        // before activation so a failure parks instead of failing the Stack rebuild.
        let operator = build_operator(self.spec, &self.config, &credentials.fields)?;
        race_cancel(cancel.as_ref(), async {
            operator.check().await.map_err(map_opendal_error)
        })
        .await
    }

    async fn interactive(
        &self,
        _connection: Connection,
        _capability: InteractiveAuthCapability,
        _cancel: Option<CancellationToken>,
    ) -> Result<AuthEventStream> {
        // OpenDAL has no interactive flow; credentials arrive with the
        // connection. `Unsupported` is the code
        // `Layer::authenticate_connection` documents for exactly this — a
        // backend with no flow, as opposed to `AuthRequired`, which is a flow
        // that exists and could not be driven. `ConnectionSet::authenticate`
        // propagates it before the promoting adapter is built, so a parked
        // connection stays parked instead of being reported `Authenticated` on
        // no grant and no probe.
        Err(Error::new(
            ErrorCode::Unsupported,
            "opendal has no interactive authentication flow; supply credentials \
             with the connection",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::find_driver;
    use ovstorage_plugin::{SecretBytes, SecretValue};

    fn driver_for(service: &str, config: &[(&str, &str)]) -> OpenDalDriver {
        let spec = find_driver(service).expect("allow-listed service");
        let config = config
            .iter()
            .map(|(key, value)| (key.to_string(), ConfigValue::String(value.to_string())))
            .collect();
        OpenDalDriver::new(spec, config)
    }

    fn bundle(fields: &[(&str, &str)]) -> SecretBundle {
        let mut bundle = SecretBundle::default();
        for (key, value) in fields {
            bundle.fields.insert(
                key.to_string(),
                SecretValue::Bytes(SecretBytes(value.as_bytes().to_vec())),
            );
        }
        bundle
    }

    fn s3_pair() -> SecretBundle {
        bundle(&[
            ("access_key_id", "AKIATEST"),
            ("secret_access_key", "wJalrXUtnFEMI/K7MDENG"),
        ])
    }

    #[tokio::test]
    async fn obtain_with_empty_bundle_is_anonymous() {
        let outcome = driver_for("fs", &[("root", "/tmp")])
            .obtain(&SecretBundle::default(), GrantPolicy::AllowConsuming, None)
            .await
            .unwrap();
        assert!(matches!(outcome, Obtained::Anonymous));
    }

    #[tokio::test]
    async fn obtain_with_credentials_is_bearer_without_expiry() {
        let driver = driver_for("s3", &[("bucket", "bkt"), ("region", "us-east-1")]);
        for policy in [GrantPolicy::AllowConsuming, GrantPolicy::NonConsumingOnly] {
            match driver.obtain(&s3_pair(), policy, None).await.unwrap() {
                Obtained::Bearer { expires_at, .. } => assert!(expires_at.is_none()),
                other => panic!("expected Bearer, got {other:?}"),
            }
        }
    }

    /// Sibling parity (s3/azure/gcs): a typo'd credential field is refused,
    /// not silently dropped into an effectively-anonymous operator.
    #[tokio::test]
    async fn obtain_rejects_unknown_credential_field() {
        let driver = driver_for("s3", &[("bucket", "bkt"), ("region", "us-east-1")]);
        let err = driver
            .obtain(
                &bundle(&[("not_a_field", "x")]),
                GrantPolicy::AllowConsuming,
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert!(err.message().contains("not_a_field"));
    }

    /// The fields are validated against the ROUTED profile, not the union of
    /// all profiles: an s3 key pair is meaningless on a webdav connection.
    #[tokio::test]
    async fn obtain_rejects_other_profiles_credential_field() {
        let driver = driver_for("webdav", &[("endpoint", "http://127.0.0.1:1")]);
        let err = driver
            .obtain(&s3_pair(), GrantPolicy::AllowConsuming, None)
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    /// fs has no credential arm at all: any non-empty bundle is a caller
    /// mistake.
    #[tokio::test]
    async fn obtain_rejects_credentials_for_fs() {
        let driver = driver_for("fs", &[("root", "/tmp")]);
        let err = driver
            .obtain(
                &bundle(&[("password", "hunter2")]),
                GrantPolicy::AllowConsuming,
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    /// Half a SigV4 key pair can never sign a request.
    #[tokio::test]
    async fn obtain_rejects_incomplete_s3_pair() {
        let driver = driver_for("s3", &[("bucket", "bkt"), ("region", "us-east-1")]);
        let err = driver
            .obtain(
                &bundle(&[("access_key_id", "AKIATEST")]),
                GrantPolicy::AllowConsuming,
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::AuthRequired);
    }

    #[tokio::test]
    async fn obtain_webdav_password_is_bearer() {
        let driver = driver_for(
            "webdav",
            &[("endpoint", "http://127.0.0.1:1"), ("username", "user")],
        );
        let outcome = driver
            .obtain(
                &bundle(&[("password", "hunter2")]),
                GrantPolicy::AllowConsuming,
                None,
            )
            .await
            .unwrap();
        assert!(matches!(outcome, Obtained::Bearer { .. }));
    }

    /// Anonymous bundles never probe: the endpoint here is unroutable, so a
    /// pass proves the no-RPC short circuit.
    #[tokio::test]
    async fn verify_anonymous_bundle_passes_without_rpc() {
        let driver = driver_for(
            "s3",
            &[
                ("bucket", "bkt"),
                ("region", "us-east-1"),
                ("endpoint", "http://127.0.0.1:1"),
            ],
        );
        driver.verify(&SecretBundle::default(), None).await.unwrap();
    }

    /// A failed `check()` must surface as a PARKING error class (anything but
    /// the Cancelled/InvalidArgument/Internal contract codes), so the
    /// `ConnectionSet` parks the connection instead of failing the add.
    #[tokio::test]
    async fn verify_unreachable_endpoint_fails_with_parking_class() {
        let driver = driver_for(
            "s3",
            &[
                ("bucket", "bkt"),
                ("region", "us-east-1"),
                ("endpoint", "http://127.0.0.1:1"),
            ],
        );
        let err = driver.verify(&s3_pair(), None).await.unwrap_err();
        assert!(
            !matches!(
                err.code(),
                ErrorCode::Cancelled | ErrorCode::InvalidArgument | ErrorCode::Internal
            ),
            "verify failure must park, not hard-error: {err:?}"
        );
    }

    /// Frozen credentials: the trait-default `Unsupported` refresh is what
    /// keeps the lifecycle from looping. Pin it.
    #[tokio::test]
    async fn refresh_is_unsupported() {
        let err = driver_for("fs", &[("root", "/tmp")])
            .refresh(&SecretBundle::default(), None, 0)
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Unsupported);
    }

    /// OpenDAL has no interactive flow to open, so the honest answer is
    /// `Unsupported` rather than a `Succeeded` event asserting a sign-in that
    /// never happened. The refusal does not depend on the connection's state or
    /// on the host's capability: there is no flow under any of them.
    #[tokio::test]
    async fn interactive_reports_no_flow() {
        use ovstorage_plugin::{
            Capabilities, ConnectionAuthState, ConnectionId, ConnectionSource,
            InteractiveAuthCapability, UserMetadata,
        };
        let connection = Connection {
            id: ConnectionId("c1".into()),
            backend_kind: "opendal".into(),
            display_name: "opendal".into(),
            source: ConnectionSource::Runtime { persisted: false },
            capabilities: Capabilities::empty(),
            current_addresses: Vec::new(),
            auth_state: ConnectionAuthState::Anonymous,
            last_probed: None,
            user_metadata: UserMetadata::new(),
        };
        // Every capability, because the claim is that there is no flow under
        // any of them — not that the default happens to be refused.
        for capability in [
            InteractiveAuthCapability::None,
            InteractiveAuthCapability::Headless,
            InteractiveAuthCapability::Browser,
        ] {
            let err = driver_for("fs", &[("root", "/tmp")])
                .interactive(connection.clone(), capability, None)
                .await
                .err()
                .expect("opendal offers no interactive flow to open");
            assert_eq!(
                err.code(),
                ErrorCode::Unsupported,
                "capability {capability:?} must not change the answer"
            );
        }
    }
}
