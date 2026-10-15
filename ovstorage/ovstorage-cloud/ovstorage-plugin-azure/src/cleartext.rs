// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Cleartext-endpoint diagnostics for plain-HTTP endpoints.
//!
//! ADVISORY ONLY. `http://azurite:10000/devstoreaccount1` is the configuration
//! the endpoint keys exist for and `azurite` is a non-loopback DNS name, so
//! nothing here refuses a connection or requires an extra key to express one.
//! What it does is name the exposure, once, at construction.
//!
//! A transport-security gate — refusing a replayable credential over a
//! cleartext link — is a separate decision that belongs at a shared
//! transport/auth boundary across providers rather than as an Azure-specific
//! prerequisite of endpoint support, and it needs its own issue.
//!
//! Split out of `backend.rs` because it is a distinct concern from Azure
//! operations: it reads only the resolved endpoint and credential mode, and
//! nothing else in the data path depends on it.
//!
//! The entry point is [`warn_on_cleartext_endpoint`], called from
//! `AzureBackend::with_auth`.

use crate::auth::AuthSource;
use crate::config::{AzureConnectionConfig, AzureEndpoint};

/// What a plain-HTTP endpoint off the local host puts on the wire under a
/// resolved credential mode.
pub(crate) struct CleartextExposure {
    /// The offending endpoint — whichever tier the connection will actually
    /// address over cleartext.
    pub(crate) endpoint: AzureEndpoint,
    /// Short name of the credential mode, for the operator-facing message.
    pub(crate) mode: &'static str,
    /// What that mode leaks over the link.
    pub(crate) exposure: &'static str,
}

/// Classify what a cleartext off-host endpoint exposes under `source`, or
/// `None` when there is nothing to say.
///
/// Tier selection and the loopback exemption live in
/// [`AzureConnectionConfig::cleartext_offhost_endpoint`]; this function adds
/// the per-mode reading of what crosses the link.
///
/// Every credential mode is covered, including anonymous — that one means only
/// that no credential is attached, while the object bytes, listings and
/// metadata still cross the link in the clear, so it gets the same warning
/// with honest wording rather than a carve-out.
pub(crate) fn cleartext_exposure(
    config: &AzureConnectionConfig,
    source: &AuthSource,
) -> Option<CleartextExposure> {
    let endpoint = config.cleartext_offhost_endpoint()?;
    let (mode, exposure) = match source {
        AuthSource::Anonymous => (
            "anonymous",
            "object bytes, listings and metadata cross the link in the clear and \
             can be read or modified in transit",
        ),
        AuthSource::Sas { .. } => (
            "sas_token",
            "a caller SAS travels in the request URL and is replayable until it expires",
        ),
        AuthSource::Oauth2ClientSecret { .. } => (
            "OAuth client secret",
            "an OAuth access token travels in the `Authorization` header and is \
             replayable until it expires",
        ),
        AuthSource::Oauth2Federated { .. } => (
            "federated OAuth",
            "an OAuth access token travels in the `Authorization` header and is \
             replayable until it expires",
        ),
        // Shared Key itself sends only a per-request HMAC, but the
        // redirect-following read and write paths mint a bearer Service SAS
        // and hand that URL to the caller — an exposure this plugin creates
        // rather than passes through, so it is worth naming too.
        AuthSource::SharedKey { .. } => (
            "account_key",
            "the redirect-following read and write paths mint a Service SAS with \
             spr=https,http and hand that URL to the caller",
        ),
    };
    Some(CleartextExposure {
        endpoint,
        mode,
        exposure,
    })
}

/// Emit the one runtime signal a cleartext off-host endpoint gets.
///
/// Called from `AzureBackend::with_auth` — the shared post-auth construction
/// point, so every constructor is covered and the resolved [`AuthSource`] is
/// in hand, making the message describe what will actually reach the wire
/// rather than which credential fields happen to be present.
pub(crate) fn warn_on_cleartext_endpoint(config: &AzureConnectionConfig, source: &AuthSource) {
    let Some(found) = cleartext_exposure(config, source) else {
        return;
    };
    tracing::warn!(
        plugin = "azure",
        endpoint = %found.endpoint.base(),
        credential_mode = found.mode,
        "Azure connection uses a plain-HTTP endpoint that is not a loopback \
         address; {}. Use https:// for anything that is not a local emulator.",
        found.exposure,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AzureAuth;
    use ovstorage_plugin::{ConfigValue, Result, SecretBundle, SecretBytes, SecretValue};
    use std::collections::HashMap;
    use std::sync::Mutex;

    use base64::Engine as _;

    const ENDPOINT: &str = "http://azurite.internal:10000";

    /// Built through the public parse hook, so these tests exercise the same
    /// validation a real connection would rather than a struct literal that
    /// can drift from it.
    fn config_with(pairs: &[(&str, ConfigValue)]) -> AzureConnectionConfig {
        let mut config = HashMap::from([
            (
                "account".to_string(),
                ConfigValue::String("devstoreaccount1".into()),
            ),
            (
                "container".to_string(),
                ConfigValue::String("assets".into()),
            ),
        ]);
        for (key, value) in pairs {
            config.insert((*key).to_string(), value.clone());
        }
        crate::__test_only_parse_config(&config).expect("fixture config parses")
    }

    fn blob_endpoint(raw: &str) -> (&'static str, ConfigValue) {
        ("blob_endpoint", ConfigValue::String(raw.into()))
    }

    fn bundle_with(credential_fields: &[(&str, &str)]) -> SecretBundle {
        let mut bundle = SecretBundle::default();
        for (field, value) in credential_fields {
            let value = if *field == "account_key" {
                base64::engine::general_purpose::STANDARD.encode([0x11u8; 32])
            } else {
                (*value).to_string()
            };
            bundle.fields.insert(
                (*field).into(),
                SecretValue::Bytes(SecretBytes(value.into_bytes())),
            );
        }
        bundle
    }

    fn source_for(credential_fields: &[(&str, &str)]) -> AuthSource {
        AzureAuth::resolve(&bundle_with(credential_fields))
            .expect("fixture credentials resolve")
            .source()
            .clone()
    }

    /// Drive the whole construction path, not just the classifier, so the
    /// policy is asserted where it actually runs.
    fn build(pairs: &[(&str, ConfigValue)], credential_fields: &[(&str, &str)]) -> Result<()> {
        crate::__test_only_with_credentials(config_with(pairs), bundle_with(credential_fields))
            .map(|_| ())
    }

    // === Captured tracing events ===
    //
    // The warning is the entire operator-facing signal for every allowed
    // cleartext configuration, so it is asserted on directly. Without this,
    // deleting the `tracing::warn!` — or naming the wrong endpoint or
    // credential mode in it — leaves the rest of this module green.
    //
    // Installed ONCE for the whole test binary rather than per-test with
    // `set_default`. `tracing` caches each callsite's `Interest` globally on
    // first hit, so with a thread-local subscriber whichever test reaches the
    // `warn!` first decides whether it is ever evaluated again — and a
    // concurrent test can re-cache it to `never` between install and emit.
    // That raced: this assertion passed in isolation and failed
    // intermittently in the full parallel suite. One process-wide subscriber
    // resolves the callsite once, for good; events are tagged with the
    // emitting thread so parallel tests read only their own.

    static EVENTS: Mutex<Vec<(std::thread::ThreadId, tracing::Level, String)>> =
        Mutex::new(Vec::new());
    static SUBSCRIBER: std::sync::Once = std::sync::Once::new();

    /// Start recording on this thread, discarding anything it logged earlier.
    fn capture_warnings() {
        SUBSCRIBER.call_once(|| {
            use tracing_subscriber::layer::SubscriberExt as _;
            tracing::subscriber::set_global_default(
                tracing_subscriber::registry().with(CaptureLayer),
            )
            .expect("no other global subscriber in this test binary");
        });
        EVENTS
            .lock()
            .expect("capture poisoned")
            .retain(|(thread, _, _)| *thread != std::thread::current().id());
    }

    /// Every WARN this thread has emitted since [`capture_warnings`].
    fn warnings() -> Vec<String> {
        EVENTS
            .lock()
            .expect("capture poisoned")
            .iter()
            .filter(|(thread, level, _)| {
                *thread == std::thread::current().id() && *level == tracing::Level::WARN
            })
            .map(|(_, _, text)| text.clone())
            .collect()
    }

    struct CaptureLayer;

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for CaptureLayer {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let mut visitor = RenderVisitor(String::new());
            event.record(&mut visitor);
            EVENTS.lock().expect("capture poisoned").push((
                std::thread::current().id(),
                *event.metadata().level(),
                visitor.0,
            ));
        }
    }

    struct RenderVisitor(String);

    impl tracing::field::Visit for RenderVisitor {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            use std::fmt::Write as _;
            if !self.0.is_empty() {
                self.0.push(' ');
            }
            let _ = write!(self.0, "{}={value:?}", field.name());
        }
    }

    /// Every cleartext off-host configuration emits exactly one WARN naming
    /// the endpoint, the credential mode and the exposure. Nothing is
    /// refused, so this warning is the whole of the operator-facing signal.
    #[test]
    fn every_cleartext_configuration_warns_with_endpoint_and_mode() {
        for (fields, mode, exposure) in [
            (&[][..], "anonymous", "object bytes"),
            (
                &[("sas_token", "sv=2024-01-01&sig=abc")][..],
                "sas_token",
                "caller SAS",
            ),
            (&[("account_key", "")][..], "account_key", "Service SAS"),
        ] {
            capture_warnings();
            build(&[blob_endpoint(ENDPOINT)], fields)
                .expect("a cleartext endpoint must build; the warning is the only signal");
            let warnings = warnings();
            assert_eq!(
                warnings.len(),
                1,
                "{fields:?} must emit exactly one warning, got {warnings:#?}"
            );
            for needle in [ENDPOINT, mode, exposure] {
                assert!(
                    warnings[0].contains(needle),
                    "{fields:?}: the warning must name {needle:?}, got {:?}",
                    warnings[0],
                );
            }
        }
    }

    /// The silent shapes: nothing leaves the host, or the link is encrypted.
    /// Asserted on the emitted events rather than on the classifier, so a
    /// warning that fired anyway would be caught.
    #[test]
    fn loopback_and_https_endpoints_warn_about_nothing() {
        for endpoint in [
            "http://127.0.0.1:10000/devstoreaccount1",
            "http://[::1]:10000",
            "https://myaccount.privatelink.blob.core.windows.net",
        ] {
            capture_warnings();
            build(&[blob_endpoint(endpoint)], &[("account_key", "")])
                .unwrap_or_else(|err| panic!("{endpoint} must build, got: {err}"));
            assert!(
                warnings().is_empty(),
                "{endpoint} must not warn, got {:#?}",
                warnings()
            );
            assert!(
                cleartext_exposure(
                    &config_with(&[blob_endpoint(endpoint)]),
                    &AuthSource::Anonymous
                )
                .is_none(),
                "{endpoint} must not be flagged"
            );
        }
    }

    /// The issue's headline configuration end to end through the public parse
    /// hook: two keys and the emulator's Shared Key, on a non-loopback
    /// container hostname over plain HTTP. This is the acceptance criterion
    /// the endpoint keys exist for, so it is asserted rather than left
    /// implied by the absence of a gate.
    #[test]
    fn the_container_hostname_azurite_shape_builds_with_two_keys() {
        build(
            &[blob_endpoint("http://azurite:10000/devstoreaccount1")],
            &[("account_key", "")],
        )
        .expect("the headline Azurite shape must build with no extra key");
    }

    /// Per-mode coverage. Nothing is refused — the endpoint keys carry no
    /// credential restriction — so what is asserted is that every mode BUILDS
    /// over a non-loopback cleartext endpoint and that the classifier names
    /// the right exposure for each, which is what the warning reads.
    #[test]
    fn cleartext_offhost_warns_for_every_mode_and_refuses_none() {
        for (fields, mode, expected) in [
            (&[][..], "anonymous", "object bytes"),
            (
                &[("sas_token", "sv=2024-01-01&sig=abc")][..],
                "sas_token",
                "caller SAS",
            ),
            (
                &[
                    ("client_id", "id"),
                    ("client_secret", "secret"),
                    ("tenant_id", "tenant"),
                ][..],
                "OAuth client secret",
                "OAuth access token",
            ),
            (
                &[
                    ("client_id", "id"),
                    ("tenant_id", "tenant"),
                    ("federated_token_file", "/var/run/secrets/token"),
                ][..],
                "federated OAuth",
                "OAuth access token",
            ),
            // Shared Key leaks no bearer itself, but its redirect paths mint
            // one — the exposure this plugin creates rather than passes on.
            (&[("account_key", "")][..], "account_key", "Service SAS"),
        ] {
            if let Err(err) = build(&[blob_endpoint(ENDPOINT)], fields) {
                panic!("{fields:?} on a cleartext endpoint must build, got: {err}");
            }

            let found = cleartext_exposure(
                &config_with(&[blob_endpoint(ENDPOINT)]),
                &source_for(fields),
            )
            .unwrap_or_else(|| panic!("{fields:?} must classify an exposure"));
            assert_eq!(found.endpoint.base(), ENDPOINT);
            assert_eq!(found.mode, mode, "{fields:?}: classified as the wrong mode");
            assert!(
                found.exposure.contains(expected),
                "{fields:?}: exposure must mention {expected:?}, got {:?}",
                found.exposure,
            );
        }
    }

    /// A `dfs_endpoint` under a FLAT namespace is inert — no request ever
    /// addresses the DFS tier — so it must not produce a warning, which is
    /// what `hns_with_only_a_dfs_endpoint_is_supported` calls a supported
    /// shape. Under HNS the same endpoint does sign, so it is flagged.
    #[test]
    fn an_inert_dfs_endpoint_is_not_flagged_until_hns_addresses_it() {
        let with_hns = |hns: bool| {
            let mut pairs = vec![
                blob_endpoint("https://blob.example.com"),
                (
                    "dfs_endpoint",
                    ConfigValue::String("http://dfs.internal:10001".into()),
                ),
            ];
            if hns {
                pairs.push(("hierarchical_namespace", ConfigValue::Bool(true)));
            }
            config_with(&pairs)
        };
        assert!(
            cleartext_exposure(&with_hns(false), &AuthSource::Anonymous).is_none(),
            "a flat-namespace connection never addresses the DFS tier"
        );
        let found = cleartext_exposure(&with_hns(true), &AuthSource::Anonymous)
            .expect("under HNS the DFS tier signs, so it is flagged");
        assert_eq!(found.endpoint.base(), "http://dfs.internal:10001");
    }

    /// The change feed resolves through its OWN precedence chain
    /// (`test_change_feed_endpoint` → `blob_endpoint` → natural host), so a
    /// loopback data-path override does not make it clean: `ChangeFeedClient`
    /// still follows `blob_endpoint` and signs over that link. Scanning only
    /// the data tiers classified this shape as safe.
    #[test]
    fn an_off_host_change_feed_is_flagged_even_behind_a_loopback_data_override() {
        let config = config_with(&[
            blob_endpoint("http://feed.internal:10000"),
            ("change_feed_enabled", ConfigValue::Bool(true)),
            (
                "__test_endpoint",
                ConfigValue::String("http://127.0.0.1:9999".into()),
            ),
        ]);
        // The data path really is loopback here — that is what made this
        // shape slip through.
        assert_eq!(config.blob_url_base(), "http://127.0.0.1:9999");
        assert_eq!(config.change_feed_base_url(), "http://feed.internal:10000");
        let found = cleartext_exposure(&config, &AuthSource::Anonymous)
            .expect("the change feed addresses an off-host cleartext endpoint");
        assert_eq!(found.endpoint.base(), "http://feed.internal:10000");

        // With the change feed disabled nothing addresses that endpoint, so
        // the same configuration is inert.
        let disabled = config_with(&[
            blob_endpoint("http://feed.internal:10000"),
            (
                "__test_endpoint",
                ConfigValue::String("http://127.0.0.1:9999".into()),
            ),
        ]);
        assert!(
            cleartext_exposure(&disabled, &AuthSource::Anonymous).is_none(),
            "a disabled change feed must not flag an endpoint nothing reads"
        );
    }
}
