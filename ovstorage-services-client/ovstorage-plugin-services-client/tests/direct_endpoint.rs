// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Direct gRPC endpoint mode.
//!
//! A deployment that knows its storage gRPC address and runs no discovery
//! service configures `address = grpc://host:port`. These tests drive that mode
//! end to end.
//!
//! The gRPC server here binds a **real loopback port**, unlike every other
//! harness in this crate, which injects a pre-connected `tokio::io::duplex`
//! channel. That is deliberate and it is the point of the feature: the claim
//! under test is that the *configured address* is what gets dialed, and a
//! duplex seam would prove nothing about address resolution.
//!
//! Coverage:
//!
//! - the configured endpoint is dialed, with no HTTP server in existence;
//! - only the `storage` service kind resolves, and the connection says so in
//!   its advertised capabilities rather than failing at first use;
//! - the connection performs no auth HTTP at all, and refuses both interactive
//!   sign-in and plugin-driven refresh with `Unsupported`;
//! - it serves anonymously with no credential, and from a host-supplied access
//!   token when there is one — including one replaced on a LIVE connection,
//!   which is how a host rotates a bearer without tearing the connection down;
//! - it takes no persistence claim and touches no stored secret, with or
//!   without a credential;
//! - the address-roots watcher does not wait for a bearer.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;

use ovstorage_plugin::connection::{ConnectionAuthDriver, GrantPolicy, Obtained};
use ovstorage_plugin::{
    ConfigValue, Connection, ConnectionAuthState, ConnectionId, ConnectionSource, ErrorCode,
    InteractiveAuthCapability, SecretBundle, UserMetadata,
};
use ovstorage_plugin_services_client::auth::DiscoveryState;
use ovstorage_plugin_services_client::backend::OmniverseStorageBackend;
use ovstorage_plugin_services_client::config::{self, ServiceLocation};
use ovstorage_plugin_services_client::driver::OmniverseStorageDriver;
use ovstorage_plugin_services_client::factory::{connection_capabilities, descriptor_capabilities};
use ovstorage_plugin_services_client::transport::OmniverseStorageTransport;
use ovstorage_services_protos::nvidia::omniverse::storage::capabilities::v1alpha as cap;
use tonic::{Request, Response, Status};

const ROOT: &str = "omni://direct/root/";

// ---- a real gRPC server on a real port --------------------------------------

#[derive(Default)]
struct CapState {
    top_level_calls: usize,
    last_bearer: Option<String>,
    /// Every `authorization` header this server has been sent, in order.
    ///
    /// `last_bearer` alone is not a safe observation once a LAYER is involved:
    /// the layer spawns a one-shot address-roots watcher whose RPC lands on its
    /// own schedule, so "the most recent request" races it. Membership does not.
    seen_bearers: Vec<Option<String>>,
    /// A bearer the server refuses, so a test can drive the case where a host
    /// rotates onto a token the deployment does not accept. `None` accepts
    /// everything, which is what every other test in this file wants.
    rejected_bearer: Option<String>,
    /// How many requests were refused, so a test asserting on a refusal can
    /// show the refusal happened rather than inferring it from an error whose
    /// text could have come from anywhere.
    refused_calls: usize,
}

struct FakeCapabilities {
    state: Arc<Mutex<CapState>>,
}

#[tonic::async_trait]
impl cap::capabilities_service_server::CapabilitiesService for FakeCapabilities {
    async fn list_top_level_addresses(
        &self,
        req: Request<cap::ListTopLevelAddressesRequest>,
    ) -> std::result::Result<Response<cap::ListTopLevelAddressesResponse>, Status> {
        let mut st = self.state.lock().unwrap();
        st.top_level_calls += 1;
        st.last_bearer = req
            .metadata()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let bearer = st.last_bearer.clone();
        st.seen_bearers.push(bearer);
        if st.rejected_bearer.is_some() && st.rejected_bearer == st.last_bearer {
            st.refused_calls += 1;
            return Err(Status::unauthenticated(
                "bearer refused by the test fixture",
            ));
        }
        // Two roots no caller could ever act on, ahead of the usable one.
        //
        // `omni:team-share` is authority-less: every request address is parsed
        // through `address::parse`, which refuses that class, so an installed
        // route on it can only ever answer `NoRoute`. `omni://server/a//b/`
        // does not survive canonicalization — it names a different node than it
        // spells. Both are dropped by `factory::list_top_level_addresses`, and
        // the `roots.len() == 1` assertion in
        // `a_direct_connection_publishes_its_root_without_watch` is what
        // detects it if either stops being.
        //
        // Placed FIRST so a filter that gave up on the first bad entry would
        // publish nothing at all rather than silently publishing too much.
        Ok(Response::new(cap::ListTopLevelAddressesResponse {
            items: vec![
                cap::TopLevelAddressEntry {
                    top_level_address: "omni:team-share".into(),
                },
                cap::TopLevelAddressEntry {
                    top_level_address: "omni://server/a//b/".into(),
                },
                cap::TopLevelAddressEntry {
                    top_level_address: ROOT.into(),
                },
            ],
        }))
    }

    async fn list_routes(
        &self,
        _req: Request<cap::ListRoutesRequest>,
    ) -> std::result::Result<Response<cap::ListRoutesResponse>, Status> {
        Ok(Response::new(cap::ListRoutesResponse::default()))
    }

    async fn list_services(
        &self,
        _req: Request<cap::ListServicesRequest>,
    ) -> std::result::Result<Response<cap::ListServicesResponse>, Status> {
        Ok(Response::new(cap::ListServicesResponse::default()))
    }
}

/// Bind a real TCP port and serve `CapabilitiesService` on it. Returns the
/// bound authority (`127.0.0.1:<port>`) and the server's observation state.
async fn spawn_grpc_server() -> (String, Arc<Mutex<CapState>>) {
    let state = Arc::new(Mutex::new(CapState::default()));
    // The SAME listener is bound and then served. Reading `local_addr`, dropping
    // the listener and re-binding would leave a window in which another process
    // takes the port, which fails as a connect error and reads exactly like the
    // resolution bug these tests exist to catch.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let service = FakeCapabilities {
        state: state.clone(),
    };
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(cap::capabilities_service_server::CapabilitiesServiceServer::new(service))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .ok();
    });
    (addr.to_string(), state)
}

fn cfg(value: &str) -> HashMap<String, ConfigValue> {
    let mut map = HashMap::new();
    map.insert("address".into(), ConfigValue::String(value.into()));
    map
}

/// The `ServiceLocation` for a direct endpoint at `authority`, built through
/// the real config path rather than by constructing the enum by hand — so the
/// test exercises the parse an operator's config actually takes.
fn direct_location(authority: &str) -> ServiceLocation {
    let location = config::service_location(&cfg(&format!("grpc://{authority}"))).unwrap();
    assert!(
        location.discovery_url().is_none(),
        "a grpc:// value must resolve to a direct endpoint, got {location:?}",
    );
    location
}

fn connection(id: &str) -> Connection {
    Connection {
        id: ConnectionId(id.into()),
        backend_kind: config::KIND.into(),
        display_name: format!("direct:{id}"),
        source: ConnectionSource::Runtime { persisted: false },
        capabilities: ovstorage_plugin::Capabilities::empty(),
        current_addresses: Vec::new(),
        auth_state: ConnectionAuthState::Anonymous,
        last_probed: None,
        user_metadata: UserMetadata::new(),
    }
}

fn direct_driver(location: &ServiceLocation) -> OmniverseStorageDriver {
    direct_driver_with_plaintext_credentials(location, false)
}

/// A direct driver with the cleartext-credential opt-in set explicitly.
///
/// Every server in this file listens on `127.0.0.1`, which is loopback and so
/// needs no opt-in — that is why [`direct_driver`] can pass `false` and every
/// bearer test in this file still sends one. Only a test naming a non-loopback
/// host reaches the refusal.
fn direct_driver_with_plaintext_credentials(
    location: &ServiceLocation,
    allow: bool,
) -> OmniverseStorageDriver {
    let state = DiscoveryState::new("default");
    let transport = OmniverseStorageTransport::new(location.clone(), state.clone());
    OmniverseStorageDriver::new(
        location.discovery_url().map(str::to_string),
        state,
        transport,
        reqwest::Client::new(),
        "",
        allow,
    )
    .unwrap()
}

// ---- the configured address is what gets dialed ------------------------------

/// The load-bearing test for this feature: with no discovery service in
/// existence, a `grpc://` configured address reaches a real gRPC server at that
/// address.
///
/// Mutation control, run: removing the `DirectGrpc` arm of `resolve_kind` makes
/// this fail — the RPC never reaches the server, which reports zero calls.
///
/// It reddens two siblings as well, both legitimately:
/// `the_roots_watcher_does_not_wait_for_a_bearer_that_cannot_come` drives
/// `list_top_level_addresses` over the same channel, and
/// `only_the_storage_kind_resolves_from_a_direct_endpoint` then gets the
/// generic no-discovery-service error instead of one naming
/// `notification-consumer`. Three tests in this file; nothing outside it moves.
#[tokio::test]
async fn a_direct_endpoint_is_dialed_with_no_discovery_service_anywhere() {
    let (authority, server_state) = spawn_grpc_server().await;
    let location = direct_location(&authority);
    let state = DiscoveryState::new("default");
    let transport = OmniverseStorageTransport::new(location, state);

    let mut client = transport
        .capabilities_client()
        .await
        .expect("a direct endpoint needs no discovery to build a storage client");
    let response = client
        .list_top_level_addresses(cap::ListTopLevelAddressesRequest {})
        .await
        .expect("the configured endpoint answers");

    // This assertion is on the RAW RPC response, before any filtering: the
    // point here is that the call reached the configured endpoint at all. The
    // two unusable entries the fixture also publishes are dropped one layer up,
    // which is what `a_direct_connection_publishes_its_root_without_watch`
    // asserts.
    let items = response.into_inner().items;
    assert_eq!(
        items.len(),
        3,
        "fixture must be non-empty or the assertion below is vacuous",
    );
    assert_eq!(items[2].top_level_address, ROOT);

    let st = server_state.lock().unwrap();
    assert_eq!(
        st.top_level_calls, 1,
        "the RPC must have reached THIS server, at the configured address",
    );
    assert_eq!(
        st.last_bearer, None,
        "a direct-endpoint connection is anonymous, so no authorization header is sent",
    );
}

/// A direct endpoint names one service. Asking for another is refused by name,
/// rather than dialed at the storage address on the chance it serves that too.
#[tokio::test]
async fn only_the_storage_kind_resolves_from_a_direct_endpoint() {
    let (authority, _state) = spawn_grpc_server().await;
    let location = direct_location(&authority);
    let transport = OmniverseStorageTransport::new(location, DiscoveryState::new("default"));

    let err = transport
        .event_consumer_client()
        .await
        .expect_err("the notification-consumer service cannot be resolved without discovery");
    assert_eq!(err.code(), ErrorCode::NotConfigured);
    assert!(
        err.message().contains("notification-consumer"),
        "the refusal must name the service that is missing, got: {}",
        err.message(),
    );
    assert!(
        err.message().contains("discovery"),
        "the refusal must say what would supply it, got: {}",
        err.message(),
    );
}

/// And the connection says so up front, instead of advertising a watch it
/// cannot serve and failing at the first call.
#[test]
fn a_direct_connection_does_not_advertise_directory_watching() {
    let kind_wide = descriptor_capabilities();
    assert!(
        kind_wide.supports_watch_directory,
        "the kind advertises watch; without that this test proves nothing",
    );

    let direct = connection_capabilities(false);
    assert!(!direct.supports_watch_directory);
    assert!(!direct.watch_directory_resumable);
    assert_eq!(
        direct.watch_directory_kinds,
        ovstorage_plugin::ChangeKindSet {
            created: false,
            deleted: false,
            modified: false,
            metadata_changed: false,
        },
    );

    // A discovery connection is untouched: the downgrade is per-connection, not
    // a change to what the kind offers.
    assert_eq!(connection_capabilities(true), kind_wide);
}

// ---- anonymous, and provably so ---------------------------------------------

/// Direct mode is anonymous and performs no auth HTTP at all.
///
/// The control is the mock server bound at *exactly* the authority the
/// connection is configured with: "zero requests" against a server the code
/// could never have contacted would be true no matter what the code did.
#[tokio::test]
async fn direct_mode_is_anonymous_and_makes_no_auth_requests() {
    let auth_server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("{}"))
        .mount(&auth_server)
        .await;
    let authority = auth_server
        .uri()
        .strip_prefix("http://")
        .unwrap()
        .to_string();

    // Prove the mock is live and counting before asserting it saw nothing.
    reqwest::get(format!("http://{authority}/probe"))
        .await
        .expect("the mock server is reachable");
    assert_eq!(
        auth_server.received_requests().await.map(|r| r.len()),
        Some(1),
        "the counter must be working before 'zero more' means anything",
    );

    // The connection is configured at the SAME authority. If any auth fetch
    // were still attempted, this server would record it.
    let driver = direct_driver(&direct_location(&authority));
    let obtained = driver
        .obtain(&SecretBundle::default(), GrantPolicy::AllowConsuming, None)
        .await
        .expect("a direct endpoint resolves without a grant");
    assert!(
        matches!(obtained, Obtained::Anonymous),
        "expected Anonymous, got {obtained:?}",
    );

    assert_eq!(
        auth_server.received_requests().await.map(|r| r.len()),
        Some(1),
        "no auth-config or OIDC request may be made for a direct endpoint",
    );
}

/// No auth-config means no flow to drive, under every capability the host can
/// offer — the claim is that there is no flow at all, not that the default one
/// happens to be refused. `Unsupported` rather than `AuthRequired` is the
/// distinction the cloud backends settled on: a backend with no flow, versus a
/// flow that exists and could not be driven.
#[tokio::test]
async fn direct_mode_refuses_interactive_sign_in_under_every_capability() {
    let (authority, _state) = spawn_grpc_server().await;
    let driver = direct_driver(&direct_location(&authority));

    for capability in [
        InteractiveAuthCapability::None,
        InteractiveAuthCapability::Headless,
        InteractiveAuthCapability::Browser,
    ] {
        let err = driver
            .interactive(connection("direct"), capability, None)
            .await
            .err()
            .expect("a direct endpoint offers no interactive flow to open");
        assert_eq!(
            err.code(),
            ErrorCode::Unsupported,
            "capability {capability:?} must be refused as unsupported, not as auth-required",
        );
    }
}

/// Likewise a refresh: there is no token endpoint to refresh against.
#[tokio::test]
async fn direct_mode_refuses_refresh() {
    let (authority, _state) = spawn_grpc_server().await;
    let driver = direct_driver(&direct_location(&authority));

    let err = driver
        .refresh(&SecretBundle::default(), None, 0)
        .await
        .expect_err("a direct endpoint has no OIDC token endpoint");
    assert_eq!(err.code(), ErrorCode::Unsupported);
}

// ---- no keyring participation ------------------------------------------------

/// A direct-endpoint connection has no durable lineage, so it must take no
/// persistence claim and touch no stored secret.
///
/// This is not hygiene. Arriving on a key another claim already holds records a
/// contention, and contention is never cleared: the real connection on that key
/// then reports non-exclusive for the rest of its life, its next credential
/// operation raises `AuthRequired`, and on a keyring-lineage bring-up that
/// purges its stored refresh token. An anonymous connection merely starting
/// could therefore destroy a real one's credential — so the assertion is on the
/// claim itself, not merely on the return values, because the damage is to the
/// sibling and no return value here would show it.
#[tokio::test]
async fn direct_mode_takes_no_persistence_claim_and_stores_nothing() {
    let (authority, _state) = spawn_grpc_server().await;
    let driver = direct_driver(&direct_location(&authority));

    assert_eq!(
        driver.stable_id(),
        None,
        "a direct endpoint has no durable key",
    );
    assert!(
        driver.load_credentials().await.unwrap().is_none(),
        "there is nothing stored to warm-continue from",
    );
    driver
        .persist_credentials(&SecretBundle::default())
        .await
        .expect("persisting nothing succeeds");
    driver
        .delete_credentials()
        .await
        .expect("deleting nothing succeeds");

    // The claim was never taken. `ConnectionSet` skips its cross-process purge
    // lock AND disables its sibling-sharing guard when `stable_id()` is `None`,
    // so anything this driver did to a shared key would be unguarded.
    assert!(
        !driver.has_persistence_claim(),
        "a direct-endpoint connection must never acquire a persistence claim",
    );
}

// ---- the roots watcher does not wait for a bearer -----------------------------

/// `watch_address_roots` blocks until a bearer is installed, because on a
/// discovery deployment a grant or a sign-in will eventually install one and
/// the probe behind the watcher is auth-gated. A direct endpoint may hold a
/// bearer — the host can supply one — but nothing here will ever produce one on
/// its own, and such a connection is equally allowed to hold none. So waiting
/// there is not slow, it is unbounded. It is also unnecessary: bring-up
/// installs a supplied bearer before any root discovery runs.
///
/// Making `requires_bearer()` return `true` unconditionally hangs this test and
/// only this test — verified.
#[tokio::test]
async fn the_roots_watcher_does_not_wait_for_a_bearer() {
    let (authority, _state) = spawn_grpc_server().await;
    let location = direct_location(&authority);
    let transport =
        OmniverseStorageTransport::new(location.clone(), DiscoveryState::new("default"));
    let backend = OmniverseStorageBackend::new(
        location.locator().to_string(),
        connection_capabilities(false),
        transport,
    );

    let opened = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        backend.watch_address_roots(None),
    )
    .await
    .expect("the watcher must not park waiting for a token that can never arrive");
    assert!(opened.is_ok(), "the watcher opens: {:?}", opened.err());
}

// ---- the layer wires it up, not just the helpers -----------------------------

/// Everything above builds the transport, backend and driver by hand. This
/// drives the real wiring in `OmniverseStorageLayer::build_scaffold` — the code
/// that decides, from one config value, that the connection is direct and
/// therefore gets the downgraded capability set and a driver with no discovery
/// URL. Without this the helpers are green and their call sites are untested,
/// which is how a correct helper ships behind a call site that never uses it.
///
/// Mutation control, run: passing `descriptor_capabilities()` at the call site
/// instead of `connection_capabilities(discovery_url.is_some())` reddens this
/// test and nothing else — the helper-level test cannot see that change.
#[tokio::test]
async fn the_layer_builds_a_direct_connection_from_config_alone() {
    use ovstorage_plugin::{BackendFactory, Extensions};

    let (authority, server_state) = spawn_grpc_server().await;
    let layer = ovstorage_plugin_services_client::layer::OmniverseStorageLayerFactory::default()
        .create_backend("direct-layer", &cfg(&format!("grpc://{authority}")), None)
        .await
        .expect("a direct-endpoint config brings a connection up with no discovery service");

    let (snapshot, _updates) = layer
        .list_address_roots(&Extensions::default(), None)
        .await
        .expect("roots are published");
    assert_eq!(
        snapshot.roots.len(),
        1,
        "the fixture must publish a root, or every assertion below is vacuous",
    );
    let root = &snapshot.roots[0];
    assert_eq!(root.root.as_str(), ROOT);
    assert!(
        !root.capabilities.supports_watch_directory,
        "a direct connection must not advertise a watch it cannot serve",
    );
    assert!(!root.capabilities.watch_directory_resumable);
    // A capability served by the storage endpoint is untouched — the downgrade
    // is surgical, not a blanket reset.
    assert!(root.capabilities.supports_list);

    assert!(
        server_state.lock().unwrap().top_level_calls >= 1,
        "the layer reached the configured endpoint",
    );
}

/// A direct connection gives the SAME answer to a probe as to a real bring-up,
/// for each bundle shape.
///
/// The second bundle is the awkward one: an empty access token with a refresh
/// token, which is exactly the shape that makes a discovery connection report
/// `WouldConsume` under a probe policy. Before the direct check was hoisted
/// above that gate, probing a direct connection returned `WouldConsume` — the
/// layer reports that as unverifiable — while adding the identical connection
/// succeeded. One config, two answers.
///
/// The two answers differ from each other, and that difference is the point:
/// no credential at all is a connection with none, while a refresh token is a
/// credential this deployment has no token endpoint to redeem — a failed
/// credential operation, not an anonymous one. Answering `Anonymous` to the
/// second would remove a working bearer on a live connection and report
/// success.
#[tokio::test]
async fn direct_mode_answers_a_probe_and_a_bring_up_alike() {
    let (authority, _state) = spawn_grpc_server().await;
    let driver = direct_driver(&direct_location(&authority));

    let refresh_only = ovstorage_plugin::oauth_secret_store::oauth_bundle(
        "",
        Some("a-refresh-token"),
        Some(std::time::SystemTime::now() - std::time::Duration::from_secs(3600)),
    );

    for policy in [GrantPolicy::AllowConsuming, GrantPolicy::NonConsumingOnly] {
        let obtained = driver
            .obtain(&SecretBundle::default(), policy, None)
            .await
            .expect("no credential is not an error");
        assert!(
            matches!(obtained, Obtained::Anonymous),
            "expected Anonymous under {policy:?}, got {obtained:?}",
        );

        let err = driver
            .obtain(&refresh_only, policy, None)
            .await
            .expect_err("a refresh token cannot be redeemed without a token endpoint");
        assert_eq!(
            err.code(),
            ErrorCode::Unsupported,
            "expected the same refusal under {policy:?}",
        );
        assert!(
            !err.message().contains("a-refresh-token"),
            "a refusal must not repeat the credential it refused, got: {}",
            err.message(),
        );
    }
}

// ---- a host-supplied bearer -----------------------------------------------

/// The `oauth` bundle a host hands over when it minted the access token itself:
/// no refresh token, because there is no token endpoint to redeem one against.
fn bearer_bundle(access: &str) -> SecretBundle {
    ovstorage_plugin::oauth_secret_store::oauth_bundle(access, None, None)
}

/// The same credential as a **configuration file** or the CLI produces it.
///
/// `[connections.credentials] oauth = "<token>"` and `--auth` fields are
/// strings, and both entry points build every credential as
/// `SecretValue::Bytes`. The structured `OAuthToken` above needs a programmatic
/// caller. So this is the spelling an operator with a config file sends, and a
/// feature that reads only the other one is unreachable from configuration.
fn configured_bearer_bundle(access: &str) -> SecretBundle {
    let mut bundle = SecretBundle::default();
    bundle.fields.insert(
        "oauth".into(),
        ovstorage_plugin::SecretValue::Bytes(ovstorage_plugin::SecretBytes(
            access.as_bytes().to_vec(),
        )),
    );
    bundle
}

/// A direct endpoint serves from an access token the host supplies, and the
/// token reaches the server.
///
/// Asserted at the SERVER, on the `authorization` metadata of a real RPC over a
/// real socket, rather than on `obtain`'s return value: the claim is that the
/// bearer is attached to traffic, and a return value would not show that.
///
/// Mutation control, run: returning `Obtained::Anonymous` unconditionally from
/// the direct arm of `obtain` reddens this test and
/// `a_host_can_replace_a_direct_connections_bearer_while_it_is_live`, and
/// nothing else.
#[tokio::test]
async fn a_direct_endpoint_sends_a_host_supplied_bearer() {
    let (authority, server_state) = spawn_grpc_server().await;
    let location = direct_location(&authority);
    let driver = direct_driver(&location);

    // The supplied bundle carries an expiry ON PURPOSE. Asserting `None` below
    // against an input that never had one asserts the fixture, not the code: a
    // driver that propagated the supplied expiry would answer `None` for that
    // input too and the assertion could not fail.
    let supplied = ovstorage_plugin::oauth_secret_store::oauth_bundle(
        "host-minted-token",
        None,
        Some(std::time::SystemTime::now() + std::time::Duration::from_secs(3600)),
    );
    let obtained = driver
        .obtain(&supplied, GrantPolicy::AllowConsuming, None)
        .await
        .expect("a supplied access token needs no grant");
    let Obtained::Bearer {
        credentials,
        expires_at,
    } = obtained
    else {
        panic!("expected a bearer, got {obtained:?}");
    };
    assert_eq!(
        expires_at, None,
        "a host-supplied bearer schedules no background refresh: this connection can mint no \
         successor, and `ConnectionSet::spawn_refresh` starts a task exactly when this is Some",
    );
    // The same drop, one level in. `activate` installs THIS bundle on the live
    // cell, so an expiry surviving here starts the refresh schedule whose only
    // answer on this connection is `Unsupported`, whatever the value above says.
    let Some(ovstorage_plugin::SecretValue::OAuthToken { expires_at, .. }) =
        credentials.fields.get("oauth")
    else {
        panic!("a bearer carries an oauth field");
    };
    assert_eq!(
        *expires_at, None,
        "the effective bundle installed on the live cell carries no expiry either",
    );

    // Prove it via `activate`, the call the lifecycle makes once a bearer is
    // accepted — installing on the live cell by hand would test the test.
    assert!(
        driver
            .activate(&credentials, driver.identity_gen())
            .await
            .expect("installing a proven bearer succeeds"),
    );

    let mut client = driver
        .transport()
        .capabilities_client()
        .await
        .expect("a direct endpoint needs no discovery to build a storage client");
    client
        .list_top_level_addresses(cap::ListTopLevelAddressesRequest {})
        .await
        .expect("the configured endpoint answers");

    let st = server_state.lock().unwrap();
    assert_eq!(st.top_level_calls, 1, "the RPC reached this server");
    assert_eq!(
        st.last_bearer.as_deref(),
        Some("Bearer host-minted-token"),
        "the host's access token must ride the request",
    );
}

/// The feature this change exists for: a host rotating a token on a **live**
/// connection, through the standard credential-update call, without tearing the
/// connection down.
///
/// Driven through the real `Layer` surface — `add_connection` then
/// `update_connection_credentials` — rather than through the driver, because
/// the driver-level answer says nothing about whether the layer's update path
/// reaches it. RPCs before and after are compared at the server, so a rotation
/// that returned `Ok` while leaving the old bearer installed would fail here.
#[tokio::test]
async fn a_host_can_replace_a_direct_connections_bearer_while_it_is_live() {
    use ovstorage_plugin::{
        BackendFactory, ConnectionKey, ConnectionRequest, LayerConnectionRequest,
        Request as LayerRequest, UpdateConnectionCredentialsRequest,
    };

    let (authority, server_state) = spawn_grpc_server().await;
    let layer = ovstorage_plugin_services_client::layer::OmniverseStorageLayerFactory::default()
        .create_backend("direct-rotate", &HashMap::new(), None)
        .await
        .expect("an empty config builds an unseeded layer");

    let connection = layer
        .add_connection(
            LayerRequest::new(LayerConnectionRequest {
                target: "direct-rotate".into(),
                connection: ConnectionRequest {
                    backend_kind: config::KIND.into(),
                    config: cfg(&format!("grpc://{authority}")),
                    credentials: bearer_bundle("first-token"),
                    persist: false,
                    display_name: None,
                },
            }),
            None,
        )
        .await
        .expect("a direct connection with a supplied bearer comes up");
    assert!(
        matches!(
            connection.auth_state,
            ovstorage_plugin::ConnectionAuthState::Authenticated { .. }
        ),
        "a supplied bearer authenticates the connection, got {:?}",
        connection.auth_state,
    );
    assert_eq!(
        server_state.lock().unwrap().last_bearer.as_deref(),
        Some("Bearer first-token"),
        "bring-up's own root discovery already carries the first token",
    );

    let mark = server_state.lock().unwrap().seen_bearers.len();
    let rotated = layer
        .update_connection_credentials(
            LayerRequest::new(UpdateConnectionCredentialsRequest {
                key: ConnectionKey {
                    target: "direct-rotate".into(),
                    id: connection.id.clone(),
                },
                credentials: bearer_bundle("second-token"),
            }),
            None,
        )
        .await
        .expect("a host may replace the bearer on a live direct connection");
    assert_eq!(
        rotated.id, connection.id,
        "the connection is the same one, not a replacement",
    );

    // COUNTED, not merely present, and the count is what makes this test able
    // to fail at all.
    //
    // The update drives exactly two requests over the fixture's socket: `verify`
    // offers the candidate over an EPHEMERAL auth state wrapped around the live
    // channel, and the layer then re-lists roots over the LIVE cell. So a
    // membership assertion proves only that the candidate was *offered* — it
    // would pass with the install deleted, because `verify` alone puts the new
    // token on the wire. Two occurrences can only happen if the second request,
    // the one reading the live cell, also carried it: that is the install.
    //
    // A stale roots watcher spawned at add-time can add requests here, and it
    // reads the live cell, so after a successful install it would RAISE the
    // count. It cannot manufacture a false pass, because with the install
    // deleted the live cell still holds the previous token and the only request
    // able to carry the successor at all is the `verify` — one occurrence.
    let after = {
        let st = server_state.lock().unwrap();
        st.seen_bearers[mark..].to_vec()
    };
    let carried = after
        .iter()
        .filter(|b| b.as_deref() == Some("Bearer second-token"))
        .count();
    assert!(
        carried >= 2,
        "the rotation must be INSTALLED, not merely offered: the verify and the live-cell \
         request after it must both carry the new token, saw {carried} of {after:?}",
    );
    assert!(
        matches!(
            rotated.auth_state,
            ovstorage_plugin::ConnectionAuthState::Authenticated { .. }
        ),
        "the rotated connection is authenticated, got {:?}",
        rotated.auth_state,
    );
}

/// A bundle carrying more than a direct endpoint can act on: the access token is
/// used, and the fields needing an OIDC token endpoint are stripped from the
/// effective bundle rather than carried into the live cell.
///
/// The stripping is what keeps `classify` honest. A refresh token or a cached
/// `client_credentials` pair on the live cell makes `has_silent_grant` true, and
/// a rejected bearer would then be classified as recoverable — sending the
/// recovery loop to drive a `refresh` this connection can only answer
/// `Unsupported`, instead of surfacing the rejection to a caller who can supply
/// a new token.
///
/// Mutation control, run: returning the input bundle unchanged from
/// `direct_bearer` reddens six tests — this one,
/// `a_direct_endpoint_sends_a_host_supplied_bearer`,
/// `a_configured_token_string_reaches_the_wire`,
/// `a_blank_oauth_value_does_not_remove_the_bearer_in_use`, and the driver's
/// `the_direct_credential_predicates_read_each_bundle_shape` and
/// `a_token_that_cannot_ride_in_a_header_is_refused_where_it_is_accepted`.
/// Counted rather than asserted from reading: every one of them observes the
/// EFFECTIVE bundle, so the mutation has a wide radius and this test is not
/// the sole control on it.
#[tokio::test]
async fn a_direct_endpoint_strips_what_it_cannot_redeem() {
    use ovstorage_plugin::{SecretBytes, SecretValue};

    let (authority, _state) = spawn_grpc_server().await;
    let driver = direct_driver(&direct_location(&authority));

    let mut creds = ovstorage_plugin::oauth_secret_store::oauth_bundle(
        "usable-access-token",
        Some("a-refresh-token"),
        None,
    );
    creds.fields.insert(
        "client_id".into(),
        SecretValue::Bytes(SecretBytes(b"an-id".to_vec())),
    );
    creds.fields.insert(
        "client_secret".into(),
        SecretValue::Bytes(SecretBytes(b"a-secret".to_vec())),
    );

    let obtained = driver
        .obtain(&creds, GrantPolicy::AllowConsuming, None)
        .await
        .expect("the usable part of the bundle is used");
    let Obtained::Bearer { credentials, .. } = obtained else {
        panic!("expected a bearer, got {obtained:?}");
    };

    let Some(SecretValue::OAuthToken { token, refresh, .. }) = credentials.fields.get("oauth")
    else {
        panic!("the effective bundle must carry the access token");
    };
    assert_eq!(token.0, b"usable-access-token");
    assert!(
        refresh.is_none(),
        "a refresh token cannot be redeemed without a token endpoint, so it must not travel",
    );
    assert!(
        !credentials.fields.contains_key("client_id")
            && !credentials.fields.contains_key("client_secret"),
        "a client-credentials pair needs the same missing token endpoint",
    );

    // And the live cell agrees, so `has_silent_grant` cannot become true.
    assert!(
        driver
            .activate(&credentials, driver.identity_gen())
            .await
            .expect("installing the stripped bundle succeeds"),
    );
    assert!(
        !driver.state().has_silent_grant(),
        "no silent grant exists on a connection with no token endpoint",
    );
}

/// The keyring property from the anonymous mode, re-asserted on the CREDENTIALED
/// path.
///
/// The sibling test above drives the credential verbs with an EMPTY bundle, and
/// would therefore not see a credentialed path that took a claim. This one runs
/// the same assertion after a real bearer has been obtained, activated and
/// persisted — which is where a claim would now be taken if any of the three
/// guards regressed.
///
/// Why it matters, restated because the damage is invisible from here: arriving
/// on a key another claim already holds records a contention that is never
/// cleared. The real connection on that key then reports non-exclusive for the
/// rest of its life, its next credential operation raises `AuthRequired`, and a
/// keyring-lineage bring-up purges its stored refresh token.
#[tokio::test]
async fn a_credentialed_direct_connection_still_takes_no_persistence_claim() {
    let (authority, _state) = spawn_grpc_server().await;
    let driver = direct_driver(&direct_location(&authority));

    let obtained = driver
        .obtain(
            &bearer_bundle("host-minted-token"),
            GrantPolicy::AllowConsuming,
            None,
        )
        .await
        .expect("a supplied access token needs no grant");
    let Obtained::Bearer { credentials, .. } = obtained else {
        panic!("the fixture must produce a bearer or every assertion below is vacuous");
    };

    driver
        .persist_credentials(&credentials)
        .await
        .expect("a direct endpoint persists nothing");
    assert!(
        driver.load_credentials().await.unwrap().is_none(),
        "and reads nothing back",
    );
    driver
        .delete_credentials()
        .await
        .expect("and deletes nothing");

    assert_eq!(driver.stable_id(), None, "still no durable key");
    assert!(
        !driver.has_persistence_claim(),
        "a direct-endpoint connection must never acquire a persistence claim, credentialed or \
         not",
    );
}

/// A bearer bound for a cleartext endpoint that is not loopback is refused
/// until the operator says otherwise in the config file — and the honest inputs
/// beside it are not.
///
/// The refusal is `Unsupported`, not `InvalidArgument`, for the blast-radius
/// reason every refusal on this path shares: the stack builder is fatal on an
/// argument error, so this would stop the whole host at bring-up instead of
/// parking one connection. The last row asserts the code for that reason.
///
/// The accepting rows are not decoration. A guard like this is written from its
/// hostile case and the cost lands entirely on the legitimate ones: loopback
/// discloses to nobody, `grpcs://` is encrypted however remote it is, an
/// anonymous connection has no credential to disclose, and an operator who has
/// stated the acceptance gets what they asked for. If any of those four
/// regressed into a refusal, the feature would be broken for the deployments it
/// exists to serve while every hostile-case test stayed green.
///
/// No server is spawned: `obtain` on a direct connection dials nothing, which
/// is what lets these rows name hosts that do not exist.
#[tokio::test]
async fn a_bearer_over_cleartext_beyond_loopback_needs_the_operator_to_say_so() {
    // Refused: cleartext, off-box, no opt-in.
    for address in [
        "grpc://storage:50051",
        "grpc://10.0.0.5:50051",
        "grpc://svc.internal:50051",
    ] {
        let location = config::service_location(&cfg(address)).expect("a valid address");
        let driver = direct_driver_with_plaintext_credentials(&location, false);
        let err = driver
            .obtain(
                &bearer_bundle("host-minted-token"),
                GrantPolicy::AllowConsuming,
                None,
            )
            .await
            .expect_err("a bearer must not cross a cleartext link off this machine unasked");
        assert_eq!(err.code(), ErrorCode::Unsupported, "code, for {address}");
        assert!(
            err.to_string()
                .contains(config::ALLOW_PLAINTEXT_CREDENTIALS_KEY),
            "the diagnostic must name the key that unblocks it, for {address}: {err}",
        );
        assert!(
            !err.to_string().contains("host-minted-token"),
            "and must never name the token itself, for {address}",
        );
        // `Error::new` runs every message through the shared redactor, which
        // rewrites the word following "bearer" — so a message merely USING the
        // phrase reaches the operator as "as a bearer REDACTED". Both refusals
        // on this path were written that way once. Asserted on the constructed
        // message rather than by re-running the redactor, which would only test
        // its idempotence. The sibling assertion is in the driver's unit test
        // for the header-legality refusal, so both refusal sites are driven.
        assert!(
            !err.to_string().contains("REDACTED"),
            "the diagnostic must not be mangled by the shared redactor, for {address}: {err}",
        );
    }

    // Accepted: each for a different reason, and each of them a shape a real
    // deployment uses.
    for (what, address, allow) in [
        (
            "loopback discloses to nobody",
            "grpc://127.0.0.1:50051",
            false,
        ),
        ("loopback by name", "grpc://localhost:50051", false),
        ("IPv6 loopback", "grpc://[::1]:50051", false),
        (
            "TLS, however remote",
            "grpcs://storage.example.com:50051",
            false,
        ),
        ("the operator stated it", "grpc://storage:50051", true),
    ] {
        let location = config::service_location(&cfg(address)).expect("a valid address");
        let driver = direct_driver_with_plaintext_credentials(&location, allow);
        let obtained = driver
            .obtain(
                &bearer_bundle("host-minted-token"),
                GrantPolicy::AllowConsuming,
                None,
            )
            .await
            .unwrap_or_else(|e| panic!("{what} ({address}) must still serve a bearer: {e}"));
        assert!(
            matches!(obtained, Obtained::Bearer { .. }),
            "{what} ({address}) must still serve a bearer, got {obtained:?}",
        );
    }

    // An anonymous connection over the same refused address is untouched: the
    // gate is about disclosing a credential, and there is none.
    let location = config::service_location(&cfg("grpc://storage:50051")).expect("a valid address");
    let driver = direct_driver_with_plaintext_credentials(&location, false);
    let obtained = driver
        .obtain(&SecretBundle::default(), GrantPolicy::AllowConsuming, None)
        .await
        .expect("an anonymous direct connection is unaffected by a credential gate");
    assert!(
        matches!(obtained, Obtained::Anonymous),
        "expected anonymous, got {obtained:?}",
    );
}

/// A plugin-driven refresh is still `Unsupported` on a connection that is
/// AUTHENTICATED and holding a live bearer — the refusal is a property of the
/// deployment having no token endpoint, not of the connection happening to hold
/// no credential.
///
/// The bearer is installed on the live cell first, with `activate`, because
/// otherwise the name is a claim the body does not make: passing a bundle to
/// `refresh` puts nothing on the connection, and `refresh` refuses on
/// `oidc_config().is_none()` without reading its argument at all. Without the
/// install this traverses byte for byte the same path as
/// `direct_mode_refuses_refresh`, and no source line reddens one without the
/// other.
///
/// Stated exactly, because it is weaker than it looks: this pins that the
/// refusal is INDEPENDENT of the live credential state, which is a real
/// property and the one the name asserts. It does not pin a distinct branch —
/// there is none, and that absence is the point.
#[tokio::test]
async fn direct_mode_refuses_refresh_even_holding_a_bearer() {
    let (authority, _state) = spawn_grpc_server().await;
    let driver = direct_driver(&direct_location(&authority));

    let obtained = driver
        .obtain(
            &bearer_bundle("host-minted-token"),
            GrantPolicy::AllowConsuming,
            None,
        )
        .await
        .expect("a supplied access token needs no grant");
    let Obtained::Bearer { credentials, .. } = obtained else {
        panic!("expected a bearer, got {obtained:?}");
    };
    assert!(
        driver
            .activate(&credentials, driver.identity_gen())
            .await
            .expect("installing a proven bearer succeeds"),
    );
    assert_eq!(
        driver.state().access_token().await.as_deref(),
        Some("host-minted-token"),
        "the precondition: this connection really is holding a bearer",
    );

    let err = driver
        .refresh(&credentials, None, driver.identity_gen())
        .await
        .expect_err("a direct endpoint has no OIDC token endpoint to refresh against");
    assert_eq!(err.code(), ErrorCode::Unsupported);
    assert_eq!(
        driver.state().access_token().await.as_deref(),
        Some("host-minted-token"),
        "and the refusal leaves the bearer in use alone",
    );
}

/// A rotation the deployment REFUSES: reported as a failure, and recoverable.
///
/// Two claims, both asserted below: the update reports failure rather than
/// silently accepting a bearer the server rejected, and the connection is not
/// stranded by it — the SAME call, with a token the deployment accepts,
/// recovers it. That recovery matters because there is no other route: this
/// connection has no grant to refresh with and no interactive flow, so the host
/// is the only party that can fix it, which is the arrangement this whole mode
/// rests on.
///
/// The good input is the load-bearing half. A guard that turned a refused
/// rotation into a dead connection would satisfy the first assertion and fail
/// the last.
///
/// Not asserted here, and stated rather than implied: the refused bearer is
/// never installed on the live cell, because `ConnectionSet::apply_grant` runs
/// `verify` before `activate` and stops on the failure. Observing that from a
/// test would need a data-path RPC, and this fixture serves only the
/// capabilities service.
#[tokio::test]
async fn a_refused_rotation_is_reported_and_is_recoverable() {
    use ovstorage_plugin::{
        BackendFactory, ConnectionKey, ConnectionRequest, Extensions, LayerConnectionRequest,
        Request as LayerRequest, UpdateConnectionCredentialsRequest,
    };

    let (authority, server_state) = spawn_grpc_server().await;
    server_state.lock().unwrap().rejected_bearer = Some("Bearer refused-token".into());

    let layer = ovstorage_plugin_services_client::layer::OmniverseStorageLayerFactory::default()
        .create_backend("direct-refuse", &HashMap::new(), None)
        .await
        .expect("an empty config builds an unseeded layer");
    let key_for = |id: ConnectionId| ConnectionKey {
        target: "direct-refuse".into(),
        id,
    };

    let connection = layer
        .add_connection(
            LayerRequest::new(LayerConnectionRequest {
                target: "direct-refuse".into(),
                connection: ConnectionRequest {
                    backend_kind: config::KIND.into(),
                    config: cfg(&format!("grpc://{authority}")),
                    credentials: bearer_bundle("accepted-token"),
                    persist: false,
                    display_name: None,
                },
            }),
            None,
        )
        .await
        .expect("a direct connection with an accepted bearer comes up");

    let refused = layer
        .update_connection_credentials(
            LayerRequest::new(UpdateConnectionCredentialsRequest {
                key: key_for(connection.id.clone()),
                credentials: bearer_bundle("refused-token"),
            }),
            None,
        )
        .await;
    assert!(
        refused.is_err(),
        "a bearer the deployment refuses must not be reported as accepted",
    );

    // The refusal is the SERVER's, not a local guard short-circuiting: the
    // candidate reached the deployment and was turned down there. Without this
    // the `is_err()` above would pass for a connection that never tried, which
    // is the shape a mistaken new guard would take.
    assert_eq!(
        server_state.lock().unwrap().refused_calls,
        1,
        "the candidate bearer must have been offered to the server and refused",
    );
    let connections = layer
        .list_connections(&Extensions::default(), None)
        .await
        .expect("the connection is still registered")
        .0;
    assert_eq!(
        connections.connections.len(),
        1,
        "a refused rotation must not remove the connection",
    );

    // Recovery: the host supplies a token the deployment accepts.
    let mark = server_state.lock().unwrap().seen_bearers.len();
    layer
        .update_connection_credentials(
            LayerRequest::new(UpdateConnectionCredentialsRequest {
                key: key_for(connection.id.clone()),
                credentials: bearer_bundle("second-accepted-token"),
            }),
            None,
        )
        .await
        .expect("a refused rotation does not strand the connection");
    // Counted for the same reason as the rotation test: one occurrence would be
    // the `verify` alone, which proves the candidate was offered and not that it
    // was installed.
    let after = {
        let st = server_state.lock().unwrap();
        st.seen_bearers[mark..].to_vec()
    };
    let carried = after
        .iter()
        .filter(|b| b.as_deref() == Some("Bearer second-accepted-token"))
        .count();
    assert!(
        carried >= 2,
        "the recovering token must be installed, not merely offered; saw {carried} of {after:?}",
    );
}

/// Removing the credential is one of the standard credential-update verbs, and
/// it has to actually remove it.
///
/// The trap this pins: `ConnectionSet` handles an `Anonymous` grant by
/// recording the state and nothing else — it never calls `activate`, because
/// there is no bearer to install. So a driver that merely *reported* anonymous
/// would leave the interceptor sending the previous token, and the connection
/// would advertise `Anonymous` while every request stayed credentialed. Nothing
/// in the return value shows that, which is why this asserts at the server.
///
/// Mutation control, run: deleting the `replace_tokens` call from the direct
/// arm of `obtain` reddens this test and
/// `a_probe_does_not_remove_a_bearer_and_a_registered_grant_does`, which
/// asserts that the same cell IS cleared by an `AllowConsuming` grant. Nothing
/// else in the crate moves.
#[tokio::test]
async fn a_host_can_remove_a_direct_connections_bearer() {
    use ovstorage_plugin::{
        BackendFactory, ConnectionKey, ConnectionRequest, Extensions, LayerConnectionRequest,
        Request as LayerRequest, UpdateConnectionCredentialsRequest,
    };

    let (authority, server_state) = spawn_grpc_server().await;
    let layer = ovstorage_plugin_services_client::layer::OmniverseStorageLayerFactory::default()
        .create_backend("direct-remove", &HashMap::new(), None)
        .await
        .expect("an empty config builds an unseeded layer");

    let connection = layer
        .add_connection(
            LayerRequest::new(LayerConnectionRequest {
                target: "direct-remove".into(),
                connection: ConnectionRequest {
                    backend_kind: config::KIND.into(),
                    config: cfg(&format!("grpc://{authority}")),
                    credentials: bearer_bundle("token-to-be-removed"),
                    persist: false,
                    display_name: None,
                },
            }),
            None,
        )
        .await
        .expect("a direct connection with a supplied bearer comes up");
    let mark = {
        let st = server_state.lock().unwrap();
        // Non-empty FIRST: `all()` over an empty vector is true, so without this
        // the guard whose whole job is "the fixture is credentialed" would pass
        // most loudly in the case it exists to rule out.
        assert!(
            !st.seen_bearers.is_empty(),
            "bring-up must have driven at least one request",
        );
        assert!(
            st.seen_bearers
                .iter()
                .all(|b| b.as_deref() == Some("Bearer token-to-be-removed")),
            "the fixture must be credentialed before removal means anything; saw {:?}",
            st.seen_bearers,
        );
        st.seen_bearers.len()
    };

    let cleared = layer
        .update_connection_credentials(
            LayerRequest::new(UpdateConnectionCredentialsRequest {
                key: ConnectionKey {
                    target: "direct-remove".into(),
                    id: connection.id.clone(),
                },
                credentials: SecretBundle::default(),
            }),
            None,
        )
        .await
        .expect("dropping the credential on a live connection succeeds");
    assert!(
        matches!(cleared.auth_state, ConnectionAuthState::Anonymous),
        "the connection reports anonymous, got {:?}",
        cleared.auth_state,
    );

    let seen = server_state.lock().unwrap().seen_bearers.clone();
    assert!(
        seen.len() > mark,
        "the removal must have driven at least one request to observe",
    );
    assert!(
        seen[mark..].iter().any(Option::is_none),
        "a request after the removal must carry NO authorization header; saw {:?}",
        &seen[mark..],
    );

    // And the roots survive the removal, since this deployment serves them
    // anonymously — a removal must not look like a teardown.
    //
    // Scope, because the obvious reading is wrong: `list_address_roots` answers
    // from the in-memory cache and drives no RPC, so this asserts that the
    // removal did not TEAR THE ROUTE DOWN, and not that routing still works over
    // the wire. The wire-level claim is the one above, on the requests the
    // removal itself drove.
    let (snapshot, _updates) = layer
        .list_address_roots(&Extensions::default(), None)
        .await
        .expect("roots are still published");
    assert_eq!(snapshot.roots.len(), 1);
}

/// An update carrying only a credential this deployment cannot redeem is a
/// FAILED update, not a removal — and the difference is a working bearer.
///
/// The trap: the direct arm answers `Anonymous` when it finds no usable bearer,
/// and `Anonymous` on a registered path clears the live cell. So if "nothing
/// usable was supplied" and "nothing was supplied" were the same case, a host
/// that sent a client-credentials pair to a direct endpoint by mistake would
/// have its working bearer removed and be told the update succeeded. It is
/// refused instead, before anything is cleared.
///
/// The refusal reports `Unsupported`, the same code `interactive` and `refresh`
/// answer here. That is deliberate rather than convenient: the lifecycle treats
/// an argument error as a caller contract failure, and the stack builder is
/// fatal on it, so one mistyped credential in one configured connection would
/// stop the whole host from starting.
///
/// This asserts the layer-level behaviour — the update fails, with a message
/// naming what to supply, and the credential is not echoed. That the previous
/// bearer survives is asserted where it is observable, on the driver's own
/// token cell, in `a_refusal_leaves_the_bearer_in_use_untouched`: a failed
/// update drives no request, so this fixture has nothing to see.
///
/// Mutation control, run: turning the refusal back into the `Anonymous` answer
/// reddens `direct_mode_answers_a_probe_and_a_bring_up_alike` and this test,
/// and nothing else.
#[tokio::test]
async fn an_update_with_only_unredeemable_credentials_is_refused_not_treated_as_removal() {
    use ovstorage_plugin::{
        BackendFactory, ConnectionKey, ConnectionRequest, LayerConnectionRequest,
        Request as LayerRequest, SecretBytes, SecretValue, UpdateConnectionCredentialsRequest,
    };

    let (authority, _server_state) = spawn_grpc_server().await;
    let layer = ovstorage_plugin_services_client::layer::OmniverseStorageLayerFactory::default()
        .create_backend("direct-unusable", &HashMap::new(), None)
        .await
        .expect("an empty config builds an unseeded layer");

    let connection = layer
        .add_connection(
            LayerRequest::new(LayerConnectionRequest {
                target: "direct-unusable".into(),
                connection: ConnectionRequest {
                    backend_kind: config::KIND.into(),
                    config: cfg(&format!("grpc://{authority}")),
                    credentials: bearer_bundle("a-working-token"),
                    persist: false,
                    display_name: None,
                },
            }),
            None,
        )
        .await
        .expect("a direct connection with a supplied bearer comes up");

    let mut m2m = SecretBundle::default();
    m2m.fields.insert(
        "client_id".into(),
        SecretValue::Bytes(SecretBytes(b"an-id".to_vec())),
    );
    m2m.fields.insert(
        "client_secret".into(),
        SecretValue::Bytes(SecretBytes(b"a-secret".to_vec())),
    );

    // The second row is the one an allowlist gets wrong. A host that names its
    // token something else, or misspells the field, sends a bundle carrying a
    // real secret under a key this plugin does not model — and a predicate
    // written as "does it contain a field I know I cannot use" answers no,
    // which lands it in the removal arm.
    let mut unmodelled = SecretBundle::default();
    unmodelled.fields.insert(
        "api_token".into(),
        SecretValue::Bytes(SecretBytes(b"a-real-secret".to_vec())),
    );

    for (what, credentials, must_not_echo) in [
        ("a client-credentials pair", m2m, "a-secret"),
        (
            "a populated field this plugin does not model",
            unmodelled,
            "a-real-secret",
        ),
    ] {
        let outcome = layer
            .update_connection_credentials(
                LayerRequest::new(UpdateConnectionCredentialsRequest {
                    key: ConnectionKey {
                        target: "direct-unusable".into(),
                        id: connection.id.clone(),
                    },
                    credentials,
                }),
                None,
            )
            .await;
        let err = match outcome {
            Err(err) => err,
            Ok(connection) => panic!(
                "{what} must not report success; got {:?}",
                connection.auth_state
            ),
        };
        assert_eq!(err.code(), ErrorCode::Unsupported, "for {what}");
        assert!(
            err.message().contains("oauth"),
            "the refusal must say what to supply instead, for {what}, got: {}",
            err.message(),
        );
        assert!(
            !err.message().contains(must_not_echo),
            "a refusal must not repeat the credential it refused, for {what}, got: {}",
            err.message(),
        );
    }
}

/// A PROBE never removes a live connection's bearer; a registered grant does.
///
/// The removal is the one thing on this path that writes the live token cell,
/// and `obtain` runs for probes as well as for registered operations. So the
/// gate that separates them is load-bearing, and it is the grant policy:
/// `NonConsumingOnly` is the probe and must mutate nothing, `AllowConsuming` is
/// bring-up, credential update and recovery.
///
/// Asserted on the cell itself rather than on a return value, because both
/// policies return `Anonymous` — the divergence is invisible from the outside,
/// which is exactly why it needs its own test.
///
/// (A probe additionally runs on a throwaway driver with its own token cell, so
/// a regression here would still not reach a live connection. That is a second
/// guard, not a reason to drop this one: the two are independent and either
/// could be removed by someone who believed the other was doing the work.)
///
/// Mutation control, run: dropping the `policy == AllowConsuming` condition
/// reddens this test and only this test.
#[tokio::test]
async fn a_probe_does_not_remove_a_bearer_and_a_registered_grant_does() {
    let (authority, _state) = spawn_grpc_server().await;
    let driver = direct_driver(&direct_location(&authority));

    // Install a bearer the way the lifecycle does.
    let obtained = driver
        .obtain(
            &bearer_bundle("a-live-token"),
            GrantPolicy::AllowConsuming,
            None,
        )
        .await
        .expect("a supplied access token needs no grant");
    let Obtained::Bearer { credentials, .. } = obtained else {
        panic!("the fixture must install a bearer or every assertion below is vacuous");
    };
    driver
        .activate(&credentials, driver.identity_gen())
        .await
        .expect("installing a proven bearer succeeds");
    assert_eq!(
        driver.state().access_token().await.as_deref(),
        Some("a-live-token"),
        "the cell must hold the bearer before removal means anything",
    );

    // A probe of the same connection with no credentials leaves it alone.
    let probed = driver
        .obtain(
            &SecretBundle::default(),
            GrantPolicy::NonConsumingOnly,
            None,
        )
        .await
        .expect("a probe with no credentials resolves");
    assert!(matches!(probed, Obtained::Anonymous), "got {probed:?}");
    assert_eq!(
        driver.state().access_token().await.as_deref(),
        Some("a-live-token"),
        "a probe must not remove a live connection's bearer",
    );

    // A registered grant with no credentials removes it.
    let registered = driver
        .obtain(&SecretBundle::default(), GrantPolicy::AllowConsuming, None)
        .await
        .expect("a registered grant with no credentials resolves");
    assert!(
        matches!(registered, Obtained::Anonymous),
        "got {registered:?}"
    );
    assert!(
        driver
            .state()
            .access_token()
            .await
            .is_none_or(|token| token.is_empty()),
        "a registered grant handed no credential must remove the one in use, not \
         replace it with another",
    );
}

/// A refused credential update leaves the bearer already in use exactly where
/// it was.
///
/// This is the half of the refusal that matters and the layer cannot show:
/// refusing is only worth anything if it happens *above* the live-cell clear.
/// A version that cleared first and returned the error afterwards would satisfy
/// every assertion in the layer-level test and still have destroyed the
/// connection's credential.
///
/// Mutation control, run: moving the refusal below the clear reddens this test
/// and only this test.
#[tokio::test]
async fn a_refusal_leaves_the_bearer_in_use_untouched() {
    use ovstorage_plugin::{SecretBytes, SecretValue};

    let (authority, _state) = spawn_grpc_server().await;
    let driver = direct_driver(&direct_location(&authority));

    let obtained = driver
        .obtain(
            &bearer_bundle("a-live-token"),
            GrantPolicy::AllowConsuming,
            None,
        )
        .await
        .expect("a supplied access token needs no grant");
    let Obtained::Bearer { credentials, .. } = obtained else {
        panic!("the fixture must install a bearer or every assertion below is vacuous");
    };
    driver
        .activate(&credentials, driver.identity_gen())
        .await
        .expect("installing a proven bearer succeeds");
    assert_eq!(
        driver.state().access_token().await.as_deref(),
        Some("a-live-token"),
    );

    let mut unusable = SecretBundle::default();
    unusable.fields.insert(
        "client_id".into(),
        SecretValue::Bytes(SecretBytes(b"an-id".to_vec())),
    );

    let err = driver
        .obtain(&unusable, GrantPolicy::AllowConsuming, None)
        .await
        .expect_err("a credential this deployment cannot redeem is refused");
    assert_eq!(err.code(), ErrorCode::Unsupported);
    assert_eq!(
        driver.state().access_token().await.as_deref(),
        Some("a-live-token"),
        "a refused update must not disturb the bearer already in use",
    );
}

/// Capture the tracing events emitted while `body` runs, as
/// `"<message> | <field>=<value> …"` strings.
///
/// Events, not accessor return values. A test that calls the accessor asserts
/// that a redaction *exists*; only the emitted event shows that the log line
/// USES it, and the log line is the thing an operator reads.
fn captured_events(body: impl FnOnce()) -> Vec<String> {
    use tracing_subscriber::layer::{Context, Layer, SubscriberExt as _};

    #[derive(Clone)]
    struct Capture(Arc<Mutex<Vec<String>>>);

    struct Visitor(String);

    impl tracing::field::Visit for Visitor {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            self.0.push_str(&format!(" | {}={:?}", field.name(), value));
        }
    }

    impl<S: tracing::Subscriber> Layer<S> for Capture {
        fn on_event(&self, event: &tracing::Event<'_>, _cx: Context<'_, S>) {
            let mut visitor = Visitor(String::new());
            event.record(&mut visitor);
            self.0.lock().unwrap().push(visitor.0);
        }
    }

    let captured = Arc::new(Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::registry().with(Capture(Arc::clone(&captured)));
    tracing::subscriber::with_default(subscriber, body);
    let captured = captured.lock().unwrap();
    captured.clone()
}

/// A locator carrying userinfo is redacted in the line the transport actually
/// EMITS, not merely in an accessor a diagnostic could choose to call.
///
/// The distinction is the whole test. The constructor logs
/// `service_url = %redacted(location.locator())` at INFO for every connection;
/// reverting that one call site to `location.locator()` would leak a password at
/// INFO on every connection while an accessor-only assertion stayed green.
///
/// Scoped deliberately: this covers the LOGGING seam, which is what the call
/// sites in this crate use. The connection's display name and `BackendId` are
/// built from `ServiceLocation::locator` in the layer and still carry a
/// discovery URL verbatim — pre-existing, untouched here, and not what this
/// asserts.
///
/// Controlled against a known positive at both ends: the fixture is checked to
/// contain the password, and the capture is checked to have seen an event
/// naming the host — so neither a redaction that silently did nothing nor a
/// subscriber that captured nothing can report success. A discovery URL
/// carrying userinfo is deliberately still accepted at config time; refusing it
/// would be a regression, so the seam that has to hold is the logging one.
#[test]
fn a_locator_is_redacted_before_it_reaches_a_diagnostic() {
    use ovstorage_plugin_services_client::config::ServiceLocation;

    let raw = "https://alice:hunter2@storage.example.com/root";
    assert!(
        raw.contains("hunter2") && raw.contains("alice"),
        "the fixture must carry userinfo or every assertion below is vacuous",
    );

    let events = captured_events(|| {
        let transport = OmniverseStorageTransport::new(
            ServiceLocation::Discovery(raw.into()),
            DiscoveryState::new("default"),
        );
        // The accessor is the other call site of the same rule, and it is
        // exercised here so both are covered by one fixture.
        tracing::info!(accessor = %transport.redacted_locator(), "accessor");
    });

    let named_host = events
        .iter()
        .filter(|line| line.contains("storage.example.com"))
        .count();
    assert!(
        named_host >= 2,
        "the constructor's INFO line and the accessor line must both have been captured, or the \
         assertions below range over nothing; got {events:?}",
    );
    for line in events {
        assert!(
            !line.contains("hunter2") && !line.contains("alice"),
            "userinfo must not survive into an emitted diagnostic, got: {line}",
        );
    }
}

/// The credential spelling that comes out of a configuration file reaches the
/// wire.
///
/// `[connections.credentials] oauth = "<token>"` and the CLI's `--auth` both
/// build a `SecretValue::Bytes`; the structured `OAuthToken` needs a
/// programmatic caller. A driver that read only the structured form would leave
/// the documented configuration spelling doing nothing — and, once a
/// mistyped-credential refusal exists, would turn that silent no-op into a hard
/// failure.
///
/// Driven through the real layer, with the credential built the way
/// `ConnectionConfig::to_connection_request` builds it.
///
/// Mutation control, run: narrowing `direct_bearer` back to the `OAuthToken`
/// variant reddens four tests — this one, the predicate table
/// (`the_direct_credential_predicates_read_each_bundle_shape`, on its
/// raw-token row), `a_token_that_cannot_ride_in_a_header_is_refused_where_it_is_accepted`,
/// and `a_blank_oauth_value_does_not_remove_the_bearer_in_use`, whose bring-up
/// uses this same configured spelling and would then be refused.
#[tokio::test]
async fn a_configured_token_string_reaches_the_wire() {
    use ovstorage_plugin::{
        BackendFactory, ConnectionRequest, LayerConnectionRequest, Request as LayerRequest,
    };

    let (authority, server_state) = spawn_grpc_server().await;
    let layer = ovstorage_plugin_services_client::layer::OmniverseStorageLayerFactory::default()
        .create_backend("direct-configured", &HashMap::new(), None)
        .await
        .expect("an empty config builds an unseeded layer");

    let connection = layer
        .add_connection(
            LayerRequest::new(LayerConnectionRequest {
                target: "direct-configured".into(),
                connection: ConnectionRequest {
                    backend_kind: config::KIND.into(),
                    config: cfg(&format!("grpc://{authority}")),
                    credentials: configured_bearer_bundle("token-from-a-config-file"),
                    persist: false,
                    display_name: None,
                },
            }),
            None,
        )
        .await
        .expect("a token written in configuration brings the connection up");
    assert!(
        matches!(
            connection.auth_state,
            ConnectionAuthState::Authenticated { .. }
        ),
        "a configured token authenticates the connection, got {:?}",
        connection.auth_state,
    );

    let seen = server_state.lock().unwrap().seen_bearers.clone();
    assert!(!seen.is_empty(), "bring-up must have driven a request");
    assert!(
        seen.iter()
            .all(|b| b.as_deref() == Some("Bearer token-from-a-config-file")),
        "every request must carry the configured token; saw {seen:?}",
    );
}

/// The config key is read from the connection's config map by the LAYER, and
/// both settings of it change what the layer does.
///
/// This is the seam the other three tests do not cross. They cover the reader
/// (`the_cleartext_credential_permission_is_granted_only_by_a_literal_true`),
/// the classifier
/// (`only_a_non_loopback_cleartext_endpoint_needs_the_credential_opt_in`) and
/// the refusal
/// (`a_bearer_over_cleartext_beyond_loopback_needs_the_operator_to_say_so`) —
/// but the last supplies the boolean by hand, so `layer.rs`'s single call to
/// `config::allow_plaintext_credentials` was pinned by nothing. Replacing that
/// argument with a literal `true` (the feature off, every bearer on every
/// cleartext wire) or a literal `false` (the key inert, no operator able to
/// unblock the refusal) left the whole suite green. A green predicate says
/// nothing about its call site.
///
/// The address here names a host that does not exist, which is deliberate: the
/// refusal and the permission are both decided before anything is dialed, so
/// the two arms differ only in the key. The permitted arm therefore gets as far
/// as trying to reach the server and fails there — what it must NOT do is fail
/// with the refusal, and the assertion is on which error it is.
#[tokio::test]
async fn the_layer_reads_the_cleartext_credential_key_from_the_connection_config() {
    use ovstorage_plugin::{
        BackendFactory, ConnectionRequest, LayerConnectionRequest, Request as LayerRequest,
    };

    /// The message the connection parked with. `add_connection` returns `Ok`
    /// with an `AwaitingAuth` state rather than an `Err` — the whole point of
    /// reporting `Unsupported` — so the diagnostic is on the attempt, not on a
    /// return value.
    async fn park_reason(allow: Option<bool>) -> String {
        let layer =
            ovstorage_plugin_services_client::layer::OmniverseStorageLayerFactory::default()
                .create_backend("direct-optin", &HashMap::new(), None)
                .await
                .expect("an empty config builds an unseeded layer");
        // Port 1 on a name that does not resolve: nothing here reaches a
        // network, and the decision under test is made before anything tries.
        let mut config = cfg("grpc://storage-that-does-not-exist:1");
        if let Some(allow) = allow {
            config.insert(
                config::ALLOW_PLAINTEXT_CREDENTIALS_KEY.into(),
                ConfigValue::Bool(allow),
            );
        }
        let connection = layer
            .add_connection(
                LayerRequest::new(LayerConnectionRequest {
                    target: "direct-optin".into(),
                    connection: ConnectionRequest {
                        backend_kind: config::KIND.into(),
                        config,
                        credentials: configured_bearer_bundle("a-token"),
                        persist: false,
                        display_name: None,
                    },
                }),
                None,
            )
            .await
            .expect("an unusable credential parks the connection, it does not fail the add");
        let ConnectionAuthState::AwaitingAuth { last_attempt, .. } = connection.auth_state else {
            panic!(
                "this address reaches no server either way, so it must park; got {:?}",
                connection.auth_state
            );
        };
        last_attempt
            .and_then(|attempt| attempt.error)
            .map(|error| error.to_string())
            .expect("a parked connection records why")
    }

    for (what, allow) in [("absent", None), ("false", Some(false))] {
        let reason = park_reason(allow).await;
        assert!(
            reason.contains(config::ALLOW_PLAINTEXT_CREDENTIALS_KEY),
            "without the key the credential must be refused by name, for {what}: {reason}",
        );
    }

    // Set, and the layer must carry it through: the credential is accepted, and
    // the connection then parks for the unrelated reason that nothing is
    // listening. Were `layer.rs` ignoring the key, this would be the refusal
    // above instead.
    let reason = park_reason(Some(true)).await;
    assert!(
        !reason.contains(config::ALLOW_PLAINTEXT_CREDENTIALS_KEY),
        "with the key set the credential must not be refused; got {reason}",
    );
}

/// A blank `oauth` value does not remove a live connection's bearer.
///
/// This is the shape an environment reference produces when the variable is
/// set and empty — an unpopulated CI secret, a token-minting sidecar that wrote
/// nothing — and it is the realistic way a configured deployment arrives at
/// "the key is there, the value is not". Reading it as a removal would delete a
/// working credential and report success, which is the outcome the whole
/// three-way answer exists to prevent.
///
/// So naming a credential this plugin models is an offer whatever it carries —
/// `oauth` here, and `client_id` / `client_secret` for the same reason, since
/// the accident belongs to the environment reference rather than to the key.
/// Removing means naming no credential at all, which is what the refusal's
/// message says to send.
///
/// Mutation control, run: deciding the removal case on content alone —
/// dropping the credential-schema presence rule from `offers_no_credential` —
/// reddens this test, the removal table
/// (`only_a_bundle_offering_nothing_counts_as_a_removal`) and
/// `presence_covers_every_credential_schema_field`. Nothing else in the crate
/// moves.
#[tokio::test]
async fn a_blank_oauth_value_does_not_remove_the_bearer_in_use() {
    use ovstorage_plugin::{
        BackendFactory, ConnectionKey, ConnectionRequest, LayerConnectionRequest,
        Request as LayerRequest, UpdateConnectionCredentialsRequest,
    };

    let (authority, server_state) = spawn_grpc_server().await;
    let layer = ovstorage_plugin_services_client::layer::OmniverseStorageLayerFactory::default()
        .create_backend("direct-blank", &HashMap::new(), None)
        .await
        .expect("an empty config builds an unseeded layer");

    let connection = layer
        .add_connection(
            LayerRequest::new(LayerConnectionRequest {
                target: "direct-blank".into(),
                connection: ConnectionRequest {
                    backend_kind: config::KIND.into(),
                    config: cfg(&format!("grpc://{authority}")),
                    credentials: configured_bearer_bundle("a-working-token"),
                    persist: false,
                    display_name: None,
                },
            }),
            None,
        )
        .await
        .expect("a configured token brings the connection up");
    // The precondition: this connection is credentialed and working, or
    // "the bearer survived" below says nothing.
    assert!(
        server_state
            .lock()
            .unwrap()
            .seen_bearers
            .iter()
            .any(|b| b.as_deref() == Some("Bearer a-working-token")),
        "bring-up must have driven a request carrying the working token",
    );

    let outcome = layer
        .update_connection_credentials(
            LayerRequest::new(UpdateConnectionCredentialsRequest {
                key: ConnectionKey {
                    target: "direct-blank".into(),
                    id: connection.id.clone(),
                },
                credentials: configured_bearer_bundle(""),
            }),
            None,
        )
        .await;
    let err = match outcome {
        Err(err) => err,
        Ok(view) => panic!(
            "a blank oauth value must not report a successful update; got {:?}",
            view.auth_state
        ),
    };
    assert_eq!(err.code(), ErrorCode::Unsupported);

    // The refusal is not a removal, and the difference is visible in the
    // connection's own state: a removal drops it to `Anonymous` — asserted in
    // `a_host_can_remove_a_direct_connections_bearer` — so a refusal that had
    // cleared the live cell along the way would land there too.
    //
    // Asserted on state rather than on traffic, deliberately. The refusal
    // returns before any grant, so it drives no RPC of its own, and
    // `list_address_roots` answers from a cache; an assertion over the requests
    // seen after this point would range over an empty slice and hold whatever
    // the code did. The bearer cell itself is asserted directly, one level down,
    // by `a_refusal_leaves_the_bearer_in_use_untouched`.
    let connections = layer
        .list_connections(&ovstorage_plugin::Extensions::default(), None)
        .await
        .expect("the connection is still registered")
        .0;
    let after = connections
        .connections
        .iter()
        .find(|c| c.id == connection.id)
        .expect("the refused connection is still registered");
    assert!(
        !matches!(after.auth_state, ConnectionAuthState::Anonymous),
        "a refusal must not drop the connection to anonymous the way a removal does, got {:?}",
        after.auth_state,
    );

    let (snapshot, _updates) = layer
        .list_address_roots(&ovstorage_plugin::Extensions::default(), None)
        .await
        .expect("routes survive a refused update");
    assert_eq!(snapshot.roots.len(), 1, "the connection still routes");
}
