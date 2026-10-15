// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use ovstorage_broker_protocol::{BrokerClientTransport, BrokerClientWatchDirectoryStream};
use ovstorage_plugin::*;
use ovstorage_plugin_broker::{
    DiscoveryState, new_layer_for_tests, new_layer_for_tests_with_token_file,
};

static NEXT_TOKEN_FILE: AtomicUsize = AtomicUsize::new(0);

struct TempTokenFile(PathBuf);

impl TempTokenFile {
    fn new(token: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "ovstorage-broker-watch-token-{}-{}",
            std::process::id(),
            NEXT_TOKEN_FILE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, token).expect("test token file is writable");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn replace(&self, token: &str) {
        std::fs::write(&self.0, token).expect("test token rotates");
    }
}

impl Drop for TempTokenFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct WatchCall {
    prefix: Url,
    options: WatchDirectoryOptions,
}

struct ControlledWatchStream {
    receiver: mpsc::Receiver<Result<ChangeEvent>>,
    cancel: CancellationToken,
    dropped: Arc<AtomicUsize>,
}

impl Iterator for ControlledWatchStream {
    type Item = Result<ChangeEvent>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.cancel.is_cancelled() {
                return None;
            }
            match self.receiver.recv_timeout(Duration::from_millis(5)) {
                Ok(event) => return Some(event),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => return None,
            }
        }
    }
}

impl Drop for ControlledWatchStream {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::SeqCst);
    }
}

struct CountingTransport {
    roots: Vec<AddressRoot>,
    calls: Mutex<Vec<WatchCall>>,
    senders: Mutex<Vec<mpsc::Sender<Result<ChangeEvent>>>>,
    cancels: Mutex<Vec<CancellationToken>>,
    dropped: Arc<AtomicUsize>,
    /// When present, generations through `authorized_generation` model
    /// principal A; every later generation models principal B, which this fake
    /// broker denies.
    auth_state: Option<DiscoveryState>,
    authorized_generation: AtomicU64,
}

impl CountingTransport {
    fn new(root: &str, resumable: bool) -> Self {
        Self::build(root, resumable, None)
    }

    fn deny_rotated_identity(root: &str, resumable: bool, auth_state: DiscoveryState) -> Self {
        Self::build(root, resumable, Some(auth_state))
    }

    fn build(root: &str, resumable: bool, auth_state: Option<DiscoveryState>) -> Self {
        let mut capabilities = Capabilities::empty();
        capabilities.supports_watch_directory = true;
        capabilities.watch_directory_resumable = resumable;
        Self {
            roots: vec![AddressRoot {
                address: Url::parse(root).expect("test root parses"),
                display_name: None,
                backend_kind: "test".into(),
                connection_id: None,
                capabilities,
                source: RouteSource::Static {
                    layer: ConfigLayer::Programmatic,
                },
                visibility: AddressVisibility::Visible,
                user_metadata: UserMetadata::new(),
            }],
            calls: Mutex::new(Vec::new()),
            senders: Mutex::new(Vec::new()),
            cancels: Mutex::new(Vec::new()),
            dropped: Arc::new(AtomicUsize::new(0)),
            auth_state,
            authorized_generation: AtomicU64::new(0),
        }
    }

    fn calls(&self) -> Vec<WatchCall> {
        self.calls.lock().unwrap().clone()
    }

    fn publish(&self, event: ChangeEvent) {
        self.senders
            .lock()
            .unwrap()
            .retain(|sender| sender.send(Ok(event.clone())).is_ok());
    }

    fn latest_watch_is_cancelled(&self) -> bool {
        self.cancels
            .lock()
            .unwrap()
            .last()
            .is_some_and(CancellationToken::is_cancelled)
    }

    fn authorize_current_identity(&self) {
        let generation = self
            .auth_state
            .as_ref()
            .expect("authorization-aware transport has identity state")
            .identity_generation();
        self.authorized_generation
            .store(generation, Ordering::SeqCst);
    }
}

#[async_trait]
impl BrokerClientTransport for CountingTransport {
    async fn list_address_roots(&self) -> Result<Vec<AddressRoot>> {
        Ok(self.roots.clone())
    }

    async fn stat(&self, _address: Url, _options: StatOptions) -> Result<ObjectInfo> {
        unreachable!("watch tests do not stat")
    }

    async fn read(&self, _address: Url, _options: ReadOptions) -> Result<ReadResult> {
        unreachable!("watch tests do not read")
    }

    async fn write(&self, _address: Url, _body: Body, _options: WriteOptions) -> Result<WriteStep> {
        unreachable!("watch tests do not write")
    }

    async fn write_redirect(
        &self,
        _address: Url,
        _options: WriteOptions,
    ) -> Result<WriteRedirectBatch> {
        unreachable!("watch tests do not redirect writes")
    }

    async fn continue_write(
        &self,
        _address: Url,
        _redirects: WriteRedirectBatch,
        _results: RedirectResultBatch,
    ) -> Result<WriteStep> {
        unreachable!("watch tests do not continue writes")
    }

    async fn delete(&self, _address: Url, _options: DeleteOptions) -> Result<()> {
        unreachable!("watch tests do not delete")
    }

    async fn list(&self, _prefix: Url, _options: ListOptions) -> Result<ListPage> {
        unreachable!("watch tests do not list")
    }

    async fn list_versions(
        &self,
        _address: Url,
        _options: ListVersionsOptions,
    ) -> Result<Vec<ObjectInfo>> {
        unreachable!("watch tests do not list versions")
    }

    async fn get_latest_version(&self, _address: Url) -> Result<ObjectInfo> {
        unreachable!("watch tests do not get versions")
    }

    async fn watch_directory(
        &self,
        prefix: Url,
        options: WatchDirectoryOptions,
    ) -> Result<BrokerClientWatchDirectoryStream> {
        self.watch_directory_with_cancel(prefix, options, None)
            .await
    }

    async fn watch_directory_with_cancel(
        &self,
        prefix: Url,
        options: WatchDirectoryOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<BrokerClientWatchDirectoryStream> {
        let (sender, receiver) = mpsc::channel();
        let cancel = cancel.unwrap_or_default();
        self.calls
            .lock()
            .unwrap()
            .push(WatchCall { prefix, options });
        if self.auth_state.as_ref().is_some_and(|state| {
            state.identity_generation() > self.authorized_generation.load(Ordering::SeqCst)
        }) {
            return Err(Error::new(
                ErrorCode::PermissionDenied,
                "principal B is not authorized for this watch",
            ));
        }
        self.senders.lock().unwrap().push(sender);
        self.cancels.lock().unwrap().push(cancel.clone());
        Ok(Box::new(ControlledWatchStream {
            receiver,
            cancel,
            dropped: self.dropped.clone(),
        }))
    }

    async fn create_directory(
        &self,
        _address: Url,
        _options: CreateDirectoryOptions,
    ) -> Result<ObjectInfo> {
        unreachable!("watch tests do not create directories")
    }

    async fn delete_directory(
        &self,
        _address: Url,
        _options: DeleteDirectoryOptions,
    ) -> Result<()> {
        unreachable!("watch tests do not delete directories")
    }

    async fn copy(
        &self,
        _source: Url,
        _destination: Url,
        _options: CopyOptions,
    ) -> Result<WriteResult> {
        unreachable!("watch tests do not copy")
    }

    async fn rename(&self, _source: Url, _destination: Url, _options: RenameOptions) -> Result<()> {
        unreachable!("watch tests do not rename")
    }

    async fn update_metadata(
        &self,
        _address: Url,
        _options: UpdateMetadataOptions,
    ) -> Result<ObjectInfo> {
        unreachable!("watch tests do not update metadata")
    }

    async fn check_access(&self, _address: Url, _operations: AccessOps) -> Result<AccessDecision> {
        unreachable!("watch tests do not check access")
    }
}

async fn layer_with(root: &str, resumable: bool) -> (LayerHandle, Arc<CountingTransport>) {
    let transport = Arc::new(CountingTransport::new(root, resumable));
    let layer = new_layer_for_tests(transport.clone())
        .await
        .expect("test layer builds from fake roots");
    (layer, transport)
}

fn watch_request(prefix: &Url, options: WatchDirectoryOptions) -> Request<WatchDirectoryRequest> {
    Request::new(WatchDirectoryRequest {
        prefix: prefix.clone(),
        options,
    })
}

fn object_event(address: Url, kind: ChangeKind, cursor: u8) -> ChangeEvent {
    ChangeEvent::Object {
        address,
        kind,
        etag: Some(format!("etag-{cursor}")),
        version: Some(format!("version-{cursor}")),
        size: Some(u64::from(cursor)),
        mtime: Some(SystemTime::UNIX_EPOCH),
        at: SystemTime::UNIX_EPOCH,
        cursor: WatchDirectoryCursor(vec![cursor]),
    }
}

fn next_event(stream: &mut ChangeStream) -> ChangeEvent {
    stream
        .next()
        .expect("watch remains open")
        .expect("watch event succeeds")
}

async fn wait_for_dropped(transport: &CountingTransport, expected: usize) {
    tokio::time::timeout(Duration::from_secs(1), async {
        while transport.dropped.load(Ordering::SeqCst) < expected {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("upstream stream dropped without hanging");
}

async fn connection_key(layer: &LayerHandle, address: &Url) -> ConnectionKey {
    let root = layer
        .root_info_for(address, &Extensions::new(), None)
        .await
        .expect("test connection owns the routed prefix");
    ConnectionKey {
        target: "broker".into(),
        id: root
            .connection_id
            .expect("test root names its owning connection"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn same_prefix_non_resumable_watches_share_and_fan_out() {
    let prefix = Url::parse("s3://bucket/team/").unwrap();
    let (layer, transport) = layer_with("s3://bucket/", false).await;

    let (first, second) = tokio::join!(
        layer.watch_directory(
            watch_request(&prefix, WatchDirectoryOptions::default()),
            None
        ),
        layer.watch_directory(
            watch_request(&prefix, WatchDirectoryOptions::default()),
            None
        )
    );
    let mut first = first.expect("first watch opens");
    let mut second = second.expect("second watch opens");
    assert_eq!(transport.calls().len(), 1, "one shared upstream watch");

    let event = object_event(prefix.join("asset.usd").unwrap(), ChangeKind::Created, 1);
    transport.publish(event.clone());
    assert_eq!(next_event(&mut first), event);
    assert_eq!(next_event(&mut second), event);
}

#[tokio::test(flavor = "multi_thread")]
async fn distinct_prefixes_open_distinct_upstream_watches() {
    let first_prefix = Url::parse("s3://bucket/team-a/").unwrap();
    let second_prefix = Url::parse("s3://bucket/team-b/").unwrap();
    let (layer, transport) = layer_with("s3://bucket/", false).await;

    let (first, second) = tokio::join!(
        layer.watch_directory(
            watch_request(&first_prefix, WatchDirectoryOptions::default()),
            None
        ),
        layer.watch_directory(
            watch_request(&second_prefix, WatchDirectoryOptions::default()),
            None
        )
    );
    let first = first.expect("first prefix watch opens");
    let second = second.expect("second prefix watch opens");
    let calls = transport.calls();
    assert_eq!(calls.len(), 2);
    assert!(calls.iter().any(|call| call.prefix == first_prefix));
    assert!(calls.iter().any(|call| call.prefix == second_prefix));
    drop((first, second));
}

#[tokio::test(flavor = "multi_thread")]
async fn resumable_watches_bypass_coalescing_and_forward_since() {
    let prefix = Url::parse("s3://bucket/team/").unwrap();
    let (layer, transport) = layer_with("s3://bucket/", true).await;
    let first_options = WatchDirectoryOptions {
        recursive: false,
        include_metadata_changes: false,
        since: Some(WatchDirectoryCursor(vec![1, 2, 3])),
        poll_interval: Duration::from_millis(250),
    };
    let second_options = WatchDirectoryOptions {
        recursive: true,
        include_metadata_changes: true,
        since: Some(WatchDirectoryCursor(vec![4, 5, 6])),
        poll_interval: Duration::from_secs(2),
    };

    let (first, second) = tokio::join!(
        layer.watch_directory(watch_request(&prefix, first_options.clone()), None),
        layer.watch_directory(watch_request(&prefix, second_options.clone()), None)
    );
    let first = first.expect("first resumable watch opens");
    let second = second.expect("second resumable watch opens");
    let calls = transport.calls();
    assert_eq!(calls.len(), 2, "resumable watches stay 1:1");
    assert!(calls.contains(&WatchCall {
        prefix: prefix.clone(),
        options: first_options,
    }));
    assert!(calls.contains(&WatchCall {
        prefix,
        options: second_options,
    }));
    drop((first, second));
}

#[tokio::test(flavor = "multi_thread")]
async fn non_resumable_since_emits_lapsed_before_live_events() {
    let prefix = Url::parse("s3://bucket/team/").unwrap();
    let (layer, transport) = layer_with("s3://bucket/", false).await;
    let options = WatchDirectoryOptions {
        since: Some(WatchDirectoryCursor(vec![9, 8, 7])),
        ..Default::default()
    };
    let mut stream = layer
        .watch_directory(watch_request(&prefix, options), None)
        .await
        .expect("watch opens");
    let live = object_event(prefix.join("live.usd").unwrap(), ChangeKind::Modified, 2);
    transport.publish(live.clone());

    assert_eq!(
        next_event(&mut stream),
        ChangeEvent::Lapsed {
            since: None,
            cursor: WatchDirectoryCursor::default(),
        }
    );
    assert_eq!(next_event(&mut stream), live);
}

#[tokio::test(flavor = "multi_thread")]
async fn coalesced_upstream_uses_superset_and_subscriber_filters_it() {
    let prefix = Url::parse("s3://bucket/team/").unwrap();
    let (layer, transport) = layer_with("s3://bucket/", false).await;
    let options = WatchDirectoryOptions {
        recursive: false,
        include_metadata_changes: false,
        since: None,
        poll_interval: Duration::from_millis(700),
    };
    let mut stream = layer
        .watch_directory(watch_request(&prefix, options.clone()), None)
        .await
        .expect("watch opens");

    assert_eq!(
        transport.calls(),
        vec![WatchCall {
            prefix: prefix.clone(),
            options: WatchDirectoryOptions {
                recursive: true,
                include_metadata_changes: true,
                since: None,
                poll_interval: options.poll_interval,
            },
        }]
    );

    transport.publish(object_event(
        prefix.join("nested/deep.usd").unwrap(),
        ChangeKind::Created,
        3,
    ));
    transport.publish(object_event(
        prefix.join("metadata.usd").unwrap(),
        ChangeKind::MetadataChanged,
        4,
    ));
    let direct = object_event(prefix.join("direct.usd").unwrap(), ChangeKind::Created, 5);
    transport.publish(direct.clone());
    assert_eq!(
        next_event(&mut stream),
        direct,
        "nested and metadata-only events are filtered for this subscriber"
    );
}

#[tokio::test]
async fn coalesced_cadence_floors_zero_before_cohort_minimum() {
    let prefix = Url::parse("s3://bucket/team/").unwrap();
    let (layer, transport) = layer_with("s3://bucket/", false).await;
    let zero_options = WatchDirectoryOptions {
        poll_interval: Duration::ZERO,
        ..WatchDirectoryOptions::default()
    };
    let slow_options = WatchDirectoryOptions {
        poll_interval: Duration::from_secs(60),
        ..WatchDirectoryOptions::default()
    };

    let (first, second) = tokio::join!(
        layer.watch_directory(watch_request(&prefix, zero_options), None),
        layer.watch_directory(watch_request(&prefix, slow_options), None),
    );
    let first = first.expect("zero-cadence subscriber opens");
    let second = second.expect("slow subscriber opens");

    assert_eq!(
        transport.calls(),
        vec![WatchCall {
            prefix,
            options: WatchDirectoryOptions {
                recursive: true,
                include_metadata_changes: true,
                since: None,
                poll_interval: Duration::from_millis(1),
            },
        }],
        "zero resolves to the wire floor before the opening cohort chooses its minimum"
    );
    drop((first, second));
}

#[tokio::test(flavor = "multi_thread")]
async fn subscriber_and_remove_connection_teardown_drop_upstreams_without_hanging() {
    let prefix = Url::parse("s3://bucket/team/").unwrap();
    let (layer, transport) = layer_with("s3://bucket/", false).await;
    let (first, second) = tokio::join!(
        layer.watch_directory(
            watch_request(&prefix, WatchDirectoryOptions::default()),
            None
        ),
        layer.watch_directory(
            watch_request(&prefix, WatchDirectoryOptions::default()),
            None
        )
    );
    let first = first.expect("first watch opens");
    let second = second.expect("second watch opens");
    assert_eq!(transport.calls().len(), 1);
    drop((first, second));
    wait_for_dropped(&transport, 1).await;

    let connection_prefix = prefix.join("connection/").unwrap();
    let key = connection_key(&layer, &connection_prefix).await;
    let subscriber = layer
        .watch_directory(
            watch_request(&connection_prefix, WatchDirectoryOptions::default()),
            None,
        )
        .await
        .expect("connection-lifetime watch opens");
    assert_eq!(transport.calls().len(), 2);
    layer
        .remove_connection(Request::new(key), None)
        .await
        .expect("test connection removes through the Layer lifecycle API");
    assert!(
        transport.latest_watch_is_cancelled(),
        "remove_connection cancels the physical watch before returning"
    );
    wait_for_dropped(&transport, 2).await;
    assert!(
        layer
            .list_address_roots(&Extensions::new(), None)
            .await
            .expect("the Layer remains usable after removing one connection")
            .0
            .roots
            .is_empty(),
        "only the removed connection's routes disappear"
    );
    assert!(
        subscriber.into_iter().next().is_none(),
        "the removed connection's subscriber reaches EOF"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn credential_rotation_cancels_old_stream_and_reauthorizes_same_prefix() {
    let prefix = Url::parse("s3://bucket/team/").unwrap();
    let auth_state = DiscoveryState::new("watch-rotation");
    let token_file = TempTokenFile::new("principal-a");
    let transport = Arc::new(CountingTransport::deny_rotated_identity(
        "s3://bucket/",
        false,
        auth_state.clone(),
    ));
    let layer = new_layer_for_tests_with_token_file(
        transport.clone(),
        auth_state.clone(),
        token_file.path().to_string_lossy().into_owned(),
    )
    .await
    .expect("test layer builds from fake roots");
    transport.authorize_current_identity();

    let mut principal_a = layer
        .watch_directory(
            watch_request(&prefix, WatchDirectoryOptions::default()),
            None,
        )
        .await
        .expect("principal A opens an authorized physical stream");
    assert_eq!(transport.calls().len(), 1);
    let key = connection_key(&layer, &prefix).await;

    // Rotate the direct endpoint's credential source, then let the production
    // Layer update path read, verify, activate, and fence the new identity. No
    // later watch call may be needed to notice the rotation.
    token_file.replace("principal-b");
    layer
        .update_connection_credentials(
            Request::new(UpdateConnectionCredentialsRequest {
                key,
                credentials: SecretBundle::default(),
            }),
            None,
        )
        .await
        .expect("credential update synchronizes the committed identity");
    assert!(
        transport.latest_watch_is_cancelled(),
        "credential update cancels principal A's physical stream before returning"
    );
    wait_for_dropped(&transport, 1).await;
    assert!(
        principal_a.next().is_none(),
        "the stream authorized for principal A ends before any subsequent watch"
    );

    let denied = layer
        .watch_directory(
            watch_request(&prefix, WatchDirectoryOptions::default()),
            None,
        )
        .await
        .err()
        .expect("principal B must open and authorize a new physical stream");
    assert_eq!(denied.code(), ErrorCode::PermissionDenied);
    assert_eq!(
        transport.calls().len(),
        2,
        "rotation cannot join A's stream"
    );
}
