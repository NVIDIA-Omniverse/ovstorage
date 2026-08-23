// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `AliasWrapper` behavior (address rewrite + reverse projection, visibility,
//! alias-root synthesis, live root-update projection) and the `Stack`
//! URL-canonicalization boundary.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use async_trait::async_trait;
use futures::StreamExt as _;

use ovstorage::layers::ALIAS_KIND;
use ovstorage::{
    AddressVisibility, AliasSource, AliasState, AuthEvent, AuthEventStream, AuthenticateRequest,
    CancellationToken, Capabilities, ChangeEvent, ChangeKind, ChangeStream, ConfigValue,
    Connection, ConnectionAuthState, ConnectionChange, ConnectionId, ConnectionKey,
    ConnectionRequest, ConnectionSource, ContinueWriteRequest, CopyRequest, ErrorCode,
    InteractiveAuthCapability, Layer, LayerConfig, LayerConnectionRequest, LayerHandle,
    LayerKindDescriptor, LayerSpec, ListPage, ListRequest, ListVersionsRequest, LocalDelegate,
    ObjectInfo, ReadRequest, ReadResult, Request, Result, RootInfo, RootInfoChange,
    RootInfoSnapshot, RootInfoUpdateStream, RouteSource, SecretBundle, Stack, StatOptions,
    StatRequest, UpdateConnectionCredentialsRequest, Url, UserMetadata, VersionPage,
    WatchDirectoryCursor, WatchDirectoryRequest, WriteRequest, WriteResult, WriteStep,
};
use ovstorage_plugin_core::{AliasRules, AliasWrapperFactory};

use crate::common::*;

/// The `user_metadata` key alias connections stamp with their rewrite target.
const ALIAS_TO_KEY: &str = "org.omniverse.ovstorage/alias-to";

/// A `Request<LayerConnectionRequest>` adding an alias `from → to` rule to the
/// `target` layer; `id` is `None` to auto-mint or `Some` to pin (config replay).
fn alias_request(
    target: &str,
    id: Option<&str>,
    from: &str,
    to: &str,
) -> Request<LayerConnectionRequest> {
    let mut config = HashMap::new();
    config.insert("from".to_string(), ConfigValue::String(from.to_string()));
    config.insert("to".to_string(), ConfigValue::String(to.to_string()));
    if let Some(id) = id {
        config.insert("id".to_string(), ConfigValue::String(id.to_string()));
    }
    Request::new(LayerConnectionRequest {
        target: target.to_string(),
        connection: ConnectionRequest {
            backend_kind: ALIAS_KIND.to_string(),
            config,
            credentials: SecretBundle::default(),
            persist: false,
            display_name: None,
        },
    })
}

/// A `Request<LayerConnectionRequest>` adding a visibility-override rule
/// `address → visibility` to the `target` layer.
fn visibility_request(
    target: &str,
    address: &str,
    visibility: &str,
) -> Request<LayerConnectionRequest> {
    let mut config = HashMap::new();
    config.insert(
        "address".to_string(),
        ConfigValue::String(address.to_string()),
    );
    config.insert(
        "visibility".to_string(),
        ConfigValue::String(visibility.to_string()),
    );
    Request::new(LayerConnectionRequest {
        target: target.to_string(),
        connection: ConnectionRequest {
            backend_kind: ALIAS_KIND.to_string(),
            config,
            credentials: SecretBundle::default(),
            persist: false,
            display_name: None,
        },
    })
}

fn connection_key(target: &str, id: &ConnectionId) -> Request<ConnectionKey> {
    Request::new(ConnectionKey {
        target: target.to_string(),
        id: id.clone(),
    })
}

async fn stat_addr(stack: &Stack, addr: &str) -> Result<ObjectInfo> {
    stack
        .stat(
            Request::new(StatRequest {
                address: Url::parse(addr).unwrap(),
                options: StatOptions::default(),
            }),
            None,
        )
        .await
}

/// A backend for the address/alias wrapper tests. Records the addresses it is
/// called with (so a test can prove the inbound `from`→`to` rewrite) and echoes
/// the received address into results (so the wrapper's reverse `to`→`from`
/// projection is observable). Advertises `roots` for `list_address_roots` /
/// `root_info_for`.
struct AddressProbe {
    content: Vec<u8>,
    roots: Vec<RootInfo>,
    received: Mutex<Vec<Url>>,
}

impl AddressProbe {
    fn new(content: &[u8], roots: Vec<RootInfo>) -> Arc<Self> {
        Arc::new(Self {
            content: content.to_vec(),
            roots,
            received: Mutex::new(Vec::new()),
        })
    }

    fn last_received(&self) -> Url {
        self.received.lock().unwrap().last().cloned().unwrap()
    }
}

#[async_trait]
impl Layer for AddressProbe {
    fn name(&self) -> &str {
        "backend"
    }

    fn descriptor(&self) -> LayerKindDescriptor {
        backend_descriptor(PROBE_KIND)
    }

    async fn root_info_for(
        &self,
        url: &Url,
        _cx: &ovstorage::Extensions,
        _cancel: Option<CancellationToken>,
    ) -> Result<RootInfo> {
        // Longest-prefix match over the configured roots, `NoRoute` otherwise —
        // the Router contract the alias wrapper's specificity rule
        // resolves real routes against.
        self.roots
            .iter()
            .filter(|root| ovstorage::address::is_ancestor_or_self(&root.root, url))
            .max_by_key(|root| root.root.as_str().len())
            .cloned()
            .ok_or_else(|| ovstorage::Error::new(ErrorCode::NoRoute, "no route matches address"))
    }

    async fn list_address_roots(
        &self,
        _cx: &ovstorage::Extensions,
        _cancel: Option<CancellationToken>,
    ) -> Result<(RootInfoSnapshot, Option<RootInfoUpdateStream>)> {
        Ok((
            RootInfoSnapshot {
                roots: self.roots.clone(),
                updates: false,
            },
            None,
        ))
    }

    async fn stat(
        &self,
        request: Request<StatRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        self.received
            .lock()
            .unwrap()
            .push(request.input.address.clone());
        Ok(object_info(
            request.input.address,
            self.content.len() as u64,
        ))
    }

    async fn read(
        &self,
        request: Request<ReadRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<ReadResult> {
        self.received
            .lock()
            .unwrap()
            .push(request.input.address.clone());
        Ok(ReadResult::Bytes {
            bytes: self.content.clone(),
            info: object_info(request.input.address, self.content.len() as u64),
        })
    }

    async fn list(
        &self,
        request: Request<ListRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<ListPage> {
        let prefix = request.input.prefix;
        self.received.lock().unwrap().push(prefix.clone());
        // One item directly under the (physical) prefix, so projecting the item
        // address back to caller space is observable.
        let item = Url::parse(&format!("{prefix}item")).unwrap();
        Ok(ListPage {
            items: vec![object_info(item, self.content.len() as u64)],
            next_page_token: None,
        })
    }

    async fn write(
        &self,
        request: Request<WriteRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        self.received
            .lock()
            .unwrap()
            .push(request.input.address.clone());
        Ok(WriteResult {
            info: object_info(request.input.address, self.content.len() as u64),
        })
    }

    async fn write_stream(
        &self,
        request: Request<WriteRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        self.received
            .lock()
            .unwrap()
            .push(request.input.address.clone());
        Ok(WriteResult {
            info: object_info(request.input.address, self.content.len() as u64),
        })
    }

    async fn continue_write(
        &self,
        request: Request<ContinueWriteRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<WriteStep> {
        self.received
            .lock()
            .unwrap()
            .push(request.input.address.clone());
        Ok(WriteStep::Done(WriteResult {
            info: object_info(request.input.address, self.content.len() as u64),
        }))
    }

    async fn copy(
        &self,
        request: Request<CopyRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<WriteStep> {
        let CopyRequest {
            source,
            destination,
            ..
        } = request.input;
        // Record both rewritten endpoints; the returned step carries the
        // destination, which the wrapper projects back to caller space.
        {
            let mut received = self.received.lock().unwrap();
            received.push(source);
            received.push(destination.clone());
        }
        Ok(WriteStep::Done(WriteResult {
            info: object_info(destination, 0),
        }))
    }

    async fn materialize(
        &self,
        request: Request<ReadRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<LocalDelegate> {
        self.received
            .lock()
            .unwrap()
            .push(request.input.address.clone());
        Ok(LocalDelegate {
            path: std::path::PathBuf::from("/phys/materialized"),
            info: object_info(request.input.address, self.content.len() as u64),
            guard: None,
        })
    }

    async fn list_versions(
        &self,
        request: Request<ListVersionsRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<VersionPage> {
        let address = request.input.address;
        self.received.lock().unwrap().push(address.clone());
        // A single version entry at the (physical) address, so projecting the
        // item address back to caller space is observable.
        Ok(VersionPage {
            items: vec![object_info(address, self.content.len() as u64)],
            next_page_token: None,
        })
    }

    async fn get_latest_version(
        &self,
        request: Request<ReadRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        self.received
            .lock()
            .unwrap()
            .push(request.input.address.clone());
        Ok(object_info(
            request.input.address,
            self.content.len() as u64,
        ))
    }

    async fn watch_directory(
        &self,
        request: Request<WatchDirectoryRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<ChangeStream> {
        let prefix = request.input.prefix;
        self.received.lock().unwrap().push(prefix.clone());
        // Emit one object event directly under the (physical) prefix; the
        // wrapper must project the event address back to caller space.
        let item = Url::parse(&format!("{prefix}item")).unwrap();
        let event = ChangeEvent::Object {
            address: item,
            kind: ChangeKind::Created,
            etag: None,
            version: None,
            size: Some(self.content.len() as u64),
            mtime: None,
            at: SystemTime::now(),
            cursor: WatchDirectoryCursor::default(),
        };
        Ok(Box::new(std::iter::once(Ok(event))))
    }
}

/// A `Stack` whose root *is* the backend (no wrappers), so a test observes the
/// `Stack`'s own canonicalization in isolation.
async fn backend_only_stack(backend: LayerHandle) -> Stack {
    Stack::builder("backend")
        .backend_factory(Arc::new(SharedBackendFactory { backend }))
        .layer(LayerSpec::backend("backend", PROBE_KIND))
        .build()
        .await
        .unwrap()
}

#[tokio::test]
async fn stack_canonicalizes_address_before_delegating() {
    // `probe://obj` is authority-with-empty-path; the `Stack` must normalize it
    // to `probe://obj/` *before* the root layer sees it, so every layer in the
    // chain keys off one canonical URL spelling. The canonicalization boundary
    // lives in the `Stack` itself, so a caller
    // driving the `Stack` API directly cannot bypass it.
    let backend = AddressProbe::new(b"x", vec![test_root("probe://obj/")]);
    let stack = backend_only_stack(backend.clone()).await;

    let info = stack
        .stat(
            Request::new(StatRequest {
                address: Url::parse("probe://obj").unwrap(),
                options: StatOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();
    // The backend (the root) was called with the canonical spelling.
    assert_eq!(backend.last_received().as_str(), "probe://obj/");
    assert_eq!(info.address.as_str(), "probe://obj/");
}

/// A fragment is REFUSED at the string ingress and stripped at the `Url` one,
/// and the divergence is structural rather than an oversight.
///
/// A fragment is a component the system would otherwise drop, and dropping a
/// component an operator wrote has to fail loudly. But the only view in which
/// a fragment still exists is the operator's raw string: `address::parse`
/// removes it, so a loader handed a `Url` has nothing left to refuse on. The
/// written ingress therefore refuses; the injected one, whose caller builds
/// `Url` values in-process and never spells a string, cannot and does not.
///
/// The rows that matter are the ones asserting the fragment-free rule still
/// WORKS, because a refusal and a silent drop are indistinguishable from a
/// test that only checks the call succeeded.
#[tokio::test]
async fn a_fragment_is_refused_at_the_written_alias_ingress() {
    let backend = AddressProbe::new(b"x", vec![test_root("target:///r/")]);
    let stack = build_stack(
        ALIAS_KIND,
        Arc::new(AliasWrapperFactory::default()),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    for (from, to, side) in [
        ("alias:///v/#note", "target:///r/", "from"),
        ("alias:///v/", "target:///r/#other", "to"),
    ] {
        let error = stack
            .root()
            .add_connection(alias_request("wrapper", None, from, to), None)
            .await
            .err()
            .unwrap_or_else(|| panic!("a fragment on `{side}` must be refused"));
        assert_eq!(error.code(), ErrorCode::InvalidArgument, "{side}");
        assert!(
            error.message().contains("fragment"),
            "{side}: the refusal must name what it refused: {}",
            error.message()
        );
    }

    // The fragment-free rule loads and routes, so the refusal is about the
    // component and not about the rule.
    stack
        .root()
        .add_connection(
            alias_request("wrapper", None, "alias:///v/", "target:///r/"),
            None,
        )
        .await
        .expect("the fragment-free rule must load");
    let info = stack
        .stat(
            Request::new(StatRequest {
                address: Url::parse("alias:///v/obj").unwrap(),
                options: StatOptions::default(),
            }),
            None,
        )
        .await
        .expect("the fragment-free rule routes");
    assert_eq!(backend.last_received().as_str(), "target:///r/obj");
    assert_eq!(info.address.as_str(), "alias:///v/obj");
}

/// The injected ingress takes `Url` values, so its fragment is stripped by
/// `canonicalize` and there is nothing left for a refusal to see. The rule it
/// installs is the fragment-free one and it routes — which is what makes the
/// divergence from the written ingress a difference in what each can observe
/// rather than a difference in the rule that ends up installed.
#[tokio::test]
async fn an_injected_fragment_is_stripped_because_no_string_reaches_the_loader() {
    let backend = AddressProbe::new(b"x", vec![test_root("target:///r/")]);
    let stack = build_stack(
        ALIAS_KIND,
        Arc::new(AliasWrapperFactory::with_rules(AliasRules {
            aliases: vec![(
                Url::parse("alias:///v/#note").unwrap(),
                Url::parse("target:///r/#other").unwrap(),
            )],
            visibility: Vec::new(),
        })),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .expect("an injected fragment has already been stripped by the time it arrives");

    let info = stack
        .stat(
            Request::new(StatRequest {
                address: Url::parse("alias:///v/obj").unwrap(),
                options: StatOptions::default(),
            }),
            None,
        )
        .await
        .expect("the stripped injected rule routes");
    assert_eq!(backend.last_received().as_str(), "target:///r/obj");
    assert_eq!(info.address.as_str(), "alias:///v/obj");
}

#[tokio::test]
async fn alias_rewrites_request_and_projects_result() {
    let backend = AddressProbe::new(b"x", vec![test_root("target:///r/")]);
    let mut config = LayerConfig::new();
    config.insert(
        "aliases".into(),
        ConfigValue::Toml("[[rule]]\nfrom = \"alias:///v/\"\nto = \"target:///r/\"\n".into()),
    );
    let stack = build_stack(
        ALIAS_KIND,
        Arc::new(AliasWrapperFactory::default()),
        backend.clone(),
        config,
    )
    .await
    .unwrap();

    let info = stack
        .stat(
            Request::new(StatRequest {
                address: Url::parse("alias:///v/obj").unwrap(),
                options: StatOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();
    assert_eq!(backend.last_received().as_str(), "target:///r/obj");
    assert_eq!(info.address.as_str(), "alias:///v/obj");
}

#[tokio::test]
async fn alias_defers_to_more_specific_real_route() {
    // Alias resolution wins only when its configured prefix is
    // longer than the matching real route's prefix: a broad alias
    // (`real:///` → `other:///space/`) must not shadow the more specific real
    // root `real:///specific/`, but still rewrites addresses no real root
    // covers.
    let backend = AddressProbe::new(b"x", vec![test_root("real:///specific/")]);
    let mut config = LayerConfig::new();
    config.insert(
        "aliases".into(),
        ConfigValue::Toml("[[rule]]\nfrom = \"real:///\"\nto = \"other:///space/\"\n".into()),
    );
    let stack = build_stack(
        ALIAS_KIND,
        Arc::new(AliasWrapperFactory::default()),
        backend.clone(),
        config,
    )
    .await
    .unwrap();

    // Under the more specific real root: the real route wins, the address
    // dispatches unchanged, and the result stays in the caller's space.
    let info = stack
        .stat(
            Request::new(StatRequest {
                address: Url::parse("real:///specific/obj").unwrap(),
                options: StatOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();
    assert_eq!(backend.last_received().as_str(), "real:///specific/obj");
    assert_eq!(info.address.as_str(), "real:///specific/obj");

    // root_info_for must not present the outweighed alias as the serving root.
    let root = stack
        .root()
        .root_info_for(
            &Url::parse("real:///specific/obj").unwrap(),
            &ovstorage::Extensions::new(),
            None,
        )
        .await
        .unwrap();
    assert_eq!(root.root.as_str(), "real:///specific/");
    assert_eq!(root.alias_state, None);

    // Outside the real root the alias still applies.
    stack
        .stat(
            Request::new(StatRequest {
                address: Url::parse("real:///elsewhere/obj").unwrap(),
                options: StatOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();
    assert_eq!(
        backend.last_received().as_str(),
        "other:///space/elsewhere/obj"
    );
}

#[tokio::test]
async fn alias_defers_to_equally_specific_real_route() {
    // "At least as specific" means the real route also wins a prefix-length
    // tie: an alias whose `from` equals a real root's prefix never rewrites.
    let backend = AddressProbe::new(b"x", vec![test_root("real:///data/")]);
    let mut config = LayerConfig::new();
    config.insert(
        "aliases".into(),
        ConfigValue::Toml("[[rule]]\nfrom = \"real:///data/\"\nto = \"other:///space/\"\n".into()),
    );
    let stack = build_stack(
        ALIAS_KIND,
        Arc::new(AliasWrapperFactory::default()),
        backend.clone(),
        config,
    )
    .await
    .unwrap();

    stack
        .stat(
            Request::new(StatRequest {
                address: Url::parse("real:///data/obj").unwrap(),
                options: StatOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();
    assert_eq!(backend.last_received().as_str(), "real:///data/obj");
}

#[tokio::test]
async fn alias_resolves_bounded_multi_hop_chain() {
    // N=2 chain: my:/// → mid:///m/ → target:///r/. The
    // request resolves through both hops, and every returned address replays
    // the applied hops in reverse — the caller's own (outermost) spelling.
    let backend = AddressProbe::new(b"x", vec![test_root("target:///r/")]);
    let mut config = LayerConfig::new();
    config.insert(
        "aliases".into(),
        ConfigValue::Toml(
            "[[rule]]\nfrom = \"my:///\"\nto = \"mid:///m/\"\n\
             [[rule]]\nfrom = \"mid:///\"\nto = \"target:///r/\"\n"
                .into(),
        ),
    );
    let stack = build_stack(
        ALIAS_KIND,
        Arc::new(AliasWrapperFactory::default()),
        backend.clone(),
        config,
    )
    .await
    .unwrap();

    let info = stack
        .stat(
            Request::new(StatRequest {
                address: Url::parse("my:///obj").unwrap(),
                options: StatOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();
    assert_eq!(backend.last_received().as_str(), "target:///r/m/obj");
    assert_eq!(info.address.as_str(), "my:///obj");

    // A caller entering the chain mid-way is mapped back only to its own
    // entry point, not the outermost namespace.
    let info = stack
        .stat(
            Request::new(StatRequest {
                address: Url::parse("mid:///m/obj").unwrap(),
                options: StatOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();
    assert_eq!(backend.last_received().as_str(), "target:///r/m/obj");
    assert_eq!(info.address.as_str(), "mid:///m/obj");

    // List items under a chained prefix round-trip the same way.
    let page = stack
        .list(
            Request::new(ListRequest {
                prefix: Url::parse("my:///").unwrap(),
                options: Default::default(),
            }),
            None,
        )
        .await
        .unwrap();
    assert_eq!(page.items[0].address.as_str(), "my:///item");
}

#[tokio::test]
async fn alias_per_hop_specificity_interrupts_chain() {
    // The specificity rule applies per hop: after the first hop
    // lands in b:///x/, the real root b:///x/ is more specific than the
    // matching rule b:/// and interrupts the chain — the second rule never
    // applies.
    let backend = AddressProbe::new(b"x", vec![test_root("b:///x/")]);
    let mut config = LayerConfig::new();
    config.insert(
        "aliases".into(),
        ConfigValue::Toml(
            "[[rule]]\nfrom = \"a:///\"\nto = \"b:///\"\n\
             [[rule]]\nfrom = \"b:///\"\nto = \"c:///\"\n"
                .into(),
        ),
    );
    let stack = build_stack(
        ALIAS_KIND,
        Arc::new(AliasWrapperFactory::default()),
        backend.clone(),
        config,
    )
    .await
    .unwrap();

    let info = stack
        .stat(
            Request::new(StatRequest {
                address: Url::parse("a:///x/obj").unwrap(),
                options: StatOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();
    assert_eq!(backend.last_received().as_str(), "b:///x/obj");
    assert_eq!(info.address.as_str(), "a:///x/obj");
}

#[tokio::test]
async fn alias_physical_space_caller_is_not_projected() {
    // Reverse projection applies only to results of requests that
    // were forward-rewritten. A caller addressing the rule's target space
    // directly gets results echoed in its own address space — not rewritten
    // into alias space.
    let backend = AddressProbe::new(b"x", vec![test_root("target:///r/")]);
    let mut config = LayerConfig::new();
    config.insert(
        "aliases".into(),
        ConfigValue::Toml("[[rule]]\nfrom = \"alias:///v/\"\nto = \"target:///r/\"\n".into()),
    );
    let stack = build_stack(
        ALIAS_KIND,
        Arc::new(AliasWrapperFactory::default()),
        backend.clone(),
        config,
    )
    .await
    .unwrap();

    let info = stack
        .stat(
            Request::new(StatRequest {
                address: Url::parse("target:///r/obj").unwrap(),
                options: StatOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();
    assert_eq!(backend.last_received().as_str(), "target:///r/obj");
    assert_eq!(info.address.as_str(), "target:///r/obj");

    let page = stack
        .list(
            Request::new(ListRequest {
                prefix: Url::parse("target:///r/").unwrap(),
                options: Default::default(),
            }),
            None,
        )
        .await
        .unwrap();
    assert_eq!(page.items[0].address.as_str(), "target:///r/item");
}

#[tokio::test]
async fn alias_factory_rejects_cycling_rules() {
    // Eager validation: a cycling rule set fails at stack
    // build with `AliasChainTooLong`, not at dispatch.
    let backend = AddressProbe::new(b"x", vec![test_root("target:///r/")]);
    let mut config = LayerConfig::new();
    config.insert(
        "aliases".into(),
        ConfigValue::Toml(
            "[[rule]]\nfrom = \"red:///\"\nto = \"blue:///\"\n\
             [[rule]]\nfrom = \"blue:///\"\nto = \"red:///\"\n"
                .into(),
        ),
    );
    let error = match build_stack(
        ALIAS_KIND,
        Arc::new(AliasWrapperFactory::default()),
        backend,
        config,
    )
    .await
    {
        Ok(_) => panic!("cycling rule set must fail at build"),
        Err(error) => error,
    };
    assert_eq!(error.code(), ErrorCode::AliasChainTooLong);
}

#[tokio::test]
async fn alias_factory_rejects_over_cap_chain() {
    // A self-prefixing rule never terminates (each application nests one level
    // deeper); eager validation reports the hop-cap breach at build time.
    let backend = AddressProbe::new(b"x", vec![test_root("target:///r/")]);
    let mut config = LayerConfig::new();
    config.insert(
        "aliases".into(),
        ConfigValue::Toml("[[rule]]\nfrom = \"cycle:///\"\nto = \"cycle:///sub/\"\n".into()),
    );
    let error = match build_stack(
        ALIAS_KIND,
        Arc::new(AliasWrapperFactory::default()),
        backend,
        config,
    )
    .await
    {
        Ok(_) => panic!("over-cap rule set must fail at build"),
        Err(error) => error,
    };
    assert_eq!(error.code(), ErrorCode::AliasChainTooLong);
}

#[tokio::test]
async fn alias_advertises_dangling_chain() {
    // An alias whose chain terminates nowhere advertises as Dangling (a bare
    // alias-facing root), so the misconfiguration is visible in discovery
    // instead of silently absent.
    let backend = AddressProbe::new(b"x", vec![test_root("target:///r/")]);
    let mut config = LayerConfig::new();
    config.insert(
        "aliases".into(),
        ConfigValue::Toml("[[rule]]\nfrom = \"alias:///v/\"\nto = \"missing:///x/\"\n".into()),
    );
    let stack = build_stack(
        ALIAS_KIND,
        Arc::new(AliasWrapperFactory::default()),
        backend,
        config,
    )
    .await
    .unwrap();

    let (snapshot, _) = stack
        .root()
        .list_address_roots(&ovstorage::Extensions::new(), None)
        .await
        .unwrap();
    let alias = snapshot
        .roots
        .iter()
        .find(|root| root.root.as_str() == "alias:///v/")
        .expect("dangling alias is advertised");
    assert_eq!(alias.alias_state, Some(AliasState::Dangling));
    match &alias.source {
        RouteSource::Alias { to, .. } => assert_eq!(to.as_str(), "missing:///x/"),
        other => panic!("expected RouteSource::Alias, got {other:?}"),
    }

    // root_info_for agrees with the advertisement: it reports the same
    // synthesized dangling alias root instead of NoRoute, so the two
    // introspection paths never diverge.
    let info = stack
        .root()
        .root_info_for(
            &Url::parse("alias:///v/obj").unwrap(),
            &ovstorage::Extensions::new(),
            None,
        )
        .await
        .unwrap();
    assert_eq!(info.root.as_str(), "alias:///v/");
    assert_eq!(info.alias_state, Some(AliasState::Dangling));
    match &info.source {
        RouteSource::Alias { to, .. } => assert_eq!(to.as_str(), "missing:///x/"),
        other => panic!("expected RouteSource::Alias, got {other:?}"),
    }
}

#[tokio::test]
async fn alias_chain_through_suppressed_intermediate_namespace() {
    // The load-bearing chain shape: a caller-visible alias
    // chains through an intermediate namespace that is suppressed by
    // construction. Dispatch through the chain works (suppression binds the
    // caller-supplied address only), the outer alias advertises Live, and the
    // suppressed intermediate is neither advertised nor directly addressable.
    let backend = AddressProbe::new(b"x", vec![test_root("target:///r/")]);
    let mut config = LayerConfig::new();
    config.insert(
        "aliases".into(),
        ConfigValue::Toml(
            "[[rule]]\nfrom = \"my:///\"\nto = \"mid:///m/\"\n\
             [[rule]]\nfrom = \"mid:///\"\nto = \"target:///r/\"\n"
                .into(),
        ),
    );
    config.insert(
        "visibility".into(),
        ConfigValue::Toml("[[entry]]\naddress = \"mid:///\"\nvisibility = \"suppressed\"\n".into()),
    );
    let stack = build_stack(
        ALIAS_KIND,
        Arc::new(AliasWrapperFactory::default()),
        backend.clone(),
        config,
    )
    .await
    .unwrap();

    // Dispatch through the chain succeeds even though the intermediate
    // namespace is suppressed.
    let info = stack
        .stat(
            Request::new(StatRequest {
                address: Url::parse("my:///obj").unwrap(),
                options: StatOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();
    assert_eq!(backend.last_received().as_str(), "target:///r/m/obj");
    assert_eq!(info.address.as_str(), "my:///obj");

    // A direct request into the suppressed intermediate is NoRoute.
    let error = stack
        .stat(
            Request::new(StatRequest {
                address: Url::parse("mid:///m/obj").unwrap(),
                options: StatOptions::default(),
            }),
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::NoRoute);

    // Advertisement: the outer alias is Live; the suppressed intermediate's
    // alias root does not appear.
    let (snapshot, _) = stack
        .root()
        .list_address_roots(&ovstorage::Extensions::new(), None)
        .await
        .unwrap();
    let roots: Vec<&str> = snapshot.roots.iter().map(|r| r.root.as_str()).collect();
    assert!(
        roots.contains(&"my:///"),
        "outer alias advertised: {roots:?}"
    );
    assert!(
        !roots.iter().any(|root| root.starts_with("mid:")),
        "suppressed intermediate stays unadvertised: {roots:?}"
    );
    let outer = snapshot
        .roots
        .iter()
        .find(|root| root.root.as_str() == "my:///")
        .unwrap();
    assert_eq!(outer.alias_state, Some(AliasState::Live));
}

#[tokio::test]
async fn alias_synthesizes_live_alias_root_and_drops_hidden() {
    // Inner roots: target:///r/ (Visible) and target:///h/ (Hidden via rule).
    // Aliases: alias:///v/ → target:///r/ (synthesized Live), and the Hidden
    // target's root must be dropped from the snapshot.
    let backend = AddressProbe::new(
        b"x",
        vec![test_root("target:///r/"), test_root("target:///h/")],
    );
    let mut config = LayerConfig::new();
    config.insert(
        "aliases".into(),
        ConfigValue::Toml("[[rule]]\nfrom = \"alias:///v/\"\nto = \"target:///r/\"\n".into()),
    );
    config.insert(
        "visibility".into(),
        ConfigValue::Toml(
            "[[entry]]\naddress = \"target:///h/\"\nvisibility = \"hidden\"\n".into(),
        ),
    );
    let stack = build_stack(
        ALIAS_KIND,
        Arc::new(AliasWrapperFactory::default()),
        backend,
        config,
    )
    .await
    .unwrap();

    let (snapshot, _) = stack
        .root()
        .list_address_roots(&ovstorage::Extensions::new(), None)
        .await
        .unwrap();
    // Hidden root dropped; Visible target + synthesized alias remain.
    let roots: Vec<&str> = snapshot.roots.iter().map(|r| r.root.as_str()).collect();
    assert!(
        roots.contains(&"target:///r/"),
        "visible target kept: {roots:?}"
    );
    assert!(
        roots.contains(&"alias:///v/"),
        "alias synthesized: {roots:?}"
    );
    assert!(
        !roots.contains(&"target:///h/"),
        "hidden dropped: {roots:?}"
    );

    let alias = snapshot
        .roots
        .iter()
        .find(|r| r.root.as_str() == "alias:///v/")
        .unwrap();
    assert!(alias.visible);
    assert_eq!(alias.visibility, AddressVisibility::Visible);
    assert_eq!(alias.alias_state, Some(AliasState::Live));
    // A construction-time alias advertises `Static { Programmatic }` — the
    // real seeded source, not a hardcode.
    match &alias.source {
        RouteSource::Alias { to, alias_source } => {
            assert_eq!(to.as_str(), "target:///r/");
            assert_eq!(
                *alias_source,
                AliasSource::Static {
                    layer: ovstorage::ConfigLayer::Programmatic
                }
            );
        }
        other => panic!("expected RouteSource::Alias, got {other:?}"),
    }
}

#[test]
fn alias_mutations_do_not_require_a_tokio_runtime() {
    // `Layer` does not require a Tokio runtime, and the plugin test harness
    // drives these slots under `futures::executor::block_on`. Detaching the
    // root-change notification must not smuggle a runtime requirement into a
    // trait implementation: with no runtime the notification runs inline
    // instead of panicking in `tokio::spawn`.
    futures::executor::block_on(async {
        let backend = AddressProbe::new(b"x", vec![test_root("target:///r/")]);
        let stack = build_stack(
            ALIAS_KIND,
            Arc::new(AliasWrapperFactory::default()),
            backend,
            LayerConfig::new(),
        )
        .await
        .unwrap();

        let connection = stack
            .root()
            .add_connection(
                alias_request("wrapper", None, "alias:///v/", "target:///r/"),
                None,
            )
            .await
            .expect("add_connection must not require a runtime");

        // The inline notification did the same work the detached one does: the
        // alias is advertised.
        let roots = stack
            .root()
            .list_address_roots(&ovstorage::Extensions::new(), None)
            .await
            .unwrap()
            .0
            .roots;
        assert!(
            roots.iter().any(|root| root.root.as_str() == "alias:///v/"),
            "the alias root must be advertised: {roots:?}",
        );

        stack
            .root()
            .update_connection_attributes(
                Request::new(ovstorage::UpdateConnectionAttributesRequest {
                    key: ConnectionKey {
                        target: "wrapper".to_string(),
                        id: connection.id.clone(),
                    },
                    patch: ovstorage::AttributePatch {
                        display_name: Some("Renamed".to_string()),
                        ..Default::default()
                    },
                }),
                None,
            )
            .await
            .expect("update_connection_attributes must not require a runtime");

        stack
            .root()
            .remove_connection(connection_key("wrapper", &connection.id), None)
            .await
            .expect("remove_connection must not require a runtime");
    });
}

#[test]
fn alias_connection_changes_are_delivered_in_commit_order() {
    // The connection-change send is sequenced by the same write guard that
    // serializes the rule swaps. Sending it after the guard dropped leaves a
    // window in which a concurrent remove of the SAME rule commits and emits
    // its `Removed` first, so a delta consumer ends holding a connection the
    // rule set no longer has — the ghost entry `NotifyOrder` fixes for roots,
    // on the sibling channel.
    //
    // The window is widest with no Tokio runtime, where the root-change
    // notification runs inline: an adder parked in its inner re-query is
    // holding an unsent `Added` for as long as that query takes.
    let backend = GatedRootsProbe::new(vec![test_root("target:///r/")]);
    let stack = Arc::new(
        futures::executor::block_on(build_stack(
            ALIAS_KIND,
            Arc::new(AliasWrapperFactory::default()),
            backend.clone(),
            LayerConfig::new(),
        ))
        .unwrap(),
    );
    let (_snapshot, stream) = futures::executor::block_on(
        stack
            .root()
            .list_connections(&ovstorage::Extensions::new(), None),
    )
    .unwrap();
    let mut stream = stream.expect("connection update stream");

    // The adder commits, then parks in the inline notification's re-query.
    backend
        .stall_next
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let adder = std::thread::spawn({
        let stack = Arc::clone(&stack);
        move || {
            futures::executor::block_on(stack.root().add_connection(
                alias_request("wrapper", Some("race"), "alias:///v/", "target:///r/"),
                None,
            ))
            .expect("add_connection");
        }
    });
    futures::executor::block_on(backend.entered.acquire())
        .expect("the gate stays open")
        .forget();

    // The remover commits while the adder is parked. Its own notification
    // queues behind the adder's ticket, so it gets its own thread.
    let remover = std::thread::spawn({
        let stack = Arc::clone(&stack);
        move || {
            futures::executor::block_on(stack.root().remove_connection(
                connection_key("wrapper", &ConnectionId("race".to_string())),
                None,
            ))
            .expect("remove_connection");
        }
    });
    // Wait for the removal to COMMIT — observable as the row leaving
    // `list_connections`, which takes no part in the notification ordering.
    loop {
        let present = futures::executor::block_on(
            stack
                .root()
                .list_connections(&ovstorage::Extensions::new(), None),
        )
        .unwrap()
        .0
        .connections
        .iter()
        .any(|connection| connection.id.0 == "race");
        if !present {
            break;
        }
        std::thread::yield_now();
    }

    backend.gate.add_permits(2);
    adder.join().expect("the adder must not panic");
    remover.join().expect("the remover must not panic");

    // Replay the deltas the way a delta consumer does.
    let mut order: Vec<&'static str> = Vec::new();
    while order.len() < 2 {
        match futures::executor::block_on(stream.next()) {
            Some(Ok(ConnectionChange::Added(connection))) if connection.id.0 == "race" => {
                order.push("added");
            }
            Some(Ok(ConnectionChange::Removed { id })) if id.0 == "race" => {
                order.push("removed");
            }
            Some(_) => {}
            None => break,
        }
    }
    assert_eq!(
        order,
        vec!["added", "removed"],
        "the connection deltas must arrive in commit order; a trailing `added` \
         leaves a delta consumer holding a connection no rule backs",
    );
}

/// Backend standing in for a FOREIGN inner layer: its `list_address_roots`
/// never returns, and the only signal that can stop the work it represents is
/// the cancellation token. A detached watcher — the analogue of the plugin-side
/// task and `user_data` allocation that outlive a dropped Rust future —
/// records that the token fired.
struct ForeignishProbe {
    cancelled: Arc<tokio::sync::Semaphore>,
}

impl ForeignishProbe {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            cancelled: Arc::new(tokio::sync::Semaphore::new(0)),
        })
    }
}

#[async_trait]
impl Layer for ForeignishProbe {
    fn name(&self) -> &str {
        "backend"
    }

    fn descriptor(&self) -> LayerKindDescriptor {
        backend_descriptor(PROBE_KIND)
    }

    async fn list_address_roots(
        &self,
        _cx: &ovstorage::Extensions,
        cancel: Option<CancellationToken>,
    ) -> Result<(RootInfoSnapshot, Option<RootInfoUpdateStream>)> {
        if let Some(cancel) = cancel {
            let cancelled = Arc::clone(&self.cancelled);
            tokio::spawn(async move {
                cancel.cancelled().await;
                cancelled.add_permits(1);
            });
        }
        std::future::pending().await
    }
}

#[tokio::test(start_paused = true)]
async fn alias_requery_timeout_cancels_the_inner_token() {
    // The notification's re-query budget exists to bound what one wedged inner
    // layer can hold. Letting the timeout merely DROP the query future bounds
    // only the Rust half: a `ForeignVtableLayer` child keeps its plugin task and
    // `user_data` alive until the FFI call ends by itself, so a blackholed
    // plugin would leak one foreign operation per alias mutation — the very
    // unbounded growth the budget was added to prevent. The timeout must cancel
    // the token, which is the one signal that crosses the ABI.
    let backend = ForeignishProbe::new();
    let stack = build_stack(
        ALIAS_KIND,
        Arc::new(AliasWrapperFactory::default()),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    // The mutation returns as soon as it commits; the notification's re-query
    // is what parks in the child.
    stack
        .root()
        .add_connection(
            alias_request("wrapper", None, "alias:///v/", "target:///r/"),
            None,
        )
        .await
        .expect("add_connection");

    // Paused clock: the budget elapses without a real wait.
    let cancelled = tokio::time::timeout(
        std::time::Duration::from_secs(120),
        backend.cancelled.acquire(),
    )
    .await;
    assert!(
        cancelled.is_ok(),
        "the timed-out re-query must cancel the token it handed the inner \
         layer; dropping the future is invisible to a foreign child",
    );
}

/// Backend whose `list_address_roots` can be pinned open for ONE call, so a
/// test can stall the root re-query behind one alias mutation's notification
/// while a later mutation's runs to completion.
struct GatedRootsProbe {
    /// Mutable so a test can retire the inner root while one re-query is pinned
    /// at the gate and a later one has already sampled it.
    roots: Mutex<Vec<RootInfo>>,
    /// One-shot: armed by the test, consumed by the next re-query, which then
    /// waits on `gate`.
    stall_next: std::sync::atomic::AtomicBool,
    gate: tokio::sync::Semaphore,
    /// Signals that a re-query has reached the gate.
    entered: tokio::sync::Semaphore,
    /// Signals that a re-query has SAMPLED the roots and returned them.
    answered: tokio::sync::Semaphore,
}

impl GatedRootsProbe {
    fn new(roots: Vec<RootInfo>) -> Arc<Self> {
        Arc::new(Self {
            roots: Mutex::new(roots),
            stall_next: std::sync::atomic::AtomicBool::new(false),
            gate: tokio::sync::Semaphore::new(0),
            entered: tokio::sync::Semaphore::new(0),
            answered: tokio::sync::Semaphore::new(0),
        })
    }

    fn set_roots(&self, roots: Vec<RootInfo>) {
        *self.roots.lock().unwrap() = roots;
    }

    /// Drop the `answered` permits the stack's own construction and subscribe
    /// calls left behind, so a later `acquire` observes only the re-query the
    /// test is waiting on.
    fn forget_answers(&self) {
        let stale = self.answered.available_permits();
        if stale > 0 {
            self.answered
                .try_acquire_many(stale as u32)
                .expect("the permits were just counted")
                .forget();
        }
    }
}

#[async_trait]
impl Layer for GatedRootsProbe {
    fn name(&self) -> &str {
        "backend"
    }

    fn descriptor(&self) -> LayerKindDescriptor {
        backend_descriptor(PROBE_KIND)
    }

    async fn list_address_roots(
        &self,
        _cx: &ovstorage::Extensions,
        _cancel: Option<CancellationToken>,
    ) -> Result<(RootInfoSnapshot, Option<RootInfoUpdateStream>)> {
        if self
            .stall_next
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            self.entered.add_permits(1);
            let _permit = self.gate.acquire().await.expect("the gate stays open");
        }
        // Sample, then announce: the caller owns the clone by the time a test
        // waiting on `answered` can change the roots.
        let roots = self.roots.lock().unwrap().clone();
        self.answered.add_permits(1);
        Ok((
            RootInfoSnapshot {
                roots,
                updates: false,
            },
            None,
        ))
    }
}

#[tokio::test]
async fn alias_root_deltas_are_delivered_in_rule_swap_order() {
    // Each alias mutation computes its root delta on a detached task, so a
    // stalled `add` can finish after the `remove` that followed it. These are
    // `Added`/`Removed` deltas and `notification_drain` applies them as a plain
    // upsert/delete, so a trailing stale `Added` strands that consumer on a root
    // no rule backs. The emissions must therefore land in rule-swap order.
    let backend = GatedRootsProbe::new(vec![test_root("target:///r/")]);
    let stack = build_stack(
        ALIAS_KIND,
        Arc::new(AliasWrapperFactory::default()),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    let (_snapshot, stream) = stack
        .root()
        .list_address_roots(&ovstorage::Extensions::new(), None)
        .await
        .unwrap();
    let mut stream = stream.expect("update stream");

    // The add commits, then its notification stalls in the backend re-query.
    backend
        .stall_next
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let connection = stack
        .root()
        .add_connection(
            alias_request("wrapper", None, "alias:///v/", "target:///r/"),
            None,
        )
        .await
        .unwrap();
    let _entered =
        tokio::time::timeout(std::time::Duration::from_secs(5), backend.entered.acquire())
            .await
            .expect("the add's notification must reach the gated re-query")
            .expect("the gate stays open");

    // The remove commits and its notification runs freely — overtaking the
    // stalled add unless the emissions are ordered.
    stack
        .root()
        .remove_connection(connection_key("wrapper", &connection.id), None)
        .await
        .unwrap();
    backend.gate.add_permits(1);

    // Drain to quiescence rather than stopping at the first `Removed`: the bug
    // is a TRAILING `Added`, which a loop that returns on `Removed` never sees.
    let alias = "alias:///v/";
    let mut order: Vec<&'static str> = Vec::new();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while let Some(Ok(change)) = stream.next().await {
            match change {
                RootInfoChange::Added(roots)
                    if roots.iter().any(|root| root.root.as_str() == alias) =>
                {
                    order.push("added")
                }
                RootInfoChange::Removed(roots)
                    if roots.iter().any(|root| root.root.as_str() == alias) =>
                {
                    order.push("removed")
                }
                _ => {}
            }
        }
    })
    .await;

    assert_eq!(
        order,
        vec!["added", "removed"],
        "the alias's deltas must arrive in rule-swap order and stop there; a \
         trailing `added` leaves a delta consumer holding a removed root",
    );
}

#[tokio::test]
async fn alias_root_deltas_are_computed_in_rule_swap_order_too() {
    // Ordering the SENDS is not enough. Each notification samples `inner` for
    // itself, so a stalled mutation's re-query can answer LATER than a
    // successor's and still emit FIRST — publishing a delta computed from an
    // older view of `inner` after one computed from a newer view. These are
    // precise Added/Removed deltas that `notification_drain` applies as an
    // upsert/delete without resnapshotting, so the pair does not telescope and
    // the consumer converges on the stale view. `inner` cannot correct it: an
    // aliased root exists only in this wrapper's projection, and an
    // `updates: false` inner has no stream at all.
    //
    // Here: `add(A)` stalls in its re-query; `add(B)` samples `inner` while the
    // target root is still live; the root then goes away; `add(A)`'s re-query
    // resumes and correctly finds both aliases dangling, so it emits nothing.
    // `add(B)`'s stale `Added(B)` then lands last, stranding the consumer on a
    // `Live` alias root nothing backs.
    let backend = GatedRootsProbe::new(vec![test_root("target:///r/")]);
    let stack = build_stack(
        ALIAS_KIND,
        Arc::new(AliasWrapperFactory::default()),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    let (snapshot, stream) = stack
        .root()
        .list_address_roots(&ovstorage::Extensions::new(), None)
        .await
        .unwrap();
    let mut stream = stream.expect("update stream");
    let mut advertised: Vec<RootInfo> = snapshot.roots.clone();

    // The first add commits; its notification stalls in the backend re-query,
    // still holding the live view of `inner`.
    backend
        .stall_next
        .store(true, std::sync::atomic::Ordering::SeqCst);
    stack
        .root()
        .add_connection(
            alias_request("wrapper", None, "alias:///a/", "target:///r/"),
            None,
        )
        .await
        .unwrap();
    let _entered =
        tokio::time::timeout(std::time::Duration::from_secs(5), backend.entered.acquire())
            .await
            .expect("the first add's notification must reach the gated re-query")
            .expect("the gate stays open");
    backend.forget_answers();

    // The second add commits and its notification re-queries freely, sampling
    // `inner` while `target:///r/` is still there.
    stack
        .root()
        .add_connection(
            alias_request("wrapper", None, "alias:///b/", "target:///r/"),
            None,
        )
        .await
        .unwrap();
    // Best-effort: this resolves when the second notification samples `inner`
    // ahead of the first. A build that samples in ticket order never gets here,
    // which is the point — it has nothing to be inconsistent with.
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        backend.answered.acquire(),
    )
    .await;

    // The inner root retires, then the stalled re-query resumes and observes
    // the world as it now is.
    backend.set_roots(Vec::new());
    backend.gate.add_permits(1);

    // Apply the deltas the way `notification_drain` does — upsert/delete, no
    // resnapshot — and drain to quiescence.
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while let Some(Ok(change)) = stream.next().await {
            let (roots, remove) = match change {
                RootInfoChange::Snapshot(roots) => {
                    advertised = roots;
                    continue;
                }
                RootInfoChange::Added(roots) | RootInfoChange::Updated(roots) => (roots, false),
                RootInfoChange::Removed(roots) => (roots, true),
            };
            for root in roots {
                advertised.retain(|held| held.root != root.root);
                if !remove {
                    advertised.push(root);
                }
            }
        }
    })
    .await;

    // Dangling aliases stay advertised — as `Dangling`. It is the LIVENESS the
    // stale snapshot corrupts, and nothing will correct it: `inner` has no
    // update stream, and an aliased root is this wrapper's projection alone.
    let live: Vec<String> = advertised
        .iter()
        .filter(|root| root.alias_state == Some(AliasState::Live))
        .map(|root| root.root.to_string())
        .collect();
    assert!(
        live.is_empty(),
        "both aliases dangle once `target:///r/` is gone, so a consumer that \
         applied every delta must hold neither as `Live`; it holds {live:?}, \
         from a delta computed against an inner snapshot older than the one \
         its predecessor had already published",
    );
}

/// Backend whose `list_address_roots` returns an empty initial snapshot and an
/// update stream that emits one `Snapshot` of `roots`. Lets a test observe that
/// the `AliasWrapper` projects live root updates, not just the first snapshot.
struct RootStreamProbe {
    roots: Vec<RootInfo>,
}

impl RootStreamProbe {
    fn new(roots: Vec<RootInfo>) -> Arc<Self> {
        Arc::new(Self { roots })
    }
}

#[async_trait]
impl Layer for RootStreamProbe {
    fn name(&self) -> &str {
        "backend"
    }

    fn descriptor(&self) -> LayerKindDescriptor {
        backend_descriptor(PROBE_KIND)
    }

    async fn list_address_roots(
        &self,
        _cx: &ovstorage::Extensions,
        _cancel: Option<CancellationToken>,
    ) -> Result<(RootInfoSnapshot, Option<RootInfoUpdateStream>)> {
        let update = RootInfoChange::Snapshot(self.roots.clone());
        let stream: RootInfoUpdateStream = Box::pin(futures::stream::iter(vec![Ok(update)]));
        Ok((
            RootInfoSnapshot {
                roots: Vec::new(),
                updates: true,
            },
            Some(stream),
        ))
    }
}

#[tokio::test]
async fn alias_projects_live_root_update_stream() {
    // The initial snapshot is empty; roots arrive later via the update stream.
    // The wrapper applies the same visibility filtering + alias synthesis to
    // stream updates as to the snapshot — the streaming projection of updates.
    // Without it, a later update leaks the Hidden root and skips the
    // synthesized alias.
    let backend = RootStreamProbe::new(vec![test_root("target:///r/"), test_root("target:///h/")]);
    let mut config = LayerConfig::new();
    config.insert(
        "aliases".into(),
        ConfigValue::Toml("[[rule]]\nfrom = \"alias:///v/\"\nto = \"target:///r/\"\n".into()),
    );
    config.insert(
        "visibility".into(),
        ConfigValue::Toml(
            "[[entry]]\naddress = \"target:///h/\"\nvisibility = \"hidden\"\n".into(),
        ),
    );
    let stack = build_stack(
        ALIAS_KIND,
        Arc::new(AliasWrapperFactory::default()),
        backend,
        config,
    )
    .await
    .unwrap();

    let (_snapshot, stream) = stack
        .root()
        .list_address_roots(&ovstorage::Extensions::new(), None)
        .await
        .unwrap();
    let mut stream = stream.expect("backend advertises an update stream");
    use futures::StreamExt as _;
    let change = stream.next().await.expect("one root update").unwrap();
    let roots: Vec<String> = match change {
        RootInfoChange::Snapshot(roots) => {
            roots.iter().map(|r| r.root.as_str().to_string()).collect()
        }
        other => panic!("expected a projected Snapshot, got {other:?}"),
    };
    assert!(
        roots.contains(&"target:///r/".to_string()),
        "visible target kept on the stream: {roots:?}"
    );
    assert!(
        roots.contains(&"alias:///v/".to_string()),
        "alias synthesized on the stream: {roots:?}"
    );
    assert!(
        !roots.contains(&"target:///h/".to_string()),
        "hidden root dropped on the stream: {roots:?}"
    );
}

#[tokio::test]
async fn alias_root_info_for_reports_alias_facing_root() {
    // root_info_for of a deeper object URL under an alias reports the alias-facing
    // root prefix + RouteSource::Alias + AliasState::Live, not the inner target.
    let backend = AddressProbe::new(b"x", vec![test_root("target:///r/")]);
    let mut config = LayerConfig::new();
    config.insert(
        "aliases".into(),
        ConfigValue::Toml("[[rule]]\nfrom = \"alias:///v/\"\nto = \"target:///r/\"\n".into()),
    );
    let stack = build_stack(
        ALIAS_KIND,
        Arc::new(AliasWrapperFactory::default()),
        backend,
        config,
    )
    .await
    .unwrap();

    let info = stack
        .root()
        .root_info_for(
            &Url::parse("alias:///v/obj").unwrap(),
            &ovstorage::Extensions::new(),
            None,
        )
        .await
        .unwrap();
    assert_eq!(info.root.as_str(), "alias:///v/");
    assert_eq!(info.alias_state, Some(AliasState::Live));
    match &info.source {
        RouteSource::Alias { to, .. } => assert_eq!(to.as_str(), "target:///r/"),
        other => panic!("expected RouteSource::Alias, got {other:?}"),
    }
}

#[tokio::test]
async fn alias_rejects_suppressed_address() {
    let backend = CacheProbe::new(b"x", Vec::new());
    let mut config = LayerConfig::new();
    config.insert(
        "visibility".into(),
        ConfigValue::Toml(
            "[[entry]]\naddress = \"mem:///secret/\"\nvisibility = \"suppressed\"\n".into(),
        ),
    );
    let stack = build_stack(
        ALIAS_KIND,
        Arc::new(AliasWrapperFactory::default()),
        backend,
        config,
    )
    .await
    .unwrap();

    let error = stack
        .stat(
            Request::new(StatRequest {
                address: Url::parse("mem:///secret/obj").unwrap(),
                options: StatOptions::default(),
            }),
            None,
        )
        .await
        .unwrap_err();
    // Suppressed rejection is `NoRoute` — indistinguishable from an
    // unconfigured namespace, so the suppressed configuration never leaks.
    assert_eq!(error.code(), ErrorCode::NoRoute);
}

// ---------------------------------------------------------------------------
// Connection-owning AliasWrapper (runtime alias/visibility CRUD)
//
// The wrapper is named "wrapper" by `build_stack`, so `target = "wrapper"`.
// ---------------------------------------------------------------------------

/// Build an `alias` wrapper with no construction-time rules over a backend
/// advertising `roots`, so every rule enters through `add_connection`.
async fn empty_alias_stack(backend: LayerHandle) -> Stack {
    build_stack(
        ALIAS_KIND,
        Arc::new(AliasWrapperFactory::default()),
        backend,
        LayerConfig::new(),
    )
    .await
    .unwrap()
}

/// A backend whose `list_address_roots` can be pinned open on a gate, standing
/// in for an inner layer that stalls (or never answers) the root re-query the
/// alias wrapper runs after a rule mutation commits.
struct StallingRoots {
    roots: Vec<RootInfo>,
    stall: std::sync::atomic::AtomicBool,
    /// Released by the test to let a stalled re-query complete.
    gate: tokio::sync::Semaphore,
    /// Signals that a re-query has reached the gate.
    entered: tokio::sync::Semaphore,
}

impl StallingRoots {
    fn new(roots: Vec<RootInfo>) -> Arc<Self> {
        Arc::new(Self {
            roots,
            stall: std::sync::atomic::AtomicBool::new(false),
            gate: tokio::sync::Semaphore::new(0),
            entered: tokio::sync::Semaphore::new(0),
        })
    }
}

#[async_trait]
impl Layer for StallingRoots {
    fn name(&self) -> &str {
        "backend"
    }

    fn descriptor(&self) -> LayerKindDescriptor {
        backend_descriptor(PROBE_KIND)
    }

    async fn root_info_for(
        &self,
        url: &Url,
        _cx: &ovstorage::Extensions,
        _cancel: Option<CancellationToken>,
    ) -> Result<RootInfo> {
        self.roots
            .iter()
            .filter(|root| ovstorage::address::is_ancestor_or_self(&root.root, url))
            .max_by_key(|root| root.root.as_str().len())
            .cloned()
            .ok_or_else(|| ovstorage::Error::new(ErrorCode::NoRoute, "no route matches address"))
    }

    async fn list_address_roots(
        &self,
        _cx: &ovstorage::Extensions,
        _cancel: Option<CancellationToken>,
    ) -> Result<(RootInfoSnapshot, Option<RootInfoUpdateStream>)> {
        if self.stall.load(std::sync::atomic::Ordering::SeqCst) {
            self.entered.add_permits(1);
            // The permit returns on drop, so once the test releases the gate
            // every later re-query passes straight through.
            let _permit = self.gate.acquire().await.expect("the gate stays open");
        }
        Ok((
            RootInfoSnapshot {
                roots: self.roots.clone(),
                updates: false,
            },
            None,
        ))
    }
}

#[tokio::test]
async fn alias_mutation_does_not_wait_on_a_stalled_inner_root_query() {
    // The rule swap commits under the write guard; the advertised-root delta
    // that follows needs a fresh `inner.list_address_roots`, which may reach
    // remote I/O. A stalled inner layer must not hold the committed mutation
    // open, and the delta must still be emitted once the inner layer answers.
    let backend = StallingRoots::new(vec![test_root("target:///r/")]);
    let stack = empty_alias_stack(backend.clone()).await;
    let (_snapshot, stream) = stack
        .root()
        .list_address_roots(&ovstorage::Extensions::new(), None)
        .await
        .unwrap();
    let mut stream = stream.expect("update stream");

    backend
        .stall
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let connection = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stack.root().add_connection(
            alias_request("wrapper", None, "alias:///v/", "target:///r/"),
            None,
        ),
    )
    .await
    .expect("a stalled inner root query must not hold the committed mutation open")
    .unwrap();
    assert_eq!(
        connection.current_addresses,
        vec![Url::parse("alias:///v/").unwrap()]
    );

    // The rule is live for dispatch while the notification is still pending:
    // the alias namespace resolves through to the physical root.
    let info = stack
        .root()
        .root_info_for(
            &Url::parse("alias:///v/obj").unwrap(),
            &ovstorage::Extensions::new(),
            None,
        )
        .await
        .unwrap();
    assert_eq!(info.root.as_str(), "alias:///v/");

    // Gate on the notification having reached the stalled re-query, then
    // release it: the delta the caller never waited for is still emitted.
    let _entered =
        tokio::time::timeout(std::time::Duration::from_secs(5), backend.entered.acquire())
            .await
            .expect("the detached notification must reach the inner root re-query");
    backend.gate.add_permits(1);

    let added = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let change = stream
                .next()
                .await
                .expect("stream is not terminated")
                .unwrap();
            if let RootInfoChange::Added(roots) = change {
                return roots;
            }
        }
    })
    .await
    .expect("the released notification must emit the new alias root");
    assert!(
        added.iter().any(|root| root.root.as_str() == "alias:///v/"),
        "the added alias root must be advertised: {added:?}",
    );
}

#[tokio::test]
async fn alias_connection_crud_round_trip() {
    // add → list_connections shows it → resolve uses it → remove → NoRoute.
    let backend = AddressProbe::new(b"x", vec![test_root("target:///r/")]);
    let stack = empty_alias_stack(backend.clone()).await;

    // Before the add: the alias namespace is unconfigured.
    assert!(
        stack
            .root()
            .list_connections(&ovstorage::Extensions::new(), None)
            .await
            .unwrap()
            .0
            .connections
            .is_empty()
    );
    assert_eq!(
        stack
            .root()
            .root_info_for(
                &Url::parse("alias:///v/obj").unwrap(),
                &ovstorage::Extensions::new(),
                None,
            )
            .await
            .unwrap_err()
            .code(),
        ErrorCode::NoRoute,
    );

    let connection = stack
        .root()
        .add_connection(
            alias_request("wrapper", None, "alias:///v/", "target:///r/"),
            None,
        )
        .await
        .unwrap();
    assert_eq!(connection.backend_kind, ALIAS_KIND);
    assert_eq!(connection.auth_state, ConnectionAuthState::Anonymous);
    assert_eq!(
        connection.current_addresses,
        vec![Url::parse("alias:///v/").unwrap()]
    );
    assert_eq!(
        connection
            .user_metadata
            .get(ALIAS_TO_KEY)
            .map(String::as_str),
        Some("target:///r/"),
    );

    // list_connections now shows the alias connection by id.
    let listed = stack
        .root()
        .list_connections(&ovstorage::Extensions::new(), None)
        .await
        .unwrap()
        .0
        .connections;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, connection.id);

    // resolve uses it: the request is rewritten into target space, the result
    // is projected back into alias space.
    let info = stat_addr(&stack, "alias:///v/obj").await.unwrap();
    assert_eq!(backend.last_received().as_str(), "target:///r/obj");
    assert_eq!(info.address.as_str(), "alias:///v/obj");

    // remove by (target, id): the rule is gone.
    stack
        .root()
        .remove_connection(connection_key("wrapper", &connection.id), None)
        .await
        .unwrap();
    assert!(
        stack
            .root()
            .list_connections(&ovstorage::Extensions::new(), None)
            .await
            .unwrap()
            .0
            .connections
            .is_empty()
    );

    // NoRoute again, and the address is not rewritten.
    assert_eq!(
        stack
            .root()
            .root_info_for(
                &Url::parse("alias:///v/obj").unwrap(),
                &ovstorage::Extensions::new(),
                None,
            )
            .await
            .unwrap_err()
            .code(),
        ErrorCode::NoRoute,
    );
    stat_addr(&stack, "alias:///v/obj").await.unwrap();
    assert_eq!(backend.last_received().as_str(), "alias:///v/obj");
}

#[tokio::test]
async fn alias_connection_rejects_duplicate_id() {
    let backend = AddressProbe::new(b"x", vec![test_root("target:///r/")]);
    let stack = empty_alias_stack(backend).await;

    stack
        .root()
        .add_connection(
            alias_request("wrapper", Some("dup"), "a:///", "target:///r/"),
            None,
        )
        .await
        .unwrap();
    let error = stack
        .root()
        .add_connection(
            alias_request("wrapper", Some("dup"), "b:///", "target:///r/"),
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::AlreadyExists);
    // The rejected add did not register a second row.
    assert_eq!(
        stack
            .root()
            .list_connections(&ovstorage::Extensions::new(), None)
            .await
            .unwrap()
            .0
            .connections
            .len(),
        1
    );
}

#[tokio::test]
async fn alias_connection_rejects_duplicate_from() {
    let backend = AddressProbe::new(b"x", vec![test_root("target:///r/")]);
    let stack = empty_alias_stack(backend).await;

    stack
        .root()
        .add_connection(
            alias_request("wrapper", Some("first"), "a:///v/", "target:///r/"),
            None,
        )
        .await
        .unwrap();
    let error = stack
        .root()
        .add_connection(
            alias_request("wrapper", Some("second"), "a:///v/", "target:///s/"),
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::InvalidArgument);
    // The rejected add did not register a second row.
    assert_eq!(
        stack
            .root()
            .list_connections(&ovstorage::Extensions::new(), None)
            .await
            .unwrap()
            .0
            .connections
            .len(),
        1
    );
}

#[tokio::test]
async fn alias_connection_add_rejects_over_cap_chain() {
    // Eager validation is reused by `add_connection`: a self-nesting rule
    // is rejected at add time and never installed.
    let backend = AddressProbe::new(b"x", vec![test_root("target:///r/")]);
    let stack = empty_alias_stack(backend).await;

    let error = stack
        .root()
        .add_connection(
            alias_request("wrapper", None, "cycle:///", "cycle:///sub/"),
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::AliasChainTooLong);
    assert!(
        stack
            .root()
            .list_connections(&ovstorage::Extensions::new(), None)
            .await
            .unwrap()
            .0
            .connections
            .is_empty()
    );
}

#[tokio::test]
async fn alias_probe_is_side_effect_free() {
    let backend = AddressProbe::new(b"x", vec![test_root("target:///r/")]);
    let stack = empty_alias_stack(backend.clone()).await;

    let probed = stack
        .root()
        .probe(
            alias_request("wrapper", None, "alias:///v/", "target:///r/"),
            None,
        )
        .await
        .unwrap();
    // A credentialless success, but nothing registered.
    assert_eq!(probed.auth_state, ConnectionAuthState::Anonymous);
    assert!(
        stack
            .root()
            .list_connections(&ovstorage::Extensions::new(), None)
            .await
            .unwrap()
            .0
            .connections
            .is_empty()
    );
    // resolve is unaffected: the alias namespace still does not rewrite.
    assert_eq!(
        stack
            .root()
            .root_info_for(
                &Url::parse("alias:///v/obj").unwrap(),
                &ovstorage::Extensions::new(),
                None,
            )
            .await
            .unwrap_err()
            .code(),
        ErrorCode::NoRoute,
    );

    // A probe that would form an invalid chain is rejected (validated, not
    // added).
    let error = stack
        .root()
        .probe(
            alias_request("wrapper", None, "cycle:///", "cycle:///sub/"),
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::AliasChainTooLong);
}

#[tokio::test]
async fn alias_add_after_snapshot_emits_synthesized_root() {
    // Subscribe to the root-update stream, THEN add an alias: the subscriber
    // observes the synthesized alias root, projected/filtered exactly like the
    // snapshot path (Visible, RouteSource::Alias, AliasState::Live).
    let backend = AddressProbe::new(b"x", vec![test_root("target:///r/")]);
    let stack = empty_alias_stack(backend).await;

    let (_snapshot, stream) = stack
        .root()
        .list_address_roots(&ovstorage::Extensions::new(), None)
        .await
        .unwrap();
    let mut stream = stream.expect("wrapper always advertises an update stream");

    stack
        .root()
        .add_connection(
            alias_request("wrapper", None, "alias:///v/", "target:///r/"),
            None,
        )
        .await
        .unwrap();

    let change = tokio::time::timeout(std::time::Duration::from_secs(5), stream.next())
        .await
        .expect("a root change is emitted")
        .expect("stream is not terminated")
        .unwrap();
    let roots = match change {
        RootInfoChange::Added(roots) => roots,
        other => panic!("expected Added, got {other:?}"),
    };
    let alias = roots
        .iter()
        .find(|root| root.root.as_str() == "alias:///v/")
        .expect("synthesized alias root emitted");
    assert!(alias.visible);
    assert_eq!(alias.visibility, AddressVisibility::Visible);
    assert_eq!(alias.alias_state, Some(AliasState::Live));
    // The synthesized root carries the rule's real `AliasSource` — a
    // runtime-added alias is reported `Runtime`, matching `list_connections`,
    // not mislabelled `Static`.
    match &alias.source {
        RouteSource::Alias { to, alias_source } => {
            assert_eq!(to.as_str(), "target:///r/");
            assert_eq!(*alias_source, AliasSource::Runtime { persisted: false });
        }
        other => panic!("expected RouteSource::Alias, got {other:?}"),
    }
}

/// Patching a hidden rule visible must not install a rule the loader refuses.
///
/// A credential-bearing prefix loads while it HIDES: matching ignores
/// userinfo, so the rule hides more than it spells, which is the safe
/// direction. `update_connection_attributes` is the one operation that turns
/// that same rule `Visible`, where the identical widening publishes a path
/// under every credential — the state the loader refuses. Validating only
/// where a rule enters the set left the refusal asserted at one door and
/// unenforced at the other.
#[tokio::test]
async fn patching_a_credential_bearing_rule_visible_is_refused() {
    let backend = AddressProbe::new(b"x", vec![test_root("target:///r/")]);
    let stack = empty_alias_stack(backend).await;

    // Hiding with a credential in the prefix is allowed, and the test would
    // prove nothing if it were not: this is the rule the patch acts on.
    let hidden = stack
        .root()
        .add_connection(
            visibility_request("wrapper", "https://reader:token@h.invalid/team/", "hidden"),
            None,
        )
        .await
        .expect("hiding more than the rule spells is the safe direction");

    let error = stack
        .root()
        .update_connection_attributes(
            Request::new(ovstorage::UpdateConnectionAttributesRequest {
                key: ConnectionKey {
                    target: "wrapper".to_string(),
                    id: hidden.id.clone(),
                },
                patch: ovstorage::AttributePatch {
                    visible: Some(true),
                    ..Default::default()
                },
            }),
            None,
        )
        .await
        .expect_err("a patch must not reach a state `add_connection` refuses");
    assert_eq!(error.code(), ErrorCode::InvalidArgument);

    // And the refused patch left the rule set alone, observed through a later
    // add: `add_connection` validates the WHOLE candidate set, so a patched
    // rule that had leaked into it would fail this unrelated add with an error
    // naming a rule the operator did not touch. The mutation happens on a
    // clone inside the commit closure and the `?` returns before the swap, so
    // this holds today; asserting it means moving the validation out of that
    // closure cannot quietly stop it being true.
    stack
        .root()
        .add_connection(
            visibility_request("wrapper", "https://h.invalid/unrelated/", "hidden"),
            None,
        )
        .await
        .expect("the refused patch must not have entered the rule set");

    // The control: the same patch on a credential-less rule is ordinary, so
    // the guard is not refusing every visibility patch.
    let plain = stack
        .root()
        .add_connection(
            visibility_request("wrapper", "https://h.invalid/other/", "hidden"),
            None,
        )
        .await
        .expect("a credential-less hidden rule adds");
    stack
        .root()
        .update_connection_attributes(
            Request::new(ovstorage::UpdateConnectionAttributesRequest {
                key: ConnectionKey {
                    target: "wrapper".to_string(),
                    id: plain.id.clone(),
                },
                patch: ovstorage::AttributePatch {
                    visible: Some(true),
                    ..Default::default()
                },
            }),
            None,
        )
        .await
        .expect("making an ordinary hidden rule visible must still work");
}

/// A runtime visibility add must not smuggle in a second spelling of a scope
/// the operator already hid.
///
/// The two spellings tie on rank, so `visibility_of_in`'s `max_by_key` returns
/// whichever the iterator reaches last — the runtime-added one. A `Visible`
/// added after a configured `Hidden` therefore silently re-advertises the
/// hidden subtree with no error surfaced. That is the fail-open the load-time
/// rejection exists to prevent, and it was reachable because only the config
/// path and the `Alias` fragment validated; the `Visibility` fragment did not.
#[tokio::test]
async fn a_runtime_visibility_add_cannot_collide_with_a_configured_scope() {
    let backend = AddressProbe::new(b"x", vec![test_root("target:///r/")]);
    let mut config = LayerConfig::new();
    // `[[visibility]]`, not `[[rule]]` — the visibility table has its own shape,
    // and a mis-spelled fixture parses to an EMPTY rule set, which is how the
    // first version of this test passed against the unfixed code.
    config.insert(
        "visibility".into(),
        ConfigValue::Toml(
            "[[visibility]]\naddress = \"alias:///team/\"\nvisibility = \"hidden\"\n".into(),
        ),
    );
    let stack = build_stack(
        ALIAS_KIND,
        Arc::new(AliasWrapperFactory::default()),
        backend,
        config,
    )
    .await
    .unwrap();

    // The slashless spelling of the SAME scope, with the opposite verdict.
    let error = stack
        .root()
        .add_connection(
            visibility_request("wrapper", "alias:///team", "visible"),
            None,
        )
        .await
        .expect_err("a colliding spelling must be refused, not silently applied");
    assert_eq!(error.code(), ErrorCode::InvalidArgument);

    // The control: a genuinely different scope still adds, so the check is not
    // simply refusing every runtime visibility rule.
    stack
        .root()
        .add_connection(
            visibility_request("wrapper", "alias:///other/", "visible"),
            None,
        )
        .await
        .expect("an unrelated scope must still be accepted");
}

#[tokio::test]
async fn alias_visibility_override_emits_root_change() {
    // Hiding a live alias's `from` at runtime drops its synthesized root from
    // the projection — observed as a Removed on the update stream.
    let backend = AddressProbe::new(b"x", vec![test_root("target:///r/")]);
    let mut config = LayerConfig::new();
    config.insert(
        "aliases".into(),
        ConfigValue::Toml("[[rule]]\nfrom = \"alias:///v/\"\nto = \"target:///r/\"\n".into()),
    );
    let stack = build_stack(
        ALIAS_KIND,
        Arc::new(AliasWrapperFactory::default()),
        backend,
        config,
    )
    .await
    .unwrap();

    let (snapshot, stream) = stack
        .root()
        .list_address_roots(&ovstorage::Extensions::new(), None)
        .await
        .unwrap();
    assert!(
        snapshot
            .roots
            .iter()
            .any(|root| root.root.as_str() == "alias:///v/"),
        "alias advertised before hiding",
    );
    let mut stream = stream.expect("update stream");

    stack
        .root()
        .add_connection(visibility_request("wrapper", "alias:///v/", "hidden"), None)
        .await
        .unwrap();

    let change = tokio::time::timeout(std::time::Duration::from_secs(5), stream.next())
        .await
        .expect("a root change is emitted")
        .expect("stream is not terminated")
        .unwrap();
    let removed = match change {
        RootInfoChange::Removed(roots) => roots,
        other => panic!("expected Removed, got {other:?}"),
    };
    assert!(
        removed
            .iter()
            .any(|root| root.root.as_str() == "alias:///v/"),
        "the now-hidden alias root is removed: {removed:?}",
    );
}

#[tokio::test]
async fn alias_remove_does_not_leak_suppressed_target() {
    // An alias into a suppressed physical target: removing it emits only the
    // alias root, never the suppressed target, and both namespaces become
    // NoRoute-indistinguishable from never-configured.
    let backend = AddressProbe::new(b"x", vec![test_root("target:///r/")]);
    let mut config = LayerConfig::new();
    config.insert(
        "visibility".into(),
        ConfigValue::Toml(
            "[[entry]]\naddress = \"target:///r/\"\nvisibility = \"suppressed\"\n".into(),
        ),
    );
    let stack = build_stack(
        ALIAS_KIND,
        Arc::new(AliasWrapperFactory::default()),
        backend,
        config,
    )
    .await
    .unwrap();

    let connection = stack
        .root()
        .add_connection(
            alias_request("wrapper", None, "alias:///v/", "target:///r/"),
            None,
        )
        .await
        .unwrap();

    let (_snapshot, stream) = stack
        .root()
        .list_address_roots(&ovstorage::Extensions::new(), None)
        .await
        .unwrap();
    let mut stream = stream.expect("update stream");

    stack
        .root()
        .remove_connection(connection_key("wrapper", &connection.id), None)
        .await
        .unwrap();

    // The wrapper emits root changes from a task detached from the mutating
    // caller, so the earlier add's `Added` can land on this subscription too;
    // take items until the removal's `Removed` arrives.
    let removed = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let change = stream
                .next()
                .await
                .expect("stream is not terminated")
                .unwrap();
            if let RootInfoChange::Removed(roots) = change {
                return roots;
            }
        }
    })
    .await
    .expect("a root removal is emitted");
    assert!(
        removed
            .iter()
            .all(|root| !root.root.as_str().starts_with("target:")),
        "the suppressed target must not leak on removal: {removed:?}",
    );
    assert!(
        removed
            .iter()
            .any(|root| root.root.as_str() == "alias:///v/"),
        "only the alias root is removed: {removed:?}",
    );

    // Both namespaces are now NoRoute — the alias (unconfigured) and its former
    // suppressed target (still suppressed) look identical from outside.
    assert_eq!(
        stack
            .root()
            .root_info_for(
                &Url::parse("alias:///v/obj").unwrap(),
                &ovstorage::Extensions::new(),
                None,
            )
            .await
            .unwrap_err()
            .code(),
        ErrorCode::NoRoute,
    );
    assert_eq!(
        stat_addr(&stack, "target:///r/obj")
            .await
            .unwrap_err()
            .code(),
        ErrorCode::NoRoute,
    );
}

#[tokio::test]
async fn alias_connection_stream_subscribe_before_snapshot_loses_nothing() {
    // subscribe-before-snapshot: an add whose row is already in the snapshot,
    // plus a later add delivered on the stream — the union covers both with no
    // lost update.
    let backend = AddressProbe::new(b"x", vec![test_root("target:///r/")]);
    let stack = empty_alias_stack(backend).await;

    let first = stack
        .root()
        .add_connection(
            alias_request("wrapper", Some("first"), "a:///", "target:///r/"),
            None,
        )
        .await
        .unwrap();

    // Snapshot taken after `first`, stream subscribed before `second`.
    let (snapshot, stream) = stack
        .root()
        .list_connections(&ovstorage::Extensions::new(), None)
        .await
        .unwrap();
    let mut stream = stream.expect("connection update stream");
    assert!(
        snapshot.connections.iter().any(|c| c.id == first.id),
        "the pre-subscribe add is in the snapshot",
    );

    let second = stack
        .root()
        .add_connection(
            alias_request("wrapper", Some("second"), "b:///", "target:///r/"),
            None,
        )
        .await
        .unwrap();

    let change = tokio::time::timeout(std::time::Duration::from_secs(5), stream.next())
        .await
        .expect("a connection change is emitted")
        .expect("stream is not terminated")
        .unwrap();
    match change {
        ConnectionChange::Added(connection) => assert_eq!(connection.id, second.id),
        other => panic!("expected Added(second), got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn alias_concurrent_add_and_read_are_consistent() {
    // Interleave 16 concurrent adds (distinct ids) with concurrent reads. The
    // RwLock-guarded read-modify-write must lose no update and never deadlock;
    // reads see a consistent rule set throughout.
    let backend = AddressProbe::new(b"x", vec![test_root("target:///r/")]);
    let stack = Arc::new(empty_alias_stack(backend).await);

    let mut handles = Vec::new();
    for index in 0..16 {
        let stack = Arc::clone(&stack);
        handles.push(tokio::spawn(async move {
            let from = format!("a{index}:///");
            stack
                .root()
                .add_connection(
                    alias_request(
                        "wrapper",
                        Some(&format!("id{index}")),
                        &from,
                        "target:///r/",
                    ),
                    None,
                )
                .await
                .unwrap();
        }));
    }
    // Concurrent readers exercise the RwLock read path against live writers.
    for _ in 0..16 {
        let stack = Arc::clone(&stack);
        handles.push(tokio::spawn(async move {
            let _ = stack
                .root()
                .list_connections(&ovstorage::Extensions::new(), None)
                .await
                .unwrap();
            let _ = stack
                .root()
                .list_address_roots(&ovstorage::Extensions::new(), None)
                .await
                .unwrap();
        }));
    }
    for handle in handles {
        handle.await.unwrap();
    }

    // Every distinct add survived (no lost update).
    let listed = stack
        .root()
        .list_connections(&ovstorage::Extensions::new(), None)
        .await
        .unwrap()
        .0
        .connections;
    assert_eq!(listed.len(), 16);
    let ids: std::collections::HashSet<String> = listed.iter().map(|c| c.id.0.clone()).collect();
    for index in 0..16 {
        assert!(ids.contains(&format!("id{index}")), "id{index} present");
    }
    // And each rewrites correctly.
    let info = stat_addr(&stack, "a7:///obj").await.unwrap();
    assert_eq!(info.address.as_str(), "a7:///obj");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn alias_concurrent_add_remove_are_consistent() {
    // The harder mutation mix: 8 removes of pre-seeded ids interleaved with 8
    // adds of fresh ids, plus concurrent reads. The symmetric
    // read-modify-write-under-write-guard must keep the swap atomic and the
    // reverse map coherent — no lost update, no surviving removed rule, no
    // deadlock — and the final set must be exactly the added ids.
    let backend = AddressProbe::new(b"x", vec![test_root("target:///r/")]);
    let stack = Arc::new(empty_alias_stack(backend.clone()).await);

    // Pre-seed ids old0..old7 so the removers have live rules to race against.
    for index in 0..8 {
        stack
            .root()
            .add_connection(
                alias_request(
                    "wrapper",
                    Some(&format!("old{index}")),
                    &format!("a{index}:///"),
                    "target:///r/",
                ),
                None,
            )
            .await
            .unwrap();
    }

    let mut handles = Vec::new();
    // 8 removers drop the seeded ids.
    for index in 0..8 {
        let stack = Arc::clone(&stack);
        handles.push(tokio::spawn(async move {
            stack
                .root()
                .remove_connection(
                    connection_key("wrapper", &ConnectionId(format!("old{index}"))),
                    None,
                )
                .await
                .unwrap();
        }));
    }
    // 8 adders install disjoint fresh ids on disjoint prefixes.
    for index in 0..8 {
        let stack = Arc::clone(&stack);
        handles.push(tokio::spawn(async move {
            stack
                .root()
                .add_connection(
                    alias_request(
                        "wrapper",
                        Some(&format!("new{index}")),
                        &format!("b{index}:///"),
                        "target:///r/",
                    ),
                    None,
                )
                .await
                .unwrap();
        }));
    }
    // Concurrent readers exercise the read path against the mutation mix.
    for _ in 0..8 {
        let stack = Arc::clone(&stack);
        handles.push(tokio::spawn(async move {
            let _ = stack
                .root()
                .list_connections(&ovstorage::Extensions::new(), None)
                .await
                .unwrap();
            let _ = stack
                .root()
                .list_address_roots(&ovstorage::Extensions::new(), None)
                .await
                .unwrap();
        }));
    }
    for handle in handles {
        handle.await.unwrap();
    }

    // Final set: exactly the 8 added ids; every removed id is gone.
    let listed = stack
        .root()
        .list_connections(&ovstorage::Extensions::new(), None)
        .await
        .unwrap()
        .0
        .connections;
    let ids: std::collections::HashSet<String> = listed.iter().map(|c| c.id.0.clone()).collect();
    assert_eq!(listed.len(), 8, "8 added, 8 removed: {ids:?}");
    for index in 0..8 {
        assert!(ids.contains(&format!("new{index}")), "new{index} present");
        assert!(!ids.contains(&format!("old{index}")), "old{index} removed");
    }
    // Reverse-map coherence survived the churn: a fresh alias still rewrites and
    // projects back into its own space.
    let info = stat_addr(&stack, "b3:///obj").await.unwrap();
    assert_eq!(backend.last_received().as_str(), "target:///r/obj");
    assert_eq!(info.address.as_str(), "b3:///obj");
}

#[tokio::test]
async fn alias_update_connection_attributes_patches_and_emits() {
    // update_connection_attributes patches presentation on an owned alias row
    // and emits a connection Updated.
    let backend = AddressProbe::new(b"x", vec![test_root("target:///r/")]);
    let stack = empty_alias_stack(backend).await;

    let connection = stack
        .root()
        .add_connection(
            alias_request("wrapper", Some("a"), "alias:///v/", "target:///r/"),
            None,
        )
        .await
        .unwrap();

    let (_snapshot, stream) = stack
        .root()
        .list_connections(&ovstorage::Extensions::new(), None)
        .await
        .unwrap();
    let mut stream = stream.expect("connection update stream");

    let patch = ovstorage::AttributePatch {
        display_name: Some("Renamed".to_string()),
        ..Default::default()
    };
    let updated = stack
        .root()
        .update_connection_attributes(
            Request::new(ovstorage::UpdateConnectionAttributesRequest {
                key: ConnectionKey {
                    target: "wrapper".to_string(),
                    id: connection.id.clone(),
                },
                patch,
            }),
            None,
        )
        .await
        .unwrap();
    assert_eq!(updated.display_name, "Renamed");

    let change = tokio::time::timeout(std::time::Duration::from_secs(5), stream.next())
        .await
        .expect("a connection change is emitted")
        .expect("stream is not terminated")
        .unwrap();
    match change {
        ConnectionChange::Updated(connection) => assert_eq!(connection.display_name, "Renamed"),
        other => panic!("expected Updated, got {other:?}"),
    }
}

#[tokio::test]
async fn alias_config_replay_through_add_connection_matches_construction() {
    // The end-state config path (`[[connections]] target = "alias"` replayed
    // via the StackBuilder's `.connection()`) yields the same resolution as a
    // construction-time `aliases` fragment. Both run through the same wrapper.
    let backend = AddressProbe::new(b"x", vec![test_root("target:///r/")]);
    let mut wrapper_spec = LayerSpec::wrapper("wrapper", ALIAS_KIND, "backend");
    wrapper_spec.config = LayerConfig::new();
    let stack = Stack::builder("wrapper")
        .wrapper_factory(Arc::new(AliasWrapperFactory::default()))
        .backend_factory(Arc::new(SharedBackendFactory {
            backend: backend.clone(),
        }))
        .layer(wrapper_spec)
        .layer(LayerSpec::backend("backend", PROBE_KIND))
        .connection(alias_request("wrapper", Some("cfg"), "alias:///v/", "target:///r/").input)
        .build()
        .await
        .unwrap();

    // The replayed connection resolves at dispatch exactly like a config rule.
    let info = stat_addr(&stack, "alias:///v/obj").await.unwrap();
    assert_eq!(backend.last_received().as_str(), "target:///r/obj");
    assert_eq!(info.address.as_str(), "alias:///v/obj");
    let listed = stack
        .root()
        .list_connections(&ovstorage::Extensions::new(), None)
        .await
        .unwrap()
        .0
        .connections;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, ConnectionId("cfg".to_string()));
    assert!(matches!(listed[0].source, ConnectionSource::Runtime { .. }));
}

// ---------------------------------------------------------------------------
// alias-auth delegation
// ---------------------------------------------------------------------------

/// The backend layer's INSTANCE NAME — deliberately different from its
/// descriptor kind (`PROBE_KIND`), so the delegation tests prove connection ops
/// route to the owning layer's name, not its kind.
const AUTH_PROBE_NAME: &str = "backend";

/// What the probe's `authenticate_connection` emits after the initial
/// `Progress`: a re-projectable `Succeeded`, or a `Failed` carrying an
/// `ErrorContext::Auth { connection_id }` naming the physical backend (so the
/// failure-path re-projection is observable).
#[derive(Clone)]
enum AuthOutcome {
    Succeeded,
    FailedWithBackendId(String),
}

/// A connection-owning backend for the alias-auth delegation tests:
/// advertises `roots` (with owning connection ids), STRICTLY enforces that each
/// auth op is addressed to its own instance name (proving name-not-kind
/// routing), records the received key + credential bundle, and answers with a
/// scripted outcome + backend `Connection` carrying PHYSICAL addresses — so the
/// wrapper's re-projection back to alias space is observable.
struct AuthProbe {
    roots: Vec<RootInfo>,
    connection: Connection,
    outcome: AuthOutcome,
    auth_keys: Mutex<Vec<ConnectionKey>>,
    credential_keys: Mutex<Vec<ConnectionKey>>,
    received_credentials: Mutex<Vec<SecretBundle>>,
    /// When set, `update_connection_credentials` fails with an
    /// `ErrorContext::Auth { connection_id }` naming this physical backend id +
    /// a physical-URL message — so the alias's error re-projection is testable.
    cred_update_error: Option<String>,
    /// When set, `authenticate_connection` returns an IMMEDIATE (pre-stream)
    /// `Err` with a physical-URL message + `ErrorContext::Auth { connection_id }`
    /// naming this backend id — so the pre-stream error re-projection is testable.
    auth_immediate_error: Option<String>,
}

impl AuthProbe {
    fn new(roots: Vec<RootInfo>, connection: Connection) -> Arc<Self> {
        Self::with_outcome(roots, connection, AuthOutcome::Succeeded)
    }

    fn with_outcome(
        roots: Vec<RootInfo>,
        connection: Connection,
        outcome: AuthOutcome,
    ) -> Arc<Self> {
        Arc::new(Self {
            roots,
            connection,
            outcome,
            auth_keys: Mutex::new(Vec::new()),
            credential_keys: Mutex::new(Vec::new()),
            received_credentials: Mutex::new(Vec::new()),
            cred_update_error: None,
            auth_immediate_error: None,
        })
    }

    fn with_auth_immediate_error(
        roots: Vec<RootInfo>,
        connection: Connection,
        backend_id: &str,
    ) -> Arc<Self> {
        Arc::new(Self {
            roots,
            connection,
            outcome: AuthOutcome::Succeeded,
            auth_keys: Mutex::new(Vec::new()),
            credential_keys: Mutex::new(Vec::new()),
            received_credentials: Mutex::new(Vec::new()),
            cred_update_error: None,
            auth_immediate_error: Some(backend_id.to_string()),
        })
    }

    fn with_cred_update_error(
        roots: Vec<RootInfo>,
        connection: Connection,
        backend_id: &str,
    ) -> Arc<Self> {
        Arc::new(Self {
            roots,
            connection,
            outcome: AuthOutcome::Succeeded,
            auth_keys: Mutex::new(Vec::new()),
            credential_keys: Mutex::new(Vec::new()),
            received_credentials: Mutex::new(Vec::new()),
            cred_update_error: Some(backend_id.to_string()),
            auth_immediate_error: None,
        })
    }
}

#[async_trait]
impl Layer for AuthProbe {
    fn name(&self) -> &str {
        AUTH_PROBE_NAME
    }

    fn descriptor(&self) -> LayerKindDescriptor {
        backend_descriptor(PROBE_KIND)
    }

    async fn root_info_for(
        &self,
        url: &Url,
        _cx: &ovstorage::Extensions,
        _cancel: Option<ovstorage::CancellationToken>,
    ) -> Result<RootInfo> {
        self.roots
            .iter()
            .filter(|root| ovstorage::address::is_ancestor_or_self(&root.root, url))
            .max_by_key(|root| root.root.as_str().len())
            .cloned()
            .ok_or_else(|| ovstorage::Error::new(ErrorCode::NoRoute, "no route matches address"))
    }

    async fn authenticate_connection(
        &self,
        request: Request<AuthenticateRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<AuthEventStream> {
        // Strict: connection ops MUST be addressed to this layer's instance
        // name, never its kind — the property alias-auth delegation must hold.
        assert_eq!(
            request.input.key.target, AUTH_PROBE_NAME,
            "auth op must route to the owning layer instance name, not its kind"
        );
        self.auth_keys.lock().unwrap().push(request.input.key);
        if let Some(backend_id) = &self.auth_immediate_error {
            // An immediate (pre-stream) failure carrying backend identity.
            return Err(ovstorage::Error::new(
                ErrorCode::AuthRequired,
                "interactive auth to s3://private-bucket/tenant unavailable",
            )
            .with_context(ovstorage::ErrorContext::Auth {
                connection_id: ConnectionId(backend_id.clone()),
                reason: None,
                expired_at: None,
            }));
        }
        let terminal = match &self.outcome {
            AuthOutcome::Succeeded => AuthEvent::Succeeded {
                connection: Box::new(self.connection.clone()),
                credentials: Some(SecretBundle::default()),
            },
            AuthOutcome::FailedWithBackendId(id) => AuthEvent::Failed {
                // The message embeds a physical backend URL (and the context a
                // physical connection id) — both must be scrubbed on the way
                // out so the alias caller never learns the physical namespace.
                error: ovstorage::Error::new(
                    ErrorCode::AuthRequired,
                    "auth to s3://private-bucket/tenant/secret failed",
                )
                .with_context(ovstorage::ErrorContext::Auth {
                    connection_id: ConnectionId(id.clone()),
                    reason: Some("token for s3://private-bucket expired".to_string()),
                    expired_at: None,
                }),
            },
        };
        let events = vec![
            Ok(AuthEvent::Progress {
                message: "backend flow".to_string(),
            }),
            Ok(terminal),
        ];
        Ok(Box::new(events.into_iter()))
    }

    async fn update_connection_credentials(
        &self,
        request: Request<UpdateConnectionCredentialsRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<Connection> {
        assert_eq!(
            request.input.key.target, AUTH_PROBE_NAME,
            "credential update must route to the owning layer instance name, not its kind"
        );
        self.credential_keys.lock().unwrap().push(request.input.key);
        self.received_credentials
            .lock()
            .unwrap()
            .push(request.input.credentials);
        if let Some(backend_id) = &self.cred_update_error {
            return Err(ovstorage::Error::new(
                ErrorCode::AuthRequired,
                "credential update to s3://private-bucket/tenant failed",
            )
            .with_context(ovstorage::ErrorContext::Auth {
                connection_id: ConnectionId(backend_id.clone()),
                reason: None,
                expired_at: None,
            }));
        }
        Ok(self.connection.clone())
    }
}

/// A `test_root` owned by `connection_id` (the delegation target shape).
fn owned_root(prefix: &str, connection_id: &str) -> RootInfo {
    let mut root = test_root(prefix);
    root.connection_id = Some(ConnectionId(connection_id.to_string()));
    // The owning Layer instance name a delegated connection op routes by — the
    // probe's own name, deliberately different from its descriptor kind.
    root.owning_target = Some(AUTH_PROBE_NAME.to_string());
    root.source = RouteSource::ConnectionContributed {
        connection_id: ConnectionId(connection_id.to_string()),
    };
    root
}

/// The scripted backend connection the probe's auth ops return: physical
/// addresses (one under the delegation terminal, one outside it) + live auth
/// facts the projection must carry.
fn backend_connection(id: &str) -> Connection {
    Connection {
        id: ConnectionId(id.to_string()),
        backend_kind: PROBE_KIND.to_string(),
        display_name: "physical backend".to_string(),
        source: ConnectionSource::Runtime { persisted: true },
        capabilities: Capabilities {
            supports_write: true,
            ..Capabilities::empty()
        },
        current_addresses: vec![
            Url::parse("target:///r/").unwrap(),
            Url::parse("elsewhere:///other/").unwrap(),
        ],
        auth_state: ConnectionAuthState::Authenticated {
            last_authenticated_at: SystemTime::UNIX_EPOCH,
            expires_at: None,
        },
        last_probed: Some(SystemTime::UNIX_EPOCH),
        user_metadata: UserMetadata::default(),
    }
}

fn auth_request_for(target: &str, id: &ConnectionId) -> Request<AuthenticateRequest> {
    Request::new(AuthenticateRequest {
        key: ConnectionKey {
            target: target.to_string(),
            id: id.clone(),
        },
        capability: InteractiveAuthCapability::None,
        auto_open_browser: false,
    })
}

#[tokio::test]
async fn alias_auth_delegates_to_backend_connection_and_reprojects_succeeded() {
    // authenticate on the ALIAS row forwards to the connection owning the
    // chain terminal, and `Succeeded.connection` comes back wearing the alias's
    // user-facing identity with the backend's live auth facts.
    let backend = AuthProbe::new(
        vec![owned_root("target:///r/", "backend-conn")],
        backend_connection("backend-conn"),
    );
    let stack = empty_alias_stack(backend.clone()).await;
    let alias = stack
        .root()
        .add_connection(
            alias_request("wrapper", None, "alias:///v/", "target:///r/"),
            None,
        )
        .await
        .unwrap();

    let events: Vec<_> = stack
        .root()
        .authenticate_connection(auth_request_for("wrapper", &alias.id), None)
        .await
        .unwrap()
        .collect::<Result<Vec<_>>>()
        .unwrap();

    // The backend saw ITS key: target = the owning layer's kind name, id = the
    // owning connection — not the alias identity.
    assert_eq!(
        backend.auth_keys.lock().unwrap().as_slice(),
        &[ConnectionKey {
            target: AUTH_PROBE_NAME.to_string(),
            id: ConnectionId("backend-conn".to_string()),
        }]
    );

    // Interactive events pass through unchanged; Succeeded re-projects.
    assert_eq!(events.len(), 2);
    assert!(matches!(&events[0], AuthEvent::Progress { message } if message == "backend flow"));
    let AuthEvent::Succeeded {
        connection,
        credentials,
    } = &events[1]
    else {
        panic!("expected Succeeded, got {:?}", events[1]);
    };
    // Alias identity preserved…
    assert_eq!(connection.id, alias.id);
    assert_eq!(connection.backend_kind, ALIAS_KIND);
    assert_eq!(
        connection
            .user_metadata
            .get(ALIAS_TO_KEY)
            .map(String::as_str),
        Some("target:///r/")
    );
    // …addresses re-projected into alias space (the physical address under the
    // terminal maps back; the out-of-window address is dropped, not leaked)…
    assert_eq!(
        connection.current_addresses,
        vec![Url::parse("alias:///v/").unwrap()]
    );
    // …and the backend's live auth facts carried over.
    assert!(matches!(
        connection.auth_state,
        ConnectionAuthState::Authenticated { .. }
    ));
    assert!(
        connection.capabilities.supports_write,
        "the backend's live capabilities carry over"
    );
    // Credentials are SCRUBBED, not forwarded: a delegated backend commits its
    // own bundle through its connection lifecycle, and the alias must not let a
    // raw bundle be re-applied by the (re-resolvable) alias key.
    assert!(
        credentials.is_none(),
        "delegated Succeeded credentials must be scrubbed"
    );
}

#[tokio::test]
async fn alias_update_credentials_delegates_and_reprojects() {
    let backend = AuthProbe::new(
        vec![owned_root("target:///r/", "backend-conn")],
        backend_connection("backend-conn"),
    );
    let stack = empty_alias_stack(backend.clone()).await;
    let alias = stack
        .root()
        .add_connection(
            alias_request("wrapper", None, "alias:///v/", "target:///r/"),
            None,
        )
        .await
        .unwrap();

    // A distinctive, non-empty credential bundle so the test proves the caller's
    // actual credentials reach the backend unaltered (not discarded/replaced).
    let mut fields = HashMap::new();
    fields.insert(
        "token".to_string(),
        ovstorage::SecretValue::Bytes(ovstorage::SecretBytes(b"caller-secret-42".to_vec())),
    );
    let sent = SecretBundle { fields };

    let updated = stack
        .root()
        .update_connection_credentials(
            Request::new(UpdateConnectionCredentialsRequest {
                key: ConnectionKey {
                    target: "wrapper".to_string(),
                    id: alias.id.clone(),
                },
                credentials: sent.clone(),
            }),
            None,
        )
        .await
        .unwrap();

    assert_eq!(
        backend.credential_keys.lock().unwrap().as_slice(),
        &[ConnectionKey {
            target: AUTH_PROBE_NAME.to_string(),
            id: ConnectionId("backend-conn".to_string()),
        }]
    );
    // The backend received the caller's exact bundle — the alias forwards
    // credentials unaltered.
    assert_eq!(
        backend.received_credentials.lock().unwrap().as_slice(),
        &[sent]
    );
    assert_eq!(updated.id, alias.id);
    assert_eq!(updated.backend_kind, ALIAS_KIND);
    assert_eq!(
        updated.current_addresses,
        vec![Url::parse("alias:///v/").unwrap()]
    );
    assert!(matches!(
        updated.auth_state,
        ConnectionAuthState::Authenticated { .. }
    ));
}

#[tokio::test]
async fn alias_auth_delegation_walks_multi_hop_chain() {
    // alias:///a/ → alias:///b/ → target:///r/ — the delegation walks the full
    // bounded chain and the projection replays BOTH hops back.
    let backend = AuthProbe::new(
        vec![owned_root("target:///r/", "backend-conn")],
        backend_connection("backend-conn"),
    );
    let stack = empty_alias_stack(backend.clone()).await;
    let outer = stack
        .root()
        .add_connection(
            alias_request("wrapper", None, "alias:///a/", "alias:///b/"),
            None,
        )
        .await
        .unwrap();
    stack
        .root()
        .add_connection(
            alias_request("wrapper", None, "alias:///b/", "target:///r/"),
            None,
        )
        .await
        .unwrap();

    let events: Vec<_> = stack
        .root()
        .authenticate_connection(auth_request_for("wrapper", &outer.id), None)
        .await
        .unwrap()
        .collect::<Result<Vec<_>>>()
        .unwrap();
    assert_eq!(
        backend.auth_keys.lock().unwrap().as_slice(),
        &[ConnectionKey {
            target: AUTH_PROBE_NAME.to_string(),
            id: ConnectionId("backend-conn".to_string()),
        }]
    );
    let AuthEvent::Succeeded { connection, .. } = &events[1] else {
        panic!("expected Succeeded");
    };
    assert_eq!(connection.id, outer.id);
    assert_eq!(
        connection.current_addresses,
        vec![Url::parse("alias:///a/").unwrap()],
        "the physical address maps back through BOTH hops to the outer alias"
    );
}

#[tokio::test]
async fn alias_auth_edge_cases_are_typed() {
    let backend = AuthProbe::new(
        vec![
            owned_root("target:///r/", "backend-conn"),
            // A static route with NO owning connection.
            test_root("static:///s/"),
        ],
        backend_connection("backend-conn"),
    );
    let stack = empty_alias_stack(backend.clone()).await;

    // Dangling: the alias target has no serving route at all.
    let dangling = stack
        .root()
        .add_connection(
            alias_request("wrapper", None, "alias:///dangling/", "nowhere:///x/"),
            None,
        )
        .await
        .unwrap();
    let err = stack
        .root()
        .authenticate_connection(auth_request_for("wrapper", &dangling.id), None)
        .await
        .err()
        .expect("delegation must fail typed");
    assert_eq!(err.code(), ErrorCode::NoRoute);
    assert!(err.message().contains("cannot delegate auth"), "{err}");

    // Connectionless: the terminal is served by a static route.
    let static_alias = stack
        .root()
        .add_connection(
            alias_request("wrapper", None, "alias:///static/", "static:///s/"),
            None,
        )
        .await
        .unwrap();
    let err = stack
        .root()
        .authenticate_connection(auth_request_for("wrapper", &static_alias.id), None)
        .await
        .err()
        .expect("delegation must fail typed");
    assert_eq!(err.code(), ErrorCode::PreconditionFailed);
    assert!(err.message().contains("no owning connection"), "{err}");

    // Unknown id on the alias target.
    let err = stack
        .root()
        .authenticate_connection(
            auth_request_for("wrapper", &ConnectionId("no-such-row".to_string())),
            None,
        )
        .await
        .err()
        .expect("delegation must fail typed");
    assert_eq!(err.code(), ErrorCode::NotFound);

    // A visibility-override row stays credentialless.
    let vis = stack
        .root()
        .add_connection(
            visibility_request("wrapper", "target:///r/", "hidden"),
            None,
        )
        .await
        .unwrap();
    let err = stack
        .root()
        .authenticate_connection(auth_request_for("wrapper", &vis.id), None)
        .await
        .err()
        .expect("delegation must fail typed");
    assert_eq!(err.code(), ErrorCode::Unsupported);
    assert!(err.message().contains("credentialless"), "{err}");

    // No delegated call ever reached the backend.
    assert!(backend.auth_keys.lock().unwrap().is_empty());
}

#[tokio::test]
async fn alias_auth_non_self_target_passes_through_untouched() {
    // A backend-targeted auth op flows through the alias wrapper unchanged —
    // delegation only claims keys addressed to the wrapper itself.
    let backend = AuthProbe::new(
        vec![owned_root("target:///r/", "backend-conn")],
        backend_connection("backend-conn"),
    );
    let stack = empty_alias_stack(backend.clone()).await;
    stack
        .root()
        .add_connection(
            alias_request("wrapper", None, "alias:///v/", "target:///r/"),
            None,
        )
        .await
        .unwrap();

    // Target the backend by its own instance name (not the alias's "wrapper"),
    // so the alias forwards it through untouched.
    let events: Vec<_> = stack
        .root()
        .authenticate_connection(
            auth_request_for(AUTH_PROBE_NAME, &ConnectionId("backend-conn".to_string())),
            None,
        )
        .await
        .unwrap()
        .collect::<Result<Vec<_>>>()
        .unwrap();
    assert_eq!(
        backend.auth_keys.lock().unwrap().as_slice(),
        &[ConnectionKey {
            target: AUTH_PROBE_NAME.to_string(),
            id: ConnectionId("backend-conn".to_string()),
        }]
    );
    // No re-projection: the backend's own identity comes back verbatim.
    let AuthEvent::Succeeded { connection, .. } = &events[1] else {
        panic!("expected Succeeded");
    };
    assert_eq!(connection.id, ConnectionId("backend-conn".to_string()));
    assert_eq!(connection.backend_kind, PROBE_KIND);
    assert_eq!(
        connection.current_addresses,
        vec![
            Url::parse("target:///r/").unwrap(),
            Url::parse("elsewhere:///other/").unwrap(),
        ]
    );
}

#[tokio::test]
async fn alias_auth_reprojects_failed_event_backend_id_to_alias_id() {
    // The FAILURE path must not leak the backend identity
    // the success path re-projects away. A backend `Failed` event carrying an
    // `ErrorContext::Auth { connection_id: <backend> }` re-projects to the alias
    // id, so the caller correlates the failure with the alias row it
    // authenticated and never sees the physical backend connection id.
    let backend = AuthProbe::with_outcome(
        vec![owned_root("target:///r/", "backend-conn")],
        backend_connection("backend-conn"),
        AuthOutcome::FailedWithBackendId("backend-conn".to_string()),
    );
    let stack = empty_alias_stack(backend.clone()).await;
    let alias = stack
        .root()
        .add_connection(
            alias_request("wrapper", None, "alias:///v/", "target:///r/"),
            None,
        )
        .await
        .unwrap();

    let events: Vec<_> = stack
        .root()
        .authenticate_connection(auth_request_for("wrapper", &alias.id), None)
        .await
        .unwrap()
        .collect::<Result<Vec<_>>>()
        .unwrap();

    let AuthEvent::Failed { error } = &events[1] else {
        panic!("expected Failed, got {:?}", events[1]);
    };
    // The error's structured Auth context now names the ALIAS row, not the
    // physical backend connection, and drops the free-text `reason`.
    match error.context() {
        Some(ovstorage::ErrorContext::Auth {
            connection_id,
            reason,
            ..
        }) => {
            assert_eq!(connection_id, &alias.id);
            assert_ne!(connection_id, &ConnectionId("backend-conn".to_string()));
            assert!(reason.is_none(), "free-text reason must be dropped");
        }
        other => panic!("expected re-projected Auth context, got {other:?}"),
    }
    // The free-text message is REPLACED, not merely re-redacted (redaction keeps
    // a URL's scheme/host/path): no physical namespace leaks to the caller.
    assert!(
        !error.message().contains("private-bucket"),
        "physical backend URL leaked in error text: {}",
        error.message()
    );
    assert!(
        !error.message().contains("s3://"),
        "physical backend URL leaked in error text: {}",
        error.message()
    );
    // …while still naming the alias the caller authenticated.
    assert!(error.message().contains("alias:///v/"));
    assert_eq!(error.code(), ErrorCode::AuthRequired);
}

/// A host-side leaf that simulates a loaded composite plugin (a wrapper/router
/// `.so`): its root layer name (`wrap`) differs from the connection-owning
/// backend name (`back`) it reports through `owned_targets` across the ABI.
struct CompositeLeafProbe;

#[async_trait]
impl Layer for CompositeLeafProbe {
    fn name(&self) -> &str {
        "wrap"
    }

    fn descriptor(&self) -> LayerKindDescriptor {
        backend_descriptor("mini")
    }

    async fn root_info_for(
        &self,
        url: &Url,
        _cx: &ovstorage::Extensions,
        _cancel: Option<ovstorage::CancellationToken>,
    ) -> Result<RootInfo> {
        if ovstorage::address::is_ancestor_or_self(&Url::parse("target:///r/").unwrap(), url) {
            Ok(owned_root("target:///r/", "back-conn"))
        } else {
            Err(ovstorage::Error::new(ErrorCode::NoRoute, "no route"))
        }
    }

    fn owned_targets(&self) -> Vec<String> {
        vec!["back".to_string()]
    }
}

#[tokio::test]
async fn owning_target_for_uses_owned_target_not_root_name_for_composite_leaf() {
    // Regression: a loaded composite plugin has no host-side `inner_layer`, so
    // ownership must resolve from `owned_targets` (which crosses the ABI), not
    // the loaded layer's own root name. Before the fix this returned
    // `Some("wrap")`; connection ops would then miss the owning backend.
    let leaf = CompositeLeafProbe;
    assert_eq!(
        leaf.owning_target_for(
            &Url::parse("target:///r/obj").unwrap(),
            &ovstorage::Extensions::new(),
            None
        )
        .await,
        Some("back".to_string())
    );
    // A url it does not serve has no owning target.
    assert_eq!(
        leaf.owning_target_for(
            &Url::parse("elsewhere:///y").unwrap(),
            &ovstorage::Extensions::new(),
            None
        )
        .await,
        None
    );
}

#[tokio::test]
async fn alias_update_credentials_error_reprojects_backend_identity() {
    // A backend credential-update failure carrying an
    // `ErrorContext::Auth { connection_id: backend }` + a physical-URL message
    // must not leak either to the alias caller: the id re-projects to the alias
    // id and the message is replaced.
    let backend = AuthProbe::with_cred_update_error(
        vec![owned_root("target:///r/", "backend-conn")],
        backend_connection("backend-conn"),
        "backend-conn",
    );
    let stack = empty_alias_stack(backend.clone()).await;
    let alias = stack
        .root()
        .add_connection(
            alias_request("wrapper", None, "alias:///v/", "target:///r/"),
            None,
        )
        .await
        .unwrap();

    let err = stack
        .root()
        .update_connection_credentials(
            Request::new(UpdateConnectionCredentialsRequest {
                key: ConnectionKey {
                    target: "wrapper".to_string(),
                    id: alias.id.clone(),
                },
                credentials: SecretBundle::default(),
            }),
            None,
        )
        .await
        .expect_err("delegated update must surface the backend failure");

    match err.context() {
        Some(ovstorage::ErrorContext::Auth { connection_id, .. }) => {
            assert_eq!(connection_id, &alias.id);
            assert_ne!(connection_id, &ConnectionId("backend-conn".to_string()));
        }
        other => panic!("expected re-projected Auth context, got {other:?}"),
    }
    assert!(
        !err.message().contains("private-bucket"),
        "{}",
        err.message()
    );
    assert!(!err.message().contains("s3://"), "{}", err.message());
    assert!(err.message().contains("alias:///v/"));
}

/// Compose two AliasWrapper instances (`outer` over `inner`) above the shared
/// backend, so stacked-alias delegation can be exercised end to end.
async fn nested_alias_stack(backend: LayerHandle) -> Stack {
    Stack::builder("outer")
        .wrapper_factory(Arc::new(AliasWrapperFactory::default()))
        .backend_factory(Arc::new(SharedBackendFactory { backend }))
        .layer(LayerSpec::wrapper("outer", ALIAS_KIND, "inner"))
        .layer(LayerSpec::wrapper("inner", ALIAS_KIND, "backend"))
        .layer(LayerSpec::backend("backend", PROBE_KIND))
        .build()
        .await
        .unwrap()
}

#[tokio::test]
async fn alias_auth_delegation_composes_across_stacked_aliases() {
    // outer:///v/ -> inner:///m/ (outer alias) -> target:///r/ (inner alias) ->
    // physical backend. Authenticating the OUTER alias row must reach the
    // physical connection THROUGH both wrappers, and re-project Succeeded to the
    // outer alias identity — the composition data dispatch already has.
    let backend = AuthProbe::new(
        vec![owned_root("target:///r/", "backend-conn")],
        backend_connection("backend-conn"),
    );
    let stack = nested_alias_stack(backend.clone()).await;
    stack
        .root()
        .add_connection(
            alias_request("inner", None, "inner:///m/", "target:///r/"),
            None,
        )
        .await
        .unwrap();
    let outer = stack
        .root()
        .add_connection(
            alias_request("outer", None, "outer:///v/", "inner:///m/"),
            None,
        )
        .await
        .unwrap();

    let events: Vec<_> = stack
        .root()
        .authenticate_connection(auth_request_for("outer", &outer.id), None)
        .await
        .unwrap()
        .collect::<Result<Vec<_>>>()
        .unwrap();

    // The flow reached the physical connection through both wrappers.
    assert_eq!(
        backend.auth_keys.lock().unwrap().as_slice(),
        &[ConnectionKey {
            target: AUTH_PROBE_NAME.to_string(),
            id: ConnectionId("backend-conn".to_string()),
        }]
    );
    // Succeeded re-projects to the OUTER alias identity (not the inner alias or
    // the physical backend), with credentials scrubbed.
    let AuthEvent::Succeeded {
        connection,
        credentials,
    } = &events[1]
    else {
        panic!("expected Succeeded, got {:?}", events[1]);
    };
    assert_eq!(connection.id, outer.id);
    assert_eq!(connection.backend_kind, ALIAS_KIND);
    assert!(credentials.is_none());
    // Addresses that cannot project into the outer alias namespace are dropped
    // (leak-proof), leaving the outer alias's own `from`.
    assert_eq!(
        connection.current_addresses,
        vec![Url::parse("outer:///v/").unwrap()]
    );
}

#[tokio::test]
async fn alias_authenticate_immediate_error_reprojects_backend_identity() {
    // A backend `authenticate_connection` that fails IMMEDIATELY (before the
    // stream) carrying a physical-URL message + `ErrorContext::Auth` must not
    // leak either to the alias caller.
    let backend = AuthProbe::with_auth_immediate_error(
        vec![owned_root("target:///r/", "backend-conn")],
        backend_connection("backend-conn"),
        "backend-conn",
    );
    let stack = empty_alias_stack(backend.clone()).await;
    let alias = stack
        .root()
        .add_connection(
            alias_request("wrapper", None, "alias:///v/", "target:///r/"),
            None,
        )
        .await
        .unwrap();

    let err = stack
        .root()
        .authenticate_connection(auth_request_for("wrapper", &alias.id), None)
        .await
        .err()
        .expect("immediate backend failure must surface");
    match err.context() {
        Some(ovstorage::ErrorContext::Auth { connection_id, .. }) => {
            assert_eq!(connection_id, &alias.id);
            assert_ne!(connection_id, &ConnectionId("backend-conn".to_string()));
        }
        other => panic!("expected re-projected Auth context, got {other:?}"),
    }
    assert!(
        !err.message().contains("private-bucket"),
        "{}",
        err.message()
    );
    assert!(!err.message().contains("s3://"), "{}", err.message());
    assert!(err.message().contains("alias:///v/"));
}

#[tokio::test]
async fn alias_delegation_reprojects_awaiting_auth_attempt_error() {
    // A delegated Succeeded whose connection is parked `AwaitingAuth` with a
    // recorded attempt embedding a physical URL + backend `ErrorContext::Auth`
    // must re-project the attempt's error — the connection view, like the event
    // stream, never surfaces backend identity.
    let mut parked = backend_connection("backend-conn");
    parked.auth_state = ConnectionAuthState::AwaitingAuth {
        reason: ovstorage::AuthReason::ManuallyRequested,
        last_attempt: Some(ovstorage::AuthAttempt {
            at: SystemTime::UNIX_EPOCH,
            error: Some(
                ovstorage::Error::new(
                    ErrorCode::AuthRequired,
                    "auth to s3://private-bucket/tenant failed",
                )
                .with_context(ovstorage::ErrorContext::Auth {
                    connection_id: ConnectionId("backend-conn".to_string()),
                    reason: None,
                    expired_at: None,
                }),
            ),
        }),
    };
    let backend = AuthProbe::new(vec![owned_root("target:///r/", "backend-conn")], parked);
    let stack = empty_alias_stack(backend.clone()).await;
    let alias = stack
        .root()
        .add_connection(
            alias_request("wrapper", None, "alias:///v/", "target:///r/"),
            None,
        )
        .await
        .unwrap();

    let events: Vec<_> = stack
        .root()
        .authenticate_connection(auth_request_for("wrapper", &alias.id), None)
        .await
        .unwrap()
        .collect::<Result<Vec<_>>>()
        .unwrap();
    let AuthEvent::Succeeded { connection, .. } = &events[1] else {
        panic!("expected Succeeded");
    };
    let ConnectionAuthState::AwaitingAuth { last_attempt, .. } = &connection.auth_state else {
        panic!("expected AwaitingAuth, got {:?}", connection.auth_state);
    };
    let attempt_error = last_attempt
        .as_ref()
        .and_then(|attempt| attempt.error.as_ref())
        .expect("recorded attempt error");
    match attempt_error.context() {
        Some(ovstorage::ErrorContext::Auth { connection_id, .. }) => {
            assert_eq!(connection_id, &alias.id);
            assert_ne!(connection_id, &ConnectionId("backend-conn".to_string()));
        }
        other => panic!("expected re-projected Auth context, got {other:?}"),
    }
    assert!(!attempt_error.message().contains("private-bucket"));
    assert!(!attempt_error.message().contains("s3://"));
}
