// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Address-routing primitives shared by the host `Router` and in-tree ABI-v2
//! backend plugins that own multiple connections and route
//! among them.
//!
//! These live in `ovstorage-plugin` — not `ovstorage-layer` — because the
//! longest-prefix lookup needs [`crate::address::relative_suffix`], which is
//! defined here. `ovstorage-plugin` sits below both the host crate and every
//! plugin cdylib and re-exports `ovstorage-layer`, so it is the lowest crate
//! that can host them without inverting the dependency graph.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::address;
use crate::{
    ChecksumSet, Error, ErrorCode, ListPage, ObjectInfo, ObjectKind, Result, RootInfo, Url,
};

// Internal process-monotonic counter minting fresh route/connection ids; an
// atomic counter, not a C ABI symbol.
/// cbindgen:ignore
static FRESH_ID_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Longest-prefix route table shared by the `Router` and connection-owning
/// backend plugins, replacing divergent ad-hoc implementations.
///
/// Selection is **longest prefix wins**; on a genuine overlap (two roots with
/// the same address, e.g. a broker advertising a prefix another connection
/// already serves) the tie-break is **FIFO** — the first-registered root keeps
/// the route and later ones are shadowed (with a `warn`). FIFO falls out of a
/// stable sort by descending prefix length over inputs given in registration
/// order, so `lookup` returns the first (earliest) longest match.
pub struct RouteTable<T> {
    entries: Vec<(RootInfo, T)>,
}

impl<T> RouteTable<T> {
    pub fn empty() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Build from `(root, target)` pairs in registration order.
    pub fn build(items: Vec<(RootInfo, T)>) -> Self {
        // Dedup on the node, not the spelling. An exact-string set does not see
        // that `x` and `x/` are one root, so the collision warning stayed
        // silent for the one shape `lookup` then resolves to a single route.
        //
        // The address is redacted because `node_key` excludes userinfo: two
        // roots differing only by credentials are one node here, so this is the
        // path a credential-bearing root takes on every route-table build.
        // Those two also render to the SAME redacted address, which is why the
        // connection and the layer are named beside it. They do not always
        // disambiguate — a synthesized root carries no connection id — so this
        // identifies the shadowed root as far as the route table knows it,
        // rather than promising an answer.
        let mut seen = std::collections::HashSet::new();
        for (root, _) in &items {
            if !seen.insert(ovstorage_layer::node_key(&root.root)) {
                tracing::warn!(
                    address = %crate::RedactedUrl(&root.root),
                    connection.id = ?root.connection_id,
                    layer.kind = %root.layer_kind,
                    "overlapping address root shadowed; first-registered route wins (FIFO)"
                );
            }
        }
        let mut entries = items;
        // Rank by how specific the root is, not by how many bytes it spells.
        // Byte length made the slashed spelling of a root outrank the slashless
        // spelling of that same root regardless of registration order,
        // inverting the documented FIFO tie-break. `node_rank` is depth then
        // whether the root pins a query — both properties of the node — so two
        // spellings of one root tie and this stable sort keeps the first
        // registration, while a pinned root still outranks its parent.
        //
        // Depth alone would tie a pinned root with its unpinned parent, leaving
        // the pinned root unreachable for the address it publishes.
        entries.sort_by_key(|(root, _)| std::cmp::Reverse(ovstorage_layer::node_rank(&root.root)));
        Self { entries }
    }

    /// Longest matching prefix for `url`, or `None` if nothing routes it.
    pub fn lookup(&self, url: &Url) -> Option<&(RootInfo, T)> {
        self.entries
            .iter()
            .find(|(root, _)| address::relative_suffix(url, &root.root).is_some())
    }

    pub fn roots(&self) -> impl Iterator<Item = &RootInfo> {
        self.entries.iter().map(|(root, _)| root)
    }
}

/// Process-unique identifier with a caller-chosen prefix that mints
/// connection/alias ids that are stable within a run and never collide across
/// concurrent backends.
pub fn fresh_id(prefix: &str) -> String {
    let count = FRESH_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{prefix}-{}-{count}", std::process::id())
}

/// Page a fully-materialized listing using the opaque numeric-offset page token
/// convention shared by every backend that lists eagerly. The token is the
/// next start offset rendered as a decimal string.
pub fn paginate_list_items(
    items: Vec<ObjectInfo>,
    max_results: Option<u32>,
    page_token: Option<String>,
) -> Result<ListPage> {
    let start = match page_token {
        Some(token) => token
            .parse::<usize>()
            .map_err(|_| Error::new(ErrorCode::InvalidArgument, "list page token is not valid"))?,
        None => 0,
    };
    if start > items.len() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "list page token is past the end of the listing",
        ));
    }
    let page_len = match max_results {
        Some(0) => {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "max_results must be greater than zero",
            ));
        }
        Some(value) => value as usize,
        None => items.len().saturating_sub(start),
    };
    let end = start.saturating_add(page_len).min(items.len());
    let next_page_token = (end < items.len()).then(|| end.to_string());
    let items = items.into_iter().skip(start).take(end - start).collect();
    Ok(ListPage {
        items,
        next_page_token,
    })
}

/// On flat backends, fold marker objects into matching inferred-directory
/// peers and tag remaining unknown subdirs as `Inferred`.
///
/// Older plugins may still expose markers as slash-terminated `File` entries;
/// newer plugins use `DirectoryMarker` directly. Concrete directory facts
/// (`Directory` and `DirectoryMarker`) win over an inferred peer at the same
/// address, including recursive listings from backends that return both facts.
/// Recursive flat listings are also closed over inferred ancestor directories
/// after caller-space projection.
///
/// Shared by Stack hosts and ABI-v2 backend plugins whose `Layer::list`
/// follows the host list flow (fold, then
/// [`paginate_list_items`]).
///
/// `normalize_directory_addresses` runs FIRST, because every merge below
/// compares serialized addresses and the compatibility case they exist for is
/// a backend that reports one node two ways — a concrete marker at
/// `s3://b/docs/` beside an inferred directory at `s3://b/docs`. Normalizing
/// afterwards left neither merge able to see the peer, so the page carried two
/// entries for one node with conflicting `kind`, both counted against
/// `max_results`. It only ever adds a slash to a directory kind, so a `File`
/// keyed `docs` still cannot collide with the directory `docs/`, which on a
/// flat store are two different objects.
pub fn fold_markers_and_infer_subdir_kinds(
    listed_prefix: &Url,
    items: Vec<ObjectInfo>,
    has_real_directories: bool,
    recursive: bool,
) -> Vec<ObjectInfo> {
    let items = normalize_directory_addresses(items);
    if has_real_directories {
        return fold_concrete_over_inferred(items);
    }
    let mut marker_entries: std::collections::HashMap<String, ObjectInfo> =
        std::collections::HashMap::new();
    for item in &items {
        if is_flat_marker_entry(item) {
            let mut marker = item.clone();
            marker.kind = ObjectKind::DirectoryMarker;
            marker.size = None;
            marker_entries.insert(marker.address.as_str().to_string(), marker);
        }
    }
    let mut out: Vec<ObjectInfo> = Vec::with_capacity(items.len());
    let mut emitted_markers = std::collections::HashSet::new();
    for mut item in items.into_iter() {
        let address_key = item.address.as_str().to_string();
        if is_flat_marker_entry(&item) {
            if emitted_markers.insert(address_key.clone())
                && let Some(marker) = marker_entries.remove(&address_key)
            {
                out.push(marker);
            }
            continue;
        }
        if is_directory_like(item.kind) {
            if emitted_markers.contains(&address_key) {
                continue;
            }
            if let Some(marker) = marker_entries.remove(&address_key) {
                emitted_markers.insert(address_key);
                out.push(marker);
                continue;
            }
            if item.kind == ObjectKind::Directory {
                item.kind = ObjectKind::DirectoryInferred;
            }
        }
        out.push(item);
    }
    // Marker addresses without a Subdirectory peer become standalone.
    for marker in marker_entries.into_values() {
        out.push(ObjectInfo {
            kind: ObjectKind::DirectoryMarker,
            ..marker
        });
    }
    if recursive {
        out = synthesize_missing_inferred_ancestors(listed_prefix, out);
    }
    fold_concrete_over_inferred(out)
}

/// Give every directory kind a trailing slash, before anything compares two
/// addresses and therefore also on the way out.
///
/// One listing could otherwise return `docs/` for a marker and `docs` for an
/// inferred directory — the same kind of thing, spelled two ways, for no reason
/// a consumer can see, and two entries a merge keyed on the serialized address
/// cannot recognize as one node. This is emission, not identity: the two
/// spellings name one node everywhere they are compared, so a consumer feeding
/// either back reaches the same place. `ObjectKind` remains the directory
/// signal, and a backend reporting a directory without a slash is still
/// reporting one.
///
/// **Add, never remove**, and the asymmetry is load-bearing. A
/// slash-terminated object with a non-zero body is a `File` whose slash is part
/// of its name; stripping it would emit a duplicate of the sibling file `docs`,
/// and a `delete` of the address the caller was handed would destroy the wrong
/// object. So a `File` keeps whatever it has, and only the directory kinds gain
/// one.
fn normalize_directory_addresses(items: Vec<ObjectInfo>) -> Vec<ObjectInfo> {
    items
        .into_iter()
        .map(|mut item| {
            if is_directory_like(item.kind) && !item.address.path().ends_with('/') {
                let path = format!("{}/", item.address.path());
                item.address.set_path(&path);
            }
            item
        })
        .collect()
}

fn fold_concrete_over_inferred(items: Vec<ObjectInfo>) -> Vec<ObjectInfo> {
    let concrete_addresses: std::collections::HashSet<String> = items
        .iter()
        .filter(|item| {
            matches!(
                item.kind,
                ObjectKind::Directory | ObjectKind::DirectoryMarker
            )
        })
        .map(|item| item.address.as_str().to_string())
        .collect();
    items
        .into_iter()
        .filter(|item| {
            item.kind != ObjectKind::DirectoryInferred
                || !concrete_addresses.contains(item.address.as_str())
        })
        .collect()
}

fn synthesize_missing_inferred_ancestors(
    listed_prefix: &Url,
    items: Vec<ObjectInfo>,
) -> Vec<ObjectInfo> {
    let mut known: std::collections::HashSet<String> = items
        .iter()
        .map(|item| item.address.as_str().to_string())
        .collect();
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        if address::relative_suffix(&item.address, listed_prefix).is_some() {
            for ancestor in ancestor_addresses(listed_prefix, &item.address) {
                if known.insert(ancestor.as_str().to_string()) {
                    out.push(inferred_directory_info(ancestor));
                }
            }
        }
        out.push(item);
    }
    out
}

/// The directory addresses strictly between the listed prefix and `address`,
/// outermost first.
///
/// **Built by truncating `address`'s own path, never by re-joining a key.**
/// The listed address is already escaped for the wire, so the escaping is
/// spent: handing a slice of it to [`address::join_relative`], which takes
/// decoded backend bytes, escapes it a second time. A child listed as
/// `s3://b/pub%20x/y.txt` then produced the ancestor `s3://b/pub%2520x/`,
/// naming the key `pub%20x/` rather than `pub x/` — a different directory, and
/// the one a `delete_directory` on the emitted address would destroy.
/// `Url::set_path` leaves a literal `%` alone, which is what makes truncation
/// the right tool here and the wrong one on the emit side.
fn ancestor_addresses(listed_prefix: &Url, address: &Url) -> Vec<Url> {
    let path = address.path();
    // Compare node forms so the boundaries are spelling-independent: the
    // listed prefix written with or without its trailing slash bounds the same
    // set, and an item that is itself a directory does not become its own
    // ancestor.
    let floor = ovstorage_layer::node_path(listed_prefix).len();
    let ceiling = ovstorage_layer::node_path(address).len();
    path.match_indices('/')
        .map(|(index, _)| &path[..=index])
        .filter(|candidate| {
            // Every candidate is a prefix of one path, so comparing lengths
            // orders them exactly.
            let node = candidate
                .strip_suffix('/')
                .unwrap_or(candidate)
                .len()
                .max(1);
            node > floor && node < ceiling
        })
        .map(|candidate| {
            let mut ancestor = address.clone();
            // The child's own query pins that child — a `versionId` selects one
            // object, not a directory — so it does not carry over. The listed
            // prefix's does: the listing was requested under that
            // qualification, and an ancestor that dropped it would name a
            // directory in a different namespace than the entries beside it.
            ancestor.set_query(listed_prefix.query());
            ancestor.set_fragment(None);
            ancestor.set_path(candidate);
            ancestor
        })
        .collect()
}

fn inferred_directory_info(address: Url) -> ObjectInfo {
    ObjectInfo {
        address,
        kind: ObjectKind::DirectoryInferred,
        etag: None,
        version: None,
        size: None,
        mtime: None,
        checksums: ChecksumSet::default(),
        effective_permissions: None,
        system_metadata: None,
        user_metadata: None,
        modified_by: None,
    }
}

fn is_flat_marker_entry(item: &ObjectInfo) -> bool {
    item.kind == ObjectKind::DirectoryMarker
        || (item.kind == ObjectKind::File
            && item.address.path().ends_with('/')
            && item.size.unwrap_or(0) == 0)
}

fn is_directory_like(kind: ObjectKind) -> bool {
    matches!(
        kind,
        ObjectKind::Directory | ObjectKind::DirectoryMarker | ObjectKind::DirectoryInferred
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- RouteTable ----------------------------------------------------
    //
    // `RouteTable::build`/`lookup` had no direct coverage, which is why an
    // earlier review of the trailing-slash work stalled on an unresolved
    // disagreement about
    // whether length-based ranking is correct. These pin current behavior.
    //
    // Roots are built with `address::parse`, not `Url::parse`: `build` and
    // `lookup` are pure over the `RootInfo`s handed in, so a `Url::parse`
    // fixture would bypass canonicalization and could never move when the
    // canonicalization rule changes.

    fn route_root(root: &str) -> RootInfo {
        RootInfo {
            root: address::parse(root).expect("test root parses"),
            display_name: None,
            layer_kind: "test".to_string(),
            connection_id: None,
            owning_target: None,
            capabilities: crate::Capabilities::empty(),
            range_read_strategy: crate::RangeReadStrategy::default(),
            source: crate::RouteSource::Static {
                layer: crate::ConfigLayer::Programmatic,
            },
            visible: true,
            visibility: crate::AddressVisibility::Visible,
            alias_state: None,
            icon: None,
            user_metadata: crate::UserMetadata::new(),
        }
    }

    fn table(roots: &[(&str, &str)]) -> RouteTable<String> {
        RouteTable::build(
            roots
                .iter()
                .map(|(root, target)| (route_root(root), (*target).to_string()))
                .collect(),
        )
    }

    fn route_for(table: &RouteTable<String>, address: &str) -> Option<String> {
        table
            .lookup(&address::parse(address).expect("test address parses"))
            .map(|(_, target)| target.clone())
    }

    /// Two spellings of one root are one root, whichever order they register.
    ///
    /// Ranking by the serialized byte length made the slashed spelling win
    /// regardless of registration order, silently inverting the documented
    /// FIFO tie-break. Segment count is spelling-independent, so the two tie
    /// and the stable sort keeps the first registration.
    #[test]
    fn route_table_breaks_a_slash_differing_root_tie_fifo() {
        for (first, second) in [
            ("file:///data/root", "file:///data/root/"),
            ("file:///data/root/", "file:///data/root"),
        ] {
            let table = table(&[(first, "first"), (second, "second")]);
            assert_eq!(
                route_for(&table, "file:///data/root/f.txt").as_deref(),
                Some("first"),
                "registering {first} then {second} must keep the first-registered route"
            );
        }
    }

    /// Rendered `tracing` events captured off the thread-local subscriber.
    /// The shadowing warning is the whole of the operator-facing signal, so
    /// the test that owns it asserts on the line itself.
    #[derive(Clone, Default)]
    struct CapturedLogs(std::sync::Arc<std::sync::Mutex<Vec<String>>>);

    impl CapturedLogs {
        fn install(&self) -> tracing::subscriber::DefaultGuard {
            use tracing_subscriber::layer::SubscriberExt;
            tracing::subscriber::set_default(
                tracing_subscriber::registry().with(CaptureLayer(self.clone())),
            )
        }

        fn lines(&self) -> Vec<String> {
            self.0
                .lock()
                .expect("the capture lock is not poisoned")
                .clone()
        }
    }

    struct CaptureLayer(CapturedLogs);

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for CaptureLayer {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let mut visitor = RenderVisitor(String::new());
            event.record(&mut visitor);
            (self.0.0)
                .lock()
                .expect("the capture lock is not poisoned")
                .push(visitor.0);
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

    /// The shadowing warning names the node, never the credential.
    ///
    /// Dedup keys on `node_key`, which excludes userinfo — so two roots
    /// differing only by their credentials are one node and take this path on
    /// every route-table build. Rendering the `Url` itself would write the
    /// password into structured logs each time.
    #[test]
    fn a_shadowed_root_is_logged_without_its_credentials() {
        let logs = CapturedLogs::default();
        let shadowed = {
            let _guard = logs.install();
            table(&[
                ("https://alice:hunter2@host.invalid/root/", "first"),
                ("https://bob:swordfish@host.invalid/root/", "second"),
            ])
        };
        // The premise: the two roots really are one node, so the warning fired
        // and the assertion below is asserting on something.
        assert_eq!(
            route_for(&shadowed, "https://host.invalid/root/f.txt").as_deref(),
            Some("first"),
        );
        let warnings: Vec<String> = logs
            .lines()
            .into_iter()
            .filter(|line| line.contains("overlapping address root shadowed"))
            .collect();
        assert_eq!(warnings.len(), 1, "captured lines: {:?}", logs.lines());
        for secret in ["hunter2", "swordfish", "alice", "bob"] {
            assert!(
                !warnings[0].contains(secret),
                "the shadowing warning leaked `{secret}`: {}",
                warnings[0]
            );
        }
        assert!(
            warnings[0].contains("https://host.invalid/root/"),
            "the warning must still name the shadowed node: {}",
            warnings[0]
        );
    }

    /// One listing spells its directories one way.
    ///
    /// A marker came back as `docs/` and an inferred directory as `docs` — the
    /// same kind of thing, spelled two ways. The slash is added to directory
    /// kinds and never removed from anything: a slash-terminated object with a
    /// body is a `File` whose slash is part of its name, and stripping it would
    /// emit a duplicate of the sibling file that `delete` then destroys.
    #[test]
    fn fold_pass_emits_every_directory_kind_with_a_trailing_slash() {
        let items = vec![
            subdir("s3://b/inferred", ObjectKind::DirectoryInferred),
            subdir("s3://b/native", ObjectKind::Directory),
            subdir("s3://b/marker/", ObjectKind::DirectoryMarker),
            obj("s3://b/file.txt"),
        ];
        for has_real_directories in [false, true] {
            let folded = fold_markers_and_infer_subdir_kinds(
                &prefix("s3://b/"),
                items.clone(),
                has_real_directories,
                false,
            );
            for item in &folded {
                if item.kind == ObjectKind::File {
                    continue;
                }
                assert!(
                    item.address.path().ends_with('/'),
                    "{} came back without its separator",
                    item.address
                );
            }
            // A file keeps the spelling it had, in both directions.
            assert!(
                folded
                    .iter()
                    .any(|item| item.address.as_str() == "s3://b/file.txt")
            );
        }
    }

    /// A slash-terminated object with a body is a file, and keeps its slash.
    ///
    /// Stripping it would emit `s3://b/docs`, a duplicate of the sibling file
    /// of that name — and a `delete` of the address the caller was handed
    /// would destroy the wrong object.
    #[test]
    fn fold_pass_does_not_strip_a_slash_from_a_file() {
        let mut slashed_file = obj("s3://b/docs/");
        slashed_file.size = Some(7);
        let folded = fold_markers_and_infer_subdir_kinds(
            &prefix("s3://b/"),
            vec![slashed_file, obj("s3://b/docs")],
            false,
            false,
        );
        let addresses: Vec<&str> = folded.iter().map(|item| item.address.as_str()).collect();
        assert!(addresses.contains(&"s3://b/docs/"), "{addresses:?}");
        assert!(addresses.contains(&"s3://b/docs"), "{addresses:?}");
    }

    /// A pinned root wins for the address it publishes.
    ///
    /// A pinned scope covers a strict subset of its unpinned parent — same node
    /// path, one exact query — so ranking on depth alone tied them and
    /// registration order decided. The pinned root was then unreachable for
    /// precisely the address it was registered for, and the request went to a
    /// different backend.
    #[test]
    fn route_table_prefers_a_pinned_root_for_the_address_it_publishes() {
        for order in [
            vec![
                ("s3://b/root/", "generic"),
                ("s3://b/root?snapshot=7", "pinned"),
            ],
            vec![
                ("s3://b/root?snapshot=7", "pinned"),
                ("s3://b/root/", "generic"),
            ],
        ] {
            let table = table(&order);
            assert_eq!(
                route_for(&table, "s3://b/root?snapshot=7").as_deref(),
                Some("pinned"),
                "registered {order:?}"
            );
            // An unpinned request still takes the unpinned root.
            assert_eq!(
                route_for(&table, "s3://b/root/f.txt").as_deref(),
                Some("generic"),
                "registered {order:?}"
            );
        }
    }

    /// A deeper root still outranks a shallower one, whatever the spelling.
    #[test]
    fn route_table_ranks_by_depth_not_by_spelling() {
        let table = table(&[
            ("file:///data/root/deep/", "deep"),
            ("file:///data/root", "shallow"),
        ]);
        assert_eq!(
            route_for(&table, "file:///data/root/deep/f.txt").as_deref(),
            Some("deep")
        );
        assert_eq!(
            route_for(&table, "file:///data/root/other.txt").as_deref(),
            Some("shallow")
        );
        // The case a single-root table cannot observe: the DEEP root addressed
        // by its own unslashed spelling, with a coarser route present. The
        // reported symptom is `NoRoute` only when nothing else matches — when
        // something does, the address is served by a backend the caller never
        // addressed, with no error and no diagnostic. Asserting *which* route
        // answers is what separates the two, and it is what the reproduction
        // on the issue thread asks acceptance to cover; this asserts it one
        // layer down from the backend, on the route the table selects.
        assert_eq!(
            route_for(&table, "file:///data/root/deep").as_deref(),
            Some("deep"),
            "the unslashed spelling of a root must not fall through to a coarser route"
        );
        assert_eq!(
            route_for(&table, "file:///data/root/deep/").as_deref(),
            Some("deep")
        );
    }

    /// The reported routing failure, at the primitive that produced it.
    ///
    /// A connection publishing `file:///data/root/` served
    /// `list file:///data/root/` and answered `NoRoute` for
    /// `file:///data/root`. Every path-joining host produces the second
    /// spelling, and the trailing slash is not part of node identity.
    #[test]
    fn a_root_routes_under_either_spelling_of_itself() {
        for published in ["file:///data/root/", "file:///data/root"] {
            let table = table(&[(published, "t")]);
            for requested in ["file:///data/root/", "file:///data/root"] {
                assert_eq!(
                    route_for(&table, requested),
                    Some("t".to_string()),
                    "root published as {published} must route {requested}"
                );
            }
            // A sibling whose name merely starts with the root's must not
            // route: node-awareness is not substring matching.
            assert_eq!(
                route_for(&table, "file:///data/rootx"),
                None,
                "root published as {published} must not route a textual sibling"
            );
            // Children still route, under either spelling.
            assert_eq!(
                route_for(&table, "file:///data/root/a/b.txt"),
                Some("t".to_string())
            );
        }
    }

    /// A pinned address is under the node its pin selects from.
    ///
    /// Comparing serialized strings made this depend on how the root was
    /// spelled: `s3://b/root?versionId=1` matched the slashless root through
    /// the `?` boundary and missed the slashed one, so the two spellings of
    /// one root disagreed about pinned addresses — the reported bug, one class
    /// narrower.
    #[test]
    fn a_version_pin_routes_under_either_spelling_of_its_root() {
        for published in ["s3://b/root/", "s3://b/root"] {
            let table = table(&[(published, "t")]);
            assert_eq!(
                route_for(&table, "s3://b/root?versionId=1"),
                Some("t".to_string()),
                "root published as {published} must route a pinned address"
            );
        }
    }

    #[test]
    fn route_table_selects_the_longest_matching_prefix() {
        let table = table(&[
            ("s3://bucket/", "bucket"),
            ("s3://bucket/team/", "team"),
            ("s3://bucket/team/docs/", "docs"),
        ]);
        assert_eq!(
            route_for(&table, "s3://bucket/other.txt").as_deref(),
            Some("bucket")
        );
        assert_eq!(
            route_for(&table, "s3://bucket/team/x.txt").as_deref(),
            Some("team")
        );
        assert_eq!(
            route_for(&table, "s3://bucket/team/docs/x.txt").as_deref(),
            Some("docs")
        );
    }

    #[test]
    fn route_table_breaks_an_exact_root_tie_fifo() {
        // Two connections publishing the identical root: the first registered
        // keeps the route and the later one is shadowed. `build` warns and
        // continues rather than rejecting.
        let table = table(&[
            ("s3://bucket/team/", "first"),
            ("s3://bucket/team/", "second"),
        ]);
        assert_eq!(
            route_for(&table, "s3://bucket/team/x.txt").as_deref(),
            Some("first")
        );
    }

    #[test]
    fn route_table_does_not_match_a_sibling_sharing_a_prefix_string() {
        // `…/root` must not capture `…/rootx`. Note the mechanism differs
        // before and after canonicalization: today the root is spelled
        // `file:///data/root/`, so plain `starts_with` already rejects the
        // sibling and `is_prefix_of`'s boundary test never runs. Once the root
        // canonicalizes to `file:///data/root`, that boundary test becomes the
        // only thing keeping them apart.
        let table = table(&[("file:///data/root/", "root")]);
        assert_eq!(route_for(&table, "file:///data/rootx/f.txt"), None);
        assert_eq!(route_for(&table, "file:///data/roo"), None);
        assert_eq!(
            route_for(&table, "file:///data/root/f.txt").as_deref(),
            Some("root")
        );
    }

    #[test]
    fn route_table_treats_both_authority_root_spellings_as_one_root() {
        // `s3://bucket` and `s3://bucket/` are already one root today: rule 2
        // of canonicalization fills the empty path, so both spellings collide
        // and FIFO applies.
        let table = table(&[("s3://bucket", "bare"), ("s3://bucket/", "slashed")]);
        assert_eq!(
            route_for(&table, "s3://bucket/x.txt").as_deref(),
            Some("bare")
        );
    }

    #[test]
    fn route_table_empty_matches_nothing() {
        let table: RouteTable<String> = RouteTable::empty();
        assert_eq!(route_for(&table, "s3://bucket/x.txt"), None);
    }

    fn make_object_info(addr: &str) -> ObjectInfo {
        ObjectInfo {
            address: Url::parse(addr).unwrap(),
            kind: ObjectKind::File,
            etag: None,
            version: None,
            size: None,
            mtime: None,
            checksums: ChecksumSet::default(),
            effective_permissions: None,
            system_metadata: None,
            user_metadata: None,
            modified_by: None,
        }
    }

    fn obj(addr: &str) -> ObjectInfo {
        make_object_info(addr)
    }

    fn subdir(addr: &str, kind: ObjectKind) -> ObjectInfo {
        let mut info = make_object_info(addr);
        info.kind = kind;
        info
    }

    fn prefix(addr: &str) -> Url {
        Url::parse(addr).unwrap()
    }

    /// One node reported two ways is one entry, whichever spelling carries the
    /// concrete fact.
    ///
    /// This is the compatibility case the concrete-over-inferred fold exists
    /// for, and the merges compare serialized addresses — so with the
    /// slash-normalization running after them, `s3://b/docs/` and
    /// `s3://b/docs` were two entries for one node with conflicting `kind`,
    /// both counted against `max_results`. Asserted for a real-directory
    /// backend and a flat one, because the two take different paths through
    /// the fold.
    #[test]
    fn fold_pass_merges_two_spellings_of_one_directory() {
        for has_real_directories in [true, false] {
            let items = vec![
                subdir("s3://b/docs/", ObjectKind::DirectoryMarker),
                subdir("s3://b/docs", ObjectKind::DirectoryInferred),
            ];
            let folded = fold_markers_and_infer_subdir_kinds(
                &prefix("s3://b/"),
                items,
                has_real_directories,
                false,
            );
            assert_eq!(
                folded.len(),
                1,
                "two spellings of one node must fold to one entry \
                 (has_real_directories = {has_real_directories}): {:?}",
                folded
                    .iter()
                    .map(|i| i.address.as_str())
                    .collect::<Vec<_>>()
            );
            assert_eq!(folded[0].kind, ObjectKind::DirectoryMarker);
            assert_eq!(folded[0].address.as_str(), "s3://b/docs/");
        }

        // The control: a `File` keyed `docs` is a different object from the
        // directory `docs/` on a flat store, and normalization must not merge
        // them — it only ever adds a slash to a directory kind.
        let items = vec![
            obj("s3://b/docs"),
            subdir("s3://b/docs/", ObjectKind::DirectoryMarker),
        ];
        let folded = fold_markers_and_infer_subdir_kinds(&prefix("s3://b/"), items, false, false);
        assert_eq!(folded.len(), 2, "a file and a directory are two objects");
    }

    /// A recursive listing does not synthesize an ancestor it was already
    /// given under the other spelling.
    ///
    /// `known` is keyed on the serialized address, so an inferred `s3://b/docs`
    /// already in the page did not suppress synthesizing `s3://b/docs/` from a
    /// child — the same node twice, and the fold could not see it either.
    #[test]
    fn fold_pass_recursive_does_not_synthesize_a_spelling_it_already_has() {
        let items = vec![
            subdir("s3://b/docs", ObjectKind::Directory),
            obj("s3://b/docs/q3/report.txt"),
        ];
        let folded = fold_markers_and_infer_subdir_kinds(&prefix("s3://b/"), items, false, true);
        let docs: Vec<&str> = folded
            .iter()
            .map(|item| item.address.as_str())
            .filter(|address| *address == "s3://b/docs/" || *address == "s3://b/docs")
            .collect();
        assert_eq!(
            docs,
            vec!["s3://b/docs/"],
            "one node, one entry: {:?}",
            folded
                .iter()
                .map(|i| i.address.as_str())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn fold_pass_passthrough_on_real_dir_backend() {
        let items = vec![
            obj("file:///root/file.txt"),
            subdir("file:///root/sub/", ObjectKind::Directory),
        ];
        let folded =
            fold_markers_and_infer_subdir_kinds(&prefix("file:///root/"), items, true, false);
        assert_eq!(folded.len(), 2);
        assert_eq!(folded[1].kind, ObjectKind::Directory);
    }

    #[test]
    fn fold_pass_recursive_promotes_marker_objects() {
        let items = vec![obj("s3://b/dir/")];
        let folded = fold_markers_and_infer_subdir_kinds(&prefix("s3://b/"), items, false, true);
        assert_eq!(folded.len(), 1);
        assert_eq!(folded[0].kind, ObjectKind::DirectoryMarker);
    }

    #[test]
    fn fold_pass_promotes_lone_marker_to_subdirectory() {
        let items = vec![obj("s3://b/team/"), obj("s3://b/team/file.txt")];
        let folded = fold_markers_and_infer_subdir_kinds(&prefix("s3://b/"), items, false, false);
        assert_eq!(folded.len(), 2);
        let subdirs: Vec<_> = folded
            .iter()
            .filter(|item| item.kind == ObjectKind::DirectoryMarker)
            .collect();
        assert_eq!(subdirs.len(), 1);
        assert_eq!(subdirs[0].address.as_str(), "s3://b/team/");
    }

    #[test]
    fn fold_pass_merges_marker_with_subdirectory_peer() {
        let mut marker_info = make_object_info("s3://b/team/");
        marker_info.size = Some(0);
        marker_info.etag = Some("MARKER-ETAG".into());
        let items = vec![marker_info, subdir("s3://b/team/", ObjectKind::Directory)];
        let folded = fold_markers_and_infer_subdir_kinds(&prefix("s3://b/"), items, false, false);
        assert_eq!(folded.len(), 1);
        assert_eq!(folded[0].kind, ObjectKind::DirectoryMarker);
        assert_eq!(folded[0].etag.as_deref(), Some("MARKER-ETAG"));
    }

    #[test]
    fn fold_pass_merges_explicit_marker_with_inferred_peer() {
        let mut marker = subdir("s3://b/team/", ObjectKind::DirectoryMarker);
        marker.etag = Some("MARKER-ETAG".into());
        let items = vec![
            subdir("s3://b/team/", ObjectKind::DirectoryInferred),
            marker,
        ];
        let folded = fold_markers_and_infer_subdir_kinds(&prefix("s3://b/"), items, false, true);
        assert_eq!(folded.len(), 1);
        assert_eq!(folded[0].kind, ObjectKind::DirectoryMarker);
        assert_eq!(folded[0].etag.as_deref(), Some("MARKER-ETAG"));
    }

    #[test]
    fn fold_pass_merges_real_directory_with_inferred_peer() {
        let mut directory = subdir("file:///root/team/", ObjectKind::Directory);
        directory.etag = Some("DIR-ETAG".into());
        let items = vec![
            subdir("file:///root/team/", ObjectKind::DirectoryInferred),
            directory,
        ];
        let folded =
            fold_markers_and_infer_subdir_kinds(&prefix("file:///root/"), items, true, true);
        assert_eq!(folded.len(), 1);
        assert_eq!(folded[0].kind, ObjectKind::Directory);
        assert_eq!(folded[0].etag.as_deref(), Some("DIR-ETAG"));
    }

    #[test]
    fn fold_pass_recursive_synthesizes_missing_inferred_ancestors() {
        let items = vec![obj("s3://b/foo/bar/baz.txt")];
        let folded = fold_markers_and_infer_subdir_kinds(&prefix("s3://b/"), items, false, true);
        let entries: Vec<_> = folded
            .iter()
            .map(|item| (item.address.as_str(), item.kind))
            .collect();
        assert_eq!(
            entries,
            vec![
                ("s3://b/foo/", ObjectKind::DirectoryInferred),
                ("s3://b/foo/bar/", ObjectKind::DirectoryInferred),
                ("s3://b/foo/bar/baz.txt", ObjectKind::File),
            ]
        );
    }

    /// A synthesized ancestor stays in the namespace the listing was made in.
    ///
    /// A qualified listing prefix pins which namespace its entries come from.
    /// An ancestor built by clearing the query names the current namespace
    /// instead, so it sits in a listing whose other entries are from another
    /// one — and acting on it reaches a different object.
    #[test]
    fn fold_pass_recursive_keeps_the_listed_prefix_qualification_on_ancestors() {
        let folded = fold_markers_and_infer_subdir_kinds(
            &prefix("s3://b/root/?snapshot=7"),
            vec![obj("s3://b/root/a/b?snapshot=7")],
            false,
            true,
        );
        assert!(
            folded
                .iter()
                .any(|item| item.address.as_str() == "s3://b/root/a/?snapshot=7"),
            "got {:?}",
            folded
                .iter()
                .map(|item| item.address.as_str())
                .collect::<Vec<_>>()
        );
    }

    /// A synthesized ancestor must name the same directory its child is under.
    ///
    /// The child's address is already correctly escaped, so an ancestor built
    /// by re-encoding a slice of it escapes the escape: a key `pub x/y.txt`
    /// listed as `s3://b/pub%20x/y.txt` yields the ancestor `s3://b/pub%2520x/`,
    /// which names the key `pub%20x/` — a different directory, and one a
    /// `delete_directory` would destroy instead.
    #[test]
    fn fold_pass_recursive_synthesizes_ancestors_of_an_escaped_key() {
        for (child, ancestor) in [
            ("s3://b/pub%20x/y.txt", "s3://b/pub%20x/"),
            ("s3://b/a%25b/c/y.txt", "s3://b/a%25b/"),
        ] {
            let folded = fold_markers_and_infer_subdir_kinds(
                &prefix("s3://b/"),
                vec![obj(child)],
                false,
                true,
            );
            assert!(
                folded.iter().any(|item| item.address.as_str() == ancestor),
                "listing {child} must synthesize {ancestor}, got {:?}",
                folded
                    .iter()
                    .map(|item| item.address.as_str())
                    .collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn fold_pass_recursive_does_not_synthesize_listed_prefix_itself() {
        let items = vec![obj("s3://b/foo/bar/baz.txt")];
        let folded =
            fold_markers_and_infer_subdir_kinds(&prefix("s3://b/foo/"), items, false, true);
        assert!(
            folded
                .iter()
                .all(|item| item.address.as_str() != "s3://b/foo/")
        );
        assert!(
            folded
                .iter()
                .any(|item| item.address.as_str() == "s3://b/foo/bar/"
                    && item.kind == ObjectKind::DirectoryInferred)
        );
    }

    #[test]
    fn fold_pass_tags_unknown_subdirs_as_inferred() {
        let items = vec![subdir("s3://b/foo/", ObjectKind::Directory)];
        let folded = fold_markers_and_infer_subdir_kinds(&prefix("s3://b/"), items, false, false);
        assert_eq!(folded[0].kind, ObjectKind::DirectoryInferred);
    }

    #[test]
    fn fold_pass_preserves_plugin_specified_inferred() {
        // Plugin-supplied `DirectoryInferred` must not be overwritten.
        let items = vec![subdir("s3://b/foo/", ObjectKind::DirectoryInferred)];
        let folded = fold_markers_and_infer_subdir_kinds(&prefix("s3://b/"), items, false, false);
        assert_eq!(folded[0].kind, ObjectKind::DirectoryInferred);
    }
}
