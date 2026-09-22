// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Bounded-state adapters for backend listing streams.

use std::collections::VecDeque;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::Stream;

use crate::routing::{
    ancestor_addresses, inferred_directory_info, is_flat_marker_entry, normalize_directory_address,
};
use crate::{Error, ErrorCode, ListStream, ObjectInfo, ObjectKind, Result, Url};

/// Incrementally applies directory-marker folding and inferred-directory
/// synthesis to a [`ListStream`].
///
/// The adapter keeps one same-address lookbehind and, for recursive listings
/// on flat stores, the ancestor chain of the previous entry. Its memory use is
/// therefore `O(depth)` rather than `O(number of listed objects)`.
///
/// Parity with [`crate::fold_markers_and_infer_subdir_kinds`] has two
/// mode-specific preconditions:
///
/// - Recursive listings on flat stores must be byte-sorted by decoded provider
///   key. Such backends list without a delimiter and naturally emit only their
///   byte-sorted object contents. A regression yields an
///   [`ErrorCode::Internal`] item and terminates the adapter.
/// - Non-recursive flat listings preserve the backend's natural order, which
///   may be per-page contents followed by common prefixes rather than globally
///   sorted. Backends must remove marker/common-prefix duplicates within each
///   page before this adapter; equivalent duplicates do not cross page
///   boundaries on conforming streams.
///
/// Real-directory backends need neither ordering rule; they receive address
/// normalization and bounded adjacent concrete-over-inferred suppression.
/// Inputs outside these preconditions are out of contract, except that a
/// recursive byte-order regression is rejected explicitly.
pub struct IncrementalListFold {
    inner: ListStream,
    listed_prefix: Url,
    has_real_directories: bool,
    recursive_flat: bool,
    lookbehind: Option<ObjectInfo>,
    last_input_key: Option<Vec<u8>>,
    previous_ancestor_chain: Vec<Url>,
    ready: VecDeque<Result<ObjectInfo>>,
    inner_done: bool,
    failed: bool,
    #[cfg(test)]
    peak_retained_state_size: usize,
}

impl IncrementalListFold {
    /// Wrap `inner` using the same backend traits that parameterize the
    /// buffered list fold.
    pub fn new(
        inner: ListStream,
        listed_prefix: &Url,
        has_real_directories: bool,
        recursive: bool,
    ) -> Self {
        Self {
            inner,
            listed_prefix: listed_prefix.clone(),
            has_real_directories,
            recursive_flat: recursive && !has_real_directories,
            lookbehind: None,
            last_input_key: None,
            previous_ancestor_chain: Vec::new(),
            ready: VecDeque::new(),
            inner_done: false,
            failed: false,
            #[cfg(test)]
            peak_retained_state_size: 0,
        }
    }

    /// Number of retained, variably-sized entries owned by this adapter.
    ///
    /// The inner stream is deliberately excluded: its residency belongs to
    /// the producer. This probe counts the lookbehind, order-check key,
    /// recursive ancestor chain, and ready queue that make up the fold's own
    /// bounded state.
    #[cfg(test)]
    fn retained_state_size(&self) -> usize {
        usize::from(self.lookbehind.is_some())
            + usize::from(self.last_input_key.is_some())
            + self.previous_ancestor_chain.len()
            + self.ready.len()
    }

    #[cfg(test)]
    fn record_retained_state_peak(&mut self) {
        self.peak_retained_state_size = self
            .peak_retained_state_size
            .max(self.retained_state_size());
    }

    #[cfg(not(test))]
    fn record_retained_state_peak(&mut self) {}

    #[cfg(test)]
    fn peak_retained_state_size(&self) -> usize {
        self.peak_retained_state_size
    }

    fn prepare_item(&self, item: ObjectInfo) -> ObjectInfo {
        // Same-address comparisons use exactly the normalized spelling callers
        // receive. The provider-ordering key is captured before this step.
        let mut item = normalize_directory_address(item);
        if self.has_real_directories {
            return item;
        }
        if is_flat_marker_entry(&item) {
            item.kind = ObjectKind::DirectoryMarker;
            item.size = None;
        } else if item.kind == ObjectKind::Directory {
            item.kind = ObjectKind::DirectoryInferred;
        }
        item
    }

    fn merge_same_address(&self, current: ObjectInfo, next: ObjectInfo) -> SameAddressMerge {
        let current_concrete = is_concrete_directory(current.kind);
        let next_concrete = is_concrete_directory(next.kind);

        if current.kind == ObjectKind::DirectoryInferred && next_concrete {
            return SameAddressMerge::Keep(next);
        }
        if current_concrete && next.kind == ObjectKind::DirectoryInferred {
            return SameAddressMerge::Keep(current);
        }
        if !self.has_real_directories
            && current.kind == ObjectKind::DirectoryMarker
            && next.kind == ObjectKind::DirectoryMarker
        {
            // The whole-set fold retains the last marker's metadata while
            // emitting it at the first marker's position.
            return SameAddressMerge::Keep(next);
        }
        SameAddressMerge::EmitThenKeep(current, Box::new(next))
    }

    fn finish_item(&mut self, item: ObjectInfo) {
        if !self.recursive_flat {
            self.ready.push_back(Ok(item));
            return;
        }

        let ancestors =
            if crate::address::relative_suffix(&item.address, &self.listed_prefix).is_some() {
                ancestor_addresses(&self.listed_prefix, &item.address)
            } else {
                Vec::new()
            };
        let shared = ancestors
            .iter()
            .zip(&self.previous_ancestor_chain)
            .take_while(|(left, right)| left == right)
            .count();
        for ancestor in ancestors.iter().skip(shared) {
            self.ready
                .push_back(Ok(inferred_directory_info(ancestor.clone())));
        }

        self.previous_ancestor_chain = ancestors;
        // The whole-set oracle's `known` set contains every input address,
        // including a non-marker file whose key ends in `/`. Such an object
        // still suppresses synthesis at that exact address, so key this on
        // spelling rather than kind.
        if item.address.path().ends_with('/')
            && self.previous_ancestor_chain.last() != Some(&item.address)
        {
            self.previous_ancestor_chain.push(item.address.clone());
        }
        self.ready.push_back(Ok(item));
    }

    fn finish_lookbehind(&mut self) {
        if let Some(item) = self.lookbehind.take() {
            self.finish_item(item);
        }
    }

    fn reject_order_regression(&mut self) {
        tracing::warn!(
            target: "ovstorage.list_stream",
            "recursive flat listing provider-key order regressed"
        );
        self.finish_lookbehind();
        self.ready.push_back(Err(Error::new(
            ErrorCode::Internal,
            "recursive flat listing is not byte-sorted",
        )));
        self.failed = true;
    }
}

enum SameAddressMerge {
    Keep(ObjectInfo),
    EmitThenKeep(ObjectInfo, Box<ObjectInfo>),
}

fn is_concrete_directory(kind: ObjectKind) -> bool {
    matches!(kind, ObjectKind::Directory | ObjectKind::DirectoryMarker)
}

impl Stream for IncrementalListFold {
    type Item = Result<ObjectInfo>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            // Record before draining `ready`, including the transient peak
            // built by one poll of the inner stream.
            this.record_retained_state_peak();
            if let Some(item) = this.ready.pop_front() {
                return Poll::Ready(Some(item));
            }
            if this.failed {
                return Poll::Ready(None);
            }
            if this.inner_done {
                this.finish_lookbehind();
                if this.ready.is_empty() {
                    return Poll::Ready(None);
                }
                continue;
            }

            match this.inner.as_mut().poll_next(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => this.inner_done = true,
                Poll::Ready(Some(Err(error))) => {
                    // Preserve source order despite the one-item lookahead.
                    this.finish_lookbehind();
                    this.ready.push_back(Err(error));
                    this.failed = true;
                }
                Poll::Ready(Some(Ok(item))) => {
                    // Provider list APIs order decoded object keys, while URL
                    // serialization percent-encodes those bytes. Comparing the
                    // serialized address would reject valid sequences such as
                    // `a x` followed by `a!x` (`%` sorts after `!`).
                    let ordering_key = crate::address::key(&item.address);
                    let item = this.prepare_item(item);
                    if this.recursive_flat
                        && let Some(previous) = this.last_input_key.as_deref()
                        && ordering_key.as_slice() < previous
                    {
                        this.reject_order_regression();
                        continue;
                    }
                    this.last_input_key = Some(ordering_key);

                    let Some(current) = this.lookbehind.take() else {
                        this.lookbehind = Some(item);
                        continue;
                    };
                    if current.address == item.address {
                        match this.merge_same_address(current, item) {
                            SameAddressMerge::Keep(item) => this.lookbehind = Some(item),
                            SameAddressMerge::EmitThenKeep(current, next) => {
                                this.finish_item(current);
                                this.lookbehind = Some(*next);
                            }
                        }
                    } else {
                        this.finish_item(current);
                        this.lookbehind = Some(item);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod fold_parity_tests {
    use futures::StreamExt;

    use super::*;
    use crate::{ChecksumSet, fold_markers_and_infer_subdir_kinds};

    fn info(address: &str, kind: ObjectKind, size: Option<u64>) -> ObjectInfo {
        ObjectInfo {
            etag_strength: Default::default(),
            address: Url::parse(address).unwrap(),
            kind,
            etag: None,
            version: None,
            size,
            mtime: None,
            checksums: ChecksumSet::default(),
            effective_permissions: None,
            system_metadata: None,
            user_metadata: None,
            modified_by: None,
            versioned_address: None,
        }
    }

    async fn incremental(
        prefix: &Url,
        items: Vec<ObjectInfo>,
        has_real_directories: bool,
        recursive: bool,
    ) -> Vec<Result<ObjectInfo>> {
        let inner: ListStream = Box::pin(futures::stream::iter(items.into_iter().map(Ok)));
        IncrementalListFold::new(inner, prefix, has_real_directories, recursive)
            .collect()
            .await
    }

    async fn assert_oracle_parity(
        case: &str,
        prefix: &Url,
        items: Vec<ObjectInfo>,
        has_real_directories: bool,
        recursive: bool,
    ) {
        let expected = fold_markers_and_infer_subdir_kinds(
            prefix,
            items.clone(),
            has_real_directories,
            recursive,
        );
        let actual = incremental(prefix, items, has_real_directories, recursive)
            .await
            .into_iter()
            .collect::<Result<Vec<_>>>()
            .unwrap_or_else(|error| panic!("{case}: incremental fold failed: {error}"));
        assert_eq!(
            actual, expected,
            "{case} (real_dirs={has_real_directories}, recursive={recursive})"
        );
    }

    fn sort_by_provider_key(items: &mut [ObjectInfo]) {
        items.sort_by_cached_key(|item| crate::address::key(&item.address));
    }

    fn marker(address: &str, tag: impl Into<String>) -> ObjectInfo {
        let mut marker = info(address, ObjectKind::File, Some(0));
        marker.etag = Some(tag.into());
        marker
    }

    #[tokio::test]
    async fn recursive_flat_sorted_input_matches_whole_set_fold() {
        let prefix = Url::parse("s3://bucket/").unwrap();
        let items = vec![
            info("s3://bucket/a/", ObjectKind::File, Some(0)),
            info("s3://bucket/a/", ObjectKind::DirectoryInferred, None),
            info("s3://bucket/a/b/c.txt", ObjectKind::File, Some(3)),
            info("s3://bucket/docs/file.txt", ObjectKind::File, Some(4)),
        ];
        let expected = fold_markers_and_infer_subdir_kinds(&prefix, items.clone(), false, true);
        let actual: Vec<ObjectInfo> = incremental(&prefix, items, false, true)
            .await
            .into_iter()
            .collect::<Result<_>>()
            .unwrap();
        assert_eq!(actual, expected);
    }

    #[tokio::test]
    async fn non_recursive_flat_natural_page_order_matches_whole_set_fold() {
        let prefix = Url::parse("s3://bucket/").unwrap();
        // Contents then common prefixes is intentionally not globally sorted:
        // docs/ follows team/file.txt.
        let items = vec![
            info("s3://bucket/team/", ObjectKind::File, Some(0)),
            info("s3://bucket/team/file.txt", ObjectKind::File, Some(3)),
            info("s3://bucket/docs", ObjectKind::Directory, None),
        ];
        let expected = fold_markers_and_infer_subdir_kinds(&prefix, items.clone(), false, false);
        let actual: Vec<ObjectInfo> = incremental(&prefix, items, false, false)
            .await
            .into_iter()
            .collect::<Result<_>>()
            .unwrap();
        assert_eq!(actual, expected);
        assert_eq!(actual[0].address.as_str(), "s3://bucket/team/");
        assert_eq!(actual[2].address.as_str(), "s3://bucket/docs/");
    }

    #[tokio::test]
    async fn real_directories_use_adjacent_concrete_over_inferred_dedup() {
        let prefix = Url::parse("file:///root/").unwrap();
        let mut concrete = info("file:///root/docs", ObjectKind::Directory, None);
        concrete.etag = Some("directory-etag".into());
        let items = vec![
            info("file:///root/docs/", ObjectKind::DirectoryInferred, None),
            concrete,
            info("file:///root/docs/file.txt", ObjectKind::File, Some(3)),
        ];
        let expected = fold_markers_and_infer_subdir_kinds(&prefix, items.clone(), true, true);
        let actual: Vec<ObjectInfo> = incremental(&prefix, items, true, true)
            .await
            .into_iter()
            .collect::<Result<_>>()
            .unwrap();
        assert_eq!(actual, expected);
    }

    #[tokio::test]
    async fn recursive_byte_order_regression_returns_internal_error_and_terminates() {
        let prefix = Url::parse("s3://bucket/").unwrap();
        let results = incremental(
            &prefix,
            vec![
                info("s3://bucket/b/file.txt", ObjectKind::File, Some(1)),
                info("s3://bucket/a/file.txt", ObjectKind::File, Some(1)),
                info("s3://bucket/z/file.txt", ObjectKind::File, Some(1)),
            ],
            false,
            true,
        )
        .await;

        let errors: Vec<&Error> = results
            .iter()
            .filter_map(|result| result.as_ref().err())
            .collect();
        assert_eq!(errors.len(), 1, "the regression emits one terminal error");
        let error = errors[0];
        assert_eq!(error.code(), ErrorCode::Internal);
        assert_eq!(error.message(), "recursive flat listing is not byte-sorted");
        assert!(!error.message().contains("s3://bucket/b/file.txt"));
        assert!(!error.message().contains("s3://bucket/a/file.txt"));
        assert!(
            results
                .iter()
                .filter_map(|result| result.as_ref().ok())
                .all(|item| {
                    !item.address.as_str().contains("/a/") && !item.address.as_str().contains("/z/")
                })
        );
    }

    #[tokio::test]
    async fn recursive_flat_order_uses_decoded_provider_key_bytes() {
        let prefix = Url::parse("s3://bucket/").unwrap();
        // These are in raw provider-key order. Percent-encoded URL bytes are
        // not order-preserving: `%20` sorts after `!`, and `%C3` sorts before
        // `z`, reversing both adjacent comparisons if URL text is used.
        let items = vec![
            info("s3://bucket/a%20x/file.txt", ObjectKind::File, Some(1)),
            info("s3://bucket/a!x/file.txt", ObjectKind::File, Some(1)),
            info("s3://bucket/az/file.txt", ObjectKind::File, Some(1)),
            info("s3://bucket/a%C3%A9/file.txt", ObjectKind::File, Some(1)),
        ];

        assert_oracle_parity(
            "percent-encoded addresses retain provider-key order",
            &prefix,
            items,
            false,
            true,
        )
        .await;
    }

    #[tokio::test]
    async fn routing_fold_cases_match_the_whole_set_oracle_in_each_mode() {
        let root = Url::parse("s3://bucket/").unwrap();

        let mut tagged_marker = marker("s3://bucket/team/", "marker-etag");
        tagged_marker.version = Some("marker-version".into());
        let mut explicit_marker = info("s3://bucket/archive/", ObjectKind::DirectoryMarker, None);
        explicit_marker.etag = Some("explicit-marker".into());
        let mut native_directory = info("s3://bucket/native", ObjectKind::Directory, None);
        native_directory.etag = Some("native-directory".into());

        let recursive_cases = vec![
            (
                "marker-only directory",
                root.clone(),
                vec![marker("s3://bucket/empty/", "empty-marker")],
            ),
            (
                "nested markers and objects",
                root.clone(),
                vec![
                    marker("s3://bucket/a/", "a-marker"),
                    marker("s3://bucket/a/b/", "b-marker"),
                    info("s3://bucket/a/b/c.txt", ObjectKind::File, Some(7)),
                    info("s3://bucket/a/d/e.txt", ObjectKind::File, Some(9)),
                ],
            ),
            (
                "missing deep ancestors",
                root.clone(),
                vec![info(
                    "s3://bucket/one/two/three/four/file.txt",
                    ObjectKind::File,
                    Some(11),
                )],
            ),
            (
                "directory spelling and descendant",
                root.clone(),
                vec![
                    info("s3://bucket/docs", ObjectKind::Directory, None),
                    info("s3://bucket/docs/q3/report.txt", ObjectKind::File, Some(12)),
                ],
            ),
            (
                "explicit marker wins over inferred peer",
                root.clone(),
                vec![
                    info("s3://bucket/archive", ObjectKind::DirectoryInferred, None),
                    explicit_marker,
                ],
            ),
            (
                "native directory wins over inferred peer",
                root.clone(),
                vec![
                    info("s3://bucket/native/", ObjectKind::DirectoryInferred, None),
                    native_directory,
                ],
            ),
            (
                "escaped ancestors",
                root.clone(),
                vec![
                    info("s3://bucket/a%25b/c/file.txt", ObjectKind::File, Some(1)),
                    info("s3://bucket/pub%20x/y.txt", ObjectKind::File, Some(1)),
                ],
            ),
            (
                "qualified ancestors",
                Url::parse("s3://bucket/root/?snapshot=7").unwrap(),
                vec![info(
                    "s3://bucket/root/a/b.txt?snapshot=7",
                    ObjectKind::File,
                    Some(1),
                )],
            ),
        ];

        for (case, prefix, mut items) in recursive_cases {
            sort_by_provider_key(&mut items);
            for has_real_directories in [false, true] {
                assert_oracle_parity(case, &prefix, items.clone(), has_real_directories, true)
                    .await;
            }
        }

        let non_recursive_cases = vec![
            (
                "multi-page contents then prefixes",
                vec![
                    marker("s3://bucket/team/", "team-marker"),
                    info("s3://bucket/team/file.txt", ObjectKind::File, Some(3)),
                    info("s3://bucket/docs", ObjectKind::Directory, None),
                ],
            ),
            (
                "adjacent marker and common-prefix collision",
                vec![
                    tagged_marker,
                    info("s3://bucket/team", ObjectKind::Directory, None),
                    info("s3://bucket/z.txt", ObjectKind::File, Some(1)),
                ],
            ),
            (
                "last adjacent marker metadata wins",
                vec![
                    marker("s3://bucket/duplicate/", "first"),
                    marker("s3://bucket/duplicate/", "last"),
                    info("s3://bucket/file.txt", ObjectKind::File, Some(5)),
                ],
            ),
            (
                "slash-terminated non-marker file",
                vec![
                    info("s3://bucket/body/", ObjectKind::File, Some(7)),
                    info("s3://bucket/body", ObjectKind::File, Some(4)),
                ],
            ),
            (
                "real-directory passthrough",
                vec![
                    info("s3://bucket/file.txt", ObjectKind::File, Some(2)),
                    info("s3://bucket/subdir", ObjectKind::Directory, None),
                ],
            ),
        ];

        for (case, items) in non_recursive_cases {
            for has_real_directories in [false, true] {
                assert_oracle_parity(case, &root, items.clone(), has_real_directories, false).await;
            }
        }
    }

    #[tokio::test]
    async fn generated_recursive_trees_match_the_whole_set_oracle() {
        let prefix = Url::parse("s3://bucket/").unwrap();
        for seed in 0..48usize {
            let mut items = Vec::new();
            let branches = seed % 5 + 1;
            for branch in 0..branches {
                let depth = (seed + branch) % 7 + 1;
                let mut path = format!("s3://bucket/tree-{branch:02}");
                for level in 0..depth {
                    path.push_str(&format!("/node-{level:02}"));
                    if (seed + branch + level) % 3 == 0 {
                        let address = format!("{path}/");
                        let mut entry = if (seed + level) % 2 == 0 {
                            marker(&address, format!("marker-{seed}-{branch}-{level}"))
                        } else {
                            info(&address, ObjectKind::DirectoryMarker, None)
                        };
                        entry.version = Some(format!("v-{seed}-{branch}-{level}"));
                        items.push(entry);
                    }
                }
                items.push(info(
                    &format!("{path}/leaf-{seed:02}.bin"),
                    ObjectKind::File,
                    Some((seed + branch) as u64),
                ));
            }
            items.push(marker(
                &format!("s3://bucket/orphan-{seed:02}/"),
                format!("orphan-{seed}"),
            ));
            sort_by_provider_key(&mut items);

            for has_real_directories in [false, true] {
                assert_oracle_parity(
                    &format!("generated recursive seed {seed}"),
                    &prefix,
                    items.clone(),
                    has_real_directories,
                    true,
                )
                .await;
            }
        }
    }

    #[tokio::test]
    async fn generated_backend_natural_pages_match_the_whole_set_oracle() {
        let prefix = Url::parse("s3://bucket/").unwrap();
        for seed in 0..48usize {
            let mut items = Vec::new();
            for page in 0..(seed % 4 + 2) {
                // Each simulated backend page emits sorted Contents first ...
                items.push(info(
                    &format!("s3://bucket/z-{seed:02}-{page:02}.bin"),
                    ObjectKind::File,
                    Some(page as u64),
                ));
                if (seed + page) % 2 == 0 {
                    items.push(marker(
                        &format!("s3://bucket/zz-{seed:02}-{page:02}/"),
                        format!("page-marker-{seed}-{page}"),
                    ));
                }
                // ... then sorted CommonPrefixes. The next page's Contents
                // regress relative to these entries, as real S3 emission can.
                items.push(info(
                    &format!("s3://bucket/a-{seed:02}-{page:02}"),
                    ObjectKind::Directory,
                    None,
                ));
                items.push(info(
                    &format!("s3://bucket/b-{seed:02}-{page:02}"),
                    ObjectKind::DirectoryInferred,
                    None,
                ));
            }

            for has_real_directories in [false, true] {
                assert_oracle_parity(
                    &format!("generated non-recursive seed {seed}"),
                    &prefix,
                    items.clone(),
                    has_real_directories,
                    false,
                )
                .await;
            }
        }
    }

    #[tokio::test]
    async fn non_recursive_flat_fold_accepts_the_recursive_regression_shape() {
        let prefix = Url::parse("s3://bucket/").unwrap();
        let items = vec![
            info("s3://bucket/b/file.txt", ObjectKind::File, Some(1)),
            info("s3://bucket/a/file.txt", ObjectKind::File, Some(1)),
        ];
        assert_oracle_parity(
            "non-recursive byte regression",
            &prefix,
            items,
            false,
            false,
        )
        .await;
    }

    #[tokio::test]
    async fn inner_error_propagates_in_order_and_terminates_the_fold() {
        let prefix = Url::parse("s3://bucket/").unwrap();
        let source_error = Error::new(ErrorCode::Transient, "synthetic page failure");
        let inner: ListStream = Box::pin(futures::stream::iter(vec![
            Ok(info("s3://bucket/a.txt", ObjectKind::File, Some(1))),
            Err(source_error.clone()),
            Ok(info("s3://bucket/z.txt", ObjectKind::File, Some(1))),
        ]));
        let results: Vec<_> = IncrementalListFold::new(inner, &prefix, false, false)
            .collect()
            .await;

        assert_eq!(results.len(), 2);
        assert_eq!(
            results[0].as_ref().unwrap().address.as_str(),
            "s3://bucket/a.txt"
        );
        assert_eq!(results[1].as_ref().unwrap_err(), &source_error);
    }

    #[tokio::test]
    async fn retained_state_is_depth_bounded_not_width_bounded() {
        const WIDTH: usize = 10_000;
        const RECURSIVE_DEPTH: usize = 2;

        let prefix = Url::parse("s3://bucket/").unwrap();
        let recursive_inner: ListStream =
            Box::pin(futures::stream::iter((0..WIDTH).map(|index| {
                Ok(info(
                    &format!("s3://bucket/wide/{index:05}/leaf.txt"),
                    ObjectKind::File,
                    Some(1),
                ))
            })));
        let mut recursive = IncrementalListFold::new(recursive_inner, &prefix, false, true);
        let mut recursive_count = 0;
        while let Some(item) = recursive.next().await {
            item.unwrap();
            recursive_count += 1;
        }
        let recursive_peak = recursive.peak_retained_state_size();
        assert_eq!(recursive_count, WIDTH * 2 + 1);
        assert!(
            recursive_peak <= RECURSIVE_DEPTH * 2 + 3,
            "recursive fold retained {recursive_peak} entries for depth {RECURSIVE_DEPTH}"
        );

        let non_recursive_inner: ListStream =
            Box::pin(futures::stream::iter((0..WIDTH).map(|index| {
                Ok(info(
                    &format!("s3://bucket/item-{index:05}.txt"),
                    ObjectKind::File,
                    Some(1),
                ))
            })));
        let mut non_recursive =
            IncrementalListFold::new(non_recursive_inner, &prefix, false, false);
        let mut non_recursive_count = 0;
        while let Some(item) = non_recursive.next().await {
            item.unwrap();
            non_recursive_count += 1;
        }
        let non_recursive_peak = non_recursive.peak_retained_state_size();
        assert_eq!(non_recursive_count, WIDTH);
        assert!(
            non_recursive_peak <= 3,
            "non-recursive fold retained {non_recursive_peak} entries"
        );
    }
}
