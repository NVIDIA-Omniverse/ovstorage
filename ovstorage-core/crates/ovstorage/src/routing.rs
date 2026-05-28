// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

pub(crate) fn list_options_are_cacheable_for_stat(opts: &ListOptions) -> bool {
    !opts.recursive
        && opts.max_results.is_none()
        && opts.page_token.is_none()
        && !opts.full_metadata
}

pub(crate) fn sort_routes(routes: &mut [Route]) {
    routes.sort_by_key(|r| std::cmp::Reverse(r.prefix.as_str().len()));
}

pub(crate) fn fresh_id(prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    format!("{prefix}-{}-{nanos}", std::process::id())
}

pub(crate) fn paginate_list_items(
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

/// `<partition>\0<backend_id>\0<resolved_url>`. Partition-first
/// layout enables `Cache::remove_prefix("tenant\0")`. None of the
/// components contain NUL, so the encoding is unambiguous.
pub(crate) fn cache_key(target: &ResolvedTarget, policy_partition: &str) -> String {
    format!(
        "{}\0{}\0{}",
        policy_partition, target.backend_id.0, target.resolved_address
    )
}

pub(crate) fn project_object_info(
    caller_prefix: &Url,
    resolved_prefix: &Url,
    mut info: ObjectInfo,
    operation: &str,
) -> Result<ObjectInfo> {
    debug_assert!(
        operation == "version" || caller_prefix.path().ends_with('/'),
        "project_object_info requires a trailing-slash caller_prefix for prefix projections; got {caller_prefix}"
    );
    let suffix = address::strip_prefix(&info.address, resolved_prefix).ok_or_else(|| {
        Error::new(
            ErrorCode::Internal,
            format!(
                "backend returned {operation} address {} outside resolved prefix {}",
                RedactedUrl(&info.address),
                RedactedUrl(resolved_prefix),
            ),
        )
    })?;
    info.address = address::parse(&format!("{}{}", caller_prefix.as_str(), suffix))?;
    Ok(info)
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
pub(crate) fn fold_markers_and_infer_subdir_kinds(
    listed_prefix: &Url,
    items: Vec<ObjectInfo>,
    has_real_directories: bool,
    recursive: bool,
) -> Vec<ObjectInfo> {
    if has_real_directories {
        return fold_concrete_over_inferred(items);
    }
    let mut marker_entries: HashMap<String, ObjectInfo> = HashMap::new();
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
        if let Some(suffix) = address::strip_prefix(&item.address, listed_prefix) {
            let suffix_path = suffix.split(['?', '#']).next().unwrap_or_default();
            let trimmed = suffix_path.trim_end_matches('/');
            let segments: Vec<_> = trimmed
                .split('/')
                .filter(|segment| !segment.is_empty())
                .collect();
            let mut relative = String::new();
            for segment in segments.iter().take(segments.len().saturating_sub(1)) {
                if !relative.is_empty() {
                    relative.push('/');
                }
                relative.push_str(segment);
                relative.push('/');
                if let Ok(address) = address::join_relative(listed_prefix, &relative) {
                    let key = address.as_str().to_string();
                    if known.insert(key) {
                        out.push(inferred_directory_info(address));
                    }
                }
                relative.pop();
            }
        }
        out.push(item);
    }
    out
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

pub(crate) fn compose_change_event(
    caller_prefix: &Url,
    resolved_prefix: &Url,
    event: BackendChangeEvent,
    metadata_cache: Option<&MetadataCache>,
) -> Result<ChangeEvent> {
    debug_assert!(
        caller_prefix.path().ends_with('/'),
        "compose_change_event requires a trailing-slash caller_prefix; got {caller_prefix}"
    );
    match event {
        BackendChangeEvent::Object {
            address,
            kind,
            etag,
            version,
            size,
            mtime,
            at,
            cursor,
        } => {
            let suffix = address::strip_prefix(&address, resolved_prefix).ok_or_else(|| {
                Error::new(
                    ErrorCode::Internal,
                    format!(
                        "backend returned watch address {} outside resolved prefix {}",
                        RedactedUrl(&address),
                        RedactedUrl(resolved_prefix),
                    ),
                )
            })?;
            let address = address::parse(&format!("{}{}", caller_prefix.as_str(), suffix))?;
            if let Some(cache) = metadata_cache {
                cache.invalidate_address(&address);
                cache.invalidate_lists_containing(&address);
            }
            Ok(ChangeEvent::Object {
                address,
                kind,
                etag,
                version,
                size,
                mtime,
                at,
                cursor,
            })
        }
        BackendChangeEvent::Lapsed { since, cursor } => Ok(ChangeEvent::Lapsed { since, cursor }),
    }
}

pub(crate) fn public_info(address: Url, info: BackendItemInfo) -> ObjectInfo {
    ObjectInfo {
        address,
        kind: info.kind,
        etag: info.etag,
        version: info.version,
        size: info.size,
        mtime: info.mtime,
        checksums: info.checksums,
        effective_permissions: info.effective_permissions,
        system_metadata: info.system_metadata,
        user_metadata: info.user_metadata,
        modified_by: info.modified_by,
    }
}

pub(crate) fn cached_info(address: Url, size: u64) -> ObjectInfo {
    ObjectInfo {
        address,
        kind: ObjectKind::File,
        etag: None,
        version: None,
        size: Some(size),
        mtime: None,
        checksums: ChecksumSet::default(),
        effective_permissions: None,
        system_metadata: None,
        user_metadata: None,
        modified_by: None,
    }
}

pub(crate) fn same_backend(left: &Route, right: &Route) -> bool {
    left.backend_id == right.backend_id && Arc::ptr_eq(&left.backend, &right.backend)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> ResolvedTarget {
        ResolvedTarget {
            backend_id: BackendId("s3".into()),
            resolved_address: Url::parse("s3://bucket/key").unwrap(),
        }
    }

    #[test]
    fn cache_key_separates_partitions() {
        let key_a = cache_key(&target(), "tenant-a");
        let key_b = cache_key(&target(), "tenant-b");
        assert_ne!(
            key_a, key_b,
            "different partitions must produce different cache keys"
        );
    }

    #[test]
    fn cache_key_same_partition_is_stable() {
        let a = cache_key(&target(), "local");
        let b = cache_key(&target(), "local");
        assert_eq!(a, b);
    }

    #[test]
    fn cache_key_partition_is_prefix() {
        let key = cache_key(&target(), "tenant-x");
        assert!(key.starts_with("tenant-x\0"));
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

    #[test]
    fn project_object_info_rewrites_under_resolved_prefix() {
        let caller = Url::parse("logical://team/dir/").unwrap();
        let resolved = Url::parse("s3://bucket/prefix/").unwrap();
        let info = make_object_info("s3://bucket/prefix/child.txt?versionId=1");

        let projected = project_object_info(&caller, &resolved, info, "list").unwrap();

        assert_eq!(
            projected.address.as_str(),
            "logical://team/dir/child.txt?versionId=1"
        );
    }

    #[test]
    fn project_object_info_rejects_addresses_outside_resolved_prefix() {
        let caller = Url::parse("logical://team/dir/").unwrap();
        let resolved = Url::parse("s3://bucket/prefix/").unwrap();
        let info = make_object_info("s3://bucket/other/child.txt");

        let err = project_object_info(&caller, &resolved, info, "list").unwrap_err();

        assert_eq!(err.code(), ErrorCode::Internal);
    }

    #[test]
    fn compose_change_event_projects_backend_address_to_caller_prefix() {
        let caller = Url::parse("logical://team/dir/").unwrap();
        let resolved = Url::parse("s3://bucket/prefix/").unwrap();
        let event = BackendChangeEvent::Object {
            address: Url::parse("s3://bucket/prefix/child.txt?versionId=1").unwrap(),
            kind: ChangeKind::Modified,
            etag: Some("etag-1".into()),
            version: Some("v1".into()),
            size: Some(42),
            mtime: None,
            at: UNIX_EPOCH,
            cursor: WatchDirectoryCursor(vec![7]),
        };

        let projected = compose_change_event(&caller, &resolved, event, None).unwrap();

        match projected {
            ChangeEvent::Object {
                address,
                kind,
                etag,
                version,
                size,
                cursor,
                ..
            } => {
                assert_eq!(address.as_str(), "logical://team/dir/child.txt?versionId=1");
                assert_eq!(kind, ChangeKind::Modified);
                assert_eq!(etag.as_deref(), Some("etag-1"));
                assert_eq!(version.as_deref(), Some("v1"));
                assert_eq!(size, Some(42));
                assert_eq!(cursor.0, vec![7]);
            }
            other => panic!("expected object change event, got {other:?}"),
        }
    }

    #[test]
    fn compose_change_event_rejects_backend_address_outside_resolved_prefix() {
        let caller = Url::parse("logical://team/dir/").unwrap();
        let resolved = Url::parse("s3://bucket/prefix/").unwrap();
        let event = BackendChangeEvent::Object {
            address: Url::parse("s3://bucket/other/child.txt").unwrap(),
            kind: ChangeKind::Modified,
            etag: None,
            version: None,
            size: None,
            mtime: None,
            at: UNIX_EPOCH,
            cursor: WatchDirectoryCursor(vec![]),
        };

        let err = compose_change_event(&caller, &resolved, event, None).unwrap_err();

        assert_eq!(err.code(), ErrorCode::Internal);
    }
}
