// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Built-in native `file://` backend.
//!
//! This module hosts the in-tree [`FileBackend`] and its factory, extracted
//! from `layers.rs` so the file backend can grow metadata/watch/owner logic
//! without crowding the router and wrapper machinery.

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use async_trait::async_trait;
use parking_lot::RwLock;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use url::Url;

use crate::address;
use crate::layers::{FILE_BACKEND_KIND, descriptor};
use crate::routing::{fresh_id, paginate_list_items};
use crate::*;

mod errors;
mod owner;
mod temp;
mod watch;

use errors::map_io;
use temp::{TempFileGuard, create_new_temp_sibling, is_atomic_write_temp_sibling};

#[derive(Default)]
pub struct FileBackendFactory;

/// Parse a `root` config value, accepted in two forms: a `file:` URL (the
/// native Layer contract) or a plain filesystem path (accepted by the host
/// connection schema, so roots like `/data/assets` must keep working).
fn root_url_from_config(raw: &str) -> Result<Url> {
    root_url_from_config_key(raw, "root")
}

/// [`root_url_from_config`] with the config key it is loading, so a diagnostic
/// names the field the operator wrote rather than always naming `root`. Both
/// keys accept both spellings and both go through this.
fn root_url_from_config_key(raw: &str, key: &str) -> Result<Url> {
    match Url::parse(raw) {
        Ok(url) if url.scheme().eq_ignore_ascii_case("file") => {
            // A `file:` URL here is a configuration address, so it is refused
            // for carrying a query or a fragment on the rule every config
            // loader in the workspace shares. `address::parse` would drop the
            // fragment and `is_ancestor_or_self` would pin the route to the
            // exact query, so neither is what the spelling reads like.
            //
            // The filesystem-path form below is NOT refused, and that is the
            // one place the rule bends rather than an oversight: there a `?` or
            // a `#` is an ordinary byte in a directory name, not a delimiter,
            // so the correct treatment is to escape it rather than to refuse a
            // legal path.
            if let Some(component) = address::refused_config_component(raw) {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    format!(
                        "file connection '{key}' must not carry a {}; an address names a \
                         node, and a file route is matched on its path alone. A filesystem \
                         path containing that character is accepted in the plain-path form",
                        component.name()
                    ),
                ));
            }
            // A `file:` URL whose first path segment reads as a Windows drive
            // letter parses with NO HOST: measured, `file://server/C:/data/`
            // becomes `file:///C:/data/`. `file_path` refuses an authority that
            // is not empty or `localhost`, but by the time it looks there is
            // none — so a root spelling a remote share installs and serves the
            // LOCAL disk of the same name, and on Windows a write or delete
            // beneath it lands on `C:\data`. Nothing later can reconstruct the
            // authority the parse destroyed, which is what makes this the
            // direction that cannot be undone.
            //
            // **Only the authority is asked about**, not the whole returned-
            // address contract. Normalizing a config address's PATH is what
            // `address::parse` is for, so a dot segment, a separator run or a
            // Windows `\` separator here is resolved rather than refused —
            // `file:///C:\data\` names the same local root as
            // `file:///C:/data/`, and both parse to one URL. And `file:/data/`
            // — a published spelling of a root, and the one this file's own
            // `route_address_from_config` doc uses as its example — has no
            // authority for either rewrite to move. The whole predicate refuses
            // all of them, which would break documented configurations to close
            // a hazard none of those spellings carries.
            //
            // The diagnostic says the address resolves to a DIFFERENT authority
            // rather than that it lost one: this refuses a host being created
            // and a host being moved as well as one being destroyed, and
            // `https:///h/x` or `file:\\server\share\x` never spelled an
            // authority to lose.
            if !ovstorage_layer::parsing_preserves_authority(raw) {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    format!(
                        "file connection '{key}' does not resolve to the authority its \
                         spelling names: {}. Write the address as it resolves, or correct \
                         it if that is not the node you meant",
                        address::parse(raw).map_or_else(
                            |_| "it does not parse as an address".to_string(),
                            |url| format!("it resolves to `{url}`"),
                        )
                    ),
                ));
            }
            address::parse(raw)
        }
        // A Windows drive path (`C:\data`, `C:/data`) parses as scheme `c`.
        Ok(_) if is_windows_drive_path(raw) => root_url_from_filesystem_path(raw),
        Ok(_) => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("file connection '{key}' must be a file: URL or a filesystem path"),
        )),
        Err(url::ParseError::RelativeUrlWithoutBase) => root_url_from_filesystem_path(raw),
        Err(error) => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("file connection '{key}' is not a valid URL: {error}"),
        )),
    }
}

/// Resolve the route (caller-facing) address a file connection contributes.
///
/// When the config carries a `prefix`, that prefix — not the broader
/// `root` — is the address the connection routes, so `root=/srv` +
/// `prefix=file:/srv/public/` exposes only `/srv/public`, never all of `/srv`.
/// The prefix must resolve strictly under `root` (realpath containment); a
/// cross-root or escaping prefix is rejected rather than silently widened.
/// With no `prefix`, the root itself is the route (unchanged behavior).
fn route_address_from_config(config: &LayerConfig, root: &Url) -> Result<Url> {
    match config.get("prefix") {
        None => Ok(root.clone()),
        Some(ConfigValue::String(raw)) => {
            let prefix = root_url_from_config_key(raw, "prefix")?;
            let prefix_path = file_path(&prefix)?;
            let root_path = file_path(root)?;
            let canonical_root = canonicalize_scope_root(&root_path)?;
            ensure_path_within_root(&prefix_path, &canonical_root).map_err(|error| {
                Error::new(
                    ErrorCode::InvalidArgument,
                    format!(
                        "file connection 'prefix' ({raw}) must resolve under the configured \
                         root ({}); cross-root rewriting is not supported: {}",
                        root_path.display(),
                        error.message()
                    ),
                )
            })?;
            Ok(prefix)
        }
        Some(_) => Err(Error::new(
            ErrorCode::InvalidArgument,
            "file connection 'prefix' must be a file: URL string",
        )),
    }
}

fn is_windows_drive_path(raw: &str) -> bool {
    let bytes = raw.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

/// Normalize a filesystem path into the canonical trailing-slash `file:` root.
///
/// **A filesystem path is not a URL, so every byte the URL parser would read as
/// structure is escaped before the string becomes one.** Those bytes are
/// ordinary characters in a directory name, and interpolating one into
/// `file:{path}` hands it to the parser as syntax. Two families, and the
/// parser treats them differently:
///
/// - `?` and `#` are delimiters. Measured, the unescaped form resolves
///   `/srv/da#ta` to `/srv/da` — the operator names one directory and is served
///   its parent — and `/srv/da?ta` to `/srv/da`.
/// - TAB, LF and CR are *removed* before the parser decides anything, so
///   `/srv/a<TAB>b` resolves to `/srv/ab`, a different directory with no
///   delimiter involved.
///
/// `%` is escaped first and for a third reason: it is what makes the other
/// escapes escapes, so escaping it afterwards would rewrite them. It also
/// stops `/srv/a%20b` resolving to `/srv/a b`, a directory that need not exist.
///
/// `/` is not escaped, because it is the separator in both grammars and that is
/// what makes this interpolation work at all.
///
/// **Two residuals, both stated rather than closed.**
///
/// A path beginning `//` opens an authority rather than a doubled separator, so
/// `//srv/x` parses with host `srv`. Nothing refuses it: with no `prefix`
/// configured the root is published as `file://srv/x/`, and since
/// `is_ancestor_or_self` compares hosts while every request address is
/// host-less, the connection is silently unroutable. Configure a `prefix` and
/// it becomes a load error instead, because `file_path` refuses a remote share.
///
/// A `\` is folded to `/` by the conversion below, unconditionally, and that
/// conversion is load-bearing for the Windows spellings this function exists to
/// accept — including the drive path the caller routes here. So on a platform
/// where `\` is an ordinary byte, `/srv/back\slash` resolves to
/// `/srv/back/slash`. Closing it needs the conversion gated on the running
/// platform, which makes one config file mean two things depending on where it
/// is loaded, and that is a decision above this function.
fn root_url_from_filesystem_path(raw: &str) -> Result<Url> {
    let mut path = raw
        .replace('\\', "/")
        .replace('%', "%25")
        .replace('?', "%3F")
        .replace('#', "%23")
        .replace('\t', "%09")
        .replace('\n', "%0A")
        .replace('\r', "%0D");
    if !path.starts_with('/') {
        path.insert(0, '/');
    }
    if !path.ends_with('/') {
        path.push('/');
    }
    address::parse(&format!("file:{path}"))
}

#[async_trait]
impl BackendFactory for FileBackendFactory {
    fn descriptor(&self) -> LayerKindDescriptor {
        file_descriptor()
    }

    async fn create_backend(
        &self,
        name: &str,
        config: &LayerConfig,
        _cancel: Option<CancellationToken>,
    ) -> Result<LayerHandle> {
        let roots = match config.get("root") {
            Some(ConfigValue::String(root)) => {
                // The static `[ovstorage.root]` / config-as-Stack path honors
                // the same `prefix` contract as `add_connection`: with a
                // `prefix`, the exposed route narrows to the prefix instead of
                // silently widening to all of `root`.
                let root = root_url_from_config(root)?;
                vec![route_address_from_config(config, &root)?]
            }
            Some(_) => {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    "file backend root config must be a string",
                ));
            }
            None if config.get("prefix").is_some() => {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    "file backend 'prefix' requires a 'root' to scope it",
                ));
            }
            None => Vec::new(),
        };
        // Opt-in realpath jail for the static-config root(s). Off by default
        // (virtual-tree model). `add_connection` parses the same key from each
        // connection's own config, so the policy is per root, not backend-wide.
        let confine_to_root = confine_to_root_from_config(config)?;
        let roots = roots
            .into_iter()
            .map(|url| RootScope {
                url,
                confine_to_root,
            })
            .collect();
        Ok(Arc::new(FileBackend {
            name: name.to_string(),
            roots: RwLock::new(roots),
            connections: RwLock::new(Vec::new()),
            target_locks: std::sync::Mutex::new(HashMap::new()),
        }))
    }
}

/// Parse the optional `confine_to_root` bool from a layer/connection config.
/// A wrong-typed value fails the build rather than silently disabling the jail
/// an operator asked for (matching the cache wrappers' convention). Shared by
/// [`FileBackendFactory::create_backend`] (static config) and
/// [`FileBackend::add_connection`] (per-connection config) so both parse and
/// reject identically.
fn confine_to_root_from_config(config: &LayerConfig) -> Result<bool> {
    match config.get("confine_to_root") {
        None => Ok(false),
        Some(ConfigValue::Bool(value)) => Ok(*value),
        Some(_) => Err(Error::new(
            ErrorCode::InvalidArgument,
            "file backend 'confine_to_root' must be a boolean",
        )),
    }
}

/// A served root plus the containment policy for addresses under it.
///
/// `confine_to_root` is stored **per root** (not backend-global) so the two
/// composition paths can carry different policies: the static
/// `[ovstorage.root]` / Stack config supplies it to
/// [`FileBackendFactory::create_backend`], while a runtime
/// [`FileBackend::add_connection`] reads it from the connection's own config —
/// and one backend serving several connections can mix policies. When `true`,
/// [`FileBackend::checked_path_for`] additionally enforces realpath containment
/// (an in-root symlink whose target resolves outside the root is denied with
/// `PermissionDenied`) and recursive `list`/`watch_directory` walkers re-jail
/// each descended directory. When `false` (the default) only lexical
/// containment applies and operator-configured in-root symlinks may redirect
/// outside the root — the "virtual tree" model (see the module note and
/// `docs/public/plugin-storage/plugin-file.md`). Default-off because no
/// client-facing SPI can create symlinks: the only links in a served tree are
/// ones the operator wired up on disk by explicit intent, so following them is
/// operator-controlled indirection, not a client-reachable escape.
#[derive(Clone)]
struct RootScope {
    url: Url,
    confine_to_root: bool,
}

type SelectedRootScope<'a> = Option<(&'a RootScope, PathBuf)>;
type ScopeResolution<'a> = (SelectedRootScope<'a>, Option<PathBuf>);

struct FileBackend {
    name: String,
    roots: RwLock<Vec<RootScope>>,
    connections: RwLock<Vec<Connection>>,
    /// Per-path async locks, interned on first use (see
    /// [`FileBackend::target_lock`]). Each mutex is held across a check-then-act
    /// sequence on its path so in-process precondition races on the same path
    /// serialize: `write_atomic`/`delete`/`create_directory`/
    /// `delete_directory` take a single path lock, while `copy`/`rename` take a
    /// source+destination pair in canonical order via
    /// [`FileBackend::lock_source_and_destination`]. Cross-process races on the
    /// same filesystem still need `renameat2(RENAME_NOREPLACE)`, not implemented
    /// here.
    target_locks: std::sync::Mutex<HashMap<PathBuf, Arc<Mutex<()>>>>,
}

#[async_trait]
impl Layer for FileBackend {
    fn name(&self) -> &str {
        &self.name
    }

    fn descriptor(&self) -> LayerKindDescriptor {
        file_descriptor()
    }

    async fn root_info_for(
        &self,
        url: &Url,
        _cx: &Extensions,
        cancel: Option<CancellationToken>,
    ) -> Result<RootInfo> {
        bail_if_cancelled(&cancel)?;
        #[cfg(windows)]
        if self.roots.read().is_empty() {
            if !is_file_scheme_root(url) {
                self.checked_path_for(url)?;
            }
            return Ok(self.root_info(file_scheme_root()));
        }
        // NOT unconditionally no-I/O: the scope scan itself is an in-memory
        // read, but `checked_path_for` performs bounded `canonicalize`
        // syscalls for any root configured with `confine_to_root` (see
        // `checked_scope_for`). That is inline blocking work on an executor
        // thread — the same shape every other slot in this backend has, not
        // something this slot does differently — so `cancel` is honoured at
        // entry only, and cannot interrupt a walk already under way.
        let (_, _, selected_root) = self.checked_scope_for_root(url)?;
        selected_root
            .map(|root| self.root_info(root))
            .ok_or_else(|| Error::new(ErrorCode::NoRoute, "no file root matches address"))
    }

    async fn list_address_roots(
        &self,
        _cx: &Extensions,
        cancel: Option<CancellationToken>,
    ) -> Result<(RootInfoSnapshot, Option<RootInfoUpdateStream>)> {
        bail_if_cancelled(&cancel)?;
        // In-memory snapshot of the configured root scopes; no filesystem
        // access, so past the entry check there is nothing left to interrupt.
        #[cfg(windows)]
        if self.roots.read().is_empty() {
            return Ok((
                RootInfoSnapshot {
                    roots: vec![self.root_info(file_scheme_root())],
                    updates: false,
                },
                None,
            ));
        }
        Ok((
            RootInfoSnapshot {
                roots: self
                    .roots
                    .read()
                    .iter()
                    .map(|scope| self.root_info(scope.url.clone()))
                    .collect(),
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
        #[cfg(windows)]
        if self.roots.read().is_empty() && is_file_scheme_root(&request.input.address) {
            return Ok(synthetic_directory_info(file_scheme_root()));
        }
        let path = self.checked_path_for(&request.input.address)?;
        stat_path(
            &request.input.address,
            &path,
            request.input.options.full_metadata,
        )
        .await
    }

    async fn read(
        &self,
        request: Request<ReadRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<ReadResult> {
        let path = self.checked_path_for(&request.input.address)?;
        // Single stat: feed the same metadata to special-file rejection and the
        // info/etag/owner computation so the read path never stats twice.
        let metadata = tokio::fs::metadata(&path).await.map_err(map_io)?;
        owner::reject_special_file(&metadata)?;
        // Ahead of the if_match and range branches so every arm agrees: a
        // directory is a type mismatch. The ranged arm needs the guard most —
        // Linux permits a read-only `open(2)` of a directory, so
        // `open_ranged_stream` succeeds and the EISDIR only surfaces when the
        // caller polls the first chunk, a half-established stream failing far
        // from the call that asked for it.
        reject_directory_target(&metadata, "read target is a directory; use list()")?;
        let len = metadata.len();
        let info = stat_path_with_meta(&request.input.address, &path, metadata, true).await?;
        if request
            .input
            .options
            .if_match
            .as_ref()
            .zip(info.etag.as_ref())
            .is_some_and(|(expected, actual)| expected != actual)
        {
            return Err(Error::new(ErrorCode::ObjectModified, "etag mismatch"));
        }
        // A ranged read streams ONLY the requested window off disk via
        // `open_ranged_stream` (matching the cdylib), never materializing the
        // whole object. A whole-object read returns a `LocalDelegate`, which
        // the broker's raw-read path streams directly (it
        // streams the delegate itself; buffering callers like `read_bytes`
        // are bulk-buffered by the byte-cache wrapper instead).
        if let Some(range) = request.input.options.range {
            let stream = open_ranged_stream(&path, len, range).await?;
            return Ok(ReadResult::Stream { stream, info });
        }
        Ok(ReadResult::LocalDelegate(LocalDelegate {
            path,
            info,
            guard: None,
        }))
    }

    async fn materialize(
        &self,
        request: Request<ReadRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<LocalDelegate> {
        let path = self.checked_path_for(&request.input.address)?;
        // Mirror `read`'s guard: a host that opens the returned delegate would
        // otherwise block on a FIFO/device. One stat feeds both the special-
        // file rejection and the info, so the materialize path never stats twice.
        let metadata = tokio::fs::metadata(&path).await.map_err(map_io)?;
        owner::reject_special_file(&metadata)?;
        reject_directory_target(&metadata, "materialize target is a directory; use list()")?;
        Ok(LocalDelegate {
            path: path.clone(),
            info: stat_path_with_meta(&request.input.address, &path, metadata, true).await?,
            guard: None,
        })
    }

    async fn write(
        &self,
        request: Request<WriteRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        let path = self.checked_path_for(&request.input.address)?;
        self.write_atomic(
            &request.input.address,
            &path,
            request.input.options,
            request.input.body,
        )
        .await
    }

    async fn write_stream(
        &self,
        request: Request<WriteRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        self.write(request, cancel).await
    }

    async fn delete(
        &self,
        request: Request<DeleteRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let path = self.checked_path_for(&request.input.address)?;
        // Hold the target lock across the if_match check and the unlink so a
        // concurrent write/rename can't slip between the etag check and the
        // remove (the same check-then-act class write_atomic closes).
        let lock = self.target_lock(&path);
        let _guard_lock = lock.lock().await;
        // delete is idempotent: a missing target is success, and a
        // precondition on a missing target is satisfied vacuously.
        let mut target_missing = false;
        if let Some(expected) = &request.input.options.if_match {
            match tokio::fs::metadata(&path).await {
                Ok(_) => {
                    let info = stat_path(&request.input.address, &path, false).await?;
                    if info.etag.as_ref() != Some(expected) {
                        return Err(Error::new(ErrorCode::PreconditionFailed, "etag mismatch"));
                    }
                }
                Err(err) if err.kind() == io::ErrorKind::NotFound => target_missing = true,
                Err(err) => return Err(map_io(err)),
            }
        }
        if !target_missing {
            match tokio::fs::remove_file(&path).await {
                Ok(()) => {}
                Err(err) if err.kind() == io::ErrorKind::NotFound => {}
                Err(err) => {
                    if let Some(mismatch) = leaf_type_mismatch(
                        &path,
                        false,
                        "delete target is a directory; use delete_directory()",
                    )
                    .await
                    {
                        return Err(mismatch);
                    }
                    return Err(map_io(err));
                }
            }
        }
        Ok(())
    }

    async fn list(
        &self,
        request: Request<ListRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<ListPage> {
        #[cfg(windows)]
        if self.roots.read().is_empty() && is_file_scheme_root(&request.input.prefix) {
            reject_recursive_synthetic_root_list(&request.input.options)?;
            return paginate_list_items(
                windows_drive_roots()?,
                request.input.options.max_results,
                request.input.options.page_token,
            );
        }
        let mut items = Vec::new();
        let (prefix_path, confine_root) = self.checked_scope_for(&request.input.prefix)?;
        if let Err(err) = collect_file_list(
            prefix_path.clone(),
            request.input.options.recursive,
            request.input.options.full_metadata,
            confine_root.as_deref(),
            &mut items,
        )
        .await
        {
            // Only the prefix itself is probed: a wrong-shaped component
            // deeper in a recursive descent still surfaces the mapped error.
            if let Some(mismatch) =
                leaf_type_mismatch(&prefix_path, true, "list prefix is a file, not a directory")
                    .await
            {
                return Err(mismatch);
            }
            return Err(err);
        }
        items.sort_by(|left, right| left.address.as_str().cmp(right.address.as_str()));
        paginate_list_items(
            items,
            request.input.options.max_results,
            request.input.options.page_token,
        )
    }

    async fn list_stream(
        &self,
        request: Request<ListRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ListStream> {
        #[cfg(windows)]
        if self.roots.read().is_empty()
            && is_file_scheme_root(&request.input.prefix)
            && request.input.options.recursive
        {
            reject_recursive_synthetic_root_list(&request.input.options)?;
        }
        if request.input.options.max_results.is_some() || request.input.options.page_token.is_some()
        {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "list_stream does not accept max_results or page_token",
            ));
        }
        bail_if_cancelled(&cancel)?;

        #[cfg(windows)]
        if self.roots.read().is_empty() && is_file_scheme_root(&request.input.prefix) {
            let stream = futures::stream::iter(windows_drive_roots()?.into_iter().map(Ok));
            return Ok(cancel_list_stream(Box::pin(stream), cancel));
        }

        let (prefix_path, confine_root) = self.checked_scope_for(&request.input.prefix)?;
        let recursive = request.input.options.recursive;
        let full_metadata = request.input.options.full_metadata;
        let stream_cancel = cancel.clone();
        let stream = async_stream::try_stream! {
            // Keep one live cursor per active DFS level. `ReadDir` performs a
            // bounded pull from the operating system, so a wide directory can
            // yield its first entry without retaining all of its children.
            // File roots have real directories, so their streams may preserve
            // the filesystem's natural traversal order.
            let root_directory = match tokio::fs::read_dir(&prefix_path).await {
                Ok(directory) => directory,
                Err(err) => {
                    // Match buffered `list`'s leaf diagnostic while leaving
                    // failures discovered below the prefix untouched.
                    if let Some(mismatch) = leaf_type_mismatch(
                        &prefix_path,
                        true,
                        "list prefix is a file, not a directory",
                    )
                    .await
                    {
                        Err(mismatch)?;
                    }
                    Err(map_io(err))?
                }
            };
            let mut directories = vec![root_directory];

            while let Some(entry_path) = next_file_list_path(
                &mut directories,
                confine_root.as_deref(),
                &stream_cancel,
            )
            .await?
            {
                bail_if_cancelled(&stream_cancel)?;
                let address = path_to_file_url(&entry_path)?;
                let info = stat_path(&address, &entry_path, full_metadata).await?;
                bail_if_cancelled(&stream_cancel)?;
                let is_directory = info.kind.is_directory();

                // `yield` is the backpressure boundary. No child directory is
                // opened until the consumer asks for the next entry.
                yield info;

                if recursive && is_directory {
                    bail_if_cancelled(&stream_cancel)?;
                    directories.push(tokio::fs::read_dir(entry_path).await.map_err(map_io)?);
                }
            }
        };
        Ok(cancel_list_stream(Box::pin(stream), cancel))
    }

    async fn watch_directory(
        &self,
        request: Request<WatchDirectoryRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ChangeStream> {
        let (root, confine_root) = self.checked_scope_for(&request.input.prefix)?;
        let base_address = address::to_directory(&request.input.prefix)?;
        let options = request.input.options;
        // The initial snapshot is synchronous (the stream is a blocking
        // sync-Iterator), so take it off the async executor on the blocking
        // pool rather than stalling a worker thread. `confine_root` (Some when
        // the matched root armed the jail) re-jails every descended directory so
        // a poll snapshot cannot enumerate an escaping in-root symlink's target.
        let stream = tokio::task::spawn_blocking(move || {
            watch::FileChangeStream::new(root, base_address, options, confine_root, cancel)
        })
        .await
        .map_err(|join_err| {
            Error::new(
                ErrorCode::Internal,
                format!("watch_directory initial scan task: {join_err}"),
            )
        })??;
        Ok(Box::new(stream))
    }

    async fn get_latest_version(
        &self,
        request: Request<ReadRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        let path = self.checked_path_for(&request.input.address)?;
        stat_path(&request.input.address, &path, true).await
    }

    async fn create_directory(
        &self,
        request: Request<CreateDirectoryRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<BackendItemInfo> {
        let path = self.checked_path_for(&request.input.address)?;
        // A directory address shares the per-path lock with `delete_directory`
        // so a recreate cannot interleave with a removal of the same path.
        let lock = self.target_lock(&path);
        let _guard_lock = lock.lock().await;
        tokio::fs::create_dir_all(&path).await.map_err(map_io)?;
        Ok(stat_path(&request.input.address, &path, true).await?.into())
    }

    async fn delete_directory(
        &self,
        request: Request<DeleteDirectoryRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let path = self.checked_path_for(&request.input.address)?;
        // Hold the per-path lock across the empty check and the dir removal so
        // a concurrent `create_directory` on the same address serializes with
        // the removal instead of interleaving with it.
        let lock = self.target_lock(&path);
        let _guard_lock = lock.lock().await;
        // `rmdir` on a link fails with ENOTDIR, which `map_io` maps to NotFound.
        // Refuse rather than unlink: no API can create this operator-configured
        // state, so the link is not this backend's to remove or follow.
        if let Ok(metadata) = tokio::fs::symlink_metadata(&path).await
            && metadata.file_type().is_symlink()
        {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "delete_directory target is a symlink; the entry is operator-configured on disk and delete_directory will not remove or follow it",
            )
            .with_next_action(
                "remove the link on the host filesystem, or address the link's target directly",
            ));
        }
        let mut entries = match tokio::fs::read_dir(&path).await {
            Ok(entries) => entries,
            Err(err) => {
                if let Some(mismatch) = leaf_type_mismatch(
                    &path,
                    true,
                    "delete_directory target is a file; use delete()",
                )
                .await
                {
                    return Err(mismatch);
                }
                return Err(map_io(err));
            }
        };
        // Every entry blocks the removal, so for the entries the API can create
        // this scan's verdict matches the one `remove_dir` will reach. A
        // same-directory atomic-write staging temp — hidden from `list`/`watch`,
        // but a real entry to the kernel — is set aside and decided by the lock
        // its writer holds: a live write refuses the removal as the
        // `DirectoryNotEmpty` it is, and a temp left by a writer that died is
        // cleared. Both verdicts are reached before anything is touched. Only a
        // name the backend's own generator can emit is set aside; any other
        // entry, hidden or not — a `.ovstorage-meta` directory included — keeps
        // the honest `DirectoryNotEmpty`.
        let mut staging = Vec::new();
        while let Some(entry) = entries.next_entry().await.map_err(map_io)? {
            let entry_path = entry.path();
            if temp::is_clearable_staging_temp(&entry_path) {
                staging.push(entry_path);
                continue;
            }
            return Err(Error::new(
                ErrorCode::DirectoryNotEmpty,
                "directory is not empty",
            ));
        }
        temp::clear_orphaned_staging_temps(&staging).await?;
        tokio::fs::remove_dir(&path).await.map_err(map_io)
    }

    async fn copy(
        &self,
        request: Request<CopyRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteStep> {
        let source = self.checked_path_for(&request.input.source)?;
        let destination = self.checked_path_for(&request.input.destination)?;
        // Hold BOTH the source and destination locks across the whole operation,
        // acquired in canonical order to avoid an ABBA deadlock between a
        // copy(A→B) and a concurrent copy(B→A). The source lock keeps the
        // if_source etag from being invalidated before the bytes are read; the
        // destination lock serializes the if_dest check→commit (as before).
        let _guards = self
            .lock_source_and_destination(&source, &destination)
            .await;
        if let Some(expected) = &request.input.options.if_source {
            let info = stat_path(&request.input.source, &source, false).await?;
            if info.etag.as_ref() != Some(expected) {
                return Err(Error::new(ErrorCode::PreconditionFailed, "etag mismatch"));
            }
        }
        apply_destination_precondition(&destination, &request.input.options.if_dest).await?;
        // Reject a special-file source (fifo/socket/device) before opening it:
        // `tokio::fs::copy` follows to the target and would block a worker
        // indefinitely on a fifo. `metadata` follows symlinks so we inspect the
        // effective object that would actually be read (an in-root symlink is
        // followed to its target, which is exactly the virtual-tree model
        // unless `confine_to_root` re-arms the realpath jail in
        // `checked_path_for`).
        let source_metadata = tokio::fs::metadata(&source).await.map_err(map_io)?;
        owner::reject_special_file(&source_metadata)?;
        if let Some(parent) = destination.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(map_io)?;
        }
        // Commit the destination through the same O_EXCL temp sibling + rename
        // as `write_atomic`. `tokio::fs::copy` opens the destination
        // O_CREAT|O_TRUNC and therefore FOLLOWS a final-component symlink; the
        // temp+rename commit instead REPLACES the final-component link entry, so
        // a `copy` never writes through a final-component symlink regardless of
        // the `confine_to_root` setting. A directory symlink earlier in the path
        // (`vdir -> /data/real`) is still followed, so `copy served/vdir/obj`
        // lands in `/data/real/obj` — the intended operator-configured virtual
        // tree, not an escape (the write path has always behaved this way).
        // Honor the caller's cancellation token while staging: a large copy
        // must abort promptly rather than run to completion after the request
        // is cancelled (the armed guard removes the partial temp file).
        let (tmp, tmp_file) = create_new_temp_sibling(&destination).await?;
        let guard = TempFileGuard::arm(tmp.clone());
        let stage_future = write_body(tmp_file, Body::LocalFile(source.clone()));
        let staged = match &cancel {
            Some(token) => {
                tokio::select! {
                    biased;
                    () = token.cancelled() => {
                        return Err(Error::new(ErrorCode::Cancelled, "copy cancelled by caller"));
                    }
                    result = stage_future => result?,
                }
            }
            None => stage_future.await?,
        };
        // Re-check `if_source` against the staged bytes before committing. The
        // source lock excludes only writers inside this process, so an external
        // writer can replace the source between the pre-read check above and
        // the read that just finished. Detecting that here costs one stat and
        // leaves the destination untouched — the armed guard removes the staged
        // temp — instead of committing content that never matched the caller's
        // precondition. The check narrows the window rather than closing it: a
        // writer racing this stat still wins.
        if let Some(expected) = &request.input.options.if_source {
            let info = stat_path(&request.input.source, &source, false).await?;
            if info.etag.as_ref() != Some(expected) {
                return Err(Error::new(
                    ErrorCode::ObjectModified,
                    "source modified during copy",
                ));
            }
        }
        // Mirror `tokio::fs::copy`'s permission propagation before the commit.
        tokio::fs::set_permissions(&tmp, source_metadata.permissions())
            .await
            .map_err(map_io)?;
        tokio::fs::rename(&tmp, &destination)
            .await
            .map_err(map_io)?;
        // The handle, and the lock it carries, close once the rename has
        // published; the lock's range never overlaps content, so a reader that
        // already found the object is unaffected.
        drop(staged);
        guard.commit();
        sync_parent(&destination).await?;
        // `CopyOptions.message` is a per-operation annotation this backend has
        // nowhere to keep; the contract lets a backend drop it.
        Ok(WriteStep::Done(WriteResult {
            info: stat_path(&request.input.destination, &destination, true).await?,
        }))
    }

    async fn rename(
        &self,
        request: Request<RenameRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let source = self.checked_path_for(&request.input.source)?;
        let destination = self.checked_path_for(&request.input.destination)?;
        // Hold BOTH the source and destination locks across the whole operation,
        // acquired in canonical order to avoid an ABBA deadlock between a
        // rename(A→B) and a concurrent rename/copy(B→A). The source lock keeps
        // the if_source etag from being invalidated before the move; the
        // destination lock serializes the if_dest check→commit (as before).
        let _guards = self
            .lock_source_and_destination(&source, &destination)
            .await;
        if let Some(expected) = &request.input.options.if_source {
            let info = stat_path(&request.input.source, &source, false).await?;
            if info.etag.as_ref() != Some(expected) {
                return Err(Error::new(ErrorCode::PreconditionFailed, "etag mismatch"));
            }
        }
        apply_destination_precondition(&destination, &request.input.options.if_dest).await?;
        if let Some(parent) = destination.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(map_io)?;
        }
        // `RenameOptions.message` is dropped for the same reason as in `copy`.
        tokio::fs::rename(&source, &destination)
            .await
            .map_err(map_io)
    }

    async fn update_metadata(
        &self,
        request: Request<UpdateMetadataRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<BackendItemInfo> {
        // The address is still validated so a malformed or out-of-scope URL
        // reports its own error rather than a blanket `Unsupported`.
        self.checked_path_for(&request.input.address)?;
        Err(unsupported_user_metadata("update_metadata"))
    }

    async fn check_access(
        &self,
        request: Request<CheckAccessRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<AccessDecision> {
        let path = self.checked_path_for(&request.input.address)?;
        // SPI: check_access on a missing target returns NotFound, not an empty
        // AccessDecision. An errored probe (e.g. a permission failure walking to
        // the target) must propagate, not be reported as a clean NotFound or, on
        // the metadata reads below, masquerade as `allowed`.
        match tokio::fs::try_exists(&path).await {
            Ok(true) => {}
            Ok(false) => return Err(Error::new(ErrorCode::NotFound, "file does not exist")),
            Err(err) => return Err(map_io(err)),
        }
        let ops = request.input.operations;
        let mut denied_ops = AccessOps::default();
        let readonly = tokio::fs::metadata(&path)
            .await
            .map_err(map_io)?
            .permissions()
            .readonly();
        // Delete unlinks the dentry from the PARENT directory, so a read-only
        // parent denies delete even when the file itself is writable.
        let parent_readonly = match path.parent() {
            Some(parent) => tokio::fs::metadata(parent)
                .await
                .map_err(map_io)?
                .permissions()
                .readonly(),
            None => false,
        };
        if ops.write && readonly {
            denied_ops.write = true;
        }
        if ops.delete && (readonly || parent_readonly) {
            denied_ops.delete = true;
        }
        if ops.update_metadata && readonly {
            denied_ops.update_metadata = true;
        }
        let allowed = denied_ops == AccessOps::default();
        Ok(AccessDecision {
            allowed,
            denied_ops,
            reason: if allowed {
                None
            } else {
                Some("filesystem metadata denies at least one requested operation".into())
            },
        })
    }

    async fn add_connection(
        &self,
        request: Request<LayerConnectionRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<Connection> {
        if request.input.target != self.name {
            return Err(Error::new(ErrorCode::NotFound, "target layer not found"));
        }
        let root =
            request.input.connection.config.get("root").ok_or_else(|| {
                Error::new(ErrorCode::InvalidArgument, "file connection needs root")
            })?;
        let root = match root {
            ConfigValue::String(raw) => root_url_from_config(raw)?,
            _ => {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    "file connection root must be a string",
                ));
            }
        };
        // The route the connection contributes is the `prefix` (validated to be
        // within `root`) when present, else the root itself. Scoping both the
        // advertised route and the containment scope to the prefix keeps a
        // legacy `prefix` config from widening into a route for all of `root`.
        let route = route_address_from_config(&request.input.connection.config, &root)?;
        // Per-connection realpath jail: the same key `create_backend` reads for
        // static config, parsed (and wrong-type-rejected) here so a brokered
        // deployment can arm the jail on the connection it adds at runtime — the
        // path all connection-driven compositions take (the backend is built
        // with an empty config, then this contributes the root + its policy).
        let confine_to_root = confine_to_root_from_config(&request.input.connection.config)?;
        let connection = Connection {
            id: ConnectionId(fresh_id("file")),
            backend_kind: FILE_BACKEND_KIND.to_string(),
            display_name: request
                .input
                .connection
                .display_name
                .unwrap_or_else(|| "File".to_string()),
            source: ConnectionSource::Runtime {
                persisted: request.input.connection.persist,
            },
            capabilities: file_capabilities(),
            current_addresses: vec![route.clone()],
            auth_state: ConnectionAuthState::Anonymous,
            last_probed: Some(SystemTime::now()),
            user_metadata: UserMetadata::new(),
            // This layer owns the connection, and its instance name is the
            // `ConnectionKey::target` that reaches it -- the same name
            // `owned_targets` reports and `remove_connection` gates on. Stamped
            // at construction so the row carries it wherever it goes, including
            // out of `ConnectionSet`'s change stream.
            owning_target: Some(self.name.clone()),
        };
        self.connections.write().push(connection.clone());
        self.roots.write().push(RootScope {
            url: route,
            confine_to_root,
        });
        Ok(connection)
    }

    async fn list_connections(
        &self,
        _cx: &Extensions,
        cancel: Option<CancellationToken>,
    ) -> Result<(ConnectionSnapshot, Option<ConnectionUpdateStream>)> {
        bail_if_cancelled(&cancel)?;
        // In-memory snapshot read of the connection list; no filesystem
        // access, so past the entry check there is nothing left to interrupt.
        Ok((
            ConnectionSnapshot {
                connections: self.connections.read().clone(),
                updates: false,
            },
            None,
        ))
    }
}

impl FileBackend {
    fn checked_path_for(&self, url: &Url) -> Result<PathBuf> {
        Ok(self.checked_scope_for(url)?.0)
    }

    fn scopes_for_path<'a>(path: &Path, roots: &'a [RootScope]) -> Result<ScopeResolution<'a>> {
        let mut selected = None;
        let mut tightest_confine = None;
        for scope in roots {
            // A root URL that cannot name a native path is unroutable. It must
            // not make every otherwise valid root fail to resolve.
            let Ok(root_path) = file_path(&scope.url).map(|path| normalize_path(&path)) else {
                continue;
            };
            if path.starts_with(&root_path) {
                if scope.confine_to_root {
                    let canonical_root = canonicalize_scope_root(&root_path)?;
                    ensure_path_within_root(path, &canonical_root)?;
                    if tightest_confine.as_ref().is_none_or(|existing: &PathBuf| {
                        canonical_root.components().count() > existing.components().count()
                    }) {
                        tightest_confine = Some(canonical_root);
                    }
                }
                let is_longer = selected.as_ref().is_none_or(
                    |(existing_scope, existing_root): &(&RootScope, PathBuf)| {
                        let depth = root_path.components().count();
                        let existing_depth = existing_root.components().count();
                        depth > existing_depth
                            || (depth == existing_depth
                                && scope.confine_to_root
                                && !existing_scope.confine_to_root)
                    },
                );
                if is_longer {
                    selected = Some((scope, root_path));
                }
            }
        }
        Ok((selected, tightest_confine))
    }

    /// Resolve and namespace-check `url`, returning the native path and — when
    /// the matched root is in `confine_to_root` mode — its canonicalized root so
    /// recursive `list`/`watch_directory` walkers can re-jail each descended
    /// directory (a plain `checked_path_for` only jails the addressed path
    /// itself, not the entries a recursive walk discovers through it).
    fn checked_scope_for(&self, url: &Url) -> Result<(PathBuf, Option<PathBuf>)> {
        let (path, confine_root, _) = self.checked_scope_for_root(url)?;
        Ok((path, confine_root))
    }

    fn checked_scope_for_root(&self, url: &Url) -> Result<(PathBuf, Option<PathBuf>, Option<Url>)> {
        let path = normalize_path(&file_path(url)?);
        // An atomic-write temp sibling is backend-internal: it is a write in
        // flight, not an object, so a caller cannot address one directly.
        if is_atomic_write_temp_sibling(&path) {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "file URL addresses backend-internal storage",
            ));
        }
        let roots = self.roots.read();
        if roots.is_empty() {
            return Ok((path, None, None));
        }
        let (selected, confine_root) = Self::scopes_for_path(&path, &roots)?;
        let Some((scope, _)) = selected else {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "file URL is outside the configured roots",
            ));
        };
        Ok((path, confine_root, Some(scope.url.clone())))
    }

    fn root_info(&self, root: Url) -> RootInfo {
        let connection_id = self
            .connections
            .read()
            .iter()
            .find(|connection| connection.current_addresses.contains(&root))
            .map(|connection| connection.id.clone());
        let capabilities = file_capabilities();
        RootInfo {
            root,
            display_name: None,
            layer_kind: FILE_BACKEND_KIND.to_string(),
            source: root_source(connection_id.clone()),
            // A connection-owned root is reached by this backend's instance
            // name; a static root has no owning connection.
            owning_target: connection_id.as_ref().map(|_| self.name().to_string()),
            connection_id,
            capabilities,
            range_read_strategy: RangeReadStrategy::Native,
            visible: true,
            visibility: AddressVisibility::Visible,
            alias_state: None,
            icon: None,
            user_metadata: UserMetadata::new(),
        }
    }

    /// Per-path async mutex, created on first use. Held across a check-then-act
    /// sequence on `path` so in-process precondition races serialize:
    /// `write_atomic`/`delete`/`create_directory`/
    /// `delete_directory` take this single lock; `copy`/`rename` take a
    /// source+destination pair via [`FileBackend::lock_source_and_destination`].
    ///
    /// Known limitation: the map interns one mutex per distinct path ever
    /// touched by a mutating op and never evicts, so a long-lived backend over
    /// an unbounded stream of distinct paths grows memory slowly. Bounding it
    /// (evict when `Arc::strong_count` returns to 1 under the map lock, or a
    /// fixed sharded lock pool keyed by path hash) is a tracked follow-up,
    /// alongside the cross-process `renameat2(RENAME_NOREPLACE)` gap.
    fn target_lock(&self, path: &Path) -> Arc<Mutex<()>> {
        let mut map = self.target_locks.lock().expect("target_locks poisoned");
        map.entry(path.to_path_buf())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    /// Acquire the per-target locks for `source` and `destination` together, in
    /// a canonical (path-sorted) order, so two concurrent two-path operations —
    /// e.g. a `copy`/`rename` of A→B and a concurrent one of B→A — cannot
    /// deadlock by taking the same pair in opposite orders. When both resolve to
    /// the same path a single lock is taken once. The returned guards must be
    /// held for the whole operation.
    async fn lock_source_and_destination(
        &self,
        source: &Path,
        destination: &Path,
    ) -> Vec<tokio::sync::OwnedMutexGuard<()>> {
        if source == destination {
            return vec![self.target_lock(source).lock_owned().await];
        }
        let (first, second) = if source < destination {
            (source, destination)
        } else {
            (destination, source)
        };
        // Acquire low→high path order regardless of which is source vs. dest.
        let first = self.target_lock(first).lock_owned().await;
        let second = self.target_lock(second).lock_owned().await;
        vec![first, second]
    }

    /// Write via temp-sibling + fsync + rename so observers never see a partial
    /// file. The rename is the only commit, so `writes_are_atomic` covers the
    /// whole write.
    ///
    /// A non-empty `user_metadata` is refused before anything touches the
    /// filesystem: this backend stores none, and the contract requires a
    /// refusal rather than a write that silently drops the caller's map.
    /// `message` is a per-operation annotation the contract lets a backend
    /// drop, and this one does.
    ///
    /// In-process if-match / no-overwrite races are closed by a per-destination
    /// async mutex held across the precondition check and the rename. Cross-
    /// process races on the same filesystem still need
    /// `renameat2(RENAME_NOREPLACE)`, not implemented here.
    async fn write_atomic(
        &self,
        address: &Url,
        path: &Path,
        options: WriteOptions,
        body: Body,
    ) -> Result<WriteResult> {
        reject_user_metadata(&options)?;
        // A write creates its path: missing ancestors are created before the commit.
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(map_io)?;
        }
        // Fail-fast: reject a doomed conditional write (IfDestExists::Fail or an
        // etag mismatch) before draining the body, so a precondition that is
        // already unsatisfiable does not burn disk/IO staging bytes that will
        // only be discarded. This is a best-effort preflight; the authoritative
        // check happens again under the per-target lock below to close the
        // in-process race.
        apply_destination_precondition(path, &options.if_dest).await?;
        let (tmp, tmp_file) = create_new_temp_sibling(path).await?;
        let guard = TempFileGuard::arm(tmp.clone());
        // Write through the O_EXCL handle returned by create-new rather than
        // reopening by path, so a same-dir writer cannot swap the entry between
        // create and write and have us truncate through to whatever now sits
        // there.
        let staged = write_body(tmp_file, body).await?;
        let lock = self.target_lock(path);
        let _guard_lock = lock.lock().await;
        apply_destination_precondition(path, &options.if_dest).await?;
        tokio::fs::rename(&tmp, path).await.map_err(map_io)?;
        // The handle, and the lock it carries, close once the rename has
        // published; the lock's range never overlaps content, so a reader that
        // already found the object is unaffected.
        drop(staged);
        guard.commit();
        sync_parent(path).await?;
        Ok(WriteResult {
            info: stat_path(address, path, true).await?,
        })
    }
}

/// Fill the open, O_EXCL temp-sibling handle (from [`create_new_temp_sibling`])
/// with `body` bytes and fsync them to disk so the subsequent rename commits
/// durable content. Writing through the handle the create-new call returned —
/// rather than reopening the temp by path — preserves the O_EXCL exclusivity:
/// there is no create-then-reopen window for a same-dir writer to slip a
/// different entry under the path. The handle is returned still open, carrying
/// the advisory lock that marks the write live to a directory removal probing
/// the name; the caller drops it once the rename has published the bytes.
/// Rust opens with `FILE_SHARE_DELETE` on Windows, so the rename does not
/// contend with the open handle.
async fn write_body(mut file: tokio::fs::File, body: Body) -> Result<tokio::fs::File> {
    match body {
        Body::Bytes(bytes) => {
            file.write_all(&bytes).await.map_err(map_io)?;
        }
        Body::LocalFile(source) => {
            let mut source = tokio::fs::File::open(source).await.map_err(map_io)?;
            tokio::io::copy(&mut source, &mut file)
                .await
                .map_err(map_io)?;
        }
        Body::Stream(mut stream) => {
            while let Some(chunk) = stream.next_chunk() {
                file.write_all(&chunk?).await.map_err(map_io)?;
            }
        }
    }
    file.sync_all().await.map_err(map_io)?;
    Ok(file)
}

/// Refuse a write that carries caller metadata this backend cannot keep. Keyed
/// on `user_metadata` alone: `message` is an annotation the contract lets a
/// backend drop, so a message-only write proceeds.
fn reject_user_metadata(options: &WriteOptions) -> Result<()> {
    if options
        .user_metadata
        .as_ref()
        .is_some_and(|metadata| !metadata.is_empty())
    {
        return Err(unsupported_user_metadata("write"));
    }
    Ok(())
}

/// The refusal every user-metadata entry point on this backend returns, worded
/// per verb so the remedy is one the caller can act on: a `write` can drop its
/// map, while `update_metadata` has no map to drop and can only go elsewhere.
/// The message text matches the C baseline's word for word.
fn unsupported_user_metadata(op: &str) -> Error {
    let (message, next_action) = match op {
        "write" => (
            "file write: backend stores no user metadata; drop user_metadata or target a \
             backend that supports it",
            "write the object without user_metadata, or route it to a backend whose kind \
             declares user-metadata support",
        ),
        _ => (
            "file update_metadata: backend stores no user metadata; target a backend that \
             supports it",
            "route the object to a backend whose kind declares user-metadata support",
        ),
    };
    Error::new(ErrorCode::Unsupported, message).with_next_action(next_action)
}

/// fsync the parent directory after a rename so the directory entry for the
/// renamed file is durable, not just the file's own data.
async fn sync_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        sync_directory(parent).await?;
    }
    Ok(())
}

#[cfg(not(windows))]
async fn sync_directory(path: &Path) -> Result<()> {
    let file = tokio::fs::File::open(path).await.map_err(map_io)?;
    file.sync_all().await.map_err(map_io)
}

#[cfg(windows)]
async fn sync_directory(path: &Path) -> Result<()> {
    // `tokio::fs::OpenOptions::custom_flags` is an inherent method on Windows,
    // so no `OpenOptionsExt` trait import is needed (importing it trips
    // `unused_imports` under `-D warnings`).
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    let file = tokio::fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
        .await
        .map_err(map_io)?;
    match file.sync_all().await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => Ok(()),
        Err(error) => Err(map_io(error)),
    }
}

/// `map_io` folds EISDIR/ENOTDIR into `NotFound` (a mid-path component with
/// the wrong shape genuinely means the target does not exist), but when the
/// operation's own leaf exists with the other kind the caller used the wrong
/// operation: probe the leaf and surface `InvalidArgument` with guidance
/// instead. Probing metadata rather than matching errno also
/// covers platforms where the mismatch surfaces as a different error (macOS
/// unlink on a directory yields EPERM).
async fn leaf_type_mismatch(path: &Path, wants_directory: bool, guidance: &str) -> Option<Error> {
    let meta = tokio::fs::metadata(path).await.ok()?;
    let mismatched = if wants_directory {
        meta.is_file()
    } else {
        meta.is_dir()
    };
    mismatched.then(|| Error::new(ErrorCode::InvalidArgument, guidance))
}

/// Refuse a directory leaf on the byte-oriented paths (`read`, `materialize`).
/// Both hand back a `LocalDelegate` the host opens itself, and opening a
/// directory yields `ErrorKind::IsADirectory` far from the call that asked for
/// it — so answer the type mismatch here, with the same `InvalidArgument` +
/// guidance shape as [`leaf_type_mismatch`]. Inspects the already-fetched
/// `Metadata` (the caller's single `stat`) rather than re-statting, matching
/// [`owner::reject_special_file`].
fn reject_directory_target(metadata: &std::fs::Metadata, guidance: &str) -> Result<()> {
    if metadata.is_dir() {
        return Err(Error::new(ErrorCode::InvalidArgument, guidance));
    }
    Ok(())
}

async fn apply_destination_precondition(path: &Path, if_dest: &IfDestExists) -> Result<()> {
    match if_dest {
        IfDestExists::Overwrite => Ok(()),
        IfDestExists::Fail => {
            if tokio::fs::try_exists(path).await.map_err(map_io)? {
                Err(Error::new(ErrorCode::AlreadyExists, "destination exists"))
            } else {
                Ok(())
            }
        }
        IfDestExists::MatchEtag(expected) => {
            let info = stat_path(&path_to_file_url(path)?, path, false).await?;
            if info.etag.as_ref() == Some(expected) {
                Ok(())
            } else {
                Err(Error::new(ErrorCode::PreconditionFailed, "etag mismatch"))
            }
        }
    }
}

async fn collect_file_list(
    path: PathBuf,
    recursive: bool,
    full_metadata: bool,
    confine_root: Option<&Path>,
    out: &mut Vec<ObjectInfo>,
) -> Result<()> {
    let mut entries = tokio::fs::read_dir(&path).await.map_err(map_io)?;
    while let Some(entry) = entries.next_entry().await.map_err(map_io)? {
        let entry_path = entry.path();
        if is_atomic_write_temp_sibling(&entry_path) {
            continue;
        }
        // In `confine_to_root` mode re-apply the realpath jail to every entry
        // so a recursive walk cannot enumerate the target of an escaping
        // in-root symlink (`root/escape -> /outside`): omit an entry that
        // resolves outside the root entirely, mirroring `checked_scope_for`
        // (which would deny a direct stat/read of the same address). Off by
        // default, so the virtual-tree walk is unaffected.
        if let Some(canonical_root) = confine_root
            && ensure_path_within_root(&entry_path, canonical_root).is_err()
        {
            continue;
        }
        let address = path_to_file_url(&entry_path)?;
        let info = stat_path(&address, &entry_path, full_metadata).await?;
        let is_directory = info.kind.is_directory();
        out.push(info);
        if recursive && is_directory {
            Box::pin(collect_file_list(
                entry_path,
                recursive,
                full_metadata,
                confine_root,
                out,
            ))
            .await?;
        }
    }
    Ok(())
}

/// Pull the next visible path from a live directory DFS.
///
/// The stack contains directory cursors, not their remaining paths, so
/// residency grows with traversal depth rather than directory width. The
/// caller pushes a child cursor after yielding a directory entry.
async fn next_file_list_path(
    directories: &mut Vec<tokio::fs::ReadDir>,
    confine_root: Option<&Path>,
    cancel: &Option<CancellationToken>,
) -> Result<Option<PathBuf>> {
    loop {
        bail_if_cancelled(cancel)?;
        let Some(directory) = directories.last_mut() else {
            return Ok(None);
        };
        let Some(entry) = directory.next_entry().await.map_err(map_io)? else {
            directories.pop();
            continue;
        };
        bail_if_cancelled(cancel)?;
        let entry_path = entry.path();
        if is_atomic_write_temp_sibling(&entry_path) {
            continue;
        }
        if let Some(canonical_root) = confine_root
            && ensure_path_within_root(&entry_path, canonical_root).is_err()
        {
            continue;
        }
        return Ok(Some(entry_path));
    }
}

/// Open an [`AsyncRead`](tokio::io::AsyncRead) over only the bytes in `range`
/// and adapt it to a [`ReadStream`]. Seeks to `range.start` and `take`s the
/// window length, so peak memory is bounded by the stream chunk size — the
/// whole object is never materialized for a partial read. Ported from the
/// legacy `ovstorage-plugin-file` cdylib.
async fn open_ranged_stream(path: &Path, len: u64, range: ByteRange) -> Result<ReadStream> {
    use futures::StreamExt;
    use tokio::io::{AsyncReadExt, AsyncSeekExt};
    if len == 0 || range.start >= len {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "byte range is outside the object",
        ));
    }
    if let Some(end) = range.end_inclusive
        && end < range.start
    {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "byte range end precedes start",
        ));
    }
    let end = range.end_inclusive.unwrap_or(len - 1).min(len - 1);
    let take = end - range.start + 1;
    let mut file = tokio::fs::File::open(path).await.map_err(map_io)?;
    file.seek(std::io::SeekFrom::Start(range.start))
        .await
        .map_err(map_io)?;
    let limited = file.take(take);
    let reader = tokio_util::io::ReaderStream::new(limited);
    let stream: ReadStream = Box::pin(reader.map(|chunk| chunk.map_err(map_io)));
    Ok(stream)
}

/// `include_modified_by` gates the per-platform owner resolve (Unix uid lookup,
/// Windows DACL probe) so a stat/list that does not ask for full metadata skips
/// it; public callers wire it from `StatOptions`/`ListOptions::full_metadata`,
/// while internal callers that only need identity/etag for a precondition check
/// pass `false`. Mirrors the legacy cdylib's `info_for_path(.., include_modified_by)`.
async fn stat_path(address: &Url, path: &Path, include_modified_by: bool) -> Result<ObjectInfo> {
    let metadata = tokio::fs::metadata(path).await.map_err(map_io)?;
    stat_path_with_meta(address, path, metadata, include_modified_by).await
}

/// Build an [`ObjectInfo`] from already-fetched `metadata`, so a caller that has
/// just stat'd the path (e.g. `read`'s special-file rejection) reuses that one
/// stat instead of taking a second. [`stat_path`] is the thin stat-then-delegate
/// wrapper for callers that hold only a path. See [`stat_path`] for
/// `include_modified_by`.
///
/// The synthesized `size:N,mtime:T` etag is a weak validator: a same-size
/// rewrite inside the filesystem clock granularity can retain the same value.
/// It remains meaningful for compare-and-swap preconditions, but does not
/// promise byte identity.
async fn stat_path_with_meta(
    address: &Url,
    path: &Path,
    metadata: std::fs::Metadata,
    include_modified_by: bool,
) -> Result<ObjectInfo> {
    let kind = if metadata.is_dir() {
        ObjectKind::Directory
    } else {
        ObjectKind::File
    };
    Ok(ObjectInfo {
        etag_strength: EtagStrength::Weak,
        address: address.clone(),
        kind,
        etag: Some(file_etag(&metadata)),
        version: None,
        size: kind.is_file().then_some(metadata.len()),
        mtime: metadata.modified().ok(),
        checksums: ChecksumSet::new(),
        effective_permissions: Some(effective_permissions_from_metadata(&metadata)),
        system_metadata: None,
        // This backend stores no user metadata, so every object reports an
        // empty map rather than `None`: the field is known, and known empty.
        user_metadata: Some(UserMetadata::new()),
        modified_by: if include_modified_by {
            owner::modified_by_for_path(path, &metadata)
        } else {
            None
        },
        versioned_address: None,
    })
}

/// Approximate effective permissions from the filesystem read-only bit, matching
/// the legacy cdylib: a read-only entry advertises `READ`, an otherwise-writable
/// entry the full set. This honors the descriptor's
/// `populates_effective_permissions_on_stat = true` rather than hardcoding the
/// full set on every entry.
fn effective_permissions_from_metadata(metadata: &std::fs::Metadata) -> EffectivePermissions {
    if metadata.permissions().readonly() {
        EffectivePermissions::READ
    } else {
        EffectivePermissions::all()
    }
}

fn file_etag(metadata: &std::fs::Metadata) -> String {
    ovstorage_layer::synthesize_file_etag(metadata.len(), metadata.modified().ok())
}

/// Canonical `size:N,mtime:nanos` etag synthesis, shared by `stat`'s
/// [`file_etag`] and the directory watcher's change events
/// (`watch::watch_etag`) so an etag observed on a change event round-trips
/// through `if_match` against a subsequent `stat`. Both call sites MUST go
/// through this one implementation; a divergence would silently break that
/// round-trip (asserted by `watch_directory_change_etag_matches_stat`).
pub(crate) fn synthesize_etag(size: u64, mtime: Option<SystemTime>) -> String {
    ovstorage_layer::synthesize_file_etag(size, mtime)
}

fn file_path(url: &Url) -> Result<PathBuf> {
    // Reject a non-empty/non-`localhost` authority before converting. The URL
    // parser silently retains the host on `file://server/share/...`, and
    // `to_file_path()` would either fabricate a UNC path (Windows) or drop the
    // authority (Unix), so a caller could smuggle a remote-share spelling past
    // the root scope. Applies to both configured roots and request addresses,
    // since every conversion funnels through here.
    if let Some(host) = url.host_str()
        && !host.is_empty()
        && !host.eq_ignore_ascii_case("localhost")
    {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "file:// URL must have an empty or 'localhost' authority, got '{host}' \
                 (UNC paths and remote shares are not supported)"
            ),
        ));
    }
    url.to_file_path()
        .map_err(|_| Error::new(ErrorCode::InvalidArgument, "URL is not a valid file path"))
}

#[cfg(windows)]
fn file_scheme_root() -> Url {
    Url::parse("file:/").expect("the file scheme root is a valid URL")
}

#[cfg(windows)]
fn is_file_scheme_root(url: &Url) -> bool {
    url.scheme().eq_ignore_ascii_case("file") && url.host_str().is_none() && url.path() == "/"
}

#[cfg(windows)]
fn synthetic_directory_info(address: Url) -> ObjectInfo {
    ObjectInfo {
        etag_strength: EtagStrength::Unspecified,
        address,
        kind: ObjectKind::Directory,
        etag: None,
        version: None,
        size: None,
        mtime: None,
        checksums: ChecksumSet::new(),
        effective_permissions: None,
        system_metadata: None,
        user_metadata: None,
        modified_by: None,
        versioned_address: None,
    }
}

/// Return the logical drive roots reported by Windows. This is intentionally a
/// directory listing, not a set of routes: publishing one route per drive would
/// make the visible address topology depend on an incidental machine state.
#[cfg(windows)]
fn windows_drive_roots() -> Result<Vec<ObjectInfo>> {
    use windows_sys::Win32::Storage::FileSystem::GetLogicalDrives;

    let mask = unsafe { GetLogicalDrives() };
    if mask == 0 {
        return Err(map_io(io::Error::last_os_error()));
    }
    (0..26)
        .filter(|index| mask & (1 << index) != 0)
        .map(|index| {
            let letter = char::from(b'A' + index as u8);
            let address = Url::parse(&format!("file:///{letter}:/"))
                .expect("an ASCII drive root is a valid file URL");
            Ok(synthetic_directory_info(address))
        })
        .collect()
}

/// Canonicalize a configured filesystem root so containment checks compare
/// realpaths. Fails (rather than silently allowing) if the root is missing or
/// unreadable — an unresolvable scope must not degrade to a lexical-only jail.
fn canonicalize_scope_root(root: &Path) -> Result<PathBuf> {
    std::fs::canonicalize(root).map_err(|err| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "configured file root ({}) is not accessible: {err}",
                root.display()
            ),
        )
    })
}

/// Canonicalize the nearest EXISTING ancestor of `path`. Callers address
/// objects that may not exist yet (writes/creates), so we walk up until a
/// component resolves, then realpath that. Any symlink in the existing prefix
/// is followed here, which is exactly what lets [`ensure_path_within_root`]
/// detect an in-root symlink that escapes the scope.
fn canonical_existing_anchor(path: &Path) -> Result<PathBuf> {
    let mut candidate = path;
    loop {
        match std::fs::canonicalize(candidate) {
            Ok(canonical) => return Ok(canonical),
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                candidate = candidate.parent().ok_or_else(|| map_io(err))?;
            }
            Err(err) => return Err(map_io(err)),
        }
    }
}

/// Enforce realpath containment: the canonicalized nearest-existing ancestor of
/// `path` must live under `canonical_root`. This is the guard the lexical
/// namespace check cannot provide — it rejects a caller spelling that stays
/// under the root textually but resolves elsewhere on disk through a symlink.
fn ensure_path_within_root(path: &Path, canonical_root: &Path) -> Result<()> {
    let anchor = canonical_existing_anchor(path)?;
    if anchor.starts_with(canonical_root) {
        return Ok(());
    }
    Err(Error::new(
        ErrorCode::PermissionDenied,
        "file address resolves outside the configured root",
    ))
}

fn normalize_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            std::path::Component::Normal(_)
            | std::path::Component::RootDir
            | std::path::Component::Prefix(_) => normalized.push(component.as_os_str()),
        }
    }
    normalized
}

/// The address of a filesystem path, in the form every other layer compares
/// against.
///
/// `Url::from_file_path` applies the `url` crate's own path escape set, which is
/// not this project's: it leaves `|` bare, so a directory literally named `C|`
/// is emitted as `file:///C|/x` while the canonical spelling of that node is
/// `file:///C%7C/x`. An entry address that differs from the root's spelling is
/// an entry no comparison downstream — the router's prefix test, the metadata
/// cache's key, an authorization scope — will match, so the conversion ends in
/// [`ovstorage_layer::canonicalize`] rather than at the crate's escape set.
///
/// The remaining work canonicalization does is a no-op on the paths that reach
/// here: a `read_dir` entry carries no dot segment, no separator run and no
/// authority to lowercase, and the other caller
/// ([`apply_destination_precondition`]) holds a path already resolved from a
/// request address. It runs unconditionally rather than on the strength of
/// that, so a third caller cannot reintroduce the divergence.
fn path_to_file_url(path: &Path) -> Result<Url> {
    Url::from_file_path(path)
        .map(ovstorage_layer::canonicalize)
        .map_err(|_| {
            Error::new(
                ErrorCode::InvalidArgument,
                "path is not representable as file://",
            )
        })
}

#[cfg(any(windows, test))]
/// Reject the one recursive-list request that the root-level capability cannot
/// describe precisely.
///
/// An unscoped Windows backend publishes `file:/` as the container for drive
/// roots, while [`Layer::root_info_for`] returns that same owning root for real
/// drive descendants. Those descendants do support recursive listing, so the
/// root consistently advertises the backend capability; only a recursive walk
/// of the synthetic container itself is refused here.
fn reject_recursive_synthetic_root_list(options: &ListOptions) -> Result<()> {
    if options.recursive {
        return Err(Error::new(
            ErrorCode::Unsupported,
            "recursive listing is not supported for the synthetic file root",
        ));
    }
    Ok(())
}

fn file_capabilities() -> Capabilities {
    Capabilities {
        supports_if_match_write: true,
        supports_no_overwrite_write: true,
        supports_native_metadata_patch: false,
        supports_metadata_rewrite_emulation: false,
        writes_are_atomic: true,
        supports_copy: true,
        supports_rename: true,
        supports_server_side_copy: true,
        supports_server_side_rename: true,
        supports_atomic_rename: true,
        has_real_directories: true,
        supports_write: true,
        supports_write_stream: true,
        supports_write_redirect: false,
        supports_delete: true,
        supports_list: true,
        supports_list_stream: true,
        wants_list_backed_stat: false,
        supports_recursive_list: true,
        populates_subdirectory_metadata: true,
        supports_create_directory: true,
        supports_delete_directory: true,
        supports_version_listing: false,
        version_list_order: None,
        populates_effective_permissions_on_stat: true,
        supports_access_check: true,
        supports_watch_directory: false,
        watch_directory_kinds: ChangeKindSet::empty(),
        watch_directory_resumable: false,
        watch_directory_max_lag: None,
        redirect_size_threshold: None,
    }
}

fn file_descriptor() -> LayerKindDescriptor {
    // The backend stores no user metadata, so it declares none: a host then
    // composes no attribution layer over a `file` branch rather than stamping a
    // key this backend must refuse.
    let mut descriptor = descriptor(FILE_BACKEND_KIND, LayerType::Backend, true, false);
    descriptor.display_name = "Local files".to_string();
    descriptor.description = Some("Read and write local file:// URLs".to_string());
    descriptor.config_schema = vec![
        // A connection requires `root` (`add_connection` rejects a config
        // without it); it is the filesystem scope the backend serves.
        ConfigField {
            key: "root".to_string(),
            display_name: "Root".to_string(),
            kind: ConfigFieldKind::Url,
            required: true,
            default: None,
            help: Some("file:// root exposed by this connection".to_string()),
            example: Some("file:///tmp/ovstorage/".to_string()),
            group: None,
            advanced: false,
        },
        // Optional narrower route within `root` (`prefix` config):
        // when set, the connection exposes only this sub-path, not all of
        // `root`. Must resolve under `root`.
        ConfigField {
            key: "prefix".to_string(),
            display_name: "Prefix".to_string(),
            kind: ConfigFieldKind::Url,
            required: false,
            default: None,
            help: Some(
                "Optional file:// sub-path within root to expose as the route (must be under root)"
                    .to_string(),
            ),
            example: Some("file:///tmp/ovstorage/public/".to_string()),
            group: None,
            advanced: true,
        },
        // Opt-in realpath jail. Default (`false`) follows operator-configured
        // in-root symlinks that redirect outside `root` (the virtual-tree
        // model); `true` denies them with `PermissionDenied`. Only meaningful
        // for deployments that run the backend under a privileged service
        // account (brokered mode); direct mode runs under the app's own UID
        // where there is no privilege boundary to jail.
        ConfigField {
            key: "confine_to_root".to_string(),
            display_name: "Confine to root".to_string(),
            kind: ConfigFieldKind::Bool,
            required: false,
            default: Some(ConfigValue::Bool(false)),
            help: Some(
                "Deny in-root symlinks whose target resolves outside root (realpath jail). \
                 Off by default: operator-configured symlinks may form a virtual tree."
                    .to_string(),
            ),
            example: Some("true".to_string()),
            group: None,
            advanced: true,
        },
    ];
    descriptor
}

fn root_source(connection_id: Option<ConnectionId>) -> RouteSource {
    match connection_id {
        Some(connection_id) => RouteSource::ConnectionContributed { connection_id },
        None => RouteSource::Static {
            layer: ConfigLayer::Programmatic,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `Layer` contract makes `Cancelled` the answer when the caller's
    /// token fired before the operation completed. These three slots are
    /// short, but "short" is not "free" — an already-cancelled caller must not
    /// receive a successful snapshot, and both hosts must agree on that.
    #[tokio::test]
    async fn introspection_slots_report_cancelled_on_an_already_fired_token() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Url::from_directory_path(tmp.path()).unwrap();
        let mut config = LayerConfig::new();
        config.insert("root".into(), ConfigValue::String(root.to_string()));
        let backend = FileBackendFactory
            .create_backend("files", &config, None)
            .await
            .unwrap();

        let cancel = CancellationToken::new();
        cancel.cancel();

        assert_eq!(
            backend
                .root_info_for(&root, &Extensions::new(), Some(cancel.clone()))
                .await
                .expect_err("root_info_for must refuse an already-cancelled caller")
                .code(),
            ErrorCode::Cancelled,
        );
        assert!(
            backend
                .list_address_roots(&Extensions::new(), Some(cancel.clone()))
                .await
                .is_err(),
            "list_address_roots must refuse an already-cancelled caller",
        );
        assert!(
            backend
                .list_connections(&Extensions::new(), Some(cancel))
                .await
                .is_err(),
            "list_connections must refuse an already-cancelled caller",
        );

        // An absent token still succeeds — the check is on a FIRED token, not
        // on the presence of one.
        assert!(
            backend
                .list_address_roots(&Extensions::new(), None)
                .await
                .is_ok(),
        );
    }

    #[tokio::test]
    async fn file_backend_reads_and_writes_file_urls() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Url::from_directory_path(tmp.path()).unwrap();
        let file = root.join("hello.txt").unwrap();
        let mut config = LayerConfig::new();
        config.insert("root".into(), ConfigValue::String(root.to_string()));
        let backend = FileBackendFactory
            .create_backend("files", &config, None)
            .await
            .unwrap();

        backend
            .write(
                Request::new(WriteRequest {
                    address: file.clone(),
                    body: Body::Bytes(b"hello".to_vec()),
                    options: WriteOptions::default(),
                }),
                None,
            )
            .await
            .unwrap();

        let stat = backend
            .stat(
                Request::new(StatRequest {
                    address: file.clone(),
                    options: StatOptions::default(),
                }),
                None,
            )
            .await
            .unwrap();
        assert!(stat.etag.is_some());
        assert_eq!(stat.etag_strength, EtagStrength::Weak);

        let read = backend
            .read(
                Request::new(ReadRequest {
                    address: file,
                    options: ReadOptions::default(),
                }),
                None,
            )
            .await
            .unwrap();
        let (bytes, info) = read_content(read).await;
        assert_eq!(bytes, b"hello");
        assert_eq!(info.size, Some(5));
    }

    #[tokio::test]
    async fn file_backend_rejects_urls_outside_configured_root() {
        let tmp = tempfile::tempdir().unwrap();
        let root_dir = tmp.path().join("root");
        std::fs::create_dir_all(&root_dir).unwrap();
        let root = Url::from_directory_path(&root_dir).unwrap();
        let outside = Url::from_file_path(tmp.path().join("outside.txt")).unwrap();
        let mut config = LayerConfig::new();
        config.insert("root".into(), ConfigValue::String(root.to_string()));
        let backend = FileBackendFactory
            .create_backend("files", &config, None)
            .await
            .unwrap();

        let err = backend
            .write(
                Request::new(WriteRequest {
                    address: outside,
                    body: Body::Bytes(b"escape".to_vec()),
                    options: WriteOptions::default(),
                }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert!(err.message().contains("outside the configured roots"));
        assert!(!tmp.path().join("outside.txt").exists());
    }

    // Regression: delete on a directory is a type mismatch with
    // guidance, not a misleading NotFound. The directory must survive.
    #[tokio::test]
    async fn file_backend_delete_on_directory_surfaces_type_mismatch() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Url::from_directory_path(tmp.path()).unwrap();
        std::fs::create_dir_all(tmp.path().join("subdir")).unwrap();
        let mut config = LayerConfig::new();
        config.insert("root".into(), ConfigValue::String(root.to_string()));
        let backend = FileBackendFactory
            .create_backend("files", &config, None)
            .await
            .unwrap();

        let err = backend
            .delete(
                Request::new(DeleteRequest {
                    address: root.join("subdir").unwrap(),
                    options: DeleteOptions::default(),
                }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert!(err.message().contains("use delete_directory"), "{err}");
        assert!(tmp.path().join("subdir").is_dir());
    }

    // Regression: delete_directory on a file is the symmetric type
    // mismatch. The file must survive.
    #[tokio::test]
    async fn file_backend_delete_directory_on_file_surfaces_type_mismatch() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Url::from_directory_path(tmp.path()).unwrap();
        std::fs::write(tmp.path().join("plain.txt"), b"bytes").unwrap();
        let mut config = LayerConfig::new();
        config.insert("root".into(), ConfigValue::String(root.to_string()));
        let backend = FileBackendFactory
            .create_backend("files", &config, None)
            .await
            .unwrap();

        let err = backend
            .delete_directory(
                Request::new(DeleteDirectoryRequest {
                    address: root.join("plain.txt").unwrap(),
                    options: DeleteDirectoryOptions,
                }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert!(err.message().contains("use delete()"), "{err}");
        assert!(tmp.path().join("plain.txt").is_file());
    }

    // Regression: list with a file as the prefix is a type mismatch,
    // not NotFound.
    #[tokio::test]
    async fn file_backend_list_on_file_surfaces_type_mismatch() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Url::from_directory_path(tmp.path()).unwrap();
        std::fs::write(tmp.path().join("plain.txt"), b"bytes").unwrap();
        let mut config = LayerConfig::new();
        config.insert("root".into(), ConfigValue::String(root.to_string()));
        let backend = FileBackendFactory
            .create_backend("files", &config, None)
            .await
            .unwrap();

        let err = backend
            .list(
                Request::new(ListRequest {
                    prefix: root.join("plain.txt").unwrap(),
                    options: ListOptions::default(),
                }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert!(err.message().contains("not a directory"), "{err}");
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn unscoped_file_scheme_root_lists_available_drive_roots() {
        let backend = FileBackendFactory
            .create_backend("files", &LayerConfig::new(), None)
            .await
            .unwrap();
        let scheme_root = file_scheme_root();

        let roots = backend
            .list_address_roots(&Extensions::new(), None)
            .await
            .unwrap()
            .0
            .roots;
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].root, scheme_root);

        let page = backend
            .list(
                Request::new(ListRequest {
                    prefix: scheme_root,
                    options: ListOptions::default(),
                }),
                None,
            )
            .await
            .unwrap();
        let expected: Vec<_> = windows_drive_roots()
            .unwrap()
            .into_iter()
            .map(|info| info.address)
            .collect();
        let actual: Vec<_> = page.items.into_iter().map(|info| info.address).collect();
        assert_eq!(actual, expected);
        assert!(actual.iter().all(|address| {
            let path = address.path().as_bytes();
            path.len() == 4
                && path[0] == b'/'
                && path[1].is_ascii_uppercase()
                && path[2] == b':'
                && path[3] == b'/'
        }));

        let drive = actual.first().expect("Windows reports at least one drive");
        let drive_info = backend
            .root_info_for(drive, &Extensions::new(), None)
            .await
            .unwrap();
        assert_eq!(drive_info.root, file_scheme_root());
        let child_info = backend
            .root_info_for(&drive.join("child.txt").unwrap(), &Extensions::new(), None)
            .await
            .unwrap();
        assert_eq!(child_info.root, file_scheme_root());

        let root_stat = backend
            .stat(
                Request::new(StatRequest {
                    address: file_scheme_root(),
                    options: StatOptions::default(),
                }),
                None,
            )
            .await
            .unwrap();
        assert_eq!(root_stat.address, file_scheme_root());
        assert_eq!(root_stat.kind, ObjectKind::Directory);
        assert_eq!(root_stat.size, None);
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn configured_file_scheme_root_does_not_expose_machine_drive_listing() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Url::from_directory_path(tmp.path()).unwrap();
        let mut config = LayerConfig::new();
        config.insert("root".into(), ConfigValue::String(root.to_string()));
        let backend = FileBackendFactory
            .create_backend("files", &config, None)
            .await
            .unwrap();

        let error = backend
            .list(
                Request::new(ListRequest {
                    prefix: file_scheme_root(),
                    options: ListOptions::default(),
                }),
                None,
            )
            .await
            .expect_err("an explicit root must keep the machine root out of scope");
        assert_eq!(error.code(), ErrorCode::InvalidArgument);
        assert!(error.message().contains("URL is not a valid file path"));
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn unscoped_file_scheme_root_streams_available_drive_roots_without_pagination() {
        use futures::{StreamExt as _, TryStreamExt as _};

        let backend = FileBackendFactory
            .create_backend("files", &LayerConfig::new(), None)
            .await
            .unwrap();
        let scheme_root = file_scheme_root();
        let buffered = backend
            .list(
                Request::new(ListRequest {
                    prefix: scheme_root.clone(),
                    options: ListOptions::default(),
                }),
                None,
            )
            .await
            .unwrap();
        let streamed: Vec<_> = backend
            .list_stream(
                Request::new(ListRequest {
                    prefix: scheme_root.clone(),
                    options: ListOptions::default(),
                }),
                None,
            )
            .await
            .unwrap()
            .try_collect()
            .await
            .unwrap();
        assert_eq!(
            streamed
                .into_iter()
                .map(|item| item.address)
                .collect::<Vec<_>>(),
            buffered
                .items
                .into_iter()
                .map(|item| item.address)
                .collect::<Vec<_>>(),
        );

        let cancel = CancellationToken::new();
        let mut cancelled_stream = backend
            .list_stream(
                Request::new(ListRequest {
                    prefix: scheme_root.clone(),
                    options: ListOptions::default(),
                }),
                Some(cancel.clone()),
            )
            .await
            .unwrap();
        cancel.cancel();
        let error = cancelled_stream
            .next()
            .await
            .expect("cancelled list stream must report cancellation")
            .expect_err("cancelled list stream must not yield a drive");
        assert_eq!(error.code(), ErrorCode::Cancelled);
        assert!(cancelled_stream.next().await.is_none());

        for options in [
            ListOptions {
                max_results: Some(1),
                ..ListOptions::default()
            },
            ListOptions {
                page_token: Some("not-a-page-token".to_string()),
                ..ListOptions::default()
            },
        ] {
            let result = backend
                .list_stream(
                    Request::new(ListRequest {
                        prefix: scheme_root.clone(),
                        options,
                    }),
                    None,
                )
                .await;
            let error = match result {
                Ok(_) => panic!("list_stream must reject pagination options"),
                Err(error) => error,
            };
            assert_eq!(error.code(), ErrorCode::InvalidArgument);
            assert!(error.message().contains("max_results or page_token"));
        }
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn unscoped_file_scheme_root_rejects_recursive_lists() {
        let backend = FileBackendFactory
            .create_backend("files", &LayerConfig::new(), None)
            .await
            .unwrap();
        let scheme_root = file_scheme_root();
        let options = ListOptions {
            recursive: true,
            ..ListOptions::default()
        };

        let root_info = backend
            .root_info_for(&scheme_root, &Extensions::new(), None)
            .await
            .unwrap();
        assert!(root_info.capabilities.supports_recursive_list);
        let (snapshot, _) = backend
            .list_address_roots(&Extensions::new(), None)
            .await
            .unwrap();
        assert_eq!(snapshot.roots.len(), 1);
        assert_eq!(snapshot.roots[0].capabilities, root_info.capabilities);

        let error = backend
            .list(
                Request::new(ListRequest {
                    prefix: scheme_root.clone(),
                    options: options.clone(),
                }),
                None,
            )
            .await
            .expect_err("the synthetic drive root must reject recursive buffered lists");
        assert_eq!(error.code(), ErrorCode::Unsupported);

        let result = backend
            .list_stream(
                Request::new(ListRequest {
                    prefix: scheme_root,
                    options,
                }),
                None,
            )
            .await;
        let error = match result {
            Ok(_) => panic!("the synthetic drive root must reject recursive streaming lists"),
            Err(error) => error,
        };
        assert_eq!(error.code(), ErrorCode::Unsupported);
    }

    #[test]
    fn synthetic_root_recursive_list_option_is_unsupported() {
        let error = reject_recursive_synthetic_root_list(&ListOptions {
            recursive: true,
            ..ListOptions::default()
        })
        .expect_err("synthetic root recursion must be unsupported");
        assert_eq!(error.code(), ErrorCode::Unsupported);
    }

    #[tokio::test]
    async fn file_backend_list_stream_matches_buffered_entry_set_with_depth_first_traversal() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Url::from_directory_path(tmp.path()).unwrap();
        std::fs::create_dir(tmp.path().join("a")).unwrap();
        std::fs::write(tmp.path().join("a").join("z.txt"), b"nested").unwrap();
        std::fs::write(tmp.path().join("a.txt"), b"sibling").unwrap();
        std::fs::write(tmp.path().join("b.txt"), b"sibling").unwrap();
        let backend = backend_over_tempdir(&tmp).await;

        let options = ListOptions {
            recursive: true,
            ..ListOptions::default()
        };
        let buffered = backend
            .list(
                Request::new(ListRequest {
                    prefix: root.clone(),
                    options: options.clone(),
                }),
                None,
            )
            .await
            .unwrap()
            .items;
        let streamed = list_stream_items(&backend, &root, options, None)
            .await
            .unwrap();

        let address_set = |items: &[ObjectInfo]| {
            items
                .iter()
                .map(|item| item.address.as_str().to_string())
                .collect::<std::collections::BTreeSet<_>>()
        };
        assert_eq!(address_set(&streamed), address_set(&buffered));

        // Sibling order follows the filesystem, but once a directory is
        // yielded its subtree is consumed before traversal resumes at the
        // parent level.
        let streamed_addresses: Vec<_> = streamed.iter().map(|item| &item.address).collect();
        let directory = root.join("a").unwrap();
        let nested = root.join("a/z.txt").unwrap();
        let directory_index = streamed_addresses
            .iter()
            .position(|address| *address == &directory)
            .unwrap();
        let nested_index = streamed_addresses
            .iter()
            .position(|address| *address == &nested)
            .unwrap();
        assert_eq!(
            nested_index,
            directory_index + 1,
            "a directory's first child must be the next DFS entry"
        );
    }

    #[tokio::test]
    async fn file_backend_list_stream_pulls_a_wide_directory_one_entry_at_a_time() {
        let tmp = tempfile::tempdir().unwrap();
        for index in 0..2_048 {
            std::fs::write(tmp.path().join(format!("{index:04}.txt")), b"entry").unwrap();
        }

        let mut directories = vec![tokio::fs::read_dir(tmp.path()).await.unwrap()];
        let first = next_file_list_path(&mut directories, None, &None)
            .await
            .unwrap()
            .expect("wide directory must have a first entry");

        assert!(first.parent().is_some_and(|parent| parent == tmp.path()));
        assert_eq!(
            directories.len(),
            1,
            "the cursor retains one directory handle, not its remaining paths"
        );
    }

    #[tokio::test]
    async fn file_backend_list_stream_one_level_and_recursive_match_buffered_sets() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Url::from_directory_path(tmp.path()).unwrap();
        std::fs::create_dir(tmp.path().join("nested")).unwrap();
        std::fs::write(tmp.path().join("direct.txt"), b"direct").unwrap();
        std::fs::write(tmp.path().join("nested").join("leaf.txt"), b"leaf").unwrap();
        let backend = backend_over_tempdir(&tmp).await;

        for recursive in [false, true] {
            let options = ListOptions {
                recursive,
                ..ListOptions::default()
            };
            let buffered = backend
                .list(
                    Request::new(ListRequest {
                        prefix: root.clone(),
                        options: options.clone(),
                    }),
                    None,
                )
                .await
                .unwrap();
            let streamed = list_stream_items(&backend, &root, options, None)
                .await
                .unwrap();
            let buffered_addresses: std::collections::BTreeSet<_> = buffered
                .items
                .iter()
                .map(|item| item.address.as_str())
                .collect();
            let streamed_addresses: std::collections::BTreeSet<_> =
                streamed.iter().map(|item| item.address.as_str()).collect();
            assert_eq!(
                streamed_addresses, buffered_addresses,
                "recursive={recursive}"
            );
            assert_eq!(
                streamed_addresses.contains(root.join("nested/leaf.txt").unwrap().as_str()),
                recursive,
                "nested leaf presence must follow the recursive option"
            );
        }
    }

    #[tokio::test]
    async fn file_backend_list_stream_cancellation_stops_mid_walk() {
        use futures::StreamExt as _;

        let tmp = tempfile::tempdir().unwrap();
        let root = Url::from_directory_path(tmp.path()).unwrap();
        for index in 0..32 {
            std::fs::write(tmp.path().join(format!("{index:02}.txt")), b"entry").unwrap();
        }
        let backend = backend_over_tempdir(&tmp).await;
        let cancel = CancellationToken::new();
        let mut stream = backend
            .list_stream(
                Request::new(ListRequest {
                    prefix: root,
                    options: ListOptions::default(),
                }),
                Some(cancel.clone()),
            )
            .await
            .unwrap();

        stream
            .next()
            .await
            .expect("stream must yield its first entry")
            .unwrap();
        cancel.cancel();
        let err = tokio::time::timeout(std::time::Duration::from_secs(1), stream.next())
            .await
            .expect("cancelled list stream did not stop promptly")
            .expect("cancelled list stream must report cancellation")
            .expect_err("cancelled list stream yielded another entry");
        assert_eq!(err.code(), ErrorCode::Cancelled);
        assert!(
            stream.next().await.is_none(),
            "cancellation must terminate the stream"
        );
    }

    #[tokio::test]
    async fn file_backend_list_stream_cancellation_after_final_entry_is_terminal() {
        use futures::StreamExt as _;

        let tmp = tempfile::tempdir().unwrap();
        let root = Url::from_directory_path(tmp.path()).unwrap();
        std::fs::write(tmp.path().join("only.txt"), b"entry").unwrap();
        let backend = backend_over_tempdir(&tmp).await;
        let cancel = CancellationToken::new();
        let mut stream = backend
            .list_stream(
                Request::new(ListRequest {
                    prefix: root,
                    options: ListOptions::default(),
                }),
                Some(cancel.clone()),
            )
            .await
            .unwrap();

        stream
            .next()
            .await
            .expect("stream must yield its only entry")
            .unwrap();
        cancel.cancel();

        let error = stream
            .next()
            .await
            .expect("cancellation after the final entry must be observable")
            .expect_err("cancellation must preempt normal completion");
        assert_eq!(error.code(), ErrorCode::Cancelled);
        assert!(stream.next().await.is_none(), "cancellation is terminal");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn file_backend_list_stream_propagates_per_entry_stat_errors() {
        use futures::StreamExt as _;

        let tmp = tempfile::tempdir().unwrap();
        let root = Url::from_directory_path(tmp.path()).unwrap();
        std::os::unix::fs::symlink(tmp.path().join("missing"), tmp.path().join("broken")).unwrap();
        let backend = backend_over_tempdir(&tmp).await;
        let buffered_error = backend
            .list(
                Request::new(ListRequest {
                    prefix: root.clone(),
                    options: ListOptions::default(),
                }),
                None,
            )
            .await
            .expect_err("buffered list must reject the broken entry");
        let mut stream = backend
            .list_stream(
                Request::new(ListRequest {
                    prefix: root,
                    options: ListOptions::default(),
                }),
                None,
            )
            .await
            .unwrap();
        let streamed_error = stream
            .next()
            .await
            .expect("stream must surface the stat failure")
            .expect_err("broken entry must not produce ObjectInfo");

        assert_eq!(streamed_error.code(), buffered_error.code());
        assert!(
            stream.next().await.is_none(),
            "an entry error must terminate the stream"
        );
    }

    // Regression: read on a directory is a type mismatch with guidance, not a
    // `LocalDelegate` whose host-side open fails with IsADirectory.
    #[tokio::test]
    async fn file_backend_read_on_directory_surfaces_type_mismatch() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Url::from_directory_path(tmp.path()).unwrap();
        std::fs::create_dir_all(tmp.path().join("subdir")).unwrap();
        let backend = backend_over_tempdir(&tmp).await;

        let err = backend
            .read(
                Request::new(ReadRequest {
                    address: root.join("subdir").unwrap(),
                    options: ReadOptions::default(),
                }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert!(err.message().contains("list()"), "{err}");
    }

    // The guard sits ahead of the range branch, so a ranged read of a directory
    // reports the type mismatch at the call. Without it the range arm opens the
    // directory successfully — Linux allows a read-only `open(2)` of one — and
    // hands back a stream whose first chunk poll fails with EISDIR.
    #[tokio::test]
    async fn file_backend_ranged_read_on_directory_surfaces_type_mismatch() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Url::from_directory_path(tmp.path()).unwrap();
        std::fs::create_dir_all(tmp.path().join("subdir")).unwrap();
        let backend = backend_over_tempdir(&tmp).await;

        let err = backend
            .read(
                Request::new(ReadRequest {
                    address: root.join("subdir").unwrap(),
                    options: ReadOptions {
                        range: Some(ByteRange {
                            start: 0,
                            end_inclusive: Some(9),
                        }),
                        ..ReadOptions::default()
                    },
                }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument, "{err}");
        assert!(err.message().contains("list()"), "{err}");
    }

    // Regression: materialize on a directory is the same type mismatch — the
    // delegate it would otherwise hand back is unopenable.
    #[tokio::test]
    async fn file_backend_materialize_on_directory_surfaces_type_mismatch() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Url::from_directory_path(tmp.path()).unwrap();
        std::fs::create_dir_all(tmp.path().join("subdir")).unwrap();
        let backend = backend_over_tempdir(&tmp).await;

        let err = backend
            .materialize(
                Request::new(ReadRequest {
                    address: root.join("subdir").unwrap(),
                    options: ReadOptions::default(),
                }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert!(err.message().contains("list()"), "{err}");
    }

    // The read-side leaf guard leaves the mid-path rule alone: a wrong-shaped
    // component MID-path still means the target does not exist.
    #[tokio::test]
    async fn file_backend_read_mid_path_file_component_stays_not_found() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Url::from_directory_path(tmp.path()).unwrap();
        std::fs::write(tmp.path().join("plain.txt"), b"bytes").unwrap();
        let backend = backend_over_tempdir(&tmp).await;

        let err = backend
            .read(
                Request::new(ReadRequest {
                    address: root.join("plain.txt/child").unwrap(),
                    options: ReadOptions::default(),
                }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::NotFound, "{err}");
    }

    // Companion to the type-mismatch fixes: a wrong-shaped component MID-path
    // means the target genuinely does not exist — that stays NotFound (only
    // the operation's own leaf is probed for a kind mismatch).
    #[tokio::test]
    async fn file_backend_mid_path_file_component_stays_not_found() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Url::from_directory_path(tmp.path()).unwrap();
        std::fs::write(tmp.path().join("plain.txt"), b"bytes").unwrap();
        let mut config = LayerConfig::new();
        config.insert("root".into(), ConfigValue::String(root.to_string()));
        let backend = FileBackendFactory
            .create_backend("files", &config, None)
            .await
            .unwrap();

        let err = backend
            .list(
                Request::new(ListRequest {
                    prefix: root.join("plain.txt/child").unwrap(),
                    options: ListOptions::default(),
                }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::NotFound, "{err}");
    }

    // By DEFAULT an in-root symlink pointing at a file OUTSIDE the root
    // is FOLLOWED on the read side — the operator-configured "virtual tree"
    // model. There is no client-facing SPI to create symlinks, so the only
    // links in a served tree are ones the operator wired up by explicit intent;
    // following them is indirection, not a client-reachable escape.
    #[cfg(unix)]
    #[tokio::test]
    async fn file_backend_default_follows_in_root_symlink_escaping_root() {
        let tmp = tempfile::tempdir().unwrap();
        let root_dir = tmp.path().join("root");
        let outside = tmp.path().join("outside.txt");
        std::fs::create_dir_all(&root_dir).unwrap();
        std::fs::write(&outside, b"linked").unwrap();
        std::os::unix::fs::symlink(&outside, root_dir.join("linked.txt")).unwrap();

        let root = Url::from_directory_path(&root_dir).unwrap();
        let linked = Url::from_file_path(root_dir.join("linked.txt")).unwrap();
        let mut config = LayerConfig::new();
        config.insert("root".into(), ConfigValue::String(root.to_string()));
        let backend = FileBackendFactory
            .create_backend("files", &config, None)
            .await
            .unwrap();

        let read = backend
            .read(
                Request::new(ReadRequest {
                    address: linked,
                    options: ReadOptions::default(),
                }),
                None,
            )
            .await
            .expect("default virtual-tree follow reads the linked target");
        let (bytes, _) = read_content(read).await;
        assert_eq!(bytes, b"linked");
    }

    // With `confine_to_root = true` the realpath jail is re-armed, so an
    // in-root symlink whose target resolves OUTSIDE the root is denied
    // (`PermissionDenied`) — the opt-in posture for brokered deployments that
    // run under a privileged service account. This is the guard the deleted
    // file cdylib enforced, kept available behind the knob.
    #[cfg(unix)]
    #[tokio::test]
    async fn file_backend_confine_to_root_denies_in_root_symlink_escaping_root() {
        let tmp = tempfile::tempdir().unwrap();
        let root_dir = tmp.path().join("root");
        let outside = tmp.path().join("outside.txt");
        std::fs::create_dir_all(&root_dir).unwrap();
        std::fs::write(&outside, b"linked").unwrap();
        std::os::unix::fs::symlink(&outside, root_dir.join("linked.txt")).unwrap();

        let root = Url::from_directory_path(&root_dir).unwrap();
        let linked = Url::from_file_path(root_dir.join("linked.txt")).unwrap();
        let mut config = LayerConfig::new();
        config.insert("root".into(), ConfigValue::String(root.to_string()));
        config.insert("confine_to_root".into(), ConfigValue::Bool(true));
        let backend = FileBackendFactory
            .create_backend("files", &config, None)
            .await
            .unwrap();

        let err = backend
            .read(
                Request::new(ReadRequest {
                    address: linked,
                    options: ReadOptions::default(),
                }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::PermissionDenied);
        assert!(err.message().contains("outside the configured root"));
    }

    // By DEFAULT a directory symlink inside the root that redirects
    // outside (`escape -> /outside`) is followed for writes too — writing
    // `escape/new.txt` lands the bytes in the operator's real data location.
    // Only the FINAL path component is protected (write commits via temp+rename
    // and never writes through a final-component symlink); a directory symlink
    // earlier in the path is the intended virtual tree.
    #[cfg(unix)]
    #[tokio::test]
    async fn file_backend_default_follows_write_through_escaping_symlink_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let root_dir = tmp.path().join("root");
        let outside_dir = tmp.path().join("outside");
        std::fs::create_dir_all(&root_dir).unwrap();
        std::fs::create_dir_all(&outside_dir).unwrap();
        std::os::unix::fs::symlink(&outside_dir, root_dir.join("escape")).unwrap();

        let root = Url::from_directory_path(&root_dir).unwrap();
        let target = Url::from_file_path(root_dir.join("escape").join("new.txt")).unwrap();
        let mut config = LayerConfig::new();
        config.insert("root".into(), ConfigValue::String(root.to_string()));
        let backend = FileBackendFactory
            .create_backend("files", &config, None)
            .await
            .unwrap();

        backend
            .write(
                Request::new(WriteRequest {
                    address: target,
                    body: Body::Bytes(b"escape".to_vec()),
                    options: WriteOptions::default(),
                }),
                None,
            )
            .await
            .expect("default virtual-tree follow writes through the directory symlink");
        assert_eq!(
            std::fs::read(outside_dir.join("new.txt")).unwrap(),
            b"escape"
        );
    }

    // With `confine_to_root = true` a symlinked DIRECTORY inside the root
    // that escapes is denied, including for a not-yet-existing child path (the
    // write creates `escape/new.txt` whose nearest existing ancestor resolves
    // out).
    #[cfg(unix)]
    #[tokio::test]
    async fn file_backend_confine_to_root_denies_write_through_escaping_symlink_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let root_dir = tmp.path().join("root");
        let outside_dir = tmp.path().join("outside");
        std::fs::create_dir_all(&root_dir).unwrap();
        std::fs::create_dir_all(&outside_dir).unwrap();
        std::os::unix::fs::symlink(&outside_dir, root_dir.join("escape")).unwrap();

        let root = Url::from_directory_path(&root_dir).unwrap();
        let target = Url::from_file_path(root_dir.join("escape").join("new.txt")).unwrap();
        let mut config = LayerConfig::new();
        config.insert("root".into(), ConfigValue::String(root.to_string()));
        config.insert("confine_to_root".into(), ConfigValue::Bool(true));
        let backend = FileBackendFactory
            .create_backend("files", &config, None)
            .await
            .unwrap();

        let err = backend
            .write(
                Request::new(WriteRequest {
                    address: target,
                    body: Body::Bytes(b"escape".to_vec()),
                    options: WriteOptions::default(),
                }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::PermissionDenied);
        assert!(!outside_dir.join("new.txt").exists());
    }

    // An in-root symlink whose target is ALSO inside the root stays
    // readable in BOTH modes — the default follows all in-root symlinks, and the
    // `confine_to_root` realpath jail rejects only escapes, not legitimate
    // in-scope indirection (target resolves under root). Exercising the knob-on
    // mode too guards against an over-restrictive jail that would reject every
    // symlink (which would still pass all the escape-denial tests).
    #[cfg(unix)]
    #[tokio::test]
    async fn file_backend_allows_in_root_symlink_to_in_root_target() {
        for confine in [None, Some(true)] {
            let tmp = tempfile::tempdir().unwrap();
            let root_dir = tmp.path().join("root");
            std::fs::create_dir_all(&root_dir).unwrap();
            let real = root_dir.join("real.txt");
            std::fs::write(&real, b"inside").unwrap();
            std::os::unix::fs::symlink(&real, root_dir.join("alias.txt")).unwrap();

            let root = Url::from_directory_path(&root_dir).unwrap();
            let alias = Url::from_file_path(root_dir.join("alias.txt")).unwrap();
            let mut config = LayerConfig::new();
            config.insert("root".into(), ConfigValue::String(root.to_string()));
            if let Some(value) = confine {
                config.insert("confine_to_root".into(), ConfigValue::Bool(value));
            }
            let backend = FileBackendFactory
                .create_backend("files", &config, None)
                .await
                .unwrap();

            let read = backend
                .read(
                    Request::new(ReadRequest {
                        address: alias,
                        options: ReadOptions::default(),
                    }),
                    None,
                )
                .await
                .unwrap_or_else(|e| panic!("confine={confine:?} in-root alias must read: {e}"));
            let (bytes, _) = read_content(read).await;
            assert_eq!(bytes, b"inside", "confine={confine:?}");
        }
    }

    // `confine_to_root` must be honored on the CONNECTION path,
    // not just static `create_backend` config. Every runtime/brokered
    // composition builds the backend with an empty config and then contributes
    // the root + its policy through `add_connection`, so a knob parsed only in
    // `create_backend` would silently no-op for exactly the brokered audience it
    // exists to serve. Here the backend starts empty and the connection arms the
    // jail; an escaping in-root symlink must be denied.
    #[cfg(unix)]
    #[tokio::test]
    async fn file_backend_add_connection_confine_to_root_denies_escape() {
        let tmp = tempfile::tempdir().unwrap();
        let root_dir = tmp.path().join("root");
        let outside = tmp.path().join("outside.txt");
        std::fs::create_dir_all(&root_dir).unwrap();
        std::fs::write(&outside, b"linked").unwrap();
        std::os::unix::fs::symlink(&outside, root_dir.join("linked.txt")).unwrap();
        let root = Url::from_directory_path(&root_dir).unwrap();
        let linked = Url::from_file_path(root_dir.join("linked.txt")).unwrap();

        // Confine ON via the connection: escaping symlink denied.
        let backend = backend_via_connection(&root, Some(true)).await;
        let err = backend
            .read(
                Request::new(ReadRequest {
                    address: linked.clone(),
                    options: ReadOptions::default(),
                }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::PermissionDenied);

        // Default (key absent) via the connection: virtual-tree follow.
        let backend = backend_via_connection(&root, None).await;
        let read = backend
            .read(
                Request::new(ReadRequest {
                    address: linked,
                    options: ReadOptions::default(),
                }),
                None,
            )
            .await
            .expect("default connection follows the in-root symlink");
        let (bytes, _) = read_content(read).await;
        assert_eq!(bytes, b"linked");
    }

    // A wrong-typed `confine_to_root` fails the build rather than
    // silently disabling a requested jail — on both the static and connection
    // paths (shared `confine_to_root_from_config`).
    #[tokio::test]
    async fn file_backend_confine_to_root_rejects_non_bool() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Url::from_directory_path(tmp.path()).unwrap();
        let mut config = LayerConfig::new();
        config.insert("root".into(), ConfigValue::String(root.to_string()));
        config.insert("confine_to_root".into(), ConfigValue::String("yes".into()));
        let err = match FileBackendFactory
            .create_backend("files", &config, None)
            .await
        {
            Ok(_) => panic!("wrong-typed confine_to_root must be rejected"),
            Err(err) => err,
        };
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert!(err.message().contains("confine_to_root"));
    }

    // Recursive `list` must honor `confine_to_root` during
    // TRAVERSAL, not just for the addressed prefix — otherwise a walk through an
    // escaping directory symlink (`root/escape -> /outside`) enumerates the
    // outside tree's entry metadata even with the jail armed. Default follows
    // (virtual tree); confine omits the escaping subtree.
    #[cfg(unix)]
    #[tokio::test]
    async fn file_backend_list_traversal_honors_confine_to_root() {
        for confine in [false, true] {
            let tmp = tempfile::tempdir().unwrap();
            let root_dir = tmp.path().join("root");
            let outside_dir = tmp.path().join("outside");
            std::fs::create_dir_all(&root_dir).unwrap();
            std::fs::create_dir_all(&outside_dir).unwrap();
            std::fs::write(outside_dir.join("secret.txt"), b"secret").unwrap();
            std::os::unix::fs::symlink(&outside_dir, root_dir.join("escape")).unwrap();
            // An ordinary in-root file so the listing is never empty.
            std::fs::write(root_dir.join("plain.txt"), b"ok").unwrap();

            let root = Url::from_directory_path(&root_dir).unwrap();
            let mut config = LayerConfig::new();
            config.insert("root".into(), ConfigValue::String(root.to_string()));
            if confine {
                config.insert("confine_to_root".into(), ConfigValue::Bool(true));
            }
            let backend = FileBackendFactory
                .create_backend("files", &config, None)
                .await
                .unwrap();

            let page = backend
                .list(
                    Request::new(ListRequest {
                        prefix: root.clone(),
                        options: ListOptions {
                            recursive: true,
                            ..ListOptions::default()
                        },
                    }),
                    None,
                )
                .await
                .unwrap();
            let leaked = page
                .items
                .iter()
                .any(|info| info.address.as_str().contains("secret.txt"));
            if confine {
                assert!(
                    !leaked,
                    "confine=true must NOT enumerate the escaping symlink's target"
                );
            } else {
                assert!(
                    leaked,
                    "default (virtual tree) follows the escaping directory symlink"
                );
            }
        }
    }

    // N11 regression: a `file://` URL with a non-empty, non-`localhost`
    // authority (UNC/remote-share spelling) is rejected at path conversion, so
    // it can neither configure a root nor address an object.
    #[test]
    fn file_path_rejects_non_local_authority() {
        let unc = Url::parse("file://server/share/x.txt").unwrap();
        let err = file_path(&unc).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert!(err.message().contains("authority"));

        // Empty and localhost authorities remain valid.
        assert!(file_path(&Url::parse("file:///tmp/ok.txt").unwrap()).is_ok());
        assert!(file_path(&Url::parse("file://localhost/tmp/ok.txt").unwrap()).is_ok());
    }

    // N12 regression: copying from a special filesystem object (here a unix
    // socket; a fifo/device hits the identical `owner::reject_special_file`
    // branch) is rejected before `tokio::fs::copy` would open and block on it.
    // Bounded by a timeout so a regression that reintroduces the blocking open
    // fails loudly instead of hanging the suite.
    /// Write-side etag preconditions refuse before committing anything, so
    /// they report `PreconditionFailed` rather than `ObjectModified`. Pins all
    /// four mutating slots at once: five sites were retagged and no existing
    /// test noticed, which is what makes this worth having.
    #[tokio::test]
    async fn write_side_precondition_mismatches_report_precondition_failed() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Url::from_directory_path(tmp.path()).unwrap();
        let backend = backend_over_tempdir(&tmp).await;
        let address = root.join("object").unwrap();

        backend
            .write(
                Request::new(WriteRequest {
                    address: address.clone(),
                    body: Body::Bytes(b"original".to_vec()),
                    options: WriteOptions::default(),
                }),
                None,
            )
            .await
            .unwrap();
        let stale = "size:0,mtime:0";

        // write, via the destination precondition
        let error = backend
            .write(
                Request::new(WriteRequest {
                    address: address.clone(),
                    body: Body::Bytes(b"clobber".to_vec()),
                    options: WriteOptions {
                        if_dest: IfDestExists::MatchEtag(stale.to_string()),
                        ..WriteOptions::default()
                    },
                }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(
            error.code(),
            ErrorCode::PreconditionFailed,
            "write: {error}"
        );

        // delete
        let error = backend
            .delete(
                Request::new(DeleteRequest {
                    address: address.clone(),
                    options: DeleteOptions {
                        if_match: Some(stale.to_string()),
                    },
                }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(
            error.code(),
            ErrorCode::PreconditionFailed,
            "delete: {error}"
        );

        // copy, on the pre-read check
        let error = backend
            .copy(
                Request::new(CopyRequest {
                    source: address.clone(),
                    destination: root.join("copied").unwrap(),
                    options: CopyOptions {
                        if_source: Some(stale.to_string()),
                        ..CopyOptions::default()
                    },
                }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(error.code(), ErrorCode::PreconditionFailed, "copy: {error}");

        // rename
        let error = backend
            .rename(
                Request::new(RenameRequest {
                    source: address.clone(),
                    destination: root.join("renamed").unwrap(),
                    options: RenameOptions {
                        if_source: Some(stale.to_string()),
                        ..RenameOptions::default()
                    },
                }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(
            error.code(),
            ErrorCode::PreconditionFailed,
            "rename: {error}"
        );

        // Nothing was committed by any of them.
        assert!(!tmp.path().join("copied").exists());
        assert!(!tmp.path().join("renamed").exists());
        let info = backend
            .stat(
                Request::new(StatRequest {
                    address: address.clone(),
                    options: StatOptions::default(),
                }),
                None,
            )
            .await
            .unwrap();
        assert_eq!(info.size, Some(8), "the original object is untouched");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn copy_rejects_special_file_source() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Url::from_directory_path(tmp.path()).unwrap();
        let backend = backend_over_tempdir(&tmp).await;

        // A bound unix socket is a special file inside the root.
        let socket_path = tmp.path().join("special.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();
        let source = Url::from_file_path(&socket_path).unwrap();
        let destination = root.join("copy.out").unwrap();

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            backend.copy(
                Request::new(CopyRequest {
                    source,
                    destination,
                    options: CopyOptions::default(),
                }),
                None,
            ),
        )
        .await
        .expect("copy must return promptly, never block on the special file");
        let err = result.unwrap_err();
        assert_eq!(err.code(), ErrorCode::Unsupported);
    }

    // A `copy` destination that is a DANGLING in-root symlink pointing outside
    // the root must not follow the link: `tokio::fs::copy` would open the dest
    // O_CREAT|O_TRUNC through the link and land the bytes outside (containment
    // passes because the link's nearest existing ancestor is the root). The
    // temp-sibling + rename commit REPLACES the link entry, so the object
    // materializes in-root and nothing is created at the link's target.
    #[cfg(unix)]
    #[tokio::test]
    async fn copy_replaces_dangling_escaping_symlink_dest_instead_of_following() {
        let tmp = tempfile::tempdir().unwrap();
        let root_dir = tmp.path().join("root");
        let outside_dir = tmp.path().join("outside");
        std::fs::create_dir_all(&root_dir).unwrap();
        std::fs::create_dir_all(&outside_dir).unwrap();
        std::fs::write(root_dir.join("src.txt"), b"copied-bytes").unwrap();
        // Dangling: the target does not exist, so realpath containment anchors
        // on the root and passes.
        let escape_target = outside_dir.join("new.txt");
        std::os::unix::fs::symlink(&escape_target, root_dir.join("dlink.txt")).unwrap();

        let root = Url::from_directory_path(&root_dir).unwrap();
        let mut config = LayerConfig::new();
        config.insert("root".into(), ConfigValue::String(root.to_string()));
        let backend = FileBackendFactory
            .create_backend("files", &config, None)
            .await
            .unwrap();

        let source = Url::from_file_path(root_dir.join("src.txt")).unwrap();
        let destination = Url::from_file_path(root_dir.join("dlink.txt")).unwrap();
        backend
            .copy(
                Request::new(CopyRequest {
                    source,
                    destination: destination.clone(),
                    options: CopyOptions::default(),
                }),
                None,
            )
            .await
            .expect("copy commits in-root by replacing the link entry");

        // Nothing escaped the root...
        assert!(
            !escape_target.exists(),
            "copy must not write through the escaping symlink"
        );
        // ...and the destination is now a regular in-root file with the bytes.
        let dest_path = root_dir.join("dlink.txt");
        let meta = std::fs::symlink_metadata(&dest_path).unwrap();
        assert!(
            meta.file_type().is_file(),
            "the symlink entry is replaced by a regular file"
        );
        assert_eq!(std::fs::read(&dest_path).unwrap(), b"copied-bytes");
    }

    // A plain copy (no symlinks involved) still round-trips through the
    // temp-sibling + rename commit.
    // Regression: copy(src, src) must not zero the file out — a naive
    // destination open would truncate the source before its bytes were read.
    // The temp-sibling staging (write_body reads the source AFTER the
    // destination commit moved to a rename) plus the same-path lock
    // dedupe in `lock_source_and_destination` closed it; pin the
    // no-data-loss outcome so a staging refactor cannot reopen it.
    #[tokio::test]
    async fn copy_to_self_preserves_content() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Url::from_directory_path(tmp.path()).unwrap();
        let backend = backend_over_tempdir(&tmp).await;
        std::fs::write(tmp.path().join("self.txt"), b"important data").unwrap();
        let result = backend
            .copy(
                Request::new(CopyRequest {
                    source: root.join("self.txt").unwrap(),
                    destination: root.join("self.txt").unwrap(),
                    options: CopyOptions::default(),
                }),
                None,
            )
            .await
            .expect("copy-to-self must not fail");
        match result {
            WriteStep::Done(done) => assert_eq!(done.info.size, Some(14)),
            other => panic!("expected Done, got {other:?}"),
        }
        assert_eq!(
            std::fs::read(tmp.path().join("self.txt")).unwrap(),
            b"important data",
            "copy-to-self must preserve the object bytes"
        );
    }

    // Regression: `RenameOptions.if_dest` is the opt-in no-overwrite
    // control (default stays POSIX overwrite). `IfDestExists::Fail`
    // against an existing destination refuses with `AlreadyExists` and
    // leaves the destination bytes intact.
    #[tokio::test]
    async fn rename_no_overwrite_refuses_existing_destination() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Url::from_directory_path(tmp.path()).unwrap();
        let backend = backend_over_tempdir(&tmp).await;
        std::fs::write(tmp.path().join("src.txt"), b"source").unwrap();
        std::fs::write(tmp.path().join("dst.txt"), b"precious").unwrap();
        let err = backend
            .rename(
                Request::new(RenameRequest {
                    source: root.join("src.txt").unwrap(),
                    destination: root.join("dst.txt").unwrap(),
                    options: RenameOptions {
                        if_dest: IfDestExists::Fail,
                        ..RenameOptions::default()
                    },
                }),
                None,
            )
            .await
            .expect_err("no-overwrite rename against an existing destination must refuse");
        assert_eq!(err.code(), ErrorCode::AlreadyExists);
        assert_eq!(
            std::fs::read(tmp.path().join("dst.txt")).unwrap(),
            b"precious",
            "the refused rename must leave the destination intact"
        );
        // The POSIX default is pinned deliberately: rename with
        // `IfDestExists::Overwrite` (the default) replaces the destination.
        backend
            .rename(
                Request::new(RenameRequest {
                    source: root.join("src.txt").unwrap(),
                    destination: root.join("dst.txt").unwrap(),
                    options: RenameOptions::default(),
                }),
                None,
            )
            .await
            .expect("default rename overwrites");
        assert_eq!(
            std::fs::read(tmp.path().join("dst.txt")).unwrap(),
            b"source"
        );
    }

    #[tokio::test]
    async fn copy_round_trips_regular_destination() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Url::from_directory_path(tmp.path()).unwrap();
        let backend = backend_over_tempdir(&tmp).await;
        std::fs::write(tmp.path().join("src.txt"), b"plain").unwrap();
        backend
            .copy(
                Request::new(CopyRequest {
                    source: root.join("src.txt").unwrap(),
                    destination: root.join("dst.txt").unwrap(),
                    options: CopyOptions::default(),
                }),
                None,
            )
            .await
            .expect("plain copy");
        assert_eq!(std::fs::read(tmp.path().join("dst.txt")).unwrap(), b"plain");
    }

    // The static `[ovstorage.root]` / config-as-Stack path honors the same
    // `prefix` contract as `add_connection`: the exposed route narrows to the
    // prefix instead of silently widening to all of `root`.
    #[tokio::test]
    async fn create_backend_static_prefix_narrows_route() {
        let tmp = tempfile::tempdir().unwrap();
        let public = tmp.path().join("public");
        std::fs::create_dir_all(&public).unwrap();
        let root = Url::from_directory_path(tmp.path()).unwrap();
        let prefix = Url::from_directory_path(&public).unwrap();

        let mut config = LayerConfig::new();
        config.insert("root".into(), ConfigValue::String(root.to_string()));
        config.insert("prefix".into(), ConfigValue::String(prefix.to_string()));
        let backend = FileBackendFactory
            .create_backend("files", &config, None)
            .await
            .unwrap();

        // Only the prefix is exposed as a root...
        let (snapshot, _) = backend
            .list_address_roots(&Extensions::new(), None)
            .await
            .unwrap();
        let roots: Vec<&Url> = snapshot.roots.iter().map(|info| &info.root).collect();
        assert_eq!(roots, vec![&prefix], "the static route is the prefix");
        // ...an object under it routes, a root-level sibling does not.
        assert!(
            backend
                .root_info_for(&prefix.join("ok.txt").unwrap(), &Extensions::new(), None)
                .await
                .is_ok()
        );
        assert!(
            backend
                .root_info_for(&root.join("secret.txt").unwrap(), &Extensions::new(), None)
                .await
                .is_err()
        );
    }

    // A static `prefix` without a `root` to scope it is rejected loudly.
    #[tokio::test]
    async fn create_backend_rejects_prefix_without_root() {
        let mut config = LayerConfig::new();
        config.insert(
            "prefix".into(),
            ConfigValue::String("file:///srv/public/".into()),
        );
        let err = match FileBackendFactory
            .create_backend("files", &config, None)
            .await
        {
            Ok(_) => panic!("a static 'prefix' without a 'root' must be rejected"),
            Err(err) => err,
        };
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert!(err.message().contains("prefix"));
    }

    // N12 regression: an already-cancelled token aborts the copy with
    // `Cancelled` rather than running it to completion.
    #[tokio::test]
    async fn copy_honors_cancellation() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Url::from_directory_path(tmp.path()).unwrap();
        let backend = backend_over_tempdir(&tmp).await;
        let source = root.join("src.bin").unwrap();
        let destination = root.join("dst.bin").unwrap();
        write_file(&backend, &source, b"payload").await;

        let cancel = CancellationToken::new();
        cancel.cancel();
        let err = backend
            .copy(
                Request::new(CopyRequest {
                    source,
                    destination: destination.clone(),
                    options: CopyOptions::default(),
                }),
                Some(cancel),
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Cancelled);
    }

    // N2 regression: `root=<tmp>, prefix=<tmp>/public/` exposes ONLY the
    // prefix as the route — an object under the prefix is reachable while a
    // sibling directly under root (outside the prefix) is not routable.
    #[tokio::test]
    async fn add_connection_prefix_narrows_route_to_prefix() {
        let tmp = tempfile::tempdir().unwrap();
        let public = tmp.path().join("public");
        std::fs::create_dir_all(&public).unwrap();
        let root = Url::from_directory_path(tmp.path()).unwrap();
        let prefix = Url::from_directory_path(&public).unwrap();

        let backend = FileBackendFactory
            .create_backend("files", &LayerConfig::new(), None)
            .await
            .unwrap();
        let mut config = LayerConfig::new();
        config.insert("root".into(), ConfigValue::String(root.to_string()));
        config.insert("prefix".into(), ConfigValue::String(prefix.to_string()));
        let connection = backend
            .add_connection(
                Request::new(LayerConnectionRequest {
                    target: "files".into(),
                    connection: ConnectionRequest {
                        backend_kind: FILE_BACKEND_KIND.into(),
                        config,
                        credentials: SecretBundle::default(),
                        persist: false,
                        display_name: None,
                    },
                }),
                None,
            )
            .await
            .unwrap();
        // The route is the prefix, not the broader root.
        assert_eq!(connection.current_addresses, vec![prefix.clone()]);

        // An object under the prefix routes here; a sibling under root but
        // outside the prefix does not.
        let inside = prefix.join("ok.txt").unwrap();
        assert!(
            backend
                .root_info_for(&inside, &Extensions::new(), None)
                .await
                .is_ok()
        );
        let outside_prefix = root.join("secret.txt").unwrap();
        assert!(
            backend
                .root_info_for(&outside_prefix, &Extensions::new(), None)
                .await
                .is_err()
        );
    }

    // N2 regression: a `prefix` that escapes `root` is rejected, not silently
    // widened.
    #[tokio::test]
    async fn add_connection_prefix_outside_root_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let root_dir = tmp.path().join("root");
        let elsewhere = tmp.path().join("elsewhere");
        std::fs::create_dir_all(&root_dir).unwrap();
        std::fs::create_dir_all(&elsewhere).unwrap();
        let root = Url::from_directory_path(&root_dir).unwrap();
        let prefix = Url::from_directory_path(&elsewhere).unwrap();

        let backend = FileBackendFactory
            .create_backend("files", &LayerConfig::new(), None)
            .await
            .unwrap();
        let mut config = LayerConfig::new();
        config.insert("root".into(), ConfigValue::String(root.to_string()));
        config.insert("prefix".into(), ConfigValue::String(prefix.to_string()));
        let err = backend
            .add_connection(
                Request::new(LayerConnectionRequest {
                    target: "files".into(),
                    connection: ConnectionRequest {
                        backend_kind: FILE_BACKEND_KIND.into(),
                        config,
                        credentials: SecretBundle::default(),
                        persist: false,
                        display_name: None,
                    },
                }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert!(err.message().contains("prefix"));
    }

    // N9: the projected descriptor matches the connection contract — `root`
    // required, `prefix` advertised.
    #[test]
    fn file_descriptor_marks_root_required_and_advertises_prefix() {
        let descriptor = file_descriptor();
        let root = descriptor
            .config_schema
            .iter()
            .find(|field| field.key == "root")
            .expect("root field present");
        assert!(
            root.required,
            "root must be required by the connection contract"
        );
        assert!(
            descriptor
                .config_schema
                .iter()
                .any(|field| field.key == "prefix"),
            "prefix field must be advertised"
        );
        let confine = descriptor
            .config_schema
            .iter()
            .find(|field| field.key == "confine_to_root")
            .expect("confine_to_root field advertised");
        assert!(
            !confine.required,
            "confine_to_root must be optional (default off)"
        );
        assert!(
            matches!(confine.default, Some(ConfigValue::Bool(false))),
            "confine_to_root default must be false (virtual-tree model)"
        );
    }

    async fn backend_over_tempdir(tmp: &tempfile::TempDir) -> LayerHandle {
        let root = Url::from_directory_path(tmp.path()).unwrap();
        let mut config = LayerConfig::new();
        config.insert("root".into(), ConfigValue::String(root.to_string()));
        FileBackendFactory
            .create_backend("files", &config, None)
            .await
            .unwrap()
    }

    async fn list_stream_items(
        backend: &LayerHandle,
        prefix: &Url,
        options: ListOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<Vec<ObjectInfo>> {
        use futures::TryStreamExt as _;

        backend
            .list_stream(
                Request::new(ListRequest {
                    prefix: prefix.clone(),
                    options,
                }),
                cancel,
            )
            .await?
            .try_collect()
            .await
    }

    /// Build a backend the way runtime/brokered compositions do: an empty
    /// `create_backend`, then contribute `root` (+ optional `confine_to_root`)
    /// through `add_connection` — the path a static-config test would bypass.
    #[cfg(unix)]
    async fn backend_via_connection(root: &Url, confine: Option<bool>) -> LayerHandle {
        let backend = FileBackendFactory
            .create_backend("files", &LayerConfig::new(), None)
            .await
            .unwrap();
        let mut config = HashMap::new();
        config.insert("root".to_string(), ConfigValue::String(root.to_string()));
        if let Some(value) = confine {
            config.insert("confine_to_root".to_string(), ConfigValue::Bool(value));
        }
        let request = LayerConnectionRequest {
            target: "files".to_string(),
            connection: ConnectionRequest {
                backend_kind: FILE_BACKEND_KIND.to_string(),
                config,
                credentials: SecretBundle::default(),
                persist: false,
                display_name: None,
            },
        };
        backend
            .add_connection(Request::new(request), None)
            .await
            .unwrap();
        backend
    }

    /// Buffer a `ReadResult`'s content: whole-object file reads return a
    /// `LocalDelegate`, ranged reads a `Stream`.
    async fn read_content(read: ReadResult) -> (Vec<u8>, ObjectInfo) {
        match read {
            ReadResult::Bytes { bytes, info } => (bytes, info),
            ReadResult::LocalDelegate(local) => {
                (tokio::fs::read(&local.path).await.unwrap(), local.info)
            }
            ReadResult::Stream { mut stream, info } => {
                use futures::StreamExt;
                let mut bytes = Vec::new();
                while let Some(chunk) = stream.next().await {
                    bytes.extend_from_slice(&chunk.unwrap());
                }
                (bytes, info)
            }
            other => panic!("unexpected read result: {other:?}"),
        }
    }

    async fn write_file(backend: &LayerHandle, address: &Url, bytes: &[u8]) {
        backend
            .write(
                Request::new(WriteRequest {
                    address: address.clone(),
                    body: Body::Bytes(bytes.to_vec()),
                    options: WriteOptions::default(),
                }),
                None,
            )
            .await
            .unwrap();
    }

    async fn stat(backend: &LayerHandle, address: &Url) -> ObjectInfo {
        backend
            .stat(
                Request::new(StatRequest {
                    address: address.clone(),
                    options: StatOptions::default(),
                }),
                None,
            )
            .await
            .unwrap()
    }

    fn set_one(key: &str, value: &str) -> UpdateMetadataOptions {
        let mut set = std::collections::HashMap::new();
        set.insert(key.to_string(), value.to_string());
        UpdateMetadataOptions {
            user_metadata_set: set,
            ..UpdateMetadataOptions::default()
        }
    }

    /// The refusal the contract asks for: a write carrying caller metadata this
    /// backend cannot keep fails with `Unsupported` before anything touches the
    /// filesystem — no object, no staging temp, not even the parent directory.
    /// `write_stream` shares the path, so both slots are driven.
    #[tokio::test]
    async fn write_refuses_user_metadata_it_cannot_store() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Url::from_directory_path(tmp.path()).unwrap();
        let file = root.join("nested/withmeta.txt").unwrap();
        let backend = backend_over_tempdir(&tmp).await;
        let mut user_metadata = UserMetadata::new();
        user_metadata.insert("origin".into(), "write".into());
        assert!(!user_metadata.is_empty(), "the fixture must carry a key");

        for streamed in [false, true] {
            let request = Request::new(WriteRequest {
                address: file.clone(),
                body: Body::Bytes(b"payload".to_vec()),
                options: WriteOptions {
                    user_metadata: Some(user_metadata.clone()),
                    ..WriteOptions::default()
                },
            });
            let result = if streamed {
                backend.write_stream(request, None).await
            } else {
                backend.write(request, None).await
            };
            let err = result.expect_err("a write carrying user metadata must be refused");
            assert_eq!(err.code(), ErrorCode::Unsupported, "{err:?}");
            assert!(err.message().contains("drop user_metadata"), "{err}");
            assert!(err.next_action().is_some(), "{err}");
        }
        assert!(
            !file.to_file_path().unwrap().exists(),
            "the object must not commit"
        );
        assert!(
            !tmp.path().join("nested").exists(),
            "the refusal must precede any directory creation"
        );
        assert_eq!(temp_sibling_count(tmp.path()), 0, "staging temp leaked");
    }

    /// The refusal is keyed on `user_metadata` alone. An absent map, an empty
    /// map and a `message` are not metadata this backend has to keep, so those
    /// writes proceed, and every object reports an empty map.
    #[tokio::test]
    async fn write_accepts_an_absent_or_empty_map_and_a_message() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Url::from_directory_path(tmp.path()).unwrap();
        let backend = backend_over_tempdir(&tmp).await;
        let cases = [
            ("absent", WriteOptions::default()),
            (
                "empty",
                WriteOptions {
                    user_metadata: Some(UserMetadata::new()),
                    ..WriteOptions::default()
                },
            ),
            (
                "message",
                WriteOptions {
                    message: Some("annotated".into()),
                    ..WriteOptions::default()
                },
            ),
        ];
        for (name, options) in cases {
            let file = root.join(&format!("{name}.txt")).unwrap();
            write_with_options(&backend, &file, b"payload", options)
                .await
                .unwrap_or_else(|err| panic!("{name}: {err:?}"));
            let info = stat(&backend, &file).await;
            assert_eq!(info.size, Some(b"payload".len() as u64), "{name}");
            assert_eq!(info.user_metadata, Some(UserMetadata::new()), "{name}");
        }
    }

    /// `copy` and `rename` carry no `user_metadata`, and their `message` is an
    /// annotation the backend drops, so both proceed and the destination
    /// reports an empty map.
    #[tokio::test]
    async fn copy_and_rename_accept_a_message() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Url::from_directory_path(tmp.path()).unwrap();
        let backend = backend_over_tempdir(&tmp).await;
        let source = root.join("source.txt").unwrap();
        let copied = root.join("copied.txt").unwrap();
        let renamed = root.join("renamed.txt").unwrap();
        write_file(&backend, &source, b"body").await;

        backend
            .copy(
                Request::new(CopyRequest {
                    source: source.clone(),
                    destination: copied.clone(),
                    options: CopyOptions {
                        message: Some("copied".into()),
                        ..CopyOptions::default()
                    },
                }),
                None,
            )
            .await
            .unwrap();
        backend
            .rename(
                Request::new(RenameRequest {
                    source: copied.clone(),
                    destination: renamed.clone(),
                    options: RenameOptions {
                        message: Some("renamed".into()),
                        ..RenameOptions::default()
                    },
                }),
                None,
            )
            .await
            .unwrap();

        let info = stat(&backend, &renamed).await;
        assert_eq!(info.size, Some(b"body".len() as u64));
        assert_eq!(info.user_metadata, Some(UserMetadata::new()));
        assert!(!copied.to_file_path().unwrap().exists());
    }

    /// `update_metadata` has nothing to patch on this backend, so it is
    /// `Unsupported` whether or not the target exists; only an address the
    /// backend cannot serve at all reports its own error first.
    #[tokio::test]
    async fn update_metadata_is_unsupported_whether_or_not_the_target_exists() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Url::from_directory_path(tmp.path()).unwrap();
        let backend = backend_over_tempdir(&tmp).await;
        let file = root.join("present.txt").unwrap();
        let missing = root.join("ghost.txt").unwrap();
        write_file(&backend, &file, b"body").await;

        for address in [&file, &missing] {
            let err = backend
                .update_metadata(
                    Request::new(UpdateMetadataRequest {
                        address: address.clone(),
                        options: set_one("color", "red"),
                    }),
                    None,
                )
                .await
                .unwrap_err();
            assert_eq!(err.code(), ErrorCode::Unsupported, "{address}: {err:?}");
            assert!(err.message().contains("update_metadata"), "{err}");
            // `UpdateMetadataOptions` has no map to drop, so the write verb's
            // remedy must not leak into this one.
            assert!(!err.message().contains("drop user_metadata"), "{err}");
            assert!(
                err.next_action()
                    .is_some_and(|a| !a.contains("write the object")),
                "{err}"
            );
        }
        assert_eq!(
            stat(&backend, &file).await.user_metadata,
            Some(UserMetadata::new())
        );

        let outside = tempfile::tempdir().unwrap();
        let escaped = Url::from_directory_path(outside.path())
            .unwrap()
            .join("elsewhere.txt")
            .unwrap();
        let err = backend
            .update_metadata(
                Request::new(UpdateMetadataRequest {
                    address: escaped,
                    options: set_one("color", "red"),
                }),
                None,
            )
            .await
            .unwrap_err();
        assert_ne!(
            err.code(),
            ErrorCode::Unsupported,
            "an address outside the root reports its own error: {err:?}"
        );
    }

    /// The capability surface says what the verbs do: no native patch and no
    /// rewrite emulation, while the single-rename write stays atomic.
    #[test]
    fn file_capabilities_declare_no_metadata_patch() {
        let capabilities = file_capabilities();
        assert!(!capabilities.supports_native_metadata_patch);
        assert!(!capabilities.supports_metadata_rewrite_emulation);
        assert!(capabilities.writes_are_atomic);
        assert!(
            !file_descriptor().supports_user_metadata,
            "a kind that refuses user metadata must not invite an attribution layer"
        );
    }

    /// A `.ovstorage-meta` directory an earlier installation left on disk is
    /// ordinary content: `list` shows it, its entries are addressable, it
    /// blocks `delete_directory` like any other entry, and the name is writable.
    #[tokio::test]
    async fn a_metadata_directory_left_on_disk_is_ordinary_content() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Url::from_directory_path(tmp.path()).unwrap();
        let backend = backend_over_tempdir(&tmp).await;
        let dir = root.join("legacy/").unwrap();
        let dir_path = dir.to_file_path().unwrap();
        let leftover = dir_path.join(".ovstorage-meta");
        std::fs::create_dir_all(&leftover).unwrap();
        std::fs::write(leftover.join("deadbeef.meta"), b"6b=76\n").unwrap();

        let page = backend
            .list(
                Request::new(ListRequest {
                    prefix: dir.clone(),
                    options: ListOptions::default(),
                }),
                None,
            )
            .await
            .unwrap();
        let addresses: Vec<_> = page
            .items
            .iter()
            .map(|item| item.address.as_str().to_owned())
            .collect();
        assert!(
            addresses
                .iter()
                .any(|address| address.contains(".ovstorage-meta")),
            "list must show the directory as ordinary content: {addresses:?}"
        );

        let entry = dir.join(".ovstorage-meta/deadbeef.meta").unwrap();
        let info = stat(&backend, &entry).await;
        assert_eq!(info.size, Some(6));
        assert_eq!(info.user_metadata, Some(UserMetadata::new()));

        let err = backend
            .delete_directory(
                Request::new(DeleteDirectoryRequest {
                    address: dir.clone(),
                    options: DeleteDirectoryOptions,
                }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::DirectoryNotEmpty, "{err:?}");
        assert!(leftover.is_dir(), "a refused removal must leave the entry");

        let fresh = dir.join(".ovstorage-meta/new.txt").unwrap();
        write_file(&backend, &fresh, b"ok").await;
        assert_eq!(stat(&backend, &fresh).await.size, Some(2));
    }

    #[tokio::test]
    async fn list_does_not_surface_internal_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Url::from_directory_path(tmp.path()).unwrap();
        let file = root.join("visible.txt").unwrap();
        let backend = backend_over_tempdir(&tmp).await;
        write_file(&backend, &file, b"body").await;
        // An in-flight atomic-write staging temp is the one entry the backend
        // hides from enumeration; seed one in the staging shape.
        let staged = tmp.path().join(".visible.txt.123456789.4242.7.tmp");
        std::fs::write(&staged, b"partial").unwrap();
        assert!(is_atomic_write_temp_sibling(&staged));

        let page = backend
            .list(
                Request::new(ListRequest {
                    prefix: root.clone(),
                    options: ListOptions::default(),
                }),
                None,
            )
            .await
            .unwrap();

        let addresses: Vec<_> = page
            .items
            .iter()
            .map(|item| item.address.as_str())
            .collect();
        assert!(
            addresses.contains(&file.as_str()),
            "expected the user file in {addresses:?}"
        );
        assert!(
            !addresses.iter().any(|address| address.ends_with(".tmp")),
            "list surfaced an in-flight staging temp: {addresses:?}"
        );
        // Every listed object reports an empty user-metadata map.
        let listed = page
            .items
            .iter()
            .find(|item| item.address == file)
            .expect("listed file");
        assert_eq!(listed.user_metadata, Some(UserMetadata::new()));
    }

    /// Count `.<name>.<...>.tmp` atomic-write temp siblings directly under `dir`
    /// (non-recursive). Asserts the temp sibling never leaks.
    fn temp_sibling_count(dir: &std::path::Path) -> usize {
        std::fs::read_dir(dir)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| is_atomic_write_temp_sibling(&entry.path()))
            .count()
    }

    async fn write_with_options(
        backend: &LayerHandle,
        address: &Url,
        bytes: &[u8],
        options: WriteOptions,
    ) -> Result<WriteResult> {
        backend
            .write(
                Request::new(WriteRequest {
                    address: address.clone(),
                    body: Body::Bytes(bytes.to_vec()),
                    options,
                }),
                None,
            )
            .await
    }

    #[tokio::test]
    async fn write_leaves_no_temp_sibling_orphan_on_success() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Url::from_directory_path(tmp.path()).unwrap();
        let file = root.join("clean.txt").unwrap();
        let backend = backend_over_tempdir(&tmp).await;

        write_file(&backend, &file, b"payload").await;

        assert_eq!(
            temp_sibling_count(tmp.path()),
            0,
            "a successful write must not leave an atomic-write temp sibling"
        );
        // The only directory entry should be the written object itself.
        let names: Vec<_> = std::fs::read_dir(tmp.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            names,
            vec!["clean.txt".to_string()],
            "unexpected entries: {names:?}"
        );
    }

    #[tokio::test]
    async fn write_into_fresh_nested_path_creates_missing_ancestors() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Url::from_directory_path(tmp.path()).unwrap();
        let leaf = root.join("a/b/c/leaf.txt").unwrap();
        let backend = backend_over_tempdir(&tmp).await;

        let result = backend
            .write(
                Request::new(WriteRequest {
                    address: leaf,
                    body: Body::Bytes(b"deep".to_vec()),
                    options: WriteOptions::default(),
                }),
                None,
            )
            .await;
        assert!(result.is_ok(), "write must create its path: {result:?}");

        let on_disk = tmp.path().join("a").join("b").join("c").join("leaf.txt");
        assert!(
            on_disk.is_file(),
            "leaf must exist under freshly created ancestors"
        );
        assert_eq!(std::fs::read(&on_disk).unwrap(), b"deep");
    }

    #[tokio::test]
    async fn write_failure_leaves_no_orphan_and_preserves_destination() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Url::from_directory_path(tmp.path()).unwrap();
        let file = root.join("guarded.txt").unwrap();
        let backend = backend_over_tempdir(&tmp).await;

        // Seed the destination so an IfDestExists::Fail write must error. The
        // fail-fast preflight rejects before any temp sibling is staged; the
        // assertions below still hold (no orphan, destination preserved)
        // regardless of where in the write the precondition trips.
        write_file(&backend, &file, b"original").await;

        let err = write_with_options(
            &backend,
            &file,
            b"replacement",
            WriteOptions {
                if_dest: IfDestExists::Fail,
                ..WriteOptions::default()
            },
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), ErrorCode::AlreadyExists);

        // The TempFileGuard cleaned up: no orphaned temp sibling remains.
        assert_eq!(
            temp_sibling_count(tmp.path()),
            0,
            "failed write must not leave a temp sibling orphan"
        );
        // The original destination is intact and unmodified.
        let read = backend
            .read(
                Request::new(ReadRequest {
                    address: file.clone(),
                    options: ReadOptions::default(),
                }),
                None,
            )
            .await
            .unwrap();
        let (bytes, _) = read_content(read).await;
        assert_eq!(bytes, b"original");
    }

    #[tokio::test]
    async fn no_overwrite_concurrent_writers_only_one_succeeds() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Url::from_directory_path(tmp.path()).unwrap();
        let object = root.join("race.txt").unwrap();
        // Shared across tasks: the per-target lock lives in this single backend.
        // LayerHandle is already Arc<dyn Layer>, so clones share one FileBackend.
        let backend = backend_over_tempdir(&tmp).await;

        let mut handles = Vec::new();
        for tag in ["one", "two", "three", "four"] {
            let backend = backend.clone();
            let address = object.clone();
            handles.push(tokio::spawn(async move {
                backend
                    .write(
                        Request::new(WriteRequest {
                            address,
                            body: Body::Bytes(tag.as_bytes().to_vec()),
                            options: WriteOptions {
                                if_dest: IfDestExists::Fail,
                                ..WriteOptions::default()
                            },
                        }),
                        None,
                    )
                    .await
            }));
        }
        let mut successes = 0;
        let mut conflicts = 0;
        for handle in handles {
            match handle.await.unwrap() {
                Ok(_) => successes += 1,
                Err(err) if err.code() == ErrorCode::AlreadyExists => conflicts += 1,
                Err(err) => panic!("unexpected error: {err:?}"),
            }
        }
        assert_eq!(
            successes, 1,
            "exactly one IfDestExists::Fail writer must commit"
        );
        assert_eq!(conflicts, 3, "three peers must observe AlreadyExists");
        assert_eq!(
            temp_sibling_count(tmp.path()),
            0,
            "no temp sibling orphan after a concurrent write race"
        );
    }

    /// A directory holding an in-flight atomic-write staging temp is not empty:
    /// the kernel counts that entry, so `remove_dir` cannot succeed. The refusal
    /// must be reported as `DirectoryNotEmpty` — a retryable code would have a
    /// caller spin for the whole duration of the upload.
    ///
    /// The multi-threaded flavour is a correctness requirement, not a taste
    /// choice. Parking the body means blocking on a `std::sync::mpsc` receive
    /// inside `BodyStream::next_chunk`, which `BodyStream` gives no async
    /// equivalent for, so that blocking call occupies a runtime worker for as
    /// long as the write is parked. A single-worker runtime has no thread left
    /// to drive `delete_directory` and the test deadlocks instead of failing.
    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn delete_directory_refuses_a_directory_holding_an_in_flight_write() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Url::from_directory_path(tmp.path()).unwrap();
        // Trailing slash marks this as a directory address.
        let dir = root.join("staging/").unwrap();
        let backend = backend_over_tempdir(&tmp).await;
        std::fs::create_dir_all(dir.to_file_path().unwrap()).unwrap();

        // The body yields one chunk, then parks until the test releases it, so
        // the staging temp sits in the directory for a window the test controls.
        let (release, parked) = std::sync::mpsc::channel::<()>();
        let mut chunk = 0;
        let body = Body::Stream(BodyStream::from_iter(std::iter::from_fn(move || {
            chunk += 1;
            match chunk {
                1 => Some(Ok(b"first-".to_vec())),
                2 => {
                    parked.recv().expect("release channel");
                    Some(Ok(b"last".to_vec()))
                }
                _ => None,
            }
        })));
        let child = dir.join("child.bin").unwrap();
        let writer = tokio::spawn({
            let backend = backend.clone();
            let address = child.clone();
            async move {
                backend
                    .write(
                        Request::new(WriteRequest {
                            address,
                            body,
                            options: WriteOptions::default(),
                        }),
                        None,
                    )
                    .await
            }
        });

        let dir_path = dir.to_file_path().unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while temp_sibling_count(&dir_path) == 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "timed out waiting for the staging temp sibling in {dir_path:?}"
            );
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }

        let err = backend
            .delete_directory(
                Request::new(DeleteDirectoryRequest {
                    address: dir.clone(),
                    options: DeleteDirectoryOptions,
                }),
                None,
            )
            .await
            .expect_err("a directory holding a staging temp cannot be removed");
        assert_eq!(
            err.code(),
            ErrorCode::DirectoryNotEmpty,
            "a removal refused because the directory holds something must not be retryable: {err:?}"
        );
        // The writer holds the staging lock, so the refusal classified its temp
        // as live and left it alone; with the writer-side lock removed the
        // removal would clear the temp and the writer's rename would fail.
        assert_eq!(
            temp_sibling_count(&dir_path),
            1,
            "a refused removal must leave the live writer's staging temp in place"
        );

        release.send(()).unwrap();
        let committed = writer
            .await
            .unwrap()
            .expect("the refused removal must not damage the concurrent writer");
        assert_eq!(committed.info.size, Some(b"first-last".len() as u64));
        // The writer's handle, and the lock it carried, are gone with the
        // write: the published bytes read plainly through the filesystem.
        assert_eq!(
            std::fs::read(child.to_file_path().unwrap()).unwrap(),
            b"first-last",
            "the published object must be readable once the writer returns"
        );
        assert_eq!(temp_sibling_count(&dir_path), 0);
        let (bytes, _) = read_content(
            backend
                .read(
                    Request::new(ReadRequest {
                        address: child.clone(),
                        options: ReadOptions::default(),
                    }),
                    None,
                )
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(bytes, b"first-last");
    }

    /// Create `dir` empty through the API and return its on-disk path, so the
    /// staging-temp cases start from a directory the removal would otherwise
    /// delete outright.
    async fn seed_empty_dir(backend: &LayerHandle, dir: &Url) -> std::path::PathBuf {
        backend
            .create_directory(
                Request::new(CreateDirectoryRequest {
                    address: dir.clone(),
                    options: CreateDirectoryOptions::default(),
                }),
                None,
            )
            .await
            .unwrap();
        dir.to_file_path().unwrap()
    }

    /// A staging temp left by a writer that died without unwinding wears the
    /// production name but holds no lock, so the removal clears it and the
    /// directory deletes, where a verdict on the name alone would hold the
    /// directory for good.
    #[tokio::test]
    async fn delete_directory_clears_a_staging_temp_whose_writer_is_gone() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Url::from_directory_path(tmp.path()).unwrap();
        let dir = root.join("staging/").unwrap();
        let backend = backend_over_tempdir(&tmp).await;
        seed_empty_dir(&backend, &dir).await;
        let dir_path = dir.to_file_path().unwrap();

        // A handle created and dropped is exactly what a killed writer leaves:
        // the name on disk and no lock on it.
        let orphan = temp::temp_sibling(&dir_path.join("child.bin"));
        drop(std::fs::File::create_new(&orphan).unwrap());
        assert_eq!(temp_sibling_count(&dir_path), 1);

        backend
            .delete_directory(
                Request::new(DeleteDirectoryRequest {
                    address: dir.clone(),
                    options: DeleteDirectoryOptions,
                }),
                None,
            )
            .await
            .expect("a staging temp with no live writer must not hold the directory");
        assert!(
            !orphan.exists(),
            "the orphaned staging temp must be cleared at {orphan:?}"
        );
        assert!(
            !dir_path.exists(),
            "the directory must be removed once its only occupant was an orphan"
        );
    }

    /// The lock, not the name, decides: a staging temp whose lock another
    /// handle holds is a live write, and the removal refuses it without
    /// touching the temp. Releasing the lock is the writer
    /// going away, after which the same removal succeeds.
    #[tokio::test]
    async fn delete_directory_refuses_a_staging_temp_held_by_a_live_writer_handle() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Url::from_directory_path(tmp.path()).unwrap();
        let dir = root.join("staging/").unwrap();
        let backend = backend_over_tempdir(&tmp).await;
        let dir_on_disk = seed_empty_dir(&backend, &dir).await;
        let dir_path = dir.to_file_path().unwrap();

        let temp = temp::temp_sibling(&dir_path.join("child.bin"));
        let holder = std::fs::File::create_new(&temp).unwrap();
        assert!(
            matches!(
                temp::lock_staging_temp(&holder).unwrap(),
                temp::StagingLock::Held
            ),
            "the fresh temp's lock is free"
        );

        let request = || {
            Request::new(DeleteDirectoryRequest {
                address: dir.clone(),
                options: DeleteDirectoryOptions,
            })
        };
        let err = backend
            .delete_directory(request(), None)
            .await
            .expect_err("a locked staging temp is a live write and holds the directory");
        assert_eq!(err.code(), ErrorCode::DirectoryNotEmpty, "{err:?}");
        assert!(
            err.message().contains("in-flight write"),
            "the refusal must name the in-flight write: {err:?}"
        );
        assert!(
            temp.exists(),
            "a refused removal must leave the live staging temp at {temp:?}"
        );
        assert!(
            dir_on_disk.is_dir(),
            "a refused removal must leave the directory in place at {dir_on_disk:?}"
        );

        drop(holder);
        backend
            .delete_directory(request(), None)
            .await
            .expect("once the lock is released the temp is an orphan and the directory deletes");
        assert!(!temp.exists());
        assert!(!dir_path.exists());
    }

    /// A name with three digit groups and nothing before them is hidden by the
    /// Rust matcher but is an ordinary object to the C host over the same
    /// on-disk format. The removal must not destroy it: it keeps the honest
    /// `DirectoryNotEmpty` that every entry the removal cannot positively call
    /// its own gets.
    #[cfg(unix)]
    #[tokio::test]
    async fn delete_directory_keeps_a_name_the_c_host_serves_as_an_object() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Url::from_directory_path(tmp.path()).unwrap();
        let dir = root.join("staging/").unwrap();
        let backend = backend_over_tempdir(&tmp).await;
        let dir_on_disk = seed_empty_dir(&backend, &dir).await;
        let dir_path = dir.to_file_path().unwrap();

        let object = dir_path.join(".2024.01.15.tmp");
        std::fs::write(&object, b"dated report").unwrap();
        assert!(temp::is_atomic_write_temp_sibling(&object));
        assert!(!temp::is_clearable_staging_temp(&object));

        let err = backend
            .delete_directory(
                Request::new(DeleteDirectoryRequest {
                    address: dir.clone(),
                    options: DeleteDirectoryOptions,
                }),
                None,
            )
            .await
            .expect_err(
                "an entry the removal cannot call its own staging temp holds the directory",
            );
        assert_eq!(err.code(), ErrorCode::DirectoryNotEmpty, "{err:?}");
        assert_eq!(
            std::fs::read(&object).unwrap(),
            b"dated report",
            "the entry must survive untouched at {object:?}"
        );
        assert!(
            dir_on_disk.is_dir(),
            "a refused removal must leave the directory"
        );
    }

    /// An entry wearing the exact staging shape but of the wrong kind is not
    /// the backend's temp. It is refused as `DirectoryNotEmpty`, not surfaced
    /// as the raw errno its open or unlink would produce, and it survives.
    #[cfg(unix)]
    #[tokio::test]
    async fn delete_directory_refuses_an_entry_of_the_wrong_kind_wearing_a_staging_name() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let root = Url::from_directory_path(tmp.path()).unwrap();
        let backend = backend_over_tempdir(&tmp).await;

        let refused = |dir: Url| {
            let backend = backend.clone();
            async move {
                let err = backend
                    .delete_directory(
                        Request::new(DeleteDirectoryRequest {
                            address: dir,
                            options: DeleteDirectoryOptions,
                        }),
                        None,
                    )
                    .await
                    .expect_err("an entry of the wrong kind holds the directory");
                assert_eq!(err.code(), ErrorCode::DirectoryNotEmpty, "{err:?}");
                assert!(
                    !err.message().contains("in-flight"),
                    "the refusal must not claim a live write: {err:?}"
                );
                err
            }
        };

        // A directory wearing the name.
        let dir = root.join("as-dir/").unwrap();
        let dir_on_disk = seed_empty_dir(&backend, &dir).await;
        let dir_path = dir.to_file_path().unwrap();
        let impostor = temp::temp_sibling(&dir_path.join("child.bin"));
        assert!(temp::is_clearable_staging_temp(&impostor));
        std::fs::create_dir(&impostor).unwrap();
        refused(dir.clone()).await;
        assert!(
            impostor.is_dir(),
            "the directory must survive at {impostor:?}"
        );
        assert!(
            dir_on_disk.is_dir(),
            "a refused removal must leave the directory"
        );

        // A regular file wearing the name that cannot be opened. Root can open
        // anything, so the premise is checked rather than assumed.
        let dir = root.join("as-unreadable/").unwrap();
        let dir_on_disk = seed_empty_dir(&backend, &dir).await;
        let dir_path = dir.to_file_path().unwrap();
        let impostor = temp::temp_sibling(&dir_path.join("child.bin"));
        std::fs::write(&impostor, b"sealed").unwrap();
        std::fs::set_permissions(&impostor, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::File::open(&impostor).is_err() {
            refused(dir.clone()).await;
            assert!(
                impostor.exists(),
                "the sealed entry must survive at {impostor:?}"
            );
            assert!(
                dir_on_disk.is_dir(),
                "a refused removal must leave the directory"
            );
        }
        std::fs::set_permissions(&impostor, std::fs::Permissions::from_mode(0o644)).unwrap();
    }

    /// The sweep holds one descriptor at a time, so the number of orphans a
    /// removal can clear is not bounded by the descriptor limit. The count is
    /// pushed past the soft limit where that limit is small enough to reach;
    /// under a larger limit the case still exercises the many-orphan path, and
    /// `ulimit -n 256` makes it discriminating.
    #[cfg(unix)]
    #[tokio::test]
    async fn delete_directory_clears_more_orphans_than_the_descriptor_limit() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Url::from_directory_path(tmp.path()).unwrap();
        let dir = root.join("staging/").unwrap();
        let backend = backend_over_tempdir(&tmp).await;
        seed_empty_dir(&backend, &dir).await;
        let dir_path = dir.to_file_path().unwrap();

        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `limit` is a valid, writable rlimit for the duration of the call.
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) },
            0
        );
        let count = usize::try_from(limit.rlim_cur)
            .unwrap_or(usize::MAX)
            .saturating_add(64)
            .min(8192);
        for index in 0..count {
            let orphan = temp::temp_sibling(&dir_path.join(format!("child-{index}.bin")));
            drop(std::fs::File::create_new(&orphan).unwrap());
        }
        assert_eq!(temp_sibling_count(&dir_path), count);

        backend
            .delete_directory(
                Request::new(DeleteDirectoryRequest {
                    address: dir.clone(),
                    options: DeleteDirectoryOptions,
                }),
                None,
            )
            .await
            .unwrap_or_else(|err| panic!("{count} orphans must not exhaust the removal: {err:?}"));
        assert!(!dir_path.exists());
    }

    /// A temp the scan saw but the probe no longer finds means the directory
    /// changed under the removal: the way a temp vanishes is its writer's
    /// rename publishing it as a child, so the directory is not the one the
    /// scan judged. The sweep refuses with a retry hint rather than carry the
    /// scan's verdict forward.
    #[tokio::test]
    async fn sweep_refuses_when_a_scanned_temp_has_vanished() {
        let tmp = tempfile::tempdir().unwrap();
        let vanished = temp::temp_sibling(&tmp.path().join("child.bin"));
        let orphan = temp::temp_sibling(&tmp.path().join("other.bin"));
        drop(std::fs::File::create_new(&orphan).unwrap());

        let err = temp::clear_orphaned_staging_temps(&[orphan.clone(), vanished])
            .await
            .expect_err("a vanished temp is a changed directory");
        assert_eq!(err.code(), ErrorCode::DirectoryNotEmpty, "{err:?}");
        assert!(err.message().contains("changed"), "{err:?}");
        assert!(
            orphan.exists(),
            "a refused sweep must clear nothing, even an orphan probed earlier"
        );
    }

    /// Every temp is probed before any is removed: an unlocked orphan listed
    /// before a live temp survives the refusal, in either order, where an
    /// eager loop would have unlinked it on the way to the live one.
    #[tokio::test]
    async fn sweep_probes_every_temp_before_removing_any() {
        let tmp = tempfile::tempdir().unwrap();
        let orphan = temp::temp_sibling(&tmp.path().join("orphan.bin"));
        drop(std::fs::File::create_new(&orphan).unwrap());
        let live = temp::temp_sibling(&tmp.path().join("live.bin"));
        let holder = std::fs::File::create_new(&live).unwrap();
        assert!(matches!(
            temp::lock_staging_temp(&holder).unwrap(),
            temp::StagingLock::Held
        ));

        for order in [[&orphan, &live], [&live, &orphan]] {
            let temps: Vec<_> = order.iter().map(|p| (*p).clone()).collect();
            let err = temp::clear_orphaned_staging_temps(&temps)
                .await
                .expect_err("a live temp refuses the sweep");
            assert_eq!(err.code(), ErrorCode::DirectoryNotEmpty, "{err:?}");
            assert!(err.message().contains("in-flight write"), "{err:?}");
            assert!(
                orphan.exists(),
                "the orphan must survive a refused sweep in order {order:?}"
            );
            assert!(live.exists());
        }

        drop(holder);
        temp::clear_orphaned_staging_temps(&[orphan.clone(), live.clone()])
            .await
            .expect("with the lock released both are orphans");
        assert!(!orphan.exists());
        assert!(!live.exists());
    }

    /// A link or a fifo wearing the staging name is classified without being
    /// followed or opened for reading: the link's target is neither locked
    /// nor removed, the fifo never holds the probe, and both refuse the
    /// removal as `DirectoryNotEmpty`.
    #[cfg(unix)]
    #[tokio::test]
    async fn delete_directory_refuses_a_link_or_fifo_wearing_a_staging_name() {
        use std::os::unix::ffi::OsStrExt;

        let tmp = tempfile::tempdir().unwrap();
        let root = Url::from_directory_path(tmp.path()).unwrap();
        let backend = backend_over_tempdir(&tmp).await;
        let refused = |dir: Url| {
            let backend = backend.clone();
            async move {
                let err = backend
                    .delete_directory(
                        Request::new(DeleteDirectoryRequest {
                            address: dir,
                            options: DeleteDirectoryOptions,
                        }),
                        None,
                    )
                    .await
                    .expect_err("an entry that is not a regular file holds the directory");
                assert_eq!(err.code(), ErrorCode::DirectoryNotEmpty, "{err:?}");
                assert!(!err.message().contains("in-flight"), "{err:?}");
            }
        };

        // A symlink to a regular file elsewhere in the root.
        let target = tmp.path().join("target.bin");
        std::fs::write(&target, b"linked").unwrap();
        let dir = root.join("as-link/").unwrap();
        let dir_on_disk = seed_empty_dir(&backend, &dir).await;
        let dir_path = dir.to_file_path().unwrap();
        let link = temp::temp_sibling(&dir_path.join("child.bin"));
        std::os::unix::fs::symlink(&target, &link).unwrap();
        refused(dir.clone()).await;
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink(),
            "the link must survive at {link:?}"
        );
        assert_eq!(std::fs::read(&target).unwrap(), b"linked");
        assert!(
            dir_on_disk.is_dir(),
            "a refused removal must leave the directory"
        );

        // A fifo with no writer: a following, blocking open would never return.
        let dir = root.join("as-fifo/").unwrap();
        let dir_on_disk = seed_empty_dir(&backend, &dir).await;
        let dir_path = dir.to_file_path().unwrap();
        let fifo = temp::temp_sibling(&dir_path.join("child.bin"));
        let c_path = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: `c_path` is a valid NUL-terminated path for the call.
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
        tokio::time::timeout(std::time::Duration::from_secs(10), refused(dir.clone()))
            .await
            .expect("the probe must not block on a fifo");
        assert!(fifo.exists(), "the fifo must survive at {fifo:?}");
        assert!(
            dir_on_disk.is_dir(),
            "a refused removal must leave the directory"
        );
    }

    /// A copy staged from a write-only source carries that mode; a read-only
    /// probe open is refused, so the probe falls back to a write-only open and
    /// the orphan still clears.
    #[cfg(unix)]
    #[tokio::test]
    async fn delete_directory_clears_an_orphan_whose_mode_denies_read() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let root = Url::from_directory_path(tmp.path()).unwrap();
        let dir = root.join("staging/").unwrap();
        let backend = backend_over_tempdir(&tmp).await;
        seed_empty_dir(&backend, &dir).await;
        let dir_path = dir.to_file_path().unwrap();

        let orphan = temp::temp_sibling(&dir_path.join("child.bin"));
        std::fs::write(&orphan, b"staged from a write-only source").unwrap();
        std::fs::set_permissions(&orphan, std::fs::Permissions::from_mode(0o200)).unwrap();
        // Root reads anything; the case is only meaningful when read is denied.
        if std::fs::File::open(&orphan).is_ok() {
            return;
        }

        backend
            .delete_directory(
                Request::new(DeleteDirectoryRequest {
                    address: dir.clone(),
                    options: DeleteDirectoryOptions,
                }),
                None,
            )
            .await
            .expect("an orphan whose mode denies read still clears");
        assert!(!orphan.exists());
        assert!(!dir_path.exists());
    }

    /// A name whose leading segment is not UTF-8 is no temp to either matcher
    /// here and is served as an object; the removal keeps it, and the C host's
    /// clearable predicate agrees so neither host destroys what the other
    /// serves.
    #[cfg(unix)]
    #[tokio::test]
    async fn delete_directory_keeps_a_non_utf8_name_wearing_the_staging_shape() {
        use std::os::unix::ffi::OsStrExt;

        let tmp = tempfile::tempdir().unwrap();
        let root = Url::from_directory_path(tmp.path()).unwrap();
        let dir = root.join("staging/").unwrap();
        let backend = backend_over_tempdir(&tmp).await;
        seed_empty_dir(&backend, &dir).await;
        let dir_path = dir.to_file_path().unwrap();

        let object = dir_path.join(std::ffi::OsStr::from_bytes(b".\xff.1.2.3.tmp"));
        std::fs::write(&object, b"served").unwrap();
        assert!(!temp::is_clearable_staging_temp(&object));
        assert!(!temp::is_atomic_write_temp_sibling(&object));

        let err = backend
            .delete_directory(
                Request::new(DeleteDirectoryRequest {
                    address: dir.clone(),
                    options: DeleteDirectoryOptions,
                }),
                None,
            )
            .await
            .expect_err("an object holds the directory");
        assert_eq!(err.code(), ErrorCode::DirectoryNotEmpty, "{err:?}");
        assert_eq!(std::fs::read(&object).unwrap(), b"served");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn delete_directory_refuses_a_symlink_entry_and_leaves_link_target_intact() {
        for target_is_inside_root in [true, false] {
            let tmp = tempfile::tempdir().unwrap();
            let outside = tempfile::tempdir().unwrap();
            let target = if target_is_inside_root {
                tmp.path().join("real")
            } else {
                outside.path().to_path_buf()
            };
            let target_contents = target.join("contents");
            let sentinel = target_contents.join("sentinel");
            std::fs::create_dir_all(&target_contents).unwrap();
            std::fs::write(&sentinel, b"keep me").unwrap();

            let link = tmp.path().join("vdir");
            std::os::unix::fs::symlink(&target, &link).unwrap();
            let root = Url::from_directory_path(tmp.path()).unwrap();
            let backend = backend_over_tempdir(&tmp).await;

            let err = backend
                .delete_directory(
                    Request::new(DeleteDirectoryRequest {
                        address: root.join("vdir/").unwrap(),
                        options: DeleteDirectoryOptions,
                    }),
                    None,
                )
                .await
                .unwrap_err();

            assert_eq!(err.code(), ErrorCode::InvalidArgument);
            assert!(err.message().contains("symlink"), "{err}");
            assert!(err.next_action().is_some(), "{err}");
            assert!(
                std::fs::symlink_metadata(&link)
                    .unwrap()
                    .file_type()
                    .is_symlink(),
                "the link must survive"
            );
            assert!(target.is_dir(), "the target directory must survive");
            assert!(sentinel.is_file(), "the target's contents must survive");
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn delete_directory_refuses_a_symlink_to_a_file_and_leaves_both_intact() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("real.txt");
        std::fs::write(&target, b"keep me").unwrap();
        let link = tmp.path().join("vfile");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let root = Url::from_directory_path(tmp.path()).unwrap();
        let backend = backend_over_tempdir(&tmp).await;

        let err = backend
            .delete_directory(
                Request::new(DeleteDirectoryRequest {
                    address: root.join("vfile/").unwrap(),
                    options: DeleteDirectoryOptions,
                }),
                None,
            )
            .await
            .unwrap_err();

        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert!(err.message().contains("symlink"), "{err}");
        assert!(
            err.message()
                .contains("delete_directory will not remove or follow"),
            "{err}"
        );
        assert!(!err.message().contains("use delete()"), "{err}");
        assert!(
            err.next_action().is_some_and(|action| {
                action.contains("host filesystem") && !action.contains("use delete()")
            }),
            "{err}"
        );
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink(),
            "the link must survive"
        );
        assert!(target.is_file(), "the target file must survive");
    }

    /// A real `ENOTEMPTY` from the kernel, produced by an actual syscall rather
    /// than a synthesized `io::Error`, must surface as the non-retryable
    /// `DirectoryNotEmpty` rather than falling through to `Transient`. `rename`
    /// onto a populated directory is the deterministic single-threaded way to
    /// make the kernel raise it through the backend: once the emptiness scan
    /// agrees with the kernel, `delete_directory`'s own `remove_dir` can only
    /// see `ENOTEMPTY` when a concurrent writer wins a race, which no
    /// thread-free test can stage.
    ///
    /// Linux-only, and the gate is about the *syscall's* contract rather than
    /// the backend's: POSIX lets `rename` onto a populated directory fail with
    /// either `ENOTEMPTY` or `EEXIST`, and `EEXIST` maps through the
    /// `AlreadyExists` arm instead. A platform taking the other branch would
    /// redden this without a defect behind it. The mapping itself is asserted
    /// portably by the `ErrorKind` case in `errors.rs`, and the errno
    /// translation by the `from_raw_os_error(ENOTEMPTY)` case beside it; what
    /// this case adds is that a real kernel raises it through a real backend
    /// call, which is worth having on the one platform where the errno is
    /// pinned.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_kernel_directory_not_empty_is_not_retryable() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Url::from_directory_path(tmp.path()).unwrap();
        let backend = backend_over_tempdir(&tmp).await;
        let source = root.join("source/").unwrap();
        let destination = root.join("destination/").unwrap();
        for address in [&source, &destination] {
            backend
                .create_directory(
                    Request::new(CreateDirectoryRequest {
                        address: address.clone(),
                        options: CreateDirectoryOptions::default(),
                    }),
                    None,
                )
                .await
                .unwrap();
        }
        write_with_options(
            &backend,
            &destination.join("occupant.txt").unwrap(),
            b"held",
            WriteOptions::default(),
        )
        .await
        .unwrap();

        let err = backend
            .rename(
                Request::new(RenameRequest {
                    source: source.clone(),
                    destination: destination.clone(),
                    options: RenameOptions::default(),
                }),
                None,
            )
            .await
            .expect_err("a rename onto a populated directory cannot succeed");
        assert_eq!(
            err.code(),
            ErrorCode::DirectoryNotEmpty,
            "the kernel's ENOTEMPTY must keep its own code: {err:?}"
        );
        assert!(
            !err.code().bucket().retryable(),
            "replaying this rename cannot make the destination empty"
        );
    }

    // ----- watch_directory ---------------------------------------------------

    /// A poll interval well under the per-event timeout so the watcher observes
    /// changes within a couple of cycles, while staying above the 10ms floor.
    const WATCH_POLL: std::time::Duration = std::time::Duration::from_millis(20);
    /// Generous-but-finite ceiling so a stuck watcher fails the test instead of
    /// hanging the suite.
    const WATCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

    async fn start_watch(
        backend: &LayerHandle,
        prefix: &Url,
        recursive: bool,
        cancel: Option<CancellationToken>,
    ) -> ChangeStream {
        backend
            .watch_directory(
                Request::new(WatchDirectoryRequest {
                    prefix: prefix.clone(),
                    options: WatchDirectoryOptions {
                        recursive,
                        include_metadata_changes: true,
                        since: None,
                        poll_interval: WATCH_POLL,
                    },
                }),
                cancel,
            )
            .await
            .unwrap()
    }

    /// Pull the next change event from the (blocking) stream off the async
    /// executor, failing if no event arrives inside [`WATCH_TIMEOUT`]. Returns
    /// the event and the stream so the caller can keep polling. `next()` blocks
    /// for one poll interval internally, so the outer timeout — not a busy spin
    /// — bounds the wait.
    async fn next_change(mut stream: ChangeStream) -> (ChangeEvent, ChangeStream) {
        let join = tokio::task::spawn_blocking(move || {
            let event = match stream.next() {
                Some(Ok(event)) => Some(event),
                Some(Err(err)) => panic!("watch stream errored: {err:?}"),
                None => None,
            };
            (event, stream)
        });
        let (event, stream) = tokio::time::timeout(WATCH_TIMEOUT, join)
            .await
            .expect("watch event did not arrive before the test timeout")
            .expect("watch blocking task panicked");
        (
            event.expect("watch stream ended before producing an event"),
            stream,
        )
    }

    fn change_address(event: &ChangeEvent) -> &Url {
        match event {
            ChangeEvent::Object { address, .. } => address,
            ChangeEvent::Lapsed { .. } => panic!("expected an Object change, got Lapsed"),
        }
    }

    fn change_kind(event: &ChangeEvent) -> ChangeKind {
        match event {
            ChangeEvent::Object { kind, .. } => *kind,
            ChangeEvent::Lapsed { .. } => panic!("expected an Object change, got Lapsed"),
        }
    }

    #[tokio::test]
    async fn watch_directory_reports_create_modify_delete() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Url::from_directory_path(tmp.path()).unwrap();
        let file = root.join("watched.txt").unwrap();
        let path = file.to_file_path().unwrap();
        let backend = backend_over_tempdir(&tmp).await;

        let stream = start_watch(&backend, &root, false, None).await;

        // Created.
        std::fs::write(&path, b"v1").unwrap();
        let (event, stream) = next_change(stream).await;
        assert_eq!(change_kind(&event), ChangeKind::Created);
        assert_eq!(change_address(&event), &file);

        // Modified. A coarse filesystem mtime can collapse two writes inside the
        // same tick; nudge the mtime forward so the diff is unambiguous.
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(&path, b"v2 longer").unwrap();
        let (event, stream) = next_change(stream).await;
        assert_eq!(change_kind(&event), ChangeKind::Modified);
        assert_eq!(change_address(&event), &file);

        // Deleted.
        std::fs::remove_file(&path).unwrap();
        let (event, _stream) = next_change(stream).await;
        assert_eq!(change_kind(&event), ChangeKind::Deleted);
        assert_eq!(change_address(&event), &file);
    }

    #[tokio::test]
    async fn watch_directory_change_etag_matches_stat() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Url::from_directory_path(tmp.path()).unwrap();
        let file = root.join("etagged.txt").unwrap();
        let path = file.to_file_path().unwrap();
        let backend = backend_over_tempdir(&tmp).await;

        let stream = start_watch(&backend, &root, false, None).await;
        std::fs::write(&path, b"payload").unwrap();
        let (event, _stream) = next_change(stream).await;
        let watch_etag = match event {
            ChangeEvent::Object { etag, .. } => etag,
            ChangeEvent::Lapsed { .. } => panic!("expected an Object change"),
        };
        // The etag carried on the change event must round-trip against stat so a
        // caller can use it as an if_match precondition.
        let info = stat(&backend, &file).await;
        assert!(watch_etag.is_some(), "create event must carry an etag");
        assert_eq!(watch_etag, info.etag);
    }

    #[tokio::test]
    async fn watch_directory_stops_when_cancelled() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Url::from_directory_path(tmp.path()).unwrap();
        let backend = backend_over_tempdir(&tmp).await;

        let cancel = CancellationToken::new();
        let mut stream = start_watch(&backend, &root, false, Some(cancel.clone())).await;

        // Cancel before polling: the stream must end promptly rather than block
        // forever waiting for a change that will never come.
        cancel.cancel();
        let ended = tokio::time::timeout(
            WATCH_TIMEOUT,
            tokio::task::spawn_blocking(move || stream.next().is_none()),
        )
        .await
        .expect("cancelled watch stream did not terminate before the test timeout")
        .expect("watch blocking task panicked");
        assert!(ended, "a cancelled watch stream must end (next() -> None)");
    }

    #[tokio::test]
    async fn watch_directory_recursive_reports_nested_create() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Url::from_directory_path(tmp.path()).unwrap();
        let nested_dir = tmp.path().join("nested");
        std::fs::create_dir_all(&nested_dir).unwrap();
        let nested = root.join("nested/").unwrap().join("leaf.txt").unwrap();
        let nested_path = nested_dir.join("leaf.txt");
        let backend = backend_over_tempdir(&tmp).await;

        let stream = start_watch(&backend, &root, true, None).await;
        std::fs::write(&nested_path, b"deep").unwrap();
        let (event, _stream) = next_change(stream).await;
        assert_eq!(change_kind(&event), ChangeKind::Created);
        assert_eq!(change_address(&event), &nested);
    }

    #[tokio::test]
    async fn watch_directory_on_missing_directory_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Url::from_directory_path(tmp.path()).unwrap();
        // In-root spelling but the directory does not exist on disk, so the
        // initial snapshot's read_dir fails. watch_directory must surface that
        // as an Err rather than hanging or panicking.
        let missing = root.join("nonexistent/").unwrap();
        let backend = backend_over_tempdir(&tmp).await;

        let result = backend
            .watch_directory(
                Request::new(WatchDirectoryRequest {
                    prefix: missing,
                    options: WatchDirectoryOptions {
                        recursive: false,
                        include_metadata_changes: true,
                        since: None,
                        poll_interval: WATCH_POLL,
                    },
                }),
                None,
            )
            .await;
        assert!(
            result.is_err(),
            "watch_directory on a missing directory must error, not hang"
        );
    }

    // Owner resolution mirrors the cdylib's
    // `modified_by_resolves_owning_user_or_falls_back_to_uid_string`: the
    // running process's uid always resolves (to a username or `uid:N`), and a
    // wholly implausible uid exercises the `uid:N` fallback even on hosts with
    // a real `/etc/passwd`.
    #[cfg(unix)]
    #[test]
    fn modified_by_resolves_owning_user_or_falls_back_to_uid_string() {
        let my_uid = unsafe { libc::getuid() };
        let resolved = owner::resolve_uid(my_uid);
        assert!(!resolved.is_empty(), "resolve_uid produced empty string");
        let absent_uid = 0xFFFE_FFFEu32;
        let absent = owner::resolve_uid(absent_uid);
        assert_eq!(absent, format!("uid:{absent_uid}"));
    }

    /// Stat `address` requesting full metadata, so the owner-resolve path runs.
    #[cfg(unix)]
    async fn stat_full(backend: &LayerHandle, address: &Url) -> ObjectInfo {
        backend
            .stat(
                Request::new(StatRequest {
                    address: address.clone(),
                    options: StatOptions {
                        full_metadata: true,
                        versioned_address: false,
                    },
                }),
                None,
            )
            .await
            .unwrap()
    }

    // A full-metadata `stat` on a real file surfaces a non-empty `modified_by`
    // (the file's owning user, or the `uid:N` fallback). The owner resolve is
    // gated on `full_metadata` (matching the legacy cdylib), so a default stat
    // omits it — costly DACL/uid work is skipped when the caller doesn't ask.
    #[cfg(unix)]
    #[tokio::test]
    async fn stat_populates_modified_by_with_owning_user() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Url::from_directory_path(tmp.path()).unwrap();
        let file = root.join("owned.txt").unwrap();
        let backend = backend_over_tempdir(&tmp).await;
        write_file(&backend, &file, b"hi").await;

        let info = stat_full(&backend, &file).await;
        let modified_by = info
            .modified_by
            .expect("a full-metadata stat must surface a best-effort modified_by on Unix");
        assert!(!modified_by.is_empty(), "modified_by must not be empty");
        // The file is owned by the running process's uid, so it resolves to
        // exactly what `resolve_uid` returns for that uid.
        let my_uid = unsafe { libc::getuid() };
        assert_eq!(modified_by, owner::resolve_uid(my_uid));

        // The cheap default stat skips the owner resolve.
        let cheap = stat(&backend, &file).await;
        assert_eq!(
            cheap.modified_by, None,
            "a stat without full_metadata must skip owner resolution"
        );
    }

    // `read` must refuse special filesystem objects (a fifo here) without
    // blocking on an open/read of the pipe. Mirrors the cdylib's
    // `file_backend_rejects_fifo_read_without_opening_it`.
    #[cfg(unix)]
    #[tokio::test]
    async fn read_rejects_fifo_without_opening_it() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let tmp = tempfile::tempdir().unwrap();
        let root = Url::from_directory_path(tmp.path()).unwrap();
        let fifo_path = tmp.path().join("pipe");
        let c_path = CString::new(fifo_path.as_os_str().as_bytes()).unwrap();
        let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
        assert_eq!(
            rc,
            0,
            "mkfifo({}) failed: {}",
            fifo_path.display(),
            std::io::Error::last_os_error()
        );

        let fifo = root.join("pipe").unwrap();
        let backend = backend_over_tempdir(&tmp).await;
        let err = backend
            .read(
                Request::new(ReadRequest {
                    address: fifo,
                    options: ReadOptions::default(),
                }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Unsupported);
    }

    // ----- ranged streaming reads --------------------------------------------

    /// Drain a `ReadResult::Stream` into a single Vec, asserting the variant.
    async fn drain_stream(result: ReadResult) -> Vec<u8> {
        use futures::StreamExt;
        match result {
            ReadResult::Stream { mut stream, .. } => {
                let mut out = Vec::new();
                while let Some(chunk) = stream.next().await {
                    out.extend_from_slice(&chunk.unwrap());
                }
                out
            }
            other => panic!("expected a Stream, got {other:?}"),
        }
    }

    // A closed byte range must stream (not buffer) exactly the requested bytes.
    // Mirrors the cdylib `read`: a ranged read returns `ReadResult::Stream`
    // produced by `open_ranged_stream`, never an in-memory `Bytes` slice.
    #[tokio::test]
    async fn ranged_read_streams_exactly_the_requested_window() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Url::from_directory_path(tmp.path()).unwrap();
        let file = root.join("ranged.bin").unwrap();
        let backend = backend_over_tempdir(&tmp).await;
        // A multi-KB body so the streamed window is a genuine sub-slice.
        let body: Vec<u8> = (0..8192u32).map(|i| (i % 251) as u8).collect();
        write_file(&backend, &file, &body).await;

        let result = backend
            .read(
                Request::new(ReadRequest {
                    address: file.clone(),
                    options: ReadOptions {
                        range: Some(ByteRange {
                            start: 10,
                            end_inclusive: Some(19),
                        }),
                        ..ReadOptions::default()
                    },
                }),
                None,
            )
            .await
            .unwrap();
        let streamed = drain_stream(result).await;
        assert_eq!(
            streamed,
            &body[10..20],
            "a closed range must stream exactly bytes [start, end_inclusive]"
        );
    }

    // An open-ended range (`bytes=N-`) streams from `start` to end-of-object.
    #[tokio::test]
    async fn open_ended_range_streams_tail_to_eof() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Url::from_directory_path(tmp.path()).unwrap();
        let file = root.join("tail.bin").unwrap();
        let backend = backend_over_tempdir(&tmp).await;
        let body: Vec<u8> = (0..4096u32).map(|i| (i % 97) as u8).collect();
        write_file(&backend, &file, &body).await;

        let result = backend
            .read(
                Request::new(ReadRequest {
                    address: file.clone(),
                    options: ReadOptions {
                        range: Some(ByteRange {
                            start: 4000,
                            end_inclusive: None,
                        }),
                        ..ReadOptions::default()
                    },
                }),
                None,
            )
            .await
            .unwrap();
        let streamed = drain_stream(result).await;
        assert_eq!(streamed, &body[4000..]);
    }

    // A whole-object read (no range) returns a `LocalDelegate` — the cdylib
    // file-plugin contract. The broker's raw-read path streams the delegate
    // itself, and buffering callers (`read_bytes`) are bulk-buffered by the
    // byte-cache wrapper, so the built-in must not eagerly buffer to `Bytes`.
    #[tokio::test]
    async fn whole_read_returns_local_delegate() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Url::from_directory_path(tmp.path()).unwrap();
        let file = root.join("whole.bin").unwrap();
        let backend = backend_over_tempdir(&tmp).await;
        let body: Vec<u8> = (0..2048u32).map(|i| (i % 13) as u8).collect();
        write_file(&backend, &file, &body).await;

        let result = backend
            .read(
                Request::new(ReadRequest {
                    address: file,
                    options: ReadOptions::default(),
                }),
                None,
            )
            .await
            .unwrap();
        match result {
            ReadResult::LocalDelegate(local) => {
                assert_eq!(tokio::fs::read(&local.path).await.unwrap(), body);
                assert_eq!(local.info.size, Some(2048));
            }
            other => panic!("expected LocalDelegate, got {other:?}"),
        }
    }

    // A range whose start is at or beyond the object size is InvalidArgument
    // (the cdylib's `open_ranged_stream` guard).
    #[tokio::test]
    async fn ranged_read_start_beyond_object_is_invalid_argument() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Url::from_directory_path(tmp.path()).unwrap();
        let file = root.join("short.bin").unwrap();
        let backend = backend_over_tempdir(&tmp).await;
        write_file(&backend, &file, b"0123456789").await;

        let err = backend
            .read(
                Request::new(ReadRequest {
                    address: file,
                    options: ReadOptions {
                        range: Some(ByteRange {
                            start: 100,
                            end_inclusive: None,
                        }),
                        ..ReadOptions::default()
                    },
                }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    // ----- check_access ------------------------------------------------------

    fn all_ops() -> AccessOps {
        AccessOps {
            read: true,
            write: true,
            delete: true,
            update_metadata: true,
        }
    }

    async fn check_access(
        backend: &LayerHandle,
        address: &Url,
        operations: AccessOps,
    ) -> Result<AccessDecision> {
        backend
            .check_access(
                Request::new(CheckAccessRequest {
                    address: address.clone(),
                    operations,
                }),
                None,
            )
            .await
    }

    // check_access on a target that does not exist is NotFound, not a vacuous
    // AccessDecision. Mirrors the cdylib's SPI-faithful behavior.
    #[tokio::test]
    async fn check_access_missing_target_is_not_found() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Url::from_directory_path(tmp.path()).unwrap();
        let missing = root.join("ghost.txt").unwrap();
        let backend = backend_over_tempdir(&tmp).await;

        let err = check_access(&backend, &missing, all_ops())
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::NotFound);
    }

    // In a read-only PARENT directory, delete is denied (the dentry can't be
    // unlinked) even though the file itself is writable; the same file in a
    // writable dir allows delete. Mirrors the cdylib's parent-readonly rule.
    #[cfg(unix)]
    #[tokio::test]
    async fn check_access_delete_denied_under_readonly_parent() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let root = Url::from_directory_path(tmp.path()).unwrap();
        let backend = backend_over_tempdir(&tmp).await;

        // A file in a writable dir: delete is allowed.
        let writable_dir = tmp.path().join("writable");
        std::fs::create_dir_all(&writable_dir).unwrap();
        let writable = root.join("writable/").unwrap().join("doc.txt").unwrap();
        write_file(&backend, &writable, b"body").await;
        let allowed = check_access(&backend, &writable, all_ops()).await.unwrap();
        assert!(
            !allowed.denied_ops.delete,
            "delete must be allowed in a writable parent dir"
        );

        // A file in a read-only dir: delete is denied (parent_readonly).
        let ro_dir = tmp.path().join("readonly");
        std::fs::create_dir_all(&ro_dir).unwrap();
        let guarded_path = ro_dir.join("doc.txt");
        std::fs::write(&guarded_path, b"body").unwrap();
        let guarded = root.join("readonly/").unwrap().join("doc.txt").unwrap();
        std::fs::set_permissions(&ro_dir, std::fs::Permissions::from_mode(0o555)).unwrap();

        let decision = check_access(&backend, &guarded, all_ops()).await;

        // Restore perms so the tempdir can clean up regardless of assertions.
        std::fs::set_permissions(&ro_dir, std::fs::Permissions::from_mode(0o755)).unwrap();

        let decision = decision.unwrap();
        assert!(
            decision.denied_ops.delete,
            "delete must be denied when the parent dir is read-only"
        );
        assert!(!decision.allowed, "a denied op must clear `allowed`");
        assert!(
            decision.reason.is_some(),
            "a denial must carry an explanatory reason"
        );
    }

    // ----- OS-specific error mapping (map_io) --------------------------------

    // An over-long filename surfaces ENAMETOOLONG, which `map_io` maps to
    // InvalidArgument (not the generic Transient default).
    #[cfg(unix)]
    #[tokio::test]
    async fn write_with_overlong_name_maps_to_invalid_argument() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Url::from_directory_path(tmp.path()).unwrap();
        // 5000 chars far exceeds NAME_MAX (255 on Linux/most filesystems).
        let long_name = "a".repeat(5000);
        let file = root.join(&long_name).unwrap();
        let backend = backend_over_tempdir(&tmp).await;

        let err = backend
            .write(
                Request::new(WriteRequest {
                    address: file,
                    body: Body::Bytes(b"x".to_vec()),
                    options: WriteOptions::default(),
                }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    // ----- delete idempotency ------------------------------------------------

    // Deleting a non-existent in-root path is idempotent success, matching the
    // cdylib. (The pre-A6 built-in propagated NotFound here.)
    #[tokio::test]
    async fn delete_missing_target_is_idempotent_success() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Url::from_directory_path(tmp.path()).unwrap();
        let missing = root.join("never-existed.txt").unwrap();
        let backend = backend_over_tempdir(&tmp).await;

        backend
            .delete(
                Request::new(DeleteRequest {
                    address: missing,
                    options: DeleteOptions::default(),
                }),
                None,
            )
            .await
            .expect("delete on a missing target must be idempotent success");
    }

    // ----- effective permissions ---------------------------------------------

    // stat reports the readonly approximation the descriptor advertises
    // (`populates_effective_permissions_on_stat`): a read-only entry surfaces
    // READ only, a writable entry the full set. Mirrors the legacy cdylib's
    // `effective_permissions_from_metadata`.
    #[cfg(unix)]
    #[tokio::test]
    async fn stat_reports_readonly_approximation_for_effective_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let root = Url::from_directory_path(tmp.path()).unwrap();
        let backend = backend_over_tempdir(&tmp).await;

        let writable = root.join("rw.txt").unwrap();
        write_file(&backend, &writable, b"body").await;
        assert_eq!(
            stat(&backend, &writable).await.effective_permissions,
            Some(EffectivePermissions::all()),
            "a writable entry advertises the full permission set"
        );

        let readonly = root.join("ro.txt").unwrap();
        write_file(&backend, &readonly, b"body").await;
        let ro_path = readonly.to_file_path().unwrap();
        std::fs::set_permissions(&ro_path, std::fs::Permissions::from_mode(0o444)).unwrap();
        assert_eq!(
            stat(&backend, &readonly).await.effective_permissions,
            Some(EffectivePermissions::READ),
            "a read-only entry advertises READ only"
        );
    }

    // ----- Body::LocalFile write ---------------------------------------------

    // A LocalFile body streams through the exclusive O_EXCL temp handle (no
    // reopen-by-path) and commits the source bytes verbatim, leaving no orphan.
    #[tokio::test]
    async fn write_local_file_body_commits_source_bytes() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Url::from_directory_path(tmp.path()).unwrap();
        let dest = root.join("from-local.bin").unwrap();
        let backend = backend_over_tempdir(&tmp).await;

        // Source file used purely as the write body (an external local path).
        let source = tmp.path().join("source.bin");
        let body: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
        std::fs::write(&source, &body).unwrap();

        backend
            .write(
                Request::new(WriteRequest {
                    address: dest.clone(),
                    body: Body::LocalFile(source),
                    options: WriteOptions::default(),
                }),
                None,
            )
            .await
            .unwrap();

        let read = backend
            .read(
                Request::new(ReadRequest {
                    address: dest,
                    options: ReadOptions::default(),
                }),
                None,
            )
            .await
            .unwrap();
        let (bytes, _) = read_content(read).await;
        assert_eq!(bytes, body);
        assert_eq!(
            temp_sibling_count(tmp.path()),
            0,
            "LocalFile write must not leave a temp sibling orphan"
        );
    }

    // ----- precondition / lost-update locking --------------------------------

    // copy(a→b) and copy(b→a) issued concurrently take the source+destination
    // locks in opposite path orders. The canonical (path-sorted) ordering must
    // prevent an ABBA deadlock; a broken ordering would hang past the timeout.
    #[tokio::test]
    async fn concurrent_cross_copies_do_not_deadlock() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Url::from_directory_path(tmp.path()).unwrap();
        let a = root.join("a.bin").unwrap();
        let b = root.join("b.bin").unwrap();
        let backend = backend_over_tempdir(&tmp).await;
        write_file(&backend, &a, b"aaaa").await;
        write_file(&backend, &b, b"bbbb").await;

        let copy = |backend: LayerHandle, source: Url, destination: Url| async move {
            backend
                .copy(
                    Request::new(CopyRequest {
                        source,
                        destination,
                        options: CopyOptions::default(),
                    }),
                    None,
                )
                .await
        };

        let run = async {
            let mut handles = Vec::new();
            for _ in 0..32 {
                handles.push(tokio::spawn(copy(backend.clone(), a.clone(), b.clone())));
                handles.push(tokio::spawn(copy(backend.clone(), b.clone(), a.clone())));
            }
            for handle in handles {
                // Individual copies may error (e.g. transient overwrite races);
                // we only care that none deadlock.
                let _ = handle.await.unwrap();
            }
        };
        tokio::time::timeout(std::time::Duration::from_secs(10), run)
            .await
            .expect("cross copies deadlocked — canonical lock ordering is broken");
    }

    // delete's if_match lock: a delete(if_match=X) must never unlink a file a
    // concurrent writer has since changed to Y. With the per-path lock the
    // check+unlink and the writer's rename serialize, so afterward the file
    // always still exists (as Y) — either delete matched X and removed it before
    // the writer recreated it as Y, or the writer won and delete saw Y≠X and
    // bailed with PreconditionFailed. Without the lock, delete can check X, the
    // writer commits Y, and delete then unlinks Y — leaving the file gone.
    // Verified to fail if the delete lock is reverted.
    #[tokio::test]
    async fn delete_if_match_lock_never_unlinks_a_changed_file() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Url::from_directory_path(tmp.path()).unwrap();
        let file = root.join("guarded.txt").unwrap();
        let path = file.to_file_path().unwrap();
        let backend = backend_over_tempdir(&tmp).await;

        for round in 0..100 {
            write_file(&backend, &file, b"XXXX").await;
            let etag_x = stat(&backend, &file).await.etag.unwrap();

            let deleter = {
                let backend = backend.clone();
                let address = file.clone();
                tokio::spawn(async move {
                    backend
                        .delete(
                            Request::new(DeleteRequest {
                                address,
                                options: DeleteOptions {
                                    if_match: Some(etag_x),
                                },
                            }),
                            None,
                        )
                        .await
                })
            };
            let writer = {
                let backend = backend.clone();
                let address = file.clone();
                tokio::spawn(async move {
                    write_with_options(&backend, &address, b"YYYYYYYY", WriteOptions::default())
                        .await
                })
            };
            let _ = deleter.await.unwrap();
            writer.await.unwrap().unwrap();

            assert!(
                path.exists(),
                "round {round}: delete(if_match=X) unlinked the file after a concurrent \
                 write changed it to Y — the if_match precondition wasn't honored under the lock"
            );
        }
    }

    // copy's if_source lock: a copy that passes if_source=X must commit exactly
    // X's bytes, never content a concurrent writer wrote after the check. The
    // source lock is held across the if_source stat AND the byte copy, so a copy
    // either reads X (before the writer) or fails if_source (after it). X and Y
    // differ in length so their etags differ regardless of mtime resolution.
    // Verified to fail if the source-side lock is reverted (copy then reads Y
    // after passing the X check).
    #[tokio::test]
    async fn copy_if_source_lock_never_commits_post_check_content() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Url::from_directory_path(tmp.path()).unwrap();
        let src = root.join("src.bin").unwrap();
        let dst = root.join("dst.bin").unwrap();
        let dst_path = dst.to_file_path().unwrap();
        let backend = backend_over_tempdir(&tmp).await;

        for round in 0..100 {
            write_file(&backend, &src, b"XXXX").await;
            let etag_x = stat(&backend, &src).await.etag.unwrap();
            let _ = tokio::fs::remove_file(&dst_path).await;

            let copier = {
                let backend = backend.clone();
                let (source, destination) = (src.clone(), dst.clone());
                tokio::spawn(async move {
                    backend
                        .copy(
                            Request::new(CopyRequest {
                                source,
                                destination,
                                options: CopyOptions {
                                    if_source: Some(etag_x),
                                    ..CopyOptions::default()
                                },
                            }),
                            None,
                        )
                        .await
                })
            };
            let writer = {
                let backend = backend.clone();
                let address = src.clone();
                tokio::spawn(async move {
                    write_with_options(&backend, &address, b"YYYYYYYY", WriteOptions::default())
                        .await
                })
            };
            let copy_result = copier.await.unwrap();
            writer.await.unwrap().unwrap();

            if copy_result.is_ok() {
                let bytes = tokio::fs::read(&dst_path).await.unwrap();
                assert_eq!(
                    bytes, b"XXXX",
                    "round {round}: copy passed if_source=X but committed non-X bytes — the \
                     source lock didn't hold across the if_source check and the read"
                );
            }
        }
    }

    /// A listing entry's address is spelled the way the rest of the stack
    /// spells that node, so an entry under a configured root is recognisably
    /// under it.
    ///
    /// The two producers are different code: the root comes from
    /// `root_url_from_config`, which ends in `address::parse`, and an entry
    /// comes from `path_to_file_url`, which starts at `Url::from_file_path`.
    /// They agree only because the entry side ends in `canonicalize` too — the
    /// `url` crate's escape set is not this project's, and `|` is the byte the
    /// two spell differently. It is `/C|/x` that makes this test load-bearing;
    /// every other row is already canonical out of `Url::from_file_path` and
    /// would pass with the call deleted.
    #[test]
    fn a_listing_entry_is_spelled_the_way_its_root_is() {
        for path in [
            "/C:/data/x",
            "/C|/x",
            "/srv/assets/a%b",
            "/srv/assets/a b",
            "/srv/assets/a\\b",
            "/srv/assets/a:b",
            "/srv/assets/plain.usd",
        ] {
            let entry = path_to_file_url(Path::new(path)).unwrap();
            assert_eq!(
                ovstorage_layer::canonicalize(entry.clone()),
                entry,
                "{path}: a listing entry must already be canonical"
            );
        }

        // The whole point, end to end: a Windows root and an entry beneath it
        // are spelled the same way, so the entry is inside the root's node.
        let root = root_url_from_config("C:\\data").unwrap();
        let entry = path_to_file_url(Path::new("/C:/data/x")).unwrap();
        assert_eq!(root.as_str(), "file:///C:/data/");
        assert!(
            entry.as_str().starts_with(root.as_str()),
            "{} is not under {}",
            entry.as_str(),
            root.as_str()
        );
    }

    /// A `root` or `prefix` whose parse moves it to a different node is a
    /// load error, because the one that matters destroys an authority nothing
    /// downstream can rebuild.
    ///
    /// `file://server/C:/data/` parses to `file:///C:/data/` with no host at
    /// all, so `FileBackend::file_path`'s refusal of a non-local authority has
    /// nothing left to refuse: an operator naming a remote share installs a
    /// connection over the local disk of the same name, and on Windows a write
    /// or a delete beneath it lands on `C:\data`.
    ///
    /// Only the authority is asked about. Normalizing a config address's PATH
    /// is what `address::parse` is for, so the accept half carries the
    /// spellings whose PATH the parser rewrites as well as every `file:`
    /// authority spelling that works: none at all, the no-`//` `file:/data/`
    /// form the public plugin doc blesses, `localhost`, and a real host — the
    /// last of which is refused later, by `file_path`, with a diagnostic naming
    /// the authority instead of the parse.
    #[test]
    fn a_root_whose_parse_moves_it_is_refused() {
        for (spelling, resolved) in [
            ("file://server/C:/data/", "file:///C:/data/"),
            ("file://server/C|/data/", "file:///C:/data/"),
            // The UNC spelling a Windows operator actually writes. It contains
            // no `//` at all, so a raw scan for `scheme://` reports no
            // authority — while the parser folds the separators, finds one, and
            // then discards it for the drive letter.
            (r#"file:\\server\C:\data\"#, "file:///C:/data/"),
        ] {
            let Err(err) = root_url_from_config(spelling) else {
                panic!("{spelling} must be refused: it parses to {resolved}");
            };
            assert_eq!(err.code(), ErrorCode::InvalidArgument, "{spelling}");
            assert!(
                err.message().contains(resolved),
                "{spelling}: the refusal must name what it resolves to, got {}",
                err.message()
            );
        }

        for spelling in [
            "file:///data/assets/",
            // The minimal, authority-less form. `docs/public/plugin-storage/
            // plugin-file.md` publishes it and `route_address_from_config`'s
            // doc comment uses it as its worked example, so refusing it would
            // break a documented configuration — and it has no authority for
            // either rewrite to move.
            "file:/data/assets/",
            "file:/srv/public/",
            // Path rewrites, which are `address::parse`'s job rather than a
            // retarget: the resolved address is the one the operator asked for.
            "file:///srv/../data/assets/",
            "file:///srv//data/assets/",
            "file://localhost/data/assets/",
            "file://server/share/assets/",
        ] {
            root_url_from_config(spelling)
                .unwrap_or_else(|err| panic!("{spelling} must load: {}", err.message()));
        }

        // And the remote share that survives parsing is still refused, one
        // layer down and for the reason it reads like — the guard above did not
        // take over that job (`file_path_rejects_non_local_authority` owns the
        // full statement of that rule).
        let root = root_url_from_config("file://server/share/assets/").unwrap();
        let err = file_path(&root).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    #[test]
    fn root_config_accepts_file_urls_and_filesystem_paths() {
        assert_eq!(
            root_url_from_config("file:///data/assets/")
                .unwrap()
                .as_str(),
            "file:///data/assets/"
        );
        // Plain filesystem paths normalize to a trailing-slash `file:` root.
        assert_eq!(
            root_url_from_config("/data/assets").unwrap().as_str(),
            "file:///data/assets/"
        );
        // A Windows drive letter is spelled plainly in the canonical form, the
        // same way `Url::from_file_path` and every other tool spells it.
        // `canonicalize` escapes `:` in a `file:` path only where the URL has
        // an authority to lose (`CANONICAL_FILE_SHARE_PATH`); a local root has
        // none, so the drive designator stays readable.
        assert_eq!(
            root_url_from_config("C:\\data").unwrap().as_str(),
            "file:///C:/data/"
        );
        // This suite can decide the SERIALIZATION, asserted above:
        // `root_url_from_config` emits the drive designator unescaped, which is
        // this crate's own behaviour, and it is the same spelling
        // `FileBackend::path_to_file_url` produces for an entry under that
        // root, so a listing entry and its root agree byte for byte.
        //
        // What is NOT tested here is that `Url::to_file_path` reads a `C:` first
        // segment back as a drive, and pretending otherwise was the previous
        // problem. That decode lives in the `url` crate behind
        // `#[cfg(windows)]`; the POSIX implementation is a different function
        // that yields a path to a directory literally named `C:`, and it
        // returns the same result either way. So no assertion runnable on this
        // host can distinguish the claim being true from it being false, and a
        // `cfg!(windows)` arm could not either — the Windows CI leg runs only
        // the C-source and Python suites, so this test never executes there.
        //
        // Stated rather than asserted, because it is load bearing: if that
        // decode did not hold, every Windows `file:` root would be
        // unresolvable and no leg would report it. Verified by reading
        // `url-2.5.8/src/lib.rs:3142-3165`, whose Windows branch accepts
        // exactly a two-byte `X:` or a four-byte `X%3A` first segment — so both
        // the canonical spelling and the escaped one it replaces resolve.
        let err = root_url_from_config("s3://bucket/").unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    /// The two forms of `root` treat `?` and `#` oppositely, and each is right
    /// for its own grammar.
    ///
    /// A `file:` URL is a configuration address, so it is refused for carrying
    /// either — `address::parse` would drop the fragment and
    /// `is_ancestor_or_self` would pin the route to the exact query, so the
    /// spelling would not mean what it reads like.
    ///
    /// A plain filesystem path is not a URL, so the same bytes are ordinary
    /// characters in a directory name and are escaped instead. Refusing them
    /// would make a legal directory unconfigurable, and interpolating them raw
    /// resolves a DIFFERENT directory: unescaped, `/srv/da#ta` becomes
    /// `file:///srv/da/`, the parent of what was asked for.
    ///
    /// Load-bearing lines: the `refused_config_component` block in
    /// `root_url_from_config`, and the six escaping `replace` calls in
    /// `root_url_from_filesystem_path`. Neither can cover for the other —
    /// deleting the first reddens the URL rows and the `prefix` row, deleting
    /// the escapes reddens only the plain-path rows.
    #[test]
    fn a_file_url_root_refuses_a_query_or_fragment_and_a_path_root_escapes_them() {
        for (spelling, component) in [
            ("file:///data/assets/#note", "fragment"),
            ("file:///data/assets/?v=1", "query"),
        ] {
            let Err(err) = root_url_from_config(spelling) else {
                panic!("{spelling} must be refused");
            };
            assert_eq!(err.code(), ErrorCode::InvalidArgument, "{spelling}");
            assert!(
                err.message().contains(component),
                "{spelling}: the refusal must name what it refused: {}",
                err.message()
            );
        }

        // The plain-path form keeps every byte. Both the serialization AND
        // the resolved filesystem path are asserted for every row: asserting
        // the serialization alone would stay green if the escape were correct
        // and the decode back to a path were not, which is the frame the loss
        // would move to.
        for (path, serialized, resolved) in [
            ("/srv/da#ta", "file:///srv/da%23ta/", "/srv/da#ta/"),
            ("/srv/da?ta", "file:///srv/da%3Fta/", "/srv/da?ta/"),
            ("/srv/a%20b", "file:///srv/a%2520b/", "/srv/a%20b/"),
            // The parser REMOVES these three rather than reading them as a
            // delimiter, so unescaped they merge two directory names into one
            // with no `?` or `#` anywhere in the string.
            ("/srv/a\tb", "file:///srv/a%09b/", "/srv/a\tb/"),
            ("/srv/a\nb", "file:///srv/a%0Ab/", "/srv/a\nb/"),
            ("/srv/a\rb", "file:///srv/a%0Db/", "/srv/a\rb/"),
        ] {
            let root = root_url_from_config(path).unwrap();
            assert_eq!(root.as_str(), serialized, "plain path {path}");
            assert_eq!(
                file_path(&root).unwrap().to_string_lossy(),
                resolved,
                "the escaped root must resolve to the directory that was named: {path}"
            );
        }

        // The refusal is on the field the operator wrote, not always on
        // `root`: the same loader serves `prefix`.
        let Err(err) = route_address_from_config(
            &LayerConfig::from([(
                "prefix".to_string(),
                ConfigValue::String("file:///srv/pub?v=1".to_string()),
            )]),
            &root_url_from_config("/srv").unwrap(),
        ) else {
            panic!("a query on `prefix` must be refused");
        };
        assert!(
            err.message().contains("'prefix'"),
            "the refusal must name the field the operator wrote: {}",
            err.message()
        );

        // The ordinary path is untouched by the escaping.
        assert_eq!(
            root_url_from_config("/data/assets").unwrap().as_str(),
            "file:///data/assets/"
        );
    }

    // Host connection config accepts a plain filesystem path as `root`; that
    // path must register and serve through the native Layer.
    #[tokio::test]
    async fn add_connection_accepts_plain_filesystem_path_root() {
        let tmp = tempfile::tempdir().unwrap();
        let backend = {
            let config = LayerConfig::new();
            FileBackendFactory
                .create_backend("files", &config, None)
                .await
                .unwrap()
        };

        let mut config = HashMap::new();
        config.insert(
            "root".into(),
            ConfigValue::String(tmp.path().to_string_lossy().into_owned()),
        );
        let connection = backend
            .add_connection(
                Request::new(LayerConnectionRequest {
                    target: "files".into(),
                    connection: ConnectionRequest {
                        backend_kind: FILE_BACKEND_KIND.into(),
                        config,
                        credentials: SecretBundle::default(),
                        persist: false,
                        display_name: None,
                    },
                }),
                None,
            )
            .await
            .unwrap();

        let root = connection.current_addresses[0].clone();
        assert_eq!(root.scheme(), "file");
        let file = root.join("hello.txt").unwrap();
        write_file(&backend, &file, b"hello").await;
        let info = backend
            .stat(
                Request::new(StatRequest {
                    address: file,
                    options: StatOptions::default(),
                }),
                None,
            )
            .await
            .unwrap();
        assert_eq!(info.size, Some(5));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn file_backend_prefers_longest_overlapping_connection_root() {
        for reverse_order in [false, true] {
            let tmp = tempfile::tempdir().unwrap();
            let srv_dir = tmp.path().join("srv");
            let outside = tmp.path().join("outside.txt");
            std::fs::create_dir_all(&srv_dir).unwrap();
            std::fs::write(srv_dir.join("inside.txt"), b"inside").unwrap();
            std::fs::write(&outside, b"outside").unwrap();
            std::os::unix::fs::symlink(&outside, srv_dir.join("escape")).unwrap();

            let backend = FileBackendFactory
                .create_backend("files", &LayerConfig::new(), None)
                .await
                .unwrap();
            let mut broad_config = LayerConfig::new();
            broad_config.insert("root".into(), ConfigValue::String("/".into()));
            let mut narrow_config = LayerConfig::new();
            narrow_config.insert(
                "root".into(),
                ConfigValue::String(srv_dir.to_string_lossy().into_owned()),
            );
            narrow_config.insert("confine_to_root".into(), ConfigValue::Bool(true));

            let add_connection = |config| LayerConnectionRequest {
                target: "files".into(),
                connection: ConnectionRequest {
                    backend_kind: FILE_BACKEND_KIND.into(),
                    config,
                    credentials: SecretBundle::default(),
                    persist: false,
                    display_name: None,
                },
            };
            let narrow_connection = if reverse_order {
                let narrow = backend
                    .add_connection(Request::new(add_connection(narrow_config)), None)
                    .await
                    .unwrap();
                backend
                    .add_connection(Request::new(add_connection(broad_config)), None)
                    .await
                    .unwrap();
                narrow
            } else {
                backend
                    .add_connection(Request::new(add_connection(broad_config)), None)
                    .await
                    .unwrap();
                backend
                    .add_connection(Request::new(add_connection(narrow_config)), None)
                    .await
                    .unwrap()
            };

            let srv = Url::from_directory_path(&srv_dir).unwrap();
            let inside = srv.join("inside.txt").unwrap();
            let root_info = backend
                .root_info_for(&inside, &Extensions::new(), None)
                .await
                .unwrap();
            assert_eq!(root_info.root, srv, "reverse_order={reverse_order}");
            assert_eq!(
                root_info.connection_id,
                Some(narrow_connection.id),
                "reverse_order={reverse_order}"
            );

            let escape = Url::from_file_path(srv_dir.join("escape")).unwrap();
            let err = backend
                .stat(
                    Request::new(StatRequest {
                        address: escape,
                        options: StatOptions::default(),
                    }),
                    None,
                )
                .await
                .expect_err("the narrow root's jail must deny its escaping symlink");
            assert_eq!(err.code(), ErrorCode::PermissionDenied);
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn enclosing_confining_root_is_not_disarmed_by_a_narrower_root() {
        for reverse_order in [false, true] {
            let tmp = tempfile::tempdir().unwrap();
            let broad_dir = tmp.path().join("broad");
            let narrow_dir = broad_dir.join("narrow");
            let outside = tmp.path().join("outside.txt");
            std::fs::create_dir_all(&narrow_dir).unwrap();
            std::fs::write(&outside, b"outside").unwrap();
            std::os::unix::fs::symlink(&outside, narrow_dir.join("escape")).unwrap();

            let backend = FileBackendFactory
                .create_backend("files", &LayerConfig::new(), None)
                .await
                .unwrap();
            let mut broad_config = LayerConfig::new();
            broad_config.insert(
                "root".into(),
                ConfigValue::String(broad_dir.to_string_lossy().into_owned()),
            );
            broad_config.insert("confine_to_root".into(), ConfigValue::Bool(true));
            let mut narrow_config = LayerConfig::new();
            narrow_config.insert(
                "root".into(),
                ConfigValue::String(narrow_dir.to_string_lossy().into_owned()),
            );
            let request = |config| {
                Request::new(LayerConnectionRequest {
                    target: "files".into(),
                    connection: ConnectionRequest {
                        backend_kind: FILE_BACKEND_KIND.into(),
                        config,
                        credentials: SecretBundle::default(),
                        persist: false,
                        display_name: None,
                    },
                })
            };
            if reverse_order {
                backend
                    .add_connection(request(narrow_config), None)
                    .await
                    .unwrap();
                backend
                    .add_connection(request(broad_config), None)
                    .await
                    .unwrap();
            } else {
                backend
                    .add_connection(request(broad_config), None)
                    .await
                    .unwrap();
                backend
                    .add_connection(request(narrow_config), None)
                    .await
                    .unwrap();
            }

            let escape = Url::from_file_path(narrow_dir.join("escape")).unwrap();
            let err = backend
                .stat(
                    Request::new(StatRequest {
                        address: escape,
                        options: StatOptions::default(),
                    }),
                    None,
                )
                .await
                .expect_err("every containing confining root must retain its jail");
            assert_eq!(err.code(), ErrorCode::PermissionDenied);
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn an_unconvertible_root_does_not_poison_a_valid_root() {
        let tmp = tempfile::tempdir().unwrap();
        let file_path = tmp.path().join("inside.txt");
        std::fs::write(&file_path, b"inside").unwrap();
        let mut config = LayerConfig::new();
        config.insert(
            "root".into(),
            ConfigValue::String(tmp.path().to_string_lossy().into_owned()),
        );
        let backend = FileBackendFactory
            .create_backend("files", &config, None)
            .await
            .unwrap();
        let mut invalid = LayerConfig::new();
        invalid.insert(
            "root".into(),
            ConfigValue::String("file://nas/share/".into()),
        );
        backend
            .add_connection(
                Request::new(LayerConnectionRequest {
                    target: "files".into(),
                    connection: ConnectionRequest {
                        backend_kind: FILE_BACKEND_KIND.into(),
                        config: invalid,
                        credentials: SecretBundle::default(),
                        persist: false,
                        display_name: None,
                    },
                }),
                None,
            )
            .await
            .unwrap();

        let address = Url::from_file_path(&file_path).unwrap();
        let info = backend
            .stat(
                Request::new(StatRequest {
                    address: address.clone(),
                    options: StatOptions::default(),
                }),
                None,
            )
            .await
            .unwrap();
        assert_eq!(info.size, Some(6));
        assert_eq!(
            backend
                .root_info_for(&address, &Extensions::new(), None)
                .await
                .unwrap()
                .root,
            Url::from_directory_path(tmp.path()).unwrap()
        );
    }
}
