// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::ChangeEvent;

pub fn backend_change_event_to_ffi(value: BackendChangeEvent) -> ffi::BackendChangeEvent {
    match value {
        BackendChangeEvent::Object {
            address,
            kind,
            etag,
            version,
            size,
            mtime,
            at,
            cursor,
        } => ffi::BackendChangeEvent::from_object(ffi::BackendChangeEventObject {
            address: address::object_address_to_ffi(address),
            kind: capabilities::change_kind_to_ffi(kind),
            etag: primitive::optional_to_ffi(etag, primitive::str_to_ffi),
            version: primitive::optional_to_ffi(version, primitive::str_to_ffi),
            size: primitive::optional_to_ffi(size, |s| s),
            mtime_unix_ms: primitive::optional_to_ffi(mtime, primitive::system_time_to_unix_ms),
            at_unix_ms: primitive::system_time_to_unix_ms(at),
            cursor: options::watch_directory_cursor_to_ffi(cursor),
        }),
        BackendChangeEvent::Lapsed { since, cursor } => {
            ffi::BackendChangeEvent::from_lapsed(ffi::BackendChangeEventLapsed {
                since_unix_ms: primitive::optional_to_ffi(since, primitive::system_time_to_unix_ms),
                cursor: options::watch_directory_cursor_to_ffi(cursor),
            })
        }
    }
}

/// # Safety
///
/// `value` must be a valid [`ffi::BackendChangeEvent`].
pub unsafe fn backend_change_event_from_ffi(
    value: ffi::BackendChangeEvent,
) -> Result<BackendChangeEvent, Error> {
    unsafe {
        let event = match value.tag {
            ffi::BackendChangeEventTag::Object => {
                let payload = std::ptr::read(value.object.as_ptr());
                std::mem::forget(value);
                let address = address::object_address_from_ffi(payload.address);
                let etag =
                    primitive::optional_from_ffi(payload.etag, |s| primitive::str_from_ffi(s));
                let version =
                    primitive::optional_from_ffi(payload.version, |s| primitive::str_from_ffi(s));
                let size = primitive::optional_from_ffi::<u64, u64, Error>(payload.size, Ok);
                let mtime = primitive::optional_from_ffi::<i64, SystemTime, Error>(
                    payload.mtime_unix_ms,
                    |ms| Ok(primitive::system_time_from_unix_ms(ms)),
                );
                BackendChangeEvent::Object {
                    address: address?,
                    kind: capabilities::change_kind_from_ffi(payload.kind),
                    etag: etag?,
                    version: version?,
                    size: size?,
                    mtime: mtime?,
                    at: primitive::system_time_from_unix_ms(payload.at_unix_ms),
                    cursor: options::watch_directory_cursor_from_ffi(payload.cursor),
                }
            }
            ffi::BackendChangeEventTag::Lapsed => {
                let payload = std::ptr::read(value.lapsed.as_ptr());
                std::mem::forget(value);
                let since = primitive::optional_from_ffi::<i64, SystemTime, Error>(
                    payload.since_unix_ms,
                    |ms| Ok(primitive::system_time_from_unix_ms(ms)),
                )?;
                BackendChangeEvent::Lapsed {
                    since,
                    cursor: options::watch_directory_cursor_from_ffi(payload.cursor),
                }
            }
        };
        Ok(event)
    }
}

pub fn address_roots_change_to_ffi(
    value: crate::AddressRootsChange,
) -> ffi::BackendAddressRootsChange {
    let (tag, roots) = match value {
        crate::AddressRootsChange::Snapshot(roots) => {
            (ffi::BackendAddressRootsChangeTag::Snapshot, roots)
        }
        crate::AddressRootsChange::Added(roots) => {
            (ffi::BackendAddressRootsChangeTag::Added, roots)
        }
        crate::AddressRootsChange::Removed(roots) => {
            (ffi::BackendAddressRootsChangeTag::Removed, roots)
        }
    };
    ffi::BackendAddressRootsChange {
        tag,
        roots: primitive::list_to_ffi(roots, address::address_root_entry_to_ffi),
    }
}

/// # Safety
///
/// `value` must be a valid [`ffi::BackendAddressRootsChange`].
pub unsafe fn address_roots_change_from_ffi(
    value: ffi::BackendAddressRootsChange,
) -> Result<crate::AddressRootsChange, Error> {
    let tag = value.tag;
    let roots_ffi = unsafe {
        // Move `roots` out without running `BackendAddressRootsChange`'s
        // field drops; the list elements travel into the iterator.
        let roots = std::ptr::read(&value.roots);
        std::mem::forget(value);
        roots
    };
    let roots: Vec<AddressRoot> = unsafe {
        primitive::list_from_ffi(roots_ffi, |entry| {
            address::address_root_entry_from_ffi(entry)
        })?
    };
    Ok(match tag {
        ffi::BackendAddressRootsChangeTag::Snapshot => crate::AddressRootsChange::Snapshot(roots),
        ffi::BackendAddressRootsChangeTag::Added => crate::AddressRootsChange::Added(roots),
        ffi::BackendAddressRootsChangeTag::Removed => crate::AddressRootsChange::Removed(roots),
    })
}

/// Host-side adapter that turns a plugin-emitted
/// [`ffi::BackendChangeStream`] into a Rust iterator over
/// `Result<crate::BackendChangeEvent>`. Same shape as
/// [`auth::AuthEventStream`].
pub struct BackendChangeStream {
    inner: ffi::BackendChangeStream,
    finished: bool,
}

impl BackendChangeStream {
    /// # Safety
    ///
    /// `inner` must satisfy the `ffi::BackendChangeStream`
    /// contract.
    pub unsafe fn from_ffi(inner: ffi::BackendChangeStream) -> Self {
        Self {
            inner,
            finished: false,
        }
    }
}

impl Iterator for BackendChangeStream {
    type Item = Result<BackendChangeEvent, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }
        let mut item = std::mem::MaybeUninit::<ffi::BackendChangeEvent>::uninit();
        let mut error = std::mem::MaybeUninit::<ffi::Error>::uninit();
        let step = unsafe {
            (self.inner.next_fn)(self.inner.state, item.as_mut_ptr(), error.as_mut_ptr())
        };
        match step {
            ffi::StreamStep::Yielded => {
                let item = unsafe { item.assume_init() };
                Some(unsafe { backend_change_event_from_ffi(item) })
            }
            ffi::StreamStep::Ended => {
                self.finished = true;
                None
            }
            // This backend change stream is terminal-on-error; a plugin
            // emitting `TransientError` is treated the same as `Failed`.
            ffi::StreamStep::Failed | ffi::StreamStep::TransientError => {
                self.finished = true;
                let error = unsafe { error.assume_init() };
                Some(Err(unsafe { error::from_ffi(error) }))
            }
        }
    }
}

/// Host-side adapter that owns the FFI cancel bridge for an iterator-shaped
/// stream's whole lifetime — `watch_directory`'s change stream and
/// `authenticate_connection`'s auth event stream both use it. It wraps the
/// boxed inner stream and forwards every
/// `next()` unchanged. Dropping it drops `inner` first — whose `Drop` runs the
/// plugin `drop_fn` that tears down the transport subscription — and then the
/// retained [`ffi::CancelTokenHandle`], which aborts the host→FFI cancel bridge
/// task and releases the shared refcount. Field declaration order is
/// load-bearing (Rust drops fields in declaration order): `inner` before
/// `_cancel`, so the transport tears down before the bridge aborts.
///
/// Retaining the `CancelTokenHandle` here keeps a host `cancel.cancel()`
/// reaching the plugin-side token the stream polls; dropping it when the
/// opening call returns would sever that link. This is the
/// ABI-compatible host half of the contract (the plugin half keeps the
/// matching `CancelTokenLocal` guard alive in the stream state).
pub struct CancelGuardedChangeStream<I> {
    inner: I,
    _cancel: Option<ffi::CancelTokenHandle>,
}

impl<I> CancelGuardedChangeStream<I> {
    /// Wrap `inner`, retaining `cancel` for the wrapped stream's lifetime.
    pub fn new(inner: I, cancel: Option<ffi::CancelTokenHandle>) -> Self {
        Self {
            inner,
            _cancel: cancel,
        }
    }
}

impl<I: Iterator> Iterator for CancelGuardedChangeStream<I> {
    type Item = I::Item;

    #[inline]
    fn next(&mut self) -> Option<I::Item> {
        self.inner.next()
    }
}

/// [`futures::Stream`] twin of [`CancelGuardedChangeStream`], with the same
/// ownership contract and the same load-bearing field order.
///
/// The v8 `list_address_roots` / `list_connections` update streams are
/// `Stream`s rather than `Iterator`s, so they cannot reuse the type above —
/// but they need the identical guarantee: dropping the
/// [`ffi::CancelTokenHandle`] when the *snapshot* returns would abort the
/// host→FFI cancel bridge while the update stream is still live, leaving a
/// host `cancel.cancel()` with nothing to reach.
pub struct CancelGuardedStream<S> {
    inner: S,
    _cancel: Option<ffi::CancelTokenHandle>,
}

impl<S> CancelGuardedStream<S> {
    /// Wrap `inner`, retaining `cancel` for the wrapped stream's lifetime.
    pub fn new(inner: S, cancel: Option<ffi::CancelTokenHandle>) -> Self {
        Self {
            inner,
            _cancel: cancel,
        }
    }
}

// `Unpin` rather than a pin projection: every caller wraps an already-boxed
// `Pin<Box<dyn Stream + Send>>`, which is `Unpin`.
impl<S: futures::Stream + Unpin> futures::Stream for CancelGuardedStream<S> {
    type Item = S::Item;

    #[inline]
    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<S::Item>> {
        std::pin::Pin::new(&mut self.inner).poll_next(cx)
    }
}

/// Host-side iterator over a plugin-emitted
/// [`ffi::BackendAddressRootsStream`]. Yields
/// `Result<crate::AddressRootsChange>` per the SPI contract.
pub struct BackendAddressRootsStreamIter {
    inner: ffi::BackendAddressRootsStream,
    finished: bool,
}

impl BackendAddressRootsStreamIter {
    /// # Safety
    ///
    /// `inner` must satisfy the `ffi::BackendAddressRootsStream`
    /// contract.
    pub unsafe fn from_ffi(inner: ffi::BackendAddressRootsStream) -> Self {
        Self {
            inner,
            finished: false,
        }
    }
}

impl Iterator for BackendAddressRootsStreamIter {
    type Item = Result<crate::AddressRootsChange, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }
        let mut item = std::mem::MaybeUninit::<ffi::BackendAddressRootsChange>::uninit();
        let mut error = std::mem::MaybeUninit::<ffi::Error>::uninit();
        let step = unsafe {
            (self.inner.next_fn)(self.inner.state, item.as_mut_ptr(), error.as_mut_ptr())
        };
        match step {
            ffi::StreamStep::Yielded => {
                let item = unsafe { item.assume_init() };
                Some(unsafe { address_roots_change_from_ffi(item) })
            }
            ffi::StreamStep::Ended => {
                self.finished = true;
                None
            }
            // Terminal-on-error stream; `TransientError` folds into `Failed`.
            ffi::StreamStep::Failed | ffi::StreamStep::TransientError => {
                self.finished = true;
                let error = unsafe { error.assume_init() };
                Some(Err(unsafe { error::from_ffi(error) }))
            }
        }
    }
}

// ---------------------------------------------------------------------
// Layer `ChangeEvent` <-> SPI `BackendChangeEvent` (identical shape,
// distinct types). Lives here so the v2 plugin/host projections share
// one mirror instead of each maintaining a copy.
// ---------------------------------------------------------------------

/// Project a layer-level [`ChangeEvent`] onto the SPI [`BackendChangeEvent`].
pub fn change_event_to_backend(event: ChangeEvent) -> BackendChangeEvent {
    match event {
        ChangeEvent::Object {
            address,
            kind,
            etag,
            version,
            size,
            mtime,
            at,
            cursor,
        } => BackendChangeEvent::Object {
            address,
            kind,
            etag,
            version,
            size,
            mtime,
            at,
            cursor,
        },
        ChangeEvent::Lapsed { since, cursor } => BackendChangeEvent::Lapsed { since, cursor },
    }
}

/// Project an SPI [`BackendChangeEvent`] onto the layer-level [`ChangeEvent`].
pub fn backend_change_event_to_change(event: BackendChangeEvent) -> ChangeEvent {
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
        } => ChangeEvent::Object {
            address,
            kind,
            etag,
            version,
            size,
            mtime,
            at,
            cursor,
        },
        BackendChangeEvent::Lapsed { since, cursor } => ChangeEvent::Lapsed { since, cursor },
    }
}
