// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

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
            ffi::StreamStep::Failed => {
                self.finished = true;
                let error = unsafe { error.assume_init() };
                Some(Err(unsafe { error::from_ffi(error) }))
            }
        }
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
            ffi::StreamStep::Failed => {
                self.finished = true;
                let error = unsafe { error.assume_init() };
                Some(Err(unsafe { error::from_ffi(error) }))
            }
        }
    }
}
