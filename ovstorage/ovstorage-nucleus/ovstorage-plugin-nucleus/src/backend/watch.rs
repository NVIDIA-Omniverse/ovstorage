// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Sync `Iterator` adapter over the async `subscribe_list` pump.
//!
//! A dedicated OS thread owns the tokio runtime so a single-thread test
//! runtime blocked on `Iterator::next` cannot deadlock the producer.
//! The whole module disappears once the SPI watch surface goes async.

use std::time::SystemTime;

use ovstorage_plugin::{
    BackendChangeEvent, ChangeKind, Error, ErrorCode, Result, Url, WatchDirectoryCursor, address,
};

use nucleus_client::types::StatusType;

use crate::ops::WatchHandle;

use super::convert::relative_key_for;

type WatchFrame = std::result::Result<Vec<u8>, ()>;

pub(super) struct WatchIter {
    rx: Option<std::sync::mpsc::Receiver<WatchFrame>>,
    cursor: WatchDirectoryCursor,
    finished: bool,
    prefix_path: String,
    recursive: bool,
    include_metadata_changes: bool,
    pending_lapsed: bool,
    prefix_address: Url,
    _pump: Option<std::thread::JoinHandle<()>>,
}

impl WatchIter {
    pub(super) fn new(
        handle: WatchHandle,
        prefix_address: Url,
        prefix_path: String,
        recursive: bool,
        include_metadata_changes: bool,
    ) -> Self {
        let (tx, rx) = std::sync::mpsc::channel::<WatchFrame>();
        let pump = std::thread::Builder::new()
            .name("ovs-nuc-watch".into())
            .spawn(move || {
                let WatchHandle { mut subscription } = handle;
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(_) => return,
                };
                runtime.block_on(async move {
                    loop {
                        match subscription.recv_raw().await {
                            Ok(raw) => {
                                if tx.send(Ok(raw.json)).is_err() {
                                    break;
                                }
                            }
                            Err(_) => {
                                let _ = tx.send(Err(()));
                                break;
                            }
                        }
                    }
                });
            })
            .ok();
        Self {
            rx: Some(rx),
            cursor: WatchDirectoryCursor::default(),
            finished: false,
            prefix_path,
            recursive,
            include_metadata_changes,
            pending_lapsed: false,
            prefix_address,
            _pump: pump,
        }
    }

    pub(super) fn lapsed_only() -> Self {
        Self {
            rx: None,
            cursor: WatchDirectoryCursor::default(),
            finished: false,
            prefix_path: String::new(),
            recursive: false,
            include_metadata_changes: false,
            pending_lapsed: true,
            prefix_address: address::parse("omniverse://lapsed/").expect("valid sentinel URL"),
            _pump: None,
        }
    }
}

impl Iterator for WatchIter {
    type Item = Result<BackendChangeEvent>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }
        if self.pending_lapsed {
            self.pending_lapsed = false;
            self.finished = true;
            return Some(Ok(BackendChangeEvent::Lapsed {
                since: None,
                cursor: self.cursor.clone(),
            }));
        }
        let rx = self.rx.as_ref()?;
        loop {
            let raw = match rx.recv() {
                Ok(Ok(raw)) => raw,
                Ok(Err(())) | Err(_) => {
                    self.finished = true;
                    return Some(Ok(BackendChangeEvent::Lapsed {
                        since: None,
                        cursor: self.cursor.clone(),
                    }));
                }
            };
            let response: nucleus_client::types::SubscribeListResponse =
                match serde_json::from_slice(&raw) {
                    Ok(resp) => resp,
                    Err(err) => {
                        self.finished = true;
                        return Some(Err(Error::new(
                            ErrorCode::Internal,
                            format!("invalid Nucleus subscribe_list frame: {err}"),
                        )));
                    }
                };
            // Only catastrophic terminal statuses end the watch; transient/info
            // statuses (`OK`, `PartiallyCompleted`, `Idle`, etc.) are stream signals,
            // not errors. Reference CLI deliberately doesn't check status here.
            match response.status {
                StatusType::Denied
                | StatusType::Unauthenticated
                | StatusType::TokenExpired
                | StatusType::AccessLost
                | StatusType::ConnectionLost => {
                    self.finished = true;
                    return Some(Err(Error::new(
                        ErrorCode::AuthRequired,
                        format!(
                            "Nucleus subscribe_list terminated by server status {:?}",
                            response.status
                        ),
                    )));
                }
                _ => {}
            }
            let Some(entry) = response.entry else {
                continue;
            };
            let Some(kind) = subscribe_event_to_change_kind(response.event) else {
                continue;
            };
            if !self.include_metadata_changes && kind == ChangeKind::MetadataChanged {
                continue;
            }
            let Some(entry_path) = entry.path.clone() else {
                continue;
            };
            let Some(relative_key) = relative_key_for(&self.prefix_path, &entry_path) else {
                continue;
            };
            if !self.recursive && relative_key.contains('/') {
                continue;
            }
            let Ok(address) = address::join_relative(&self.prefix_address, &relative_key) else {
                // One unaddressable path must not end the stream: every later
                // event for every other path would be lost with it. Skip this
                // one and keep watching.
                tracing::warn!(
                    target: "ovstorage.nucleus.watch",
                    plugin = "nucleus",
                    key = %relative_key,
                    "nucleus: path is not addressable as a URI path; change event omitted",
                );
                continue;
            };
            let etag = entry.etag.clone();
            let size = entry.size;
            let mtime = entry
                .modified_timestamp
                .map(|secs| SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(secs));
            let at = mtime.unwrap_or_else(SystemTime::now);
            // Omni1's `subscribe_list` carries `etag`, `modified_timestamp`, and `size`
            // on the entry payload; it has no generation/version token, so `version`
            // stays `None` for Nucleus.
            return Some(Ok(BackendChangeEvent::Object {
                address,
                kind,
                etag,
                version: None,
                size,
                mtime,
                at,
                cursor: self.cursor.clone(),
            }));
        }
    }
}

fn subscribe_event_to_change_kind(
    event: Option<nucleus_client::types::PathEvent>,
) -> Option<ChangeKind> {
    use nucleus_client::types::PathEvent;
    match event? {
        PathEvent::Create | PathEvent::Full => Some(ChangeKind::Created),
        PathEvent::Delta | PathEvent::Rename | PathEvent::Copy | PathEvent::VersionReplaced => {
            Some(ChangeKind::Modified)
        }
        PathEvent::Delete => Some(ChangeKind::Deleted),
        PathEvent::ChangeAcl
        | PathEvent::Options
        | PathEvent::Locked
        | PathEvent::Unlocked
        | PathEvent::CheckpointsChanged => Some(ChangeKind::MetadataChanged),
    }
}
