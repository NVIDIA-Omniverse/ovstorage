// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Structured SPI-call log; siblings the per-method counter map in
//! the internal `store` module.

use std::sync::{Arc, Mutex};

use ovstorage_plugin::{ResolvedTarget, Url};

/// One observed SPI call. Variants mirror
/// [`ovstorage_plugin::shim::Backend`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ObservedCall {
    Stat { target: Url },
    Read { target: Url },
    Write { target: Url, byte_len: usize },
    WriteStream { target: Url, byte_len: usize },
    WriteRedirect { target: Url },
    ContinueWrite { target: Url },
    Delete { target: Url },
    List { prefix: Url, recursive: bool },
    ListVersions { target: Url },
    WatchDirectory { prefix: Url },
    WatchAddressRoots,
    CreateDirectory { target: Url },
    DeleteDirectory { target: Url },
    Copy { src: Url, dest: Url },
    Rename { src: Url, dest: Url },
    UpdateMetadata { target: Url },
    CheckAccess { target: Url },
}

impl ObservedCall {
    /// SPI method name; matches [`crate::scenarios::ExpectedCall::method`].
    pub fn method_name(&self) -> &'static str {
        match self {
            ObservedCall::Stat { .. } => "stat",
            ObservedCall::Read { .. } => "read",
            ObservedCall::Write { .. } => "write",
            ObservedCall::WriteStream { .. } => "write_stream",
            ObservedCall::WriteRedirect { .. } => "write_redirect",
            ObservedCall::ContinueWrite { .. } => "continue_write",
            ObservedCall::Delete { .. } => "delete",
            ObservedCall::List { .. } => "list",
            ObservedCall::ListVersions { .. } => "list_versions",
            ObservedCall::WatchDirectory { .. } => "watch_directory",
            ObservedCall::WatchAddressRoots => "watch_address_roots",
            ObservedCall::CreateDirectory { .. } => "create_directory",
            ObservedCall::DeleteDirectory { .. } => "delete_directory",
            ObservedCall::Copy { .. } => "copy",
            ObservedCall::Rename { .. } => "rename",
            ObservedCall::UpdateMetadata { .. } => "update_metadata",
            ObservedCall::CheckAccess { .. } => "check_access",
        }
    }
}

/// Cheaply-cloneable handle on a shared call log.
#[derive(Clone, Default)]
pub struct Recorder {
    calls: Arc<Mutex<Vec<ObservedCall>>>,
}

impl Recorder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a call to the log.
    pub fn observe(&self, call: ObservedCall) {
        if let Ok(mut log) = self.calls.lock() {
            log.push(call);
        }
    }

    pub fn snapshot(&self) -> Vec<ObservedCall> {
        self.calls.lock().map(|log| log.clone()).unwrap_or_default()
    }

    pub fn clear(&self) {
        if let Ok(mut log) = self.calls.lock() {
            log.clear();
        }
    }

    /// Count entries whose method name matches.
    pub fn count_method(&self, method: &str) -> usize {
        self.snapshot()
            .iter()
            .filter(|c| c.method_name() == method)
            .count()
    }
}

/// Synthesize an `ObservedCall` from a `ResolvedTarget` and method name.
pub fn observe_simple(recorder: &Recorder, method: &str, target: &ResolvedTarget) {
    let url = target.resolved_address.clone();
    let call = match method {
        "stat" => ObservedCall::Stat { target: url },
        "read" => ObservedCall::Read { target: url },
        "delete" => ObservedCall::Delete { target: url },
        "write_redirect" => ObservedCall::WriteRedirect { target: url },
        "continue_write" => ObservedCall::ContinueWrite { target: url },
        "list_versions" => ObservedCall::ListVersions { target: url },
        "create_directory" => ObservedCall::CreateDirectory { target: url },
        "delete_directory" => ObservedCall::DeleteDirectory { target: url },
        "update_metadata" => ObservedCall::UpdateMetadata { target: url },
        "check_access" => ObservedCall::CheckAccess { target: url },
        // Methods needing richer args must call `observe` directly.
        _ => return,
    };
    recorder.observe(call);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observe_appends_in_order() {
        let r = Recorder::new();
        r.observe(ObservedCall::Stat {
            target: Url::parse("test://a/").unwrap(),
        });
        r.observe(ObservedCall::Read {
            target: Url::parse("test://a/key").unwrap(),
        });
        let log = r.snapshot();
        assert_eq!(log.len(), 2);
        assert_eq!(log[0].method_name(), "stat");
        assert_eq!(log[1].method_name(), "read");
    }

    #[test]
    fn count_method_filters_by_name() {
        let r = Recorder::new();
        r.observe(ObservedCall::Stat {
            target: Url::parse("test://a/").unwrap(),
        });
        r.observe(ObservedCall::Stat {
            target: Url::parse("test://b/").unwrap(),
        });
        r.observe(ObservedCall::Read {
            target: Url::parse("test://a/key").unwrap(),
        });
        assert_eq!(r.count_method("stat"), 2);
        assert_eq!(r.count_method("read"), 1);
        assert_eq!(r.count_method("write"), 0);
    }

    #[test]
    fn clear_resets_log() {
        let r = Recorder::new();
        r.observe(ObservedCall::Stat {
            target: Url::parse("test://a/").unwrap(),
        });
        r.clear();
        assert!(r.snapshot().is_empty());
    }
}
