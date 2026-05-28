// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Named scenario registry. Each entry pins a behavior by name with
//! profile gating, capability requirements, expected calls, and a
//! failure contract. Coexists with the URL-driven `TestConfig` knobs
//! that the legacy `tests/loaded.rs` host tests still drive.

use std::collections::BTreeMap;

use ovstorage_plugin::{Capabilities, ChangeKindSet, ErrorCode};

/// Address scheme for registry-driven dispatch. Coexists with the
/// legacy `test://` scheme in [`crate::config::ADDRESS_SCHEME`].
pub const CONFORMANCE_ADDRESS_SCHEME: &str = "conformance";

/// One named registry entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Scenario {
    /// Registry lookup key; also the `<scenario>` segment of
    /// `conformance://<scenario>/<key>`. ASCII alnum + `_`, no
    /// leading digit.
    pub name: &'static str,
    pub spi_methods: &'static [&'static str],
    pub required_profile: Profile,
    pub required_capabilities: &'static [&'static str],
    /// `ConnectionRequest.config` keys the runner populates; manual
    /// drivers must set these or get `InvalidArgument`.
    pub required_config: &'static [&'static str],
    /// Hosts the scenario may contact. Empty = no outbound network;
    /// the loopback responder enforces the allowlist.
    pub allowed_hosts: &'static [&'static str],
    pub expected_calls: &'static [ExpectedCall],
    pub failure_contract: FailureContract,
    pub report_tags: &'static [&'static str],
}

/// Capability profile gate; scenarios pick one, hosts that don't
/// satisfy it are skipped. `#[non_exhaustive]` so adding profiles is
/// non-breaking.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Profile {
    /// stat/read/write/delete/list/create_dir/delete_dir floor.
    Minimal,
    /// `If-Match`, `If-None-Match`, `If-Modified-Since`.
    ConditionalWrites,
    /// First-class metadata on every stat/list.
    MetadataNative,
    /// Latest-version lookup returns the newest pinned version address.
    VersionsNewest,
    /// Real directory entities (no marker-folding).
    DirectoriesReal,
    /// Atomic rename; non-atomic backends fall through to copy+delete.
    AtomicRename,
    /// `watch_directory` survives cursor reconnect.
    WatchDirectoryResumable,
    /// `read`/`write` may return a redirect.
    Redirects,
    /// Read may return `LocalDelegate`.
    LocalDelegate,
}

impl Profile {
    /// [`Capabilities`] the test plugin advertises for this profile.
    /// Additive over the `Minimal` floor.
    pub fn capabilities(self) -> Capabilities {
        let mut caps = Capabilities::empty();
        caps.supports_list = true;
        caps.supports_delete = true;
        caps.supports_create_directory = true;
        caps.supports_delete_directory = true;
        caps.supports_write = true;
        caps.supports_write_stream = true;
        match self {
            Profile::Minimal => {}
            Profile::ConditionalWrites => {
                caps.supports_no_overwrite_write = true;
                caps.supports_if_match_write = true;
            }
            Profile::MetadataNative => {
                caps.supports_native_metadata_patch = true;
            }
            Profile::VersionsNewest => {
                caps.supports_version_listing = true;
            }
            Profile::DirectoriesReal => {
                caps.has_real_directories = true;
                caps.supports_recursive_list = true;
            }
            Profile::AtomicRename => {
                caps.supports_server_side_rename = true;
                caps.supports_atomic_rename = true;
            }
            Profile::WatchDirectoryResumable => {
                caps.supports_watch_directory = true;
                caps.watch_directory_kinds = ChangeKindSet {
                    created: true,
                    modified: true,
                    deleted: true,
                    metadata_changed: true,
                };
            }
            Profile::Redirects => {
                // No dedicated capability bit; redirect path is
                // selected via `test_redirect_url`.
            }
            Profile::LocalDelegate => {
                // No capability bit; LocalDelegate is a ReadResult shape.
            }
        }
        caps
    }
}

/// One entry in a scenario's `expected_calls`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpectedCall {
    /// SPI method name (e.g. `"stat"`, `"write_redirect"`).
    pub method: &'static str,
    /// Tolerates additional same-method calls in the surrounding gap.
    pub allow_extra: bool,
}

/// Failure shape the scenario expects.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FailureContract {
    Success,
    /// `method` must surface `code`; later methods aren't invoked.
    Errors {
        method: &'static str,
        code: ErrorCode,
    },
}

/// Lookup table for runner crates. Built once, read-only afterwards.
#[derive(Clone, Debug, Default)]
pub struct ScenarioRegistry {
    by_name: BTreeMap<&'static str, Scenario>,
}

impl ScenarioRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register the harness's default scenario set.
    pub fn with_defaults() -> Self {
        let mut reg = Self::new();
        reg.insert(Scenario {
            name: "stat-basic-objectinfo",
            spi_methods: &["stat"],
            required_profile: Profile::Minimal,
            required_capabilities: &[],
            required_config: &[],
            allowed_hosts: &[],
            expected_calls: &[ExpectedCall {
                method: "stat",
                allow_extra: false,
            }],
            failure_contract: FailureContract::Success,
            report_tags: &["stat", "smoke"],
        });
        reg.insert(Scenario {
            name: "stat-not-found",
            spi_methods: &["stat"],
            required_profile: Profile::Minimal,
            required_capabilities: &[],
            required_config: &[],
            allowed_hosts: &[],
            expected_calls: &[ExpectedCall {
                method: "stat",
                allow_extra: false,
            }],
            failure_contract: FailureContract::Errors {
                method: "stat",
                code: ErrorCode::NotFound,
            },
            report_tags: &["stat"],
        });
        reg.insert(Scenario {
            name: "read-streamed-empty",
            spi_methods: &["read"],
            required_profile: Profile::Minimal,
            required_capabilities: &[],
            required_config: &[],
            allowed_hosts: &[],
            expected_calls: &[ExpectedCall {
                method: "read",
                allow_extra: false,
            }],
            failure_contract: FailureContract::Success,
            report_tags: &["read", "smoke"],
        });
        reg.insert(Scenario {
            name: "write-done-inline",
            spi_methods: &["write"],
            required_profile: Profile::Minimal,
            required_capabilities: &[],
            required_config: &[],
            allowed_hosts: &[],
            expected_calls: &[ExpectedCall {
                method: "write",
                allow_extra: false,
            }],
            failure_contract: FailureContract::Success,
            report_tags: &["write", "smoke"],
        });
        reg.insert(Scenario {
            name: "write-no-overwrite-existing",
            spi_methods: &["write"],
            required_profile: Profile::ConditionalWrites,
            required_capabilities: &["supports_no_overwrite_write"],
            required_config: &[],
            allowed_hosts: &[],
            expected_calls: &[
                ExpectedCall {
                    method: "write",
                    allow_extra: false,
                },
                ExpectedCall {
                    method: "write",
                    allow_extra: false,
                },
            ],
            failure_contract: FailureContract::Errors {
                method: "write",
                code: ErrorCode::Conflict,
            },
            report_tags: &["write", "preconditions"],
        });
        reg.insert(Scenario {
            name: "delete-existing-object",
            spi_methods: &["write", "delete"],
            required_profile: Profile::Minimal,
            required_capabilities: &[],
            required_config: &[],
            allowed_hosts: &[],
            expected_calls: &[
                ExpectedCall {
                    method: "write",
                    allow_extra: false,
                },
                ExpectedCall {
                    method: "delete",
                    allow_extra: false,
                },
            ],
            failure_contract: FailureContract::Success,
            report_tags: &["delete"],
        });
        reg.insert(Scenario {
            name: "list-one-level-vs-recursive",
            spi_methods: &["list"],
            required_profile: Profile::Minimal,
            required_capabilities: &[],
            required_config: &[],
            allowed_hosts: &[],
            expected_calls: &[ExpectedCall {
                method: "list",
                allow_extra: true,
            }],
            failure_contract: FailureContract::Success,
            report_tags: &["list"],
        });
        reg.insert(Scenario {
            name: "metadata-unsupported-not-called",
            spi_methods: &[],
            required_profile: Profile::Minimal,
            required_capabilities: &[],
            required_config: &[],
            allowed_hosts: &[],
            // Negative assertion: no calls allowed.
            expected_calls: &[],
            failure_contract: FailureContract::Success,
            report_tags: &["capability-skip", "metadata"],
        });
        reg
    }

    pub fn insert(&mut self, scenario: Scenario) {
        self.by_name.insert(scenario.name, scenario);
    }

    pub fn get(&self, name: &str) -> Option<&Scenario> {
        self.by_name.get(name)
    }

    pub fn iter(&self) -> impl Iterator<Item = &Scenario> {
        self.by_name.values()
    }

    pub fn len(&self) -> usize {
        self.by_name.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_name.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_with_defaults_seeds_named_scenarios() {
        let reg = ScenarioRegistry::with_defaults();
        assert!(!reg.is_empty());
        assert!(reg.get("stat-basic-objectinfo").is_some());
        assert!(reg.get("write-done-inline").is_some());
        assert!(reg.get("delete-existing-object").is_some());
    }

    #[test]
    fn registry_new_starts_empty() {
        let reg = ScenarioRegistry::new();
        assert!(reg.is_empty());
    }

    #[test]
    fn profile_minimal_advertises_floor_capabilities() {
        let caps = Profile::Minimal.capabilities();
        assert!(caps.supports_list);
        assert!(!caps.supports_native_metadata_patch);
    }

    #[test]
    fn profile_atomic_rename_advertises_atomic_bits() {
        let caps = Profile::AtomicRename.capabilities();
        assert!(caps.supports_server_side_rename);
        assert!(caps.supports_atomic_rename);
    }

    #[test]
    fn registry_insert_and_lookup() {
        let mut reg = ScenarioRegistry::new();
        reg.insert(Scenario {
            name: "round_trip",
            spi_methods: &["write", "read", "stat"],
            required_profile: Profile::Minimal,
            required_capabilities: &[],
            required_config: &[],
            allowed_hosts: &[],
            expected_calls: &[
                ExpectedCall {
                    method: "write",
                    allow_extra: false,
                },
                ExpectedCall {
                    method: "read",
                    allow_extra: false,
                },
            ],
            failure_contract: FailureContract::Success,
            report_tags: &["smoke"],
        });
        assert_eq!(reg.len(), 1);
        let s = reg.get("round_trip").expect("inserted");
        assert_eq!(s.required_profile, Profile::Minimal);
    }
}
