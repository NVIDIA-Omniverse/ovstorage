// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Named scenario registry. Each entry pins a behavior by name with
//! profile gating, capability requirements, expected calls, and a
//! failure contract. Coexists with the URL-driven `TestConfig` knobs
//! that the `tests/loaded.rs` host tests drive across the plugin FFI.

use std::collections::BTreeMap;

use ovstorage_plugin::{Capabilities, ChangeKindSet, ErrorCode};

/// Address scheme for registry-driven dispatch. Coexists with the
/// legacy `test://` scheme in [`crate::config::ADDRESS_SCHEME`].
pub const CONFORMANCE_ADDRESS_SCHEME: &str = "conformance";

/// The `capability-gate-<op>-unsupported` family: one
/// `(scenario name, gated slot)` pair per self-gated optional slot. The
/// driver disables exactly that op's capability bit
/// (`test_caps_disable = "<op>"`), invokes the op anyway, and expects a
/// typed `Unsupported` with no recorded call and no side effects.
pub const CAPABILITY_GATE_SCENARIOS: &[(&str, &str)] = &[
    ("capability-gate-delete-unsupported", "delete"),
    (
        "capability-gate-write-redirect-unsupported",
        "write_redirect",
    ),
    (
        "capability-gate-update-metadata-unsupported",
        "update_metadata",
    ),
    ("capability-gate-check-access-unsupported", "check_access"),
    (
        "capability-gate-create-directory-unsupported",
        "create_directory",
    ),
    (
        "capability-gate-delete-directory-unsupported",
        "delete_directory",
    ),
    ("capability-gate-list-versions-unsupported", "list_versions"),
    (
        "capability-gate-watch-directory-unsupported",
        "watch_directory",
    ),
];

/// One named registry entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Scenario {
    /// Registry lookup key; also the `<scenario>` segment of
    /// `conformance://<scenario>/<key>`. ASCII alnum + `_`, no
    /// leading digit.
    pub name: &'static str,
    /// `OvStorage_LayerVTable` slot names this scenario exercises.
    /// Descriptive metadata for reports and filtering only — the
    /// runner matches `expected_calls` against recorded bare method
    /// names, never this list.
    pub vtable_slots: &'static [&'static str],
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
                caps.supports_rename = true;
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
    /// Vtable-slot method name, bare (e.g. `"stat"`, `"write_redirect"`).
    pub method: &'static str,
    /// Tolerates additional same-method calls in the surrounding gap.
    pub allow_extra: bool,
}

/// Failure shape the scenario expects.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FailureContract {
    Success,
    /// `method` must surface `code`; later methods aren't invoked.
    ///
    /// Only the [`ErrorCode`] is conformance-enforced. Guidance text
    /// (e.g. the type-mismatch "use delete_directory()" hints) is
    /// deliberately not pinned here: wording is implementation-specific,
    /// and pinning substrings across providers would couple the registry
    /// to each backend's phrasing. The reference implementations'
    /// messages are asserted in their own unit tests instead
    /// (`ovstorage/src/file/mod.rs`, `conformance_contracts.rs`).
    Errors {
        method: &'static str,
        code: ErrorCode,
    },
    /// Either outcome conforms: the full `expected_calls` sequence
    /// completes successfully, OR `method` refuses typed with `code`
    /// before its effect (on the refusal path, `expected_calls` entries
    /// after `method` are not required — the runner truncates the
    /// expectation there). Encodes contracts whose essence is an
    /// invariant (e.g. "no silent data loss") that both a faithful
    /// success and an upfront typed refusal satisfy.
    SuccessOrRefusal {
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
            vtable_slots: &["stat"],
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
            vtable_slots: &["stat"],
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
            vtable_slots: &["read"],
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
            vtable_slots: &["write"],
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
            vtable_slots: &["write"],
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
            // `IfDestExists::Fail` against an existing destination is
            // documented as `AlreadyExists` (see the `IfDestExists` docs);
            // the original `Conflict` demand contradicted both the SPI
            // contract and the test backend, and was never driven.
            failure_contract: FailureContract::Errors {
                method: "write",
                code: ErrorCode::AlreadyExists,
            },
            report_tags: &["write", "preconditions"],
        });
        reg.insert(Scenario {
            name: "delete-existing-object",
            vtable_slots: &["write", "delete"],
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
        // Encoded as a contract: `copy(src, src)` must NOT lose
        // data (truncating the destination before the source bytes are
        // read would zero the file out). Both
        // outcomes conform: the copy succeeds and a subsequent read
        // returns the original bytes, OR the copy refuses typed with
        // `Conflict` before touching anything (OpenDAL's `IsSameFile`
        // guard) — silent loss is what fails.
        //
        // LIMITATION: the registry pins the op shape and outcome codes;
        // byte-preservation itself is asserted by each DRIVER's readback
        // (the same division as `Errors` pinning only the code, not the
        // guidance text). A driver wiring this scenario through
        // `verify_recorded` without reading the bytes back would pass
        // vacuously on the data-safety half — drivers MUST assert the
        // post-copy content. Expressing content assertions in the
        // registry itself is a possible future extension.
        reg.insert(Scenario {
            name: "copy-to-self-preserves-content",
            vtable_slots: &["write", "copy", "read"],
            required_profile: Profile::Minimal,
            required_capabilities: &["supports_server_side_copy"],
            required_config: &[],
            allowed_hosts: &[],
            expected_calls: &[
                ExpectedCall {
                    method: "write",
                    allow_extra: false,
                },
                ExpectedCall {
                    method: "copy",
                    allow_extra: false,
                },
                ExpectedCall {
                    method: "read",
                    allow_extra: false,
                },
            ],
            failure_contract: FailureContract::SuccessOrRefusal {
                method: "copy",
                code: ErrorCode::Conflict,
            },
            report_tags: &["copy", "data-safety"],
        });
        // Encoded as a contract: `RenameOptions.if_dest` is the
        // opt-in no-overwrite control (the default deliberately stays
        // POSIX overwrite); `IfDestExists::Fail` against an existing
        // destination surfaces `AlreadyExists` — the same documented
        // `IfDestExists` contract as `write-no-overwrite-existing` — and
        // the destination survives.
        reg.insert(Scenario {
            name: "rename-no-overwrite-existing",
            vtable_slots: &["write", "rename"],
            required_profile: Profile::AtomicRename,
            required_capabilities: &["supports_server_side_rename", "supports_no_overwrite_write"],
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
                ExpectedCall {
                    method: "rename",
                    allow_extra: false,
                },
            ],
            failure_contract: FailureContract::Errors {
                method: "rename",
                code: ErrorCode::AlreadyExists,
            },
            report_tags: &["rename", "preconditions", "data-safety"],
        });
        reg.insert(Scenario {
            name: "list-one-level-vs-recursive",
            vtable_slots: &["list"],
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
            vtable_slots: &[],
            required_profile: Profile::Minimal,
            required_capabilities: &[],
            required_config: &[],
            allowed_hosts: &[],
            // Negative assertion: no calls allowed.
            expected_calls: &[],
            failure_contract: FailureContract::Success,
            report_tags: &["capability-skip", "metadata"],
        });
        // Type-mismatch contracts: a leaf whose kind mismatches the operation
        // surfaces a typed InvalidArgument with guidance, never a
        // misleading NotFound and never a handle the caller cannot open.
        // Covers `delete`, `delete_directory`, `list` and `read`. Only
        // meaningful for backends with real directory entities.
        reg.insert(Scenario {
            name: "delete-on-directory-type-mismatch",
            vtable_slots: &["create_directory", "delete"],
            required_profile: Profile::DirectoriesReal,
            required_capabilities: &["has_real_directories"],
            required_config: &[],
            allowed_hosts: &[],
            expected_calls: &[
                ExpectedCall {
                    method: "create_directory",
                    allow_extra: false,
                },
                ExpectedCall {
                    method: "delete",
                    allow_extra: false,
                },
            ],
            failure_contract: FailureContract::Errors {
                method: "delete",
                code: ErrorCode::InvalidArgument,
            },
            report_tags: &["delete", "type-mismatch"],
        });
        reg.insert(Scenario {
            name: "delete-directory-on-file-type-mismatch",
            vtable_slots: &["write", "delete_directory"],
            required_profile: Profile::DirectoriesReal,
            required_capabilities: &["has_real_directories"],
            required_config: &[],
            allowed_hosts: &[],
            expected_calls: &[
                ExpectedCall {
                    method: "write",
                    allow_extra: false,
                },
                ExpectedCall {
                    method: "delete_directory",
                    allow_extra: false,
                },
            ],
            failure_contract: FailureContract::Errors {
                method: "delete_directory",
                code: ErrorCode::InvalidArgument,
            },
            report_tags: &["delete_directory", "type-mismatch"],
        });
        reg.insert(Scenario {
            name: "list-on-file-type-mismatch",
            vtable_slots: &["write", "list"],
            required_profile: Profile::DirectoriesReal,
            required_capabilities: &["has_real_directories"],
            required_config: &[],
            allowed_hosts: &[],
            expected_calls: &[
                ExpectedCall {
                    method: "write",
                    allow_extra: false,
                },
                ExpectedCall {
                    method: "list",
                    allow_extra: false,
                },
            ],
            failure_contract: FailureContract::Errors {
                method: "list",
                code: ErrorCode::InvalidArgument,
            },
            report_tags: &["list", "type-mismatch"],
        });
        reg.insert(Scenario {
            name: "read-on-directory-type-mismatch",
            vtable_slots: &["create_directory", "read"],
            required_profile: Profile::DirectoriesReal,
            required_capabilities: &["has_real_directories"],
            required_config: &[],
            allowed_hosts: &[],
            expected_calls: &[
                ExpectedCall {
                    method: "create_directory",
                    allow_extra: false,
                },
                ExpectedCall {
                    method: "read",
                    allow_extra: false,
                },
            ],
            failure_contract: FailureContract::Errors {
                method: "read",
                code: ErrorCode::InvalidArgument,
            },
            report_tags: &["read", "type-mismatch"],
        });
        // Capability self-gate: a slot whose capability bit is false
        // returns a typed Unsupported with no side effects — and never
        // reaches the backend bodies (expected_calls is empty because the
        // layer's own gate refuses before anything records).
        for &(name, method) in CAPABILITY_GATE_SCENARIOS {
            reg.insert(Scenario {
                name,
                vtable_slots: &[],
                required_profile: Profile::Minimal,
                required_capabilities: &[],
                required_config: &[],
                allowed_hosts: &[],
                expected_calls: &[],
                failure_contract: FailureContract::Errors {
                    method,
                    code: ErrorCode::Unsupported,
                },
                report_tags: &["capability-skip", "self-gate"],
            });
        }
        // Mutations on a read-only connection are rejected by the
        // owning backend itself (the driver configures a read-only
        // capability set; `write` is the primary probed mutation).
        reg.insert(Scenario {
            name: "readonly-connection-rejects-mutations",
            vtable_slots: &[],
            required_profile: Profile::Minimal,
            required_capabilities: &[],
            required_config: &[],
            allowed_hosts: &[],
            expected_calls: &[],
            failure_contract: FailureContract::Errors {
                method: "write",
                code: ErrorCode::Unsupported,
            },
            report_tags: &["capability-skip", "read-only"],
        });
        // A competing-consumer backend self-coalesces overlapping subscriptions
        // onto one recursive, metadata-inclusive physical watch and projects
        // narrower logical subscriptions. That is sound only when enabling
        // either option adds events without replacing events from the narrower
        // stream.
        reg.insert(Scenario {
            name: "watch-directory-option-superset",
            vtable_slots: &["watch_directory"],
            required_profile: Profile::Minimal,
            required_capabilities: &["supports_watch_directory"],
            required_config: &[],
            allowed_hosts: &[],
            expected_calls: &[
                ExpectedCall {
                    method: "watch_directory",
                    allow_extra: false,
                },
                ExpectedCall {
                    method: "watch_directory",
                    allow_extra: false,
                },
                ExpectedCall {
                    method: "watch_directory",
                    allow_extra: false,
                },
            ],
            failure_contract: FailureContract::Success,
            report_tags: &["watch_directory", "option-superset"],
        });
        // Cross-prefix non-split (the load-bearing reason coalescing is a
        // backend responsibility): concurrent watches on DIFFERENT prefixes
        // of ONE connection each receive all of their matching events and
        // lose none. Three watchers on one connection — W1 `root/a/` and
        // W2 `root/b/` (disjoint), plus W3 `root/` recursive (overlaps both;
        // a non-recursive `root/` watch would not match `root/a/`/`root/b/`
        // descendants). A competing-consumer transport (SQS/Pub-Sub) that
        // opens one physical consumer per `watch_directory` call
        // cannibalizes here: the single delivered batch reaches exactly one
        // consumer, starving the others. Backends that share a notification
        // resource MUST self-coalesce; this scenario is the conformance gate
        // for that, and each adopted backend must DRIVE it (a skipped result
        // does not satisfy the gate).
        reg.insert(Scenario {
            name: "watch-concurrent-cross-prefix-no-split",
            vtable_slots: &["watch_directory"],
            required_profile: Profile::Minimal,
            required_capabilities: &["supports_watch_directory"],
            required_config: &[],
            allowed_hosts: &[],
            expected_calls: &[
                ExpectedCall {
                    method: "watch_directory",
                    allow_extra: false,
                },
                ExpectedCall {
                    method: "watch_directory",
                    allow_extra: false,
                },
                ExpectedCall {
                    method: "watch_directory",
                    allow_extra: false,
                },
            ],
            failure_contract: FailureContract::Success,
            report_tags: &["watch_directory", "cross-prefix", "no-split"],
        });
        // Stable scenario id: the Layer gates on its advertised
        // capabilities; the recorder proves the rejected operation never
        // crosses into its implementation.
        reg.insert(Scenario {
            name: "compat-gates-v1-capability",
            vtable_slots: &["delete"],
            required_profile: Profile::Minimal,
            required_capabilities: &[],
            required_config: &[],
            allowed_hosts: &["library"],
            expected_calls: &[],
            failure_contract: FailureContract::Errors {
                method: "delete",
                code: ErrorCode::Unsupported,
            },
            report_tags: &["capability-skip", "stable-id"],
        });
        // Protocol-slot contract: mutations commit at
        // `continue_write -> Done`, not at `write_redirect`.
        reg.insert(Scenario {
            name: "write-redirect-commits-on-done",
            vtable_slots: &["write_redirect", "continue_write"],
            required_profile: Profile::Redirects,
            required_capabilities: &["supports_write_redirect"],
            required_config: &["test_redirect_url"],
            allowed_hosts: &[],
            expected_calls: &[
                ExpectedCall {
                    method: "write_redirect",
                    allow_extra: false,
                },
                ExpectedCall {
                    method: "continue_write",
                    allow_extra: true,
                },
            ],
            failure_contract: FailureContract::Success,
            report_tags: &["write", "protocol-slot"],
        });
        // Protocol-slot contract: nothing is observable at the address while
        // a write is mid-flight. A `continue_write` that returns `Redirects`
        // has more transfers to run, and the object must not be visible until
        // the step that returns `Done`. Hosts rely on this: a caching host
        // leaves its index untouched on a redirect step precisely because the
        // address is unchanged, so anything a host derived from it is still
        // valid; a plugin that published partial content there would silently
        // invalidate those derivations. The in-tree byte cache is additionally
        // robust to a violation -- it invalidates before `continue_write` runs
        // -- but that is defence in depth, not permission.
        //
        // SCOPE: like every entry here, this pins the call sequence. The
        // registry verifies recorded calls; it cannot stat an address between
        // two of them, so the visibility assertion itself lives in the driver
        // (`ovstorage/tests/conformance_protocol_slots.rs`), which stats
        // mid-flight and requires NotFound. A provider wired only against this
        // entry gets the sequence checked and the invariant not.
        reg.insert(Scenario {
            name: "write-redirect-nothing-observable-mid-flight",
            vtable_slots: &["write_redirect", "continue_write"],
            required_profile: Profile::Redirects,
            required_capabilities: &["supports_write_redirect"],
            required_config: &["test_redirect_url"],
            allowed_hosts: &[],
            expected_calls: &[
                ExpectedCall {
                    method: "write_redirect",
                    allow_extra: false,
                },
                ExpectedCall {
                    method: "continue_write",
                    allow_extra: true,
                },
            ],
            failure_contract: FailureContract::Success,
            report_tags: &["write", "protocol-slot"],
        });
        // Protocol-slot contract: a retry wrapper must never replay
        // `continue_write` — the failure surfaces and the slot is invoked
        // exactly once.
        reg.insert(Scenario {
            name: "retry-never-replays-continue-write",
            vtable_slots: &["write_redirect", "continue_write"],
            required_profile: Profile::Redirects,
            required_capabilities: &["supports_write_redirect"],
            required_config: &["test_redirect_url"],
            allowed_hosts: &[],
            expected_calls: &[
                ExpectedCall {
                    method: "write_redirect",
                    allow_extra: false,
                },
                ExpectedCall {
                    method: "continue_write",
                    allow_extra: false,
                },
            ],
            failure_contract: FailureContract::Errors {
                method: "continue_write",
                code: ErrorCode::Transient,
            },
            report_tags: &["retry", "protocol-slot"],
        });
        // Protocol-slot contract: wrappers that don't understand the
        // write-plan protocol forward `write_redirect` untouched (rests on
        // the mechanically safe `inner_layer()` delegation).
        reg.insert(Scenario {
            name: "protocol-slots-pass-through",
            vtable_slots: &["write_redirect"],
            required_profile: Profile::Redirects,
            required_capabilities: &["supports_write_redirect"],
            required_config: &["test_redirect_url"],
            allowed_hosts: &[],
            expected_calls: &[ExpectedCall {
                method: "write_redirect",
                allow_extra: false,
            }],
            failure_contract: FailureContract::Success,
            report_tags: &["wrapper", "protocol-slot"],
        });
        reg
    }

    /// Register `scenario`.
    ///
    /// Panics on a duplicate name. The registry is a map, so a second insert
    /// under an existing name silently replaces it — a copy-pasted block with
    /// an unedited name is dead weight, and one with a *wrongly* edited name
    /// quietly removes the scenario it collides with. `with_defaults` runs in
    /// every conformance test, so this surfaces at first use.
    pub fn insert(&mut self, scenario: Scenario) {
        assert!(
            !self.by_name.contains_key(scenario.name),
            "conformance scenario `{}` is registered twice",
            scenario.name
        );
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
            vtable_slots: &["write", "read", "stat"],
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
