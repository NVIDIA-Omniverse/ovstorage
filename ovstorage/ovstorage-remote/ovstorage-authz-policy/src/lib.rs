// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Pure authorization policy engine for ovstorage.
//!
//! This crate carries no plugin ABI, no dynamic loading, and no dependency on
//! core `ovstorage` — only the low-level
//! `ovstorage-plugin` value types (`Url`, `Error`, `AccessDecision`, …). It is
//! consumed by the built-in auth Layer (`ovstorage-authz-layer`), which gates a
//! Layer stack on these decisions.
//!
//! What lives here:
//!
//! - [`Operation`] and its name round-trip ([`operation_name`],
//!   [`operation_from_name`]). The operation *decompositions* (Copy/Rename →
//!   Read+Write(+Delete), AddAlias → its own op plus a Read-check of the target)
//!   are applied by the caller, not encoded here — an [`Operation`] is a single
//!   authorizable verb.
//! - [`Policy`] and its per-rule matching (principal-id glob + operation +
//!   address prefix) and [`Decision`] outcome, parsed from the same TOML rule
//!   set accepted by [`TomlPolicyConfig`].
//! - The decision helpers [`filter_list_batch`], [`is_root_visible`]
//!   (the lifted `filter_address_roots` predicate), and
//!   [`apply_authz_access_decision`].

mod decision;
mod rules;

pub use decision::{apply_authz_access_decision, filter_list_batch, is_root_visible};
pub use rules::{
    Decision, Effect, Policy, TomlPolicyConfig, TomlPolicyEffect, TomlPolicyRule,
    default_plugin_name,
};

/// Manifest name of the first-party TOML authz policy. Retained as the default
/// `plugin` field value so an existing rule set parses unchanged.
pub const AUTHZ_POLICY_KIND_TOML: &str = "ovstorage-authz-toml";

/// Authorizable operations. Copy/Rename decompose into Read+Write(+Delete);
/// AddAlias keeps its own op AND Read-checks the `to` address. The
/// decomposition is the caller's responsibility (see the auth Layer's verb
/// bodies); each variant here is a single authorizable verb.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Operation {
    Stat,
    Read,
    Write,
    Delete,
    List,
    ListVersions,
    WatchDirectory,
    CreateDirectory,
    DeleteDirectory,
    UpdateMetadata,
    CheckAccess,
    ListAddressRoots,
    ListBackendKinds,
    AddConnection,
    RemoveConnection,
    UpdateConnectionCredentials,
    ListConnections,
    AddAlias,
    RemoveAlias,
    ListAliases,
    SetAddressVisibility,
}

pub fn operation_name(operation: Operation) -> &'static str {
    match operation {
        Operation::Stat => "stat",
        Operation::Read => "read",
        Operation::Write => "write",
        Operation::Delete => "delete",
        Operation::List => "list",
        Operation::ListVersions => "list_versions",
        Operation::WatchDirectory => "watch_directory",
        Operation::CreateDirectory => "create_directory",
        Operation::DeleteDirectory => "delete_directory",
        Operation::UpdateMetadata => "update_metadata",
        Operation::CheckAccess => "check_access",
        Operation::ListAddressRoots => "list_address_roots",
        Operation::ListBackendKinds => "list_backend_kinds",
        Operation::AddConnection => "add_connection",
        Operation::RemoveConnection => "remove_connection",
        Operation::UpdateConnectionCredentials => "update_connection_credentials",
        Operation::ListConnections => "list_connections",
        Operation::AddAlias => "add_alias",
        Operation::RemoveAlias => "remove_alias",
        Operation::ListAliases => "list_aliases",
        Operation::SetAddressVisibility => "set_address_visibility",
    }
}

pub fn operation_from_name(name: &str) -> Option<Operation> {
    match name {
        "stat" => Some(Operation::Stat),
        "read" => Some(Operation::Read),
        "write" => Some(Operation::Write),
        "delete" => Some(Operation::Delete),
        "list" => Some(Operation::List),
        "list_versions" => Some(Operation::ListVersions),
        "watch_directory" => Some(Operation::WatchDirectory),
        "create_directory" => Some(Operation::CreateDirectory),
        "delete_directory" => Some(Operation::DeleteDirectory),
        "update_metadata" => Some(Operation::UpdateMetadata),
        "check_access" => Some(Operation::CheckAccess),
        "list_address_roots" => Some(Operation::ListAddressRoots),
        "list_backend_kinds" => Some(Operation::ListBackendKinds),
        "add_connection" => Some(Operation::AddConnection),
        "remove_connection" => Some(Operation::RemoveConnection),
        "update_connection_credentials" => Some(Operation::UpdateConnectionCredentials),
        "list_connections" => Some(Operation::ListConnections),
        "add_alias" => Some(Operation::AddAlias),
        "remove_alias" => Some(Operation::RemoveAlias),
        "list_aliases" => Some(Operation::ListAliases),
        "set_address_visibility" => Some(Operation::SetAddressVisibility),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operation_names_round_trip() {
        let operations = [
            Operation::Stat,
            Operation::Read,
            Operation::Write,
            Operation::Delete,
            Operation::List,
            Operation::ListVersions,
            Operation::WatchDirectory,
            Operation::CreateDirectory,
            Operation::DeleteDirectory,
            Operation::UpdateMetadata,
            Operation::CheckAccess,
            Operation::ListAddressRoots,
            Operation::ListBackendKinds,
            Operation::AddConnection,
            Operation::RemoveConnection,
            Operation::UpdateConnectionCredentials,
            Operation::ListConnections,
            Operation::AddAlias,
            Operation::RemoveAlias,
            Operation::ListAliases,
            Operation::SetAddressVisibility,
        ];
        for operation in operations {
            assert_eq!(
                operation_from_name(operation_name(operation)),
                Some(operation)
            );
        }
    }
}
