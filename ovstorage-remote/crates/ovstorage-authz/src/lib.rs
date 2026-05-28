// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![doc = include_str!("../README.md")]

use std::collections::HashMap;
use std::time::{Duration, SystemTime};

use ovstorage_plugin::{Error, ErrorCode, Result, Url};

pub mod attribution;
pub mod compose;
pub mod ffi;
pub mod loaded;
pub mod policy;
pub mod shim;
pub mod thunks;

pub use attribution::{
    ATTRIBUTION_KEY_MODIFIED_BY, AttributionLayer, AttributionStrategy, RESERVED_METADATA_PREFIX,
};
pub use loaded::LoadedAuthzPlugin;
pub use policy::{PolicyEpochState, PolicyFreshness};

/// Manifest name of the first-party TOML authz plugin.
pub const AUTHZ_PLUGIN_KIND_TOML: &str = "ovstorage-authz-toml";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Principal {
    pub id: String,
    pub display_name: Option<String>,
    pub attributes: HashMap<String, String>,
    pub valid_until: Option<SystemTime>,
    pub source: String,
}

impl Principal {
    pub fn anonymous() -> Self {
        Self {
            id: "anonymous".into(),
            display_name: None,
            attributes: HashMap::new(),
            valid_until: None,
            source: "anonymous".into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestContext {
    pub principal: Principal,
    pub policy_epoch: u64,
    pub audit_id: Option<String>,
}

impl Default for RequestContext {
    fn default() -> Self {
        Self {
            principal: Principal::anonymous(),
            policy_epoch: 0,
            audit_id: None,
        }
    }
}

/// Authorizable operations. Copy/Rename decompose into Read+Write(+Delete);
/// AddAlias keeps its own op AND Read-checks the `to` address.
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthzRequest {
    pub principal: Principal,
    pub operation: Operation,
    pub address: Option<Url>,
    pub policy_epoch: u64,
    pub audit_id: Option<String>,
}

impl AuthzRequest {
    pub fn from_context(
        context: &RequestContext,
        operation: Operation,
        address: Option<&Url>,
    ) -> Self {
        Self {
            principal: context.principal.clone(),
            operation,
            address: address.cloned(),
            policy_epoch: context.policy_epoch,
            audit_id: context.audit_id.clone(),
        }
    }

    pub fn for_address(&self, operation: Operation, address: Url) -> Self {
        Self {
            principal: self.principal.clone(),
            operation,
            address: Some(address),
            policy_epoch: self.policy_epoch,
            audit_id: self.audit_id.clone(),
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthzEffect {
    Allow,
    Deny,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthzDecision {
    pub effect: AuthzEffect,
    pub reason: Option<String>,
    pub explanation: Option<String>,
    pub decision_ttl: Option<Duration>,
}

impl AuthzDecision {
    pub fn allow() -> Self {
        Self {
            effect: AuthzEffect::Allow,
            reason: None,
            explanation: None,
            decision_ttl: None,
        }
    }

    pub fn allow_with_explanation(explanation: impl Into<String>) -> Self {
        Self {
            explanation: Some(explanation.into()),
            ..Self::allow()
        }
    }

    pub fn deny(reason: impl Into<String>) -> Self {
        Self {
            effect: AuthzEffect::Deny,
            reason: Some(reason.into()),
            explanation: None,
            decision_ttl: None,
        }
    }

    pub fn deny_with_explanation(
        reason: impl Into<String>,
        explanation: impl Into<String>,
    ) -> Self {
        Self {
            effect: AuthzEffect::Deny,
            reason: Some(reason.into()),
            explanation: Some(explanation.into()),
            decision_ttl: None,
        }
    }

    pub fn is_allow(&self) -> bool {
        self.effect == AuthzEffect::Allow
    }

    pub fn into_result(self, request: &AuthzRequest) -> Result<()> {
        if self.is_allow() {
            return Ok(());
        }
        let address = request
            .address
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_else(|| "<none>".into());
        let reason = self.reason.unwrap_or_else(|| {
            format!(
                "broker principal '{}' is not authorized for {} on {}",
                request.principal.id,
                operation_name(request.operation),
                address
            )
        });
        Err(Error::new(ErrorCode::PermissionDenied, reason))
    }
}

/// Authz plugin trait. Default `filter_list_batch` loops `authorize` per
/// address; override for batch-aware policy backends.
#[async_trait::async_trait]
pub trait AuthzPlugin: Send + Sync {
    fn plugin_name(&self) -> &str;

    async fn authorize(&self, request: &AuthzRequest) -> Result<AuthzDecision>;

    async fn filter_list_batch(
        &self,
        request: &AuthzRequest,
        addresses: &[Url],
    ) -> Result<Vec<AuthzDecision>> {
        let mut decisions = Vec::with_capacity(addresses.len());
        for address in addresses {
            let item_request = request.for_address(request.operation, address.clone());
            decisions.push(self.authorize(&item_request).await?);
        }
        Ok(decisions)
    }
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

    #[tokio::test]
    async fn filter_list_batch_default_uses_request_operation() {
        use std::sync::Mutex;

        use ovstorage_plugin::address;

        struct RecordingPlugin {
            observed: Mutex<Vec<(Operation, Url)>>,
        }

        #[async_trait::async_trait]
        impl AuthzPlugin for RecordingPlugin {
            fn plugin_name(&self) -> &str {
                "recording"
            }
            async fn authorize(&self, request: &AuthzRequest) -> Result<AuthzDecision> {
                let address = request.address.clone().expect("address required");
                self.observed
                    .lock()
                    .unwrap()
                    .push((request.operation, address));
                Ok(AuthzDecision::allow())
            }
        }

        let plugin = RecordingPlugin {
            observed: Mutex::new(Vec::new()),
        };
        let request = AuthzRequest {
            principal: Principal::anonymous(),
            operation: Operation::List,
            address: None,
            policy_epoch: 0,
            audit_id: None,
        };
        let addresses = vec![
            address::parse("file:///a").unwrap(),
            address::parse("file:///b").unwrap(),
        ];

        let _ = plugin
            .filter_list_batch(&request, &addresses)
            .await
            .unwrap();

        let observed = plugin.observed.lock().unwrap();
        assert_eq!(observed.len(), 2);
        assert_eq!(
            observed[0].0,
            Operation::List,
            "expected List, got {:?}",
            observed[0].0
        );
        assert_eq!(
            observed[1].0,
            Operation::List,
            "expected List, got {:?}",
            observed[1].0
        );
    }

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
