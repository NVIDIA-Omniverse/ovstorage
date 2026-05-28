// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

use ovstorage_authz::operation_name;

pub struct AllowAllAuthzPlugin;

#[async_trait::async_trait]
impl AuthzPlugin for AllowAllAuthzPlugin {
    fn plugin_name(&self) -> &str {
        "test-allow-all"
    }

    async fn authorize(&self, request: &AuthzRequest) -> ovstorage::Result<AuthzDecision> {
        tracing::debug!(
            target: "ovstorage.broker.authz",
            op = operation_name(request.operation),
            principal_id = %request.principal.id,
            policy_epoch = request.policy_epoch,
            outcome = "allow",
            "authz decision"
        );
        Ok(AuthzDecision::allow())
    }
}

pub struct DenyAllAuthzPlugin;

#[async_trait::async_trait]
impl AuthzPlugin for DenyAllAuthzPlugin {
    fn plugin_name(&self) -> &str {
        "test-deny-all"
    }

    async fn authorize(&self, request: &AuthzRequest) -> ovstorage::Result<AuthzDecision> {
        let address = request
            .address
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_else(|| "<none>".into());
        tracing::debug!(
            target: "ovstorage.broker.authz",
            op = operation_name(request.operation),
            principal_id = %request.principal.id,
            policy_epoch = request.policy_epoch,
            error_code = "PermissionDenied",
            outcome = "deny",
            "authz decision"
        );
        Ok(AuthzDecision::deny(format!(
            "broker principal '{}' is not authorized for {:?} on {}",
            request.principal.id, request.operation, address
        )))
    }
}

pub struct AllowAllAuthorizer;

#[async_trait::async_trait]
impl AuthzPlugin for AllowAllAuthorizer {
    fn plugin_name(&self) -> &str {
        "test-allow-all"
    }

    async fn authorize(&self, request: &AuthzRequest) -> ovstorage::Result<AuthzDecision> {
        tracing::debug!(
            target: "ovstorage.broker.authz",
            op = operation_name(request.operation),
            principal_id = %request.principal.id,
            policy_epoch = request.policy_epoch,
            outcome = "allow",
            "authz decision"
        );
        Ok(AuthzDecision::allow())
    }
}

pub struct DenyAllAuthorizer;

#[async_trait::async_trait]
impl AuthzPlugin for DenyAllAuthorizer {
    fn plugin_name(&self) -> &str {
        "test-deny-all"
    }

    async fn authorize(&self, request: &AuthzRequest) -> ovstorage::Result<AuthzDecision> {
        let address = request
            .address
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_else(|| "<none>".into());
        tracing::debug!(
            target: "ovstorage.broker.authz",
            op = operation_name(request.operation),
            principal_id = %request.principal.id,
            policy_epoch = request.policy_epoch,
            error_code = "PermissionDenied",
            outcome = "deny",
            "authz decision"
        );
        Ok(AuthzDecision::deny(format!(
            "broker principal '{}' is not authorized for {:?} on {}",
            request.principal.id, request.operation, address
        )))
    }
}
