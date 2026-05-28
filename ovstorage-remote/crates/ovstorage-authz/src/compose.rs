// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared authz composition helpers used by both the gRPC broker
//! daemon and the REST gateway. The pre-divergence broker had inline
//! versions of these; promoting them here keeps gRPC and REST from
//! drifting out of step on per-resource authz semantics.
//!
//! Both helpers take an [`AuthzCheck`] which pairs the per-call
//! policy-epoch gate with [`crate::AuthzPlugin::authorize`]. The
//! helpers are otherwise gateway-agnostic.

use ovstorage_plugin::{AccessDecision, AccessOps, AddressRoot, Result, Url};

use crate::{Operation, RequestContext};

/// Single-operation authz check used by [`filter_address_roots`] and
/// [`apply_authz_access_decision`]. Implementors are expected to gate
/// on the policy epoch carried in `context` before delegating to the
/// authz plugin so that requests in a closed epoch fail loudly rather
/// than silently allow.
#[async_trait::async_trait]
pub trait AuthzCheck: Send + Sync {
    async fn check(
        &self,
        context: &RequestContext,
        operation: Operation,
        address: &Url,
    ) -> Result<bool>;
}

/// Filter `roots` to those for which the caller has either `Read` or
/// `List` authz against the root's address. Mirrors the per-root gate
/// that gRPC has historically applied; the REST gateway must call this
/// so its `list_address_roots` does not leak routes the policy hides
/// from gRPC clients.
pub async fn filter_address_roots(
    check: &dyn AuthzCheck,
    context: &RequestContext,
    roots: Vec<AddressRoot>,
) -> Result<Vec<AddressRoot>> {
    let mut allowed = Vec::with_capacity(roots.len());
    for root in roots {
        let read_allowed = check.check(context, Operation::Read, &root.address).await?;
        let list_allowed = check.check(context, Operation::List, &root.address).await?;
        if read_allowed || list_allowed {
            allowed.push(root);
        }
    }
    Ok(allowed)
}

/// Intersect a backend [`AccessDecision`] with per-operation authz for
/// `address`. For each `operations` flag the caller set, deny the
/// matching slot in `decision.denied_ops` when authz says the caller
/// is not allowed. When any op is authz-denied, force `allowed = false`
/// and write `deny_reason` into `decision.reason` (unless the backend
/// already set a reason — preserved so backend-specific signal is not
/// lost).
pub async fn apply_authz_access_decision(
    check: &dyn AuthzCheck,
    context: &RequestContext,
    address: &Url,
    operations: &AccessOps,
    decision: &mut AccessDecision,
    deny_reason: &str,
) -> Result<()> {
    let mut authz_denied = false;
    if operations.read && !check.check(context, Operation::Read, address).await? {
        decision.denied_ops.read = true;
        authz_denied = true;
    }
    if operations.write && !check.check(context, Operation::Write, address).await? {
        decision.denied_ops.write = true;
        authz_denied = true;
    }
    if operations.delete && !check.check(context, Operation::Delete, address).await? {
        decision.denied_ops.delete = true;
        authz_denied = true;
    }
    if operations.update_metadata
        && !check
            .check(context, Operation::UpdateMetadata, address)
            .await?
    {
        decision.denied_ops.update_metadata = true;
        authz_denied = true;
    }
    if authz_denied {
        decision.allowed = false;
        if decision.reason.is_none() {
            decision.reason = Some(deny_reason.into());
        }
    }
    Ok(())
}
