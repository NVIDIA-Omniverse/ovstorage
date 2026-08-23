// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Synchronous decision helpers over the pure [`Policy`] engine.

use ovstorage_plugin::{AccessDecision, AccessOps, Url};

use crate::{Operation, Policy};

/// Per-item allow flags for a `list` post-filter, evaluated with `operation`
/// against each address. The broker calls this with
/// [`Operation::Stat`] (list entries are metadata; a `Read`-filtered page would
/// hide items a stat-but-not-read principal can stat directly).
pub fn filter_list_batch(
    policy: &Policy,
    principal_id: &str,
    operation: Operation,
    addresses: &[Url],
) -> Vec<bool> {
    addresses
        .iter()
        .map(|address| policy.is_allowed(principal_id, operation, Some(address)))
        .collect()
}

/// Whether `principal_id` may see the address root at `address`: the lifted
/// `compose::filter_address_roots` predicate — `Read` OR `List` on the root's
/// address. The auth Layer applies this per `RootInfo` in `list_address_roots`
/// so it never leaks a route the policy hides.
pub fn is_root_visible(policy: &Policy, principal_id: &str, address: &Url) -> bool {
    policy.is_allowed(principal_id, Operation::Read, Some(address))
        || policy.is_allowed(principal_id, Operation::List, Some(address))
}

/// Intersect a backend [`AccessDecision`] with per-operation authz for
/// `address`. For each `operations` flag the caller set, deny the matching slot
/// in `decision.denied_ops` when the policy denies. When any op is authz-denied,
/// force `allowed = false` and write `deny_reason` into `decision.reason`
/// (unless the backend already set a reason — preserved so backend-specific
/// signal is not lost). Lifted verbatim from
/// `compose::apply_authz_access_decision`.
pub fn apply_authz_access_decision(
    policy: &Policy,
    principal_id: &str,
    address: &Url,
    operations: &AccessOps,
    decision: &mut AccessDecision,
    deny_reason: &str,
) {
    let mut authz_denied = false;
    if operations.read && !policy.is_allowed(principal_id, Operation::Read, Some(address)) {
        decision.denied_ops.read = true;
        authz_denied = true;
    }
    if operations.write && !policy.is_allowed(principal_id, Operation::Write, Some(address)) {
        decision.denied_ops.write = true;
        authz_denied = true;
    }
    if operations.delete && !policy.is_allowed(principal_id, Operation::Delete, Some(address)) {
        decision.denied_ops.delete = true;
        authz_denied = true;
    }
    if operations.update_metadata
        && !policy.is_allowed(principal_id, Operation::UpdateMetadata, Some(address))
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
}
