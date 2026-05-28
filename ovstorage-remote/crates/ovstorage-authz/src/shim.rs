// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Rust ↔ FFI marshaling for the authz plugin SPI. `*_to_ffi` consumes
//! Rust input and produces a heap-owning FFI struct; `*_from_ffi` does
//! the inverse, taking ownership of FFI heap allocations.

use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ovstorage_plugin::ffi as plugin_ffi;
use ovstorage_plugin::shim::primitive;
use ovstorage_plugin::{Error, Result};

use crate::ffi as authz_ffi;
use crate::{
    AuthzDecision, AuthzEffect, AuthzRequest, Principal, operation_from_name, operation_name,
};

pub fn principal_to_ffi(value: Principal) -> authz_ffi::PrincipalV1 {
    authz_ffi::PrincipalV1 {
        struct_size: std::mem::size_of::<authz_ffi::PrincipalV1>(),
        id: primitive::str_to_ffi(value.id),
        display_name: primitive::optional_to_ffi(value.display_name, primitive::str_to_ffi),
        attributes: primitive::key_value_list_to_ffi(value.attributes),
        valid_until_unix_ms: primitive::optional_to_ffi(value.valid_until, |t| {
            t.duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis() as i64)
                .unwrap_or(0)
        }),
        source: primitive::str_to_ffi(value.source),
    }
}

/// # Safety
///
/// `value` must be a valid `PrincipalV1` produced by `principal_to_ffi`.
pub unsafe fn principal_from_ffi(value: authz_ffi::PrincipalV1) -> Result<Principal> {
    unsafe {
        let id = primitive::str_from_ffi(value.id)?;
        let display_name =
            primitive::optional_from_ffi(value.display_name, |s| primitive::str_from_ffi(s))?;
        let attributes = primitive::key_value_list_from_ffi(value.attributes)?;
        let valid_until = primitive::optional_from_ffi::<i64, SystemTime, Error>(
            value.valid_until_unix_ms,
            |ms| {
                Ok(if ms >= 0 {
                    UNIX_EPOCH + Duration::from_millis(ms as u64)
                } else {
                    UNIX_EPOCH
                })
            },
        )?;
        let source = primitive::str_from_ffi(value.source)?;
        Ok(Principal {
            id,
            display_name,
            attributes,
            valid_until,
            source,
        })
    }
}

pub fn authz_request_to_ffi(value: AuthzRequest) -> authz_ffi::AuthzRequestV1 {
    authz_ffi::AuthzRequestV1 {
        struct_size: std::mem::size_of::<authz_ffi::AuthzRequestV1>(),
        principal: principal_to_ffi(value.principal),
        operation: primitive::str_to_ffi(operation_name(value.operation).to_string()),
        address: primitive::optional_to_ffi(
            value.address.map(|u| u.to_string()),
            primitive::str_to_ffi,
        ),
        policy_epoch: value.policy_epoch,
        audit_id: primitive::optional_to_ffi(value.audit_id, primitive::str_to_ffi),
    }
}

/// # Safety
///
/// `value` must be a valid `AuthzRequestV1` produced by
/// `authz_request_to_ffi`.
pub unsafe fn authz_request_from_ffi(value: authz_ffi::AuthzRequestV1) -> Result<AuthzRequest> {
    unsafe {
        let principal = principal_from_ffi(value.principal)?;
        let operation_name_str = primitive::str_from_ffi(value.operation)?;
        let operation = operation_from_name(&operation_name_str).ok_or_else(|| {
            Error::new(
                ovstorage_plugin::ErrorCode::InvalidArgument,
                format!("unknown authz operation: '{operation_name_str}'"),
            )
        })?;
        let address = primitive::optional_from_ffi::<plugin_ffi::Str, ovstorage_plugin::Url, Error>(
            value.address,
            |s| {
                let raw = primitive::str_from_ffi(s)?;
                ovstorage_plugin::address::parse(&raw)
            },
        )?;
        let audit_id =
            primitive::optional_from_ffi(value.audit_id, |s| primitive::str_from_ffi(s))?;
        Ok(AuthzRequest {
            principal,
            operation,
            address,
            policy_epoch: value.policy_epoch,
            audit_id,
        })
    }
}

pub fn authz_decision_to_ffi(value: AuthzDecision) -> authz_ffi::AuthzDecisionV1 {
    authz_ffi::AuthzDecisionV1 {
        struct_size: std::mem::size_of::<authz_ffi::AuthzDecisionV1>(),
        effect: match value.effect {
            AuthzEffect::Allow => authz_ffi::AuthzEffectFFI::Allow,
            AuthzEffect::Deny => authz_ffi::AuthzEffectFFI::Deny,
        },
        reason: primitive::optional_to_ffi(value.reason, primitive::str_to_ffi),
        explanation: primitive::optional_to_ffi(value.explanation, primitive::str_to_ffi),
        decision_ttl_ms: primitive::optional_to_ffi(value.decision_ttl, |d| d.as_millis() as u64),
    }
}

/// # Safety
///
/// `value` must be a valid `AuthzDecisionV1`.
pub unsafe fn authz_decision_from_ffi(value: authz_ffi::AuthzDecisionV1) -> Result<AuthzDecision> {
    unsafe {
        let effect = match value.effect {
            authz_ffi::AuthzEffectFFI::Allow => AuthzEffect::Allow,
            authz_ffi::AuthzEffectFFI::Deny => AuthzEffect::Deny,
        };
        let reason = primitive::optional_from_ffi(value.reason, |s| primitive::str_from_ffi(s))?;
        let explanation =
            primitive::optional_from_ffi(value.explanation, |s| primitive::str_from_ffi(s))?;
        let decision_ttl =
            primitive::optional_from_ffi::<u64, Duration, Error>(value.decision_ttl_ms, |ms| {
                Ok(Duration::from_millis(ms))
            })?;
        Ok(AuthzDecision {
            effect,
            reason,
            explanation,
            decision_ttl,
        })
    }
}

pub fn config_to_ffi(
    config: HashMap<String, ovstorage_plugin::ConfigValue>,
) -> plugin_ffi::List<plugin_ffi::ConnectionConfigEntry> {
    let entries: Vec<(String, ovstorage_plugin::ConfigValue)> = config.into_iter().collect();
    primitive::list_to_ffi(entries, |(k, v)| plugin_ffi::ConnectionConfigEntry {
        key: primitive::str_to_ffi(k),
        value: ovstorage_plugin::shim::descriptor::config_value_to_ffi(v),
    })
}

/// # Safety
///
/// `value` must be a valid `List<ConnectionConfigEntry>`.
pub unsafe fn config_from_ffi(
    value: plugin_ffi::List<plugin_ffi::ConnectionConfigEntry>,
) -> Result<HashMap<String, ovstorage_plugin::ConfigValue>> {
    unsafe {
        let entries = primitive::list_from_ffi(value, |entry| {
            let key = primitive::str_from_ffi(entry.key)?;
            let val = ovstorage_plugin::shim::descriptor::config_value_from_ffi(entry.value)?;
            Ok::<_, Error>((key, val))
        })?;
        Ok(entries.into_iter().collect())
    }
}
