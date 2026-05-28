// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrokerRoutePolicy {
    pub cache_max_object_bytes: Option<u64>,
    pub read_redirect_endpoint: Option<String>,
    pub write_redirect_endpoint: Option<String>,
    pub redirect_ttl: Duration,
}

impl Default for BrokerRoutePolicy {
    fn default() -> Self {
        Self {
            cache_max_object_bytes: None,
            read_redirect_endpoint: None,
            write_redirect_endpoint: None,
            redirect_ttl: Duration::from_secs(300),
        }
    }
}

impl BrokerRoutePolicy {
    pub fn should_redirect_read(&self, size: Option<u64>) -> bool {
        self.read_redirect_endpoint.is_some() && self.exceeds_cache_threshold(size)
    }

    pub fn should_redirect_write(&self, size_hint: Option<u64>) -> bool {
        self.write_redirect_endpoint.is_some() && self.exceeds_cache_threshold(size_hint)
    }

    pub(crate) fn exceeds_cache_threshold(&self, size: Option<u64>) -> bool {
        let Some(max) = self.cache_max_object_bytes else {
            return false;
        };
        size.map(|size| size > max).unwrap_or(true)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BrokerRoutePolicies {
    default: BrokerRoutePolicy,
    rules: Vec<BrokerRoutePolicyRule>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BrokerRoutePolicyRule {
    prefix: Url,
    policy: BrokerRoutePolicy,
}

impl BrokerRoutePolicies {
    pub fn single(policy: BrokerRoutePolicy) -> Self {
        Self {
            default: policy,
            rules: Vec::new(),
        }
    }

    pub fn from_config(routes: &[RouteConfig]) -> ovstorage::Result<Self> {
        let mut policies = Self::default();
        for route in routes {
            let prefix = address::parse(&route.prefix).map_err(|error| {
                Error::new(
                    ErrorCode::InvalidArgument,
                    format!(
                        "broker route policy prefix '{}' is invalid: {}",
                        route.prefix,
                        error.message()
                    ),
                )
            })?;
            if policies.rules.iter().any(|rule| rule.prefix == prefix) {
                return Err(Error::new(
                    ErrorCode::RouteConflict,
                    format!("duplicate broker route policy prefix '{prefix}'"),
                ));
            }
            let policy = BrokerRoutePolicy::from_config(route)?;
            policies
                .rules
                .push(BrokerRoutePolicyRule { prefix, policy });
        }
        policies
            .rules
            .sort_by_key(|r| std::cmp::Reverse(r.prefix.as_str().len()));
        Ok(policies)
    }

    pub fn default_policy(&self) -> &BrokerRoutePolicy {
        &self.default
    }

    pub(crate) fn policy_for(&self, address: &Url) -> &BrokerRoutePolicy {
        self.rules
            .iter()
            .find(|rule| address::is_prefix_of(&rule.prefix, address))
            .map(|rule| &rule.policy)
            .unwrap_or(&self.default)
    }
}

impl BrokerRoutePolicy {
    pub(crate) fn from_config(route: &RouteConfig) -> ovstorage::Result<Self> {
        let cache = route.cache.clone().unwrap_or_default();
        let redirect = route.redirect.clone().unwrap_or_default();
        let redirect_ttl = match redirect.ttl_seconds {
            Some(seconds) if !(30..=3600).contains(&seconds) => {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    format!(
                        "broker route policy '{}' redirect.ttl_seconds must be between 30 and 3600",
                        route.prefix
                    ),
                ));
            }
            Some(seconds) => Duration::from_secs(seconds),
            None => Duration::from_secs(300),
        };
        if let Some(endpoint) = &redirect.read_endpoint {
            validate_url(
                &format!(
                    "broker route policy '{}' redirect.read_endpoint",
                    route.prefix
                ),
                endpoint,
            )?;
        }
        if let Some(endpoint) = &redirect.write_endpoint {
            validate_url(
                &format!(
                    "broker route policy '{}' redirect.write_endpoint",
                    route.prefix
                ),
                endpoint,
            )?;
        }
        Ok(Self {
            cache_max_object_bytes: Some(cache.max_object_bytes.unwrap_or(0)),
            read_redirect_endpoint: redirect.read_endpoint.clone(),
            write_redirect_endpoint: redirect.write_endpoint,
            redirect_ttl,
        })
    }
}

// Policy-epoch state lives in `ovstorage-authz` so the REST gateway
// shares it; broker uses type aliases for identical semantics.
pub use ovstorage_authz::{
    PolicyEpochState as BrokerPolicyEpochState, PolicyFreshness as BrokerPolicyFreshness,
};
