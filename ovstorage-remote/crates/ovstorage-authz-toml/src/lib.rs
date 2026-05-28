// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![doc = include_str!("../README.md")]

use std::time::Duration;

use ovstorage_authz::{
    AUTHZ_PLUGIN_KIND_TOML, AuthzDecision, AuthzEffect, AuthzPlugin, AuthzRequest, Operation,
    operation_from_name,
};
use ovstorage_plugin::{Error, ErrorCode, Result, Url, address};
use serde::Deserialize;

mod ffi_export;

pub const PLUGIN_NAME: &str = AUTHZ_PLUGIN_KIND_TOML;

#[derive(Clone, Debug, Deserialize)]
pub struct TomlAuthzConfig {
    #[serde(default = "default_plugin_name")]
    pub plugin: String,
    #[serde(default)]
    pub decision_ttl_max_seconds: Option<u64>,
    #[serde(default)]
    pub policy: Vec<TomlAuthzPolicy>,
}

impl Default for TomlAuthzConfig {
    fn default() -> Self {
        Self {
            plugin: default_plugin_name(),
            decision_ttl_max_seconds: None,
            policy: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct TomlAuthzPolicy {
    #[serde(default)]
    pub id: Option<String>,
    pub effect: TomlAuthzEffect,
    pub principal: String,
    pub operations: Vec<String>,
    pub prefix: String,
}

#[derive(Copy, Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TomlAuthzEffect {
    Allow,
    Deny,
}

#[derive(Clone, Debug)]
pub struct TomlAuthzPlugin {
    rules: Vec<Rule>,
    decision_ttl: Option<Duration>,
}

#[derive(Clone, Debug)]
struct Rule {
    id: String,
    effect: AuthzEffect,
    principal: String,
    operations: Option<Vec<Operation>>,
    prefix: Option<Url>,
    order: usize,
}

impl TomlAuthzPlugin {
    /// Parses a TOML config string into a plugin in one step.
    pub fn from_toml(toml_str: &str) -> Result<Self> {
        let config: TomlAuthzConfig = toml::from_str(toml_str).map_err(|err| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!("invalid authz-toml config: {err}"),
            )
        })?;
        Self::from_config(config)
    }

    pub fn from_config(config: TomlAuthzConfig) -> Result<Self> {
        if config.plugin != PLUGIN_NAME {
            return Err(Error::new(
                ErrorCode::Unsupported,
                format!(
                    "unsupported authz plugin '{}'; expected '{}'",
                    config.plugin, PLUGIN_NAME
                ),
            ));
        }
        let mut rules = Vec::with_capacity(config.policy.len());
        for (index, policy) in config.policy.into_iter().enumerate() {
            let id = policy.id.unwrap_or_else(|| format!("rule-{}", index + 1));
            if id.trim().is_empty() {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    "authz policy rule id must not be empty",
                ));
            }
            if policy.principal.is_empty() {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    format!("authz policy rule '{id}' principal must not be empty"),
                ));
            }
            if policy.operations.is_empty() {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    format!("authz policy rule '{id}' operations must not be empty"),
                ));
            }
            let operations = parse_operations(&id, policy.operations)?;
            let prefix = parse_prefix(&id, &policy.prefix)?;
            rules.push(Rule {
                id,
                effect: match policy.effect {
                    TomlAuthzEffect::Allow => AuthzEffect::Allow,
                    TomlAuthzEffect::Deny => AuthzEffect::Deny,
                },
                principal: policy.principal,
                operations,
                prefix,
                order: index,
            });
        }
        Ok(Self {
            rules,
            decision_ttl: config.decision_ttl_max_seconds.map(Duration::from_secs),
        })
    }

    fn matching_rule<'a>(&'a self, request: &AuthzRequest) -> Option<&'a Rule> {
        self.rules
            .iter()
            .filter(|rule| rule.matches(request))
            .max_by_key(|rule| (rule.prefix_len(), rule.order))
    }
}

#[async_trait::async_trait]
impl AuthzPlugin for TomlAuthzPlugin {
    fn plugin_name(&self) -> &str {
        PLUGIN_NAME
    }

    async fn authorize(&self, request: &AuthzRequest) -> Result<AuthzDecision> {
        let op_name = ovstorage_authz::operation_name(request.operation);
        let Some(rule) = self.matching_rule(request) else {
            tracing::debug!(
                target: "ovstorage.authz.toml",
                op = op_name,
                principal_id = %request.principal.id,
                policy_epoch = request.policy_epoch,
                error_code = "PermissionDenied",
                outcome = "deny",
                "authz decision: no matching rule"
            );
            return Ok(AuthzDecision {
                decision_ttl: self.decision_ttl,
                ..AuthzDecision::deny("no matching authz policy rule")
            });
        };
        let decision = match rule.effect {
            AuthzEffect::Allow => {
                tracing::debug!(
                    target: "ovstorage.authz.toml",
                    op = op_name,
                    principal_id = %request.principal.id,
                    policy_epoch = request.policy_epoch,
                    rule_id = %rule.id,
                    outcome = "allow",
                    "authz decision"
                );
                AuthzDecision::allow_with_explanation(rule.id.clone())
            }
            AuthzEffect::Deny => {
                tracing::debug!(
                    target: "ovstorage.authz.toml",
                    op = op_name,
                    principal_id = %request.principal.id,
                    policy_epoch = request.policy_epoch,
                    rule_id = %rule.id,
                    error_code = "PermissionDenied",
                    outcome = "deny",
                    "authz decision"
                );
                AuthzDecision::deny_with_explanation(
                    format!("authorization denied by policy '{}'", rule.id),
                    rule.id.clone(),
                )
            }
            // Defensive: future AuthzEffect variants conservatively
            // deny until this match is updated. AuthzEffect is
            // `#[non_exhaustive]`.
            _ => {
                tracing::debug!(
                    target: "ovstorage.authz.toml",
                    op = op_name,
                    principal_id = %request.principal.id,
                    policy_epoch = request.policy_epoch,
                    rule_id = %rule.id,
                    error_code = "PermissionDenied",
                    outcome = "deny",
                    "authz decision: unknown effect"
                );
                AuthzDecision::deny_with_explanation(
                    format!("unknown authz effect for rule '{}'", rule.id),
                    rule.id.clone(),
                )
            }
        };
        Ok(AuthzDecision {
            decision_ttl: self.decision_ttl,
            ..decision
        })
    }
}

impl Rule {
    fn matches(&self, request: &AuthzRequest) -> bool {
        if !glob_match(&self.principal, &request.principal.id) {
            return false;
        }
        if let Some(operations) = &self.operations
            && !operations.contains(&request.operation)
        {
            return false;
        }
        match (&self.prefix, &request.address) {
            (None, _) => true,
            (Some(prefix), Some(address)) => address::is_prefix_of(prefix, address),
            (Some(_), None) => false,
        }
    }

    fn prefix_len(&self) -> usize {
        self.prefix
            .as_ref()
            .map(|prefix| prefix.as_str().len())
            .unwrap_or(0)
    }
}

fn parse_operations(id: &str, operations: Vec<String>) -> Result<Option<Vec<Operation>>> {
    if operations.iter().any(|operation| operation == "*") {
        if operations.len() != 1 {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!("authz policy rule '{id}' must use '*' as its only operation"),
            ));
        }
        return Ok(None);
    }
    let mut parsed = Vec::with_capacity(operations.len());
    for operation in operations {
        let Some(parsed_operation) = operation_from_name(&operation) else {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!("authz policy rule '{id}' uses unknown operation '{operation}'"),
            ));
        };
        parsed.push(parsed_operation);
    }
    Ok(Some(parsed))
}

fn parse_prefix(id: &str, prefix: &str) -> Result<Option<Url>> {
    if prefix == "*" {
        return Ok(None);
    }
    if prefix.is_empty() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("authz policy rule '{id}' prefix must not be empty"),
        ));
    }
    address::parse(prefix).map(Some).map_err(|error| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "authz policy rule '{id}' has invalid prefix '{prefix}': {}",
                error.message()
            ),
        )
    })
}

fn glob_match(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == value;
    }

    let mut remainder = value;
    if let Some(first) = parts.first()
        && !first.is_empty()
    {
        let Some(next) = remainder.strip_prefix(first) else {
            return false;
        };
        remainder = next;
    }

    for part in parts.iter().skip(1).take(parts.len().saturating_sub(2)) {
        if part.is_empty() {
            continue;
        }
        let Some(index) = remainder.find(part) else {
            return false;
        };
        remainder = &remainder[index + part.len()..];
    }

    if let Some(last) = parts.last()
        && !last.is_empty()
        && !remainder.ends_with(last)
    {
        return false;
    }
    true
}

fn default_plugin_name() -> String {
    PLUGIN_NAME.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ovstorage_authz::operation_name;
    use ovstorage_authz::{Principal, RequestContext};

    fn request(principal: &str, operation: Operation, address: &str) -> AuthzRequest {
        AuthzRequest::from_context(
            &RequestContext {
                principal: Principal {
                    id: principal.into(),
                    display_name: None,
                    attributes: Default::default(),
                    valid_until: None,
                    source: "test".into(),
                },
                policy_epoch: 7,
                audit_id: Some("audit-1".into()),
            },
            operation,
            Some(&address::parse(address).unwrap()),
        )
    }

    fn plugin(contents: &str) -> Result<TomlAuthzPlugin> {
        let config: TomlAuthzConfig = toml::from_str(contents).unwrap();
        TomlAuthzPlugin::from_config(config)
    }

    #[tokio::test]
    async fn empty_policy_denies() {
        let plugin = TomlAuthzPlugin::from_config(TomlAuthzConfig::default()).unwrap();
        let decision = plugin
            .authorize(&request("alice", Operation::Read, "file:/root/a.txt"))
            .await
            .unwrap();
        assert_eq!(decision.effect, AuthzEffect::Deny);
    }

    #[tokio::test]
    async fn allow_and_deny_matching() {
        let plugin = plugin(
            r#"
            [[policy]]
            id = "allow-team"
            effect = "allow"
            principal = "team-*"
            operations = ["read"]
            prefix = "file:/root/"

            [[policy]]
            id = "deny-secret"
            effect = "deny"
            principal = "team-*"
            operations = ["read"]
            prefix = "file:/root/secret/"
            "#,
        )
        .unwrap();

        assert!(
            plugin
                .authorize(&request("team-alice", Operation::Read, "file:/root/a.txt"))
                .await
                .unwrap()
                .is_allow()
        );
        let denied = plugin
            .authorize(&request(
                "team-alice",
                Operation::Read,
                "file:/root/secret/a.txt",
            ))
            .await
            .unwrap();
        assert_eq!(denied.effect, AuthzEffect::Deny);
        assert_eq!(denied.explanation.as_deref(), Some("deny-secret"));
    }

    #[tokio::test]
    async fn wildcard_principal_and_operation_match() {
        let plugin = plugin(
            r#"
            [[policy]]
            effect = "allow"
            principal = "*"
            operations = ["*"]
            prefix = "*"
            "#,
        )
        .unwrap();

        assert!(
            plugin
                .authorize(&request("anyone", Operation::Delete, "s3://bucket/key",))
                .await
                .unwrap()
                .is_allow()
        );
    }

    #[tokio::test]
    async fn longest_prefix_precedence_wins() {
        let plugin = plugin(
            r#"
            [[policy]]
            id = "allow-root"
            effect = "allow"
            principal = "alice"
            operations = ["read"]
            prefix = "file:/root/"

            [[policy]]
            id = "deny-narrow"
            effect = "deny"
            principal = "alice"
            operations = ["read"]
            prefix = "file:/root/narrow/"
            "#,
        )
        .unwrap();

        let decision = plugin
            .authorize(&request(
                "alice",
                Operation::Read,
                "file:/root/narrow/a.txt",
            ))
            .await
            .unwrap();
        assert_eq!(decision.effect, AuthzEffect::Deny);
        assert_eq!(decision.explanation.as_deref(), Some("deny-narrow"));
    }

    #[tokio::test]
    async fn later_rule_wins_for_same_prefix() {
        let plugin = plugin(
            r#"
            [[policy]]
            id = "first"
            effect = "deny"
            principal = "alice"
            operations = ["read"]
            prefix = "file:/root/"

            [[policy]]
            id = "second"
            effect = "allow"
            principal = "alice"
            operations = ["read"]
            prefix = "file:/root/"
            "#,
        )
        .unwrap();

        let decision = plugin
            .authorize(&request("alice", Operation::Read, "file:/root/a.txt"))
            .await
            .unwrap();
        assert!(decision.is_allow());
        assert_eq!(decision.explanation.as_deref(), Some("second"));
    }

    #[test]
    fn invalid_operation_fails_validation() {
        let error = plugin(
            r#"
            [[policy]]
            effect = "allow"
            principal = "*"
            operations = ["fly"]
            prefix = "*"
            "#,
        )
        .unwrap_err();
        assert_eq!(error.code(), ErrorCode::InvalidArgument);
    }

    #[test]
    fn wildcard_operation_must_stand_alone() {
        let error = plugin(
            r#"
            [[policy]]
            effect = "allow"
            principal = "*"
            operations = ["*", "read"]
            prefix = "*"
            "#,
        )
        .unwrap_err();
        assert_eq!(error.code(), ErrorCode::InvalidArgument);
    }

    #[test]
    fn invalid_prefix_fails_validation() {
        let error = plugin(
            r#"
            [[policy]]
            effect = "allow"
            principal = "*"
            operations = ["read"]
            prefix = "not-an-address"
            "#,
        )
        .unwrap_err();
        assert_eq!(error.code(), ErrorCode::InvalidArgument);
    }

    #[test]
    fn invalid_effect_fails_deserialization() {
        let error = toml::from_str::<TomlAuthzConfig>(
            r#"
            [[policy]]
            effect = "maybe"
            principal = "*"
            operations = ["read"]
            prefix = "*"
            "#,
        )
        .unwrap_err();
        assert!(error.to_string().contains("unknown variant"));
    }

    #[test]
    fn operation_names_are_accepted() {
        for operation in [
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
        ] {
            assert!(parse_operations("rule", vec![operation_name(operation).into()]).is_ok());
        }
    }

    #[test]
    fn glob_match_wildcard_only_matches_anything() {
        assert!(glob_match("*", ""));
        assert!(glob_match("*", "anything"));
        assert!(glob_match("*", "team-alice"));
    }

    #[test]
    fn glob_match_leading_wildcard() {
        assert!(glob_match("*foo", "foo"));
        assert!(glob_match("*foo", "barfoo"));
        assert!(!glob_match("*foo", "fooBAR"));
    }

    #[test]
    fn glob_match_trailing_wildcard() {
        assert!(glob_match("foo*", "foo"));
        assert!(glob_match("foo*", "foobar"));
        assert!(!glob_match("foo*", "barfoo"));
    }

    #[test]
    fn glob_match_double_sided_wildcard() {
        assert!(glob_match("*foo*", "foo"));
        assert!(glob_match("*foo*", "xyfoozz"));
        assert!(!glob_match("*foo*", "fxooz"));
    }

    #[test]
    fn glob_match_multi_segment_wildcards() {
        assert!(glob_match("a*b*c", "abc"));
        assert!(glob_match("a*b*c", "axxbyyc"));
        assert!(glob_match("a*b*c", "abxc"));
        assert!(!glob_match("a*b*c", "ax"));
        assert!(!glob_match("a*b*c", "abcd"));
    }

    #[test]
    fn glob_match_empty_inner_segments() {
        assert!(glob_match("a**b", "ab"));
        assert!(glob_match("a**b", "axb"));
    }

    #[test]
    fn glob_match_literal_only_pattern() {
        assert!(glob_match("alice", "alice"));
        assert!(!glob_match("alice", "alicebob"));
        assert!(!glob_match("alice", ""));
    }

    #[tokio::test]
    async fn decision_ttl_round_trips_into_decisions() {
        let plugin = plugin(
            r#"
            decision_ttl_max_seconds = 30

            [[policy]]
            id = "allow-alice"
            effect = "allow"
            principal = "alice"
            operations = ["read"]
            prefix = "file:/root/"

            [[policy]]
            id = "deny-secret"
            effect = "deny"
            principal = "alice"
            operations = ["read"]
            prefix = "file:/root/secret/"
            "#,
        )
        .unwrap();

        let allow = plugin
            .authorize(&request("alice", Operation::Read, "file:/root/a.txt"))
            .await
            .unwrap();
        assert!(allow.is_allow());
        assert_eq!(allow.decision_ttl, Some(Duration::from_secs(30)));

        let deny = plugin
            .authorize(&request(
                "alice",
                Operation::Read,
                "file:/root/secret/x.txt",
            ))
            .await
            .unwrap();
        assert_eq!(deny.effect, AuthzEffect::Deny);
        assert_eq!(deny.decision_ttl, Some(Duration::from_secs(30)));

        let bob = plugin
            .authorize(&request("bob", Operation::Read, "file:/elsewhere"))
            .await
            .unwrap();
        assert_eq!(bob.effect, AuthzEffect::Deny);
        assert_eq!(bob.decision_ttl, Some(Duration::from_secs(30)));
    }

    #[tokio::test]
    async fn address_none_only_matches_wildcard_prefix() {
        let plugin = plugin(
            r#"
            [[policy]]
            id = "concrete"
            effect = "allow"
            principal = "alice"
            operations = ["list_address_roots"]
            prefix = "file:/root/"

            [[policy]]
            id = "wildcard"
            effect = "allow"
            principal = "ops-*"
            operations = ["list_address_roots"]
            prefix = "*"
            "#,
        )
        .unwrap();

        let no_addr = AuthzRequest::from_context(
            &ovstorage_authz::RequestContext {
                principal: ovstorage_authz::Principal {
                    id: "alice".into(),
                    display_name: None,
                    attributes: Default::default(),
                    valid_until: None,
                    source: "test".into(),
                },
                policy_epoch: 0,
                audit_id: None,
            },
            Operation::ListAddressRoots,
            None,
        );

        let alice = plugin.authorize(&no_addr).await.unwrap();
        assert_eq!(alice.effect, AuthzEffect::Deny);

        let ops_req = AuthzRequest::from_context(
            &ovstorage_authz::RequestContext {
                principal: ovstorage_authz::Principal {
                    id: "ops-bob".into(),
                    display_name: None,
                    attributes: Default::default(),
                    valid_until: None,
                    source: "test".into(),
                },
                policy_epoch: 0,
                audit_id: None,
            },
            Operation::ListAddressRoots,
            None,
        );

        let ops = plugin.authorize(&ops_req).await.unwrap();
        assert!(ops.is_allow());
        assert_eq!(ops.explanation.as_deref(), Some("wildcard"));
    }
}
