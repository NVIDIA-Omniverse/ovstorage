// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Connection-config parsing and S3 / S3-compatible URL derivation.

use std::collections::HashMap;

use ovstorage_plugin::{
    ConfigField, ConfigFieldKind, ConfigValue, CredentialField, CredentialMethod, EnumSource,
    Error, ErrorCode, Result, Url, address,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompatibilityProfile {
    Aws,
    Minio,
    R2,
    B2,
    Custom,
}

impl CompatibilityProfile {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "aws" => Ok(Self::Aws),
            "minio" => Ok(Self::Minio),
            "r2" => Ok(Self::R2),
            "b2" => Ok(Self::B2),
            "custom" => Ok(Self::Custom),
            _ => Err(Error::new(
                ErrorCode::InvalidArgument,
                "S3 compatibility_profile must be one of aws, minio, r2, b2, or custom",
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Aws => "aws",
            Self::Minio => "minio",
            Self::R2 => "r2",
            Self::B2 => "b2",
            Self::Custom => "custom",
        }
    }

    /// True if path-style addressing is required (MinIO/Custom/B2; AWS+R2 default to virtual-hosted).
    pub fn requires_path_style(self) -> bool {
        matches!(self, Self::Minio | Self::Custom | Self::B2)
    }

    /// True when `endpoint` must be supplied (host can't be derived from bucket+region).
    pub fn requires_endpoint(self) -> bool {
        matches!(self, Self::Minio | Self::Custom)
    }

    /// SigV4 credential-scope region; R2/B2 require the literal `auto`.
    pub fn signing_region(self, configured: &str) -> &str {
        match self {
            Self::R2 | Self::B2 => "auto",
            _ => configured,
        }
    }
}

#[derive(Clone, Debug)]
pub struct S3Config {
    pub bucket: String,
    pub region: String,
    pub endpoint: Option<String>,
    pub profile_name: Option<String>,
    pub compatibility: CompatibilityProfile,
    pub force_path_style: bool,
    pub force_request_payer: bool,
    pub sqs_queue_url: Option<String>,
    pub sqs_max_messages: u32,
    pub sqs_wait_seconds: u32,
    pub sqs_visibility_timeout: u32,
    pub address_root: Url,
}

impl S3Config {
    /// True if path-style addressing applies (operator-forced or profile-required).
    pub fn use_path_style(&self) -> bool {
        self.force_path_style || self.compatibility.requires_path_style()
    }

    pub fn signing_region(&self) -> &str {
        self.compatibility.signing_region(&self.region)
    }
}

#[derive(Clone, Debug)]
pub struct ResolvedEndpoint {
    pub scheme: String,
    pub host: String,
    pub canonical_uri: String,
    /// True when `host` already names the bucket as a subdomain (test inspection).
    #[allow(dead_code)]
    pub virtual_hosted: bool,
}

/// Resolve scheme/host/canonical-URI for a (bucket, key) pair as the signer should sign it.
pub fn resolve_endpoint(config: &S3Config, key: &str) -> Result<ResolvedEndpoint> {
    if config.compatibility.requires_endpoint() && config.endpoint.is_none() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "S3 compatibility profile '{}' requires an explicit endpoint",
                config.compatibility.as_str()
            ),
        ));
    }
    let path_style = config.use_path_style();
    let (scheme, host) = derive_host(config, path_style)?;
    let canonical_uri = if path_style {
        crate::sigv4::canonical_path_path_style(&config.bucket, key)
    } else {
        crate::sigv4::canonical_path(key)
    };
    Ok(ResolvedEndpoint {
        scheme,
        host,
        canonical_uri,
        virtual_hosted: !path_style,
    })
}

fn derive_host(config: &S3Config, path_style: bool) -> Result<(String, String)> {
    if let Some(endpoint) = &config.endpoint {
        let parsed = url::Url::parse(endpoint).map_err(|err| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!("S3 endpoint '{endpoint}' is not a valid URL: {err}"),
            )
        })?;
        let scheme = parsed.scheme().to_ascii_lowercase();
        let host = host_with_port(&parsed)?;
        let host = if path_style {
            host
        } else {
            format!("{}.{}", config.bucket, host)
        };
        return Ok((scheme, host));
    }
    match config.compatibility {
        CompatibilityProfile::Aws => {
            let suffix = format!("s3.{}.amazonaws.com", config.region);
            let host = if path_style {
                suffix
            } else {
                format!("{}.{}", config.bucket, suffix)
            };
            Ok(("https".into(), host))
        }
        CompatibilityProfile::R2 => {
            let suffix = "r2.cloudflarestorage.com".to_string();
            let host = if path_style {
                suffix
            } else {
                format!("{}.{}", config.bucket, suffix)
            };
            Ok(("https".into(), host))
        }
        CompatibilityProfile::B2 => Err(Error::new(
            ErrorCode::InvalidArgument,
            "S3 compatibility profile 'b2' requires an explicit endpoint",
        )),
        CompatibilityProfile::Minio | CompatibilityProfile::Custom => Err(Error::new(
            ErrorCode::InvalidArgument,
            "S3 endpoint is required for this compatibility profile",
        )),
    }
}

fn host_with_port(url: &url::Url) -> Result<String> {
    let host = url
        .host_str()
        .ok_or_else(|| Error::new(ErrorCode::InvalidArgument, "S3 endpoint has no host"))?;
    let default_port = matches!(url.scheme(), "http" | "https") && url.port().is_none();
    if default_port {
        Ok(host.to_ascii_lowercase())
    } else if let Some(port) = url.port() {
        Ok(format!("{}:{}", host.to_ascii_lowercase(), port))
    } else {
        Ok(host.to_ascii_lowercase())
    }
}

pub fn config_schema() -> Vec<ConfigField> {
    vec![
        text_field(
            "bucket",
            "Bucket",
            true,
            None,
            Some("S3 bucket served by this connection"),
            Some("example-bucket"),
            false,
        ),
        text_field(
            "region",
            "Region",
            true,
            None,
            Some("AWS region or S3-compatible region label"),
            Some("us-west-2"),
            false,
        ),
        text_field(
            "endpoint",
            "Endpoint",
            false,
            None,
            Some("Optional S3-compatible endpoint URL"),
            Some("http://127.0.0.1:9000"),
            true,
        ),
        ConfigField {
            key: "compatibility_profile".into(),
            display_name: "Compatibility profile".into(),
            kind: ConfigFieldKind::Enum {
                source: EnumSource::Static(vec![
                    "aws".into(),
                    "minio".into(),
                    "r2".into(),
                    "b2".into(),
                    "custom".into(),
                ]),
            },
            required: false,
            default: Some(ConfigValue::String("aws".into())),
            help: Some("Provider dialect used for S3-compatible request shaping".into()),
            example: Some("minio".into()),
            group: Some("provider".into()),
            advanced: true,
        },
        text_field(
            "profile",
            "AWS profile",
            false,
            None,
            Some("Optional named profile in the AWS credential chain"),
            Some("prod"),
            true,
        ),
        bool_field("force_path_style", "Force path-style addressing", true),
        bool_field("force_request_payer", "Force requester-pays requests", true),
        watch_text_field(
            "sqs_queue_url",
            "SQS queue URL",
            None,
            Some("Queue receiving S3 EventBridge or direct bucket notifications"),
            Some("https://sqs.us-west-2.amazonaws.com/123456789012/ovstorage-watch"),
        ),
        watch_int_field(
            "sqs_max_messages",
            "SQS max messages",
            Some(10),
            Some("Maximum SQS messages to receive per long-poll request"),
            Some("10"),
        ),
        watch_int_field(
            "sqs_wait_seconds",
            "SQS wait seconds",
            Some(20),
            Some("SQS long-poll wait time in seconds"),
            Some("20"),
        ),
        watch_int_field(
            "sqs_visibility_timeout",
            "SQS visibility timeout",
            Some(30),
            Some("Visibility timeout applied to received notification messages"),
            Some("30"),
        ),
    ]
}

pub fn credential_methods() -> Vec<CredentialMethod> {
    vec![
        CredentialMethod {
            key: "static_key".into(),
            display_name: "Static access key".into(),
            fields: vec!["aws_access_key_id".into(), "aws_secret_access_key".into()],
            help: Some("A long-lived IAM user access key.".into()),
            advanced: false,
        },
        CredentialMethod {
            key: "session".into(),
            display_name: "Temporary session credentials".into(),
            fields: vec![
                "aws_access_key_id".into(),
                "aws_secret_access_key".into(),
                "aws_session_token".into(),
            ],
            help: Some("Short-lived credentials issued by STS or SSO.".into()),
            advanced: false,
        },
        CredentialMethod {
            key: "aws_credentials_file".into(),
            display_name: "AWS shared credentials file".into(),
            fields: vec!["file_path".into(), "profile".into()],
            help: Some("Read access key + secret from an INI section.".into()),
            advanced: false,
        },
    ]
}

pub fn credential_schema() -> Vec<CredentialField> {
    vec![
        CredentialField {
            key: "aws_access_key_id".into(),
            display_name: "AWS access key ID".into(),
            default: Some("${AWS_ACCESS_KEY_ID}".into()),
            help: Some("AWS access key id (defaults to $AWS_ACCESS_KEY_ID env var)".into()),
            advanced: false,
        },
        CredentialField {
            key: "aws_secret_access_key".into(),
            display_name: "AWS secret access key".into(),
            default: Some("${AWS_SECRET_ACCESS_KEY}".into()),
            help: Some("AWS secret access key (defaults to $AWS_SECRET_ACCESS_KEY env var)".into()),
            advanced: false,
        },
        CredentialField {
            key: "aws_session_token".into(),
            display_name: "AWS session token".into(),
            default: Some("${AWS_SESSION_TOKEN}".into()),
            help: Some("STS session token (defaults to $AWS_SESSION_TOKEN env var)".into()),
            advanced: false,
        },
        CredentialField {
            key: "file_path".into(),
            display_name: "AWS credentials file path".into(),
            default: Some("~/.aws/credentials".into()),
            help: Some("Path to AWS shared credentials INI file".into()),
            advanced: false,
        },
        CredentialField {
            key: "profile".into(),
            display_name: "AWS profile name".into(),
            default: Some("default".into()),
            help: Some("Section name within the AWS credentials file".into()),
            advanced: false,
        },
    ]
}

fn text_field(
    key: &str,
    display_name: &str,
    required: bool,
    default: Option<ConfigValue>,
    help: Option<&str>,
    example: Option<&str>,
    advanced: bool,
) -> ConfigField {
    ConfigField {
        key: key.into(),
        display_name: display_name.into(),
        kind: ConfigFieldKind::Text,
        required,
        default,
        help: help.map(str::to_string),
        example: example.map(str::to_string),
        group: Some("provider".into()),
        advanced,
    }
}

fn bool_field(key: &str, display_name: &str, advanced: bool) -> ConfigField {
    ConfigField {
        key: key.into(),
        display_name: display_name.into(),
        kind: ConfigFieldKind::Bool,
        required: false,
        default: Some(ConfigValue::Bool(false)),
        help: None,
        example: None,
        group: Some("provider".into()),
        advanced,
    }
}

fn watch_text_field(
    key: &str,
    display_name: &str,
    default: Option<ConfigValue>,
    help: Option<&str>,
    example: Option<&str>,
) -> ConfigField {
    ConfigField {
        key: key.into(),
        display_name: display_name.into(),
        kind: ConfigFieldKind::Text,
        required: false,
        default,
        help: help.map(str::to_string),
        example: example.map(str::to_string),
        group: Some("watch".into()),
        advanced: true,
    }
}

fn watch_int_field(
    key: &str,
    display_name: &str,
    default: Option<i64>,
    help: Option<&str>,
    example: Option<&str>,
) -> ConfigField {
    ConfigField {
        key: key.into(),
        display_name: display_name.into(),
        kind: ConfigFieldKind::Integer,
        required: false,
        default: default.map(ConfigValue::Int),
        help: help.map(str::to_string),
        example: example.map(str::to_string),
        group: Some("watch".into()),
        advanced: true,
    }
}

pub fn parse_config(config: &HashMap<String, ConfigValue>) -> Result<S3Config> {
    let bucket = canonical_bucket(config_string(config, "bucket", true)?.as_deref())?;
    let region = config_string(config, "region", true)?.ok_or_else(|| {
        Error::new(
            ErrorCode::InvalidArgument,
            "missing required S3 connection config 'region'",
        )
    })?;
    let endpoint = config_string(config, "endpoint", false)?;
    let compat_str = config_string(config, "compatibility_profile", false)?.unwrap_or_else(|| {
        if endpoint.is_some() {
            "custom".into()
        } else {
            "aws".into()
        }
    });
    let compatibility = CompatibilityProfile::parse(&compat_str)?;
    let profile_name = config_string(config, "profile", false)?;
    let force_path_style = config_bool(config, "force_path_style")?;
    let force_request_payer = config_bool(config, "force_request_payer")?;
    let sqs_queue_url = config_string(config, "sqs_queue_url", false)?;
    let sqs_max_messages = config_u32(config, "sqs_max_messages", 10, 1, 10)?;
    let sqs_wait_seconds = config_u32(config, "sqs_wait_seconds", 20, 0, 20)?;
    let sqs_visibility_timeout = config_u32(config, "sqs_visibility_timeout", 30, 1, 43_200)?;
    let address_root = address::parse(&format!("s3://{bucket}/"))?;
    Ok(S3Config {
        bucket,
        region,
        endpoint,
        profile_name,
        compatibility,
        force_path_style,
        force_request_payer,
        sqs_queue_url,
        sqs_max_messages,
        sqs_wait_seconds,
        sqs_visibility_timeout,
        address_root,
    })
}

fn config_string(
    config: &HashMap<String, ConfigValue>,
    key: &str,
    required: bool,
) -> Result<Option<String>> {
    match config.get(key) {
        Some(ConfigValue::String(value)) if !value.trim().is_empty() => {
            Ok(Some(value.trim().to_string()))
        }
        Some(ConfigValue::String(_)) if required => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("missing required S3 connection config '{key}'"),
        )),
        Some(ConfigValue::String(_)) => Ok(None),
        Some(_) => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("S3 connection config '{key}' must be a string"),
        )),
        None if required => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("missing required S3 connection config '{key}'"),
        )),
        None => Ok(None),
    }
}

fn config_bool(config: &HashMap<String, ConfigValue>, key: &str) -> Result<bool> {
    match config.get(key) {
        Some(ConfigValue::Bool(value)) => Ok(*value),
        Some(_) => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("S3 connection config '{key}' must be a bool"),
        )),
        None => Ok(false),
    }
}

fn config_u32(
    config: &HashMap<String, ConfigValue>,
    key: &str,
    default: u32,
    min: u32,
    max: u32,
) -> Result<u32> {
    match config.get(key) {
        Some(ConfigValue::Int(value)) if *value >= i64::from(min) && *value <= i64::from(max) => {
            Ok(*value as u32)
        }
        Some(ConfigValue::Int(_)) => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("S3 connection config '{key}' must be between {min} and {max}"),
        )),
        Some(_) => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("S3 connection config '{key}' must be an integer"),
        )),
        None => Ok(default),
    }
}

fn canonical_bucket(bucket: Option<&str>) -> Result<String> {
    let Some(bucket) = bucket else {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "missing required S3 connection config 'bucket'",
        ));
    };
    if bucket
        .chars()
        .any(|ch| matches!(ch, '/' | '\\' | ':' | '?' | '#' | '@') || ch.is_whitespace())
    {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "S3 bucket must be a single URL authority label",
        ));
    }
    let root = address::parse(&format!("s3://{bucket}/"))?;
    let parsed = parse_s3_address(&root, "")?;
    Ok(parsed.bucket)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct S3AddressParts {
    pub bucket: String,
    pub key: String,
}

pub fn parse_s3_address(addr: &Url, configured_bucket: &str) -> Result<S3AddressParts> {
    let value = addr.as_str();
    let Some((scheme, rest)) = value.split_once("://") else {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "S3 backend requires s3:// or s3+minio:// addresses",
        ));
    };
    if !matches!(scheme, "s3" | "s3+minio") {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "S3 backend requires s3:// or s3+minio:// addresses",
        ));
    }
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let bucket = rest[..authority_end].to_string();
    if bucket.is_empty() {
        return Err(Error::new(ErrorCode::InvalidArgument, "S3 bucket is empty"));
    }
    if !configured_bucket.is_empty() && bucket != configured_bucket {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "S3 address bucket '{bucket}' does not match configured bucket '{configured_bucket}'"
            ),
        ));
    }

    let suffix = &rest[authority_end..];
    let key_source = suffix.strip_prefix('/').unwrap_or("");
    let key_end = key_source.find(['?', '#']).unwrap_or(key_source.len());
    Ok(S3AddressParts {
        bucket,
        key: key_source[..key_end].to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_for(profile: CompatibilityProfile, endpoint: Option<&str>) -> S3Config {
        S3Config {
            bucket: "example-bucket".into(),
            region: "us-west-2".into(),
            endpoint: endpoint.map(str::to_string),
            profile_name: None,
            compatibility: profile,
            force_path_style: false,
            force_request_payer: false,
            sqs_queue_url: None,
            sqs_max_messages: 10,
            sqs_wait_seconds: 20,
            sqs_visibility_timeout: 30,
            address_root: address::parse("s3://example-bucket/").unwrap(),
        }
    }

    #[test]
    fn aws_profile_uses_virtual_hosted_style_by_default() {
        let endpoint =
            resolve_endpoint(&config_for(CompatibilityProfile::Aws, None), "key").unwrap();
        assert_eq!(endpoint.scheme, "https");
        assert_eq!(endpoint.host, "example-bucket.s3.us-west-2.amazonaws.com");
        assert_eq!(endpoint.canonical_uri, "/key");
        assert!(endpoint.virtual_hosted);
    }

    #[test]
    fn aws_force_path_style_switches_to_path_addressing() {
        let mut config = config_for(CompatibilityProfile::Aws, None);
        config.force_path_style = true;
        let endpoint = resolve_endpoint(&config, "key/with/path").unwrap();
        assert_eq!(endpoint.host, "s3.us-west-2.amazonaws.com");
        assert_eq!(endpoint.canonical_uri, "/example-bucket/key/with/path");
        assert!(!endpoint.virtual_hosted);
    }

    #[test]
    fn minio_profile_requires_endpoint_and_uses_path_style() {
        let err =
            resolve_endpoint(&config_for(CompatibilityProfile::Minio, None), "key").unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);

        let endpoint = resolve_endpoint(
            &config_for(CompatibilityProfile::Minio, Some("http://127.0.0.1:9000")),
            "obj",
        )
        .unwrap();
        assert_eq!(endpoint.scheme, "http");
        assert_eq!(endpoint.host, "127.0.0.1:9000");
        assert_eq!(endpoint.canonical_uri, "/example-bucket/obj");
        assert!(!endpoint.virtual_hosted);
    }

    #[test]
    fn r2_profile_uses_virtual_hosted_with_auto_signing_region() {
        let config = config_for(CompatibilityProfile::R2, None);
        let endpoint = resolve_endpoint(&config, "obj").unwrap();
        assert_eq!(endpoint.host, "example-bucket.r2.cloudflarestorage.com");
        assert!(endpoint.virtual_hosted);
        assert_eq!(config.signing_region(), "auto");
    }

    #[test]
    fn b2_profile_requires_endpoint_and_uses_path_style_with_auto_region() {
        let err = resolve_endpoint(&config_for(CompatibilityProfile::B2, None), "key").unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);

        let config = config_for(
            CompatibilityProfile::B2,
            Some("https://s3.us-east-005.backblazeb2.com"),
        );
        let endpoint = resolve_endpoint(&config, "obj").unwrap();
        assert_eq!(endpoint.host, "s3.us-east-005.backblazeb2.com");
        assert_eq!(endpoint.canonical_uri, "/example-bucket/obj");
        assert!(!endpoint.virtual_hosted);
        assert_eq!(config.signing_region(), "auto");
    }

    #[test]
    fn custom_endpoint_with_explicit_path_style_is_preserved() {
        let mut config = config_for(
            CompatibilityProfile::Custom,
            Some("https://store.example.com:8443/"),
        );
        config.force_path_style = true;
        let endpoint = resolve_endpoint(&config, "k").unwrap();
        assert_eq!(endpoint.host, "store.example.com:8443");
        assert_eq!(endpoint.canonical_uri, "/example-bucket/k");
    }
}
