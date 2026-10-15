// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Connection-config parsing and S3 / S3-compatible URL derivation.

use std::collections::HashMap;

use ovstorage_plugin::fallback::{ANONYMOUS_FALLBACK_KEY, is_anonymous_fallback_key};
use ovstorage_plugin::{
    ConfigField, ConfigFieldKind, ConfigValue, CredentialField, CredentialMethod, EnumSource,
    Error, ErrorCode, LayerConfig, Result, Url, address,
};

/// SQS long-poll defaults shared by a parsed connection and a synthesized
/// fallback config, so the two shapes cannot drift on the watch cadence.
const DEFAULT_SQS_MAX_MESSAGES: u32 = 10;
const DEFAULT_SQS_WAIT_SECONDS: u32 = 20;
const DEFAULT_SQS_VISIBILITY_TIMEOUT: u32 = 30;

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
        canonical_path_path_style(&config.bucket, key)
    } else {
        canonical_path(key)
    };
    Ok(ResolvedEndpoint {
        scheme,
        host,
        canonical_uri,
        virtual_hosted: !path_style,
    })
}

/// The DNS suffix of the AWS partition a region belongs to. The China
/// partition is reachable only under `amazonaws.com.cn`; GovCloud and every
/// other region use the standard suffix. Shared by [`derive_host`] and
/// [`alternate_url_prefixes`] so the host a request is signed against and the
/// host spellings the connection accepts name the same partition.
fn partition_suffix(region: &str) -> &'static str {
    if region.starts_with("cn-") {
        "amazonaws.com.cn"
    } else {
        "amazonaws.com"
    }
}

/// Region prefixes that are NOT in the standard commercial partition.
const NON_COMMERCIAL_REGION_PREFIXES: [&str; 4] = ["cn-", "us-gov-", "us-iso", "eu-iso"];

/// Whether the region-less "global" S3 host (`s3.<suffix>`) names a bucket in
/// this region's partition.
///
/// Only the standard commercial partition has one. `s3.amazonaws.com` is a
/// us-east-1 commercial endpoint and does not route into GovCloud, China, or
/// the isolated partitions — and S3 bucket names are unique only WITHIN a
/// partition, so the same name can be different data, under a different
/// owner, in each. Accepting the global form as a spelling of a
/// non-commercial bucket would therefore alias a URL that names someone
/// else's bucket onto this connection, and would extend an HTTPS-prefix
/// authorization grant written for the commercial bucket over this one's
/// data.
///
/// This is the line between the global form and the legacy dashed form, which
/// IS generated everywhere: the dashed form is region-scoped
/// (`s3-{configured_region}`), so where it was never issued it is a rule no
/// request can match — dead, not wrong. The global form is not region-scoped,
/// so outside the commercial partition it is wrong rather than dead.
fn has_global_endpoint(region: &str) -> bool {
    !NON_COMMERCIAL_REGION_PREFIXES
        .iter()
        .any(|prefix| region.starts_with(prefix))
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
            let suffix = format!("s3.{}.{}", config.region, partition_suffix(&config.region));
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

/// Endpoint URL to hand the AWS SDK `Config` builder, or `None` to let the SDK
/// synthesize the canonical AWS host from region + bucket.
///
/// The bucket label is **never** included here: the SDK inserts it as a
/// subdomain (virtual-hosted) when `force_path_style` is false, or as a path
/// segment when true. This mirrors `derive_host` minus the bucket so presigned
/// URLs and redirect-scope prefixes keep today's host shapes:
/// - `aws` with no endpoint → `None` (the SDK builds the regional host on its
///   own partition suffix, as [`partition_suffix`] does here);
/// - `r2` with no endpoint → `https://r2.cloudflarestorage.com`;
/// - any profile with an explicit `endpoint` → that endpoint (scheme + host);
/// - `minio` / `custom` / `b2` without an endpoint → error (as `resolve_endpoint`).
pub(crate) fn sdk_endpoint_url(config: &S3Config) -> Result<Option<String>> {
    if let Some(endpoint) = &config.endpoint {
        let parsed = url::Url::parse(endpoint).map_err(|err| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!("S3 endpoint '{endpoint}' is not a valid URL: {err}"),
            )
        })?;
        let scheme = parsed.scheme().to_ascii_lowercase();
        let host = host_with_port(&parsed)?;
        return Ok(Some(format!("{scheme}://{host}")));
    }
    match config.compatibility {
        CompatibilityProfile::Aws => Ok(None),
        CompatibilityProfile::R2 => Ok(Some("https://r2.cloudflarestorage.com".to_string())),
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

/// The alternate URL prefixes this connection accepts as spellings of its
/// `s3://{bucket}/` root — the value the layer stamps under
/// [`ovstorage_plugin::ACCEPTED_URL_SPELLINGS_METADATA_KEY`] so an alias
/// wrapper above can auto-generate hidden alias rules. Lives next to
/// [`derive_host`] on purpose: an endpoint-derived spelling must come from
/// the same derivation as the signed endpoint or the two drift.
///
/// The templated AWS shapes diverge from [`derive_host`] in exactly one
/// place, deliberate and in the accept-only direction (an alias `from`
/// selects inbound addresses; it never reaches a wire): the virtual-hosted
/// shapes are withheld for a dotted bucket even though [`derive_host`] signs
/// against that multi-label host under virtual-hosted addressing. Fixing that
/// on the SIGNING side — path-style for dotted buckets, as the AWS SDKs do —
/// is a data-path change with its own blast radius, owned by [`derive_host`],
/// not here. The partition suffix is NOT such a divergence: both sides read
/// it from [`partition_suffix`], so a China connection is signed against the
/// same `amazonaws.com.cn` host it accepts spellings of.
///
/// The governing test for membership is *"what URL could a user plausibly be
/// holding?"*, not "what can the SDK emit":
///
/// - **Explicit endpoint** (any profile): exactly the one shape the endpoint
///   configuration describes, read straight out of [`derive_host`] —
///   `{scheme}://{host}/{bucket}/` under path-style addressing,
///   `{scheme}://{bucket}.{host}/` otherwise. No guessing beyond the config.
/// - **AWS, no endpoint**: the six public shapes — virtual-hosted and
///   path-style, each in the regional, the global, and the legacy dashed
///   (`s3-{region}`) spelling. The dashed form is generated for EVERY region
///   rather than gated on where it was historically issued: such a list rots,
///   and a dash alias for a post-2019 region is a rule no request can match —
///   dead, not wrong. It matches `s3-{configured_region}` exactly, never a
///   wildcard, so `s3-website-…`/`s3-accesspoint-…`/`s3-fips-…` (different
///   resources, not other spellings) can never be captured. The China
///   partition swaps the suffix to `amazonaws.com.cn`. All six are generated
///   regardless of `force_path_style`: the URL a user holds does not depend
///   on this connection's addressing preference. **Exception: a bucket whose
///   name contains a dot gets only the three path-style shapes.** Its
///   virtual-hosted host is multi-label and falls outside AWS's
///   `*.s3.<region>.<suffix>` wildcard certificate, so the HTTPS spelling
///   fails the membership test — no fetch of it ever succeeded, so no user
///   plausibly holds one. Path-style is what AWS documents for such buckets.
/// - **R2, no endpoint**: the one shape [`derive_host`] signs against on the
///   fixed `r2.cloudflarestorage.com` suffix.
/// - **Endpoint required but missing** (MinIO/Custom/B2): empty — backend
///   construction reports the real configuration error; there is no URL a
///   user could be holding that came from this config.
///
/// Deliberately excluded: transport variants (dualstack, FIPS, transfer
/// acceleration — this repository never constructs such an endpoint and they
/// are not universally valid), and different resources (access points, MRAP,
/// S3 Express, VPC endpoints, Outposts — aliasing those to the bucket would
/// be incorrect rather than merely noisy).
pub fn alternate_url_prefixes(config: &S3Config) -> Vec<Url> {
    let mut spellings: Vec<String> = Vec::new();
    let bucket = &config.bucket;
    // The single shape [`derive_host`] would sign against, formatted back into
    // a root prefix: `derive_host` already folds the bucket into the host under
    // virtual-hosted addressing, so only the path-style case appends it.
    // Reusing that derivation rather than re-parsing the endpoint here is what
    // keeps an accepted spelling from drifting away from the signed endpoint
    // when endpoint normalization changes. `None` on a configuration
    // `derive_host` rejects — the backend reports that error where a caller can
    // read it, and there is no URL to accept for a config that cannot be built.
    let signed_prefix = || {
        let path_style = config.use_path_style();
        let (scheme, host) = derive_host(config, path_style).ok()?;
        Some(if path_style {
            format!("{scheme}://{host}/{bucket}/")
        } else {
            format!("{scheme}://{host}/")
        })
    };
    if config.endpoint.is_some() {
        // Exactly from configuration: whatever the endpoint describes.
        spellings.extend(signed_prefix());
    } else {
        match config.compatibility {
            CompatibilityProfile::Aws => {
                let region = &config.region;
                let suffix = partition_suffix(region);
                // The region-less global form belongs to the commercial
                // partition alone; see `has_global_endpoint`.
                let global = has_global_endpoint(region).then(|| format!("s3.{suffix}"));
                // Regional, then global where it exists, then legacy dashed.
                let hosts = || {
                    [Some(format!("s3.{region}.{suffix}")), global.clone()]
                        .into_iter()
                        .flatten()
                        .chain([format!("s3-{region}.{suffix}")])
                };
                // A dotted bucket has no working HTTPS virtual-hosted
                // spelling (the multi-label host is outside AWS's wildcard
                // certificate), so only its documented path-style shapes are
                // URLs a user plausibly holds.
                if !bucket.contains('.') {
                    spellings.extend(hosts().map(|host| format!("https://{bucket}.{host}/")));
                }
                // Path-style twins of the same hosts.
                spellings.extend(hosts().map(|host| format!("https://{host}/{bucket}/")));
            }
            // The fixed `r2.cloudflarestorage.com` suffix is `derive_host`'s
            // decision too, so it is read from there rather than restated.
            CompatibilityProfile::R2 => spellings.extend(signed_prefix()),
            // No endpoint to derive from; `resolve_endpoint` reports the
            // configuration error where a caller can read it.
            CompatibilityProfile::Minio
            | CompatibilityProfile::Custom
            | CompatibilityProfile::B2 => {}
        }
    }
    // `address::parse` so the prefixes normalize exactly as the alias layer
    // parses its rule config; the shapes above cannot fail it (the bucket is
    // validated as a single authority label), but a spelling that somehow
    // does is dropped rather than poisoning its neighbours.
    spellings
        .iter()
        .filter_map(|spelling| address::parse(spelling).ok())
        .collect()
}

/// Canonical-URI path for a key: each segment percent-encoded with the
/// unreserved alphabet, `/` kept literal. Used for virtual-hosted addressing,
/// `x-amz-copy-source`, and anonymous object URLs.
pub(crate) fn canonical_path(key: &str) -> String {
    let mut out = String::with_capacity(key.len() + 1);
    out.push('/');
    let mut first = true;
    for segment in key.split('/') {
        if !first {
            out.push('/');
        }
        first = false;
        out.push_str(&encode_uri_segment(segment));
    }
    out
}

/// Canonical URI `/{bucket}/{key}` for path-style addressing; bucket unencoded,
/// key canonicalised.
pub(crate) fn canonical_path_path_style(bucket: &str, key: &str) -> String {
    let mut out = String::with_capacity(key.len() + bucket.len() + 2);
    out.push('/');
    out.push_str(bucket);
    if key.is_empty() {
        return out;
    }
    out.push('/');
    let mut first = true;
    for segment in key.split('/') {
        if !first {
            out.push('/');
        }
        first = false;
        out.push_str(&encode_uri_segment(segment));
    }
    out
}

fn encode_uri_segment(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if is_unreserved(byte) {
            out.push(byte as char);
        } else {
            out.push('%');
            out.push(hex_digit(byte >> 4));
            out.push(hex_digit(byte & 0x0f));
        }
    }
    out
}

fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

fn hex_digit(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        10..=15 => (b'A' + value - 10) as char,
        _ => unreachable!("nibble in range"),
    }
}

/// Percent-encode + sort query params into a canonical `k=v&...` string.
pub(crate) fn canonicalize_query(params: &[(String, String)]) -> String {
    let mut encoded: Vec<(String, String)> = params
        .iter()
        .map(|(k, v)| (encode_query_token(k), encode_query_token(v)))
        .collect();
    encoded.sort();
    encoded
        .into_iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

pub(crate) fn encode_query_token(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if is_unreserved(byte) {
            out.push(byte as char);
        } else {
            out.push('%');
            out.push(hex_digit(byte >> 4));
            out.push(hex_digit(byte & 0x0f));
        }
    }
    out
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
    let sqs_max_messages = config_u32(config, "sqs_max_messages", DEFAULT_SQS_MAX_MESSAGES, 1, 10)?;
    let sqs_wait_seconds = config_u32(config, "sqs_wait_seconds", DEFAULT_SQS_WAIT_SECONDS, 0, 20)?;
    let sqs_visibility_timeout = config_u32(
        config,
        "sqs_visibility_timeout",
        DEFAULT_SQS_VISIBILITY_TIMEOUT,
        1,
        43_200,
    )?;
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

/// The connection config the anonymous `s3://` fallback synthesizes for one
/// bucket it reaches with no configured connection.
///
/// Shaped exactly like a parsed anonymous connection for `bucket`, so
/// [`parse_s3_address`] keeps its bucket pin and every data-path operation
/// runs unchanged: `force_request_payer` off (an anonymous request cannot be
/// billed to a requester), no SQS queue (a fallback never watches), and the
/// `address_root` a connection for the same bucket would publish.
///
/// A bucket whose name contains a dot is addressed path-style whatever the
/// operator set. Its virtual-hosted host is multi-label and falls outside
/// AWS's `*.s3.<region>.amazonaws.com` wildcard certificate, so a TLS
/// connection to it fails on hostname mismatch; path-style is what AWS
/// documents for such buckets, and the operator never named this bucket, so
/// there is no per-bucket setting to defer to.
///
/// # Errors
///
/// - [`ErrorCode::InvalidArgument`] — `bucket` is not a single URL authority
///   label.
pub(crate) fn fallback_config(
    bucket: &str,
    region: &str,
    endpoint: Option<&str>,
    compatibility: CompatibilityProfile,
    force_path_style: bool,
) -> Result<S3Config> {
    let bucket = canonical_bucket(Some(bucket))?;
    let address_root = address::parse(&format!("s3://{bucket}/"))?;
    let force_path_style = force_path_style || bucket.contains('.');
    Ok(S3Config {
        region: region.to_string(),
        endpoint: endpoint.map(str::to_string),
        profile_name: None,
        compatibility,
        force_path_style,
        force_request_payer: false,
        sqs_queue_url: None,
        sqs_max_messages: DEFAULT_SQS_MAX_MESSAGES,
        sqs_wait_seconds: DEFAULT_SQS_WAIT_SECONDS,
        sqs_visibility_timeout: DEFAULT_SQS_VISIBILITY_TIMEOUT,
        address_root,
        bucket,
    })
}

/// Layer key: the region a cold bucket's probe is sent to, and the region a
/// bucket is assumed to live in when no probe runs.
pub(crate) const FALLBACK_REGION_KEY: &str = "anonymous_fallback_region";
/// Layer key: an explicit S3-compatible endpoint for every fallback bucket.
/// Setting it skips the region probe, because the endpoint pins the host.
///
/// Screened at parse ([`fallback_endpoint`]) down to a bare `http` or `https`
/// origin — scheme, host and port — and refused when it embeds credentials or
/// carries a path, query or fragment, so the string [`FallbackPolicy`] carries
/// is that origin and nothing else. Every consumer still rebuilds the host from
/// parsed parts (`derive_host`, `sdk_endpoint_url`, the anonymous read URL)
/// rather than concatenating the raw string; a consumer that concatenated it
/// would be safe only because of the screening, so neither half is to be
/// dropped without the other.
pub(crate) const FALLBACK_ENDPOINT_KEY: &str = "anonymous_fallback_endpoint";
/// Layer key: the compatibility profile, parsed exactly as the connection key.
pub(crate) const FALLBACK_COMPATIBILITY_KEY: &str = "anonymous_fallback_compatibility_profile";
/// Layer key: path-style addressing for every fallback bucket.
pub(crate) const FALLBACK_FORCE_PATH_STYLE_KEY: &str = "anonymous_fallback_force_path_style";
/// Layer key: how many per-bucket anonymous backends stay resident.
pub(crate) const FALLBACK_MAX_BACKENDS_KEY: &str = "anonymous_fallback_max_backends";
/// Layer key: how many backends may be built per sliding minute.
pub(crate) const FALLBACK_MINTS_PER_MINUTE_KEY: &str = "anonymous_fallback_mints_per_minute";

/// Every layer key the fallback reads besides the grant itself; anything else
/// under the `anonymous_fallback_` prefix is a typo and is refused by name.
const FALLBACK_TUNABLE_KEYS: [&str; 6] = [
    FALLBACK_REGION_KEY,
    FALLBACK_ENDPOINT_KEY,
    FALLBACK_COMPATIBILITY_KEY,
    FALLBACK_FORCE_PATH_STYLE_KEY,
    FALLBACK_MAX_BACKENDS_KEY,
    FALLBACK_MINTS_PER_MINUTE_KEY,
];

const DEFAULT_FALLBACK_REGION: &str = "us-east-1";
const DEFAULT_FALLBACK_MAX_BACKENDS: usize = 64;
const DEFAULT_FALLBACK_MINTS_PER_MINUTE: u32 = 120;

/// The layer-level tunables behind `anonymous_fallback = ["s3"]`, read from
/// the policy half of a layer table. These describe how the fallback reaches
/// a bucket nobody configured; they are never connection config, and a
/// connection request carrying one is refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FallbackPolicy {
    /// Probe target and default region.
    pub region: String,
    /// Explicit endpoint for every fallback bucket; skips the region probe.
    /// A bare origin, as [`fallback_endpoint`] admits it.
    pub endpoint: Option<Url>,
    pub compatibility: CompatibilityProfile,
    pub force_path_style: bool,
    pub max_backends: usize,
    pub mints_per_minute: u32,
}

impl FallbackPolicy {
    /// The endpoint as `S3Config` carries it.
    pub(crate) fn endpoint_str(&self) -> Option<&str> {
        self.endpoint.as_ref().map(Url::as_str)
    }
}

/// Parse the fallback tunables out of the policy half of layer `layer_name`'s
/// table.
///
/// Defaults: region `us-east-1`, no endpoint, profile `aws` (or `custom` once
/// an endpoint is set, as a connection defaults), virtual-hosted addressing,
/// 64 resident backends, 120 builds per minute. Every value is validated here
/// so a mistake fails at `create_backend` rather than on the first unrouted
/// address: the region must have the shape of a region identifier because it
/// becomes part of a hostname, the endpoint must be a bare `http` or `https`
/// origin because it is what every fallback host and every anonymous read
/// redirect is built from ([`fallback_endpoint`]), the endpoint and profile
/// must together derive a host (the same rule a connection meets), and the
/// bounds must be positive — a zero budget would mean "build nothing" and a
/// zero cache "keep nothing", neither of which is what an operator means by
/// turning the fallback on.
///
/// # Errors
///
/// - [`ErrorCode::InvalidArgument`] — an unknown `anonymous_fallback_*` key,
///   a value of the wrong type, a region that is not a region identifier, a
///   bound outside its range, an endpoint that is not a bare `http` or
///   `https` origin, or an endpoint/profile pair that derives no host.
pub(crate) fn parse_fallback_policy(
    policy: &LayerConfig,
    layer_name: &str,
) -> Result<FallbackPolicy> {
    if let Some(key) = policy.keys().find(|key| {
        is_anonymous_fallback_key(key)
            && key.as_str() != ANONYMOUS_FALLBACK_KEY
            && !FALLBACK_TUNABLE_KEYS.contains(&key.as_str())
    }) {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "`{key}` is not a fallback layer key; the fallback keys are {}",
                FALLBACK_TUNABLE_KEYS.join(", ")
            ),
        ));
    }
    let region = policy_string(policy, FALLBACK_REGION_KEY)?
        .unwrap_or_else(|| DEFAULT_FALLBACK_REGION.to_string());
    if !crate::errors::is_valid_region_token(&region) {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "`{FALLBACK_REGION_KEY}` must be a region identifier such as \
                 {DEFAULT_FALLBACK_REGION}"
            ),
        ));
    }
    let endpoint = fallback_endpoint(policy, layer_name)?;
    let compatibility = match policy_string(policy, FALLBACK_COMPATIBILITY_KEY)? {
        Some(profile) => CompatibilityProfile::parse(&profile)?,
        None if endpoint.is_some() => CompatibilityProfile::Custom,
        None => CompatibilityProfile::Aws,
    };
    let force_path_style = policy_bool(policy, FALLBACK_FORCE_PATH_STYLE_KEY)?;
    let max_backends = policy_bounded(
        policy,
        FALLBACK_MAX_BACKENDS_KEY,
        DEFAULT_FALLBACK_MAX_BACKENDS as i64,
        1,
        100_000,
    )? as usize;
    let mints_per_minute = policy_bounded(
        policy,
        FALLBACK_MINTS_PER_MINUTE_KEY,
        i64::from(DEFAULT_FALLBACK_MINTS_PER_MINUTE),
        1,
        1_000_000,
    )? as u32;
    let parsed = FallbackPolicy {
        region,
        endpoint,
        compatibility,
        force_path_style,
        max_backends,
        mints_per_minute,
    };
    // The endpoint and profile must derive a host together — the same rule a
    // connection meets in `resolve_endpoint` — so a profile that requires an
    // endpoint and has none fails here, not on the first unrouted address.
    let probe = fallback_config(
        "bucket",
        &parsed.region,
        parsed.endpoint_str(),
        parsed.compatibility,
        parsed.force_path_style,
    )?;
    resolve_endpoint(&probe, "")?;
    Ok(parsed)
}

/// Read and screen the fallback endpoint on layer `layer_name`: `None` when
/// the key is absent or blank, otherwise the endpoint rebuilt as a bare origin
/// — scheme, host and port — and nothing else.
///
/// This string is what every fallback bucket's host is derived from and, on
/// an anonymous `read`, what the redirect URL handed back to the caller is
/// built from. Userinfo is refused because a credential written here would
/// otherwise ride every anonymous request on a tier whose promise is that
/// none is sent, and the redirect would hand it to the caller. A query or
/// fragment is refused because S3 request URLs place the bucket, key and
/// query after the origin, so a delimiter left here would push them into the
/// wrong component. A path is refused because S3 addresses the bucket and key
/// directly under the origin and the host derivation keeps scheme, host and
/// port only: a path written here would be dropped silently, and an operator
/// who wrote one meant something by it. The userinfo and delimiter checks read
/// the raw text as well as the parsed URL: `Url` normalizes an empty userinfo
/// (`https://@host`) and a bare trailing `?` or `#` away before either is
/// visible after parsing.
///
/// The refusal names the key and the layer, never the value: the value is
/// where the credential was.
fn fallback_endpoint(policy: &LayerConfig, layer_name: &str) -> Result<Option<Url>> {
    let Some(raw) = policy_string(policy, FALLBACK_ENDPOINT_KEY)? else {
        return Ok(None);
    };
    if let Some(component) = address::refused_config_component(&raw) {
        return Err(fallback_endpoint_refused(
            layer_name,
            &format!("must not carry a {}", component.name()),
        ));
    }
    if raw_authority(&raw).contains('@') {
        return Err(fallback_endpoint_refused(
            layer_name,
            "must not embed credentials in the URL",
        ));
    }
    let parsed = Url::parse(&raw).map_err(|err| {
        fallback_endpoint_refused(layer_name, &format!("must be an absolute URL: {err}"))
    })?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(fallback_endpoint_refused(
            layer_name,
            "must use http or https",
        ));
    }
    let Some(host) = parsed.host_str().filter(|host| !host.is_empty()) else {
        return Err(fallback_endpoint_refused(layer_name, "must name a host"));
    };
    // The raw scan above is the check that sees everything; this one is the
    // parser's own reading of the authority, kept so that no spelling the
    // parser recognizes as userinfo can reach the rebuild below.
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(fallback_endpoint_refused(
            layer_name,
            "must not embed credentials in the URL",
        ));
    }
    if !matches!(parsed.path(), "" | "/") {
        return Err(fallback_endpoint_refused(
            layer_name,
            "must not carry a path; the bucket and key are addressed under the origin",
        ));
    }
    // `port()` is already `None` for the scheme default, and an IPv6 host
    // comes back bracketed, so the parts concatenate straight into a URL.
    let port = parsed
        .port()
        .map(|port| format!(":{port}"))
        .unwrap_or_default();
    let rebuilt = format!("{}://{host}{port}", parsed.scheme());
    Url::parse(&rebuilt).map(Some).map_err(|err| {
        Error::new(
            ErrorCode::Internal,
            format!("the screened `{FALLBACK_ENDPOINT_KEY}` does not parse as a URL: {err}"),
        )
    })
}

fn fallback_endpoint_refused(layer_name: &str, why: &str) -> Error {
    Error::new(
        ErrorCode::InvalidArgument,
        format!("`{FALLBACK_ENDPOINT_KEY}` on layer `{layer_name}` {why}"),
    )
}

/// The authority substring of a raw endpoint — `[userinfo@]host[:port]` — as
/// the operator wrote it. `Url` drops a syntactically empty userinfo
/// (`https://@host` parses with an empty username and no password), so the
/// raw text is the only place a stray `@` is still visible.
fn raw_authority(raw: &str) -> &str {
    let after_scheme = raw.split_once("://").map_or(raw, |(_, rest)| rest);
    let end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    &after_scheme[..end]
}

fn policy_string(policy: &LayerConfig, key: &str) -> Result<Option<String>> {
    match policy.get(key) {
        Some(ConfigValue::String(value)) if !value.trim().is_empty() => {
            Ok(Some(value.trim().to_string()))
        }
        Some(ConfigValue::String(_)) => Ok(None),
        Some(_) => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("`{key}` must be a string"),
        )),
        None => Ok(None),
    }
}

fn policy_bool(policy: &LayerConfig, key: &str) -> Result<bool> {
    match policy.get(key) {
        Some(ConfigValue::Bool(value)) => Ok(*value),
        Some(_) => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("`{key}` must be a bool"),
        )),
        None => Ok(false),
    }
}

fn policy_bounded(
    policy: &LayerConfig,
    key: &str,
    default: i64,
    min: i64,
    max: i64,
) -> Result<i64> {
    match policy.get(key) {
        Some(ConfigValue::Int(value)) if (min..=max).contains(value) => Ok(*value),
        Some(ConfigValue::Int(_)) => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("`{key}` must be between {min} and {max}"),
        )),
        Some(_) => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("`{key}` must be an integer"),
        )),
        None => Ok(default),
    }
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
    if !matches!(addr.scheme(), "s3" | "s3+minio") {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "S3 backend requires s3:// or s3+minio:// addresses",
        ));
    }
    // The bucket is the parsed host, not a slice of the serialized authority.
    // Slicing takes userinfo and a port with it, and those are exactly the
    // components on which the backend must agree with the authorization
    // matcher: the matcher keys on `(scheme, host, port)` and ignores userinfo
    // entirely, so a backend deriving a bucket from a different set of
    // components either rejects addresses the matcher allows or serves two
    // scopes the matcher ranks apart.
    //
    // Bucket names are case-insensitive. In practice the host arrives already
    // lowercased — `ovstorage_layer::canonicalize` (via `address::parse`)
    // lowercases the host of every address-bearing request — but normalise here
    // too so direct callers and the byte-for-byte instance lookup
    // (`unique_instance_for_bucket`) stay consistent regardless of how the URL
    // was spelled.
    let bucket = addr.host_str().unwrap_or_default().to_ascii_lowercase();
    if bucket.is_empty() {
        return Err(Error::new(ErrorCode::InvalidArgument, "S3 bucket is empty"));
    }
    if addr.port().is_some() {
        // A port makes two addresses distinct scopes to the matcher while
        // naming one bucket here. Refuse rather than let the two disagree: an
        // S3 address has no port to carry.
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "S3 address must not carry a port",
        ));
    }
    if !configured_bucket.is_empty() && bucket != configured_bucket.to_ascii_lowercase() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "S3 address bucket '{bucket}' does not match configured bucket '{configured_bucket}'"
            ),
        ));
    }

    // The key is the DECODED path, which is what `address::key` documents and
    // what the other backends derive. Slicing the serialized address gives the
    // wrong key: the canonical form still escapes space, controls and `%`, so
    // `s3://b/pub%20x` sliced raw asks S3 for an object named `pub%20x`.
    // Deriving it from the parsed URL also excludes the query and the fragment
    // by construction rather than by cutting the string at `?` and `#`.
    //
    // `key_utf8` rather than `key`: the key goes into the SigV4 canonical URI
    // and the signed request path, both `&str`. AWS documents an object key as
    // Unicode encoded as UTF-8, so a key outside that has no S3 spelling and is
    // refused rather than collapsed onto a different object.
    Ok(S3AddressParts {
        bucket,
        key: address::key_utf8(addr)?,
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

    /// The key is the decoded path, which is what `address::key` documents and
    /// what four of the six backends already derive.
    ///
    /// A raw slice of the serialized address is the wrong key: the canonical
    /// form still escapes space, controls and `%`, so `s3://b/pub%20x` sliced
    /// raw asks S3 for an object literally named `pub%20x`.
    #[test]
    fn the_key_is_the_decoded_path() {
        for (address, expected) in [
            ("s3://example-bucket/pub%20x", "pub x"),
            ("s3://example-bucket/dir/a%25b", "dir/a%b"),
            ("s3://example-bucket/plain/key", "plain/key"),
            ("s3://example-bucket/", ""),
            // The query and fragment are address modifiers, never key bytes.
            ("s3://example-bucket/k?versionId=7", "k"),
        ] {
            let parsed =
                parse_s3_address(&address::parse(address).unwrap(), "example-bucket").unwrap();
            assert_eq!(parsed.key, expected, "key of {address}");
        }
    }

    /// The two halves must agree, or `list` hands out addresses `read` and
    /// `delete` resolve elsewhere.
    ///
    /// The emitter escapes the key and the parser decodes it; testing either
    /// alone passes while the pair is broken. The wire spelling is checked too,
    /// because the signed canonical URI is derived from the parsed key — before
    /// this pair agreed, key `pub x` was signed as `pub%2520x`.
    #[test]
    fn a_listed_key_round_trips_through_the_address_it_is_given() {
        let root = address::parse("s3://example-bucket/").unwrap();
        for original in ["pub x", "a%2Fb", "100%", "dir/nested/x.txt", "a+b"] {
            let emitted = address::join_relative(&root, original).unwrap();
            let parsed = parse_s3_address(&emitted, "example-bucket").unwrap();
            assert_eq!(
                parsed.key, original,
                "{original} emitted as {emitted} and came back as {}",
                parsed.key
            );
        }

        assert_eq!(canonical_path("pub x"), "/pub%20x");
        assert_eq!(canonical_path("a%2Fb"), "/a%252Fb");
    }

    /// An allow on a path must not extend to a literal sibling that merely
    /// looks like an encoded spelling of it.
    ///
    /// Asserted against the key the backend actually derives, so the test
    /// cannot pass by comparing two addresses that never reach an object.
    #[test]
    fn an_encoded_sibling_is_a_different_key_from_the_allowed_prefix() {
        let under = parse_s3_address(
            &address::parse("s3://example-bucket/pub/secret").unwrap(),
            "example-bucket",
        )
        .unwrap();
        assert_eq!(under.key, "pub/secret");

        // `%2570ub%252Fsecret` decodes to the literal five-character `%70ub…`
        // spelling, which is a different object and is not under `pub/`.
        let sibling = parse_s3_address(
            &address::parse("s3://example-bucket/%2570ub%252Fsecret").unwrap(),
            "example-bucket",
        )
        .unwrap();
        assert_eq!(sibling.key, "%70ub%2Fsecret");
        assert!(!sibling.key.starts_with("pub/"));
    }

    fn prefixes(config: &S3Config) -> Vec<String> {
        alternate_url_prefixes(config)
            .iter()
            .map(|url| url.as_str().to_string())
            .collect()
    }

    /// The six public AWS shapes, exactly: virtual-hosted and
    /// path-style, each regional / global / legacy dashed. The dashed form is
    /// pinned to the CONFIGURED region — never a wildcard — so
    /// `s3-website-…` and friends can never be captured.
    #[test]
    fn aws_generates_the_six_public_url_shapes() {
        let config = config_for(CompatibilityProfile::Aws, None);
        assert_eq!(
            prefixes(&config),
            vec![
                "https://example-bucket.s3.us-west-2.amazonaws.com/",
                "https://example-bucket.s3.amazonaws.com/",
                "https://example-bucket.s3-us-west-2.amazonaws.com/",
                "https://s3.us-west-2.amazonaws.com/example-bucket/",
                "https://s3.amazonaws.com/example-bucket/",
                "https://s3-us-west-2.amazonaws.com/example-bucket/",
            ]
        );
    }

    /// An explicit endpoint's PATH never reaches a generated spelling. The
    /// spellings are published in connection metadata that introspection-only
    /// callers can read, and an endpoint path can be a capability token; the
    /// derivation reads `derive_host`, which keeps `host[:port]` and nothing
    /// else, so the withholding is a property of the shared derivation rather
    /// than a filter that could be forgotten here.
    #[test]
    fn an_explicit_endpoint_path_never_reaches_a_spelling() {
        let config = config_for(
            CompatibilityProfile::Custom,
            Some("https://gateway.example/sas-capability-token"),
        );
        let generated = prefixes(&config);
        assert_eq!(
            generated,
            vec!["https://gateway.example/example-bucket/"],
            "the endpoint host is kept and its path is not"
        );
        assert!(
            !generated
                .iter()
                .any(|prefix| prefix.contains("sas-capability-token")),
            "a path-carried token must never be published: {generated:?}"
        );
    }

    /// The accepted spellings and the signed endpoint read the partition from
    /// the same place, so a pasted URL is never aliased onto a host the signer
    /// then rebuilds in another partition. Asserted as membership rather than
    /// as a literal: the signed host must be one of the shapes this connection
    /// says it answers to.
    #[test]
    fn the_signed_host_is_one_of_the_accepted_spellings() {
        for region in ["cn-north-1", "us-west-2", "us-gov-west-1"] {
            let mut config = config_for(CompatibilityProfile::Aws, None);
            config.region = region.into();
            let signed = resolve_endpoint(&config, "key").unwrap();
            let signed_prefix = format!("{}://{}/", signed.scheme, signed.host);
            assert!(
                prefixes(&config).contains(&signed_prefix),
                "{region}: the signed host {signed_prefix} is not among the \
                 accepted spellings {:?}",
                prefixes(&config)
            );
        }
    }

    /// `force_path_style` changes how THIS connection addresses the bucket,
    /// not which URLs a user may be holding — the six shapes are invariant.
    #[test]
    fn aws_shapes_do_not_depend_on_the_addressing_preference() {
        let mut forced = config_for(CompatibilityProfile::Aws, None);
        forced.force_path_style = true;
        assert_eq!(
            prefixes(&forced),
            prefixes(&config_for(CompatibilityProfile::Aws, None))
        );
    }

    /// Outside the commercial partition there is no region-less global host,
    /// so only the regional and legacy-dashed shapes are generated — four,
    /// not six. China additionally swaps the DNS suffix.
    #[test]
    fn a_non_commercial_partition_generates_no_global_shape() {
        let mut config = config_for(CompatibilityProfile::Aws, None);
        config.region = "cn-north-1".into();
        assert_eq!(
            prefixes(&config),
            vec![
                "https://example-bucket.s3.cn-north-1.amazonaws.com.cn/",
                "https://example-bucket.s3-cn-north-1.amazonaws.com.cn/",
                "https://s3.cn-north-1.amazonaws.com.cn/example-bucket/",
                "https://s3-cn-north-1.amazonaws.com.cn/example-bucket/",
            ]
        );

        // GovCloud keeps the standard suffix, which is exactly why the global
        // form has to be withheld: `s3.amazonaws.com` is a COMMERCIAL
        // endpoint, and bucket names are unique only within a partition, so
        // accepting it would alias a URL naming someone else's bucket onto
        // this one.
        let mut config = config_for(CompatibilityProfile::Aws, None);
        config.region = "us-gov-west-1".into();
        let generated = prefixes(&config);
        assert_eq!(
            generated,
            vec![
                "https://example-bucket.s3.us-gov-west-1.amazonaws.com/",
                "https://example-bucket.s3-us-gov-west-1.amazonaws.com/",
                "https://s3.us-gov-west-1.amazonaws.com/example-bucket/",
                "https://s3-us-gov-west-1.amazonaws.com/example-bucket/",
            ]
        );
        assert!(
            !generated.iter().any(|prefix| {
                prefix == "https://example-bucket.s3.amazonaws.com/"
                    || prefix == "https://s3.amazonaws.com/example-bucket/"
            }),
            "a commercial global host must never spell a GovCloud bucket: {generated:?}"
        );

        // The isolated partitions get the same treatment, for the same
        // reason — their regional hosts are unreachable from here, which is
        // dead rather than wrong, but the global commercial host is wrong.
        for region in ["us-iso-east-1", "us-isob-east-1", "eu-isoe-west-1"] {
            let mut config = config_for(CompatibilityProfile::Aws, None);
            config.region = region.into();
            let generated = prefixes(&config);
            assert_eq!(generated.len(), 4, "{region}: {generated:?}");
            assert!(
                !generated
                    .iter()
                    .any(|prefix| prefix.contains("s3.amazonaws.com")),
                "{region} must not borrow the commercial global host: {generated:?}"
            );
        }
    }

    /// And the commercial partition still gets all six.
    #[test]
    fn the_commercial_partition_keeps_its_global_shape() {
        let mut config = config_for(CompatibilityProfile::Aws, None);
        config.region = "eu-west-1".into();
        let generated = prefixes(&config);
        assert_eq!(generated.len(), 6, "{generated:?}");
        assert!(generated.contains(&"https://example-bucket.s3.amazonaws.com/".to_string()));
        assert!(generated.contains(&"https://s3.amazonaws.com/example-bucket/".to_string()));
    }

    /// An explicit endpoint generates exactly the one shape the configuration
    /// describes — path-style for MinIO/B2 (profile-required) and Custom with
    /// `force_path_style`, virtual-hosted otherwise — with the endpoint's own
    /// scheme and port.
    #[test]
    fn an_explicit_endpoint_generates_exactly_its_configured_shape() {
        assert_eq!(
            prefixes(&config_for(
                CompatibilityProfile::Minio,
                Some("http://127.0.0.1:9000"),
            )),
            vec!["http://127.0.0.1:9000/example-bucket/"]
        );
        assert_eq!(
            prefixes(&config_for(
                CompatibilityProfile::B2,
                Some("https://s3.us-east-005.backblazeb2.com"),
            )),
            vec!["https://s3.us-east-005.backblazeb2.com/example-bucket/"]
        );
        // A custom endpoint without forced path style is virtual-hosted.
        assert_eq!(
            prefixes(&config_for(
                CompatibilityProfile::Aws,
                Some("https://store.example.com:8443"),
            )),
            vec!["https://example-bucket.store.example.com:8443/"]
        );
    }

    /// A dotted bucket gets only its three path-style spellings. Its
    /// virtual-hosted host is multi-label and falls outside AWS's
    /// `*.s3.<region>.amazonaws.com` wildcard certificate, so the HTTPS
    /// spelling fails the membership test — no fetch of it ever succeeded, so
    /// no user plausibly holds one — while path-style is what AWS documents
    /// for such buckets. (An explicit-endpoint profile is untouched by this:
    /// there the shape mirrors the operator's own working configuration
    /// exactly, dots or not.)
    #[test]
    fn a_dotted_bucket_generates_path_style_spellings_only() {
        let mut config = config_for(CompatibilityProfile::Aws, None);
        config.bucket = "my.bucket.name".into();
        assert_eq!(
            prefixes(&config),
            vec![
                "https://s3.us-west-2.amazonaws.com/my.bucket.name/",
                "https://s3.amazonaws.com/my.bucket.name/",
                "https://s3-us-west-2.amazonaws.com/my.bucket.name/",
            ]
        );
    }

    #[test]
    fn r2_generates_its_fixed_suffix_shape() {
        assert_eq!(
            prefixes(&config_for(CompatibilityProfile::R2, None)),
            vec!["https://example-bucket.r2.cloudflarestorage.com/"]
        );
    }

    /// A profile whose endpoint is required but missing has no URL a user
    /// could be holding that came from this config; the configuration error
    /// is reported by `resolve_endpoint`, not here.
    #[test]
    fn a_missing_required_endpoint_generates_nothing() {
        for profile in [
            CompatibilityProfile::Minio,
            CompatibilityProfile::Custom,
            CompatibilityProfile::B2,
        ] {
            assert!(prefixes(&config_for(profile, None)).is_empty());
        }
    }

    /// A key whose bytes are not valid UTF-8 is refused rather than collapsed.
    ///
    /// The signed canonical URI is built from a `&str`, so there is nowhere for
    /// those bytes to go. Converting them lossily would make the backend fetch
    /// one object for two distinct addresses, which is exactly the divergence
    /// the byte-exact key exists to remove.
    #[test]
    fn a_key_that_is_not_utf8_is_refused_rather_than_collapsed() {
        let error = parse_s3_address(
            &address::parse("s3://example-bucket/x%FF").unwrap(),
            "example-bucket",
        )
        .expect_err("a non-UTF-8 key has no S3 wire spelling");
        assert_eq!(error.code(), ErrorCode::InvalidArgument);
    }
    fn fallback_table(entries: &[(&str, ConfigValue)]) -> LayerConfig {
        entries
            .iter()
            .map(|(key, value)| ((*key).to_string(), value.clone()))
            .collect()
    }

    fn parse_fallback_endpoint(spelling: &str) -> Result<FallbackPolicy> {
        parse_fallback_policy(
            &fallback_table(&[(FALLBACK_ENDPOINT_KEY, ConfigValue::String(spelling.into()))]),
            "s3",
        )
    }

    fn fallback_endpoint_error(spelling: &str) -> Error {
        parse_fallback_endpoint(spelling)
            .err()
            .unwrap_or_else(|| panic!("{spelling} was accepted"))
    }

    /// The endpoint is the string every fallback host is derived from and, on
    /// an anonymous read, the redirect handed to the caller is built from; a
    /// credential written into it is refused before any client could carry
    /// it, and the refusal never echoes the value.
    #[test]
    fn a_userinfo_bearing_fallback_endpoint_is_refused_at_parse() {
        for spelling in [
            "https://reader:hunter2@store.example.test",
            "https://reader@store.example.test",
            "http://reader:hunter2@127.0.0.1:9000/",
            // `Url` normalizes an empty userinfo away; only the raw authority
            // still shows the `@`.
            "https://@store.example.test",
        ] {
            let error = fallback_endpoint_error(spelling);
            assert_eq!(error.code(), ErrorCode::InvalidArgument, "{spelling}");
            assert!(
                error
                    .message()
                    .contains("`anonymous_fallback_endpoint` on layer `s3`")
                    && error.message().contains("credentials"),
                "{spelling}: {}",
                error.message()
            );
            assert!(
                !error.message().contains("hunter2") && !error.message().contains("reader"),
                "the refusal never echoes the credential: {}",
                error.message()
            );
        }
    }

    /// A query or fragment would land in the wrong component of every request
    /// URL built under the origin; a bare delimiter is refused too, because
    /// the parser would drop it silently.
    #[test]
    fn a_fallback_endpoint_carrying_a_query_or_fragment_is_refused_at_parse() {
        for (spelling, component) in [
            ("http://127.0.0.1:9000/?x-id=GetObject", "query"),
            ("http://127.0.0.1:9000/?", "query"),
            ("http://127.0.0.1:9000/#anchor", "fragment"),
            ("http://127.0.0.1:9000/#", "fragment"),
        ] {
            let error = fallback_endpoint_error(spelling);
            assert_eq!(error.code(), ErrorCode::InvalidArgument, "{spelling}");
            assert!(
                error
                    .message()
                    .contains("`anonymous_fallback_endpoint` on layer `s3`")
                    && error.message().contains(component),
                "{spelling}: {}",
                error.message()
            );
        }
    }

    /// Only a bare `http` or `https` origin is an endpoint: the host
    /// derivation keeps scheme, host and port and nothing else, so a scheme
    /// it cannot dial, a missing host, or a path it would drop silently is
    /// refused rather than half-honoured.
    #[test]
    fn a_fallback_endpoint_that_is_not_a_bare_http_origin_is_refused_at_parse() {
        for (spelling, complaint) in [
            ("minio:9000", "http or https"),
            ("ftp://store.example.test", "http or https"),
            ("127.0.0.1:9000", "absolute URL"),
            ("http:///", "host"),
            ("http://store.example.test/prefix", "path"),
        ] {
            let error = fallback_endpoint_error(spelling);
            assert_eq!(error.code(), ErrorCode::InvalidArgument, "{spelling}");
            assert!(
                error
                    .message()
                    .contains("`anonymous_fallback_endpoint` on layer `s3`")
                    && error.message().contains(complaint),
                "{spelling}: {}",
                error.message()
            );
        }
    }

    /// What passes is kept as scheme, host and port only, as `derive_host`
    /// and `sdk_endpoint_url` read it: the scheme and host fold to lower
    /// case, a default port drops, an IPv6 host keeps its brackets, and a
    /// trailing slash is the same origin.
    #[test]
    fn the_fallback_endpoint_is_kept_as_a_bare_origin() {
        for (spelling, expected) in [
            (
                "HTTPS://Store.Example.Test:443/",
                "https://store.example.test/",
            ),
            ("http://127.0.0.1:9000", "http://127.0.0.1:9000/"),
            ("http://127.0.0.1:9000/", "http://127.0.0.1:9000/"),
            ("http://[::1]:9000", "http://[::1]:9000/"),
        ] {
            let parsed =
                parse_fallback_endpoint(spelling).unwrap_or_else(|err| panic!("{spelling}: {err}"));
            assert_eq!(parsed.endpoint_str(), Some(expected), "{spelling}");
            assert_eq!(
                parsed.compatibility,
                CompatibilityProfile::Custom,
                "an endpoint defaults the profile to custom"
            );
        }
        assert_eq!(
            parse_fallback_policy(&fallback_table(&[]), "s3")
                .unwrap()
                .endpoint,
            None,
            "no key, no endpoint"
        );
    }
}
