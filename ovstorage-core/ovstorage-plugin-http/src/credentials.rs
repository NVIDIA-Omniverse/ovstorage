// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The credential channels one HTTP connection holds.
//!
//! A bundle may carry HTTP Basic or Bearer authorization, a prefix-scoped
//! signed query, and an explicit set of secret-bearing headers. All channels
//! are resolved together so an invalid replacement is rejected before a live
//! connection swaps away from its previous credential.

use std::fmt;

use base64::Engine;
use ovstorage_plugin::address;
use ovstorage_plugin::{Error, ErrorCode, Result, SecretBundle, SecretValue, Url};
use zeroize::Zeroizing;

/// A credential component lifted out of `SecretBytes`.
///
/// `Zeroizing` wipes the owned copy on drop. It deliberately does not provide
/// redacted `Debug`, so every enclosing credential type implements `Debug` by
/// hand.
pub(crate) type SecretText = Zeroizing<String>;

/// Keys this backend accepts. A bundle naming anything else is rejected rather
/// than partially honoured.
pub(crate) const KNOWN_CREDENTIAL_FIELDS: &[&str] = &[
    "bearer_token",
    "username",
    "password",
    "signed_query",
    "secret_headers",
];

/// Header names `secret_headers` refuses. A credential may authenticate a
/// request, but it may not choose the authority, frame the message, or override
/// operation-specific conditions.
pub(crate) const REFUSED_SECRET_HEADER_NAMES: &[&str] = &[
    "host",
    "connection",
    "proxy-connection",
    "content-length",
    "transfer-encoding",
    "te",
    "trailer",
    "upgrade",
    "range",
    "if-match",
];

/// The declared `Authorization` credential, if any.
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum HttpCredential {
    Bearer(SecretText),
    Basic {
        username: SecretText,
        password: SecretText,
    },
}

impl fmt::Debug for HttpCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bearer(_) => f.write_str("Bearer(<redacted>)"),
            Self::Basic { .. } => f.write_str("Basic(<redacted>)"),
        }
    }
}

/// Which declared field owns the `Authorization` value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AuthorizationShape {
    Bearer,
    Basic,
    SecretHeader,
}

/// The stable channel set a rotation must preserve.
///
/// Header names and multiplicity are included: changing an API-key header into
/// a cookie is a credential-shape change even though both values use the
/// `secret_headers` field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CredentialShape {
    authorization: Option<AuthorizationShape>,
    signed_query: bool,
    secret_headers: Vec<(String, usize)>,
}

/// The complete credential snapshot one operation presents.
#[derive(Clone, Default)]
pub(crate) struct HttpCredentials {
    authorization: Option<reqwest::header::HeaderValue>,
    signed_query: Option<SecretText>,
    secret_headers: reqwest::header::HeaderMap,
    shape: Option<CredentialShape>,
}

impl fmt::Debug for HttpCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpCredentials")
            .field("authorization", &"<redacted>")
            .field("signed_query", &"<redacted>")
            .field("secret_headers", &"<redacted>")
            .field("shape", &self.shape)
            .finish()
    }
}

impl HttpCredentials {
    pub(crate) fn is_anonymous(&self) -> bool {
        self.authorization.is_none()
            && self.signed_query.is_none()
            && self.secret_headers.is_empty()
    }

    pub(crate) fn writes_authorization(&self) -> bool {
        self.authorization.is_some()
            || self
                .secret_headers
                .contains_key(reqwest::header::AUTHORIZATION)
    }

    pub(crate) fn shape(&self) -> CredentialShape {
        self.shape.clone().unwrap_or_else(|| CredentialShape {
            authorization: None,
            signed_query: false,
            secret_headers: Vec::new(),
        })
    }
}

/// The scope family an operator declares for a held signed query.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SignedQueryScope {
    Prefix,
    Object,
}

pub(crate) fn parse_signed_query_scope(raw: &str) -> Result<SignedQueryScope> {
    match raw {
        "prefix" => Ok(SignedQueryScope::Prefix),
        "object" => Ok(SignedQueryScope::Object),
        other => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("unknown HTTP signed_query_scope '{other}' (expected 'prefix', 'object')"),
        )),
    }
}

/// The scope inferred from a signed query's parameter names and, for a
/// CloudFront custom policy, its decoded resource.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SignatureFamily {
    PerObject,
    PrefixScoped,
    Unrecognized,
}

fn query_parameter<'a>(query: &'a str, wanted: &str) -> Option<&'a str> {
    query.split('&').find_map(|pair| {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        name.eq_ignore_ascii_case(wanted).then_some(value)
    })
}

/// Decode a CloudFront custom policy and return its one resource pattern.
///
/// CloudFront's URL-safe alphabet uses `-`, `_`, and `~` in place of `+`, `=`,
/// and `/`. A custom policy that cannot be decoded, has multiple resources, or
/// uses a wildcard anywhere except the final byte is refused rather than
/// guessed into a connection-wide scope.
fn cloudfront_resource(query: &str) -> Result<Option<String>> {
    let has_key_pair = query_parameter(query, "Key-Pair-Id").is_some();
    let Some(policy) = query_parameter(query, "Policy") else {
        return Ok(None);
    };
    if !has_key_pair {
        return Ok(None);
    }
    let standard = policy.replace('-', "+").replace('_', "=").replace('~', "/");
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(standard)
        .map_err(|_| {
            Error::new(
                ErrorCode::InvalidArgument,
                "the signed_query contains a CloudFront custom policy that is not valid base64",
            )
        })?;
    let document: serde_json::Value = serde_json::from_slice(&decoded).map_err(|_| {
        Error::new(
            ErrorCode::InvalidArgument,
            "the signed_query contains a CloudFront custom policy that is not valid JSON",
        )
    })?;
    let statements = document
        .get("Statement")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            Error::new(
                ErrorCode::InvalidArgument,
                "the signed_query CloudFront policy has no Statement array",
            )
        })?;
    if statements.len() != 1 {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "the signed_query CloudFront policy must name exactly one Resource",
        ));
    }
    let resource = statements[0]
        .get("Resource")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            Error::new(
                ErrorCode::InvalidArgument,
                "the signed_query CloudFront policy has no string Resource",
            )
        })?;
    let wildcard_prefix = resource.strip_suffix('*');
    if wildcard_prefix.unwrap_or(resource).contains('*') {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "the signed_query CloudFront policy uses a wildcard this backend cannot scope",
        ));
    }
    Ok(Some(resource.to_string()))
}

/// Classify the families whose wire shapes are unambiguous.
pub(crate) fn classify_signed_query(query: &str) -> SignatureFamily {
    let has_amz_signature = query_parameter(query, "X-Amz-Signature").is_some();
    let azure_sr = query_parameter(query, "sr");
    let has_azure_ss = query_parameter(query, "ss").is_some();
    let has_azure_srt = query_parameter(query, "srt").is_some();
    let has_key_pair = query_parameter(query, "Key-Pair-Id").is_some();
    let has_expires = query_parameter(query, "Expires").is_some();
    let has_policy = query_parameter(query, "Policy").is_some();

    let azure_blob = azure_sr.is_some_and(|value| {
        ["b", "bs", "bv"]
            .iter()
            .any(|kind| value.eq_ignore_ascii_case(kind))
    });
    let cloudfront_canned = has_key_pair && has_expires && !has_policy;
    if has_amz_signature || azure_blob || cloudfront_canned {
        return SignatureFamily::PerObject;
    }

    let azure_account = has_azure_ss && has_azure_srt;
    let azure_container = azure_sr.is_some_and(|value| {
        ["c", "d"]
            .iter()
            .any(|kind| value.eq_ignore_ascii_case(kind))
    });
    if azure_account || azure_container {
        return SignatureFamily::PrefixScoped;
    }

    SignatureFamily::Unrecognized
}

fn validate_known_fields(bundle: &SecretBundle) -> Result<()> {
    for key in bundle.fields.keys() {
        if !KNOWN_CREDENTIAL_FIELDS.contains(&key.as_str()) {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "unknown HTTP credential field '{key}' (expected one of: {})",
                    KNOWN_CREDENTIAL_FIELDS.join(", ")
                ),
            ));
        }
    }
    Ok(())
}

fn raw_text_field(bundle: &SecretBundle, key: &str) -> Result<Option<SecretText>> {
    let Some(value) = bundle.fields.get(key) else {
        return Ok(None);
    };
    let bytes = match value {
        SecretValue::Bytes(bytes) => bytes,
        _ => {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "HTTP credential field '{key}' must be supplied as raw bytes; \
                     this backend accepts no file, certificate or refreshable secret"
                ),
            ));
        }
    };
    let text = std::str::from_utf8(bytes.as_bytes()).map_err(|_| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("HTTP credential field '{key}' is not valid UTF-8"),
        )
    })?;
    Ok(Some(Zeroizing::new(text.to_string())))
}

/// Read a single-field credential whose text may not contain controls.
fn string_field(bundle: &SecretBundle, key: &str) -> Result<SecretText> {
    let text = raw_text_field(bundle, key)?.ok_or_else(|| {
        Error::new(
            ErrorCode::Internal,
            format!("HTTP credential field '{key}' vanished during classification"),
        )
    })?;
    if let Some(offset) = text.find(|c: char| c.is_ascii_control()) {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "HTTP credential field '{key}' contains a control character at byte {offset} \
                 (a trailing newline from reading the secret out of a file is the usual cause)"
            ),
        ));
    }
    Ok(text)
}

fn classify_authorization(bundle: &SecretBundle) -> Result<Option<HttpCredential>> {
    let has_bearer = bundle.fields.contains_key("bearer_token");
    let has_username = bundle.fields.contains_key("username");
    let has_password = bundle.fields.contains_key("password");

    if has_bearer && (has_username || has_password) {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "HTTP credentials must supply either 'bearer_token' or 'username' and 'password', not both",
        ));
    }
    if has_bearer {
        let token = string_field(bundle, "bearer_token")?;
        if token.is_empty() {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "HTTP credential field 'bearer_token' is empty",
            ));
        }
        return Ok(Some(HttpCredential::Bearer(token)));
    }
    match (has_username, has_password) {
        (true, true) => {
            let username = string_field(bundle, "username")?;
            if username.contains(':') {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    "HTTP credential field 'username' must not contain ':'",
                ));
            }
            let password = string_field(bundle, "password")?;
            if username.is_empty() && password.is_empty() {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    "HTTP basic credentials must supply a non-empty 'username' or 'password'",
                ));
            }
            Ok(Some(HttpCredential::Basic { username, password }))
        }
        (false, false) => Ok(None),
        _ => Err(Error::new(
            ErrorCode::InvalidArgument,
            "HTTP basic credentials require both 'username' and 'password'",
        )),
    }
}

/// Classify the legacy Authorization-only shapes. Kept as a focused helper for
/// unit coverage; connection construction uses [`resolve_credentials`].
#[cfg(test)]
pub(crate) fn classify(bundle: &SecretBundle) -> Result<Option<HttpCredential>> {
    validate_known_fields(bundle)?;
    if bundle.fields.contains_key("signed_query") || bundle.fields.contains_key("secret_headers") {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "signed_query and secret_headers require full HTTP credential resolution",
        ));
    }
    classify_authorization(bundle)
}

pub(crate) fn credential_header(
    credential: &HttpCredential,
) -> Result<reqwest::header::HeaderValue> {
    let raw = match credential {
        HttpCredential::Bearer(token) => {
            let mut raw = Zeroizing::new(String::with_capacity("Bearer ".len() + token.len()));
            raw.push_str("Bearer ");
            raw.push_str(token);
            raw
        }
        HttpCredential::Basic { username, password } => {
            let mut pair = Zeroizing::new(String::with_capacity(
                username
                    .len()
                    .saturating_add(1)
                    .saturating_add(password.len()),
            ));
            pair.push_str(username);
            pair.push(':');
            pair.push_str(password);
            let encoded =
                Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(pair.as_bytes()));
            let mut raw = Zeroizing::new(String::with_capacity("Basic ".len() + encoded.len()));
            raw.push_str("Basic ");
            raw.push_str(&encoded);
            raw
        }
    };
    let mut value = reqwest::header::HeaderValue::from_str(&raw).map_err(|_| {
        Error::new(
            ErrorCode::InvalidArgument,
            "HTTP credential is not representable as an Authorization header value",
        )
    })?;
    value.set_sensitive(true);
    Ok(value)
}

/// Parse the `secret_headers` credential: one `Name: Value` per line.
pub(crate) fn parse_secret_headers(raw: Option<&str>) -> Result<reqwest::header::HeaderMap> {
    let mut map = reqwest::header::HeaderMap::new();
    let Some(raw) = raw else {
        return Ok(map);
    };
    for (index, line) in raw.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let position = index + 1;
        let Some((name, value)) = line.split_once(':') else {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "malformed secret_headers entry at line {position} (expected 'Name: Value', one header per line)"
                ),
            ));
        };
        let header_name: reqwest::header::HeaderName = name.trim().parse().map_err(|_| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!("invalid header name in secret_headers entry at line {position}"),
            )
        })?;
        if REFUSED_SECRET_HEADER_NAMES.contains(&header_name.as_str()) {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "secret_headers must not set '{}': it names the authority, frames the message, or belongs to the data path",
                    header_name.as_str()
                ),
            ));
        }
        if (header_name == reqwest::header::AUTHORIZATION
            || header_name == reqwest::header::PROXY_AUTHORIZATION)
            && map.contains_key(&header_name)
        {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "secret_headers sets '{}' more than once; supply exactly one",
                    header_name.as_str()
                ),
            ));
        }
        let mut header_value =
            reqwest::header::HeaderValue::from_str(value.trim()).map_err(|_| {
                Error::new(
                    ErrorCode::InvalidArgument,
                    format!("invalid header value in secret_headers entry at line {position}"),
                )
            })?;
        header_value.set_sensitive(true);
        map.append(header_name, header_value);
    }
    Ok(map)
}

fn header_shape(headers: &reqwest::header::HeaderMap) -> Vec<(String, usize)> {
    let mut names: Vec<(String, usize)> = headers
        .keys()
        .map(|name| {
            (
                name.as_str().to_string(),
                headers.get_all(name).iter().count(),
            )
        })
        .collect();
    names.sort_unstable();
    names.dedup();
    names
}

/// Resolve every credential channel and its immutable rotation shape.
pub(crate) fn resolve_credentials(
    bundle: &SecretBundle,
    scope: Option<SignedQueryScope>,
    root_url: &Url,
) -> Result<HttpCredentials> {
    validate_known_fields(bundle)?;
    let authorization_credential = classify_authorization(bundle)?;
    let authorization_shape = match authorization_credential.as_ref() {
        Some(HttpCredential::Bearer(_)) => Some(AuthorizationShape::Bearer),
        Some(HttpCredential::Basic { .. }) => Some(AuthorizationShape::Basic),
        None => None,
    };
    let authorization = authorization_credential
        .as_ref()
        .map(credential_header)
        .transpose()?;

    let signed_query = raw_text_field(bundle, "signed_query")?
        .map(|raw| {
            let query = raw.strip_prefix('?').unwrap_or(&raw);
            if query.is_empty() {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    "HTTP credential field 'signed_query' is empty",
                ));
            }
            if query.chars().any(char::is_control) || query.contains('#') {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    "HTTP credential field 'signed_query' contains bytes a URL query cannot preserve",
                ));
            }
            Ok(Zeroizing::new(query.to_string()))
        })
        .transpose()?;

    let secret_headers_raw = raw_text_field(bundle, "secret_headers")?;
    let secret_headers =
        parse_secret_headers(secret_headers_raw.as_ref().map(|text| text.as_str()))?;
    if secret_headers_raw.is_some() && secret_headers.is_empty() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "HTTP credential field 'secret_headers' contains no headers",
        ));
    }

    match (signed_query.as_deref(), scope) {
        (Some(_), None) => {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "a signed_query credential requires signed_query_scope ('prefix' or 'object')",
            ));
        }
        (None, Some(_)) => {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "signed_query_scope is set but no signed_query credential is supplied",
            ));
        }
        (Some(_), Some(SignedQueryScope::Object)) => {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "signed_query_scope 'object' names a per-object signature, which a connection cannot hold; dispatch the presign as a per-request address",
            ));
        }
        (Some(query), Some(SignedQueryScope::Prefix)) => {
            if classify_signed_query(query) == SignatureFamily::PerObject {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    "signed_query_scope declares 'prefix' but the signed_query parameters name a per-object signature",
                ));
            }
            if let Some(resource) = cloudfront_resource(query)? {
                let Some(prefix) = resource.strip_suffix('*') else {
                    return Err(Error::new(
                        ErrorCode::InvalidArgument,
                        "the signed_query CloudFront policy names one exact object, not a prefix",
                    ));
                };
                if !root_url.as_str().starts_with(prefix) {
                    return Err(Error::new(
                        ErrorCode::InvalidArgument,
                        "the signed_query CloudFront policy Resource does not cover root_url",
                    ));
                }
            }
        }
        (None, None) => {}
    }

    if authorization.is_some() && secret_headers.contains_key(reqwest::header::AUTHORIZATION) {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "the declared bearer/basic credential and secret_headers both write Authorization; supply exactly one",
        ));
    }

    let authorization_shape = if secret_headers.contains_key(reqwest::header::AUTHORIZATION) {
        Some(AuthorizationShape::SecretHeader)
    } else {
        authorization_shape
    };
    let shape = CredentialShape {
        authorization: authorization_shape,
        signed_query: signed_query.is_some(),
        secret_headers: header_shape(&secret_headers),
    };
    Ok(HttpCredentials {
        authorization,
        signed_query,
        secret_headers,
        shape: Some(shape),
    })
}

/// Append the held query textually, preserving its bytes and order.
pub(crate) fn sign_url(credentials: &HttpCredentials, url: &Url) -> Result<Url> {
    let Some(query) = credentials.signed_query.as_deref() else {
        return Ok(url.clone());
    };
    let serialized = url.as_str();
    let (base, fragment) = serialized
        .split_once('#')
        .map_or((serialized, None), |(base, fragment)| {
            (base, Some(fragment))
        });
    let separator = if base.contains('?') { '&' } else { '?' };
    let mut signed = Zeroizing::new(format!("{base}{separator}{query}"));
    if let Some(fragment) = fragment {
        signed.push('#');
        signed.push_str(fragment);
    }
    let parsed = address::parse(&signed)?;
    let expected_query = base
        .split_once('?')
        .map(|(_, existing)| format!("{existing}&{query}"))
        .unwrap_or_else(|| query.to_string());
    if parsed.query() != Some(expected_query.as_str()) {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "the signed_query contains bytes the URL parser cannot preserve",
        ));
    }
    Ok(parsed)
}

/// Remove one whole-parameter occurrence of the held query from a redirect
/// target so the next request adds it exactly once.
pub(crate) fn strip_held_query(credentials: &HttpCredentials, url: &Url) -> Result<Url> {
    let Some(held) = credentials.signed_query.as_deref() else {
        return Ok(url.clone());
    };
    let serialized = url.as_str();
    let (base, fragment) = serialized
        .split_once('#')
        .map_or((serialized, None), |(base, fragment)| {
            (base, Some(fragment))
        });
    let Some((head, query)) = base.split_once('?') else {
        return Ok(url.clone());
    };
    let held_pairs: Vec<&str> = held.split('&').collect();
    let pairs: Vec<&str> = query.split('&').collect();
    let Some(at) = pairs.len().checked_sub(held_pairs.len()) else {
        return Ok(url.clone());
    };
    if pairs[at..] != held_pairs {
        return Ok(url.clone());
    }
    let remaining = pairs[..at].join("&");
    let mut stripped = Zeroizing::new(head.to_string());
    if !remaining.is_empty() {
        stripped.push('?');
        stripped.push_str(&remaining);
    }
    if let Some(fragment) = fragment {
        stripped.push('#');
        stripped.push_str(fragment);
    }
    address::parse(&stripped)
}

/// Attach every header credential to one request.
pub(crate) fn apply_credential_headers(
    mut request: reqwest::RequestBuilder,
    credentials: &HttpCredentials,
) -> reqwest::RequestBuilder {
    if let Some(value) = credentials.authorization.as_ref() {
        request = request.header(reqwest::header::AUTHORIZATION, value.clone());
    }
    for (name, value) in &credentials.secret_headers {
        request = request.header(name, value.clone());
    }
    request
}

#[cfg(test)]
mod tests {
    use super::*;
    use ovstorage_plugin::SecretBytes;

    fn bundle(pairs: &[(&str, &str)]) -> SecretBundle {
        let mut bundle = SecretBundle::default();
        for (key, value) in pairs {
            bundle.fields.insert(
                (*key).to_string(),
                SecretValue::Bytes(SecretBytes(value.as_bytes().to_vec())),
            );
        }
        bundle
    }

    fn root() -> Url {
        address::parse("https://cdn.example/media/").unwrap()
    }

    #[test]
    fn bearer_and_basic_classify() {
        assert!(matches!(
            classify(&bundle(&[("bearer_token", "tok")])).unwrap(),
            Some(HttpCredential::Bearer(_))
        ));
        assert!(matches!(
            classify(&bundle(&[("username", "u"), ("password", "p")])).unwrap(),
            Some(HttpCredential::Basic { .. })
        ));
    }

    #[test]
    fn malformed_authorization_shapes_are_rejected() {
        for pairs in [
            vec![("bearer_token", "")],
            vec![("username", "u")],
            vec![("password", "p")],
            vec![("username", ""), ("password", "")],
            vec![("bearer_token", "t"), ("username", "u")],
        ] {
            assert_eq!(
                classify(&bundle(&pairs)).unwrap_err().code(),
                ErrorCode::InvalidArgument
            );
        }
    }

    #[test]
    fn signed_query_families_are_classified() {
        assert_eq!(
            classify_signed_query("X-Amz-Signature=abc"),
            SignatureFamily::PerObject
        );
        assert_eq!(
            classify_signed_query("sv=1&sr=c&sig=abc"),
            SignatureFamily::PrefixScoped
        );
        assert_eq!(
            classify_signed_query("vendor_grant=abc"),
            SignatureFamily::Unrecognized
        );
    }

    fn cloudfront_query(resource: &str) -> String {
        let policy = serde_json::json!({
            "Statement": [{
                "Resource": resource,
                "Condition": {"DateLessThan": {"AWS:EpochTime": 2_000_000_000_u64}}
            }]
        });
        let encoded = base64::engine::general_purpose::STANDARD
            .encode(serde_json::to_vec(&policy).unwrap())
            .replace('+', "-")
            .replace('=', "_")
            .replace('/', "~");
        format!("Policy={encoded}&Key-Pair-Id=K1&Signature=opaque")
    }

    #[test]
    fn cloudfront_custom_policy_must_cover_the_root_with_one_trailing_wildcard() {
        let allowed = cloudfront_query("https://cdn.example/media/*");
        resolve_credentials(
            &bundle(&[("signed_query", &allowed)]),
            Some(SignedQueryScope::Prefix),
            &root(),
        )
        .expect("the custom policy wildcard covers the root");

        for resource in [
            "https://cdn.example/media/one.bin",
            "https://cdn.example/private/*",
            "https://cdn.example/*/one.bin",
            "https://cdn.example/media/é",
        ] {
            let error = resolve_credentials(
                &bundle(&[("signed_query", &cloudfront_query(resource))]),
                Some(SignedQueryScope::Prefix),
                &root(),
            )
            .unwrap_err();
            assert_eq!(error.code(), ErrorCode::InvalidArgument, "{resource}");
        }
    }

    #[test]
    fn signed_query_is_preserved_and_appended() {
        let credentials = resolve_credentials(
            &bundle(&[("signed_query", "?sv=1&sr=c&sig=a%2Fb%2Bc%3D")]),
            Some(SignedQueryScope::Prefix),
            &root(),
        )
        .unwrap();
        let signed = sign_url(
            &credentials,
            &address::parse("https://cdn.example/media/a.bin?v=2").unwrap(),
        )
        .unwrap();
        assert_eq!(signed.query(), Some("v=2&sv=1&sr=c&sig=a%2Fb%2Bc%3D"));
    }

    #[test]
    fn redirect_cleanup_removes_only_the_appended_query_suffix() {
        let credentials = resolve_credentials(
            &bundle(&[("signed_query", "grant=held")]),
            Some(SignedQueryScope::Prefix),
            &root(),
        )
        .unwrap();
        let echoed = address::parse("https://cdn.example/media/a?caller=1&grant=held").unwrap();
        assert_eq!(
            strip_held_query(&credentials, &echoed).unwrap().query(),
            Some("caller=1")
        );

        let caller_owned =
            address::parse("https://cdn.example/media/a?grant=held&caller=1").unwrap();
        assert_eq!(
            strip_held_query(&credentials, &caller_owned)
                .unwrap()
                .query(),
            Some("grant=held&caller=1"),
            "a matching caller parameter in the middle is not the appended credential"
        );
    }

    #[test]
    fn secret_headers_are_sensitive_and_shape_is_exact() {
        let credentials = resolve_credentials(
            &bundle(&[(
                "secret_headers",
                "X-Api-Key: one\nX-Api-Key: two\nCookie: sid=abc",
            )]),
            None,
            &root(),
        )
        .unwrap();
        assert!(!credentials.is_anonymous());
        assert_eq!(
            credentials.shape().secret_headers,
            vec![("cookie".into(), 1), ("x-api-key".into(), 2)]
        );
        assert!(!format!("{credentials:?}").contains("sid=abc"));
    }

    #[test]
    fn authorization_writers_conflict() {
        let error = resolve_credentials(
            &bundle(&[
                ("bearer_token", "tok"),
                ("secret_headers", "Authorization: Token other"),
            ]),
            None,
            &root(),
        )
        .unwrap_err();
        assert_eq!(error.code(), ErrorCode::InvalidArgument);
        assert!(!error.message().contains("other"));
    }

    #[test]
    fn unknown_and_non_bytes_fields_are_rejected() {
        let error = resolve_credentials(&bundle(&[("bearer_tokn", "s3cret-value")]), None, &root())
            .unwrap_err();
        assert!(error.message().contains("bearer_tokn"));
        assert!(!error.message().contains("s3cret-value"));

        let mut non_bytes = SecretBundle::default();
        non_bytes.fields.insert(
            "bearer_token".into(),
            SecretValue::OAuthToken {
                token: SecretBytes(b"tok".to_vec()),
                refresh: None,
                expires_at: None,
            },
        );
        assert_eq!(
            resolve_credentials(&non_bytes, None, &root())
                .unwrap_err()
                .code(),
            ErrorCode::InvalidArgument
        );
    }
}
