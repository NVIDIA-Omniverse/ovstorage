// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OIDC bearer JWT validator for the REST gateway.
//!
//! Validates a JWT against a JWKS document fetched from a configured
//! URL. JWKS is cached with a TTL and refreshed on TTL expiry or
//! unknown `kid` so routine IdP key rotation does not require a restart.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, UNIX_EPOCH};

use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{DecodingKey, Validation, decode, decode_header};
use ovstorage::{Error, ErrorCode};
use ovstorage_authz::Principal;
use serde::Deserialize;
use serde_json::Value;

const DEFAULT_JWKS_TTL: Duration = Duration::from_secs(600);
const DEFAULT_JWKS_FETCH_TIMEOUT: Duration = Duration::from_secs(10);

struct CachedJwks {
    jwks: JwkSet,
    fetched_at: Instant,
}

pub struct JwtAuthenticator {
    issuer: String,
    audience: String,
    jwks_url: String,
    jwks_cache: Arc<Mutex<Option<CachedJwks>>>,
    http: reqwest::Client,
    ttl: Duration,
}

impl JwtAuthenticator {
    pub fn new(issuer: String, audience: String, jwks_url: String) -> Self {
        Self::with_ttl(issuer, audience, jwks_url, DEFAULT_JWKS_TTL)
    }

    pub fn with_ttl(issuer: String, audience: String, jwks_url: String, ttl: Duration) -> Self {
        let http = reqwest::Client::builder()
            .connect_timeout(DEFAULT_JWKS_FETCH_TIMEOUT)
            .timeout(DEFAULT_JWKS_FETCH_TIMEOUT)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            issuer,
            audience,
            jwks_url,
            jwks_cache: Arc::new(Mutex::new(None)),
            http,
            ttl,
        }
    }

    /// Validate a Bearer token and return the decoded `Principal`;
    /// errors carry `ErrorCode::AuthRequired` (mapped to `401`).
    pub async fn authenticate(&self, bearer: &str) -> ovstorage::Result<Principal> {
        let header = decode_header(bearer).map_err(|error| {
            Error::new(
                ErrorCode::AuthRequired,
                format!("invalid bearer JWT header: {error}"),
            )
        })?;
        let kid = header.kid.as_deref().unwrap_or("<none>");
        let mut jwks = self.cached_jwks().await?;
        let jwk = match resolve_key(&jwks, header.kid.as_deref()) {
            KeyResolution::Found(jwk) => jwk,
            KeyResolution::UnknownKid => {
                tracing::warn!(
                    target: "ovstorage.rest.jwt",
                    kid,
                    "unknown kid; triggering JWKS refetch"
                );
                jwks = self.refresh_jwks().await?;
                match resolve_key(&jwks, header.kid.as_deref()) {
                    KeyResolution::Found(jwk) => jwk,
                    _ => {
                        tracing::debug!(
                            target: "ovstorage.rest.jwt",
                            kid,
                            outcome = "reject",
                            "JWT validation failed: kid not found after JWKS refetch"
                        );
                        return Err(Error::new(
                            ErrorCode::AuthRequired,
                            "bearer JWT key id is not present in JWKS",
                        ));
                    }
                }
            }
            KeyResolution::AmbiguousMissingKid => {
                tracing::debug!(
                    target: "ovstorage.rest.jwt",
                    outcome = "reject",
                    "JWT validation failed: missing kid with multiple JWKS keys"
                );
                return Err(Error::new(
                    ErrorCode::AuthRequired,
                    "bearer JWT is missing kid and JWKS contains multiple keys",
                ));
            }
            KeyResolution::EmptyJwks => {
                tracing::debug!(
                    target: "ovstorage.rest.jwt",
                    outcome = "reject",
                    "JWT validation failed: JWKS is empty"
                );
                return Err(Error::new(ErrorCode::AuthRequired, "JWKS is empty"));
            }
        };
        let key = DecodingKey::from_jwk(jwk).map_err(|error| {
            Error::new(
                ErrorCode::AuthRequired,
                format!("invalid JWKS key for bearer JWT: {error}"),
            )
        })?;
        let mut validation = Validation::new(header.alg);
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&[&self.audience]);
        validation.validate_nbf = true;
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        let claims = decode::<JwtClaims>(bearer, &key, &validation)
            .map_err(|error| {
                tracing::debug!(
                    target: "ovstorage.rest.jwt",
                    kid,
                    outcome = "reject",
                    "JWT validation failed: {}", error
                );
                Error::new(
                    ErrorCode::AuthRequired,
                    format!("bearer JWT validation failed: {error}"),
                )
            })?
            .claims;
        let principal = principal_from_claims(claims, "jwt_verify")?;
        tracing::debug!(
            target: "ovstorage.rest.jwt",
            kid,
            principal.id = %principal.id,
            outcome = "ok",
            "JWT validation succeeded"
        );
        Ok(principal)
    }

    async fn cached_jwks(&self) -> ovstorage::Result<JwkSet> {
        if let Some(entry) = self.peek_fresh()? {
            return Ok(entry);
        }
        self.refresh_jwks().await
    }

    fn peek_fresh(&self) -> ovstorage::Result<Option<JwkSet>> {
        let guard = self
            .jwks_cache
            .lock()
            .map_err(|_| Error::new(ErrorCode::Internal, "JWKS cache lock is poisoned"))?;
        Ok(guard
            .as_ref()
            .filter(|entry| entry.fetched_at.elapsed() < self.ttl)
            .map(|entry| entry.jwks.clone()))
    }

    async fn refresh_jwks(&self) -> ovstorage::Result<JwkSet> {
        let url = &self.jwks_url;
        let jwks = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|error| {
                Error::new(
                    ErrorCode::Transient,
                    format!("failed to fetch JWKS from '{url}': {error}"),
                )
            })?
            .error_for_status()
            .map_err(|error| {
                Error::new(
                    ErrorCode::Transient,
                    format!("JWKS request failed for '{url}': {error}"),
                )
            })?
            .json::<JwkSet>()
            .await
            .map_err(|error| {
                Error::new(
                    ErrorCode::AuthRequired,
                    format!("JWKS document from '{url}' is invalid: {error}"),
                )
            })?;
        let mut guard = self
            .jwks_cache
            .lock()
            .map_err(|_| Error::new(ErrorCode::Internal, "JWKS cache lock is poisoned"))?;
        *guard = Some(CachedJwks {
            jwks: jwks.clone(),
            fetched_at: Instant::now(),
        });
        Ok(jwks)
    }
}

enum KeyResolution<'a> {
    Found(&'a jsonwebtoken::jwk::Jwk),
    UnknownKid,
    AmbiguousMissingKid,
    EmptyJwks,
}

fn resolve_key<'a>(jwks: &'a JwkSet, kid: Option<&str>) -> KeyResolution<'a> {
    match kid {
        Some(kid) => match jwks.find(kid) {
            Some(jwk) => KeyResolution::Found(jwk),
            None => KeyResolution::UnknownKid,
        },
        None if jwks.keys.len() == 1 => KeyResolution::Found(&jwks.keys[0]),
        None if jwks.keys.is_empty() => KeyResolution::EmptyJwks,
        None => KeyResolution::AmbiguousMissingKid,
    }
}

#[derive(Clone, Debug, Deserialize)]
struct JwtClaims {
    sub: Option<String>,
    exp: Option<u64>,
    #[allow(dead_code)]
    nbf: Option<u64>,
    iss: Option<String>,
    aud: Option<Value>,
    #[serde(flatten)]
    extra: HashMap<String, Value>,
}

fn principal_from_claims(claims: JwtClaims, source: &str) -> ovstorage::Result<Principal> {
    let id = claims
        .sub
        .clone()
        .filter(|sub| !sub.trim().is_empty())
        .ok_or_else(|| Error::new(ErrorCode::AuthRequired, "JWT subject claim is required"))?;
    let mut attributes = HashMap::new();
    if let Some(issuer) = claims.iss {
        attributes.insert("jwt.issuer".into(), issuer);
    }
    if let Some(audience) = claims.aud.as_ref().and_then(jwt_value_to_string) {
        attributes.insert("jwt.audience".into(), audience);
    }
    for (key, value) in &claims.extra {
        if let Some(value) = jwt_value_to_string(value) {
            attributes.insert(key.clone(), value);
        }
    }
    let display_name = claims
        .extra
        .get("name")
        .and_then(jwt_value_to_string)
        .or_else(|| {
            claims
                .extra
                .get("preferred_username")
                .and_then(jwt_value_to_string)
        });
    Ok(Principal {
        id,
        display_name,
        attributes,
        valid_until: claims
            .exp
            .and_then(|exp| UNIX_EPOCH.checked_add(Duration::from_secs(exp))),
        source: source.into(),
    })
}

fn jwt_value_to_string(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        Value::Array(values) => Some(
            values
                .iter()
                .filter_map(jwt_value_to_string)
                .collect::<Vec<_>>()
                .join(","),
        ),
        _ => None,
    }
}
