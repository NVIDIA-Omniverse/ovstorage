// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OIDC bearer JWT validation for the built-in combined auth layer.
//!
//! Ported from the REST gateway's `jwt.rs`: [`principal_from_claims`] (claims →
//! principal) and the JWKS/OIDC validation around it, adapted to the auth
//! layer's [`ResolvedPrincipal`] and `ovstorage` error types. Per-request
//! validation is offline against the [`JwkSet`] held in [`JwtConfig`], snapshot
//! from an [`ArcSwap`]. A background refresher re-fetches the JWKS on a TTL
//! ([`JWKS_REFRESH_INTERVAL`]) so routine IdP signing-key rotation is picked up
//! without an operator reload; an unknown-`kid` bearer additionally nudges the
//! refresher out-of-band (the immediate request still fails, but a retry after
//! the refetch lands succeeds).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::jwk::{AlgorithmParameters, EllipticCurve, Jwk, JwkSet};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use ovstorage::{Error, ErrorCode, Result};
use serde::Deserialize;
use serde_json::Value;
use tokio::sync::Notify;
use tokio::task::JoinHandle;

use crate::ResolvedPrincipal;

const JWKS_FETCH_TIMEOUT: Duration = Duration::from_secs(10);
const JWT_CLOCK_SKEW_LEEWAY: u64 = 60;

/// TTL for the proactive background JWKS refresh — the refresher re-fetches at
/// this cadence so rotated signing keys are picked up during the IdP's overlap
/// window (normally longer than this interval) without an operator reload.
const JWKS_REFRESH_INTERVAL: Duration = Duration::from_secs(300);

/// Owns the background JWKS refresher's [`JoinHandle`] and aborts it on drop, so
/// a SIGHUP-rebuilt layer (which drops the old [`JwtConfig`]) does not leak the
/// task. `None` for test configs built via `JwtConfig::from_jwks`, which spawn
/// no task.
struct RefreshTask(Option<JoinHandle<()>>);

impl Drop for RefreshTask {
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            handle.abort();
        }
    }
}

/// OIDC validation parameters plus the JWKS bearer tokens are validated against.
/// The `jwks` is fetched by the layer factory ([`JwtConfig::fetch`]) and held in
/// an [`ArcSwap`] so per-request [`resolve_jwt`] validation is offline against a
/// lock-free snapshot while the background refresher swaps in rotated keys.
pub(crate) struct JwtConfig {
    issuer: String,
    audience: String,
    jwks: Arc<ArcSwap<JwkSet>>,
    /// Signalled by [`resolve_jwt`] on an unknown `kid` to force an out-of-band
    /// refetch (the rotation backstop).
    refresh: Arc<Notify>,
    /// Abort-on-drop guard for the background refresher task.
    _refresher: RefreshTask,
}

/// Fetch and parse a JWKS document from `jwks_url`. A network/status failure is
/// [`ErrorCode::Transient`]; a malformed document is [`ErrorCode::AuthRequired`]
/// (bad key material, not a retryable outage).
async fn fetch_jwks(http: &reqwest::Client, jwks_url: &str) -> Result<JwkSet> {
    http.get(jwks_url)
        .send()
        .await
        .map_err(|error| {
            Error::new(
                ErrorCode::Transient,
                format!("failed to fetch JWKS from '{jwks_url}': {error}"),
            )
        })?
        .error_for_status()
        .map_err(|error| {
            Error::new(
                ErrorCode::Transient,
                format!("JWKS request failed for '{jwks_url}': {error}"),
            )
        })?
        .json::<JwkSet>()
        .await
        .map_err(|error| {
            Error::new(
                ErrorCode::AuthRequired,
                format!("JWKS document from '{jwks_url}' is invalid: {error}"),
            )
        })
}

impl JwtConfig {
    /// Fetch the initial JWKS from `jwks_url` and build a [`JwtConfig`]. Run at
    /// layer-build time (the factory's `create_wrapper` is async, on a tokio
    /// runtime). The initial fetch/parse failure fails the layer build rather
    /// than admitting unauthenticated callers; once the layer is up a background
    /// task keeps the JWKS fresh (TTL + unknown-`kid` backstop).
    pub(crate) async fn fetch(issuer: String, audience: String, jwks_url: &str) -> Result<Self> {
        let http = reqwest::Client::builder()
            .connect_timeout(JWKS_FETCH_TIMEOUT)
            .timeout(JWKS_FETCH_TIMEOUT)
            .build()
            .map_err(|error| {
                Error::new(
                    ErrorCode::Internal,
                    format!("failed to build JWKS HTTP client: {error}"),
                )
            })?;
        let initial = fetch_jwks(&http, jwks_url).await?;
        let jwks = Arc::new(ArcSwap::from_pointee(initial));
        let refresh = Arc::new(Notify::new());
        let handle = tokio::spawn(refresher_loop(
            http,
            jwks_url.to_string(),
            Arc::clone(&jwks),
            Arc::clone(&refresh),
        ));
        Ok(Self {
            issuer,
            audience,
            jwks,
            refresh,
            _refresher: RefreshTask(Some(handle)),
        })
    }

    /// Construct a config from an in-memory JWKS, bypassing the network fetch and
    /// spawning no background task (so it needs no tokio runtime).
    #[cfg(test)]
    pub(crate) fn from_jwks(issuer: String, audience: String, jwks: JwkSet) -> Self {
        Self {
            issuer,
            audience,
            jwks: Arc::new(ArcSwap::from_pointee(jwks)),
            refresh: Arc::new(Notify::new()),
            _refresher: RefreshTask(None),
        }
    }
}

/// Background JWKS refresher: wakes on the [`JWKS_REFRESH_INTERVAL`] TTL or an
/// out-of-band `refresh` notification, re-fetches, and swaps the new set in. A
/// failed refetch keeps the previous set and the loop continues — a transient
/// IdP outage must not blank the JWKS. Runs until aborted by [`RefreshTask`] on
/// [`JwtConfig`] drop.
async fn refresher_loop(
    http: reqwest::Client,
    jwks_url: String,
    jwks: Arc<ArcSwap<JwkSet>>,
    refresh: Arc<Notify>,
) {
    loop {
        tokio::select! {
            _ = tokio::time::sleep(JWKS_REFRESH_INTERVAL) => {}
            _ = refresh.notified() => {}
        }
        if let Ok(new) = fetch_jwks(&http, &jwks_url).await {
            jwks.store(Arc::new(new));
        }
    }
}

/// Validate an OIDC bearer JWT against `cfg` and resolve the principal. Ported
/// from REST `JwtAuthenticator::authenticate` minus the async JWKS fetch/cache:
/// validation is offline against `cfg.jwks`. Every failure maps to
/// [`ErrorCode::AuthRequired`] — the caller presented bearer material that
/// failed authentication.
pub(crate) fn resolve_jwt(token: &[u8], cfg: &JwtConfig) -> Result<ResolvedPrincipal> {
    let token = std::str::from_utf8(token).map_err(|error| {
        Error::new(
            ErrorCode::AuthRequired,
            format!("bearer JWT is not valid UTF-8: {error}"),
        )
    })?;
    let header = decode_header(token).map_err(|error| {
        Error::new(
            ErrorCode::AuthRequired,
            format!("invalid bearer JWT header: {error}"),
        )
    })?;
    let jwks = cfg.jwks.load();
    let jwk = match resolve_key(&jwks, header.kid.as_deref()) {
        KeyResolution::Found(jwk) => jwk,
        KeyResolution::UnknownKid => {
            // Rotation backstop: the `kid` is absent from the current snapshot,
            // most likely because the IdP rotated its signing keys. Nudge the
            // background refresher to refetch out-of-band; this request still
            // fails, but the client's retry after the new set lands succeeds.
            cfg.refresh.notify_one();
            return Err(Error::new(
                ErrorCode::AuthRequired,
                "bearer JWT key id is not present in JWKS; a JWKS refresh was \
                 triggered — retry shortly",
            ));
        }
        KeyResolution::AmbiguousMissingKid => {
            return Err(Error::new(
                ErrorCode::AuthRequired,
                "bearer JWT is missing kid and JWKS contains multiple keys",
            ));
        }
        KeyResolution::EmptyJwks => {
            return Err(Error::new(ErrorCode::AuthRequired, "JWKS is empty"));
        }
    };
    let key = DecodingKey::from_jwk(jwk).map_err(|error| {
        Error::new(
            ErrorCode::AuthRequired,
            format!("invalid JWKS key for bearer JWT: {error}"),
        )
    })?;
    // The accepted signature algorithms are derived from the RESOLVED KEY's own
    // family (`kty`/curve), never from the attacker-controlled token header. This
    // closes the algorithm-confusion path: a bearer with `alg: HS256` whose `kid`
    // resolves to an RSA/EC key presents a header alg outside the key-family set,
    // so `jsonwebtoken` rejects it with `InvalidAlgorithm` before any
    // family-specific verify arm runs — the HMAC arm can never call `as_bytes()`
    // on an RSA key. Deriving the set from `header.alg` (as `Validation::new`
    // does) would instead admit the token's own claim into the accepted set.
    let algorithms = accepted_algorithms(jwk)?;
    let mut validation = Validation::new(algorithms[0]);
    validation.algorithms = algorithms;
    validation.set_issuer(&[&cfg.issuer]);
    validation.set_audience(&[&cfg.audience]);
    validation.validate_nbf = true;
    validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
    let claims = decode::<JwtClaims>(token, &key, &validation)
        .map_err(|error| {
            Error::new(
                ErrorCode::AuthRequired,
                format!("bearer JWT validation failed: {error}"),
            )
        })?
        .claims;
    principal_from_claims(claims)
}

/// Claim-value checks applied to a proxy-supplied unsigned JWT, sourced from the
/// listener's `jwt_issuer` / `jwt_audience` config. Each is optional: `None`
/// means the claim is not compared, and the fronting proxy is the sole authority
/// for it. Configuring both closes the confused-deputy path a signature-only
/// proxy leaves open — a token minted by the same IdP for a different relying
/// party carries a foreign `aud` and is rejected here.
#[derive(Clone, Debug, Default)]
pub(crate) struct UnsignedJwtClaimChecks {
    pub(crate) issuer: Option<String>,
    pub(crate) audience: Option<String>,
}

/// Decode claims from a JWT supplied by an allowlisted TLS-terminating proxy.
/// The proxy owns signature verification; this layer still requires a
/// well-formed token, a non-empty subject, valid `exp`/`nbf` bounds, and any
/// configured `iss`/`aud` claim match ([`UnsignedJwtClaimChecks`]).
pub(crate) fn resolve_unsigned_jwt(
    token: &[u8],
    checks: &UnsignedJwtClaimChecks,
) -> Result<ResolvedPrincipal> {
    let token = std::str::from_utf8(token).map_err(|error| {
        Error::new(
            ErrorCode::AuthRequired,
            format!("trusted unsigned JWT is not valid UTF-8: {error}"),
        )
    })?;
    let mut parts = token.split('.');
    let header = parts
        .next()
        .filter(|part| !part.is_empty())
        .ok_or_else(|| {
            Error::new(
                ErrorCode::AuthRequired,
                "trusted unsigned JWT is missing header",
            )
        })?;
    let payload = parts
        .next()
        .filter(|part| !part.is_empty())
        .ok_or_else(|| {
            Error::new(
                ErrorCode::AuthRequired,
                "trusted unsigned JWT is missing payload",
            )
        })?;
    if parts.next().is_none() || parts.next().is_some() {
        return Err(Error::new(
            ErrorCode::AuthRequired,
            "trusted unsigned JWT must have exactly three segments",
        ));
    }
    let header = URL_SAFE_NO_PAD.decode(header).map_err(|error| {
        Error::new(
            ErrorCode::AuthRequired,
            format!("trusted unsigned JWT header is invalid: {error}"),
        )
    })?;
    let header: UnsignedJwtHeader = serde_json::from_slice(&header).map_err(|error| {
        Error::new(
            ErrorCode::AuthRequired,
            format!("trusted unsigned JWT header is invalid: {error}"),
        )
    })?;
    if header.alg.trim().is_empty() {
        return Err(Error::new(
            ErrorCode::AuthRequired,
            "trusted unsigned JWT header must name its algorithm",
        ));
    }
    let payload = URL_SAFE_NO_PAD.decode(payload).map_err(|error| {
        Error::new(
            ErrorCode::AuthRequired,
            format!("trusted unsigned JWT payload is invalid: {error}"),
        )
    })?;
    let claims: JwtClaims = serde_json::from_slice(&payload).map_err(|error| {
        Error::new(
            ErrorCode::AuthRequired,
            format!("trusted unsigned JWT claims are invalid: {error}"),
        )
    })?;
    validate_unsigned_times(&claims)?;
    validate_unsigned_claims(&claims, checks)?;
    principal_from_claims(claims)
}

/// Compare the configured `iss`/`aud` values against the token's claims. An
/// unconfigured check passes; a configured one requires the claim to be present
/// and to match exactly (`aud` may be a string or an array, matching if any
/// member equals the configured value — the RFC 7519 shape).
fn validate_unsigned_claims(claims: &JwtClaims, checks: &UnsignedJwtClaimChecks) -> Result<()> {
    if let Some(expected) = &checks.issuer
        && claims.iss.as_deref() != Some(expected.as_str())
    {
        return Err(Error::new(
            ErrorCode::AuthRequired,
            "trusted unsigned JWT issuer does not match the configured jwt_issuer",
        ));
    }
    if let Some(expected) = &checks.audience
        && !audience_contains(claims.aud.as_ref(), expected)
    {
        return Err(Error::new(
            ErrorCode::AuthRequired,
            "trusted unsigned JWT audience does not match the configured jwt_audience",
        ));
    }
    Ok(())
}

/// Whether an `aud` claim admits `expected`. RFC 7519 gives `aud` two shapes: a
/// case-sensitive string, or an array of such strings. A string claim must equal
/// `expected`; an array claim must consist entirely of strings and contain
/// `expected`. Every other shape — absent, number, bool, object, or an array
/// with any non-string member — admits nothing.
///
/// Rejecting a mixed array rather than ignoring its invalid members is the
/// strict reading: a claim that is not a well-formed `aud` is a malformed token,
/// and this path has no signature check to fall back on, so it fails closed.
fn audience_contains(audience: Option<&Value>, expected: &str) -> bool {
    match audience {
        Some(Value::String(value)) => value == expected,
        Some(Value::Array(values)) => {
            values.iter().all(Value::is_string)
                && values.iter().any(|value| value.as_str() == Some(expected))
        }
        _ => false,
    }
}

fn validate_unsigned_times(claims: &JwtClaims) -> Result<()> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::new(ErrorCode::Internal, "system clock is before Unix epoch"))?
        .as_secs();
    if claims
        .exp
        .is_some_and(|exp| exp < now.saturating_sub(JWT_CLOCK_SKEW_LEEWAY))
    {
        return Err(Error::new(
            ErrorCode::AuthRequired,
            "trusted unsigned JWT is expired",
        ));
    }
    if claims
        .nbf
        .is_some_and(|nbf| nbf > now.saturating_add(JWT_CLOCK_SKEW_LEEWAY))
    {
        return Err(Error::new(
            ErrorCode::AuthRequired,
            "trusted unsigned JWT is not valid yet",
        ));
    }
    Ok(())
}

/// The signature algorithms accepted for a resolved JWKS key, derived from the
/// key's family (`kty`, plus curve for EC/OKP) — the sole source of truth for
/// which `alg` a token may carry, independent of the token header. RSA keys
/// accept the PKCS#1v1.5 and PSS families; EC keys accept the ECDSA algorithm
/// for their curve (`ring`/`jsonwebtoken` support P-256/P-384 only — P-521 has
/// no `ES512`); Ed25519 OKP keys accept `EdDSA`; symmetric `oct` keys accept the
/// HMAC family. An EC/OKP key on an unsupported curve is a clean auth error, not
/// a silent admit.
fn accepted_algorithms(jwk: &Jwk) -> Result<Vec<Algorithm>> {
    let algorithms = match &jwk.algorithm {
        AlgorithmParameters::RSA(_) => vec![
            Algorithm::RS256,
            Algorithm::RS384,
            Algorithm::RS512,
            Algorithm::PS256,
            Algorithm::PS384,
            Algorithm::PS512,
        ],
        AlgorithmParameters::EllipticCurve(ec) => match &ec.curve {
            EllipticCurve::P256 => vec![Algorithm::ES256],
            EllipticCurve::P384 => vec![Algorithm::ES384],
            other => {
                return Err(Error::new(
                    ErrorCode::AuthRequired,
                    format!("unsupported JWKS EC curve for bearer JWT: {other:?}"),
                ));
            }
        },
        AlgorithmParameters::OctetKeyPair(okp) => match &okp.curve {
            EllipticCurve::Ed25519 => vec![Algorithm::EdDSA],
            other => {
                return Err(Error::new(
                    ErrorCode::AuthRequired,
                    format!("unsupported JWKS OKP curve for bearer JWT: {other:?}"),
                ));
            }
        },
        AlgorithmParameters::OctetKey(_) => {
            vec![Algorithm::HS256, Algorithm::HS384, Algorithm::HS512]
        }
    };
    Ok(algorithms)
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
    // `exp`/`nbf` are validated by `jsonwebtoken` for signed JWTs and explicitly
    // by `validate_unsigned_times` for trusted proxy JWTs. The layer does not
    // carry token lifetime into `ResolvedPrincipal`.
    exp: Option<u64>,
    nbf: Option<u64>,
    iss: Option<String>,
    aud: Option<Value>,
    #[serde(flatten)]
    extra: HashMap<String, Value>,
}

#[derive(Debug, Deserialize)]
struct UnsignedJwtHeader {
    alg: String,
}

/// Map validated JWT claims to a [`ResolvedPrincipal`]: `sub` → id (required,
/// non-empty), `iss`/`aud`/all remaining claims → attributes, `name` (else
/// `preferred_username`) → display name. Ported verbatim from REST
/// `principal_from_claims`.
fn principal_from_claims(claims: JwtClaims) -> Result<ResolvedPrincipal> {
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
    Ok(ResolvedPrincipal {
        id,
        display_name,
        attributes,
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

#[cfg(test)]
mod unsigned_tests {
    use super::*;

    fn token(claims: serde_json::Value) -> Vec<u8> {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","typ":"JWT"}"#);
        let claims = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        format!("{header}.{claims}.proxy-verified").into_bytes()
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// Claim checks with neither `iss` nor `aud` configured.
    fn unchecked() -> UnsignedJwtClaimChecks {
        UnsignedJwtClaimChecks::default()
    }

    #[test]
    fn trusted_unsigned_jwt_requires_a_well_formed_header() {
        let claims = URL_SAFE_NO_PAD.encode(br#"{"sub":"alice"}"#);
        let error = resolve_unsigned_jwt(
            format!("Basic abc.{claims}.proxy-verified").as_bytes(),
            &unchecked(),
        )
        .unwrap_err();
        assert_eq!(error.code(), ErrorCode::AuthRequired);
        assert!(error.message().contains("header"));

        let error = resolve_unsigned_jwt(b"eyJhbGciOiJSUzI1NiJ9.only-two-segments", &unchecked())
            .unwrap_err();
        assert_eq!(error.code(), ErrorCode::AuthRequired);
        assert!(error.message().contains("three segments"));

        let error = resolve_unsigned_jwt(
            b"eyJhbGciOiJSUzI1NiJ9.not+base64.proxy-verified",
            &unchecked(),
        )
        .unwrap_err();
        assert_eq!(error.code(), ErrorCode::AuthRequired);
        assert!(error.message().contains("payload"));
    }

    #[test]
    fn trusted_unsigned_jwt_enforces_configured_issuer_and_audience() {
        let checks = UnsignedJwtClaimChecks {
            issuer: Some("https://issuer.test".into()),
            audience: Some("ovstorage".into()),
        };
        let principal = resolve_unsigned_jwt(
            &token(serde_json::json!({
                "sub": "alice",
                "iss": "https://issuer.test",
                "aud": "ovstorage"
            })),
            &checks,
        )
        .unwrap();
        assert_eq!(principal.id, "alice");

        // A token minted by the same IdP for a different relying party: the
        // signature a proxy verified is genuine, but the audience is foreign.
        let error = resolve_unsigned_jwt(
            &token(serde_json::json!({
                "sub": "alice",
                "iss": "https://issuer.test",
                "aud": "some-other-service"
            })),
            &checks,
        )
        .unwrap_err();
        assert_eq!(error.code(), ErrorCode::AuthRequired);
        assert!(error.message().contains("audience"), "{}", error.message());

        let error = resolve_unsigned_jwt(
            &token(serde_json::json!({
                "sub": "alice",
                "iss": "https://evil.test",
                "aud": "ovstorage"
            })),
            &checks,
        )
        .unwrap_err();
        assert_eq!(error.code(), ErrorCode::AuthRequired);
        assert!(error.message().contains("issuer"), "{}", error.message());

        // A configured check requires the claim to be present, not merely
        // non-conflicting. The issuer check runs first, so this pins the issuer
        // arm; the audience arm has its own test with `issuer: None`.
        let error =
            resolve_unsigned_jwt(&token(serde_json::json!({"sub": "alice"})), &checks).unwrap_err();
        assert_eq!(error.code(), ErrorCode::AuthRequired);
        assert!(error.message().contains("issuer"), "{}", error.message());
    }

    #[test]
    fn trusted_unsigned_jwt_requires_a_present_audience_claim() {
        // `issuer` is deliberately unset: `validate_unsigned_claims` checks the
        // issuer first, so a configured issuer would short-circuit and this
        // branch would never run.
        let checks = UnsignedJwtClaimChecks {
            issuer: None,
            audience: Some("ovstorage".into()),
        };
        let error = resolve_unsigned_jwt(
            &token(serde_json::json!({
                "sub": "alice",
                "iss": "https://issuer.test"
            })),
            &checks,
        )
        .unwrap_err();
        assert_eq!(error.code(), ErrorCode::AuthRequired);
        assert!(error.message().contains("audience"), "{}", error.message());
    }

    #[test]
    fn trusted_unsigned_jwt_rejects_non_string_audience_shapes() {
        // A malformed/hostile `aud` must fail closed, never match by coercion.
        let checks = UnsignedJwtClaimChecks {
            issuer: None,
            audience: Some("ovstorage".into()),
        };
        for audience in [
            serde_json::json!(7),
            serde_json::json!(true),
            serde_json::json!(null),
            serde_json::json!([]),
            serde_json::json!([7, true]),
            serde_json::json!([["ovstorage"]]),
            serde_json::json!({ "aud": "ovstorage" }),
            // Mixed arrays: the expected value IS present, but the claim is not
            // a well-formed `aud`. The strict reading rejects it rather than
            // ignoring the invalid members — there is no signature check behind
            // this path to fall back on.
            serde_json::json!(["ovstorage", 7]),
            serde_json::json!([["invalid"], "ovstorage"]),
            serde_json::json!(["ovstorage", null]),
        ] {
            let error = resolve_unsigned_jwt(
                &token(serde_json::json!({"sub": "alice", "aud": audience})),
                &checks,
            )
            .unwrap_err();
            assert_eq!(error.code(), ErrorCode::AuthRequired);
            assert!(error.message().contains("audience"), "{}", error.message());
        }
    }

    #[test]
    fn trusted_unsigned_jwt_matches_any_member_of_an_audience_array() {
        let checks = UnsignedJwtClaimChecks {
            issuer: None,
            audience: Some("ovstorage".into()),
        };
        assert!(
            resolve_unsigned_jwt(
                &token(serde_json::json!({
                    "sub": "alice",
                    "aud": ["other-service", "ovstorage"]
                })),
                &checks,
            )
            .is_ok()
        );
        assert!(
            resolve_unsigned_jwt(
                &token(serde_json::json!({
                    "sub": "alice",
                    "aud": ["other-service"]
                })),
                &checks,
            )
            .is_err()
        );
    }

    #[test]
    fn trusted_unsigned_jwt_without_configured_claims_accepts_any_issuer_and_audience() {
        // Unset means "not enforced": the upstream verifier is the sole authority
        // for `iss`/`aud`, and a config naming only the mode stays valid.
        assert!(
            resolve_unsigned_jwt(
                &token(serde_json::json!({
                    "sub": "alice",
                    "iss": "https://anything.test",
                    "aud": "some-other-service"
                })),
                &unchecked(),
            )
            .is_ok()
        );
    }

    #[test]
    fn trusted_unsigned_jwt_expiry_uses_signed_jwt_leeway() {
        let current = now();
        assert!(
            resolve_unsigned_jwt(
                &token(serde_json::json!({
                    "sub": "alice",
                    "exp": current - JWT_CLOCK_SKEW_LEEWAY + 1
                })),
                &unchecked(),
            )
            .is_ok()
        );
        let error = resolve_unsigned_jwt(
            &token(serde_json::json!({
                "sub": "alice",
                "exp": current - JWT_CLOCK_SKEW_LEEWAY - 1
            })),
            &unchecked(),
        )
        .unwrap_err();
        assert!(error.message().contains("expired"));
    }

    #[test]
    fn trusted_unsigned_jwt_not_before_uses_signed_jwt_leeway() {
        let current = now();
        assert!(
            resolve_unsigned_jwt(
                &token(serde_json::json!({
                    "sub": "alice",
                    "nbf": current + JWT_CLOCK_SKEW_LEEWAY - 1
                })),
                &unchecked(),
            )
            .is_ok()
        );
        let error = resolve_unsigned_jwt(
            &token(serde_json::json!({
                "sub": "alice",
                "nbf": current + JWT_CLOCK_SKEW_LEEWAY + 1
            })),
            &unchecked(),
        )
        .unwrap_err();
        assert!(error.message().contains("not valid yet"));
    }
}
