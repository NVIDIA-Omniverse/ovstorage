// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

use std::net::IpAddr;

/// Peer-IP CIDR allowlist for a `trusted_proxy` listener; checked
/// before consulting the proxy-set authn header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CidrConstraint {
    base: IpAddr,
    prefix_len: u8,
}

impl CidrConstraint {
    pub(crate) fn parse(value: &str) -> ovstorage::Result<Self> {
        let (addr_str, prefix_str) = value.split_once('/').ok_or_else(|| {
            invalid_config(format!(
                "trusted_peers entry '{value}' must be a CIDR (host/prefix)"
            ))
        })?;
        let base: IpAddr = addr_str.parse().map_err(|err| {
            invalid_config(format!(
                "trusted_peers entry '{value}' has invalid address: {err}"
            ))
        })?;
        let prefix_len: u8 = prefix_str.parse().map_err(|err| {
            invalid_config(format!(
                "trusted_peers entry '{value}' has invalid prefix length: {err}"
            ))
        })?;
        let max = match base {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix_len > max {
            return Err(invalid_config(format!(
                "trusted_peers entry '{value}' prefix length {prefix_len} exceeds /{max}"
            )));
        }
        Ok(Self { base, prefix_len })
    }

    pub(crate) fn contains(&self, addr: IpAddr) -> bool {
        match (self.base, addr) {
            (IpAddr::V4(base), IpAddr::V4(peer)) => {
                cidr_matches_v4(base.octets(), peer.octets(), self.prefix_len)
            }
            (IpAddr::V6(base), IpAddr::V6(peer)) => {
                cidr_matches_v6(base.octets(), peer.octets(), self.prefix_len)
            }
            _ => false,
        }
    }
}

fn cidr_matches_v4(base: [u8; 4], peer: [u8; 4], prefix_len: u8) -> bool {
    let base = u32::from_be_bytes(base);
    let peer = u32::from_be_bytes(peer);
    if prefix_len == 0 {
        return true;
    }
    let mask = u32::MAX.checked_shl(32 - prefix_len as u32).unwrap_or(0);
    (base & mask) == (peer & mask)
}

fn cidr_matches_v6(base: [u8; 16], peer: [u8; 16], prefix_len: u8) -> bool {
    let mut bits_left = prefix_len as usize;
    for i in 0..16 {
        if bits_left == 0 {
            return true;
        }
        let take = bits_left.min(8);
        let mask = if take == 8 {
            0xff
        } else {
            0xffu8 << (8 - take)
        };
        if (base[i] & mask) != (peer[i] & mask) {
            return false;
        }
        bits_left -= take;
    }
    true
}

pub(crate) fn parse_trusted_peers(values: &[String]) -> ovstorage::Result<Vec<CidrConstraint>> {
    values.iter().map(|s| CidrConstraint::parse(s)).collect()
}

#[derive(Clone)]
pub(crate) struct GrpcAuthn {
    mode: GrpcAuthnMode,
    trusted_peers: Vec<CidrConstraint>,
    trusted_proxy: bool,
}

#[derive(Clone)]
pub(crate) enum GrpcAuthnMode {
    DevCurrentUser,
    JwtVerify {
        issuer: String,
        audience: String,
        jwks_url: String,
        jwks: Arc<Mutex<Option<CachedJwks>>>,
        http: Arc<reqwest::Client>,
    },
    TrustedUnsignedJwt,
    TrustedForwardedHeaders {
        identity_header: String,
        claim_headers: HashMap<String, String>,
    },
    PeerCred,
}

#[derive(Clone)]
pub(crate) struct CachedJwks {
    jwks: JwkSet,
    fetched_at: std::time::Instant,
}

const JWKS_CACHE_TTL: Duration = Duration::from_secs(300);

pub(crate) enum GrpcAuthnInput {
    DevCurrentUser,
    JwtVerify {
        token: String,
    },
    TrustedUnsignedJwt {
        token: String,
    },
    TrustedForwardedHeaders {
        id: String,
        attributes: HashMap<String, String>,
    },
    PeerCred {
        principal: Principal,
    },
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct JwtClaims {
    sub: Option<String>,
    exp: Option<u64>,
    nbf: Option<u64>,
    iss: Option<String>,
    aud: Option<Value>,
    #[serde(flatten)]
    extra: HashMap<String, Value>,
}

impl GrpcAuthn {
    pub(crate) fn dev_current_user() -> Self {
        Self {
            mode: GrpcAuthnMode::DevCurrentUser,
            trusted_peers: Vec::new(),
            trusted_proxy: false,
        }
    }

    pub(crate) fn from_listener(listener: &BrokerListenerConfig) -> ovstorage::Result<Self> {
        let authn = listener.resolved_authn()?;
        let mode = match authn.mode {
            BrokerAuthnMode::JwtVerify => {
                let http = reqwest::Client::builder()
                    .connect_timeout(Duration::from_secs(5))
                    .timeout(Duration::from_secs(10))
                    .build()
                    .map_err(|err| {
                        invalid_config(format!(
                            "listener authn.jwt_verify could not build HTTP client: {err}"
                        ))
                    })?;
                GrpcAuthnMode::JwtVerify {
                    issuer: authn.issuer.ok_or_else(|| {
                        invalid_config("listener authn.issuer must be configured for jwt_verify")
                    })?,
                    audience: authn.audience.ok_or_else(|| {
                        invalid_config("listener authn.audience must be configured for jwt_verify")
                    })?,
                    jwks_url: authn.jwks_url.ok_or_else(|| {
                        invalid_config("listener authn.jwks_url must be configured for jwt_verify")
                    })?,
                    jwks: Arc::new(Mutex::new(None)),
                    http: Arc::new(http),
                }
            }
            BrokerAuthnMode::TrustedUnsignedJwt => GrpcAuthnMode::TrustedUnsignedJwt,
            BrokerAuthnMode::TrustedForwardedHeaders => GrpcAuthnMode::TrustedForwardedHeaders {
                identity_header: authn.identity_header,
                claim_headers: authn.claim_headers,
            },
            BrokerAuthnMode::PeerCred => GrpcAuthnMode::PeerCred,
            BrokerAuthnMode::Mtls => {
                return Err(Error::new(
                    ErrorCode::Unsupported,
                    "authn.mode = \"mtls\" is reserved in 0.4; full support ships in 0.5",
                ));
            }
        };
        let trusted_peers = parse_trusted_peers(&listener.trusted_peers)?;
        Ok(Self {
            mode,
            trusted_peers,
            trusted_proxy: listener.trusted_proxy,
        })
    }

    pub(crate) fn enforce_trusted_peer<T>(&self, request: &Request<T>) -> Result<(), Status> {
        if !self.trusted_proxy || self.trusted_peers.is_empty() {
            return Ok(());
        }
        let peer = request
            .extensions()
            .get::<tonic::transport::server::TcpConnectInfo>()
            .and_then(|info| info.remote_addr())
            .ok_or_else(|| {
                Status::unauthenticated(
                    "trusted_proxy listener requires a TCP peer address; none was captured",
                )
            })?;
        if self
            .trusted_peers
            .iter()
            .any(|cidr| cidr.contains(peer.ip()))
        {
            Ok(())
        } else {
            Err(Status::unauthenticated(format!(
                "peer {peer} is not in the listener's trusted_peers CIDR allowlist",
            )))
        }
    }

    pub(crate) fn input<T>(&self, request: &Request<T>) -> Result<GrpcAuthnInput, Status> {
        self.enforce_trusted_peer(request)?;
        match &self.mode {
            GrpcAuthnMode::DevCurrentUser => Ok(GrpcAuthnInput::DevCurrentUser),
            GrpcAuthnMode::JwtVerify { .. } => Ok(GrpcAuthnInput::JwtVerify {
                token: bearer_token(request)?,
            }),
            GrpcAuthnMode::TrustedUnsignedJwt => Ok(GrpcAuthnInput::TrustedUnsignedJwt {
                token: bearer_token(request)?,
            }),
            GrpcAuthnMode::TrustedForwardedHeaders {
                identity_header,
                claim_headers,
            } => {
                let id = metadata_string(request, identity_header)?.ok_or_else(|| {
                    Status::unauthenticated(format!(
                        "trusted forwarded identity header '{identity_header}' is missing"
                    ))
                })?;
                let mut attributes = HashMap::new();
                for (claim, header) in claim_headers {
                    if let Some(value) = metadata_string(request, header)? {
                        attributes.insert(claim.clone(), value);
                    }
                }
                Ok(GrpcAuthnInput::TrustedForwardedHeaders { id, attributes })
            }
            GrpcAuthnMode::PeerCred => Ok(GrpcAuthnInput::PeerCred {
                principal: peer_cred_principal(request)?,
            }),
        }
    }

    pub(crate) async fn principal(&self, input: GrpcAuthnInput) -> Result<Principal, Status> {
        let mode_name = match &input {
            GrpcAuthnInput::DevCurrentUser => "dev_current_user",
            GrpcAuthnInput::JwtVerify { .. } => "jwt_verify",
            GrpcAuthnInput::TrustedUnsignedJwt { .. } => "trusted_unsigned_jwt",
            GrpcAuthnInput::TrustedForwardedHeaders { .. } => "trusted_forwarded_headers",
            GrpcAuthnInput::PeerCred { .. } => "peer_cred",
        };
        let _span = tracing::info_span!("broker.authn.principal", authn.mode = mode_name,);
        let _guard = _span.enter();
        let principal = match &self.mode {
            GrpcAuthnMode::DevCurrentUser => Principal {
                id: current_principal(),
                display_name: None,
                attributes: HashMap::new(),
                valid_until: None,
                source: "dev_current_user".into(),
            },
            GrpcAuthnMode::JwtVerify {
                issuer,
                audience,
                jwks_url,
                jwks,
                http,
            } => {
                let GrpcAuthnInput::JwtVerify { token } = input else {
                    return Err(Status::internal("authn input mode mismatch"));
                };
                let header = decode_header(&token).map_err(|error| {
                    tracing::debug!(error = %error, "invalid bearer JWT header");
                    Status::unauthenticated(format!("invalid bearer JWT header: {error}"))
                })?;
                let jwks_set = cached_jwks(http, jwks_url, jwks, false).await?;
                let jwk = match header.kid.as_deref() {
                    Some(kid) => match jwks_set.find(kid) {
                        Some(jwk) => jwk.clone(),
                        None => {
                            tracing::debug!(kid = kid, "JWKS key not found, refreshing");
                            let refreshed = cached_jwks(http, jwks_url, jwks, true).await?;
                            refreshed.find(kid).cloned().ok_or_else(|| {
                                Status::unauthenticated("bearer JWT key id is not present in JWKS")
                            })?
                        }
                    },
                    None if jwks_set.keys.len() == 1 => jwks_set.keys[0].clone(),
                    None => {
                        return Err(Status::unauthenticated(
                            "bearer JWT is missing kid and JWKS contains multiple keys",
                        ));
                    }
                };
                let key = DecodingKey::from_jwk(&jwk).map_err(|error| {
                    Status::unauthenticated(format!("invalid JWKS key for bearer JWT: {error}"))
                })?;
                let mut validation = Validation::new(header.alg);
                validation.set_issuer(&[issuer]);
                validation.set_audience(&[audience]);
                validation.validate_nbf = true;
                validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
                let claims = decode::<JwtClaims>(&token, &key, &validation)
                    .map_err(|error| {
                        tracing::debug!(error = %error, "bearer JWT validation failed");
                        Status::unauthenticated(format!("bearer JWT validation failed: {error}"))
                    })?
                    .claims;
                principal_from_claims(claims, "jwt_verify")?
            }
            GrpcAuthnMode::TrustedUnsignedJwt => {
                let GrpcAuthnInput::TrustedUnsignedJwt { token } = input else {
                    return Err(Status::internal("authn input mode mismatch"));
                };
                let claims = decode_unsigned_jwt_claims(&token)?;
                validate_jwt_time(&claims)?;
                principal_from_claims(claims, "trusted_unsigned_jwt")?
            }
            GrpcAuthnMode::TrustedForwardedHeaders { .. } => {
                let GrpcAuthnInput::TrustedForwardedHeaders { id, attributes } = input else {
                    return Err(Status::internal("authn input mode mismatch"));
                };
                Principal {
                    id,
                    display_name: None,
                    attributes,
                    valid_until: None,
                    source: "trusted_forwarded_headers".into(),
                }
            }
            GrpcAuthnMode::PeerCred => {
                let GrpcAuthnInput::PeerCred { principal } = input else {
                    return Err(Status::internal("authn input mode mismatch"));
                };
                principal
            }
        };
        Ok(principal)
    }
}

async fn cached_jwks(
    http: &reqwest::Client,
    url: &str,
    cache: &Arc<Mutex<Option<CachedJwks>>>,
    force_refresh: bool,
) -> Result<JwkSet, Status> {
    if !force_refresh
        && let Some(entry) = cache
            .lock()
            .map_err(|_| Status::internal("JWKS cache lock is poisoned"))?
            .clone()
        && entry.fetched_at.elapsed() < JWKS_CACHE_TTL
    {
        return Ok(entry.jwks);
    }
    let jwks = http
        .get(url)
        .send()
        .await
        .map_err(|error| {
            Status::unavailable(format!(
                "failed to fetch listener JWKS from '{url}': {error}"
            ))
        })?
        .error_for_status()
        .map_err(|error| {
            Status::unavailable(format!("listener JWKS request failed for '{url}': {error}"))
        })?
        .json::<JwkSet>()
        .await
        .map_err(|error| {
            Status::unauthenticated(format!(
                "listener JWKS document from '{url}' is invalid: {error}"
            ))
        })?;
    *cache
        .lock()
        .map_err(|_| Status::internal("JWKS cache lock is poisoned"))? = Some(CachedJwks {
        jwks: jwks.clone(),
        fetched_at: std::time::Instant::now(),
    });
    Ok(jwks)
}

fn bearer_token<T>(request: &Request<T>) -> Result<String, Status> {
    let header = metadata_string(request, "authorization")?
        .ok_or_else(|| Status::unauthenticated("missing Authorization bearer token"))?;
    header
        .strip_prefix("Bearer ")
        .or_else(|| header.strip_prefix("bearer "))
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(str::to_string)
        .ok_or_else(|| Status::unauthenticated("Authorization header must use Bearer token"))
}

fn metadata_string<T>(request: &Request<T>, header: &str) -> Result<Option<String>, Status> {
    let header = header.trim().to_ascii_lowercase();
    let Some(value) = request.metadata().get(header.as_str()) else {
        return Ok(None);
    };
    Ok(Some(
        value
            .to_str()
            .map_err(|_| {
                Status::unauthenticated(format!("metadata header '{header}' is not valid ASCII"))
            })?
            .to_string(),
    ))
}

fn decode_unsigned_jwt_claims(token: &str) -> Result<JwtClaims, Status> {
    let mut parts = token.split('.');
    let _header = parts
        .next()
        .filter(|part| !part.is_empty())
        .ok_or_else(|| Status::unauthenticated("trusted unsigned JWT is missing header"))?;
    let payload = parts
        .next()
        .filter(|part| !part.is_empty())
        .ok_or_else(|| Status::unauthenticated("trusted unsigned JWT is missing payload"))?;
    if parts.next().is_none() {
        return Err(Status::unauthenticated(
            "trusted unsigned JWT must include a signature segment, even when it is not verified",
        ));
    }
    let payload = URL_SAFE_NO_PAD.decode(payload).map_err(|error| {
        Status::unauthenticated(format!("trusted unsigned JWT payload is invalid: {error}"))
    })?;
    serde_json::from_slice(&payload).map_err(|error| {
        Status::unauthenticated(format!("trusted unsigned JWT claims are invalid: {error}"))
    })
}

fn validate_jwt_time(claims: &JwtClaims) -> Result<(), Status> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Status::internal("system clock is before Unix epoch"))?
        .as_secs();
    if let Some(exp) = claims.exp {
        if exp <= now {
            return Err(Status::unauthenticated("trusted unsigned JWT is expired"));
        }
    }
    if let Some(nbf) = claims.nbf {
        if nbf > now {
            return Err(Status::unauthenticated(
                "trusted unsigned JWT is not valid yet",
            ));
        }
    }
    Ok(())
}

fn principal_from_claims(claims: JwtClaims, source: &str) -> Result<Principal, Status> {
    let id = claims
        .sub
        .clone()
        .filter(|sub| !sub.trim().is_empty())
        .ok_or_else(|| Status::unauthenticated("JWT subject claim is required"))?;
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

#[cfg(unix)]
fn peer_cred_principal<T>(request: &Request<T>) -> Result<Principal, Status> {
    let info = request
        .extensions()
        .get::<tonic::transport::server::UdsConnectInfo>()
        .ok_or_else(|| Status::unauthenticated("peer_cred requires a local Unix socket peer"))?;
    let cred = info
        .peer_cred
        .as_ref()
        .ok_or_else(|| Status::unauthenticated("Unix socket peer credentials are unavailable"))?;
    let mut attributes = HashMap::new();
    attributes.insert("uid".into(), cred.uid().to_string());
    attributes.insert("gid".into(), cred.gid().to_string());
    if let Some(pid) = cred.pid() {
        attributes.insert("pid".into(), pid.to_string());
    }
    Ok(Principal {
        id: format!("uid:{}", cred.uid()),
        display_name: None,
        attributes,
        valid_until: None,
        source: "peer_cred".into(),
    })
}

#[cfg(windows)]
fn peer_cred_principal<T>(request: &Request<T>) -> Result<Principal, Status> {
    let info = request
        .extensions()
        .get::<NamedPipeConnectInfo>()
        .ok_or_else(|| Status::unauthenticated("peer_cred requires a local named-pipe peer"))?;
    let mut attributes = HashMap::new();
    let client_process_id = info.client_process_id();
    if let Some(pid) = client_process_id {
        attributes.insert("pid".into(), pid.to_string());
    }
    Ok(Principal {
        id: client_process_id
            .map(|pid| format!("pid:{pid}"))
            .unwrap_or_else(|| "named-pipe-peer".into()),
        display_name: None,
        attributes,
        valid_until: None,
        source: "peer_cred".into(),
    })
}

#[cfg(not(any(unix, windows)))]
fn peer_cred_principal<T>(_request: &Request<T>) -> Result<Principal, Status> {
    Err(Status::unauthenticated(
        "peer_cred is not supported on this platform",
    ))
}
