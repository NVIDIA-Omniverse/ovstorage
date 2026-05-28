// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

/// Drain a test gRPC server cleanly. `BrokerGrpcServer::drop` only
/// fires the shutdown signal; it can't await the drain because Drop
/// isn't async. Tests that drop the server and then drop the Library
/// race the server's worker against the plugin .so unload — observable
/// on CI as SIGSEGV mid-RPC. Production code goes through
/// `lifecycle.rs` which awaits `take_drained()`; tests need to do the
/// same.
pub async fn shutdown_test_server(mut server: BrokerGrpcServer) {
    let drained = server.take_drained();
    server.fire_shutdown();
    if let Some(rx) = drained {
        // 5s is generous: in passing runs the drain completes in
        // milliseconds via the watch-supervisor + Hub Drop chain. The
        // timeout is a safety net so a stray bug bounds the test budget.
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), rx).await;
    }
}

pub fn unique_temp_dir() -> std::path::PathBuf {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "ovstorage-broker-test-{}-{stamp}",
        std::process::id()
    ))
}

pub const TEST_TLS_CERT_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIC5zCCAc+gAwIBAgIJAJErJdEv/iZWMA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMTCWxvY2Fs
aG9zdDAeFw0yNjA0MjYxOTQ4NDZaFw00NjA0MjcxOTQ4NDZaMBQxEjAQBgNVBAMTCWxvY2FsaG9z
dDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJ81+KEuvI9hb92unBDJyN9NHMJTzr8o
EB4CIFtelESmd48VK+XqhN8Lf/7vy95eIfmjYabofFoPOWvs+qWCMXeFtwr5TrDXjl8jv3l3OC1z
AN+iZ3oXxeIsyzHqzaSQUgLwVutPAp9gA+fO3ARGykzGSTMCDC7UrpVpCaY0tnokJ4An38SzhQu5
Vzv9KhUKCEWW9tC9L9Ea2UJRTYoTk47Dvukry1iLMlvBis8do2iO3EbxaSFPREJ2DED8FyuOA9J4
lR7W9piBcEGpaLvhHD2zPoCp7CvysbfCbFfzUhbmtrzBol1S5x2fdW1SJD5iCJB3f9kLMyxkbtuL
n6AnVjkCAwEAAaM8MDowGgYDVR0RBBMwEYIJbG9jYWxob3N0hwR/AAABMAwGA1UdEwEB/wQCMAAw
DgYDVR0PAQH/BAQDAgWgMA0GCSqGSIb3DQEBCwUAA4IBAQA8EDTq/d8n+7V+wH2VZJ2GHgbAg189
RTtoEfc3FyeQjyqwkcWXZ/J7iTlH9edpAdVg7t2gZ4jwUDjL1E1T2M2DYGe5pKQv8Blk4KM6LgD3
nd1QGfoA2VCnmsU7naikxhLso/TH5jyxeHn5PUbJlPPoZ4M4NWJzOztBCzu0IUWOpRxtnxnbfCCz
EpHwfx94Fu0ZyaxWjrhUHnxzPRcxf0VMAAf/YszqZXHNoM1N7vFyVvAllMTu6m4xDnc5J+l2o3jP
NT+LagetDlrcnS+GOpCGhDVq14mH8wg5alNTXTxWB/4sutoIXrZmz/yQTcxYbRjyaWf3LE3bka0J
dSCDhj0j
-----END CERTIFICATE-----"#;

pub const TEST_TLS_KEY_PEM: &str = r#"-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAnzX4oS68j2Fv3a6cEMnI300cwlPOvygQHgIgW16URKZ3jxUr5eqE3wt//u/L
3l4h+aNhpuh8Wg85a+z6pYIxd4W3CvlOsNeOXyO/eXc4LXMA36JnehfF4izLMerNpJBSAvBW608C
n2AD587cBEbKTMZJMwIMLtSulWkJpjS2eiQngCffxLOFC7lXO/0qFQoIRZb20L0v0RrZQlFNihOT
jsO+6SvLWIsyW8GKzx2jaI7cRvFpIU9EQnYMQPwXK44D0niVHtb2mIFwQalou+EcPbM+gKnsK/Kx
t8JsV/NSFua2vMGiXVLnHZ91bVIkPmIIkHd/2QszLGRu24ufoCdWOQIDAQABAoIBAFRywkBsk+PR
oQ6K8YkOHxgixOBmp8FJNNNV+We9kROg4MXqSvCXJodQiEHnW9HFSGwrtz5bDqqObLzMZF6p4ict
q9uMRasTixb31TZOgGPLHmmAsTZXqcTAUb9WdmGVk4qvhMsni5KR0UCBvr4d9mwmuOjvaxrkAP6L
Smz4hNnfwRNE4R8c2alX/WpttKCTIqqr77D9gTpKz6IsW4+sjZU2G2KxeZpeFF120UxvDvGBrr/v
KRtwvopKStNN1Y5OgvtdUqxklhIZBtomMnB2GbJYxfiy63Uh5e46IZU3xes0JhL6M54ITYnqytzo
n/1yfZ2LFK17TPtR/w/ek7vDLYkCgYEA06DJ4WnxewPirrjhgIFqwpXkRWh2dSvWtwe33fDnado/
CDWqMWHi+vYVuJlOU0mQKJH6PAt3J5B65/XFJQheyXPjhlk2O1fRBjWacFj3sGabY3dilk6cLwdo
Kztua1g5+wZ5JOTnj39lgG5rJRYrEOCcKRc1NvruVNW6hQRH/qcCgYEAwJerBZ2n8ut5OnS9Qhrz
kf9NZp9tMuv+QtxKmFKx2KeahcQ3jtRqRtYSdcN0DvE6aQy/2OvD601c6uYgY8xI1O8CiTqMyQxo
ph3uceS91nkPwKGrk/XlPR/KJl5rkwUBAGnLe6gzK4iLE7ycssnBf4PXnGP0g62eB0YnkIKEgB8C
gYB4aU8Uo7wTW1WaRnWAMaK2DqUwXMyxxHzJ7WlPraduEhC1MhuhN2n3kxcuzoPDXeLZQp3Xlkp4
x3s3Ch7fAFE2XGsD4TS7NS8oUk2KSQS9aNRXFvGQRjAVjihWGN2t1ChBTSCWvmuGuVzeY3UxR9i/
JJ2Vv6+2lbYPrQAQeSwhlwKBgQCu6Q/picV+WV1AOcWow9FyRuuEyEXkeW/ySR92N6RNn+o2kn3i
ugfLTaB2U4yUBYGG5o1V9Ml6akh5DYddG6sJuAgVmZdDAIIKXCSyS4wdvNURncK2HhyT5ssxDY+l
dmXyeiLTq27NmrS0uBeYSKPzq0mmPyFSdduPv6cvF1o/AQKBgAf4unOMtzz2aH4eumgc4YE46vF6
ZOdhyXirdi4+aMOHAhycv0ZYU/atAbDbJZPczrf1AElycRP1WTpbl6ipjd24v1KONMpDz0+pxxaF
b85i0FFYwEgGex5iJeDwQ6OBc64e3jyG+o/ADt4XAuu3dy7PPPPAo+D9fx+BLFCEmA8A
-----END RSA PRIVATE KEY-----"#;

pub fn address_for_path(path: &std::path::Path) -> Url {
    let mut path = path.to_string_lossy().replace('\\', "/");
    if !path.starts_with('/') {
        path.insert(0, '/');
    }
    if !path.ends_with('/') {
        path.push('/');
    }
    address::parse(&format!("file:{path}")).unwrap()
}

pub fn file_url(path: &std::path::Path) -> String {
    url::Url::from_file_path(path)
        .expect("test paths convert to file URLs")
        .to_string()
}

pub fn remove_file_retry(path: std::path::PathBuf) -> std::io::Result<()> {
    let mut last_error = None;
    for _ in 0..20 {
        match std::fs::remove_file(&path) {
            Ok(()) => return Ok(()),
            Err(error) if error.raw_os_error() == Some(32) => {
                last_error = Some(error);
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error),
        }
    }
    Err(last_error.expect("retry loop records the last sharing violation"))
}

pub fn remove_dir_all_retry(path: std::path::PathBuf) -> std::io::Result<()> {
    let mut last_error = None;
    for _ in 0..20 {
        match std::fs::remove_dir_all(&path) {
            Ok(()) => return Ok(()),
            Err(error) if error.raw_os_error() == Some(32) => {
                last_error = Some(error);
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error),
        }
    }
    Err(last_error.expect("retry loop records the last sharing violation"))
}

pub async fn add_broker_connection(client: &Library, discovery_url: &str, _prefix: &Url) {
    let mut config = HashMap::new();
    config.insert(
        "address".into(),
        ConfigValue::String(discovery_url.to_string()),
    );
    client
        .add_connection(
            ConnectionRequest {
                backend_kind: "broker".into(),
                config,
                credentials: SecretBundle::default(),
                persist: false,
                display_name: Some("broker".into()),
            },
            None,
        )
        .await
        .unwrap();
}

pub async fn broker_round_trip(prefix: &Url, discovery_url: &str) {
    let client = Library::builder().open_with_test_plugins();
    add_broker_connection(&client, discovery_url, prefix).await;
    let object =
        address::join_relative(prefix, &format!("local-transport-{}.txt", unique_suffix()))
            .unwrap();
    client
        .write(
            object.clone(),
            Body::Bytes(b"local broker bytes".to_vec()),
            WriteOptions::default(),
            None,
        )
        .await
        .unwrap();
    let (bytes, info) = client
        .read_bytes(object, ReadOptions::default(), None)
        .await
        .unwrap();
    assert_eq!(bytes, b"local broker bytes");
    assert_eq!(info.size, Some(18));
}

pub fn test_listener_config(mode: BrokerAuthnMode) -> BrokerListenerConfig {
    let trusted_proxy = matches!(
        mode,
        BrokerAuthnMode::TrustedForwardedHeaders | BrokerAuthnMode::TrustedUnsignedJwt
    );
    BrokerListenerConfig {
        bind: "127.0.0.1:0".into(),
        tls: None,
        trusted_proxy,
        trusted_peers: if trusted_proxy {
            vec!["127.0.0.1/32".into()]
        } else {
            vec![]
        },
        authn: Some(BrokerListenerAuthnConfig {
            mode,
            issuer: None,
            audience: None,
            jwks_url: None,
            identity_header: "x-forwarded-user".into(),
            claim_headers: HashMap::new(),
        }),
    }
}

pub fn unique_suffix() -> String {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{}-{stamp}", std::process::id())
}

pub fn unsigned_test_jwt(subject: &str, expiry_offset_seconds: i64) -> String {
    let header = json!({"alg": "none", "typ": "JWT"});
    let claims = json!({
        "sub": subject,
        "exp": jwt_timestamp(expiry_offset_seconds),
        "nbf": jwt_timestamp(-60),
    });
    format!("{}.{}.", base64_json(&header), base64_json(&claims))
}

pub fn signed_test_jwt(
    subject: &str,
    issuer: &str,
    audience: &str,
    kid: &str,
    secret: &[u8],
    expiry_offset_seconds: i64,
) -> String {
    signed_test_jwt_with_nbf(
        subject,
        issuer,
        audience,
        kid,
        secret,
        expiry_offset_seconds,
        -60,
    )
}

pub fn signed_test_jwt_with_nbf(
    subject: &str,
    issuer: &str,
    audience: &str,
    kid: &str,
    secret: &[u8],
    expiry_offset_seconds: i64,
    nbf_offset_seconds: i64,
) -> String {
    #[derive(Serialize)]
    struct Claims<'a> {
        sub: &'a str,
        iss: &'a str,
        aud: &'a str,
        exp: u64,
        nbf: u64,
    }

    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
    header.kid = Some(kid.into());
    jsonwebtoken::encode(
        &header,
        &Claims {
            sub: subject,
            iss: issuer,
            aud: audience,
            exp: jwt_timestamp(expiry_offset_seconds),
            nbf: jwt_timestamp(nbf_offset_seconds),
        },
        &jsonwebtoken::EncodingKey::from_secret(secret),
    )
    .unwrap()
}

pub fn list_roots_request_with_bearer(
    token: String,
) -> tonic::Request<pb::ListAddressRootsRequest> {
    let mut request = tonic::Request::new(pb::ListAddressRootsRequest {});
    request
        .metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    request
}

pub async fn assert_list_roots_unauthenticated(
    client: &mut pb::broker_service_client::BrokerServiceClient<tonic::transport::Channel>,
    token: String,
) {
    assert_eq!(
        client
            .list_address_roots(list_roots_request_with_bearer(token))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::Unauthenticated
    );
}

pub fn jwt_timestamp(offset_seconds: i64) -> u64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    now.saturating_add(offset_seconds).max(0) as u64
}

pub fn base64_json(value: &serde_json::Value) -> String {
    use base64::Engine as _;

    URL_SAFE_NO_PAD.encode(serde_json::to_vec(value).unwrap())
}

pub fn spawn_test_jwks_server(kid: &str, secret: &[u8]) -> (String, oneshot::Sender<()>) {
    use base64::Engine as _;

    let jwks = json!({
        "keys": [
            {
                "kty": "oct",
                "kid": kid,
                "alg": "HS256",
                "k": URL_SAFE_NO_PAD.encode(secret),
            }
        ]
    });
    let app = Router::new().route(
        "/jwks",
        get(move || {
            let jwks = jwks.clone();
            async move { Json(jwks) }
        }),
    );
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown, shutdown_rx) = oneshot::channel();
    std::thread::Builder::new()
        .name("ovs-test-jwks".into())
        .spawn(move || {
            let runtime = tokio::runtime::Runtime::new().unwrap();
            runtime.block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                axum::serve(listener, app)
                    .with_graceful_shutdown(async {
                        let _ = shutdown_rx.await;
                    })
                    .await
                    .unwrap();
            });
        })
        .expect("failed to spawn thread");
    (format!("http://{addr}/jwks"), shutdown)
}

pub struct DenyHiddenReadAuthorizer;

#[async_trait::async_trait]
impl AuthzPlugin for DenyHiddenReadAuthorizer {
    fn plugin_name(&self) -> &str {
        "test-deny-hidden-read"
    }

    async fn authorize(&self, request: &AuthzRequest) -> ovstorage::Result<AuthzDecision> {
        if request.operation == Operation::Read
            && request
                .address
                .as_ref()
                .map(|address| address.as_str().contains("hidden"))
                .unwrap_or(false)
        {
            return Ok(AuthzDecision::deny("hidden objects are filtered"));
        }
        Ok(AuthzDecision::allow())
    }
}
