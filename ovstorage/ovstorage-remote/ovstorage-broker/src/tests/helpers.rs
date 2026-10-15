// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Drain a test gRPC server cleanly. `BrokerGrpcServer::drop` only
/// fires the shutdown signal; it can't await the drain because Drop
/// isn't async. Tests that drop the server and then drop the client Stack
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

/// Three crates keep their own copy of this helper (this one,
/// `ovstorage-rest/src/tests.rs`, `ovstorage-rest/tests/rest_conformance.rs`)
/// because they share no test-support crate: two are `#[cfg(test)]` modules in
/// different libraries and the third is a separate integration binary. They
/// are kept identical in mechanism and in coverage, so a change to the naming
/// rule is the same edit three times rather than three different rules.
/// `ovstorage-rest/src/test_utils.rs`'s auth root is deliberately NOT one of
/// them: `ovstorage::init_auth_substrate` holds a process-global substrate and
/// rejects a second call naming a different `auth_dir`, so that name must stay
/// one-per-process and carries no serial.
static TEMP_DIR_SERIAL: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn next_temp_dir_serial() -> u64 {
    TEMP_DIR_SERIAL.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// The naming rule, with both varying inputs supplied by the caller.
///
/// Split out so a test can freeze the clock reading. The collision this
/// helper defends against is two calls landing in the SAME tick, and two real
/// `SystemTime::now()` readings almost always differ -- so a test that simply
/// called `unique_temp_dir()` twice would stay green with the serial removed,
/// which is a regression guard that does not guard.
fn temp_dir_named(stamp: u128, serial: u64) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "ovstorage-broker-test-{}-{stamp}-{serial}",
        std::process::id()
    ))
}

/// A temporary root no other call in this process can name.
///
/// The pid and the wall-clock stamp keep the name distinct across processes
/// and runs; the serial is what makes it distinct *within* a process. A key
/// built only from `SystemTime::now()` is probabilistically unique, and the
/// probability is worst exactly where it matters: several tests here take two
/// roots back to back on one thread and depend on them differing (a source and
/// a destination, a Visible and a Hidden root). Those two calls can fall in
/// the same nanosecond, and a collision then silently collapses the two roots
/// into one and the test passes for the wrong reason. The serial removes the
/// possibility instead of shrinking it.
pub fn unique_temp_dir() -> std::path::PathBuf {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    temp_dir_named(stamp, next_temp_dir_serial())
}

#[test]
fn same_tick_temp_dirs_differ() {
    // The clock is frozen so the same-tick collision is certain rather than
    // merely possible; this is the case that silently collapses two roots a
    // test meant to keep apart.
    const FROZEN_TICK: u128 = 1_700_000_000_000_000_000;

    let first = temp_dir_named(FROZEN_TICK, next_temp_dir_serial());
    let second = temp_dir_named(FROZEN_TICK, next_temp_dir_serial());
    assert_ne!(
        first, second,
        "two temp roots minted in the same clock tick must not collide"
    );
}

#[test]
fn concurrent_temp_dirs_are_all_distinct() {
    const THREADS: usize = 16;
    const PER_THREAD: usize = 64;

    let paths: Vec<std::path::PathBuf> = std::thread::scope(|scope| {
        // Every thread is spawned before any is joined, so the calls really do
        // overlap. Joining as part of the spawning iterator would run them one
        // after another and test nothing about concurrency.
        let mut handles = Vec::with_capacity(THREADS);
        for _ in 0..THREADS {
            handles.push(scope.spawn(|| {
                (0..PER_THREAD)
                    .map(|_| unique_temp_dir())
                    .collect::<Vec<_>>()
            }));
        }
        handles
            .into_iter()
            .flat_map(|handle| handle.join().unwrap())
            .collect()
    });

    let distinct: std::collections::HashSet<_> = paths.iter().collect();
    assert_eq!(
        distinct.len(),
        THREADS * PER_THREAD,
        "{} of {} concurrently minted temp roots collided",
        THREADS * PER_THREAD - distinct.len(),
        THREADS * PER_THREAD
    );
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

pub async fn broker_round_trip(prefix: &Url, discovery_url: &str) {
    let client = broker_client_stack(discovery_url).await;
    let object =
        address::join_relative(prefix, &format!("local-transport-{}.txt", unique_suffix()))
            .unwrap();
    ovstorage::ext::LayerExt::write(
        &*client,
        object.clone(),
        Body::Bytes(b"local broker bytes".to_vec()),
        WriteOptions::default(),
        None,
    )
    .await
    .unwrap();
    let (bytes, info) =
        ovstorage::ext::LayerExt::read_bytes(&*client, object, ReadOptions::default(), None)
            .await
            .unwrap();
    assert_eq!(bytes, b"local broker bytes");
    assert_eq!(info.size, Some(18));
}

/// A local (peer-cred) transport listener config for transport round-trip
/// tests. Authn is the auth layer's concern (transport-tag driven at request
/// time), so this only carries transport fields; `auth = "anonymous"` keeps the
/// listener valid without gating the round trip.
pub fn test_listener_config() -> BrokerListenerConfig {
    BrokerListenerConfig {
        bind: "127.0.0.1:0".into(),
        tls: None,
        trusted_proxy: false,
        trusted_peers: vec![],
        auth: Some(toml::Value::String("anonymous".into())),
    }
}

pub fn unique_suffix() -> String {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{}-{stamp}", std::process::id())
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

/// Allow-all authz policy TOML. The single home is the auth crate's
/// [`ANONYMOUS_ALLOW_ALL_POLICY`] (what `auth = "anonymous"` expands to); the
/// broker does not define its own allow-all body.
pub use ovstorage_authz_layer::ANONYMOUS_ALLOW_ALL_POLICY;

/// Deny-all authz policy TOML (an empty rule set denies by default).
pub const DENY_ALL_POLICY: &str = "";

/// Allow-all baseline plus a deny of `stat` + `read` on `denied` for a concrete
/// object address. The deny rule's prefix is the full object URL, longer than
/// the `*` allow, so longest-prefix precedence denies stat/read on exactly that
/// object while every other op/address stays allowed. Denying `stat` (not just
/// `read`) makes the object disappear from the in-stack list `Stat` post-filter;
/// denying `read` drives `check_access`'s read intersect.
pub fn deny_read_stat_on(denied: &Url) -> String {
    format!(
        r#"
[[policy]]
id = "allow-all"
effect = "allow"
principal = "*"
operations = ["*"]
prefix = "*"

[[policy]]
id = "deny-hidden"
effect = "deny"
principal = "*"
operations = ["stat", "read"]
prefix = "{denied}"
"#
    )
}
