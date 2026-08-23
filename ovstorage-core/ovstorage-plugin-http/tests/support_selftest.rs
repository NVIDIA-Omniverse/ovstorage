// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Self-test for the signing toolkit in `tests/support/`.
//!
//! Every credential test downstream is only as trustworthy as its verifier: one
//! that answers `true` unconditionally would make the whole suite vacuous. So
//! each minter is checked against its own verifier here, each verifier is shown
//! to reject a one-byte tamper and an out-of-scope request, and the verifying
//! origin is shown to answer `403` — not `200` — when the check fails.
//!
//! The origin is driven over a raw socket rather than through the plugin: the
//! subject here is the fixture, and a bare `TcpStream` keeps the request bytes
//! under the test's own control.

mod support;

use std::io::{Read, Write};
use std::net::TcpStream;

use support::{
    VerifyingOrigin, mint_container_sas, mint_sigv4_presign, verify_container_sas,
    verify_sigv4_presign,
};

/// Signing key shared by the minters and the verifiers, so a mismatch can only
/// come from the request, never from a key disagreement.
const KEY: &[u8] = b"ovstorage-http-test-signing-key!";
const CONTAINER: &str = "media";
const EXPIRY: &str = "2030-01-01T00:00:00Z";
const AMZ_DATE: &str = "20300101T000000Z";

/// Flip the final byte of a query string — always inside the signature, since
/// both minters emit the signature last.
fn tamper_final_byte(query: &str) -> String {
    let mut bytes = query.as_bytes().to_vec();
    let last = bytes.len() - 1;
    bytes[last] = if bytes[last] == b'a' { b'b' } else { b'a' };
    String::from_utf8(bytes).expect("ASCII query stays UTF-8")
}

fn get(port: u16, target: &str) -> (u16, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect to the origin");
    let head = format!("GET {target} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    stream.write_all(head.as_bytes()).expect("write request");
    stream.flush().expect("flush request");
    let mut response = Vec::new();
    stream.read_to_end(&mut response).expect("read response");
    let text = String::from_utf8_lossy(&response).into_owned();
    let status = text
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .expect("status line");
    (status, text)
}

#[test]
fn container_sas_grants_every_path_under_its_container() {
    let sas = mint_container_sas(KEY, CONTAINER, EXPIRY);
    assert!(
        sas.contains("sr=c"),
        "container SAS is container-scoped: {sas}"
    );
    for path in ["/media/a.txt", "/media/nested/deep/b.bin"] {
        assert!(
            verify_container_sas(KEY, CONTAINER, path, &sas),
            "one container grant covers {path}"
        );
    }
}

#[test]
fn container_sas_does_not_reach_outside_its_container() {
    let sas = mint_container_sas(KEY, CONTAINER, EXPIRY);
    assert!(!verify_container_sas(KEY, CONTAINER, "/other/a.txt", &sas));
    assert!(!verify_container_sas(KEY, CONTAINER, "/mediaX/a.txt", &sas));
}

#[test]
fn container_sas_rejects_a_tampered_signature() {
    let sas = mint_container_sas(KEY, CONTAINER, EXPIRY);
    let tampered = tamper_final_byte(&sas);
    assert_ne!(sas, tampered);
    assert!(!verify_container_sas(
        KEY,
        CONTAINER,
        "/media/a.txt",
        &tampered
    ));
}

#[test]
fn container_sas_rejects_a_foreign_key() {
    let sas = mint_container_sas(KEY, CONTAINER, EXPIRY);
    assert!(!verify_container_sas(
        b"a-different-signing-key-entirely",
        CONTAINER,
        "/media/a.txt",
        &sas
    ));
}

#[test]
fn sigv4_presign_verifies_only_at_the_path_it_was_minted_for() {
    let presign = mint_sigv4_presign(KEY, "/media/a.txt", AMZ_DATE);
    assert!(verify_sigv4_presign(KEY, "/media/a.txt", &presign));
    // The path is signed material, which is what makes the token per-object.
    assert!(!verify_sigv4_presign(KEY, "/media/b.txt", &presign));
    assert!(!verify_sigv4_presign(KEY, "/media/a.txt/", &presign));
}

#[test]
fn sigv4_presign_rejects_a_tampered_signature() {
    let presign = mint_sigv4_presign(KEY, "/media/a.txt", AMZ_DATE);
    let tampered = tamper_final_byte(&presign);
    assert_ne!(presign, tampered);
    assert!(!verify_sigv4_presign(KEY, "/media/a.txt", &tampered));
}

#[test]
fn verifying_origin_answers_200_on_a_valid_signature_and_403_otherwise() {
    let origin = VerifyingOrigin::spawn(b"signed-body".to_vec(), |request| {
        verify_container_sas(KEY, CONTAINER, &request.path, &request.query)
    });
    let sas = mint_container_sas(KEY, CONTAINER, EXPIRY);

    let (status, response) = get(origin.port(), &format!("/media/a.txt?{sas}"));
    assert_eq!(status, 200, "valid signature is served: {response}");
    assert!(
        response.ends_with("signed-body"),
        "body follows the head: {response}"
    );

    let (status, _) = get(
        origin.port(),
        &format!("/media/a.txt?{}", tamper_final_byte(&sas)),
    );
    assert_eq!(status, 403, "a tampered signature is refused");

    let (status, _) = get(origin.port(), "/media/a.txt");
    assert_eq!(status, 403, "an unsigned request is refused");
}

#[test]
fn verifying_origin_records_raw_request_lines() {
    let origin = VerifyingOrigin::spawn(b"signed-body".to_vec(), |request| {
        verify_container_sas(KEY, CONTAINER, &request.path, &request.query)
    });
    let sas = mint_container_sas(KEY, CONTAINER, EXPIRY);
    let target = format!("/media/a.txt?{sas}");
    let (status, _) = get(origin.port(), &target);
    assert_eq!(status, 200);

    assert_eq!(
        origin.request_lines(),
        vec![format!("GET {target} HTTP/1.1")],
        "the request line is recorded byte-for-byte"
    );
    let recorded = origin.requests();
    assert_eq!(
        recorded[0].query, sas,
        "the query survives with its encoding intact"
    );
    assert_eq!(recorded[0].header("Host"), Some("127.0.0.1"));
}
