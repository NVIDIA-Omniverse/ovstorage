// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared fixtures for the Hugging Face plugin's integration tests.
//!
//! `ScriptedHttpServer` (from `ovstorage-plugin-test`) covers almost every
//! flow; the one thing it cannot script is a response that must reference the
//! server's OWN origin — the Hub's `Link: <…>; rel="next"` pagination header,
//! which the plugin refuses to follow off the configured endpoint. The
//! [`LinkedHubServer`] here binds first, so each page's `Link` target can be
//! spelled against the live address.

#![allow(dead_code)] // each test binary uses a subset

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread;

/// One scripted page: the JSON body, and whether the response carries a
/// `Link: rel="next"` header pointing at `{endpoint}{next_path}`.
pub struct LinkedPage {
    pub body: String,
    pub next_path: Option<String>,
}

/// Sequential loopback server whose `Link` headers reference its own origin.
/// Answers one request per connection (`Connection: close`) so the ordinal
/// script cannot be defeated by keep-alive reuse.
pub struct LinkedHubServer {
    endpoint: String,
    requests: Arc<Mutex<Vec<String>>>,
}

impl LinkedHubServer {
    pub fn spawn(pages: Vec<LinkedPage>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let endpoint = format!("http://{}", listener.local_addr().expect("local addr"));
        let requests: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let seen = requests.clone();
        let origin = endpoint.clone();
        thread::spawn(move || {
            for page in pages {
                let Ok((mut stream, _)) = listener.accept() else {
                    return;
                };
                // Read the request head; the tree/commits requests these
                // pages script are bodyless GETs.
                let mut raw = Vec::new();
                let mut buf = [0u8; 1024];
                while !raw.windows(4).any(|window| window == b"\r\n\r\n") {
                    match stream.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => raw.extend_from_slice(&buf[..n]),
                        Err(_) => return,
                    }
                }
                seen.lock()
                    .expect("request log")
                    .push(String::from_utf8_lossy(&raw).into_owned());
                let link_header = page
                    .next_path
                    .as_deref()
                    .map(|path| format!("Link: <{origin}{path}>; rel=\"next\"\r\n"))
                    .unwrap_or_default();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{link_header}\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                    page.body.len(),
                    page.body
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        Self { endpoint, requests }
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub fn requests(&self) -> Vec<String> {
        self.requests.lock().expect("request log").clone()
    }

    pub fn hits(&self) -> usize {
        self.requests.lock().expect("request log").len()
    }
}
