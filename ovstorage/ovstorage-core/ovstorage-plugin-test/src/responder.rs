// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Loopback HTTP responder for redirect-follower tests.
//!
//! Binds only `127.0.0.1`. Framing is intentionally restrictive
//! (`GET`/`PUT`/`POST`/`HEAD` with `Content-Length`, no chunked, no
//! keep-alive); deviations surface as a captured request the
//! assertion can pin. Manual framing avoids dragging an HTTP server
//! crate into the test plugin.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

/// Scripted response for one [`Route`] match.
#[derive(Clone, Debug)]
pub struct ScriptedResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl ScriptedResponse {
    pub fn ok(body: &[u8]) -> Self {
        Self {
            status: 200,
            headers: vec![("content-type".into(), "application/octet-stream".into())],
            body: body.to_vec(),
        }
    }

    pub fn not_found() -> Self {
        Self {
            status: 404,
            headers: vec![],
            body: Vec::new(),
        }
    }
}

/// One match clause; matched in insertion order, first match wins.
#[derive(Clone, Debug)]
pub struct Route {
    pub method: String,
    /// Empty path prefix matches any path under the method.
    pub path_prefix: String,
    pub response: ScriptedResponse,
}

impl Route {
    pub fn new(method: &str, path_prefix: &str, response: ScriptedResponse) -> Self {
        Self {
            method: method.to_uppercase(),
            path_prefix: path_prefix.to_string(),
            response,
        }
    }
}

/// One captured request, retrieved via [`Responder::captures`].
#[derive(Clone, Debug)]
pub struct CapturedRequest {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl CapturedRequest {
    /// Header lookup, case-insensitive.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

struct ResponderState {
    routes: Vec<Route>,
    captures: Vec<CapturedRequest>,
    // Surfaces unexpected requests as a captured 400, not a TCP drop.
    default_response: ScriptedResponse,
}

/// Loopback-only HTTP responder; stops on drop.
pub struct Responder {
    addr: SocketAddr,
    state: Arc<Mutex<ResponderState>>,
    shutdown: Arc<AtomicBool>,
    accept_thread: Mutex<Option<JoinHandle<()>>>,
}

impl Responder {
    /// Start on a loopback ephemeral port.
    pub fn start(routes: Vec<Route>) -> std::io::Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let addr = listener.local_addr()?;
        listener.set_nonblocking(true)?;

        let state = Arc::new(Mutex::new(ResponderState {
            routes,
            captures: Vec::new(),
            default_response: ScriptedResponse {
                status: 400,
                headers: vec![],
                body: b"unmatched request".to_vec(),
            },
        }));
        let state_for_thread = state.clone();
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_for_thread = shutdown.clone();

        let handle = thread::Builder::new()
            .name("ovs-test-resp".into())
            .spawn(move || {
                while !shutdown_for_thread.load(Ordering::Acquire) {
                    match listener.accept() {
                        Ok((s, _peer)) => {
                            let _ = s.set_nonblocking(false);
                            let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
                            let _ = s.set_write_timeout(Some(Duration::from_secs(5)));
                            let st = state_for_thread.clone();
                            thread::Builder::new()
                                .name("ovs-test-conn".into())
                                .spawn(move || handle_connection(s, st))
                                .expect("failed to spawn thread");
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(20));
                        }
                        Err(error) => {
                            eprintln!("ovs-test-resp accept error: {error}");
                            thread::sleep(Duration::from_millis(20));
                        }
                    }
                }
            })?;

        Ok(Self {
            addr,
            state,
            shutdown,
            accept_thread: Mutex::new(Some(handle)),
        })
    }

    /// Base URL for redirect emission. Always loopback.
    pub fn base_url(&self) -> String {
        format!("http://{}/", self.addr)
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Snapshot the captured requests.
    pub fn captures(&self) -> Vec<CapturedRequest> {
        self.state
            .lock()
            .map(|s| s.captures.clone())
            .unwrap_or_default()
    }

    /// Replace the route table without restarting the listener.
    pub fn set_routes(&self, routes: Vec<Route>) {
        if let Ok(mut s) = self.state.lock() {
            s.routes = routes;
            s.captures.clear();
        }
    }
}

impl Drop for Responder {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        let _ = TcpStream::connect(self.addr);
        if let Ok(mut slot) = self.accept_thread.lock()
            && let Some(handle) = slot.take()
        {
            let _ = handle.join();
        }
    }
}

fn handle_connection(mut stream: TcpStream, state: Arc<Mutex<ResponderState>>) {
    let mut reader = BufReader::new(
        stream
            .try_clone()
            .expect("test-responder: cloning stream for read side"),
    );
    let request = match read_request(&mut reader) {
        Ok(r) => r,
        Err(_) => return,
    };

    let response = {
        let mut st = state.lock().expect("test-responder state lock");
        let matched = st
            .routes
            .iter()
            .find(|route| {
                route.method.eq_ignore_ascii_case(&request.method)
                    && request.path.starts_with(&route.path_prefix)
            })
            .cloned();
        st.captures.push(request);
        matched
            .map(|r| r.response)
            .unwrap_or_else(|| st.default_response.clone())
    };

    let _ = write_response(&mut stream, &response);
}

fn read_request<R: BufRead>(reader: &mut R) -> std::io::Result<CapturedRequest> {
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "malformed request line",
        ));
    }
    let method = parts[0].to_string();
    let path = parts[1].to_string();

    let mut headers: Vec<(String, String)> = Vec::new();
    let mut content_length: usize = 0;
    loop {
        line.clear();
        reader.read_line(&mut line)?;
        if line == "\r\n" || line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.trim_end().split_once(':') {
            let k = k.trim().to_lowercase();
            let v = v.trim().to_string();
            if k == "content-length" {
                content_length = v.parse().unwrap_or(0);
            }
            headers.push((k, v));
        }
    }

    // Content-Length only; no chunked. Streaming-write tests should
    // capture a fixed-length request here.
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body)?;
    }

    Ok(CapturedRequest {
        method,
        path,
        headers,
        body,
    })
}

fn write_response<W: Write>(out: &mut W, response: &ScriptedResponse) -> std::io::Result<()> {
    let status_text = match response.status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        400 => "Bad Request",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "OK",
    };
    write!(out, "HTTP/1.1 {} {}\r\n", response.status, status_text)?;
    let mut have_content_length = false;
    let mut header_map: HashMap<String, ()> = HashMap::new();
    for (k, v) in &response.headers {
        if k.eq_ignore_ascii_case("content-length") {
            have_content_length = true;
        }
        header_map.insert(k.to_lowercase(), ());
        write!(out, "{}: {}\r\n", k, v)?;
    }
    if !have_content_length {
        write!(out, "content-length: {}\r\n", response.body.len())?;
    }
    if !header_map.contains_key("connection") {
        // Force close so the client EOFs without waiting on keep-alive.
        write!(out, "connection: close\r\n")?;
    }
    write!(out, "\r\n")?;
    out.write_all(&response.body)?;
    out.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpStream;

    fn http_get(url: &str) -> (u16, Vec<(String, String)>, Vec<u8>) {
        let after = url.strip_prefix("http://").unwrap();
        let (host, path) = after
            .split_once('/')
            .map(|(h, p)| (h, format!("/{p}")))
            .unwrap_or((after, "/".into()));
        let mut stream = TcpStream::connect(host).unwrap();
        write!(
            stream,
            "GET {} HTTP/1.1\r\nhost: {}\r\nconnection: close\r\n\r\n",
            path, host
        )
        .unwrap();
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).unwrap();
        parse_response(&raw)
    }

    fn http_put(url: &str, body: &[u8]) -> (u16, Vec<(String, String)>, Vec<u8>) {
        let after = url.strip_prefix("http://").unwrap();
        let (host, path) = after
            .split_once('/')
            .map(|(h, p)| (h, format!("/{p}")))
            .unwrap_or((after, "/".into()));
        let mut stream = TcpStream::connect(host).unwrap();
        write!(
            stream,
            "PUT {} HTTP/1.1\r\nhost: {}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            path,
            host,
            body.len()
        )
        .unwrap();
        stream.write_all(body).unwrap();
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).unwrap();
        parse_response(&raw)
    }

    fn parse_response(raw: &[u8]) -> (u16, Vec<(String, String)>, Vec<u8>) {
        let s = String::from_utf8_lossy(raw);
        let mut iter = s.splitn(2, "\r\n\r\n");
        let head = iter.next().unwrap();
        let body_str = iter.next().unwrap_or("");
        let mut lines = head.lines();
        let status_line = lines.next().unwrap();
        let parts: Vec<&str> = status_line.split_whitespace().collect();
        let status: u16 = parts[1].parse().unwrap();
        let mut headers = Vec::new();
        for line in lines {
            if let Some((k, v)) = line.split_once(':') {
                headers.push((k.trim().to_lowercase(), v.trim().to_string()));
            }
        }
        let content_length: usize = headers
            .iter()
            .find(|(k, _)| k == "content-length")
            .and_then(|(_, v)| v.parse().ok())
            .unwrap_or(body_str.len());
        let body = body_str.as_bytes()[..content_length.min(body_str.len())].to_vec();
        (status, headers, body)
    }

    #[test]
    fn responder_serves_scripted_get_and_records_capture() {
        let routes = vec![Route::new("GET", "/hello", ScriptedResponse::ok(b"world"))];
        let resp = Responder::start(routes).expect("responder starts");
        let url = format!("{}hello", resp.base_url());
        let (status, _headers, body) = http_get(&url);
        assert_eq!(status, 200);
        assert_eq!(body, b"world");
        let captures = resp.captures();
        assert_eq!(captures.len(), 1);
        assert_eq!(captures[0].method, "GET");
        assert!(captures[0].path.starts_with("/hello"));
    }

    #[test]
    fn responder_records_put_body_for_assertion() {
        let routes = vec![Route::new(
            "PUT",
            "/upload",
            ScriptedResponse {
                status: 201,
                headers: vec![("etag".into(), "v1".into())],
                body: Vec::new(),
            },
        )];
        let resp = Responder::start(routes).expect("responder starts");
        let url = format!("{}upload", resp.base_url());
        let (status, headers, _body) = http_put(&url, b"payload-bytes");
        assert_eq!(status, 201);
        assert!(headers.iter().any(|(k, v)| k == "etag" && v == "v1"));
        let captures = resp.captures();
        assert_eq!(captures.len(), 1);
        assert_eq!(captures[0].method, "PUT");
        assert_eq!(captures[0].body, b"payload-bytes");
        assert_eq!(captures[0].header("content-length"), Some("13"));
    }

    #[test]
    fn responder_returns_400_for_unmatched_route() {
        let resp = Responder::start(vec![]).expect("responder starts");
        let url = format!("{}some/path", resp.base_url());
        let (status, _headers, _body) = http_get(&url);
        assert_eq!(status, 400);
        let captures = resp.captures();
        assert_eq!(captures.len(), 1);
    }

    #[test]
    fn responder_base_url_is_loopback_only() {
        let resp = Responder::start(vec![]).expect("responder starts");
        let addr = resp.addr();
        assert!(addr.ip().is_loopback());
    }
}
