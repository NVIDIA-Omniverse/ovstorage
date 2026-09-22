// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Engine-owned types for the hub cache-aside client.
//!
//! Configuration, the error type, the hub's result codes translated out of
//! protobuf, and the outcome enums that keep expected answers — a cache
//! miss, a write another client is already performing — out of the error
//! channel.

use std::time::Duration;

use crate::client::{ReadHandle, WriteHandle};

/// The address the hub listens on when nothing else is configured.
pub const DEFAULT_HUB_ENDPOINT: &str = "127.0.0.1:14093";

/// Connection settings for a [`HubCacheClient`](crate::HubCacheClient).
#[derive(Clone, Debug)]
pub struct HubClientConfig {
    /// `host:port` of the hub's framed-protobuf listener.
    pub endpoint: String,
    /// Name reported in the connect handshake; the hub uses it for
    /// diagnostics only.
    pub client_name: String,
    /// Deadline for each round trip: the dial, the handshake, and every
    /// call each get this budget.
    pub timeout: Duration,
    /// How long the client fails fast after a connection failure before it
    /// dials again.
    pub cooldown: Duration,
}

impl Default for HubClientConfig {
    fn default() -> Self {
        Self {
            endpoint: DEFAULT_HUB_ENDPOINT.to_string(),
            client_name: "ovstorage".to_string(),
            timeout: Duration::from_millis(1000),
            cooldown: Duration::from_secs(5),
        }
    }
}

/// A hub result code, translated out of the wire enum.
///
/// The client maps the codes that carry an expected outcome into
/// [`ReadOpen`] and [`WriteOpen`]; the rest reach callers inside
/// [`HubError::Hub`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum HubResultCode {
    /// The operation succeeded.
    Success,
    /// The entry was abandoned by the client that was writing it.
    Abandoned,
    /// The key is already present; hub keys are write-once.
    AlreadyExists,
    /// The entry does not fit within the hub's size limits.
    TooLarge,
    /// The supplied handle is not open on this connection.
    HandleNotFound,
    /// The hub failed internally.
    Internal,
    /// The key is not cached.
    NotFound,
    /// Another client holds a write lease on the key.
    PendingWrite,
    /// A code this crate does not recognise, carried verbatim.
    Unrecognized(i32),
}

impl HubResultCode {
    /// Translates a wire result code into its engine-owned form.
    pub(crate) fn from_wire(code: i32) -> Self {
        match code {
            0 => Self::Success,
            1 => Self::Abandoned,
            2 => Self::AlreadyExists,
            3 => Self::TooLarge,
            4 => Self::HandleNotFound,
            5 => Self::Internal,
            6 => Self::NotFound,
            7 => Self::PendingWrite,
            other => Self::Unrecognized(other),
        }
    }
}

impl std::fmt::Display for HubResultCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Success => f.write_str("success"),
            Self::Abandoned => f.write_str("abandoned"),
            Self::AlreadyExists => f.write_str("already exists"),
            Self::TooLarge => f.write_str("too large"),
            Self::HandleNotFound => f.write_str("handle not found"),
            Self::Internal => f.write_str("internal hub error"),
            Self::NotFound => f.write_str("not found"),
            Self::PendingWrite => f.write_str("pending write"),
            Self::Unrecognized(code) => write!(f, "unrecognized result code {code}"),
        }
    }
}

/// Why a hub call failed.
///
/// The split exists so a caller can tell "the hub is not answering" from
/// "the hub answered something impossible". An unreachable hub is always
/// [`HubError::Unavailable`] and never resembles a cache miss: a miss is an
/// [`ReadOpen::NotCached`] outcome, not an error.
#[derive(Clone, Debug)]
pub enum HubError {
    /// The hub is not usable right now: the dial failed, the transport
    /// broke, the deadline expired, the handshake failed, or the client is
    /// still in its post-failure cooldown.
    Unavailable(String),
    /// The hub violated the protocol: a malformed or mismatched frame, a
    /// result the request cannot produce, an `ErrorInfoResult`, or a
    /// missing cache-aside interface.
    Protocol(String),
    /// The hub answered with a result code the operation does not define.
    Hub(HubResultCode),
}

impl HubError {
    /// Reports whether the failure is availability-shaped, so callers can
    /// degrade to their uncached path instead of surfacing an error.
    pub fn is_unavailable(&self) -> bool {
        matches!(self, Self::Unavailable(_))
    }

    pub(crate) fn unavailable(message: impl Into<String>) -> Self {
        Self::Unavailable(message.into())
    }

    pub(crate) fn protocol(message: impl Into<String>) -> Self {
        Self::Protocol(message.into())
    }
}

impl std::fmt::Display for HubError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable(message) => write!(f, "hub unavailable: {message}"),
            Self::Protocol(message) => write!(f, "hub protocol violation: {message}"),
            Self::Hub(code) => write!(f, "hub returned {code}"),
        }
    }
}

impl std::error::Error for HubError {}

/// The outcome of opening a key for reading.
#[derive(Debug)]
pub enum ReadOpen {
    /// The key is cached and the returned handle holds a read lease on it.
    Opened(ReadHandle),
    /// The key is not cached.
    NotCached,
    /// Another client is writing this key; there is nothing to read yet and
    /// nothing to fill.
    PendingWrite,
}

/// The outcome of opening a key for writing.
#[derive(Debug)]
pub enum WriteOpen {
    /// The key is reserved and the returned handle holds a write lease on
    /// it until it is committed or aborted.
    Opened(WriteHandle),
    /// The key is already committed. Hub keys are write-once, so this is
    /// the benign answer to a redundant fill rather than a failure.
    AlreadyExists,
    /// Another client is filling this key right now. Nothing is committed
    /// yet, so there is nothing to serve either — only to wait out, which
    /// the hub offers no way to do.
    PendingWrite,
    /// The hub refuses to store an entry of the requested size.
    TooLarge,
}
