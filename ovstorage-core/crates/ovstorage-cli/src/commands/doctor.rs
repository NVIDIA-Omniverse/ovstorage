// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Aggregate library diagnostic state for operators and agents.

use std::sync::Arc;

use ovstorage::{ConnectionAuthState, Error, ErrorCode, Library, Storage, redact_message};
use serde::Serialize;

const OPERATION: &str = "doctor";

#[derive(Debug, Clone, Serialize)]
pub struct DoctorReport {
    pub ovstorage_version: String,
    pub backend_kinds: Vec<BackendKindEntry>,
    pub connections: Vec<ConnectionEntry>,
    pub address_roots: Vec<AddressRootEntry>,
    pub aliases: Vec<AliasEntry>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackendKindEntry {
    pub kind: String,
    pub display_name: String,
    pub description: Option<String>,
    pub supports_runtime_add: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConnectionEntry {
    pub id: String,
    pub backend_kind: String,
    pub display_name: String,
    pub addresses: Vec<String>,
    pub auth_state_kind: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AddressRootEntry {
    pub address: String,
    pub backend_kind: String,
    pub display_name: Option<String>,
    pub visibility: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AliasEntry {
    pub id: String,
    pub from: String,
    pub to: String,
    pub visibility: String,
}

pub async fn run(library: Arc<Library>, json: bool) -> ovstorage::Result<()> {
    let report = gather(library.as_ref())?;
    if json {
        emit_json(&report)?;
    } else {
        emit_human(&report);
    }
    Ok(())
}

pub fn gather(library: &Library) -> ovstorage::Result<DoctorReport> {
    Ok(DoctorReport {
        ovstorage_version: env!("CARGO_PKG_VERSION").to_string(),
        backend_kinds: gather_backend_kinds(library)?,
        connections: gather_connections(library)?,
        address_roots: gather_address_roots(library)?,
        aliases: gather_aliases(library)?,
    })
}

pub fn gather_backend_kinds(library: &Library) -> ovstorage::Result<Vec<BackendKindEntry>> {
    Ok(library
        .list_backend_kinds()?
        .into_iter()
        .map(|d| BackendKindEntry {
            kind: redact_message(&d.kind).into_owned(),
            display_name: redact_message(&d.display_name).into_owned(),
            description: d.description.map(|s| redact_message(&s).into_owned()),
            supports_runtime_add: d.supports_runtime_add,
        })
        .collect())
}

pub fn gather_connections(library: &Library) -> ovstorage::Result<Vec<ConnectionEntry>> {
    Ok(library
        .list_connections()?
        .into_iter()
        .map(|c| ConnectionEntry {
            id: c.id.0,
            backend_kind: redact_message(&c.backend_kind).into_owned(),
            display_name: redact_message(&c.display_name).into_owned(),
            addresses: c
                .current_addresses
                .into_iter()
                .map(|u| redact_message(u.as_str()).into_owned())
                .collect(),
            auth_state_kind: auth_state_kind(&c.auth_state).to_string(),
        })
        .collect())
}

pub fn gather_address_roots(library: &Library) -> ovstorage::Result<Vec<AddressRootEntry>> {
    Ok(library
        .list_address_roots()?
        .into_iter()
        .map(|r| AddressRootEntry {
            address: redact_message(r.address.as_str()).into_owned(),
            backend_kind: redact_message(&r.backend_kind).into_owned(),
            display_name: r.display_name.map(|s| redact_message(&s).into_owned()),
            visibility: format!("{:?}", r.visibility),
        })
        .collect())
}

pub fn gather_aliases(library: &Library) -> ovstorage::Result<Vec<AliasEntry>> {
    Ok(library
        .list_aliases()?
        .into_iter()
        .map(|a| AliasEntry {
            id: a.id.0,
            from: redact_message(a.from.as_str()).into_owned(),
            to: redact_message(a.to.as_str()).into_owned(),
            visibility: format!("{:?}", a.visibility),
        })
        .collect())
}

fn auth_state_kind(auth_state: &ConnectionAuthState) -> &'static str {
    match auth_state {
        ConnectionAuthState::Authenticated { .. } => "Authenticated",
        ConnectionAuthState::AwaitingAuth { .. } => "AwaitingAuth",
        ConnectionAuthState::AuthFailed { .. } => "AuthFailed",
        ConnectionAuthState::Anonymous => "Anonymous",
    }
}

fn emit_human(r: &DoctorReport) {
    println!("ovstorage doctor");
    println!("================");
    println!("Version: {}", r.ovstorage_version);
    println!();

    println!("Backend kinds loaded: {}", r.backend_kinds.len());
    for k in &r.backend_kinds {
        println!("  - {} ({})", k.display_name, k.kind);
        if let Some(desc) = &k.description {
            println!("    {desc}");
        }
    }
    println!();

    println!("Connections: {}", r.connections.len());
    for c in &r.connections {
        println!("  - {} [{}]", c.display_name, c.backend_kind);
        println!("    id={} auth={}", c.id, c.auth_state_kind);
        for a in &c.addresses {
            println!("    addr={a}");
        }
    }
    println!();

    println!("Address roots: {}", r.address_roots.len());
    for a in &r.address_roots {
        let name = a.display_name.as_deref().unwrap_or("(unnamed)");
        println!(
            "  - {} ({}) [{}] visibility={}",
            a.address, a.backend_kind, name, a.visibility
        );
    }
    println!();

    println!("Aliases: {}", r.aliases.len());
    for al in &r.aliases {
        println!(
            "  - {} -> {} (id={} visibility={})",
            al.from, al.to, al.id, al.visibility
        );
    }
}

fn emit_json(r: &DoctorReport) -> ovstorage::Result<()> {
    let env = ovstorage_envelope::Envelope::ok(OPERATION, r);
    let text = serde_json::to_string_pretty(&env).map_err(|err| {
        Error::new(
            ErrorCode::Internal,
            format!("envelope serialization failed: {err}"),
        )
    })?;
    println!("{text}");
    Ok(())
}
