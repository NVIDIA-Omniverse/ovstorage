// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! AWS credential extraction from a `SecretBundle`. The library layer
//! resolves env / shared-file / keyring sources via `SecretRef` and hands
//! the plugin a populated bundle; we only read from it here.

use std::fmt;

use ovstorage_plugin::{
    ConnectionId, Error, ErrorCode, ErrorContext, Result, SecretBundle, SecretBytes, SecretValue,
};

#[derive(Clone, PartialEq, Eq)]
pub struct AwsCredentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: Option<String>,
}

impl fmt::Debug for AwsCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AwsCredentials")
            .field(
                "access_key_id",
                &redacted_present(!self.access_key_id.is_empty()),
            )
            .field(
                "secret_access_key",
                &redacted_present(!self.secret_access_key.is_empty()),
            )
            .field(
                "session_token",
                &redacted_option(self.session_token.as_ref()),
            )
            .finish()
    }
}

fn redacted_present(present: bool) -> &'static str {
    if present { "<redacted>" } else { "<empty>" }
}

fn redacted_option(value: Option<&String>) -> Option<&'static str> {
    value.map(|_| "<redacted>")
}

impl AwsCredentials {
    /// Empty-strings sentinel used when the backend is anonymous: signing
    /// code paths are skipped, so the values themselves are never read.
    pub fn empty() -> Self {
        Self {
            access_key_id: String::new(),
            secret_access_key: String::new(),
            session_token: None,
        }
    }
}

/// Read credentials from the bundle. Errors when the bundle is incomplete
/// (one of access_key_id / secret_access_key set without the other), or
/// when fields are non-UTF-8. An empty bundle returns `Ok(None)` — the
/// caller decides whether that's anonymous or an error.
pub fn from_bundle(bundle: &SecretBundle) -> Result<Option<AwsCredentials>> {
    let access = bytes_field(bundle, "aws_access_key_id")?;
    let secret = bytes_field(bundle, "aws_secret_access_key")?;
    let token = bytes_field(bundle, "aws_session_token")?;
    match (access, secret) {
        (Some(access), Some(secret)) => Ok(Some(AwsCredentials {
            access_key_id: access,
            secret_access_key: secret,
            session_token: token,
        })),
        (None, None) => Ok(None),
        _ => Err(Error::new(
            ErrorCode::AuthRequired,
            "AWS credentials bundle is incomplete: aws_access_key_id and aws_secret_access_key must be set together",
        )
        .with_context(ErrorContext::Auth {
            connection_id: ConnectionId(String::new()),
            reason: Some("incomplete_bundle".into()),
            expired_at: None,
        })),
    }
}

fn bytes_field(bundle: &SecretBundle, key: &str) -> Result<Option<String>> {
    let Some(value) = bundle.fields.get(key) else {
        return Ok(None);
    };
    let secret = match value {
        SecretValue::Bytes(SecretBytes(bytes)) => bytes,
        SecretValue::File(SecretBytes(bytes)) => bytes,
        _ => {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!("S3 credential field '{key}' must be a Bytes secret"),
            ));
        }
    };
    let text = std::str::from_utf8(secret).map_err(|_| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("S3 credential field '{key}' must be UTF-8 text"),
        )
    })?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    Ok(Some(trimmed.to_string()))
}

pub const KNOWN_CREDENTIAL_FIELDS: &[&str] = &[
    "aws_access_key_id",
    "aws_secret_access_key",
    "aws_session_token",
    "file_path",
    "profile",
];

pub fn known_credential_field(key: &str) -> bool {
    KNOWN_CREDENTIAL_FIELDS.contains(&key)
}

/// Read access key + secret (and optional session token) from an AWS
/// shared credentials INI file section.
pub fn from_aws_credentials_file(path: &str, profile: &str) -> Result<AwsCredentials> {
    let expanded = expand_tilde(path);
    let ini = ini::Ini::load_from_file(&expanded).map_err(|err| {
        Error::new(
            ErrorCode::NotConfigured,
            format!("failed to read AWS credentials file '{expanded}': {err}"),
        )
    })?;
    let section = ini.section(Some(profile)).ok_or_else(|| {
        Error::new(
            ErrorCode::NotConfigured,
            format!("AWS credentials file '{expanded}' has no section '[{profile}]'"),
        )
    })?;
    let access_key_id = section
        .get("aws_access_key_id")
        .ok_or_else(|| {
            Error::new(
                ErrorCode::NotConfigured,
                format!("section '[{profile}]' missing aws_access_key_id"),
            )
        })?
        .trim()
        .to_string();
    let secret_access_key = section
        .get("aws_secret_access_key")
        .ok_or_else(|| {
            Error::new(
                ErrorCode::NotConfigured,
                format!("section '[{profile}]' missing aws_secret_access_key"),
            )
        })?
        .trim()
        .to_string();
    let session_token = section
        .get("aws_session_token")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    Ok(AwsCredentials {
        access_key_id,
        secret_access_key,
        session_token,
    })
}

fn expand_tilde(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/")
        && let Some(home) = home_dir()
    {
        let mut out = home;
        out.push(rest);
        return out.to_string_lossy().into_owned();
    }
    path.to_string()
}

fn home_dir() -> Option<std::path::PathBuf> {
    if let Some(home) = std::env::var_os("HOME") {
        return Some(std::path::PathBuf::from(home));
    }
    if let Some(profile) = std::env::var_os("USERPROFILE") {
        return Some(std::path::PathBuf::from(profile));
    }
    let drive = std::env::var_os("HOMEDRIVE")?;
    let path = std::env::var_os("HOMEPATH")?;
    let mut out = std::path::PathBuf::from(drive);
    out.push(path);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ovstorage_plugin::SecretBytes;

    #[test]
    fn from_bundle_reads_explicit_keys() {
        let mut bundle = SecretBundle::default();
        bundle.fields.insert(
            "aws_access_key_id".into(),
            SecretValue::Bytes(SecretBytes(b"AKIA-EXAMPLE".to_vec())),
        );
        bundle.fields.insert(
            "aws_secret_access_key".into(),
            SecretValue::Bytes(SecretBytes(b"secret-x".to_vec())),
        );
        let creds = from_bundle(&bundle).unwrap().unwrap();
        assert_eq!(creds.access_key_id, "AKIA-EXAMPLE");
        assert_eq!(creds.secret_access_key, "secret-x");
        assert!(creds.session_token.is_none());
    }

    #[test]
    fn from_bundle_empty_returns_none() {
        let creds = from_bundle(&SecretBundle::default()).unwrap();
        assert!(creds.is_none());
    }

    #[test]
    fn from_bundle_with_session_token() {
        let mut bundle = SecretBundle::default();
        bundle.fields.insert(
            "aws_access_key_id".into(),
            SecretValue::Bytes(SecretBytes(b"AKIA".to_vec())),
        );
        bundle.fields.insert(
            "aws_secret_access_key".into(),
            SecretValue::Bytes(SecretBytes(b"s".to_vec())),
        );
        bundle.fields.insert(
            "aws_session_token".into(),
            SecretValue::Bytes(SecretBytes(b"token".to_vec())),
        );
        let creds = from_bundle(&bundle).unwrap().unwrap();
        assert_eq!(creds.session_token.as_deref(), Some("token"));
    }

    #[test]
    fn debug_redacts_aws_credentials() {
        let creds = AwsCredentials {
            access_key_id: "AKIA-SECRET-ID".into(),
            secret_access_key: "secret-access-key".into(),
            session_token: Some("session-token".into()),
        };
        let debug = format!("{creds:?}");
        assert!(!debug.contains("AKIA-SECRET-ID"), "{debug}");
        assert!(!debug.contains("secret-access-key"), "{debug}");
        assert!(!debug.contains("session-token"), "{debug}");
        assert!(debug.contains("<redacted>"), "{debug}");
    }

    #[test]
    fn incomplete_bundle_is_rejected() {
        let mut bundle = SecretBundle::default();
        bundle.fields.insert(
            "aws_access_key_id".into(),
            SecretValue::Bytes(SecretBytes(b"only-access".to_vec())),
        );
        let err = from_bundle(&bundle).unwrap_err();
        assert_eq!(err.code(), ErrorCode::AuthRequired);
    }

    #[test]
    fn known_credential_field_rejects_unknown_key() {
        assert!(known_credential_field("aws_access_key_id"));
        assert!(!known_credential_field("does_not_exist"));
    }
}
