// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Versioned JSON envelope for agent-facing surfaces.
//!
//! The v0.1 shape wraps CLI `--json` output and future machine-facing
//! responses in a stable `{v, ok, operation, result | error}` contract.

use ovstorage_plugin::ErrorContext;
use serde::{Deserialize, Serialize};

/// Envelope schema version emitted by this crate.
pub const ENVELOPE_VERSION: &str = "0.1";

/// Generic envelope wrapping an operation-specific result payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "R: Serialize", deserialize = "R: Deserialize<'de>"))]
pub struct Envelope<R> {
    pub v: String,
    pub ok: bool,
    pub operation: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub operation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub backend: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub resource: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub result: Option<R>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub error: Option<EnvelopeError>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub warnings: Vec<String>,
}

/// Partial-completion payload inside [`EnvelopeError`].
///
/// Present only when `code == "PartialCompletion"`. Field values are the
/// stable `snake_case` names from the corresponding `as_str()` helpers in the
/// core library.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EnvelopePartialContext {
    pub completed: String,
    pub failed: String,
    pub failed_outcome: String,
    pub rollback: String,
}

/// Error object emitted when an envelope has `ok == false`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvelopeError {
    pub code: String,
    pub message: String,
    pub retryable: bool,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub next_action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub partial: Option<EnvelopePartialContext>,
}

impl<R> Envelope<R> {
    /// Construct a success envelope.
    pub fn ok(operation: impl Into<String>, result: R) -> Self {
        Self {
            v: ENVELOPE_VERSION.to_string(),
            ok: true,
            operation: operation.into(),
            operation_id: None,
            backend: None,
            resource: None,
            result: Some(result),
            error: None,
            warnings: Vec::new(),
        }
    }

    /// Construct a failure envelope from a typed error object.
    pub fn err(operation: impl Into<String>, error: EnvelopeError) -> Self {
        Self {
            v: ENVELOPE_VERSION.to_string(),
            ok: false,
            operation: operation.into(),
            operation_id: None,
            backend: None,
            resource: None,
            result: None,
            error: Some(error),
            warnings: Vec::new(),
        }
    }

    pub fn with_operation_id(mut self, id: impl Into<String>) -> Self {
        self.operation_id = Some(id.into());
        self
    }

    pub fn with_backend(mut self, backend: impl Into<String>) -> Self {
        self.backend = Some(backend.into());
        self
    }

    pub fn with_resource(mut self, resource: impl Into<String>) -> Self {
        self.resource = Some(resource.into());
        self
    }

    pub fn with_warnings(mut self, warnings: Vec<String>) -> Self {
        self.warnings = warnings;
        self
    }
}

impl From<&ovstorage_plugin::Error> for EnvelopeError {
    fn from(err: &ovstorage_plugin::Error) -> Self {
        let partial = err.context().and_then(|ctx| match ctx {
            ErrorContext::Partial {
                completed,
                failed,
                failed_outcome,
                rollback,
            } => Some(EnvelopePartialContext {
                completed: completed.as_str().to_string(),
                failed: failed.as_str().to_string(),
                failed_outcome: failed_outcome.as_str().to_string(),
                rollback: rollback.as_str().to_string(),
            }),
            _ => None,
        });
        EnvelopeError {
            code: err.code().as_str().to_string(),
            message: err.message().to_string(),
            retryable: err.code().retryable(),
            next_action: err.next_action().map(str::to_string),
            partial,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct StubResult {
        value: u32,
    }

    #[test]
    fn ok_envelope_serializes_canonical_shape() {
        let env = Envelope::ok("doctor", StubResult { value: 7 });
        let json = serde_json::to_value(&env).unwrap();
        assert_eq!(json["v"], "0.1");
        assert_eq!(json["ok"], true);
        assert_eq!(json["operation"], "doctor");
        assert_eq!(json["result"]["value"], 7);
        assert!(json.get("error").is_none());
        assert!(json.get("operation_id").is_none());
        assert!(json.get("warnings").is_none());
    }

    #[test]
    fn err_envelope_serializes_canonical_shape() {
        let env: Envelope<StubResult> = Envelope::err(
            "doctor",
            EnvelopeError {
                code: "NotFound".into(),
                message: "object missing".into(),
                retryable: false,
                next_action: Some("Add a matching connection to the active Stack first.".into()),
                partial: None,
            },
        );
        let json = serde_json::to_value(&env).unwrap();
        assert_eq!(json["ok"], false);
        assert_eq!(json["error"]["code"], "NotFound");
        assert_eq!(json["error"]["retryable"], false);
        assert_eq!(
            json["error"]["next_action"],
            "Add a matching connection to the active Stack first."
        );
        assert!(json.get("result").is_none());
    }

    #[test]
    fn envelope_roundtrips_through_json() {
        let env = Envelope::ok("read", StubResult { value: 42 })
            .with_resource("s3://bucket/key")
            .with_backend("s3")
            .with_operation_id("01HZX0K3W2B7E9V8M");
        let json = serde_json::to_string(&env).unwrap();
        let parsed: Envelope<StubResult> = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.v, "0.1");
        assert!(parsed.ok);
        assert_eq!(parsed.operation, "read");
        assert_eq!(parsed.backend.as_deref(), Some("s3"));
        assert_eq!(parsed.resource.as_deref(), Some("s3://bucket/key"));
        assert_eq!(parsed.operation_id.as_deref(), Some("01HZX0K3W2B7E9V8M"));
        assert_eq!(parsed.result, Some(StubResult { value: 42 }));
    }

    #[test]
    fn envelope_error_omits_next_action_when_none() {
        let json = serde_json::to_value(EnvelopeError {
            code: "Internal".into(),
            message: "boom".into(),
            retryable: false,
            next_action: None,
            partial: None,
        })
        .unwrap();
        assert_eq!(json["code"], "Internal");
        assert!(json.get("next_action").is_none());
        assert!(json.get("partial").is_none());
    }

    #[test]
    fn partial_completion_error_emits_partial_context_in_envelope() {
        use ovstorage_plugin::{
            Error, ErrorCode, ErrorContext, PartialStage, RollbackEffect, StageOutcome,
        };

        let err = Error::new(ErrorCode::PartialCompletion, "bytes committed")
            .with_context(ErrorContext::Partial {
                completed: PartialStage::ObjectData,
                failed: PartialStage::UserMetadata,
                failed_outcome: StageOutcome::NotApplied,
                rollback: RollbackEffect::DestroysRequestedWork,
            })
            .with_next_action("Re-apply the user metadata.");

        let envelope_err = EnvelopeError::from(&err);
        let json = serde_json::to_value(&envelope_err).unwrap();

        assert_eq!(json["code"], "PartialCompletion");
        assert_eq!(json["retryable"], false);
        assert_eq!(json["next_action"], "Re-apply the user metadata.");
        assert_eq!(json["partial"]["completed"], "object_data");
        assert_eq!(json["partial"]["failed"], "user_metadata");
        assert_eq!(json["partial"]["failed_outcome"], "not_applied");
        assert_eq!(json["partial"]["rollback"], "destroys_requested_work");
    }

    #[test]
    fn non_partial_error_omits_partial_from_envelope() {
        use ovstorage_plugin::{Error, ErrorCode};

        let err = Error::new(ErrorCode::NotFound, "missing");
        let json = serde_json::to_value(EnvelopeError::from(&err)).unwrap();
        assert!(json.get("partial").is_none());
    }
}
