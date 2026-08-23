// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("connection failed: {0}")]
    ConnectionFailed(String),

    #[error("connection closed")]
    ConnectionClosed,

    #[error("subscription closed")]
    SubscriptionClosed,

    #[error("websocket error: {0}")]
    WebSocketError(#[from] tokio_tungstenite::tungstenite::Error),

    #[error("serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("request timed out")]
    Timeout,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_failed_display() {
        let err = TransportError::ConnectionFailed("refused".to_string());
        assert_eq!(err.to_string(), "connection failed: refused");
    }

    #[test]
    fn connection_closed_display() {
        let err = TransportError::ConnectionClosed;
        assert_eq!(err.to_string(), "connection closed");
    }

    #[test]
    fn timeout_display() {
        let err = TransportError::Timeout;
        assert_eq!(err.to_string(), "request timed out");
    }

    #[test]
    fn serialization_error_from_json() {
        let json_err = serde_json::from_str::<serde_json::Value>("{{bad").unwrap_err();
        let err: TransportError = json_err.into();
        assert!(matches!(err, TransportError::SerializationError(_)));
        assert!(err.to_string().starts_with("serialization error:"));
    }
}
