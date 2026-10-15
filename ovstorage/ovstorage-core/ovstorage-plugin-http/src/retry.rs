// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use ovstorage_plugin::{ConfigValue, Error, ErrorCode, LayerConfig, Result};

pub(crate) use ovstorage_retry::{RetryConfig, RetryStep, is_retryable, with_http_retry_async};

pub(crate) fn retry_config_from(config: &LayerConfig) -> Result<RetryConfig> {
    let mut retry = RetryConfig::default();
    if let Some(value) = config.get("initial_delay_ms") {
        retry.initial_delay_ms = crate::config_u64(value, "initial_delay_ms")?;
    }
    if let Some(value) = config.get("max_delay_ms") {
        retry.max_delay_ms = crate::config_u64(value, "max_delay_ms")?;
    }
    if let Some(value) = config.get("max_attempts") {
        let value = match value {
            ConfigValue::Int(value) if *value >= 0 => *value as u64,
            _ => {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    "layer config `max_attempts` must be a non-negative integer",
                ));
            }
        };
        retry.max_attempts = u32::try_from(value).map_err(|_| {
            Error::new(
                ErrorCode::InvalidArgument,
                "retry config `max_attempts` exceeds the supported maximum",
            )
        })?;
    }
    retry.validate()?;
    Ok(retry)
}
