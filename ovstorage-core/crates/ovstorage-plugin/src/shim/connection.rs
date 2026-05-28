// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

pub fn connection_id_to_ffi(value: ConnectionId) -> ffi::ConnectionId {
    ffi::ConnectionId {
        id: primitive::str_to_ffi(value.0),
    }
}

/// # Safety
///
/// `value` must be a valid [`ffi::ConnectionId`] produced by
/// [`connection_id_to_ffi`].
pub unsafe fn connection_id_from_ffi(value: ffi::ConnectionId) -> Result<ConnectionId, Error> {
    unsafe {
        let id = primitive::str_from_ffi(value.id)?;
        if id.is_empty() {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "connection id must not be empty",
            ));
        }
        Ok(ConnectionId(id))
    }
}

pub fn config_layer_to_ffi(value: ConfigLayer) -> ffi::ConfigLayer {
    match value {
        ConfigLayer::Programmatic => ffi::ConfigLayer::Programmatic,
        ConfigLayer::Env => ffi::ConfigLayer::Env,
        ConfigLayer::Project => ffi::ConfigLayer::Project,
        ConfigLayer::User => ffi::ConfigLayer::User,
        ConfigLayer::Machine => ffi::ConfigLayer::Machine,
    }
}

pub fn config_layer_from_ffi(value: ffi::ConfigLayer) -> ConfigLayer {
    match value {
        ffi::ConfigLayer::Programmatic => ConfigLayer::Programmatic,
        ffi::ConfigLayer::Env => ConfigLayer::Env,
        ffi::ConfigLayer::Project => ConfigLayer::Project,
        ffi::ConfigLayer::User => ConfigLayer::User,
        ffi::ConfigLayer::Machine => ConfigLayer::Machine,
    }
}

pub fn connection_source_to_ffi(value: ConnectionSource) -> ffi::ConnectionSource {
    match value {
        ConnectionSource::Static { layer } => {
            ffi::ConnectionSource::from_static(config_layer_to_ffi(layer))
        }
        ConnectionSource::Runtime { persisted } => {
            ffi::ConnectionSource::from_runtime(ffi::ConnectionSourceRuntime { persisted })
        }
        ConnectionSource::BrokerDelivered { broker_principal } => {
            ffi::ConnectionSource::from_broker(ffi::ConnectionSourceBrokerDelivered {
                broker_principal: primitive::str_to_ffi(broker_principal),
            })
        }
    }
}

/// # Safety
///
/// `value` must be a valid [`ffi::ConnectionSource`] produced by
/// [`connection_source_to_ffi`].
pub unsafe fn connection_source_from_ffi(
    value: ffi::ConnectionSource,
) -> Result<ConnectionSource, Error> {
    unsafe {
        let result = match value.tag {
            ffi::ConnectionSourceTag::Static => {
                let payload = std::ptr::read(value.static_.as_ptr());
                std::mem::forget(value);
                ConnectionSource::Static {
                    layer: config_layer_from_ffi(payload.layer),
                }
            }
            ffi::ConnectionSourceTag::Runtime => {
                let payload = std::ptr::read(value.runtime.as_ptr());
                std::mem::forget(value);
                ConnectionSource::Runtime {
                    persisted: payload.persisted,
                }
            }
            ffi::ConnectionSourceTag::BrokerDelivered => {
                let payload = std::ptr::read(value.broker_delivered.as_ptr());
                std::mem::forget(value);
                let broker_principal = primitive::str_from_ffi(payload.broker_principal)?;
                ConnectionSource::BrokerDelivered { broker_principal }
            }
        };
        Ok(result)
    }
}
