// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

// Connection identity / source / config-layer types
// ---------------------------------------------------------------------

/// Opaque connection identifier (UUID encoded as a string).
#[repr(C)]
#[derive(Debug)]
pub struct ConnectionId {
    pub id: Str,
}

unsafe impl Send for ConnectionId {}

/// Configuration source layer.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ConfigLayer {
    Programmatic = 0,
    Env = 1,
    Project = 2,
    User = 3,
    Machine = 4,
}

/// Tag for [`ConnectionSource`].
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ConnectionSourceTag {
    Static = 0,
    Runtime = 1,
    BrokerDelivered = 2,
}

/// `ConnectionSource::Static` payload.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct ConnectionSourceStatic {
    pub layer: ConfigLayer,
}

/// `ConnectionSource::Runtime` payload.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct ConnectionSourceRuntime {
    pub persisted: bool,
}

/// `ConnectionSource::BrokerDelivered` payload.
#[repr(C)]
#[derive(Debug)]
pub struct ConnectionSourceBrokerDelivered {
    pub broker_principal: Str,
}

unsafe impl Send for ConnectionSourceBrokerDelivered {}

/// Where a connection came from.
#[repr(C)]
#[derive(Debug)]
pub struct ConnectionSource {
    pub tag: ConnectionSourceTag,
    pub static_: core::mem::MaybeUninit<ConnectionSourceStatic>,
    pub runtime: core::mem::MaybeUninit<ConnectionSourceRuntime>,
    pub broker_delivered: core::mem::MaybeUninit<ConnectionSourceBrokerDelivered>,
}

unsafe impl Send for ConnectionSource {}

impl ConnectionSource {
    pub fn from_static(layer: ConfigLayer) -> Self {
        Self {
            tag: ConnectionSourceTag::Static,
            static_: core::mem::MaybeUninit::new(ConnectionSourceStatic { layer }),
            runtime: core::mem::MaybeUninit::uninit(),
            broker_delivered: core::mem::MaybeUninit::uninit(),
        }
    }

    pub fn from_runtime(value: ConnectionSourceRuntime) -> Self {
        Self {
            tag: ConnectionSourceTag::Runtime,
            static_: core::mem::MaybeUninit::uninit(),
            runtime: core::mem::MaybeUninit::new(value),
            broker_delivered: core::mem::MaybeUninit::uninit(),
        }
    }

    pub fn from_broker(value: ConnectionSourceBrokerDelivered) -> Self {
        Self {
            tag: ConnectionSourceTag::BrokerDelivered,
            static_: core::mem::MaybeUninit::uninit(),
            runtime: core::mem::MaybeUninit::uninit(),
            broker_delivered: core::mem::MaybeUninit::new(value),
        }
    }
}

impl Drop for ConnectionSource {
    fn drop(&mut self) {
        unsafe {
            match self.tag {
                ConnectionSourceTag::Static => self.static_.assume_init_drop(),
                ConnectionSourceTag::Runtime => self.runtime.assume_init_drop(),
                ConnectionSourceTag::BrokerDelivered => self.broker_delivered.assume_init_drop(),
            }
        }
    }
}

// ---------------------------------------------------------------------
// ConfigValue
// ---------------------------------------------------------------------

/// Tag for [`ConfigValue`].
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ConfigValueTag {
    String = 0,
    Int = 1,
    Bool = 2,
    /// Reserialized TOML payload (nested table or array of tables).
    /// Distinct from `String` so callers can round-trip nested
    /// values without ambiguity.
    Toml = 3,
}

/// Configuration value carried by a [`ConnectionRequest::config`]
/// entry. Top-level TOML scalars use the matching variant; tables and
/// arrays arrive as `Toml` (reserialized to a TOML string).
#[repr(C)]
#[derive(Debug)]
pub struct ConfigValue {
    pub tag: ConfigValueTag,
    pub string_value: core::mem::MaybeUninit<Str>,
    pub int_value: i64,
    pub bool_value: bool,
    pub toml_value: core::mem::MaybeUninit<Str>,
}

unsafe impl Send for ConfigValue {}

impl ConfigValue {
    pub fn from_string(value: Str) -> Self {
        Self {
            tag: ConfigValueTag::String,
            string_value: core::mem::MaybeUninit::new(value),
            int_value: 0,
            bool_value: false,
            toml_value: core::mem::MaybeUninit::uninit(),
        }
    }

    pub fn from_int(value: i64) -> Self {
        Self {
            tag: ConfigValueTag::Int,
            string_value: core::mem::MaybeUninit::uninit(),
            int_value: value,
            bool_value: false,
            toml_value: core::mem::MaybeUninit::uninit(),
        }
    }

    pub fn from_bool(value: bool) -> Self {
        Self {
            tag: ConfigValueTag::Bool,
            string_value: core::mem::MaybeUninit::uninit(),
            int_value: 0,
            bool_value: value,
            toml_value: core::mem::MaybeUninit::uninit(),
        }
    }

    pub fn from_toml(value: Str) -> Self {
        Self {
            tag: ConfigValueTag::Toml,
            string_value: core::mem::MaybeUninit::uninit(),
            int_value: 0,
            bool_value: false,
            toml_value: core::mem::MaybeUninit::new(value),
        }
    }
}

impl Drop for ConfigValue {
    fn drop(&mut self) {
        unsafe {
            match self.tag {
                ConfigValueTag::String => self.string_value.assume_init_drop(),
                ConfigValueTag::Toml => self.toml_value.assume_init_drop(),
                ConfigValueTag::Int | ConfigValueTag::Bool => {}
            }
        }
    }
}

/// Tag for [`EnumSource`].
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EnumSourceTag {
    Static = 0,
    Discovered = 1,
}

/// Enum-field choice list source.
#[repr(C)]
#[derive(Debug)]
pub struct EnumSource {
    pub tag: EnumSourceTag,
    pub static_choices: core::mem::MaybeUninit<List<Str>>,
}

unsafe impl Send for EnumSource {}

impl EnumSource {
    pub fn from_static(choices: List<Str>) -> Self {
        Self {
            tag: EnumSourceTag::Static,
            static_choices: core::mem::MaybeUninit::new(choices),
        }
    }

    pub fn discovered() -> Self {
        Self {
            tag: EnumSourceTag::Discovered,
            static_choices: core::mem::MaybeUninit::uninit(),
        }
    }
}

impl Drop for EnumSource {
    fn drop(&mut self) {
        if let EnumSourceTag::Static = self.tag {
            unsafe {
                self.static_choices.assume_init_drop();
            }
        }
    }
}

/// Tag for [`ConfigFieldKind`].
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ConfigFieldKindTag {
    Url = 0,
    Text = 1,
    Integer = 2,
    Bool = 3,
    Enum = 4,
    Path = 5,
}

/// `ConfigField`'s kind. The `Enum` variant carries an [`EnumSource`].
#[repr(C)]
#[derive(Debug)]
pub struct ConfigFieldKind {
    pub tag: ConfigFieldKindTag,
    pub enum_source: core::mem::MaybeUninit<EnumSource>,
}

unsafe impl Send for ConfigFieldKind {}

impl ConfigFieldKind {
    pub fn url() -> Self {
        Self {
            tag: ConfigFieldKindTag::Url,
            enum_source: core::mem::MaybeUninit::uninit(),
        }
    }

    pub fn text() -> Self {
        Self {
            tag: ConfigFieldKindTag::Text,
            enum_source: core::mem::MaybeUninit::uninit(),
        }
    }

    pub fn integer() -> Self {
        Self {
            tag: ConfigFieldKindTag::Integer,
            enum_source: core::mem::MaybeUninit::uninit(),
        }
    }

    pub fn bool_kind() -> Self {
        Self {
            tag: ConfigFieldKindTag::Bool,
            enum_source: core::mem::MaybeUninit::uninit(),
        }
    }

    pub fn enum_kind(source: EnumSource) -> Self {
        Self {
            tag: ConfigFieldKindTag::Enum,
            enum_source: core::mem::MaybeUninit::new(source),
        }
    }

    pub fn path() -> Self {
        Self {
            tag: ConfigFieldKindTag::Path,
            enum_source: core::mem::MaybeUninit::uninit(),
        }
    }
}

impl Drop for ConfigFieldKind {
    fn drop(&mut self) {
        if let ConfigFieldKindTag::Enum = self.tag {
            unsafe {
                self.enum_source.assume_init_drop();
            }
        }
    }
}

/// One configuration-schema field of a backend kind descriptor.
#[repr(C)]
#[derive(Debug)]
pub struct ConfigField {
    pub key: Str,
    pub display_name: Str,
    pub kind: ConfigFieldKind,
    pub required: bool,
    pub default: Optional<ConfigValue>,
    pub help: Optional<Str>,
    pub example: Optional<Str>,
    pub group: Optional<Str>,
    pub advanced: bool,
}

unsafe impl Send for ConfigField {}

// ---------------------------------------------------------------------
// Backend-kind descriptor / credential schema
// ---------------------------------------------------------------------

/// One credential-schema field of a backend kind descriptor.
#[repr(C)]
#[derive(Debug)]
pub struct CredentialField {
    pub key: Str,
    pub display_name: Str,
    /// Per-method default (literal or `${NAME}` template). See
    /// `types::CredentialField::default`.
    pub default: Optional<Str>,
    pub help: Optional<Str>,
    pub advanced: bool,
}

unsafe impl Send for CredentialField {}

/// Named credential entry-point referenced by a backend descriptor.
/// `fields` keys index into the descriptor's `credential_schema`.
#[repr(C)]
#[derive(Debug)]
pub struct CredentialMethod {
    pub key: Str,
    pub display_name: Str,
    pub fields: List<Str>,
    pub help: Optional<Str>,
    pub advanced: bool,
}

unsafe impl Send for CredentialMethod {}

/// Backend-kind descriptor.
#[repr(C)]
#[derive(Debug)]
pub struct StorageBackendKindDescriptor {
    pub kind: Str,
    pub display_name: Str,
    pub description: Optional<Str>,
    pub config_schema: List<ConfigField>,
    pub credential_schema: List<CredentialField>,
    pub credential_methods: List<CredentialMethod>,
    pub icon: Optional<Bytes>,
    pub supports_runtime_add: bool,
}

unsafe impl Send for StorageBackendKindDescriptor {}

// ---------------------------------------------------------------------
