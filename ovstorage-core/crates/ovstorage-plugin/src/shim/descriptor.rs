// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

pub fn config_value_to_ffi(value: ConfigValue) -> ffi::ConfigValue {
    match value {
        ConfigValue::String(s) => ffi::ConfigValue::from_string(primitive::str_to_ffi(s)),
        ConfigValue::Int(n) => ffi::ConfigValue::from_int(n),
        ConfigValue::Bool(b) => ffi::ConfigValue::from_bool(b),
        ConfigValue::Toml(s) => ffi::ConfigValue::from_toml(primitive::str_to_ffi(s)),
    }
}

/// # Safety
///
/// `value` must be a valid [`ffi::ConfigValue`] produced by
/// [`config_value_to_ffi`].
pub unsafe fn config_value_from_ffi(value: ffi::ConfigValue) -> Result<ConfigValue, Error> {
    unsafe {
        let out = match value.tag {
            ffi::ConfigValueTag::String => {
                let s = std::ptr::read(value.string_value.as_ptr());
                std::mem::forget(value);
                ConfigValue::String(primitive::str_from_ffi(s)?)
            }
            ffi::ConfigValueTag::Int => {
                let n = value.int_value;
                std::mem::forget(value);
                ConfigValue::Int(n)
            }
            ffi::ConfigValueTag::Bool => {
                let b = value.bool_value;
                std::mem::forget(value);
                ConfigValue::Bool(b)
            }
            ffi::ConfigValueTag::Toml => {
                let s = std::ptr::read(value.toml_value.as_ptr());
                std::mem::forget(value);
                ConfigValue::Toml(primitive::str_from_ffi(s)?)
            }
        };
        Ok(out)
    }
}

pub fn enum_source_to_ffi(value: EnumSource) -> ffi::EnumSource {
    match value {
        EnumSource::Static(choices) => {
            ffi::EnumSource::from_static(primitive::list_to_ffi(choices, primitive::str_to_ffi))
        }
        EnumSource::Discovered => ffi::EnumSource::discovered(),
    }
}

/// # Safety
///
/// `value` must be a valid [`ffi::EnumSource`] produced by
/// [`enum_source_to_ffi`].
pub unsafe fn enum_source_from_ffi(value: ffi::EnumSource) -> Result<EnumSource, Error> {
    unsafe {
        match value.tag {
            ffi::EnumSourceTag::Static => {
                let list = std::ptr::read(value.static_choices.as_ptr());
                std::mem::forget(value);
                let choices = primitive::list_from_ffi(list, |s| primitive::str_from_ffi(s))?;
                Ok(EnumSource::Static(choices))
            }
            ffi::EnumSourceTag::Discovered => {
                std::mem::forget(value);
                Ok(EnumSource::Discovered)
            }
        }
    }
}

pub fn config_field_kind_to_ffi(value: ConfigFieldKind) -> ffi::ConfigFieldKind {
    match value {
        ConfigFieldKind::Url => ffi::ConfigFieldKind::url(),
        ConfigFieldKind::Text => ffi::ConfigFieldKind::text(),
        ConfigFieldKind::Integer => ffi::ConfigFieldKind::integer(),
        ConfigFieldKind::Bool => ffi::ConfigFieldKind::bool_kind(),
        ConfigFieldKind::Enum { source } => {
            ffi::ConfigFieldKind::enum_kind(enum_source_to_ffi(source))
        }
        ConfigFieldKind::Path => ffi::ConfigFieldKind::path(),
    }
}

/// # Safety
///
/// `value` must be a valid [`ffi::ConfigFieldKind`] produced by
/// [`config_field_kind_to_ffi`].
pub unsafe fn config_field_kind_from_ffi(
    value: ffi::ConfigFieldKind,
) -> Result<ConfigFieldKind, Error> {
    unsafe {
        match value.tag {
            ffi::ConfigFieldKindTag::Url => {
                std::mem::forget(value);
                Ok(ConfigFieldKind::Url)
            }
            ffi::ConfigFieldKindTag::Text => {
                std::mem::forget(value);
                Ok(ConfigFieldKind::Text)
            }
            ffi::ConfigFieldKindTag::Integer => {
                std::mem::forget(value);
                Ok(ConfigFieldKind::Integer)
            }
            ffi::ConfigFieldKindTag::Bool => {
                std::mem::forget(value);
                Ok(ConfigFieldKind::Bool)
            }
            ffi::ConfigFieldKindTag::Enum => {
                let source = std::ptr::read(value.enum_source.as_ptr());
                std::mem::forget(value);
                Ok(ConfigFieldKind::Enum {
                    source: enum_source_from_ffi(source)?,
                })
            }
            ffi::ConfigFieldKindTag::Path => {
                std::mem::forget(value);
                Ok(ConfigFieldKind::Path)
            }
        }
    }
}

pub fn config_field_to_ffi(value: ConfigField) -> ffi::ConfigField {
    ffi::ConfigField {
        key: primitive::str_to_ffi(value.key),
        display_name: primitive::str_to_ffi(value.display_name),
        kind: config_field_kind_to_ffi(value.kind),
        required: value.required,
        default: primitive::optional_to_ffi(value.default, config_value_to_ffi),
        help: primitive::optional_to_ffi(value.help, primitive::str_to_ffi),
        example: primitive::optional_to_ffi(value.example, primitive::str_to_ffi),
        group: primitive::optional_to_ffi(value.group, primitive::str_to_ffi),
        advanced: value.advanced,
    }
}

/// # Safety
///
/// `value` must be a valid [`ffi::ConfigField`] produced by
/// [`config_field_to_ffi`].
pub unsafe fn config_field_from_ffi(value: ffi::ConfigField) -> Result<ConfigField, Error> {
    unsafe {
        let key_ffi = value.key;
        let display_ffi = value.display_name;
        let kind_ffi = value.kind;
        let required = value.required;
        let default_ffi = value.default;
        let help_ffi = value.help;
        let example_ffi = value.example;
        let group_ffi = value.group;
        let advanced = value.advanced;

        let key = primitive::str_from_ffi(key_ffi);
        let display_name = primitive::str_from_ffi(display_ffi);
        let kind = config_field_kind_from_ffi(kind_ffi);
        let default = primitive::optional_from_ffi(default_ffi, |c| config_value_from_ffi(c));
        let help = primitive::optional_from_ffi(help_ffi, |s| primitive::str_from_ffi(s));
        let example = primitive::optional_from_ffi(example_ffi, |s| primitive::str_from_ffi(s));
        let group = primitive::optional_from_ffi(group_ffi, |s| primitive::str_from_ffi(s));
        Ok(ConfigField {
            key: key?,
            display_name: display_name?,
            kind: kind?,
            required,
            default: default?,
            help: help?,
            example: example?,
            group: group?,
            advanced,
        })
    }
}

pub fn credential_method_to_ffi(value: CredentialMethod) -> ffi::CredentialMethod {
    ffi::CredentialMethod {
        key: primitive::str_to_ffi(value.key),
        display_name: primitive::str_to_ffi(value.display_name),
        fields: primitive::list_to_ffi(value.fields, primitive::str_to_ffi),
        help: primitive::optional_to_ffi(value.help, primitive::str_to_ffi),
        advanced: value.advanced,
    }
}

/// # Safety
///
/// `value` must be a valid [`ffi::CredentialMethod`] produced by
/// [`credential_method_to_ffi`].
pub unsafe fn credential_method_from_ffi(
    value: ffi::CredentialMethod,
) -> Result<CredentialMethod, Error> {
    unsafe {
        let key_ffi = value.key;
        let display_ffi = value.display_name;
        let fields_ffi = value.fields;
        let help_ffi = value.help;
        let advanced = value.advanced;
        let key = primitive::str_from_ffi(key_ffi);
        let display_name = primitive::str_from_ffi(display_ffi);
        let fields = primitive::list_from_ffi(fields_ffi, |s| primitive::str_from_ffi(s));
        let help = primitive::optional_from_ffi(help_ffi, |s| primitive::str_from_ffi(s));
        Ok(CredentialMethod {
            key: key?,
            display_name: display_name?,
            fields: fields?,
            help: help?,
            advanced,
        })
    }
}

pub fn credential_field_to_ffi(value: CredentialField) -> ffi::CredentialField {
    ffi::CredentialField {
        key: primitive::str_to_ffi(value.key),
        display_name: primitive::str_to_ffi(value.display_name),
        default: primitive::optional_to_ffi(value.default, primitive::str_to_ffi),
        help: primitive::optional_to_ffi(value.help, primitive::str_to_ffi),
        advanced: value.advanced,
    }
}

/// # Safety
///
/// `value` must be a valid [`ffi::CredentialField`].
pub unsafe fn credential_field_from_ffi(
    value: ffi::CredentialField,
) -> Result<CredentialField, Error> {
    unsafe {
        let key_ffi = value.key;
        let display_ffi = value.display_name;
        let default_ffi = value.default;
        let help_ffi = value.help;
        let advanced = value.advanced;
        let key = primitive::str_from_ffi(key_ffi);
        let display_name = primitive::str_from_ffi(display_ffi);
        let default = primitive::optional_from_ffi(default_ffi, |s| primitive::str_from_ffi(s));
        let help = primitive::optional_from_ffi(help_ffi, |s| primitive::str_from_ffi(s));
        Ok(CredentialField {
            key: key?,
            display_name: display_name?,
            default: default?,
            help: help?,
            advanced,
        })
    }
}

pub fn storage_backend_kind_descriptor_to_ffi(
    value: StorageBackendKindDescriptor,
) -> ffi::StorageBackendKindDescriptor {
    ffi::StorageBackendKindDescriptor {
        kind: primitive::str_to_ffi(value.kind),
        display_name: primitive::str_to_ffi(value.display_name),
        description: primitive::optional_to_ffi(value.description, primitive::str_to_ffi),
        config_schema: primitive::list_to_ffi(value.config_schema, config_field_to_ffi),
        credential_schema: primitive::list_to_ffi(value.credential_schema, credential_field_to_ffi),
        credential_methods: primitive::list_to_ffi(
            value.credential_methods,
            credential_method_to_ffi,
        ),
        icon: primitive::optional_to_ffi(value.icon, primitive::bytes_to_ffi),
        supports_runtime_add: value.supports_runtime_add,
    }
}

/// # Safety
///
/// `value` must be a valid [`ffi::StorageBackendKindDescriptor`].
pub unsafe fn storage_backend_kind_descriptor_from_ffi(
    value: ffi::StorageBackendKindDescriptor,
) -> Result<StorageBackendKindDescriptor, Error> {
    unsafe {
        let kind_ffi = value.kind;
        let display_ffi = value.display_name;
        let description_ffi = value.description;
        let config_schema_ffi = value.config_schema;
        let credential_schema_ffi = value.credential_schema;
        let credential_methods_ffi = value.credential_methods;
        let icon_ffi = value.icon;
        let supports_runtime_add = value.supports_runtime_add;

        let kind = primitive::str_from_ffi(kind_ffi);
        let display_name = primitive::str_from_ffi(display_ffi);
        let description =
            primitive::optional_from_ffi(description_ffi, |s| primitive::str_from_ffi(s));
        let config_schema =
            primitive::list_from_ffi(config_schema_ffi, |c| config_field_from_ffi(c));
        let credential_schema =
            primitive::list_from_ffi(credential_schema_ffi, |c| credential_field_from_ffi(c));
        let credential_methods =
            primitive::list_from_ffi(credential_methods_ffi, |c| credential_method_from_ffi(c));
        let icon = primitive::optional_from_ffi::<ffi::Bytes, Vec<u8>, Error>(icon_ffi, |b| {
            Ok(primitive::bytes_from_ffi(b))
        });
        Ok(StorageBackendKindDescriptor {
            kind: kind?,
            display_name: display_name?,
            description: description?,
            config_schema: config_schema?,
            credential_schema: credential_schema?,
            credential_methods: credential_methods?,
            icon: icon?,
            supports_runtime_add,
        })
    }
}

pub fn secret_bytes_to_ffi(value: SecretBytes) -> ffi::SecretBytes {
    ffi::SecretBytes {
        bytes: primitive::bytes_to_ffi(value.into_inner()),
    }
}

/// # Safety
///
/// `value` must be a valid [`ffi::SecretBytes`] produced by
/// [`secret_bytes_to_ffi`] (or by an FFI counterpart that uses
/// the same allocator and the `cap == max(len, 1)` rule the
/// `ffi::Bytes` constructors document).
///
/// Takes ownership of the FFI buffer in place rather than copying:
/// the underlying `Vec<u8>` allocation is rewrapped under
/// [`SecretBytes`], whose `Drop` zeroizes the bytes before the
/// allocator reclaims them. Copying first (the generic
/// `bytes_from_ffi` path) would leave the original FFI page in
/// cleartext on the freed heap.
pub unsafe fn secret_bytes_from_ffi(value: ffi::SecretBytes) -> SecretBytes {
    unsafe {
        let len = value.bytes.len;
        let ptr = value.bytes.ptr;
        let bytes_vec = if ptr.is_null() {
            Vec::new()
        } else {
            let cap = if len == 0 { 1 } else { len };
            Vec::from_raw_parts(ptr, len, cap)
        };
        std::mem::forget(value);
        SecretBytes(bytes_vec)
    }
}

pub fn secret_value_to_ffi(value: SecretValue) -> ffi::SecretValue {
    match value {
        SecretValue::Bytes(b) => ffi::SecretValue::from_bytes(secret_bytes_to_ffi(b)),
        SecretValue::OAuthToken {
            token,
            refresh,
            expires_at,
        } => ffi::SecretValue::from_oauth(ffi::SecretValueOAuthToken {
            token: secret_bytes_to_ffi(token),
            refresh: primitive::optional_to_ffi(refresh, secret_bytes_to_ffi),
            expires_at_unix_ms: primitive::optional_to_ffi(
                expires_at,
                primitive::system_time_to_unix_ms,
            ),
        }),
        SecretValue::File(b) => ffi::SecretValue::from_file(secret_bytes_to_ffi(b)),
        SecretValue::MtlsCertPair { cert_pem, key_pem } => {
            ffi::SecretValue::from_mtls_cert_pair(ffi::SecretValueMtlsCertPair {
                cert_pem: secret_bytes_to_ffi(cert_pem),
                key_pem: secret_bytes_to_ffi(key_pem),
            })
        }
        SecretValue::SystemIdentity => ffi::SecretValue::system_identity(),
    }
}

/// # Safety
///
/// `value` must be a valid [`ffi::SecretValue`].
pub unsafe fn secret_value_from_ffi(value: ffi::SecretValue) -> Result<SecretValue, Error> {
    unsafe {
        match value.tag {
            ffi::SecretValueTag::Bytes => {
                let bytes = std::ptr::read(value.bytes.as_ptr());
                std::mem::forget(value);
                Ok(SecretValue::Bytes(secret_bytes_from_ffi(bytes)))
            }
            ffi::SecretValueTag::OAuthToken => {
                let payload = std::ptr::read(value.oauth_token.as_ptr());
                std::mem::forget(value);
                let token = secret_bytes_from_ffi(payload.token);
                let refresh = primitive::optional_from_ffi::<ffi::SecretBytes, SecretBytes, Error>(
                    payload.refresh,
                    |b| Ok(secret_bytes_from_ffi(b)),
                )?;
                let expires_at = primitive::optional_from_ffi::<i64, SystemTime, Error>(
                    payload.expires_at_unix_ms,
                    |ms| Ok(primitive::system_time_from_unix_ms(ms)),
                )?;
                Ok(SecretValue::OAuthToken {
                    token,
                    refresh,
                    expires_at,
                })
            }
            ffi::SecretValueTag::File => {
                let bytes = std::ptr::read(value.file.as_ptr());
                std::mem::forget(value);
                Ok(SecretValue::File(secret_bytes_from_ffi(bytes)))
            }
            ffi::SecretValueTag::MtlsCertPair => {
                let payload = std::ptr::read(value.mtls_cert_pair.as_ptr());
                std::mem::forget(value);
                Ok(SecretValue::MtlsCertPair {
                    cert_pem: secret_bytes_from_ffi(payload.cert_pem),
                    key_pem: secret_bytes_from_ffi(payload.key_pem),
                })
            }
            ffi::SecretValueTag::SystemIdentity => {
                std::mem::forget(value);
                Ok(SecretValue::SystemIdentity)
            }
        }
    }
}

pub fn secret_bundle_to_ffi(value: SecretBundle) -> ffi::SecretBundle {
    let entries: Vec<(String, SecretValue)> = value.fields.into_iter().collect();
    ffi::SecretBundle {
        entries: primitive::list_to_ffi(entries, |(field, value)| ffi::SecretBundleEntry {
            field: primitive::str_to_ffi(field),
            value: secret_value_to_ffi(value),
        }),
    }
}

/// # Safety
///
/// `value` must be a valid [`ffi::SecretBundle`].
pub unsafe fn secret_bundle_from_ffi(value: ffi::SecretBundle) -> Result<SecretBundle, Error> {
    unsafe {
        let entries = primitive::list_from_ffi(value.entries, |entry| {
            let field = primitive::str_from_ffi(entry.field)?;
            let value = secret_value_from_ffi(entry.value)?;
            Ok::<_, Error>((field, value))
        })?;
        Ok(SecretBundle {
            fields: entries.into_iter().collect(),
        })
    }
}

pub fn connection_request_to_ffi(value: ConnectionRequest) -> ffi::ConnectionRequest {
    let config_entries: Vec<(String, ConfigValue)> = value.config.into_iter().collect();
    ffi::ConnectionRequest {
        backend_kind: primitive::str_to_ffi(value.backend_kind),
        config: primitive::list_to_ffi(config_entries, |(k, v)| ffi::ConnectionConfigEntry {
            key: primitive::str_to_ffi(k),
            value: config_value_to_ffi(v),
        }),
        credentials: secret_bundle_to_ffi(value.credentials),
        persist: value.persist,
        display_name: primitive::optional_to_ffi(value.display_name, primitive::str_to_ffi),
    }
}

/// # Safety
///
/// `value` must be a valid [`ffi::ConnectionRequest`].
pub unsafe fn connection_request_from_ffi(
    value: ffi::ConnectionRequest,
) -> Result<ConnectionRequest, Error> {
    unsafe {
        let backend_kind_ffi = value.backend_kind;
        let config_ffi = value.config;
        let credentials_ffi = value.credentials;
        let persist = value.persist;
        let display_ffi = value.display_name;

        let backend_kind = primitive::str_from_ffi(backend_kind_ffi);
        let config_entries = primitive::list_from_ffi(config_ffi, |entry| {
            let key = primitive::str_from_ffi(entry.key)?;
            let value = config_value_from_ffi(entry.value)?;
            Ok::<_, Error>((key, value))
        });
        let credentials = secret_bundle_from_ffi(credentials_ffi);
        let display_name =
            primitive::optional_from_ffi(display_ffi, |s| primitive::str_from_ffi(s));
        Ok(ConnectionRequest {
            backend_kind: backend_kind?,
            config: config_entries?.into_iter().collect(),
            credentials: credentials?,
            persist,
            display_name: display_name?,
        })
    }
}
