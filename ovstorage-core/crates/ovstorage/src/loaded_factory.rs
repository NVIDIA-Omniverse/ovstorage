// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Host-side `shim::Factory` adapter for the plugin's
//! `BackendFactoryVTableV1`. Same callback-shaped async as
//! `loaded_backend.rs`; `descriptor` stays sync (cached accessor).

use std::ffi::c_void;
use std::mem::MaybeUninit;
use std::sync::Arc;

use ovstorage_plugin::{
    AuthEventStream, CancellationToken, Connection, ConnectionRequest, Error, ErrorCode,
    InteractiveAuthCapability, Result, SecretBundle, StorageBackendKindDescriptor, ffi, shim,
};
use tokio::sync::oneshot;

use crate::loaded_backend::{LoadedBackend, decode_async_result};
use crate::loader::HostPlugin;

pub(crate) struct LoadedFactory {
    plugin: Arc<HostPlugin>,
    descriptor: StorageBackendKindDescriptor,
}

impl LoadedFactory {
    pub fn new(plugin: Arc<HostPlugin>) -> Result<Self> {
        let descriptor = read_descriptor(&plugin)?;
        Ok(Self { plugin, descriptor })
    }
}

fn read_descriptor(plugin: &HostPlugin) -> Result<StorageBackendKindDescriptor> {
    let vtable = unsafe { &*plugin.factory_vtable() };
    let mut out = MaybeUninit::<ffi::StorageBackendKindDescriptor>::uninit();
    let err_ptr = unsafe { (vtable.descriptor)(plugin.factory_state(), out.as_mut_ptr()) };
    check_err(err_ptr)?;
    unsafe { shim::descriptor::storage_backend_kind_descriptor_from_ffi(out.assume_init()) }
}

fn dropped_sender_error() -> Error {
    Error::new(
        ErrorCode::Internal,
        "plugin dropped on_complete sender without firing",
    )
}

/// See `loaded_backend::decode_async_result`.
fn decode_async_unit_result(_status: i32, error: *mut ffi::Error) -> Result<()> {
    if error.is_null() {
        Ok(())
    } else {
        let boxed = unsafe { Box::from_raw(error) };
        Err(unsafe { shim::error::from_ffi(*boxed) })
    }
}

#[async_trait::async_trait]
impl shim::Factory for LoadedFactory {
    fn descriptor(&self) -> StorageBackendKindDescriptor {
        self.descriptor.clone()
    }

    #[tracing::instrument(level = "debug", skip_all, fields(op = "instantiate"))]
    async fn instantiate(
        &self,
        request: &ConnectionRequest,
        cancel: Option<CancellationToken>,
    ) -> Result<shim::BackendInstance> {
        let plugin = Arc::clone(&self.plugin);
        let request_ffi = shim::descriptor::connection_request_to_ffi(request.clone());
        let cancel_handle = cancel.map(ffi::cancel_token_to_ffi);

        let (tx, rx) = oneshot::channel::<Result<ffi::BackendInstance>>();
        let user_data = Box::into_raw(Box::new(tx)) as *mut c_void;

        extern "C" fn on_instantiate(
            status: i32,
            result: *mut ffi::BackendInstance,
            error: *mut ffi::Error,
            user_data: *mut c_void,
        ) {
            let tx: Box<oneshot::Sender<Result<ffi::BackendInstance>>> =
                unsafe { Box::from_raw(user_data as *mut _) };
            let res =
                decode_async_result(status, result, error, |r| Ok(unsafe { *Box::from_raw(r) }));
            let _ = tx.send(res);
        }

        let vtable = unsafe { &*plugin.factory_vtable() };
        unsafe {
            (vtable.instantiate)(
                plugin.factory_state(),
                &request_ffi,
                cancel_handle
                    .as_ref()
                    .map_or(std::ptr::null(), |h| h.as_ffi_ptr()),
                on_instantiate,
                user_data,
            );
        }
        std::mem::forget(request_ffi);

        let instance_ffi = rx.await.map_err(|_| dropped_sender_error())??;
        drop(cancel_handle);
        instance_from_ffi(instance_ffi, plugin)
    }

    #[tracing::instrument(level = "debug", skip_all, fields(op = "update_credentials"))]
    async fn update_credentials(
        &self,
        connection: &Connection,
        credentials: SecretBundle,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let plugin = Arc::clone(&self.plugin);
        let connection_ffi = shim::auth::connection_to_ffi(connection.clone());
        let credentials_ffi = shim::descriptor::secret_bundle_to_ffi(credentials);
        let cancel_handle = cancel.map(ffi::cancel_token_to_ffi);

        let (tx, rx) = oneshot::channel::<Result<()>>();
        let user_data = Box::into_raw(Box::new(tx)) as *mut c_void;

        extern "C" fn on_update_credentials(
            status: i32,
            error: *mut ffi::Error,
            user_data: *mut c_void,
        ) {
            let tx: Box<oneshot::Sender<Result<()>>> =
                unsafe { Box::from_raw(user_data as *mut _) };
            let _ = tx.send(decode_async_unit_result(status, error));
        }

        let vtable = unsafe { &*plugin.factory_vtable() };
        unsafe {
            (vtable.update_credentials)(
                plugin.factory_state(),
                &connection_ffi,
                &credentials_ffi,
                cancel_handle
                    .as_ref()
                    .map_or(std::ptr::null(), |h| h.as_ffi_ptr()),
                on_update_credentials,
                user_data,
            );
        }
        std::mem::forget(connection_ffi);
        std::mem::forget(credentials_ffi);

        let result = rx.await.map_err(|_| dropped_sender_error())?;
        drop(cancel_handle);
        result
    }

    #[tracing::instrument(level = "debug", skip_all, fields(op = "authenticate"))]
    async fn authenticate(
        &self,
        connection: Connection,
        capability: InteractiveAuthCapability,
        cancel: Option<CancellationToken>,
    ) -> Result<AuthEventStream> {
        let plugin = Arc::clone(&self.plugin);
        let connection_ffi = shim::auth::connection_to_ffi(connection);
        let capability_ffi = shim::auth::interactive_auth_capability_to_ffi(capability);
        let cancel_handle = cancel.map(ffi::cancel_token_to_ffi);

        let (tx, rx) = oneshot::channel::<Result<AuthEventStream>>();
        let user_data = Box::into_raw(Box::new(tx)) as *mut c_void;

        extern "C" fn on_authenticate(
            status: i32,
            result: *mut ffi::AuthEventStream,
            error: *mut ffi::Error,
            user_data: *mut c_void,
        ) {
            let tx: Box<oneshot::Sender<Result<AuthEventStream>>> =
                unsafe { Box::from_raw(user_data as *mut _) };
            let res = decode_async_result(status, result, error, |r| {
                let ffi_stream = unsafe { *Box::from_raw(r) };
                let stream = unsafe { shim::auth::AuthEventStream::from_ffi(ffi_stream) };
                Ok(Box::new(stream) as AuthEventStream)
            });
            let _ = tx.send(res);
        }

        let vtable = unsafe { &*plugin.factory_vtable() };
        unsafe {
            (vtable.authenticate)(
                plugin.factory_state(),
                &connection_ffi,
                capability_ffi,
                cancel_handle
                    .as_ref()
                    .map_or(std::ptr::null(), |h| h.as_ffi_ptr()),
                on_authenticate,
                user_data,
            );
        }
        std::mem::forget(connection_ffi);

        let result = rx.await.map_err(|_| dropped_sender_error())?;
        drop(cancel_handle);
        result
    }
}

fn check_err(err_ptr: *mut ffi::Error) -> Result<()> {
    if err_ptr.is_null() {
        return Ok(());
    }
    let boxed: Box<ffi::Error> = unsafe { Box::from_raw(err_ptr) };
    Err(unsafe { shim::error::from_ffi(*boxed) })
}

fn instance_from_ffi(
    value: ffi::BackendInstance,
    plugin: Arc<HostPlugin>,
) -> Result<shim::BackendInstance> {
    let ffi::BackendInstance {
        backend_id: backend_id_ffi,
        backend: backend_handle,
        address_roots: address_roots_ffi,
        display_name: display_name_ffi,
        auth_state: auth_state_ffi,
    } = value;

    let backend_id = unsafe { shim::address::backend_id_from_ffi(backend_id_ffi)? };

    if backend_handle.state.is_null() || backend_handle.vtable.is_null() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "plugin returned a BackendInstance with null state or vtable",
        ));
    }
    let bvt_struct_size = unsafe { (*backend_handle.vtable).struct_size };
    if bvt_struct_size < std::mem::size_of::<ffi::BackendVTableV1>() {
        return Err(Error::new(
            ErrorCode::IncompatibleType,
            "plugin BackendVTableV1 struct_size is too small",
        ));
    }
    let backend_state = backend_handle.state;
    let backend_vtable = backend_handle.vtable;
    std::mem::forget(backend_handle);

    let address_roots = unsafe {
        shim::primitive::list_from_ffi(address_roots_ffi, |entry| {
            shim::address::address_root_entry_from_ffi(entry)
        })?
    };
    let display_name = unsafe {
        shim::primitive::optional_from_ffi(display_name_ffi, |s| shim::primitive::str_from_ffi(s))?
    };
    let auth_state = unsafe { shim::auth::connection_auth_state_from_ffi(auth_state_ffi)? };

    let backend = Arc::new(LoadedBackend::new(plugin, backend_state, backend_vtable));

    Ok(shim::BackendInstance {
        backend_id,
        backend,
        address_roots,
        display_name,
        auth_state,
    })
}
