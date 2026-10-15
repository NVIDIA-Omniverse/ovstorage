// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Python projections of the listener-auth credential wire format.

use ovstorage_authz_context::{AuthCredential as RustAuthCredential, Transport};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

/// TCP peer identity decoded from an `AUTH_CREDENTIAL` extension.
#[pyclass(frozen)]
pub(crate) struct TcpTransport {
    #[pyo3(get)]
    peer_addr: String,
    tls_client_cert: Option<Vec<u8>>,
}

#[pymethods]
impl TcpTransport {
    #[getter]
    fn tls_client_cert<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.tls_client_cert
            .as_deref()
            .map(|bytes| PyBytes::new_bound(py, bytes))
    }
}

/// Unix-domain-socket peer identity decoded from an `AUTH_CREDENTIAL` extension.
#[pyclass(frozen)]
pub(crate) struct UdsTransport {
    #[pyo3(get)]
    uid: u32,
    #[pyo3(get)]
    gid: u32,
    #[pyo3(get)]
    pid: i32,
}

/// Windows named-pipe peer identity decoded from an `AUTH_CREDENTIAL` extension.
#[pyclass(frozen)]
pub(crate) struct NamedPipeTransport {
    #[pyo3(get)]
    sid: String,
    #[pyo3(get)]
    pid: u32,
}

/// A decoded caller credential supplied to a Python-authored layer.
#[pyclass]
pub(crate) struct AuthCredential {
    inner: RustAuthCredential,
}

#[pymethods]
impl AuthCredential {
    /// Decode the bytes stored under `extensions[EXT_AUTH_CREDENTIAL]`.
    #[staticmethod]
    fn decode(bytes: &[u8]) -> PyResult<Self> {
        RustAuthCredential::decode(bytes)
            .map(|inner| Self { inner })
            .map_err(|error| PyValueError::new_err(error.to_string()))
    }

    #[getter]
    fn bearer<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.inner
            .bearer
            .as_deref()
            .map(|bytes| PyBytes::new_bound(py, bytes))
    }

    #[getter]
    fn transport(&self, py: Python<'_>) -> PyResult<PyObject> {
        match &self.inner.transport {
            Transport::Tcp {
                peer_addr,
                tls_client_cert,
            } => Ok(Py::new(
                py,
                TcpTransport {
                    peer_addr: peer_addr.clone(),
                    tls_client_cert: tls_client_cert.clone(),
                },
            )?
            .into_py(py)),
            Transport::Uds { uid, gid, pid } => Ok(Py::new(
                py,
                UdsTransport {
                    uid: *uid,
                    gid: *gid,
                    pid: *pid,
                },
            )?
            .into_py(py)),
            Transport::NamedPipe { sid, pid } => Ok(Py::new(
                py,
                NamedPipeTransport {
                    sid: sid.clone(),
                    pid: *pid,
                },
            )?
            .into_py(py)),
        }
    }

    #[getter]
    fn forwarded(&self) -> Option<Vec<(String, String)>> {
        self.inner
            .forwarded
            .as_ref()
            .map(|forwarded| forwarded.values.clone())
    }

    fn __repr__(&self) -> String {
        let bearer = match &self.inner.bearer {
            Some(bytes) => format!("Some(<redacted; {} bytes>)", bytes.len()),
            None => "None".to_string(),
        };
        let transport = match &self.inner.transport {
            Transport::Tcp {
                tls_client_cert, ..
            } => format!(
                "Tcp(tls_client_cert={} bytes)",
                tls_client_cert.as_ref().map_or(0, Vec::len)
            ),
            Transport::Uds { .. } => "Uds".to_string(),
            Transport::NamedPipe { .. } => "NamedPipe".to_string(),
        };
        let forwarded_headers = self
            .inner
            .forwarded
            .as_ref()
            .map_or(0, |forwarded| forwarded.values.len());
        format!(
            "AuthCredential(bearer={bearer}, transport={transport}, \
             forwarded_headers={forwarded_headers})"
        )
    }
}
