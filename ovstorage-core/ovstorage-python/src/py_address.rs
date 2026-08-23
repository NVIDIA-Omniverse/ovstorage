// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Python bindings for the `ovstorage_plugin::address` helpers.
//!
//! The surface is string-in / string-out: there is no Python address value
//! type, exactly as the native side has no `ObjectAddress` newtype. Every
//! entry point parses its address arguments with `address::parse` first, so
//! each call canonicalizes its inputs (host lowercasing and the
//! empty-authority path for ovstorage's non-special schemes, both of which
//! `urllib.parse` cannot reproduce) and reports a malformed URL as
//! `InvalidArgumentError` from one site.

use pyo3::prelude::*;

use crate::ovs;

/// Name the argument that held the malformed URL: several entry points parse
/// more than one address, and the native message alone does not say which.
///
/// `Error` has no message setter, so the label goes on through a rebuild. The
/// context and next-action copies are future-proofing: `address::parse` leaves
/// both `None` today, and carrying them keeps this a relabeling rather than a
/// lossier adaptation path than the single-address entry points use.
fn parse_failed(argument: &str, error: ovs::Error) -> PyErr {
    let mut relabeled = ovs::Error::new(error.code(), format!("{argument}: {}", error.message()));
    if let Some(context) = error.context().cloned() {
        relabeled = relabeled.with_context(context);
    }
    if let Some(next_action) = error.next_action() {
        relabeled = relabeled.with_next_action(next_action);
    }
    crate::py_error(relabeled)
}

/// Parse and canonicalize an address, returning its RFC 3986 canonical form.
#[pyfunction]
fn parse(address: &str) -> PyResult<String> {
    let url = ovs::address::parse(address).map_err(crate::py_error)?;
    Ok(url.to_string())
}

/// Backend primary object key — the percent-decoded path without its leading
/// `/`. Empty for a root path. Raises `InvalidArgumentError` when the decoded
/// key is not valid UTF-8 and therefore has no Python `str` representation.
#[pyfunction]
fn key(address: &str) -> PyResult<String> {
    let url = ovs::address::parse(address).map_err(crate::py_error)?;
    ovs::address::key_utf8(&url).map_err(crate::py_error)
}

/// True when the address refers to a directory (its path ends with `/`).
#[pyfunction]
fn is_directory(address: &str) -> PyResult<bool> {
    let url = ovs::address::parse(address).map_err(crate::py_error)?;
    Ok(ovs::address::is_directory(&url))
}

/// Append `/` if missing, preserving the query.
#[pyfunction]
fn to_directory(address: &str) -> PyResult<String> {
    let url = ovs::address::parse(address).map_err(crate::py_error)?;
    let out = ovs::address::to_directory(&url).map_err(crate::py_error)?;
    Ok(out.to_string())
}

/// Split into `(parent_directory, child_name)` with `child_name`
/// percent-decoded. `None` for directory-form addresses and root paths. Raises
/// `InvalidArgumentError` when the child name is not valid UTF-8.
#[pyfunction]
fn parent_and_name(address: &str) -> PyResult<Option<(String, String)>> {
    let url = ovs::address::parse(address).map_err(crate::py_error)?;
    let Some((parent, name)) = ovs::address::parent_and_name(&url) else {
        return Ok(None);
    };
    let name = String::from_utf8(name).map_err(|_| {
        crate::py_error(ovs::Error::new(
            ovs::ErrorCode::InvalidArgument,
            "child name is not valid UTF-8 and has no Python string representation",
        ))
    })?;
    Ok(Some((parent.to_string(), name)))
}

/// Append a relative path. The relative path must not start with `/`; an
/// empty relative path is a no-op.
#[pyfunction]
fn join_relative(address: &str, relative_path: &str) -> PyResult<String> {
    let url = ovs::address::parse(address).map_err(crate::py_error)?;
    let out = ovs::address::join_relative(&url, relative_path).map_err(crate::py_error)?;
    Ok(out.to_string())
}

/// True when `prefix` is a segment-aligned prefix of `address`. The argument
/// order mirrors the native helper, and so does the answer: this is the same
/// question the routing layer asks.
#[pyfunction]
fn is_prefix_of(prefix: &str, address: &str) -> PyResult<bool> {
    let prefix_url = ovs::address::parse(prefix).map_err(|e| parse_failed("prefix", e))?;
    let url = ovs::address::parse(address).map_err(|e| parse_failed("address", e))?;
    Ok(ovs::address::is_ancestor_or_self(&prefix_url, &url))
}

/// Suffix after `prefix`, or `None` when `prefix` is not a segment-aligned
/// prefix of `address`.
#[pyfunction]
fn strip_prefix(address: &str, prefix: &str) -> PyResult<Option<String>> {
    let url = ovs::address::parse(address).map_err(|e| parse_failed("address", e))?;
    let prefix_url = ovs::address::parse(prefix).map_err(|e| parse_failed("prefix", e))?;
    Ok(ovs::address::relative_suffix(&url, &prefix_url).map(str::to_owned))
}

/// Replace `prefix` with `replacement` at the head of `address`. Raises
/// `NoRouteError` when `address` is not under `prefix`.
#[pyfunction]
fn replace_prefix(address: &str, prefix: &str, replacement: &str) -> PyResult<String> {
    let url = ovs::address::parse(address).map_err(|e| parse_failed("address", e))?;
    let prefix_url = ovs::address::parse(prefix).map_err(|e| parse_failed("prefix", e))?;
    let replacement_url =
        ovs::address::parse(replacement).map_err(|e| parse_failed("replacement", e))?;
    let out = ovs::address::replace_prefix(&url, &prefix_url, &replacement_url)
        .map_err(crate::py_error)?;
    Ok(out.to_string())
}

/// Append or replace one query parameter with URL-parser semantics. Raises
/// `InvalidArgumentError` for an empty `key`.
#[pyfunction]
fn with_query_pair(address: &str, key: &str, value: &str) -> PyResult<String> {
    let url = ovs::address::parse(address).map_err(crate::py_error)?;
    let out = ovs::address::with_query_pair(&url, key, value).map_err(crate::py_error)?;
    Ok(out.to_string())
}

/// Build the `ovstorage.address` submodule and attach it to `parent`.
pub(crate) fn register(py: Python<'_>, parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let module = PyModule::new_bound(py, "address")?;
    // `wrap_pyfunction!` stamps `__module__` from the wrapped module's
    // `__name__`, so set the dotted name before adding the functions.
    // `add_submodule` keys the parent attribute off that same `__name__`,
    // so attach under the bare name by hand instead.
    module.setattr("__name__", "ovstorage.address")?;
    module.add_function(wrap_pyfunction!(is_directory, &module)?)?;
    module.add_function(wrap_pyfunction!(is_prefix_of, &module)?)?;
    module.add_function(wrap_pyfunction!(join_relative, &module)?)?;
    module.add_function(wrap_pyfunction!(key, &module)?)?;
    module.add_function(wrap_pyfunction!(parent_and_name, &module)?)?;
    module.add_function(wrap_pyfunction!(parse, &module)?)?;
    module.add_function(wrap_pyfunction!(replace_prefix, &module)?)?;
    module.add_function(wrap_pyfunction!(strip_prefix, &module)?)?;
    module.add_function(wrap_pyfunction!(to_directory, &module)?)?;
    module.add_function(wrap_pyfunction!(with_query_pair, &module)?)?;
    module.add(
        "__all__",
        vec![
            "is_directory",
            "is_prefix_of",
            "join_relative",
            "key",
            "parent_and_name",
            "parse",
            "replace_prefix",
            "strip_prefix",
            "to_directory",
            "with_query_pair",
        ],
    )?;
    parent.add("address", &module)?;
    // Without the `sys.modules` write `import ovstorage.address` fails even
    // though the parent attribute exists.
    let modules = py.import_bound("sys")?.getattr("modules")?;
    modules.set_item("ovstorage.address", &module)?;
    Ok(())
}
