// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::ffi::c_int;
use std::ffi::{CString, c_char};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Output};
use std::sync::OnceLock;

// Portable entry points: compiled on every target so the completeness and
// header-conformance gates keep running when Windows CI returns.
unsafe extern "C" {
    fn ovstorage_c_source_completeness() -> c_int;
    fn ovstorage_c_source_list_entry_stream_free_contract() -> c_int;
    fn ovstorage_c_source_header_ovstorage_c() -> c_int;
    fn ovstorage_c_source_header_defaults_c() -> c_int;
    fn ovstorage_c_source_header_plugin_c() -> c_int;
    fn ovstorage_c_source_header_ovstorage_cpp17() -> c_int;
    fn ovstorage_c_source_header_defaults_cpp17() -> c_int;
    fn ovstorage_c_source_header_plugin_cpp17() -> c_int;
    fn ovstorage_c_source_permission_bits(which: c_int) -> u32;
    fn ovstorage_c_source_permission_bits_cpp17(which: c_int) -> u32;
    fn ovstorage_c_source_secret_wipe_contract() -> c_int;
    fn ovstorage_c_source_auth_credential_contract() -> c_int;
    fn ovstorage_c_source_auth_decoder_plugin_contract(fixture_path: *const c_char) -> c_int;
    fn ovstorage_c_source_roundtrip_c() -> c_int;
    fn ovstorage_c_source_stack_build_async_contract() -> c_int;
    fn ovstorage_c_source_runtime_contracts() -> c_int;
    fn ovstorage_c_source_stream_cancel_contracts() -> c_int;
    fn ovstorage_c_source_auth_cancel_failed_step() -> c_int;
    fn ovstorage_c_source_auth_nul_progress() -> c_int;
    fn ovstorage_c_source_stream_concurrency() -> c_int;
    fn ovstorage_c_source_auth_terminal_contract() -> c_int;
    fn ovstorage_c_source_auth_credentials_round_trip() -> c_int;
    fn ovstorage_c_source_auth_credentials_empty_bundle_present() -> c_int;
    fn ovstorage_c_source_pump_reap_contract() -> c_int;
    fn ovstorage_c_source_file_backend_etag_precondition() -> c_int;
    fn ovstorage_c_source_default_vtables_reserved_null() -> c_int;
    fn ovstorage_c_source_connection_ownership_contract() -> c_int;
    fn ovstorage_c_source_handoff_contract() -> c_int;
    fn ovstorage_c_source_declined_release_contract() -> c_int;
}

// The shipped C++ wrapper needs C++20. `build.rs` emits `ovstorage_cpp20`
// only when its capability probe compiled `ovstorage.hpp`, so a toolchain
// below the documented floor drops these translation units from the link
// instead of failing it.
#[cfg(ovstorage_cpp20)]
unsafe extern "C" {
    fn ovstorage_c_source_header_hpp_cpp20() -> c_int;
    fn ovstorage_c_source_roundtrip_cpp20() -> c_int;
    fn ovstorage_c_source_etag_strength_abi_cpp20(fixture_path: *const c_char) -> c_int;
    fn ovstorage_c_source_versioned_address_abi_cpp20(fixture_path: *const c_char) -> c_int;
}

// Plugin inspection and parked-discovery drivers need a dynamically loaded
// test plugin. The shipped loader covers both POSIX (dlopen) and Win32
// (LoadLibraryW), so these entry points are compiled on every target.
unsafe extern "C" {
    fn ovstorage_c_source_inspect_contract(fixture_path: *const c_char) -> c_int;
    fn ovstorage_c_source_stack_build_parked_contract(fixture_path: *const c_char) -> c_int;
}

#[cfg(ovstorage_cpp20)]
unsafe extern "C" {
    fn ovstorage_c_source_stack_build_parked_cpp(fixture_path: *const c_char) -> c_int;
}

static RUNTIME_CONTRACTS: OnceLock<c_int> = OnceLock::new();

fn ensure_runtime_contracts() {
    // Every integration test enters this OnceLock before it can build a Stack.
    // That makes the two-thread Stack deterministic even under libtest's
    // default parallel execution and pins first-build-wins semantics once.
    let status = *RUNTIME_CONTRACTS.get_or_init(|| {
        // SAFETY: the C entry point owns its temporary Stacks and returns only
        // after their callbacks have quiesced.
        unsafe { ovstorage_c_source_runtime_contracts() }
    });
    assert_eq!(
        status, 0,
        "the process-global runtime warn/reuse contract failed"
    );
}

#[test]
fn process_global_runtime_is_first_build_wins() {
    ensure_runtime_contracts();
}

#[test]
fn pure_c_source_roundtrip() {
    ensure_runtime_contracts();
    // SAFETY: build.rs links this no-argument C test entry point into the test
    // binary. It owns all state it creates and returns only an integer status.
    let status = unsafe { ovstorage_c_source_roundtrip_c() };
    assert_eq!(
        status, 0,
        "the pure-C write/stat/read/stream/list/rename/copy/delete round \
         trip failed"
    );
}

/// The shipped configuration: the C++20 wrapper driving the pure-C
/// implementation this crate compiles and links.
#[test]
#[cfg(ovstorage_cpp20)]
fn cpp20_wrapper_roundtrip() {
    ensure_runtime_contracts();
    // SAFETY: build.rs links this no-argument extern-C adapter into the test
    // binary. It owns all state it creates and returns only an integer status.
    let status = unsafe { ovstorage_c_source_roundtrip_cpp20() };
    assert_eq!(status, 0, "the C++20 wrapper round trip failed");
}

/// The pure-C secret wipe must actually erase, and must leave the buffer it
/// cleared allocated for the clearing path to release.
///
/// The Rust residue tests cover the Rust codec only; this is the same
/// guarantee asserted against the C implementation that ships alongside it.
/// Portable: it touches no Stack, runtime, or filesystem, so unlike the
/// other C entries it needs no runtime-contract prelude.
#[test]
fn pure_c_secret_wipe_erases_the_buffer() {
    // SAFETY: the C entry owns only stack storage and returns a status.
    let status = unsafe { ovstorage_c_source_secret_wipe_contract() };
    assert_eq!(status, 0, "the pure-C secret wipe contract failed");
}

#[test]
fn pure_c_auth_credential_decoder_matches_canonical_vectors() {
    // SAFETY: the C entry owns every decoded credential and error allocation
    // and returns only after releasing them.
    let status = unsafe { ovstorage_c_source_auth_credential_contract() };
    assert_eq!(
        status, 0,
        "the pure-C AuthCredential decoder diverged from the canonical wire vectors"
    );
}

#[test]
fn c_auth_plugin_bundles_credential_decoder_without_host_exports() {
    let fixture = CString::new(env!("OVSTORAGE_C_AUTH_DECODER_PLUGIN_FIXTURE"))
        .expect("the generated C auth plugin path has no interior NUL");
    // SAFETY: the path remains live for the call. The C driver loads the
    // auth-capable plugin with local visibility, resolves its exported probe,
    // and the probe releases every value it decodes before returning.
    let status = unsafe { ovstorage_c_source_auth_decoder_plugin_contract(fixture.as_ptr()) };
    assert_eq!(
        status, 0,
        "the C auth plugin did not resolve its bundled AuthCredential SDK helpers"
    );
}

#[test]
fn pure_c_auth_credential_decoder_reclaims_every_nested_allocation() {
    match env!("OVSTORAGE_C_SOURCE_AUTH_OWNERSHIP_STATUS") {
        "built" => {
            let Some(binary) = option_env!("OVSTORAGE_C_SOURCE_AUTH_OWNERSHIP_BIN") else {
                panic!("built AuthCredential ownership driver has a binary path");
            };
            let status = std::process::Command::new(binary)
                .status()
                .unwrap_or_else(|error| {
                    panic!("failed to run AuthCredential ownership driver `{binary}`: {error}")
                });
            assert!(
                status.success(),
                "the pure-C AuthCredential ownership driver failed: {status}"
            );
        }
        "skipped" => {
            eprintln!("skipping pure-C AuthCredential ownership driver for a cross build");
        }
        failure => panic!("pure-C AuthCredential ownership coverage unavailable: {failure}"),
    }
}

struct CredentialScratch {
    path: PathBuf,
}

impl CredentialScratch {
    fn new() -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::time::{SystemTime, UNIX_EPOCH};

        static NEXT: AtomicU64 = AtomicU64::new(0);

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("the system clock is after the Unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "ovstorage-c-source-cred-{}-{nanos}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap_or_else(|error| {
            panic!(
                "failed to create credential-store scratch directory {}: {error}",
                path.display()
            )
        });
        Self { path }
    }
}

impl Drop for CredentialScratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn credential_store_process_driver() -> Option<&'static str> {
    match env!("OVSTORAGE_C_SOURCE_CRED_STORE_STATUS") {
        "built" => match option_env!("OVSTORAGE_C_SOURCE_CRED_STORE_BIN") {
            Some(path) => Some(path),
            None => panic!("a built credential-store process driver has no binary path"),
        },
        "skipped" => {
            eprintln!("skipping pure-C credential-store process coverage for a cross build");
            None
        }
        failure => panic!("pure-C credential-store process coverage unavailable: {failure}"),
    }
}

fn run_cred_driver(dir: &Path, namespace: &str, args: &[&str]) -> ExitStatus {
    let binary = credential_store_process_driver()
        .expect("run_cred_driver is called only when the native driver was built");
    Command::new(binary)
        .arg(dir)
        .arg(namespace)
        .args(args)
        .status()
        .unwrap_or_else(|error| panic!("failed to run credential-store driver `{binary}`: {error}"))
}

fn run_cred_driver_output(dir: &Path, namespace: &str, args: &[&str]) -> Output {
    let binary = credential_store_process_driver()
        .expect("run_cred_driver_output is called only when the native driver was built");
    Command::new(binary)
        .arg(dir)
        .arg(namespace)
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("failed to run credential-store driver `{binary}`: {error}"))
}

fn credential_record_path(dir: &Path, namespace: &str) -> PathBuf {
    dir.join("c-credentials")
        .join(format!("{}.creds", credential_namespace_stem(namespace)))
}

fn credential_temp_path(dir: &Path, namespace: &str) -> PathBuf {
    dir.join("c-credentials").join(format!(
        "{}.creds.tmp",
        credential_namespace_stem(namespace)
    ))
}

fn credential_namespace_stem(namespace: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    namespace
        .as_bytes()
        .iter()
        .flat_map(|byte| [HEX[(byte >> 4) as usize], HEX[(byte & 0x0f) as usize]])
        .map(char::from)
        .collect()
}

fn assert_cred_driver_success(dir: &Path, namespace: &str, args: &[&str]) {
    let status = run_cred_driver(dir, namespace, args);
    assert!(
        status.success(),
        "credential-store driver {:?} failed: {status}",
        args.first().copied().unwrap_or("<missing phase>")
    );
    assert!(
        !credential_temp_path(dir, namespace).exists(),
        "credential-store operation left its temporary record behind"
    );
}

#[test]
fn pure_c_credentials_survive_a_process_restart() {
    if credential_store_process_driver().is_none() {
        return;
    }
    let scratch = CredentialScratch::new();
    let namespace = "restart-app";
    let record = credential_record_path(&scratch.path, namespace);

    assert_cred_driver_success(&scratch.path, namespace, &["put", "k", "v1"]);
    assert!(
        record.is_file(),
        "the first put did not create the record file"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mode = |path: &Path| {
            std::fs::metadata(path)
                .unwrap_or_else(|error| panic!("failed to stat {}: {error}", path.display()))
                .permissions()
                .mode()
                & 0o777
        };
        assert_eq!(mode(&scratch.path), 0o700, "auth directory mode");
        assert_eq!(
            mode(&scratch.path.join("c-credentials")),
            0o700,
            "credential directory mode"
        );
        assert_eq!(mode(&record), 0o600, "credential record mode");
    }

    assert_cred_driver_success(&scratch.path, namespace, &["get", "k", "v1"]);
    assert_cred_driver_success(&scratch.path, "other-app", &["absent", "k"]);
    assert_cred_driver_success(&scratch.path, namespace, &["put", "k", "v2"]);
    assert_cred_driver_success(&scratch.path, namespace, &["get", "k", "v2"]);
    assert_cred_driver_success(&scratch.path, namespace, &["delete", "k"]);
    assert_cred_driver_success(&scratch.path, namespace, &["absent", "k"]);
}

#[test]
fn pure_c_credential_store_serialises_concurrent_processes() {
    let Some(binary) = credential_store_process_driver() else {
        return;
    };
    let scratch = CredentialScratch::new();
    let namespace = "contention-app";
    let mut children = Vec::new();

    for worker in 0..4 {
        children.push(
            Command::new(binary)
                .arg(&scratch.path)
                .arg(namespace)
                .arg("contend")
                .arg(worker.to_string())
                .arg("20")
                .spawn()
                .unwrap_or_else(|error| {
                    panic!("failed to launch credential contention worker {worker}: {error}")
                }),
        );
    }
    for (worker, mut child) in children.into_iter().enumerate() {
        let status = child.wait().unwrap_or_else(|error| {
            panic!("failed to wait for credential contention worker {worker}: {error}")
        });
        assert!(
            status.success(),
            "contention worker {worker} failed: {status}"
        );
    }
    assert!(
        !credential_temp_path(&scratch.path, namespace).exists(),
        "concurrent credential operations left a temporary record behind"
    );
    for worker in 0..4 {
        let key = format!("worker-{worker}");
        let value = format!("{worker}:19");
        assert_cred_driver_success(
            &scratch.path,
            namespace,
            &["get", key.as_str(), value.as_str()],
        );
    }
}

#[test]
fn pure_c_credential_store_refuses_a_corrupt_file() {
    if credential_store_process_driver().is_none() {
        return;
    }
    let scratch = CredentialScratch::new();
    let namespace = "corrupt-app";
    let record = credential_record_path(&scratch.path, namespace);

    assert_cred_driver_success(&scratch.path, namespace, &["put", "k", "v"]);
    let original = std::fs::read(&record)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", record.display()));
    assert!(
        original.len() > 1,
        "credential record is unexpectedly short"
    );

    let truncated = original[..original.len() - 1].to_vec();
    let mut bad_trailer = original;
    let trailer = bad_trailer
        .last_mut()
        .expect("the non-empty credential record has a trailer byte");
    *trailer ^= 0x80;

    for corrupt in [&truncated, &bad_trailer] {
        std::fs::write(&record, corrupt)
            .unwrap_or_else(|error| panic!("failed to corrupt {}: {error}", record.display()));
        let before = std::fs::read(&record)
            .unwrap_or_else(|error| panic!("failed to re-read {}: {error}", record.display()));

        let get =
            run_cred_driver_output(&scratch.path, namespace, &["get-expect-unavailable", "k"]);
        assert_eq!(
            get.status.code(),
            Some(2),
            "corrupt credential read did not report StateRootUnavailable: {}",
            String::from_utf8_lossy(&get.stderr)
        );
        assert!(
            String::from_utf8_lossy(&get.stderr).contains(&record.to_string_lossy()[..]),
            "corrupt credential diagnostic did not name {}: {}",
            record.display(),
            String::from_utf8_lossy(&get.stderr)
        );
        assert_eq!(
            std::fs::read(&record).expect("read record after refused get"),
            before,
            "a refused get changed the corrupt record"
        );

        let put = run_cred_driver_output(&scratch.path, namespace, &["put", "k", "v2"]);
        assert!(
            !put.status.success(),
            "put unexpectedly replaced a corrupt credential record"
        );
        assert_eq!(
            std::fs::read(&record).expect("read record after refused put"),
            before,
            "a refused put changed the corrupt record"
        );
        assert!(
            !credential_temp_path(&scratch.path, namespace).exists(),
            "a refused corrupt-file operation left a temporary record behind"
        );
    }
}

#[test]
#[cfg(unix)]
fn pure_c_credential_store_lock_timeout_is_transient() {
    use std::io::{BufRead, BufReader};
    use std::process::Stdio;

    let Some(binary) = credential_store_process_driver() else {
        return;
    };
    let scratch = CredentialScratch::new();
    let namespace = "timeout-app";

    /* Materialize the private directory and lock file before the holder opens
     * it directly. The holder announces only after fcntl owns the lock. */
    assert_cred_driver_success(&scratch.path, namespace, &["put", "seed", "seed"]);
    let mut holder = Command::new(binary)
        .arg(&scratch.path)
        .arg(namespace)
        .args(["hold-lock", "15"])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap_or_else(|error| panic!("failed to launch credential lock holder: {error}"));
    let stdout = holder
        .stdout
        .take()
        .expect("the credential lock holder has piped stdout");
    let mut ready = String::new();
    BufReader::new(stdout)
        .read_line(&mut ready)
        .expect("read credential lock holder readiness");
    if ready != "locked\n" {
        let _ = holder.kill();
        let status = holder.wait().expect("reap failed credential lock holder");
        panic!("credential lock holder was not ready ({status}): {ready:?}");
    }

    let put = run_cred_driver_output(&scratch.path, namespace, &["put", "k", "v"]);
    let _ = holder.kill();
    let _ = holder.wait();

    let stderr = String::from_utf8_lossy(&put.stderr);
    assert!(
        !put.status.success(),
        "put unexpectedly succeeded while another process held the lock"
    );
    assert!(
        stderr.contains("Transient") || stderr.contains("held by another process"),
        "lock timeout diagnostic was not transient: {stderr}"
    );
}

#[test]
fn frozen_c_api_is_link_complete() {
    ensure_runtime_contracts();
    // SAFETY: build.rs renames completeness.c's no-argument main function to
    // this C symbol. Calling it forces all frozen API references into the link.
    let status = unsafe { ovstorage_c_source_completeness() };
    assert_eq!(status, 0, "the frozen C API completeness table failed");
}

#[test]
fn list_entry_stream_free_drops_once_and_accepts_null() {
    ensure_runtime_contracts();
    // SAFETY: the C entry owns its heap stream fixture and keeps the
    // drop-counter state live until the destructor returns.
    let status = unsafe { ovstorage_c_source_list_entry_stream_free_contract() };
    assert_eq!(
        status, 0,
        "the list-entry stream destructor contract failed"
    );
}

#[test]
fn cpp_wrapper_c_operation_parity_is_exact() {
    use std::collections::BTreeSet;

    const C_HEADER: &str = include_str!("../../../ovstorage-c-source/include/ovstorage.h");
    const CPP_PROBE: &str = include_str!("cc/header_hpp_cpp20.cpp");
    const WRAPPED: &[(&str, &str)] = &[
        ("ovstorage_stat", "LayerHandle::stat"),
        ("ovstorage_read_bytes", "LayerHandle::read_bytes"),
        ("ovstorage_read_stream", "LayerHandle::read_stream"),
        ("ovstorage_read_local_file", "LayerHandle::read_local_file"),
        ("ovstorage_write", "LayerHandle::write"),
        ("ovstorage_write_stream", "LayerHandle::write_stream"),
        ("ovstorage_write_redirect", "LayerHandle::write_redirect"),
        ("ovstorage_continue_write", "LayerHandle::continue_write"),
        ("ovstorage_delete", "LayerHandle::delete_object"),
        ("ovstorage_list", "LayerHandle::list"),
        ("ovstorage_list_versions", "LayerHandle::list_versions"),
        (
            "ovstorage_get_latest_version",
            "LayerHandle::get_latest_version",
        ),
        ("ovstorage_watch_directory", "LayerHandle::watch_directory"),
        ("ovstorage_copy", "LayerHandle::copy"),
        ("ovstorage_rename", "LayerHandle::rename"),
        (
            "ovstorage_create_directory",
            "LayerHandle::create_directory",
        ),
        (
            "ovstorage_delete_directory",
            "LayerHandle::delete_directory",
        ),
        ("ovstorage_update_metadata", "LayerHandle::update_metadata"),
        ("ovstorage_check_access", "LayerHandle::check_access"),
        ("ovstorage_probe", "LayerHandle::probe"),
        ("ovstorage_add_connection", "LayerHandle::add_connection"),
        (
            "ovstorage_list_connections",
            "LayerHandle::list_connections",
        ),
        (
            "ovstorage_remove_connection",
            "LayerHandle::remove_connection",
        ),
        (
            "ovstorage_update_connection_credentials",
            "LayerHandle::update_connection_credentials",
        ),
        (
            "ovstorage_update_connection_attributes",
            "LayerHandle::update_connection_attributes",
        ),
        (
            "ovstorage_authenticate_connection",
            "LayerHandle::authenticate_connection",
        ),
        (
            "ovstorage_list_address_roots",
            "LayerHandle::list_address_roots",
        ),
        ("ovstorage_root_info_for", "LayerHandle::root_info_for"),
    ];
    let c_operations = C_HEADER
        .split(';')
        .filter_map(|declaration| {
            let signature = declaration
                .split_once("void ovstorage_")
                .map(|(_, suffix)| format!("ovstorage_{}", suffix.trim_start()))?;
            if !signature.contains("(const OvStorage_LayerHandle *handle") {
                return None;
            }
            signature
                .split_once('(')
                .map(|(name, _)| name.trim().to_owned())
        })
        .collect::<BTreeSet<_>>();
    let wrapped = WRAPPED
        .iter()
        .map(|(c_name, cpp_marker)| {
            assert!(
                CPP_PROBE.contains(cpp_marker),
                "the C++ conformance probe no longer names {cpp_marker}"
            );
            (*c_name).to_owned()
        })
        .collect::<BTreeSet<_>>();
    let actual = c_operations
        .difference(&wrapped)
        .cloned()
        .collect::<BTreeSet<_>>();
    assert_eq!(
        actual,
        BTreeSet::new(),
        "every public C LayerHandle operation must have a C++ wrapper"
    );
}

#[test]
fn shipped_headers_conform_as_c_and_cpp17() {
    ensure_runtime_contracts();
    // SAFETY: each probe is a freestanding pure function in a conformance TU
    // that includes exactly one shipped header. Calling them pulls every
    // conformance object into the link, so the plugin header's extern "C"
    // linkage is verified against the C implementation, not just compiled.
    let probes: [(&str, unsafe extern "C" fn() -> c_int); 6] = [
        ("ovstorage.h as C99", ovstorage_c_source_header_ovstorage_c),
        (
            "ovstorage_defaults.h as C99",
            ovstorage_c_source_header_defaults_c,
        ),
        (
            "ovstorage_plugin.h as C99",
            ovstorage_c_source_header_plugin_c,
        ),
        (
            "ovstorage.h as C++17",
            ovstorage_c_source_header_ovstorage_cpp17,
        ),
        (
            "ovstorage_defaults.h as C++17",
            ovstorage_c_source_header_defaults_cpp17,
        ),
        (
            "ovstorage_plugin.h as C++17",
            ovstorage_c_source_header_plugin_cpp17,
        ),
    ];
    for (surface, probe) in probes {
        // SAFETY: see above; every probe owns no state and returns a status.
        let status = unsafe { probe() };
        assert_eq!(status, 0, "header conformance probe failed: {surface}");
    }
}

/// `ovstorage.hpp` is the one shipped header that needs C++20, so it gets its
/// own probe rather than joining the table above — a toolchain below the
/// documented floor must not take the C and C++17 conformance down with it.
#[test]
#[cfg(ovstorage_cpp20)]
fn shipped_wrapper_conforms_as_cpp20() {
    ensure_runtime_contracts();
    // SAFETY: the probe is a freestanding pure function in a TU that includes
    // exactly one shipped header. Calling it pulls that object into the link.
    let status = unsafe { ovstorage_c_source_header_hpp_cpp20() };
    assert_eq!(
        status, 0,
        "header conformance probe failed: ovstorage.hpp as C++20"
    );
}

#[test]
fn blocking_pull_cancel_teardown_is_stable() {
    ensure_runtime_contracts();
    // SAFETY: the C entry owns every stub stream, cancellation token, pump,
    // and synchronization primitive. It repeats both watch and public-auth
    // cancellation 100 times before returning a status.
    let status = unsafe { ovstorage_c_source_stream_cancel_contracts() };
    assert_eq!(status, 0, "blocking-pull cancellation teardown failed");
}

#[test]
fn auth_cancel_racing_failed_step_reports_cancelled() {
    ensure_runtime_contracts();
    // SAFETY: the C entry owns its stub Layer, token, and callback state. It
    // repeats the cancel-races-Failed-step auth flow 100 times.
    let status = unsafe { ovstorage_c_source_auth_cancel_failed_step() };
    assert_eq!(
        status, 0,
        "a cancel racing a Failed auth step must report Cancelled"
    );
}

#[test]
fn effective_permissions_macros_match_rust_bits() {
    use ovstorage_layer::EffectivePermissions;

    // The C constants are hand-emitted via cbindgen `after_includes`
    // (cbindgen cannot render the Rust associated constants), so this is
    // the only automated lock-step check between the two definitions.
    let expected = [
        ("READ", 0, EffectivePermissions::READ),
        ("WRITE", 1, EffectivePermissions::WRITE),
        ("DELETE", 2, EffectivePermissions::DELETE),
        ("UPDATE_METADATA", 3, EffectivePermissions::UPDATE_METADATA),
    ];
    for (name, which, rust_value) in expected {
        // SAFETY: both probes only read compile-time constants. The macros
        // carry separate C and C++ arms, and macros are checked only when
        // expanded — so each arm needs its own probe.
        let c_bits = unsafe { ovstorage_c_source_permission_bits(which) };
        let cpp_bits = unsafe { ovstorage_c_source_permission_bits_cpp17(which) };
        assert_eq!(
            c_bits,
            rust_value.bits(),
            "shipped C macro for EffectivePermissions::{name} diverged \
             from the Rust definition"
        );
        assert_eq!(
            cpp_bits,
            rust_value.bits(),
            "shipped C++ macro arm for EffectivePermissions::{name} \
             diverged from the Rust definition"
        );
    }
}

#[test]
fn auth_progress_with_interior_nul_converts_lossily() {
    ensure_runtime_contracts();
    // SAFETY: the C entry owns its stub Layer and callback state. It runs
    // an auth flow whose Progress event carries an interior NUL and pins
    // the escaped delivery plus the clean success terminal.
    let status = unsafe { ovstorage_c_source_auth_nul_progress() };
    assert_eq!(
        status, 0,
        "an interior NUL in an auth event must convert lossily, not fail \
         the flow"
    );
}

#[test]
fn completed_auth_pumps_are_reaped_before_destroy() {
    ensure_runtime_contracts();
    // SAFETY: the C entry owns its stub Layer, tokens, and callback state.
    // It runs ten auth flows against one live handle and polls the private
    // pump-registration count down to zero before destroying the handle.
    let status = unsafe { ovstorage_c_source_pump_reap_contract() };
    assert_eq!(
        status, 0,
        "completed auth pumps must be reaped at their terminal, not at \
         handle destroy"
    );
}

#[test]
fn active_stream_does_not_starve_runtime_io() {
    ensure_runtime_contracts();
    // SAFETY: the C entry owns its stub Layer and waits for all callbacks.
    let status = unsafe { ovstorage_c_source_stream_concurrency() };
    assert_eq!(status, 0, "an active stream starved stat/read dispatch");
}

#[test]
fn authenticate_connection_ends_with_empty_success_fire() {
    ensure_runtime_contracts();
    // SAFETY: the C entry owns its stub Layer and callback state.
    let status = unsafe { ovstorage_c_source_auth_terminal_contract() };
    assert_eq!(status, 0, "authentication terminal callback shape drifted");
}

#[test]
fn auth_credentials_round_trip_through_the_plugin_decoder() {
    ensure_runtime_contracts();
    // SAFETY: the C entry owns its stub Layer, callback state, and the
    // taken SecretBundle it forwards through update_connection_credentials.
    let status = unsafe { ovstorage_c_source_auth_credentials_round_trip() };
    assert_eq!(
        status, 0,
        "a Succeeded auth event's credentials did not survive decode, \
         take, and re-encode through update_connection_credentials"
    );
}

#[test]
fn auth_credentials_empty_bundle_present_is_not_collapsed_to_absent() {
    ensure_runtime_contracts();
    // SAFETY: the C entry owns its stub Layer, callback state, and the
    // taken SecretBundle it forwards through update_connection_credentials.
    let status = unsafe { ovstorage_c_source_auth_credentials_empty_bundle_present() };
    assert_eq!(
        status, 0,
        "a present-but-empty plugin SecretBundle must decode to a real, \
         non-NULL bundle, not collapse to the same NULL that means \
         \"no credentials field was reported\""
    );
}

#[test]
fn file_backend_etag_mismatch_reports_object_modified() {
    ensure_runtime_contracts();
    // SAFETY: the C entry owns its Registry, backend handle, temp directory,
    // and completion latches. The public write options carry no etag slot, so
    // it drives the real file backend's plugin-ABI write slot directly.
    let status = unsafe { ovstorage_c_source_file_backend_etag_precondition() };
    assert_eq!(
        status, 0,
        "a stale if_dest MatchEtag write must fail with PreconditionFailed"
    );
}

#[test]
fn default_vtables_keep_reserved_slots_null() {
    ensure_runtime_contracts();
    // SAFETY: the C entry only reads the two const default vtables.
    let status = unsafe { ovstorage_c_source_default_vtables_reserved_null() };
    assert_eq!(
        status, 0,
        "a default vtable populated a frozen _reserved slot (NULL means \
         not-implemented)"
    );
}

#[test]
fn connection_calls_report_whether_they_took_the_handle() {
    ensure_runtime_contracts();
    // SAFETY: the C entry owns its stub Layer, public handle, connection
    // request, credential bundle, and callback state. It drives one
    // prologue rejection and one layer-side error through each of the two
    // ownership-taking connection verbs and checks the caller's slot after
    // each, then cleans up unconditionally.
    let status = unsafe { ovstorage_c_source_connection_ownership_contract() };
    assert_eq!(
        status, 0,
        "a connection call misreported whether it took the caller's handle"
    );
}

#[test]
fn exported_handles_import_and_outlive_the_exporter() {
    ensure_runtime_contracts();
    // SAFETY: the C entry owns its temp directory, built Stack, exported
    // handles, and callback state. It pins the import handshake's typed
    // failures and disposal contract, then drives an export -> import ->
    // drive -> destroy round trip (including an import that outlives the
    // exporting handle) before returning a status.
    let status = unsafe { ovstorage_c_source_handoff_contract() };
    assert_eq!(
        status, 0,
        "the C->C export/import live-handoff contract failed"
    );
}

/// Every slot a partial backend leaves at `OVSTORAGE_UNSUPPORTED_VTABLE`
/// releases the request it was handed.
///
/// The slot owns that request -- the host relinquishes it before the call --
/// so a slot that answers "unsupported" without releasing leaks every buffer
/// the request names. All 27 are driven; the six `file_backend.c` inherits
/// are the leak as it ships, `probe` most of all since its request carries a
/// connection's whole `SecretBundle`.
///
/// This binary carries NO sanitizer, so what runs here is the contract's
/// completion counts, its per-case message and ordering assertions, and the
/// stream-drop check. The leak oracle is the same contract compiled into the
/// sanitized leak-contracts driver by `make c-source-examples`; a release that
/// silently stops freeing is caught there, not here.
///
/// That gate is why the contract builds each request from many small
/// allocations rather than one large one, and why the fixtures populate every
/// owning field. See the file header.
#[test]
fn declining_slots_release_the_request_they_own() {
    let status = unsafe { ovstorage_c_source_declined_release_contract() };
    assert_eq!(
        status, 0,
        "a declining slot did not release the request it was handed"
    );
}

#[test]
fn stack_build_async_completes_rejects_inline_and_cancels() {
    ensure_runtime_contracts();
    // SAFETY: the C entry owns its temp directory, builders, cancel token,
    // and callback latch. It drives an async build to success, pins the
    // inline prologue rejection (root unset) leaving the builder reusable,
    // and completes a pre-cancelled build with Cancelled before rebuilding
    // the same intact builder; every wait is a condition-variable latch.
    let status = unsafe { ovstorage_c_source_stack_build_async_contract() };
    assert_eq!(
        status, 0,
        "the pure-C ovstorage_stack_build_async ownership contract failed"
    );
}

/// Serializes the two tests that drive the `ovstorage-plugin-test-abi`
/// cdylib's parked-introspection fixture.
///
/// The fixture's release gate and arrival channel are process-wide statics in
/// the dlopen'd image, and both tests here `dlopen` the same image into this
/// one test binary. `ovstorage_test_export_parked_stack` re-arms the gate and
/// drains pending arrivals, so a concurrent sibling's export eats the arrival
/// this test is waiting for; `ovstorage_test_park_wait_arrived` then returns
/// on the sibling's signal, the cancel fires before the op has parked, and the
/// discovery completes `Ok` instead of `Cancelled`. Same guard, same reason,
/// as `ovstorage/tests/handoff_cross_binary.rs`'s `SERIAL`.
///
/// Poison-tolerant: a panic in one test must fail only that test, not convert
/// the other into a poisoned-mutex panic that hides its real outcome.
static PARK_FIXTURE_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// A genuinely PARKED async operation over the pure-C runtime, driven against
/// the Rust `ovstorage-plugin-test-abi` parking fixture: the pure-C
/// `ovstorage_import_handle` imports the fixture's parked root across the
/// foreign Rust vtable, and `ovstorage_list_address_roots` parks until released
/// or cancelled. Pins that a parked discovery does not complete/block while
/// parked (a sibling `stat` progresses), cancels to `Cancelled` (code name
/// "Cancelled"), and leaves the imported root destructible + a fresh import
/// reusable. See `tests/cc/stack_build_parked_c.c` for why this drives the
/// parked ROOT-DISCOVERY slot rather than `ovstorage_stack_build_async` (the
/// fixture's `ParkBackend` is not a factory kind and cannot be composed into a
/// Stack), and `stack_async_c.c` for the real build cancel/reuse contract.
///
/// Locates the fixture cdylib next to the test binary — building it on demand,
/// as the Stack-plugin tests do — and skips when absent unless
/// `OVSTORAGE_REQUIRE_TEST_PLUGINS` is set (then a hard error).
#[test]
fn parked_discovery_over_pure_c_is_nonblocking_and_cancellable() {
    let _serial = PARK_FIXTURE_SERIAL
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    ensure_runtime_contracts();
    let require = require_env("OVSTORAGE_REQUIRE_TEST_PLUGINS");
    let Some(fixture) = locate_test_plugin_so(
        "ovstorage-plugin-test-abi",
        "ovstorage_plugin_test_abi",
        require,
    ) else {
        return;
    };
    let fixture = CString::new(fixture.to_string_lossy().into_owned())
        .expect("fixture path has no interior NUL");
    // SAFETY: the path stays live for the call. The C entry owns its dlopen,
    // imported roots, worker threads, tokens, and latches, and returns only a
    // status after every callback has quiesced.
    let status = unsafe { ovstorage_c_source_stack_build_parked_contract(fixture.as_ptr()) };
    assert_eq!(
        status, 0,
        "a parked pure-C discovery must be non-blocking, cancel to Cancelled, \
         and leave the imported root reusable/destructible"
    );
}

/// The same parked-discovery contract as the C driver above, but reached
/// through the shipped C++20 wrapper's coroutine machinery (`task<T>` /
/// `detail::awaiter_base` / `sync_wait`) rather than the raw callbacks — the
/// shipped configuration, wrapper over C source. The wrapper must not block
/// while the op is parked, must complete it with `Cancelled` when its token
/// fires, and must leave the imported root reusable and destructible.
#[test]
#[cfg(ovstorage_cpp20)]
fn parked_discovery_through_the_cpp_wrapper_is_nonblocking_and_cancellable() {
    let _serial = PARK_FIXTURE_SERIAL
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    ensure_runtime_contracts();
    let require = require_env("OVSTORAGE_REQUIRE_TEST_PLUGINS");
    let Some(fixture) = locate_test_plugin_so(
        "ovstorage-plugin-test-abi",
        "ovstorage_plugin_test_abi",
        require,
    ) else {
        return;
    };
    let fixture = CString::new(fixture.to_string_lossy().into_owned())
        .expect("fixture path has no interior NUL");
    // SAFETY: the path stays live for the call. The C++ entry owns its dlopen,
    // imported roots, worker threads, tokens, and latches, and returns only a
    // status after every callback has quiesced.
    let status = unsafe { ovstorage_c_source_stack_build_parked_cpp(fixture.as_ptr()) };
    assert_eq!(
        status, 0,
        "a parked discovery driven through the C++ wrapper must be non-blocking, \
         cancel to Cancelled, and leave the imported root reusable/destructible"
    );
}

/// Current metadata crosses Rust plugin ABI -> pure-C dispatch -> public C
/// snapshot -> C++ with its etag strength unchanged.
#[test]
#[cfg(ovstorage_cpp20)]
fn cpp20_etag_strength_crosses_ffi() {
    let _serial = PARK_FIXTURE_SERIAL
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    ensure_runtime_contracts();
    let require = require_env("OVSTORAGE_REQUIRE_TEST_PLUGINS");
    let Some(fixture) = locate_test_plugin_so(
        "ovstorage-plugin-test-abi",
        "ovstorage_plugin_test_abi",
        require,
    ) else {
        return;
    };
    let fixture = CString::new(fixture.to_string_lossy().into_owned())
        .expect("fixture path has no interior NUL");
    // SAFETY: the path stays live for the call. The C++ driver imports the
    // current fixture handle, waits for stat to complete, and returns only
    // after every owned snapshot is destroyed.
    let status = unsafe { ovstorage_c_source_etag_strength_abi_cpp20(fixture.as_ptr()) };
    assert_eq!(
        status, 0,
        "the C++ projection did not preserve current etag strength"
    );
}

/// A version pin crosses Rust plugin ABI -> pure-C dispatch -> public C
/// snapshot -> C++ unchanged, and only when asked for. The fixture pins an
/// item only when the request flag reaches it, so the options forms of
/// `stat` and `list` prove the C and C++ request paths carry the flag, and
/// the bool and positional forms prove they do not invent it.
#[test]
#[cfg(ovstorage_cpp20)]
fn cpp20_versioned_address_crosses_ffi() {
    let _serial = PARK_FIXTURE_SERIAL
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    ensure_runtime_contracts();
    let require = require_env("OVSTORAGE_REQUIRE_TEST_PLUGINS");
    let Some(fixture) = locate_test_plugin_so(
        "ovstorage-plugin-test-abi",
        "ovstorage_plugin_test_abi",
        require,
    ) else {
        return;
    };
    let fixture = CString::new(fixture.to_string_lossy().into_owned())
        .expect("fixture path has no interior NUL");
    // SAFETY: the path stays live for the call. The C++ driver imports the
    // current fixture handle, waits for every stat and list to complete, and
    // returns only after every owned snapshot is destroyed.
    let status = unsafe { ovstorage_c_source_versioned_address_abi_cpp20(fixture.as_ptr()) };
    assert_eq!(
        status, 0,
        "the C++ projection did not carry the versioned_address flag and pin faithfully"
    );
}

/// Regression coverage: the eager-start `task<T>` drop-before-await abandon
/// path must not self-destroy its coroutine frame from inside
/// `final_awaiter::await_suspend` — freeing a coroutine from inside its own
/// suspension machinery is UB. The reporter saw it as a worker-thread hang
/// under ASan; the same defect risks use-after-free, double-free, or a leaked
/// frame depending on codegen.
#[test]
#[cfg(ovstorage_cpp20)]
fn cpp20_task_drop_before_await_no_uaf() {
    run_task_drop_regression(
        option_env!("OVSTORAGE_C_SOURCE_TASK_DROP_STATUS"),
        option_env!("OVSTORAGE_C_SOURCE_TASK_DROP_BIN"),
        option_env!("OVSTORAGE_C_SOURCE_TASK_DROP_ASAN"),
        "task drop-before-await",
        "a worker thread is wedged inside resume() (the self-destroy regression)",
    );
}

/// Regression coverage: when the callback worker reaches `final_suspend`
/// before an un-awaited task is dropped, the destructor must defer frame
/// destruction until the worker's `resume()` call has fully unwound.
#[test]
#[cfg(ovstorage_cpp20)]
fn cpp20_task_drop_after_worker_park_no_uaf() {
    run_task_drop_regression(
        option_env!("OVSTORAGE_C_SOURCE_TASK_WORKER_PARK_STATUS"),
        option_env!("OVSTORAGE_C_SOURCE_TASK_WORKER_PARK_BIN"),
        option_env!("OVSTORAGE_C_SOURCE_TASK_WORKER_PARK_ASAN"),
        "task worker-park-first drop",
        "a worker thread is wedged in the frame-ownership handshake",
    );
}

/// Drive one `task<T>` lifetime regression, applying this crate's tri-state
/// policy: only a structural reason skips. An absent status means the C++20
/// gate dropped the regression at build time; `skipped` means a non-native
/// build; anything else is a build failure and panics, so
/// a compiler that chokes on the wrapper cannot silently delete the coverage.
#[cfg(ovstorage_cpp20)]
fn run_task_drop_regression(
    status: Option<&str>,
    binary: Option<&str>,
    asan: Option<&str>,
    label: &str,
    timeout_context: &str,
) {
    match status {
        None => {
            eprintln!("skipping the {label} regression: not built on this platform");
            return;
        }
        Some("built") => {}
        Some("skipped") => {
            eprintln!("skipping the {label} regression: needs a native build");
            return;
        }
        Some(other) => panic!("the {label} regression did not build: {other}"),
    }
    let (Some(binary), Some(asan)) = (binary, asan) else {
        panic!("a built {label} regression must report its path");
    };
    eprintln!("running {binary} (leak detection: {asan})");
    // `crt` is the debug CRT alone: it reports blocks still outstanding at
    // exit, and cannot see a freed-frame access or a double-free, because
    // neither leaves an outstanding allocation. These regressions exist for
    // exactly that failure, so leak-only coverage is not enough where the
    // runner is required to have the full article.
    assert!(
        asan != "crt" || !require_env("OVSTORAGE_REQUIRE_SANITIZERS"),
        "the {label} regression has the debug CRT but no AddressSanitizer \
         (ASAN=crt) while OVSTORAGE_REQUIRE_SANITIZERS is set — the \
         use-after-free half of this check is unobserved"
    );
    if asan == "0" {
        assert!(
            !require_env("OVSTORAGE_REQUIRE_SANITIZERS"),
            "the {label} regression built without leak detection (ASAN=0) but \
             OVSTORAGE_REQUIRE_SANITIZERS is set — refusing to run an outcome-only \
             check for a lifetime bug"
        );
        eprintln!(
            "warning: the {label} regression has no leak detector on this \
             toolchain; only hang / crash / wrong-outcome coverage remains"
        );
    }

    let mut child = std::process::Command::new(binary)
        // Make any ASan finding a hard, non-zero-exit failure rather than a
        // best-effort warning.
        .env(
            "ASAN_OPTIONS",
            "abort_on_error=1:halt_on_error=1:exitcode=1",
        )
        // These regressions assert on a leaked frame as well as a
        // use-after-free, and `LSAN_OPTIONS` is consulted after `ASAN_OPTIONS`
        // for leak settings — so a developer with `detect_leaks=0` exported to
        // quieten unrelated noise would lose the leak half without being told.
        // Cleared rather than set to `detect_leaks=1`: asking explicitly is
        // fatal where LeakSanitizer cannot exist, and the platform default
        // already covers the hosts where it can.
        .env("LSAN_OPTIONS", "")
        .spawn()
        .unwrap_or_else(|error| panic!("failed to launch {binary}: {error}"));

    let timeout = std::time::Duration::from_secs(120);
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                assert!(
                    status.success(),
                    "the {label} regression exited with failure: {status} \
                     (a use-after-free, double-free, or leak in the task<T> \
                      lifetime path)"
                );
                return;
            }
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!(
                        "the {label} regression hung for {}s — {timeout_context}",
                        timeout.as_secs(),
                    );
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(error) => panic!("failed to poll the {label} regression: {error}"),
        }
    }
}

/// Allocation failure inside a C callback must not escape into the C frame
/// that invoked it, must not leak the payload that callback was handed, and
/// must still resolve the awaiting coroutine.
///
/// Runs as a separate process because the driver replaces the global
/// `operator new` and interposes `free`, and because two of the failure modes
/// are process-wide: a boundary that swallows the exception without resuming
/// hangs, and one that lets it escape a `noexcept` thunk aborts. The timeout
/// below is what turns the hang into a named failure instead of a wedged job.
#[test]
#[cfg(all(unix, ovstorage_cpp20))]
fn callback_boundaries_contain_allocation_failure() {
    // Only a structural reason may skip: a non-native target, a C library
    // without the `__libc_free` the driver's leak assertion forwards to, or a
    // C++ standard library whose allocation sizes the driver's trap does not
    // encode. A compile or link failure reports `failed:<reason>` and panics
    // here, so a driver that stops building cannot silently delete the only
    // coverage these boundaries have.
    let status = match option_env!("OVSTORAGE_C_SOURCE_CALLBACK_BOUNDARIES_STATUS") {
        Some(status) => status,
        None => panic!("build.rs must report a callback-boundary driver status"),
    };
    match status {
        "built" => {}
        "skipped" => {
            eprintln!("skipping: the callback-boundary driver needs a native build");
            return;
        }
        "unsupported-c-library" => {
            eprintln!(
                "skipping: the callback-boundary driver interposes `free` through \
                 glibc's `__libc_free`, which this target's C library does not provide"
            );
            return;
        }
        "unsupported-cxx-library" => {
            eprintln!(
                "skipping: the callback-boundary driver arms its allocation trap on \
                 libstdc++'s exact allocation sizes, and this toolchain builds against \
                 a different C++ standard library"
            );
            return;
        }
        other => panic!("the callback-boundary driver did not build: {other}"),
    }
    let Some(binary) = option_env!("OVSTORAGE_C_SOURCE_CALLBACK_BOUNDARIES_BIN") else {
        panic!("a built callback-boundary driver must report its path");
    };
    eprintln!("running {binary}");

    let mut child = std::process::Command::new(binary)
        .spawn()
        .unwrap_or_else(|error| panic!("failed to launch {binary}: {error}"));

    // The driver bounds each of its own waits at 30s and finishes in
    // milliseconds when they all resolve, so this ceiling only ever fires if
    // the driver itself is wedged.
    let timeout = std::time::Duration::from_secs(180);
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                assert!(
                    status.success(),
                    "the callback-boundary driver exited with failure: {status} \
                     (a boundary leaked its payload, resolved an allocation \
                      failure as a success, or let the exception escape into \
                      the C frame — the driver names which on stderr)"
                );
                return;
            }
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!(
                        "the callback-boundary driver hung for {}s — a boundary \
                         consumed its awaiter state without calling deliver(), so \
                         the awaiting coroutine is never resumed",
                        timeout.as_secs(),
                    );
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(error) => panic!("failed to poll the callback-boundary driver: {error}"),
        }
    }
}

/// Regression coverage: `sync_wait` must not let the completing thread touch
/// its mutex/condition_variable after the waiting thread has returned and
/// destroyed them. `wait(lk, pred)` checks the predicate before blocking, so
/// a result published in the window between entering `sync_wait` and reaching
/// `wait` lets the waiter return without ever blocking — and tear the
/// primitives down while the completing thread is still inside them.
///
/// Needs ThreadSanitizer: the offending access happens inside
/// `pthread_cond_broadcast`, which AddressSanitizer does not instrument. On a
/// host where TSan cannot run, the driver still catches a wrong outcome or a
/// hang and says so.
#[test]
#[cfg(all(unix, ovstorage_cpp20))]
fn cpp20_sync_wait_does_not_destroy_a_condvar_in_use() {
    let status = option_env!("OVSTORAGE_C_SOURCE_SYNC_WAIT_RACE_STATUS");
    match status {
        None => {
            eprintln!("skipping the sync_wait race regression: not built on this platform");
            return;
        }
        Some("built") => {}
        Some("built-without-tsan") => {
            eprintln!(
                "running the sync_wait race regression WITHOUT ThreadSanitizer: this \
                 host cannot run a TSan binary, so only a wrong outcome or a hang is \
                 caught, not the destruction race itself"
            );
        }
        Some("built-without-tsan-racy-coroutine-frames") => {
            eprintln!(
                "running the sync_wait race regression WITHOUT ThreadSanitizer: only a \
                 wrong outcome or a hang is caught here, not the destruction race \
                 itself. Not because TSan is missing — because this toolchain's \
                 coroutine frames are not race-free, so a TSan build would halt on the \
                 COMPILER's frame race and never reach the condvar race this test \
                 exists to pin. See `cpp20_toolchain_coroutine_frames_are_race_free`, \
                 which is where that defect is reported; build the C++ wrapper with \
                 GCC 13/14 or Clang 17+ to get this coverage back."
            );
        }
        Some("skipped") => {
            eprintln!("skipping the sync_wait race regression: needs a native build");
            return;
        }
        Some(other) => panic!("the sync_wait race regression did not build: {other}"),
    }
    let Some(binary) = option_env!("OVSTORAGE_C_SOURCE_SYNC_WAIT_RACE_BIN") else {
        panic!("a built sync_wait race regression must report its path");
    };

    let timeout = std::time::Duration::from_secs(300);
    let Some(run) = run_driver(binary, timeout) else {
        panic!(
            "the sync_wait race regression hung for {}s — a completion was \
             published without waking the waiter",
            timeout.as_secs(),
        );
    };
    // Report what was OBSERVED, then what it probably means — in that order,
    // and with the driver's own output attached.
    //
    // A toolchain whose coroutine frames race can produce a non-zero exit while
    // the driver's own check passes and prints `ok`: TSan halts on something
    // other than the condvar. A test may not assert a diagnosis it has not made.
    assert!(
        run.status.success(),
        "the sync_wait race regression exited with failure: {}\n{}\n\
         What that means depends on the output above.\n\
         * A ThreadSanitizer report naming the waiter's mutex or condition \
         variable, or a `pthread_cond_*` call: a completing thread used them \
         after the waiter destroyed them. That is the defect this test exists \
         to pin, and it is in `ovstorage.hpp`.\n\
         * A report naming a coroutine frame, or an address inside a frame's \
         heap block: read `cpp20_toolchain_coroutine_frames_are_race_free` \
         BEFORE suspecting `ovstorage.hpp`. A compiler that races its own \
         coroutine frames fails this test for a reason that has nothing to do \
         with `sync_wait`.\n\
         * A wrong-outcome line from the driver and no sanitizer report at all: \
         `sync_wait` returned the wrong value or no value.",
        run.status,
        run.transcript(),
    );
}

/// What a standalone driver did and what it printed.
#[cfg(all(unix, ovstorage_cpp20))]
struct DriverRun {
    status: std::process::ExitStatus,
    stdout: String,
    stderr: String,
}

#[cfg(all(unix, ovstorage_cpp20))]
impl DriverRun {
    /// The driver's own output, labelled and indented for a panic message.
    ///
    /// Both streams, because for these drivers the interesting failure is the
    /// disagreement BETWEEN them: the sync_wait driver prints its own `ok` to
    /// stdout while ThreadSanitizer writes a report to stderr and sets the exit
    /// code. Showing only one of the two is how "the test says the condvar was
    /// destroyed in use" and "the binary says it passed" end up in the same bug
    /// report without anyone noticing they cannot both be about the same thing.
    fn transcript(&self) -> String {
        let mut out = String::new();
        for (label, text) in [("stdout", &self.stdout), ("stderr", &self.stderr)] {
            let text = text.trim_end();
            if text.is_empty() {
                continue;
            }
            out.push_str(&format!("--- {label} ---\n"));
            for line in text.lines() {
                out.push_str(&format!("  {line}\n"));
            }
        }
        if out.is_empty() {
            out.push_str("(the driver printed nothing)\n");
        }
        out
    }

    /// Did the coroutine-frame probe report the race it exists to detect, or
    /// merely *a* race?
    ///
    /// TSan exits 1 for ANY report or runtime failure — a race inside
    /// libstdc++, a startup failure, a report the control loop provoked. Taking
    /// a bare 1 as the finding would print a confident, wrong diagnosis naming
    /// the compiler, which is the same mistake this probe exists to correct.
    /// So the report has to be identified from the output: the control loop
    /// printed its completion marker (whatever halted TSan came after it, so it
    /// is not the control's), and the report is a `data race` in the racy
    /// loop's coroutine on a two-byte access — the frame refcount's width.
    ///
    /// The markers belong to the driver; its `OUTPUT CONTRACT` comment
    /// (`tests/cc/coroutine_frame_refcount_race.cpp`) defines them, and
    /// `build_coroutine_frame_probe` in `build.rs` applies the same check to
    /// the build-time run. All three move together. Matching sanitizer output
    /// by literal follows `LEAK_PROBE_REPORT` below.
    fn reported_the_coroutine_frame_race(&self) -> bool {
        self.stdout.contains(CORO_PROBE_CONTROL_OK)
            && self.stderr.contains("data race")
            && self.stderr.contains("of size 2")
            && (self.stderr.contains(CORO_PROBE_RACY_FUNCTION)
                || self.stderr.contains(CORO_PROBE_RACY_FRAME_BLOCK))
    }
}

/// The line the probe prints once its control loop has finished.
#[cfg(all(unix, ovstorage_cpp20))]
const CORO_PROBE_CONTROL_OK: &str =
    "coroutine_frame_refcount_race: control (publish after the ramp) ok";

/// The coroutine ThreadSanitizer must name for the report to be the one the
/// probe exists to provoke. Used as the primary check; `CORO_PROBE_RACY_FRAME_BLOCK`
/// is the fallback for unsymbolized hosts where function names are not printed.
#[cfg(all(unix, ovstorage_cpp20))]
const CORO_PROBE_RACY_FUNCTION: &str = "publishes_during_the_ramp";

/// The heap-block location line TSan emits for the racing coroutine frame.
/// Unlike the function name above, this line survives an unsymbolized report
/// (no llvm-symbolizer/addr2line → `<null> (binary+0xNNNN)` instead of a name).
#[cfg(all(unix, ovstorage_cpp20))]
const CORO_PROBE_RACY_FRAME_BLOCK: &str = "Location is heap block";

/// The strings the two matchers look for must be strings the driver can still
/// produce.
///
/// Both are literals here and in `build.rs`, matched against what the probe
/// prints and what ThreadSanitizer symbolizes. Nothing in the C++ file can
/// reference them — a constant naming the coroutine would just be dead code,
/// which Clang rejects under the `-Wall -Werror` the probe is built with — so
/// a rename there would leave all three matchers quietly looking for a string
/// absent from the driver. Every run would then classify as "not the
/// coroutine-frame race", the toolchain verdict would fall to `unknown`, and
/// the defect would stop being detected while every test still passed.
///
/// Checking the source text is what closes that. It is a weaker link than a
/// symbol reference, but it is the strongest one available across a language
/// boundary, and it fails loudly at the moment of the rename.
#[test]
#[cfg(all(unix, ovstorage_cpp20))]
fn cpp20_coroutine_frame_probe_markers_match_the_driver() {
    const DRIVER: &str = include_str!("cc/coroutine_frame_refcount_race.cpp");

    assert!(
        DRIVER.contains(CORO_PROBE_CONTROL_OK),
        "the coroutine-frame probe does not contain the control marker its callers \
         match on: {CORO_PROBE_CONTROL_OK:?}. Update `CORO_PROBE_CONTROL_OK` here, \
         `probe_reported_its_own_race` in build.rs, and the driver's OUTPUT CONTRACT \
         comment together — until then neither the build-time verdict nor the test \
         can recognise the race the probe reports."
    );
    assert!(
        DRIVER.contains(&format!("fire_and_forget {CORO_PROBE_RACY_FUNCTION}(")),
        "the coroutine-frame probe does not define the coroutine its callers expect \
         ThreadSanitizer to name: {CORO_PROBE_RACY_FUNCTION:?}. It is the racy loop's \
         body, so if it was renamed, update `CORO_PROBE_RACY_FUNCTION` here and \
         `probe_reported_its_own_race` in build.rs to match — until then every report \
         is classified as 'not the coroutine-frame race' and the defect stops being \
         detected."
    );
}

/// Run a standalone driver under TSan's halt-on-first-report settings, bounded
/// by `timeout`, collecting both streams. `None` means it never exited and was
/// killed; the caller says what a hang means for its own driver.
///
/// Collecting rather than inheriting so the output can go INTO the failure
/// message. A sanitizer report that scrolls past in the harness log, detached
/// from the assertion that fired, is how a test's guess about a cause gets read
/// as the finding. Reading after exit follows the leak self-check above and is
/// safe for the same reason: under `halt_on_error=1` these drivers print one
/// report, kilobytes at most, far below the pipe buffer that would deadlock a
/// read-after-wait.
///
/// `abort_on_error=0` is load-bearing, not decoration. sanitizer_common
/// defaults it to 1 on Darwin, where a report then terminates the process with
/// `SIGABRT` — and `ExitStatus::code()` is `None` for a signalled child, so the
/// `exitcode=1` these callers read their verdict from never arrives. Without
/// this the coroutine-frame probe would report "terminated abnormally, no
/// finding" on macOS for what is in fact a clean detection.
#[cfg(all(unix, ovstorage_cpp20))]
fn run_driver(binary: &str, timeout: std::time::Duration) -> Option<DriverRun> {
    let mut child = std::process::Command::new(binary)
        .env(
            "TSAN_OPTIONS",
            "halt_on_error=1:exitcode=1:abort_on_error=0",
        )
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap_or_else(|error| panic!("failed to launch {binary}: {error}"));

    let deadline = std::time::Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    // Collect anyway: on a hang the partial output is the only
                    // evidence there is, and the caller's message is a guess
                    // without it.
                    if let Ok(output) = child.wait_with_output() {
                        eprint!(
                            "{}",
                            DriverRun {
                                status: output.status,
                                stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
                                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
                            }
                            .transcript()
                        );
                    }
                    return None;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(error) => panic!("failed to poll {binary}: {error}"),
        }
    }
    let output = child
        .wait_with_output()
        .unwrap_or_else(|error| panic!("failed to collect the output of {binary}: {error}"));
    let run = DriverRun {
        status: output.status,
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    };
    // Echo a PASSING run: piping the streams would otherwise make it quieter
    // under `--nocapture` than it was before they were collected. A failing
    // run needs no echo — every caller puts the transcript in its message.
    if run.status.success() {
        eprint!("{}", run.transcript());
    }
    Some(run)
}

/// The bounded re-run's observable outcome, before the build-time verdict or
/// local acknowledgement is considered.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CoroutineProbeRun {
    Hung,
    Completed {
        exit_code: Option<i32>,
        reported_known_race: bool,
    },
}

/// What the toolchain probe test must do with its build-time and re-run
/// evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CoroutineProbeDisposition {
    RaceFree,
    AcknowledgedUnsupportedToolchain,
    KnownRace,
    UnrelatedFailure,
    SelfCheckFailure,
    AbnormalTermination,
    Hung,
}

/// Classifies all probe evidence in one place so the acknowledgement can
/// soften only the diagnosed compiler race. A broken or inconclusive re-run
/// remains fatal even when the build-time run recorded the known race.
fn classify_coroutine_probe(
    recorded_racy: bool,
    rerun: CoroutineProbeRun,
    acknowledged: bool,
    require_tsan: bool,
) -> CoroutineProbeDisposition {
    let rerun_observed_race = match rerun {
        CoroutineProbeRun::Hung => return CoroutineProbeDisposition::Hung,
        CoroutineProbeRun::Completed {
            exit_code: Some(0), ..
        } => false,
        CoroutineProbeRun::Completed {
            exit_code: Some(1),
            reported_known_race: true,
        } => true,
        CoroutineProbeRun::Completed {
            exit_code: Some(1),
            reported_known_race: false,
        } => return CoroutineProbeDisposition::UnrelatedFailure,
        CoroutineProbeRun::Completed {
            exit_code: Some(2), ..
        } => return CoroutineProbeDisposition::SelfCheckFailure,
        CoroutineProbeRun::Completed { .. } => {
            return CoroutineProbeDisposition::AbnormalTermination;
        }
    };

    if !(recorded_racy || rerun_observed_race) {
        CoroutineProbeDisposition::RaceFree
    } else if acknowledgement_applies(acknowledged, require_tsan) {
        CoroutineProbeDisposition::AcknowledgedUnsupportedToolchain
    } else {
        CoroutineProbeDisposition::KnownRace
    }
}

/// What happened to `cpp20_sync_wait_does_not_destroy_a_condvar_in_use`'s
/// ThreadSanitizer coverage, from `OVSTORAGE_C_SOURCE_SYNC_WAIT_RACE_STATUS`.
///
/// `build.rs` decides that build on its own run of the probe, so both the
/// acknowledged report and the fatal failure text answer from the recorded
/// status instead of asserting the degraded case. When the build-time run did
/// not record the race (this test can still find it on its re-run), that
/// regression was built WITH ThreadSanitizer and will itself halt on this
/// compiler's frame race.
fn sync_wait_coverage_line(sync_wait_status: Option<&str>) -> String {
    match sync_wait_status {
        Some("built-without-tsan-racy-coroutine-frames") => {
            "degraded coverage: cpp20_sync_wait_does_not_destroy_a_condvar_in_use runs \
             without TSan on this host (build.rs degraded it after its own run of this \
             probe recorded the race)"
                .to_owned()
        }
        Some("built-without-tsan") => {
            "degraded coverage: cpp20_sync_wait_does_not_destroy_a_condvar_in_use runs \
             without TSan on this host (no usable ThreadSanitizer runtime)"
                .to_owned()
        }
        Some("built") => {
            "coverage: cpp20_sync_wait_does_not_destroy_a_condvar_in_use was built WITH \
             TSan because the build-time run of this probe did not record the race; \
             expect it to halt on this compiler's coroutine-frame race"
                .to_owned()
        }
        other => format!(
            "coverage: cpp20_sync_wait_does_not_destroy_a_condvar_in_use build status is {}",
            other.unwrap_or("unknown")
        ),
    }
}

/// Write a notice a passing test must still surface.
///
/// libtest captures `println!`/`eprintln!` from a passing test and discards
/// it unless `--nocapture` is given, so an acknowledged toolchain would pass
/// silently. A direct write to the `Stderr` handle bypasses that hook.
/// Gated like its only caller, the toolchain probe test.
#[cfg(all(unix, ovstorage_cpp20))]
fn report_to_stderr(message: &str) {
    use std::io::Write as _;
    let _ = writeln!(std::io::stderr(), "{message}");
}

fn acknowledged_unsupported_toolchain_report(
    compiler: &str,
    evidence: &str,
    sync_wait_status: Option<&str>,
) -> String {
    // The coverage line is shared with the unacknowledged fatal text, so the
    // clause that only makes sense under an acknowledgement is added here.
    let mut coverage = sync_wait_coverage_line(sync_wait_status);
    if sync_wait_status == Some("built") {
        coverage.push_str(", which this acknowledgement does not cover");
    }
    format!(
        "ACKNOWLEDGED UNSUPPORTED TOOLCHAIN\n  \
         compiler: {compiler}\n  \
         evidence: {evidence}\n  \
         upstream: GCC PR c++/127320 \
         (https://gcc.gnu.org/bugzilla/show_bug.cgi?id=127320)\n  \
         {coverage}\n  \
         retirement: drop {ACKNOWLEDGE_UNSUPPORTED_TOOLCHAIN_ENV}=1 when this test \
         passes without it"
    )
}

/// The evidence sentence for a run that reached the recorded-verdict path: the
/// race was observed by this run, by `build.rs`'s run, or both. Factual only;
/// what the outcome MEANS for the suite is the caller's sentence, because the
/// same evidence backs both the acknowledged pass and the fatal failure.
fn recorded_race_evidence(rerun: CoroutineProbeRun) -> String {
    match rerun {
        CoroutineProbeRun::Completed {
            reported_known_race: true,
            ..
        } => "The probe halted on a ThreadSanitizer data race in its racy loop.".to_owned(),
        CoroutineProbeRun::Completed {
            exit_code: Some(0), ..
        } => "This run of the probe exited cleanly. The build-time run of the SAME probe \
              did not: it reported the race, and `build.rs` has already degraded the \
              sync_wait regression on the strength of that. The interleaving is \
              scheduler-dependent, so one clean run does not retract it."
            .to_owned(),
        // The classifier has already ruled every other outcome fatal (2 is the
        // self-check, 1 without the marker is an unrelated report, a signal or
        // any other code is abnormal termination, a hang is fatal), so only 0
        // and 1-with-the-marker can reach the recorded-verdict path.
        other => unreachable!(
            "{other:?} reached the recorded-verdict path; classify_coroutine_probe \
             should have made it fatal"
        ),
    }
}

/// What `build.rs` recorded when it built and ran the probe.
#[derive(Clone, Copy, Debug)]
struct ProbeBuild<'a> {
    /// `OVSTORAGE_C_SOURCE_CORO_FRAME_PROBE_STATUS`: how far the probe got.
    status: Option<&'a str>,
    /// `OVSTORAGE_C_SOURCE_TOOLCHAIN_CORO_FRAMES`: the build-time verdict.
    verdict: Option<&'a str>,
    /// `OVSTORAGE_C_SOURCE_SYNC_WAIT_RACE_STATUS`: how sync_wait was built.
    sync_wait_status: Option<&'a str>,
}

impl ProbeBuild<'static> {
    /// The facts `build.rs` exported for this build, read in exactly one place
    /// so `probe_build_reads_the_variables_build_rs_exports` can pin which
    /// variable feeds which field: status and verdict are both short strings,
    /// and swapping them would silently change what the notice keys on.
    fn recorded() -> Self {
        ProbeBuild {
            status: option_env!("OVSTORAGE_C_SOURCE_CORO_FRAME_PROBE_STATUS"),
            verdict: option_env!("OVSTORAGE_C_SOURCE_TOOLCHAIN_CORO_FRAMES"),
            sync_wait_status: option_env!("OVSTORAGE_C_SOURCE_SYNC_WAIT_RACE_STATUS"),
        }
    }
}

/// Which notice, if any, the toolchain probe test must surface for a
/// non-fatal disposition. Pure over its inputs so the emission decision is
/// table-tested: an acknowledged toolchain must be LOUD, and a `RaceFree` run
/// with the switch set must say whether it could have seen the race at all.
fn toolchain_probe_notice(
    disposition: CoroutineProbeDisposition,
    acknowledged: bool,
    require_tsan: bool,
    build: ProbeBuild<'_>,
    compiler: &str,
    evidence: &str,
) -> Option<String> {
    match disposition {
        CoroutineProbeDisposition::AcknowledgedUnsupportedToolchain => Some(
            acknowledged_unsupported_toolchain_report(compiler, evidence, build.sync_wait_status),
        ),
        CoroutineProbeDisposition::RaceFree
            if acknowledgement_applies(acknowledged, require_tsan) =>
        {
            // `RaceFree` is the absence of an observation, not a finding. The
            // removal advice needs a POSITIVE one: a probe built WITH
            // ThreadSanitizer (status) whose build-time run actually concluded
            // race-free (verdict). `build.rs` exports the two separately and can
            // reach status `built` with verdict `unknown` after a run it refused
            // to conclude on; a host in that state, or one that cannot run a
            // TSan binary, must not be told to drop a switch it may need.
            if build.status == Some("built") && build.verdict == Some("race-free") {
                Some(format!(
                    "{ACKNOWLEDGE_UNSUPPORTED_TOOLCHAIN_ENV}=1 is unnecessary on this \
                     race-free compiler ({compiler}) and should be removed"
                ))
            } else {
                Some(format!(
                    "{ACKNOWLEDGE_UNSUPPORTED_TOOLCHAIN_ENV}=1 is set, but this run could \
                     not observe the coroutine-frame race (the probe was built without \
                     ThreadSanitizer, or build.rs's own run of it produced no verdict), \
                     so whether this compiler ({compiler}) needs the acknowledgement is \
                     NOT established here. Decide on evidence from a host that can run \
                     a TSan binary."
                ))
            }
        }
        _ => None,
    }
}

/// Toolchain coverage: this compiler must emit coroutine frames that can be
/// resumed from another thread without racing the frame's own bookkeeping.
///
/// This is NOT a test of ovstorage, and it is the only test here that is not.
/// Its driver includes no ovstorage header at all, so when it fails there is
/// nothing in this repository to go and read.
///
/// It exists because the failure it reports is otherwise unattributable. GCC 15
/// gives every coroutine frame a 16-bit `_Coro_frame_refcount` and decrements it
/// non-atomically from both the ramp and the actor, so any coroutine resumed by
/// the thread that completes it — which is every callback-driven awaiter,
/// including all of `ovstorage.hpp`'s — races two plain read-modify-writes on
/// the same two bytes. ThreadSanitizer reports that INSIDE the awaiting
/// coroutine, which reads exactly like a defect in the wrapper. Pinning it here,
/// with no ovstorage in the picture, makes the difference legible.
///
/// A local affected host can set
/// `OVSTORAGE_ACKNOWLEDGE_UNSUPPORTED_TOOLCHAIN=1` to acknowledge only this
/// diagnosed compiler race and let this test report that unsupported-toolchain
/// result without failing. A recorded race still decides when a valid re-run
/// happens not to reproduce it. Invalid probe outcomes remain fatal, and
/// `OVSTORAGE_REQUIRE_TSAN=1` disables the acknowledgement; `build.rs` rejects
/// setting both switches to `1`, and refuses the acknowledgement outright when
/// `GITHUB_ACTIONS` or `CI` is set, so no CI job can carry it.
#[test]
#[cfg(all(unix, ovstorage_cpp20))]
fn cpp20_toolchain_coroutine_frames_are_race_free() {
    match option_env!("OVSTORAGE_C_SOURCE_CORO_FRAME_PROBE_STATUS") {
        None => {
            eprintln!("skipping the coroutine-frame toolchain probe: not built on this platform");
            return;
        }
        Some("built") => {}
        Some("built-without-tsan") => {
            eprintln!(
                "running the coroutine-frame toolchain probe WITHOUT ThreadSanitizer: \
                 this host cannot run a TSan binary, so the probe can only catch a \
                 wrong resumption count or a hang. Whether this compiler's coroutine \
                 frames are race-free is NOT established by this run either way"
            );
        }
        Some("skipped") => {
            eprintln!("skipping the coroutine-frame toolchain probe: needs a native build");
            return;
        }
        Some(other) => panic!("the coroutine-frame toolchain probe did not build: {other}"),
    }
    let Some(binary) = option_env!("OVSTORAGE_C_SOURCE_CORO_FRAME_PROBE_BIN") else {
        panic!("a built coroutine-frame toolchain probe must report its path");
    };
    let compiler = option_env!("OVSTORAGE_C_SOURCE_CORO_FRAME_COMPILER").unwrap_or("unknown");
    // What `build.rs` saw when IT ran this probe. That observation is already
    // load-bearing: a `racy` verdict is what made it build the sync_wait
    // regression without ThreadSanitizer.
    let recorded = option_env!("OVSTORAGE_C_SOURCE_TOOLCHAIN_CORO_FRAMES").unwrap_or("unknown");

    let timeout = std::time::Duration::from_secs(300);
    let run = run_driver(binary, timeout);
    let rerun = match run.as_ref() {
        Some(run) => CoroutineProbeRun::Completed {
            exit_code: run.status.code(),
            reported_known_race: run.reported_the_coroutine_frame_race(),
        },
        None => CoroutineProbeRun::Hung,
    };
    let acknowledged = require_env(ACKNOWLEDGE_UNSUPPORTED_TOOLCHAIN_ENV);
    let require_tsan = require_env(REQUIRE_TSAN_ENV);
    let recorded_racy = recorded == "racy";
    let disposition = classify_coroutine_probe(recorded_racy, rerun, acknowledged, require_tsan);
    // When `build.rs`'s own run recorded the race, a broken re-run must not read
    // as a retraction: that verdict is retained and already degraded sync_wait.
    let retained_verdict = if recorded_racy {
        "\n  build.rs's own run of this probe DID record the race and degraded the \
         sync_wait regression on the strength of it; this re-run is inconclusive, \
         not a retraction."
    } else {
        ""
    };
    let Some(run) = run else {
        debug_assert_eq!(disposition, CoroutineProbeDisposition::Hung);
        panic!(
            "the coroutine-frame toolchain probe hung for {}s — its worker stopped \
             resuming the handles handed to it, which is neither a race-free nor a \
             racy verdict{retained_verdict}",
            timeout.as_secs(),
        );
    };
    // The recorded verdict decides, not this run.
    //
    // Believing only the re-run would be unsound in one direction. The
    // interleaving this probe needs is scheduler-dependent, so a racy toolchain
    // can exit 0 on any given run — and then this test would pass while
    // `cpp20_sync_wait_does_not_destroy_a_condvar_in_use` is STILL built
    // without ThreadSanitizer, on the strength of the build-time observation
    // this run just declined to repeat. Green suite, condvar coverage silently
    // off, nothing on screen connecting the two. A race observed once has been
    // observed; it does not un-happen on a retry.
    //
    // The re-run still earns its keep: it collects the transcript that makes
    // the failure readable, and it can fail a toolchain the build-time run
    // happened to clear.
    //
    // Only the exit codes the driver's contract defines mean anything. 0, 1 and
    // 2 are a verdict; a signal (`code()` is `None` on Unix when the child is
    // killed) or any other code means the probe did not work, which is not the
    // same fact as "the toolchain is affected" and must not be reported as one.
    // That is the same taxonomy `build_coroutine_frame_probe` uses for its
    // `Unknown`, and the two must not reach opposite verdicts from one run.
    let build = ProbeBuild::recorded();
    match disposition {
        // The two passing dispositions. Whether they say anything, and what,
        // is decided by `toolchain_probe_notice` so the decision is testable;
        // this arm only carries the notice to a place libtest cannot swallow.
        CoroutineProbeDisposition::RaceFree
        | CoroutineProbeDisposition::AcknowledgedUnsupportedToolchain => {
            let evidence =
                if disposition == CoroutineProbeDisposition::AcknowledgedUnsupportedToolchain {
                    recorded_race_evidence(rerun)
                } else {
                    String::new()
                };
            if let Some(notice) = toolchain_probe_notice(
                disposition,
                acknowledged,
                require_tsan,
                build,
                compiler,
                &evidence,
            ) {
                report_to_stderr(&notice);
            }
            return;
        }
        CoroutineProbeDisposition::KnownRace => {}
        CoroutineProbeDisposition::UnrelatedFailure => panic!(
            "the coroutine-frame toolchain probe exited 1, but what \
             ThreadSanitizer reported is not the coroutine-frame race, so this run \
             made NO finding about this compiler ({compiler}):\n{}\n\
             Expected the control loop's completion marker on stdout and a `data \
             race` of size 2 in `publishes_during_the_ramp` on stderr. Something \
             else was reported — an unrelated race, or a sanitizer runtime failure. \
             Nothing here says whether this toolchain's coroutine frames are \
             race-free.{retained_verdict}",
            run.transcript(),
        ),
        // 2 is the probe's own self-check, deliberately kept off 1 so a
        // broken probe can never be read as a toolchain verdict.
        CoroutineProbeDisposition::SelfCheckFailure => panic!(
            "the coroutine-frame toolchain probe failed its OWN self-check, so it \
             made no finding about this compiler ({compiler}):\n{}\n\
             Some of its coroutine bodies were never resumed. Fix the probe — this \
             says nothing about whether the toolchain is affected.{retained_verdict}",
            run.transcript(),
        ),
        CoroutineProbeDisposition::AbnormalTermination => panic!(
            "the coroutine-frame toolchain probe terminated abnormally ({:?}), so \
             it made NO finding about this compiler ({compiler}):\n{}\n\
             A signal or an undefined exit code is not a verdict. Nothing here says \
             whether this toolchain's coroutine frames are race-free.{retained_verdict}",
            run.status.code(),
            run.transcript(),
        ),
        CoroutineProbeDisposition::Hung => {
            unreachable!("a hung run is handled before a DriverRun is unwrapped")
        }
    }
    // KnownRace: the race was observed — by this run, by the build script's
    // run, or both. Say which, rather than describing a report that may not be
    // in the transcript above. The consequence sentence belongs only here: an
    // unacknowledged clean re-run passing while the sync_wait coverage stays
    // off is the failure this check exists to prevent, whereas the same
    // evidence under an acknowledgement is the recorded, accepted outcome.
    let evidence = recorded_race_evidence(rerun);
    let clean_rerun_note = match rerun {
        CoroutineProbeRun::Completed {
            exit_code: Some(0),
            reported_known_race: false,
        } => {
            " Passing here while that coverage stays off is the failure this check \
              exists to prevent."
        }
        _ => "",
    };
    let sync_wait_coverage = sync_wait_coverage_line(build.sync_wait_status);
    panic!(
        "this compiler ({compiler}) does not emit race-free coroutine frames.\n\n\
             \x20 WHAT THE PROBE OBSERVED\n{}\n  \
             {evidence}{clean_rerun_note}\n\n  \
             Its first loop publishes after the ramp has returned — that control \
             runs clean, ruling out \"resuming a coroutine on another thread is \
             inherently racy\" as the explanation. Its second loop hands the SAME \
             handle to the SAME worker through the SAME release/acquire pair, \
             differing only in that it publishes from inside `await_suspend`; \
             ThreadSanitizer halts on a 2-byte data race in the coroutine's own \
             frame.\n\n\
             \x20 WHAT IT IS\n  \
             The compiler gives each coroutine frame a 16-bit \
             `_Coro_frame_refcount` and manipulates it NON-ATOMICALLY from both \
             halves of the coroutine: the ramp decrements it after the actor \
             returns, while the resuming thread decrements it at final suspend. \
             Two threads, one plain read-modify-write, no synchronization between \
             them.\n\n  \
             This is a defect in the COMPILER, not in `ovstorage.hpp`. The probe \
             includes no ovstorage header. Coroutine code that can resume on \
             another thread before its ramp returns is affected, whoever wrote \
             it.\n\n\
             \x20 UPSTREAM\n  \
             Reported as GCC PR c++/127320 \
             (https://gcc.gnu.org/bugzilla/show_bug.cgi?id=127320). Check it for \
             the fixing release before moving the CI pin.\n\n\
             \x20 CONSEQUENCE\n  \
             Beyond the formal undefined behaviour: when the two decrements are \
             lost against each other the refcount never reaches zero and nobody \
             frees the frame, so affected coroutines LEAK their frames; when both \
             sides re-read zero they both free it, a double free (seen at -O0).\n\n\
             \x20 WORKAROUND\n  \
             Build the C++ wrapper with GCC 13/14 or Clang 17+.\n  \
             {sync_wait_coverage}\n  \
             On a local affected host, set \
             {ACKNOWLEDGE_UNSUPPORTED_TOOLCHAIN_ENV}=1 to acknowledge ONLY this \
             diagnosed compiler race. The acknowledgement is refused in CI and \
             when {REQUIRE_TSAN_ENV}=1.",
        run.transcript(),
    );
}

const ACKNOWLEDGE_UNSUPPORTED_TOOLCHAIN_ENV: &str = "OVSTORAGE_ACKNOWLEDGE_UNSUPPORTED_TOOLCHAIN";
/// Same spelling as `REQUIRE_TSAN_ENV` in `build.rs`, which owns the
/// build-time contradiction gate; both switches are read through `require_env`.
/// Gated like its only reader, the toolchain probe test, so the Windows build
/// (where that test is compiled out) does not see a dead constant.
#[cfg(all(unix, ovstorage_cpp20))]
const REQUIRE_TSAN_ENV: &str = "OVSTORAGE_REQUIRE_TSAN";

fn acknowledgement_applies(acknowledged: bool, require_tsan: bool) -> bool {
    acknowledged && !require_tsan
}

#[test]
fn unsupported_toolchain_acknowledgement_classifier_table() {
    use CoroutineProbeDisposition as Disposition;
    use CoroutineProbeRun as Run;

    let cases = [
        (
            "a recorded race remains acknowledged when the rerun is clean",
            true,
            Run::Completed {
                exit_code: Some(0),
                reported_known_race: false,
            },
            true,
            false,
            Disposition::AcknowledgedUnsupportedToolchain,
        ),
        (
            "the rerun's own race report can be acknowledged",
            false,
            Run::Completed {
                exit_code: Some(1),
                reported_known_race: true,
            },
            true,
            false,
            Disposition::AcknowledgedUnsupportedToolchain,
        ),
        (
            "a recorded and rerun race can be acknowledged",
            true,
            Run::Completed {
                exit_code: Some(1),
                reported_known_race: true,
            },
            true,
            false,
            Disposition::AcknowledgedUnsupportedToolchain,
        ),
        (
            "an unrelated exit one stays fatal after a recorded race",
            true,
            Run::Completed {
                exit_code: Some(1),
                reported_known_race: false,
            },
            true,
            false,
            Disposition::UnrelatedFailure,
        ),
        (
            "the probe self-check stays fatal after a recorded race",
            true,
            Run::Completed {
                exit_code: Some(2),
                reported_known_race: false,
            },
            true,
            false,
            Disposition::SelfCheckFailure,
        ),
        (
            "abnormal termination stays fatal after a recorded race",
            true,
            Run::Completed {
                exit_code: None,
                reported_known_race: false,
            },
            true,
            false,
            Disposition::AbnormalTermination,
        ),
        (
            "a hang stays fatal after a recorded race",
            true,
            Run::Hung,
            true,
            false,
            Disposition::Hung,
        ),
        (
            "required TSan refuses the acknowledgement",
            true,
            Run::Completed {
                exit_code: Some(0),
                reported_known_race: false,
            },
            true,
            true,
            Disposition::KnownRace,
        ),
        (
            "a known race without acknowledgement fails",
            false,
            Run::Completed {
                exit_code: Some(1),
                reported_known_race: true,
            },
            false,
            false,
            Disposition::KnownRace,
        ),
        (
            "a recorded race without acknowledgement fails even when the rerun is clean",
            true,
            Run::Completed {
                exit_code: Some(0),
                reported_known_race: false,
            },
            false,
            false,
            Disposition::KnownRace,
        ),
        (
            "a clean toolchain passes even when acknowledgement is set",
            false,
            Run::Completed {
                exit_code: Some(0),
                reported_known_race: false,
            },
            true,
            false,
            Disposition::RaceFree,
        ),
    ];

    for (name, recorded_racy, rerun, acknowledgement, require_tsan, expected) in cases {
        assert_eq!(
            classify_coroutine_probe(recorded_racy, rerun, acknowledgement, require_tsan),
            expected,
            "{name}"
        );
    }
}

/// The acknowledged report and the notices must survive libtest's capture of a
/// passing test's output, which is the one property `report_to_stderr` exists
/// for. The pure notice tables cannot see how a string is emitted, so this
/// re-runs the probe test as a child of this same binary, WITHOUT
/// `--nocapture`, with the switch set and required TSan cleared, and reads
/// what reached the child's stderr. Replacing `report_to_stderr`'s body with
/// `eprintln!` fails this test and nothing else.
#[test]
#[cfg(all(unix, ovstorage_cpp20))]
fn an_acknowledged_probe_run_reaches_stderr_under_libtest_capture() {
    if !matches!(
        option_env!("OVSTORAGE_C_SOURCE_CORO_FRAME_PROBE_STATUS"),
        Some("built") | Some("built-without-tsan")
    ) {
        eprintln!("skipping: the probe test itself skips on this build, so it emits nothing");
        return;
    }
    let exe = std::env::current_exe().expect("the test binary knows its own path");
    let output = std::process::Command::new(exe)
        .args(["cpp20_toolchain_coroutine_frames_are_race_free", "--exact"])
        .env(ACKNOWLEDGE_UNSUPPORTED_TOOLCHAIN_ENV, "1")
        .env_remove(REQUIRE_TSAN_ENV)
        .output()
        .expect("re-exec the test binary");
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() {
        // A fatal disposition in the child (for example this host's TSan
        // runtime aborting) panics loudly on its own; that path is not what
        // this test pins, and there is no passing run to assert about.
        eprintln!("the child probe run did not pass, so emission is not asserted:\n{stderr}");
        return;
    }
    let markers = [
        "ACKNOWLEDGED UNSUPPORTED TOOLCHAIN",
        "is unnecessary on this race-free compiler",
        "is NOT established here",
    ];
    assert!(
        markers.iter().any(|marker| stderr.contains(marker)),
        "a passing acknowledged run printed no notice to stderr, so libtest swallowed it:\n{stderr}"
    );
}

/// Pins the wiring the notice table cannot see: which exported variable
/// reaches which `ProbeBuild` field. On a Linux build the status and verdict
/// vocabularies never coincide (`built`/`built-without-tsan` versus
/// `race-free`/`racy`/`unknown`), so swapping the two initialisers fails here.
#[test]
fn probe_build_reads_the_variables_build_rs_exports() {
    let build = ProbeBuild::recorded();
    assert_eq!(
        build.status,
        option_env!("OVSTORAGE_C_SOURCE_CORO_FRAME_PROBE_STATUS")
    );
    assert_eq!(
        build.verdict,
        option_env!("OVSTORAGE_C_SOURCE_TOOLCHAIN_CORO_FRAMES")
    );
    assert_eq!(
        build.sync_wait_status,
        option_env!("OVSTORAGE_C_SOURCE_SYNC_WAIT_RACE_STATUS")
    );
}

#[test]
fn toolchain_probe_notice_table() {
    use CoroutineProbeDisposition as Disposition;
    // (name, disposition, acknowledged, require_tsan, probe status,
    //  build-time verdict, expected fragment or None)
    let cases = [
        (
            "an acknowledged toolchain is loud",
            Disposition::AcknowledgedUnsupportedToolchain,
            true,
            false,
            Some("built"),
            Some("racy"),
            Some("ACKNOWLEDGED UNSUPPORTED TOOLCHAIN"),
        ),
        (
            "a TSan-built clean run with a race-free verdict says the switch is unnecessary",
            Disposition::RaceFree,
            true,
            false,
            Some("built"),
            Some("race-free"),
            Some("is unnecessary on this race-free compiler"),
        ),
        (
            "a TSan-built run whose build-time verdict is unknown settles nothing",
            Disposition::RaceFree,
            true,
            false,
            Some("built"),
            Some("unknown"),
            Some("is NOT established here"),
        ),
        (
            "a clean run that could not see the race settles nothing",
            Disposition::RaceFree,
            true,
            false,
            Some("built-without-tsan"),
            Some("unknown"),
            Some("is NOT established here"),
        ),
        (
            "an unknown probe status is treated as unable to see the race",
            Disposition::RaceFree,
            true,
            false,
            None,
            None,
            Some("is NOT established here"),
        ),
        (
            "a clean run without the switch is silent",
            Disposition::RaceFree,
            false,
            false,
            Some("built"),
            Some("race-free"),
            None,
        ),
        (
            "required TSan silences the switch's advice as well",
            Disposition::RaceFree,
            true,
            true,
            Some("built"),
            Some("race-free"),
            None,
        ),
        (
            "a known race has no notice; it panics instead",
            Disposition::KnownRace,
            false,
            false,
            Some("built"),
            Some("racy"),
            None,
        ),
        (
            "a fatal outcome has no notice; it panics instead",
            Disposition::SelfCheckFailure,
            true,
            false,
            Some("built"),
            Some("racy"),
            None,
        ),
    ];
    for (name, disposition, acknowledged, require_tsan, status, verdict, expected) in cases {
        let build = ProbeBuild {
            status,
            verdict,
            sync_wait_status: Some("built-without-tsan-racy-coroutine-frames"),
        };
        let notice = toolchain_probe_notice(
            disposition,
            acknowledged,
            require_tsan,
            build,
            "g++ (GCC) 15.3.0",
            "evidence",
        );
        match expected {
            Some(fragment) => {
                let notice = notice.unwrap_or_else(|| panic!("{name}: expected a notice"));
                assert!(notice.contains(fragment), "{name}: {notice}");
            }
            None => assert_eq!(notice, None, "{name}"),
        }
    }
}

#[test]
fn unsupported_toolchain_acknowledgement_emits_the_result() {
    let disposition = classify_coroutine_probe(
        false,
        CoroutineProbeRun::Completed {
            exit_code: Some(1),
            reported_known_race: true,
        },
        true,
        false,
    );
    assert_eq!(
        disposition,
        CoroutineProbeDisposition::AcknowledgedUnsupportedToolchain
    );

    // The ordinary affected-host shape: build.rs recorded the race, this
    // re-run happened to be clean, the switch is set. The report must carry
    // the retained verdict without calling its own passing outcome a failure.
    let clean_rerun = CoroutineProbeRun::Completed {
        exit_code: Some(0),
        reported_known_race: false,
    };
    let recorded = classify_coroutine_probe(true, clean_rerun, true, false);
    let report = toolchain_probe_notice(
        recorded,
        true,
        false,
        ProbeBuild {
            status: Some("built-without-tsan"),
            verdict: Some("racy"),
            sync_wait_status: Some("built-without-tsan-racy-coroutine-frames"),
        },
        "g++ (Ubuntu 15.2.0) 15.2.0",
        &recorded_race_evidence(clean_rerun),
    )
    .expect("an acknowledged toolchain must report");
    assert!(report.starts_with("ACKNOWLEDGED UNSUPPORTED TOOLCHAIN\n"));
    assert!(report.contains("one clean run does not retract it"));
    assert!(!report.contains("the failure this check exists to prevent"));

    let degraded = acknowledged_unsupported_toolchain_report(
        "g++ (Ubuntu 15.2.0) 15.2.0",
        "the standalone probe reported the known race",
        Some("built-without-tsan-racy-coroutine-frames"),
    );
    assert!(degraded.starts_with("ACKNOWLEDGED UNSUPPORTED TOOLCHAIN\n"));
    assert!(degraded.contains("compiler: g++ (Ubuntu 15.2.0) 15.2.0"));
    assert!(degraded.contains("degraded coverage:"));
    assert!(degraded.contains("GCC PR c++/127320"));
    assert!(degraded.contains(ACKNOWLEDGE_UNSUPPORTED_TOOLCHAIN_ENV));

    // The disposition above is the rerun-only race: `build.rs` saw no race, so
    // the sync_wait regression was built WITH TSan. The report must say so
    // rather than claim degraded coverage.
    let with_tsan = acknowledged_unsupported_toolchain_report(
        "g++ (GCC) 15.3.0",
        "the re-run reported the known race",
        Some("built"),
    );
    assert!(!with_tsan.contains("degraded coverage:"));
    assert!(with_tsan.contains("built WITH TSan"));

    let no_runtime = acknowledged_unsupported_toolchain_report(
        "g++ (GCC) 15.3.0",
        "the build-time run recorded the known race",
        Some("built-without-tsan"),
    );
    assert!(no_runtime.contains("degraded coverage:"));
    assert!(no_runtime.contains("no usable ThreadSanitizer runtime"));
}

/// An `OVSTORAGE_REQUIRE_*` switch is on only when set to exactly `1`.
///
/// Presence alone would make `...=0` turn the requirement ON, which is the
/// opposite of what anyone typing it means. `1` is the spelling the Makefile,
/// the workflows and the Python gates all use.
fn require_env(name: &str) -> bool {
    std::env::var(name).as_deref() == Ok("1")
}

/// Exit code the self-check demands from a working LeakSanitizer.
///
/// Any value ASan will exit with does; 23 is simply outside the range the
/// probe program can produce itself (it returns 0 or calls `abort`), and it
/// matches the pure-C examples gate's constant so the two probes read alike.
#[cfg(unix)]
const LEAK_PROBE_EXIT: i32 = 23;

/// The stderr a leak report contains, and an unrelated fatal does not.
///
/// Matching `LeakSanitizer` alone is too weak: 23 is also ASan's generic
/// `common_flags()->exitcode`, which any post-parse fatal uses — including
/// `detect_leaks is not supported on this platform`, whose text does not
/// contain this phrase. Requiring the report headline means only an actual
/// leak report reads as success.
#[cfg(unix)]
const LEAK_PROBE_REPORT: &str = "detected memory leaks";

/// A hung probe is a broken sanitizer, not a slow one.
///
/// The probe leaks 64 KiB and exits; on a working runtime it finishes in
/// milliseconds. A sanitizer that wedges during initialisation would otherwise
/// block the collecting read forever, outside the abandon regression's own
/// 120 s bound, and never reach the strict failure this probe exists to
/// trigger.
#[cfg(unix)]
const LEAK_PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Whether this machine's LeakSanitizer reports a leak it is handed.
///
/// Runs the probe `build.rs` compiled, every time, because this is a question
/// about the current host and not about the build that produced the binary.
/// An absent, unlaunchable, hung or silent probe all mean the same thing here
/// — detection cannot be demonstrated — and the caller decides how loudly to
/// treat that.
#[cfg(unix)]
fn leak_detection_works() -> bool {
    let Some(probe) = option_env!("OVSTORAGE_C_SOURCE_ABANDON_REPRO_LEAK_PROBE") else {
        return false;
    };
    let Ok(mut child) = std::process::Command::new(probe)
        .env(
            "ASAN_OPTIONS",
            format!("detect_leaks=1:exitcode={LEAK_PROBE_EXIT}"),
        )
        // Consulted after ASAN_OPTIONS for leak settings, so a stale
        // `detect_leaks=0` here would silently answer "LSan is broken" on a
        // host where it works.
        .env("LSAN_OPTIONS", "")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
    else {
        return false;
    };

    let deadline = std::time::Instant::now() + LEAK_PROBE_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if std::time::Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                eprintln!(
                    "the LeakSanitizer self-check hung for {}s and was killed: its \
                     runtime wedged rather than reporting, so leak detection is \
                     treated as unproven",
                    LEAK_PROBE_TIMEOUT.as_secs()
                );
                return false;
            }
            Ok(None) => std::thread::sleep(std::time::Duration::from_millis(20)),
            Err(_) => return false,
        }
    }
    let Ok(output) = child.wait_with_output() else {
        return false;
    };
    output.status.code() == Some(LEAK_PROBE_EXIT)
        && String::from_utf8_lossy(&output.stderr).contains(LEAK_PROBE_REPORT)
}

/// A Stack build blocked in a Layer that ignores its cancellation token must
/// still be abandonable: cancelling fires `on_complete` with `Cancelled`
/// promptly, and the Layer's late completion afterwards corrupts nothing.
///
/// Runs as a separate process under a timeout because the regression's failure
/// mode is a hang, and under AddressSanitizer where the toolchain supports it
/// because the completion state behind the abandoned slot is reference-counted
/// across the build thread and the plugin callback.
#[test]
#[cfg(unix)]
fn parked_build_is_abandonable_when_the_layer_ignores_its_token() {
    // Only a non-native target may skip. A compile or link failure reports
    // `failed:<reason>` and fails here, so a broken fixture cannot silently
    // delete the only coverage this regression has.
    let status = match option_env!("OVSTORAGE_C_SOURCE_ABANDON_REPRO_STATUS") {
        Some(status) => status,
        None => panic!("build.rs must report a build-abandon regression status"),
    };
    // `require_sanitizers` gates every degradation, including this one. A
    // non-native build deletes the whole regression rather than half of it, so
    // leaving it ungated would make the most severe outcome the only silent
    // one.
    let require_sanitizers = require_env("OVSTORAGE_REQUIRE_SANITIZERS");
    match status {
        "built" => {}
        "skipped" => {
            let notice = "skipping: the build-abandon regression needs a native build";
            assert!(!require_sanitizers, "{notice}");
            eprintln!("{notice}");
            return;
        }
        other => panic!("the build-abandon regression did not build: {other}"),
    }
    let (Some(binary), Some(fixture), Some(asan)) = (
        option_env!("OVSTORAGE_C_SOURCE_ABANDON_REPRO_BIN"),
        option_env!("OVSTORAGE_C_SOURCE_ABANDON_REPRO_FIXTURE"),
        option_env!("OVSTORAGE_C_SOURCE_ABANDON_REPRO_ASAN"),
    ) else {
        panic!("a built build-abandon regression must report its paths");
    };

    // Whether the ASan runtime LINKS is settled at build time (`asan`);
    // whether its leak half REPORTS is a property of the machine this test
    // runs on, so it is re-probed every run rather than baked into
    // `rustc-env`. `OUT_DIR` outlives a local toolchain change, and a test
    // binary can be executed on a machine other than the one that built it —
    // either way a recorded verdict would answer for a host it never saw, and
    // the test would certify leak-cleanliness while observing nothing.
    assert!(
        asan == "1" || asan == "0",
        "unknown build-abandon AddressSanitizer status: {asan}"
    );
    let leak_detection = asan == "1" && leak_detection_works();

    // A degraded sanitizer still catches a wrong outcome, a hang, and (with
    // plain ASan) the use-after-free — so the run proceeds and says what it is
    // no longer observing, rather than skipping and covering nothing. CI sets
    // `OVSTORAGE_REQUIRE_SANITIZERS` on a runner that must have the full
    // article, which turns each degradation into a failure.
    let sanitizer = if asan != "1" {
        let notice = "running the build-abandon regression WITHOUT AddressSanitizer: \
                      this toolchain cannot link or run an -fsanitize=address \
                      binary, so neither the use-after-free nor the leak half of \
                      the assertion is observed — only a wrong outcome or a hang.";
        assert!(!require_sanitizers, "{notice}");
        eprintln!("{notice}");
        "address-sanitizer-unavailable"
    } else if !leak_detection {
        let notice = "running the build-abandon regression WITHOUT leak detection: \
                      AddressSanitizer links here, but the self-check handed its \
                      LeakSanitizer a batch of deliberately leaked blocks and got no \
                      report, so only the use-after-free half of the assertion is \
                      observed. Raise LEAK_BLOCKS in build.rs before concluding the \
                      toolchain is at fault: a lone stale root can pin a small leak, \
                      and this probe has been miscalibrated that way before.";
        assert!(!require_sanitizers, "{notice}");
        eprintln!("{notice}");
        "leak-detection-unproven"
    } else {
        "leak-checked"
    };
    eprintln!("running {binary} {fixture} (sanitizer: {sanitizer})");

    // `detect_leaks=1` is stated only where the probe just demonstrated that
    // LeakSanitizer reports, and is OMITTED otherwise.
    //
    // Asking for it unconditionally is not harmless. Where ASan links but
    // LeakSanitizer cannot exist for the host or arch (compiler-rt's
    // `CAN_SANITIZE_LEAKS == 0` — 32-bit Linux, some Darwin arm64 toolchains),
    // an EXPLICIT `detect_leaks=1` is fatal during flag initialisation: the
    // runtime reports `detect_leaks is not supported on this platform` and
    // `Die()`s before `main`. The child would exit non-zero having run
    // nothing, and the assertion below would blame "a wrong outcome, or a
    // use-after-free / leak" — contradicting the `leak-detection-unproven`
    // branch above, which promises the run still gets the use-after-free half.
    //
    // Where it IS stated it remains defence in depth rather than a fix for a
    // missing check: Linux ASan already defaults leak detection on, and the
    // leak half of the assertion fires without it. Saying so keeps the gate
    // from silently depending on that default staying put.
    let asan_options = if leak_detection {
        "detect_leaks=1:abort_on_error=1:halt_on_error=1:exitcode=1"
    } else {
        "abort_on_error=1:halt_on_error=1:exitcode=1"
    };

    let mut child = std::process::Command::new(binary)
        .arg(fixture)
        // Make any ASan finding a hard, non-zero-exit failure rather than a
        // best-effort warning.
        .env("ASAN_OPTIONS", asan_options)
        // Consulted AFTER `ASAN_OPTIONS` for leak settings, so a stale
        // `detect_leaks=0` in a developer's environment would otherwise switch
        // leak detection back off. Clearing it never asks for leak detection,
        // so it is safe on a platform that cannot provide it.
        .env("LSAN_OPTIONS", "")
        .spawn()
        .unwrap_or_else(|error| panic!("failed to launch {binary}: {error}"));

    // The program finishes in seconds even under ASan; a generous ceiling
    // keeps slow CI from flaking while still bounding a real hang.
    let timeout = std::time::Duration::from_secs(120);
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                assert!(
                    status.success(),
                    "the build-abandon regression exited with failure: {status} \
                     (a wrong outcome, or a use-after-free / leak in the abandoned \
                      build slot)"
                );
                return;
            }
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!(
                        "the build-abandon regression hung for {}s — a cancelled build \
                         stayed parked in a Layer that ignores its token instead of \
                         firing Cancelled",
                        timeout.as_secs(),
                    );
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(error) => panic!("failed to poll the build-abandon regression: {error}"),
        }
    }
}

/// Locate a workspace test-plugin cdylib next to this test binary's target
/// profile dir, building it on demand (`cargo build --lib`) if the artifact is
/// missing — `cargo test -p ovstorage-c-source-cc-test` does not build the
/// workspace's plugin cdylibs. Returns `None` (a skip) when still absent and
/// `require` is false; panics when `require` is set.
///
/// Naming follows each target's cdylib convention: `lib*.so` / `lib*.dylib` on
/// Unix, bare `*.dll` on Windows (MSVC does not prefix `lib`).
fn locate_test_plugin_so(package: &str, stem: &str, require: bool) -> Option<std::path::PathBuf> {
    let filename = if cfg!(target_os = "macos") {
        format!("lib{stem}.dylib")
    } else if cfg!(windows) {
        format!("{stem}.dll")
    } else {
        format!("lib{stem}.so")
    };
    let Some(profile_dir) = std::env::current_exe()
        .ok()
        .and_then(|exe| Some(exe.parent()?.parent()?.to_path_buf()))
    else {
        assert!(!require, "cannot resolve the target profile dir");
        eprintln!("skipping: cannot resolve the target profile dir");
        return None;
    };
    let path = profile_dir.join(&filename);
    if path.exists() {
        return Some(path);
    }
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut cmd = std::process::Command::new(&cargo);
    cmd.args(["build", "--lib", "--quiet", "--package", package]);
    if !cfg!(debug_assertions) {
        cmd.arg("--release");
    }
    match cmd.status() {
        Ok(status) if status.success() && path.exists() => Some(path),
        other => {
            assert!(
                !require,
                "test plugin `{package}` unavailable at {} (cargo build result: {other:?}) but \
                 OVSTORAGE_REQUIRE_TEST_PLUGINS is set",
                path.display(),
            );
            eprintln!(
                "skipping: test plugin `{package}` not built at {} (cargo build result: {other:?})",
                path.display()
            );
            None
        }
    }
}

#[test]
fn inspect_plugin_returns_descriptors_and_pins_mapping() {
    ensure_runtime_contracts();
    let fixture = CString::new(env!("OVSTORAGE_C_SOURCE_INSPECT_FIXTURE"))
        .expect("the generated inspect fixture path has no interior NUL");
    // SAFETY: the path remains live for the call. The C test copies and checks
    // descriptors, then destroys the list. Per ovstorage-c-source/README.md's
    // Header inventory and the frozen ovstorage.h warning, the mapping itself
    // remains pinned for process lifetime; no unload assertion is attempted.
    let status = unsafe { ovstorage_c_source_inspect_contract(fixture.as_ptr()) };
    assert_eq!(status, 0, "plugin inspection did not return its descriptor");
}
