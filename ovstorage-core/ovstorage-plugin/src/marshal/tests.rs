// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

/// Every `ErrorCode` round-trips Rust → ffi → Rust losslessly. This
/// is the contract the host's vtable thunks rely on, so an
/// accidental enum-variant skew shows up immediately as a failed
/// equality.
#[test]
fn every_error_code_round_trips() {
    for code in ErrorCode::KNOWN {
        let ffi_code = error::code_to_ffi(*code);
        let back = error::code_from_ffi(ffi_code);
        assert_eq!(*code, back, "{code:?} did not round-trip");
    }
}

#[test]
fn error_round_trip_preserves_code_and_message() {
    let original = Error::new(
        ErrorCode::ObjectModified,
        "etag mismatch on s3://bucket/key",
    );
    let ffi_value = error::to_ffi(&original);
    // SAFETY: `to_ffi` returned a valid FFI Error with an owned
    // message buffer.
    let back = unsafe { error::from_ffi(ffi_value) };
    assert_eq!(original, back);
}

#[test]
fn error_round_trip_handles_empty_message() {
    let original = Error::new(ErrorCode::Cancelled, "");
    let ffi_value = error::to_ffi(&original);
    assert_eq!(ffi_value.message_len, 0);
    assert!(!ffi_value.message_ptr.is_null());
    let back = unsafe { error::from_ffi(ffi_value) };
    assert_eq!(original, back);
}

#[test]
fn error_round_trip_handles_non_ascii_message() {
    let original = Error::new(
        ErrorCode::Internal,
        "❌ object key contained \u{2028} U+2028 line separator",
    );
    let ffi_value = error::to_ffi(&original);
    let back = unsafe { error::from_ffi(ffi_value) };
    assert_eq!(original, back);
}

/// An error without `with_context` round-trips with a NULL context
/// pointer on the FFI side and `None` context on the Rust side.
#[test]
fn error_round_trip_without_context_uses_null_pointer() {
    let original = Error::new(ErrorCode::NotFound, "missing");
    let ffi_value = error::to_ffi(&original);
    assert!(ffi_value.context.is_null());
    let back = unsafe { error::from_ffi(ffi_value) };
    assert_eq!(original, back);
    assert!(back.context().is_none());
}

/// `ObjectModified` carries an `Identity` context whose `new_etag`
/// survives FFI round-trip when populated.
#[test]
fn error_identity_context_round_trips_full_identity() {
    let original = Error::new(ErrorCode::ObjectModified, "etag changed").with_context(
        ErrorContext::Identity {
            new_etag: Some("abc123".to_string()),
        },
    );
    let ffi_value = error::to_ffi(&original);
    assert!(!ffi_value.context.is_null());
    let back = unsafe { error::from_ffi(ffi_value) };
    assert_eq!(original, back);
}

/// `Identity` context with `new_etag` set to `None` round-trips —
/// the marshaller must not silently elide the context.
#[test]
fn error_identity_context_round_trips_empty_identity() {
    let original = Error::new(ErrorCode::ObjectModified, "no metadata returned")
        .with_context(ErrorContext::Identity { new_etag: None });
    let ffi_value = error::to_ffi(&original);
    assert!(!ffi_value.context.is_null());
    let back = unsafe { error::from_ffi(ffi_value) };
    assert_eq!(original, back);
    assert!(matches!(
        back.context(),
        Some(ErrorContext::Identity { new_etag: None })
    ));
}

/// `AuthRequired` with a connection id and a reason round-trips.
#[test]
fn error_auth_context_round_trips_required_with_reason() {
    let original = Error::new(ErrorCode::AuthRequired, "interactive auth needed").with_context(
        ErrorContext::Auth {
            connection_id: ConnectionId("conn-abc-123".to_string()),
            reason: Some("refresh token absent".to_string()),
            expired_at: None,
        },
    );
    let ffi_value = error::to_ffi(&original);
    let back = unsafe { error::from_ffi(ffi_value) };
    assert_eq!(original, back);
}

/// `AuthCancelled` with an unset `reason` and unset `expired_at`
/// round-trips — both `Optional`s preserve their `None` value.
#[test]
fn error_auth_context_round_trips_cancelled_minimal() {
    let original = Error::new(ErrorCode::AuthCancelled, "cancelled by deadline").with_context(
        ErrorContext::Auth {
            connection_id: ConnectionId("conn-xyz".to_string()),
            reason: None,
            expired_at: None,
        },
    );
    let ffi_value = error::to_ffi(&original);
    let back = unsafe { error::from_ffi(ffi_value) };
    assert_eq!(original, back);
}

/// `AuthExpired` carries an `expired_at` timestamp; verify the
/// Unix-ms FFI clock contract preserves it across the boundary.
#[test]
fn error_auth_context_round_trips_expired_with_timestamp() {
    let expired_at = SystemTime::UNIX_EPOCH + Duration::from_millis(1_650_000_000_000);
    let original =
        Error::new(ErrorCode::AuthExpired, "token expired").with_context(ErrorContext::Auth {
            connection_id: ConnectionId("conn-expired".to_string()),
            reason: Some("token past `exp`".to_string()),
            expired_at: Some(expired_at),
        });
    let ffi_value = error::to_ffi(&original);
    let back = unsafe { error::from_ffi(ffi_value) };
    assert_eq!(original, back);
    match back.context() {
        Some(ErrorContext::Auth {
            expired_at: Some(t),
            ..
        }) => {
            assert_eq!(*t, expired_at);
        }
        other => panic!("unexpected context: {other:?}"),
    }
}

/// The exported `ovstorage_plugin_error_context_free` accepts NULL
/// (no-op). The standard pattern for hosts that lift the context
/// out of an error is to call this function exactly once.
#[test]
fn error_context_free_accepts_null() {
    unsafe {
        ffi::ovstorage_plugin_error_context_free(std::ptr::null_mut());
    }
}

/// Regression: an `ffi::Error` whose `context` slot is left
/// uninitialized — e.g. produced by a plugin compiled before the
/// `context` field existed, or built from a `MaybeUninit`
/// slot whose tail bytes were never written — surfaces a
/// non-null but **misaligned** pointer to the host. A naive read or
/// free of such a pointer would abort the process with a
/// "misaligned pointer dereference" panic; both `from_ffi` and
/// `ffi::Error: Drop` instead treat misaligned pointers as absent
/// context and continue.
#[test]
fn error_round_trip_with_misaligned_context_does_not_deref_garbage() {
    // Synthesize the old-ABI failure: build an Error whose `context`
    // field carries a tagged-int sentinel (0x25 — the discriminant
    // byte the original repro found) instead of a heap pointer.
    let message = b"injected\0".to_vec();
    let mut message = message;
    let message_len = message.len() - 1; // exclude NUL
    let message_ptr = message.as_mut_ptr() as *mut std::os::raw::c_char;
    std::mem::forget(message);
    let bogus_context = 0x25usize as *mut ffi::ErrorContextV1;
    let synth = ffi::Error {
        code: ffi::ErrorCode::Transient,
        message_ptr,
        message_len,
        context: bogus_context,
        next_action: ffi::Optional::none(),
    };
    // `from_ffi` must not deref the misaligned pointer.
    let recovered = unsafe { error::from_ffi(synth) };
    assert_eq!(recovered.code(), ErrorCode::Transient);
    assert_eq!(recovered.message(), "injected");
    assert!(recovered.context().is_none());
}

/// Companion regression for the explicit free entry point: the
/// `ovstorage_plugin_error_context_free` C export must not
/// dereference a misaligned context pointer either. (Hosts that
/// lift the context out of an error and free it later go through
/// this path.)
#[test]
fn error_context_free_ignores_misaligned_pointer() {
    let bogus = 0x25usize as *mut ffi::ErrorContextV1;
    unsafe {
        ffi::ovstorage_plugin_error_context_free(bogus);
    }
}

/// Every `ovstorage_*_free` exported so far accepts NULL, so
/// callers that have already consumed the value don't have to
/// branch on it.
#[test]
fn free_functions_accept_null_pointer() {
    unsafe {
        ffi::ovstorage_plugin_error_free(std::ptr::null_mut());
        ffi::ovstorage_plugin_str_free(std::ptr::null_mut());
        ffi::ovstorage_plugin_bytes_free(std::ptr::null_mut());
        ffi::ovstorage_plugin_backend_id_free(std::ptr::null_mut());
        ffi::ovstorage_plugin_resolved_target_free(std::ptr::null_mut());
        ffi::ovstorage_plugin_object_info_free(std::ptr::null_mut());
        ffi::ovstorage_plugin_body_free(std::ptr::null_mut());
        ffi::ovstorage_plugin_write_result_free(std::ptr::null_mut());
        ffi::ovstorage_plugin_read_result_free(std::ptr::null_mut());
        ffi::ovstorage_plugin_write_step_free(std::ptr::null_mut());
        ffi::ovstorage_plugin_access_decision_free(std::ptr::null_mut());
        ffi::ovstorage_plugin_storage_backend_kind_descriptor_free(std::ptr::null_mut());
        ffi::ovstorage_plugin_connection_request_free(std::ptr::null_mut());
        ffi::ovstorage_plugin_connection_free(std::ptr::null_mut());
        ffi::ovstorage_plugin_auth_event_free(std::ptr::null_mut());
        ffi::ovstorage_plugin_backend_change_event_free(std::ptr::null_mut());
        ffi::ovstorage_plugin_auth_event_stream_free(std::ptr::null_mut());
        ffi::ovstorage_plugin_backend_change_stream_free(std::ptr::null_mut());
    }
}

/// `_free` exports for caller-owned types must release nested
/// allocations *without* trying to reclaim the outer slot — the
/// pointee storage isn't a `Box`. Pass them stack-allocated values
/// to prove they don't `Box::from_raw` a non-Box pointer.
#[test]
fn free_functions_accept_caller_owned_storage_for_in_place_clear() {
    unsafe {
        let mut s = primitive::str_to_ffi("hello".to_owned());
        ffi::ovstorage_plugin_str_free(&mut s as *mut ffi::Str);

        let mut b = primitive::bytes_to_ffi(vec![1u8, 2, 3]);
        ffi::ovstorage_plugin_bytes_free(&mut b as *mut ffi::Bytes);

        let mut id = ffi::BackendId {
            id: primitive::str_to_ffi("backend".to_owned()),
        };
        ffi::ovstorage_plugin_backend_id_free(&mut id as *mut ffi::BackendId);

        let mut target = ffi::ResolvedTarget {
            backend_id: ffi::BackendId {
                id: primitive::str_to_ffi("backend".to_owned()),
            },
            resolved_address: primitive::str_to_ffi("s3://bucket/key".to_owned()),
        };
        ffi::ovstorage_plugin_resolved_target_free(&mut target as *mut ffi::ResolvedTarget);
    }
}

#[test]
fn str_round_trip_preserves_bytes_including_empty() {
    for input in ["", "abc", "❌ unicode \u{2028} edges", "tab\there"] {
        let ffi_value = primitive::str_to_ffi(input.to_owned());
        assert!(!ffi_value.ptr.is_null());
        // SAFETY: just constructed.
        let back = unsafe { primitive::str_from_ffi(ffi_value).unwrap() };
        assert_eq!(input, back);
    }
}

#[test]
fn str_from_ffi_rejects_invalid_utf8() {
    // Borrow the Bytes allocator path to mint an invalid-UTF-8 Str:
    // forget the Bytes shadow and reuse its ptr/len in an ffi::Str,
    // which owns the allocation thereafter.
    let invalid = vec![0xFFu8, 0xFE, 0xFD];
    let bytes = primitive::bytes_to_ffi(invalid);
    let ptr = bytes.ptr;
    let len = bytes.len;
    std::mem::forget(bytes);
    let ffi_value = ffi::Str {
        ptr: ptr as *mut std::os::raw::c_char,
        len,
    };
    // SAFETY: `ffi_value` owns the allocation `bytes` produced.
    let result = unsafe { primitive::str_from_ffi(ffi_value) };
    assert!(matches!(
        result,
        Err(ref e) if e.code() == ErrorCode::InvalidArgument
    ));
}

#[test]
fn bytes_round_trip_preserves_arbitrary_data() {
    for input in [vec![], vec![0u8], (0..=255u8).collect::<Vec<_>>()] {
        let ffi_value = primitive::bytes_to_ffi(input.clone());
        assert!(!ffi_value.ptr.is_null());
        // SAFETY: just constructed.
        let back = unsafe { primitive::bytes_from_ffi(ffi_value) };
        assert_eq!(input, back);
    }
}

#[test]
fn key_value_list_round_trip_preserves_entries() {
    let mut original = HashMap::new();
    original.insert("alpha".to_string(), "one".to_string());
    original.insert("beta".to_string(), "two".to_string());
    original.insert("".to_string(), "empty key value".to_string());

    let ffi_value = primitive::key_value_list_to_ffi(original.clone());
    // SAFETY: just constructed.
    let back = unsafe { primitive::key_value_list_from_ffi(ffi_value).unwrap() };
    assert_eq!(original, back);
}

#[test]
fn empty_key_value_list_round_trips() {
    let original: HashMap<String, String> = HashMap::new();
    let ffi_value = primitive::key_value_list_to_ffi(original.clone());
    assert_eq!(ffi_value.len, 0);
    assert!(!ffi_value.ptr.is_null());
    // SAFETY: just constructed.
    let back = unsafe { primitive::key_value_list_from_ffi(ffi_value).unwrap() };
    assert_eq!(original, back);
}

#[test]
fn optional_constructors_track_present_flag() {
    let some: ffi::Optional<u64> = ffi::Optional::some(7);
    assert!(some.is_some());
    // SAFETY: constructor wrote the value; `as_ptr` keeps `some` owning it.
    unsafe {
        assert_eq!(*some.value.as_ptr(), 7);
    }

    let none: ffi::Optional<u64> = ffi::Optional::none();
    assert!(none.is_none());
}

#[test]
fn system_time_round_trip_at_millisecond_resolution() {
    // SystemTime → unix_ms is lossy below ms; ms-expressible input round-trips.
    let pinned = primitive::system_time_from_unix_ms(1_700_000_000_123);
    let ms = primitive::system_time_to_unix_ms(pinned);
    assert_eq!(ms, 1_700_000_000_123);
    let back = primitive::system_time_from_unix_ms(ms);
    assert_eq!(pinned, back);
}

#[test]
fn system_time_round_trip_handles_pre_epoch() {
    let pinned = primitive::system_time_from_unix_ms(-1_500);
    let ms = primitive::system_time_to_unix_ms(pinned);
    assert_eq!(ms, -1_500);
    let back = primitive::system_time_from_unix_ms(ms);
    assert_eq!(pinned, back);
}

#[test]
fn object_address_round_trip_preserves_canonical_url() {
    let original = crate::address::parse("s3://bucket/team/file.txt").unwrap();
    let ffi_value = address::object_address_to_ffi(original.clone());
    // SAFETY: just constructed.
    let back = unsafe { address::object_address_from_ffi(ffi_value).unwrap() };
    assert_eq!(original, back);
}

/// A returned address whose canonical form names a **different** object is
/// refused, not rewritten.
///
/// This is the direction that inverts: normalizing a request is the point,
/// normalizing an answer is retargeting. Before this check the address below
/// was silently remapped to `s3://bucket/private/secret`, so a caller that
/// deleted the address it had just been handed destroyed a different object.
#[test]
fn returned_address_that_would_be_retargeted_is_refused() {
    for returned in [
        // Dot-segment resolution moves it.
        "s3://bucket/public%2F..%2Fprivate/secret",
        // The same retarget spelled RAW, which `Url::parse` resolves before
        // `canonicalize_preserves_node` can see it: this arrives already
        // flattened to `s3://bucket/private/secret` and is a fixed point.
        // `parsing_preserves_node` is the check that refuses it, and removing
        // that call turns this row — and only this row — red.
        "s3://bucket/public/../private/secret",
        // The parser removes ASCII TAB/LF/CR from anywhere in the input, which
        // manufactures a dot segment out of a key that has none.
        "s3://bucket/team/.\t./private",
        // So does the empty-segment collapse. This regressed once: the
        // predicate checked only dot segments, so when the collapse was added
        // to `canonicalize` a plugin's answer started being silently
        // retargeted. Both steps now come from one shared pipeline.
        "s3://bucket/a//b",
        "s3://bucket/a%2F%2Fb",
    ] {
        let ffi_value = primitive::str_to_ffi(returned.to_string());
        // SAFETY: just constructed.
        let result = unsafe { address::object_address_from_ffi(ffi_value) };
        let error = match result {
            Ok(address) => panic!("{returned} must be refused, got {address}"),
            Err(error) => error,
        };
        assert_eq!(error.code(), ErrorCode::Internal, "{returned}");
    }
}

/// No refusal of a returned address echoes a secret.
///
/// All three fire on a string the host did not choose, and a plugin's answer
/// can carry userinfo or a signed query. Each row is shaped so that only the
/// rendering under test can catch it:
///
/// - The authority-less address gets **only its scheme**, because its whole
///   post-scheme payload is opaque. `Error`'s redactor recognizes only
///   `scheme://`-shaped tokens, so it does not see this one at all, and
///   `RedactedUrl` would render the payload as a path.
/// - The retargeted address is rendered through `RedactedUrl`, and its secret
///   is a **query** parameter rather than userinfo: `Error`'s redactor strips
///   userinfo on its own, so a userinfo row would pass with the rendering
///   removed and prove nothing. It scrubs only the provider parameter names it
///   knows, and `api_key` is not one of them.
#[test]
fn a_refused_return_address_does_not_echo_its_secrets() {
    for returned in [
        // No authority: `s3:` with an opaque payload the parser never splits.
        "s3:reader:hunter2@bucket/team/file.txt",
        // Retargeted, and carrying a secret the error redactor does not know.
        "https://origin.invalid/a//b?api_key=hunter2",
        // Refused by the PARSE-step arm rather than either of the two above:
        // the raw dot segment is resolved before `canonicalize_preserves_node`
        // can see it, so neither other row reaches this rendering. Measured
        // with the arm's `RedactedUrl(&url)` replaced by `raw` — only this row
        // turns red.
        "https://origin.invalid/public/../private/secret?api_key=hunter2",
    ] {
        let ffi_value = primitive::str_to_ffi(returned.to_string());
        // SAFETY: just constructed.
        let result = unsafe { address::object_address_from_ffi(ffi_value) };
        let error = match result {
            Ok(address) => panic!("{returned} must be refused, got {address}"),
            Err(error) => error,
        };
        assert_eq!(error.code(), ErrorCode::Internal, "{returned}");
        assert!(
            !error.message().contains("hunter2"),
            "the refusal of {returned} leaked the credential: {}",
            error.message()
        );
    }
}

/// Normalizing is not retargeting. Everything `canonicalize` does other than
/// the path pipeline leaves the address naming the same node, so a plugin
/// answering with any of these spellings is answering correctly and gets the
/// normalized form back rather than an error.
///
/// An earlier version of this check compared the whole address and refused the
/// first two, which would have broken every plugin publishing a bare authority
/// root or an uppercase host.
#[test]
fn returned_addresses_the_host_merely_normalizes_are_accepted() {
    for (returned, expected) in [
        // Rule 1: the host is case-insensitive.
        ("omniverse://SERVER/p", "omniverse://server/p"),
        // Rule 2: an empty authority path gains a `/`.
        ("omniverse://host", "omniverse://host/"),
        // Rule 4: the fragment is client-side and never reached the server.
        ("s3://bucket/obj#frag", "s3://bucket/obj"),
        // Re-encoding: both spellings decode to the same key.
        ("s3://bucket/a%7bb", "s3://bucket/a%7Bb"),
    ] {
        let ffi_value = primitive::str_to_ffi(returned.to_string());
        // SAFETY: just constructed.
        let back = unsafe { address::object_address_from_ffi(ffi_value) }
            .unwrap_or_else(|error| panic!("{returned} must be accepted: {error:?}"));
        assert_eq!(back.as_str(), expected, "{returned}");
    }
}

#[test]
fn backend_id_round_trip_preserves_string() {
    let original = BackendId("backend-7".to_string());
    let ffi_value = address::backend_id_to_ffi(original.clone());
    // SAFETY: just constructed.
    let back = unsafe { address::backend_id_from_ffi(ffi_value).unwrap() };
    assert_eq!(original, back);
}

#[test]
fn backend_id_from_ffi_rejects_empty_id() {
    let ffi_value = ffi::BackendId {
        id: primitive::str_to_ffi(String::new()),
    };
    // SAFETY: just constructed.
    let result = unsafe { address::backend_id_from_ffi(ffi_value) };
    assert!(matches!(
        result,
        Err(ref e) if e.code() == ErrorCode::InvalidArgument
    ));
}

#[test]
fn resolved_target_round_trip_preserves_both_halves() {
    let original = ResolvedTarget {
        backend_id: BackendId("be-1".to_string()),
        resolved_address: crate::address::parse("https://files.example.com/a").unwrap(),
    };
    let ffi_value = address::resolved_target_to_ffi(original.clone());
    // SAFETY: just constructed.
    let back = unsafe { address::resolved_target_from_ffi(ffi_value).unwrap() };
    assert_eq!(original, back);
}

#[test]
fn checksum_algorithm_round_trip_preserves_normalized_token() {
    for raw in ["sha256", "crc32c", "md5", "x-provider-hash"] {
        let original = ChecksumAlgorithm::new(raw).unwrap();
        let ffi_value = metadata::checksum_algorithm_to_ffi(original.clone());
        // SAFETY: just constructed.
        let back = unsafe { metadata::checksum_algorithm_from_ffi(ffi_value).unwrap() };
        assert_eq!(original, back);
    }
}

#[test]
fn checksum_algorithm_from_ffi_rejects_empty_token() {
    let ffi_value = ffi::ChecksumAlgorithm {
        token: primitive::str_to_ffi(String::new()),
    };
    // SAFETY: just constructed.
    let result = unsafe { metadata::checksum_algorithm_from_ffi(ffi_value) };
    assert!(matches!(
        result,
        Err(ref e) if e.code() == ErrorCode::InvalidArgument
    ));
}

#[test]
fn checksum_set_round_trip_preserves_entries() {
    let mut original = ChecksumSet::new();
    original.insert(ChecksumAlgorithm::sha256(), vec![0xde, 0xad, 0xbe, 0xef]);
    original.insert(ChecksumAlgorithm::crc32c(), vec![0x01, 0x02, 0x03, 0x04]);

    let ffi_value = metadata::checksum_set_to_ffi(original.clone());
    // SAFETY: just constructed.
    let back = unsafe { metadata::checksum_set_from_ffi(ffi_value).unwrap() };
    assert_eq!(original, back);
}

#[test]
fn empty_checksum_set_round_trips() {
    let original = ChecksumSet::new();
    let ffi_value = metadata::checksum_set_to_ffi(original.clone());
    // SAFETY: just constructed.
    let back = unsafe { metadata::checksum_set_from_ffi(ffi_value).unwrap() };
    assert_eq!(original, back);
    assert!(back.is_empty());
}

#[test]
fn effective_permissions_round_trip_preserves_known_bits() {
    let cases = [
        EffectivePermissions::empty(),
        EffectivePermissions::READ,
        EffectivePermissions::READ | EffectivePermissions::WRITE,
        EffectivePermissions::all(),
    ];
    for original in cases {
        let ffi_value = metadata::effective_permissions_to_ffi(original);
        assert_eq!(ffi_value.bits, original.bits());
        let back = metadata::effective_permissions_from_ffi(ffi_value);
        assert_eq!(original, back);
    }
}

#[test]
fn effective_permissions_from_ffi_truncates_unknown_bits() {
    // Pins current truncation behavior; loosening it requires
    // updating both the impl and this assertion.
    let ffi_value = ffi::EffectivePermissions { bits: 0xFFFF_FFFF };
    let back = metadata::effective_permissions_from_ffi(ffi_value);
    assert_eq!(back, EffectivePermissions::all());
}

#[test]
fn object_info_round_trip_preserves_full_payload() {
    let mut checksums = ChecksumSet::new();
    checksums.insert(ChecksumAlgorithm::sha256(), vec![0xab; 32]);

    let mut user_meta: HashMap<String, String> = HashMap::new();
    user_meta.insert("x-app-tag".to_string(), "v1".to_string());

    let original = ObjectInfo {
        address: crate::address::parse("s3://b/k").unwrap(),
        kind: ObjectKind::DirectoryMarker,
        etag: Some("\"abc\"".to_string()),
        version: None,
        size: Some(7),
        mtime: Some(primitive::system_time_from_unix_ms(42)),
        checksums,
        effective_permissions: Some(EffectivePermissions::READ | EffectivePermissions::DELETE),
        system_metadata: Some(HashMap::new()),
        user_metadata: Some(user_meta),
        modified_by: Some("alice@example.com".to_string()),
    };

    let ffi_value = metadata::object_info_to_ffi(original.clone());
    // SAFETY: just constructed.
    let back = unsafe { metadata::object_info_from_ffi(ffi_value).unwrap() };
    assert_eq!(original, back);
}

#[test]
fn object_info_round_trip_with_all_optionals_absent() {
    let original = ObjectInfo {
        address: crate::address::parse("file:///tmp/x").unwrap(),
        kind: ObjectKind::File,
        etag: None,
        version: None,
        size: None,
        mtime: None,
        checksums: ChecksumSet::new(),
        effective_permissions: None,
        system_metadata: None,
        user_metadata: None,
        modified_by: None,
    };
    let ffi_value = metadata::object_info_to_ffi(original.clone());
    // SAFETY: just constructed.
    let back = unsafe { metadata::object_info_from_ffi(ffi_value).unwrap() };
    assert_eq!(original, back);
}

#[test]
fn stat_options_round_trip() {
    for full in [false, true] {
        let original = StatOptions {
            full_metadata: full,
        };
        let back =
            options::stat_options_from_ffi(options::stat_options_to_ffi(original.clone())).unwrap();
        assert_eq!(original, back);
    }
}

#[test]
fn read_options_round_trip_with_range_identity_and_buffer_cap() {
    let original = ReadOptions {
        if_match: Some("abc".into()),
        range: Some(ByteRange {
            start: 0,
            end_inclusive: Some(1023),
        }),
        max_bytes: Some(4096),
    };
    let ffi_value = options::read_options_to_ffi(original.clone());
    // SAFETY: just constructed.
    let back = unsafe { options::read_options_from_ffi(ffi_value).unwrap() };
    assert_eq!(original, back);
}

#[test]
fn read_options_undersized_struct_size_is_rejected() {
    // Build a deliberately undersized `struct_size` and assert the
    // converter refuses with `InvalidArgument` rather than reading
    // past the declared size.
    let original = ReadOptions {
        if_match: None,
        range: None,
        max_bytes: None,
    };
    let mut ffi_value = options::read_options_to_ffi(original);
    ffi_value.struct_size = 0x10; // smaller than size_of::<ffi::ReadOptions>()
    // SAFETY: just constructed; we only mutate the `struct_size` prefix.
    let err = unsafe { options::read_options_from_ffi(ffi_value).unwrap_err() };
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
    let message = err.message();
    assert!(
        message.contains("ReadOptions"),
        "error message should name the rejected struct, got: {message}"
    );
    assert!(
        message.contains("struct_size"),
        "error message should mention struct_size, got: {message}"
    );
}

#[test]
fn read_options_struct_size_zero_is_rejected() {
    // 0 is rejected the same as any undersized prefix — the
    // converter reads tail fields unconditionally, so accepting 0
    // would be UB on uninitialised memory.
    let original = ReadOptions {
        if_match: None,
        range: None,
        max_bytes: None,
    };
    let mut ffi_value = options::read_options_to_ffi(original);
    ffi_value.struct_size = 0;
    // SAFETY: just constructed.
    let err = unsafe { options::read_options_from_ffi(ffi_value).unwrap_err() };
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
    assert!(err.message().contains("ReadOptions"));
}

#[test]
fn write_options_round_trip_carries_user_metadata() {
    let mut user_meta: HashMap<String, String> = HashMap::new();
    user_meta.insert("k".to_string(), "v".to_string());
    let original = WriteOptions {
        if_dest: IfDestExists::Fail,
        size_hint: Some(4096),
        user_metadata: Some(user_meta),
        message: Some("v3".into()),
    };
    let ffi_value = options::write_options_to_ffi(original.clone());
    // SAFETY: just constructed.
    let back = unsafe { options::write_options_from_ffi(ffi_value).unwrap() };
    assert_eq!(original, back);
}

#[test]
fn delete_options_round_trip() {
    let original = DeleteOptions {
        if_match: Some("etag-v9".into()),
    };
    let ffi_value = options::delete_options_to_ffi(original.clone());
    // SAFETY: just constructed.
    let back = unsafe { options::delete_options_from_ffi(ffi_value).unwrap() };
    assert_eq!(original, back);
}

#[test]
fn list_options_round_trip_carries_paging_fields() {
    let original = ListOptions {
        recursive: true,
        max_results: Some(50),
        page_token: Some("opaque-cursor".into()),
        full_metadata: true,
    };
    let ffi_value = options::list_options_to_ffi(original.clone());
    // SAFETY: just constructed.
    let back = unsafe { options::list_options_from_ffi(ffi_value).unwrap() };
    assert_eq!(original, back);
}

#[test]
fn list_versions_options_round_trip() {
    let original = ListVersionsOptions {
        max_results: None,
        page_token: None,
    };
    let ffi_value = options::list_versions_options_to_ffi(original.clone());
    // SAFETY: just constructed.
    let back = unsafe { options::list_versions_options_from_ffi(ffi_value).unwrap() };
    assert_eq!(original, back);
}

#[test]
fn create_directory_options_round_trip() {
    let original = CreateDirectoryOptions {};
    let back = options::create_directory_options_from_ffi(
        options::create_directory_options_to_ffi(original.clone()),
    )
    .unwrap();
    assert_eq!(original, back);
}

#[test]
fn delete_directory_options_round_trip() {
    let original = DeleteDirectoryOptions;
    let ffi_value = options::delete_directory_options_to_ffi(original.clone());
    // SAFETY: just constructed.
    let back = unsafe { options::delete_directory_options_from_ffi(ffi_value).unwrap() };
    assert_eq!(original, back);
}

#[test]
fn copy_and_rename_options_round_trip() {
    let copy = CopyOptions {
        if_source: Some("a".into()),
        if_dest: IfDestExists::Overwrite,
        message: Some("copy msg".into()),
    };
    let rename = RenameOptions {
        if_source: Some("b".into()),
        if_dest: IfDestExists::Overwrite,
        message: Some("rename msg".into()),
    };

    let copy_back = unsafe {
        options::copy_options_from_ffi(options::copy_options_to_ffi(copy.clone())).unwrap()
    };
    assert_eq!(copy, copy_back);

    let rename_back = unsafe {
        options::rename_options_from_ffi(options::rename_options_to_ffi(rename.clone())).unwrap()
    };
    assert_eq!(rename, rename_back);
}

#[test]
fn update_metadata_options_round_trip_with_set_and_remove() {
    let mut set = HashMap::new();
    set.insert("x-app".to_string(), "1".to_string());
    let original = UpdateMetadataOptions {
        if_match: None,
        allow_rewrite_emulation: true,
        user_metadata_set: set,
        user_metadata_remove: vec!["legacy-key".to_string()],
        message: Some("annotated patch".to_string()),
    };
    let ffi_value = options::update_metadata_options_to_ffi(original.clone());
    // SAFETY: just constructed.
    let back = unsafe { options::update_metadata_options_from_ffi(ffi_value).unwrap() };
    assert_eq!(original, back);
}

#[test]
fn watch_directory_options_round_trip_with_cursor() {
    let original = WatchDirectoryOptions {
        recursive: true,
        include_metadata_changes: true,
        since: Some(WatchDirectoryCursor(vec![1, 2, 3, 4])),
        poll_interval: std::time::Duration::from_millis(2_500),
    };
    let ffi_value = options::watch_directory_options_to_ffi(original.clone());
    // SAFETY: just constructed.
    let back = unsafe { options::watch_directory_options_from_ffi(ffi_value).unwrap() };
    assert_eq!(original, back);
}

#[test]
fn access_ops_round_trip() {
    let original = AccessOps {
        read: true,
        write: false,
        delete: true,
        update_metadata: false,
    };
    let back = access::access_ops_from_ffi(access::access_ops_to_ffi(original.clone()));
    assert_eq!(original, back);
}

#[test]
fn http_request_round_trip_preserves_headers() {
    let original = HttpRequest {
        method: "PUT".into(),
        url: "https://example.com/k".into(),
        headers: vec![
            ("content-type".into(), "application/octet-stream".into()),
            ("x-amz-meta-app".into(), "ovstorage".into()),
        ],
    };
    let ffi_value = redirect::http_request_to_ffi(original.clone());
    // SAFETY: just constructed.
    let back = unsafe { redirect::http_request_from_ffi(ffi_value).unwrap() };
    // Header order is not preserved (KeyValueList is unordered),
    // so compare as sets.
    let original_set: std::collections::HashSet<_> = original.headers.into_iter().collect();
    let back_set: std::collections::HashSet<_> = back.headers.into_iter().collect();
    assert_eq!(original_set, back_set);
    assert_eq!(original.method, back.method);
    assert_eq!(original.url, back.url);
}

#[test]
fn mtime_format_round_trips_each_variant() {
    for variant in [
        MtimeFormat::Rfc1123,
        MtimeFormat::Iso8601,
        MtimeFormat::UnixSeconds,
    ] {
        let back = redirect::mtime_format_from_ffi(redirect::mtime_format_to_ffi(variant));
        assert_eq!(variant, back);
    }
}

#[test]
fn redirect_body_source_round_trips_every_variant() {
    let cases = [
        RedirectBodySource::Empty,
        RedirectBodySource::UserBytes {
            offset: 1024,
            len: 2048,
        },
        RedirectBodySource::Inline(b"complete-multipart-xml".to_vec()),
    ];
    for original in cases {
        let ffi_value = redirect::redirect_body_source_to_ffi(original.clone());
        // SAFETY: just constructed.
        let back = unsafe { redirect::redirect_body_source_from_ffi(ffi_value).unwrap() };
        assert_eq!(original, back);
    }
}

#[test]
fn read_redirect_round_trip_preserves_every_field() {
    let original = ReadRedirect {
        request: HttpRequest {
            method: "GET".into(),
            url: "https://b.example.com/k".into(),
            headers: Vec::new(),
        },
        response_parsing: ResponseParsing::default(),
        expires_at: primitive::system_time_from_unix_ms(1_700_000_000_000),
        scope: RedirectScope {
            physical_url_prefix: "https://b.example.com/".into(),
            operations: AccessOps {
                read: true,
                write: false,
                delete: false,
                update_metadata: false,
            },
            expires_at: primitive::system_time_from_unix_ms(1_700_000_001_000),
            // The two redirect fixtures carry different non-default
            // credentials, so a marshal that dropped the field would fail one
            // of them instead of passing on a shared value.
            credential: RedirectCredential::Request,
        },
        audit_id: "audit-id-1".into(),
        policy_epoch: 7,
    };
    let ffi_value = redirect::read_redirect_to_ffi(original.clone());
    // SAFETY: just constructed.
    let back = unsafe { redirect::read_redirect_from_ffi(ffi_value).unwrap() };
    assert_eq!(original, back);
}

#[test]
fn write_redirect_batch_round_trip_preserves_continuation_and_payload() {
    let single_redirect = WriteRedirect {
        request: HttpRequest {
            method: "PUT".into(),
            url: "https://b.example.com/k?upload=1&part=2".into(),
            headers: Vec::new(),
        },
        body_source: RedirectBodySource::UserBytes {
            offset: 0,
            len: 5_242_880,
        },
        result_capture: ResultCapture {
            headers: vec!["etag".into()],
            body_max_bytes: 0,
        },
        expires_at: primitive::system_time_from_unix_ms(1_700_000_000_000),
        scope: RedirectScope {
            physical_url_prefix: "https://b.example.com/".into(),
            operations: AccessOps {
                read: false,
                write: true,
                delete: false,
                update_metadata: false,
            },
            expires_at: primitive::system_time_from_unix_ms(1_700_000_001_000),
            credential: RedirectCredential::Connection,
        },
        audit_id: "audit-id-2".into(),
        policy_epoch: 9,
    };
    let original = WriteRedirectBatch {
        continuation: b"opaque-state".to_vec(),
        redirects: vec![single_redirect],
    };
    let ffi_value = redirect::write_redirect_batch_to_ffi(original.clone());
    // SAFETY: just constructed.
    let back = unsafe { redirect::write_redirect_batch_from_ffi(ffi_value).unwrap() };
    assert_eq!(original, back);
}

#[test]
fn redirect_result_batch_round_trips_with_captured_data() {
    let original = RedirectResultBatch {
        results: vec![RedirectResult {
            status_code: 200,
            captured_headers: vec![("etag".into(), "\"abc\"".into())],
            captured_body: b"<UploadId>123</UploadId>".to_vec(),
        }],
    };
    let ffi_value = redirect::redirect_result_batch_to_ffi(original.clone());
    // SAFETY: just constructed.
    let back = unsafe { redirect::redirect_result_batch_from_ffi(ffi_value).unwrap() };
    assert_eq!(original, back);
}

#[test]
fn body_round_trips_bytes_and_local_file_variants() {
    {
        let original_bytes = vec![0xde, 0xad, 0xbe, 0xef];
        let ffi_value = payload::body_to_ffi(Body::Bytes(original_bytes.clone()));
        let back = unsafe { payload::body_from_ffi(ffi_value).unwrap() };
        match back {
            Body::Bytes(bytes) => assert_eq!(bytes, original_bytes),
            other => panic!("expected Bytes, got {other:?}"),
        }
    }
    {
        let original_path = PathBuf::from("/tmp/file");
        let ffi_value = payload::body_to_ffi(Body::LocalFile(original_path.clone()));
        let back = unsafe { payload::body_from_ffi(ffi_value).unwrap() };
        match back {
            Body::LocalFile(path) => assert_eq!(path, original_path),
            other => panic!("expected LocalFile, got {other:?}"),
        }
    }
}

#[test]
fn body_stream_round_trips_chunks_through_ffi() {
    let chunks: Vec<Result<Vec<u8>, Error>> = vec![Ok(b"hello ".to_vec()), Ok(b"world".to_vec())];
    let stream = crate::BodyStream::from_iter(chunks.into_iter());
    let ffi_value = payload::body_to_ffi(Body::Stream(stream));
    let back = unsafe { payload::body_from_ffi(ffi_value).unwrap() };
    match back {
        Body::Stream(mut s) => {
            let c1 = s.next_chunk().expect("first chunk").expect("ok");
            assert_eq!(c1, b"hello ");
            let c2 = s.next_chunk().expect("second chunk").expect("ok");
            assert_eq!(c2, b"world");
            assert!(s.next_chunk().is_none(), "stream should be exhausted");
        }
        other => panic!("expected Stream, got {other:?}"),
    }
}

#[test]
fn body_stream_propagates_chunk_error_through_ffi() {
    let chunks: Vec<Result<Vec<u8>, Error>> = vec![
        Ok(b"first".to_vec()),
        Err(Error::new(ErrorCode::Internal, "synthetic stream failure")),
        Ok(b"unreachable".to_vec()),
    ];
    let stream = crate::BodyStream::from_iter(chunks.into_iter());
    let ffi_value = payload::body_to_ffi(Body::Stream(stream));
    let back = unsafe { payload::body_from_ffi(ffi_value).unwrap() };
    match back {
        Body::Stream(mut s) => {
            assert_eq!(s.next_chunk().unwrap().unwrap(), b"first");
            let err = s.next_chunk().unwrap().unwrap_err();
            assert_eq!(err.code(), ErrorCode::Internal);
            assert!(err.message().contains("synthetic"));
            assert!(
                s.next_chunk().is_none(),
                "stream must be exhausted after Failed per StreamStep contract"
            );
            assert!(
                s.next_chunk().is_none(),
                "follow-up polls also stay terminal"
            );
        }
        other => panic!("expected Stream, got {other:?}"),
    }
}

#[test]
fn body_stream_plugin_side_latches_failed_terminal_state() {
    // Drive `next_fn` directly (skipping the host-side
    // `BodyStreamIter` latch) to prove the plugin wrapper enforces
    // the terminal contract by itself, even when the underlying
    // iterator yields more after the error.
    let chunks: Vec<Result<Vec<u8>, Error>> = vec![
        Ok(b"first".to_vec()),
        Err(Error::new(ErrorCode::Internal, "synthetic")),
        Ok(b"unreachable-after-failed".to_vec()),
    ];
    let stream = crate::BodyStream::from_iter(chunks.into_iter());
    let mut handle = payload::body_stream_to_ffi(stream);
    let mut chunk = std::mem::MaybeUninit::<ffi::Bytes>::uninit();
    let mut error = std::mem::MaybeUninit::<ffi::Error>::uninit();

    unsafe {
        let step = (handle.next_fn)(handle.state, chunk.as_mut_ptr(), error.as_mut_ptr());
        assert_eq!(step, ffi::StreamStep::Yielded);
        let bytes = chunk.assume_init();
        let recovered = primitive::bytes_from_ffi(bytes);
        assert_eq!(recovered, b"first");
        chunk = std::mem::MaybeUninit::uninit();

        let step = (handle.next_fn)(handle.state, chunk.as_mut_ptr(), error.as_mut_ptr());
        assert_eq!(step, ffi::StreamStep::Failed);
        let err = error::from_ffi(error.assume_init());
        assert_eq!(err.code(), ErrorCode::Internal);
        error = std::mem::MaybeUninit::uninit();

        let step = (handle.next_fn)(handle.state, chunk.as_mut_ptr(), error.as_mut_ptr());
        assert_eq!(
            step,
            ffi::StreamStep::Ended,
            "plugin-side latch must short-circuit subsequent calls to Ended"
        );

        let step = (handle.next_fn)(handle.state, chunk.as_mut_ptr(), error.as_mut_ptr());
        assert_eq!(
            step,
            ffi::StreamStep::Ended,
            "latch stays Ended on follow-up polls"
        );

        (handle.drop_fn)(handle.state);
        handle.state = std::ptr::null_mut();
    }
    std::mem::forget(handle);
}

#[test]
fn body_stream_plugin_side_latches_natural_end() {
    // Once the iterator returns None, subsequent polls must stay
    // Ended without re-entering the iterator.
    use std::sync::atomic::{AtomicUsize, Ordering};
    let calls = std::sync::Arc::new(AtomicUsize::new(0));
    let calls_inner = calls.clone();
    let mut yielded = false;
    let stream = crate::BodyStream::from_iter(std::iter::from_fn(move || {
        calls_inner.fetch_add(1, Ordering::SeqCst);
        if !yielded {
            yielded = true;
            Some(Ok(b"only".to_vec()))
        } else {
            None
        }
    }));
    let mut handle = payload::body_stream_to_ffi(stream);
    let mut chunk = std::mem::MaybeUninit::<ffi::Bytes>::uninit();
    let mut error = std::mem::MaybeUninit::<ffi::Error>::uninit();

    unsafe {
        let step = (handle.next_fn)(handle.state, chunk.as_mut_ptr(), error.as_mut_ptr());
        assert_eq!(step, ffi::StreamStep::Yielded);
        drop(primitive::bytes_from_ffi(chunk.assume_init()));
        chunk = std::mem::MaybeUninit::uninit();

        let step = (handle.next_fn)(handle.state, chunk.as_mut_ptr(), error.as_mut_ptr());
        assert_eq!(step, ffi::StreamStep::Ended);
        let calls_after_first_end = calls.load(Ordering::SeqCst);

        let step = (handle.next_fn)(handle.state, chunk.as_mut_ptr(), error.as_mut_ptr());
        assert_eq!(step, ffi::StreamStep::Ended);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            calls_after_first_end,
            "Ended latch must short-circuit without re-entering the underlying iterator"
        );

        (handle.drop_fn)(handle.state);
        handle.state = std::ptr::null_mut();
    }
    std::mem::forget(handle);
}

#[test]
fn write_result_round_trip_preserves_info() {
    let original = WriteResult {
        info: ObjectInfo {
            address: crate::address::parse("s3://b/k").unwrap(),
            kind: ObjectKind::File,
            etag: Some("\"abc\"".into()),
            version: None,
            size: None,
            mtime: None,
            checksums: ChecksumSet::new(),
            effective_permissions: None,
            system_metadata: None,
            user_metadata: None,
            modified_by: None,
        },
    };
    let ffi_value = payload::write_result_to_ffi(original.clone());
    // SAFETY: just constructed.
    let back = unsafe { payload::write_result_from_ffi(ffi_value).unwrap() };
    assert_eq!(original, back);
}

#[test]
fn local_delegate_round_trip_preserves_path_and_info() {
    let original = LocalDelegate {
        path: PathBuf::from("/var/cache/ov/abc"),
        info: ObjectInfo {
            address: crate::address::parse("file:///x").unwrap(),
            kind: ObjectKind::File,
            etag: None,
            version: None,
            size: None,
            mtime: None,
            checksums: ChecksumSet::new(),
            effective_permissions: None,
            system_metadata: None,
            user_metadata: None,
            modified_by: None,
        },
        guard: None,
    };
    let ffi_value = payload::local_delegate_to_ffi(original.clone());
    // SAFETY: just constructed.
    let back = unsafe { payload::local_delegate_from_ffi(ffi_value).unwrap() };
    assert_eq!(original, back);
}

#[test]
fn read_result_round_trips_each_variant() {
    let info = ObjectInfo {
        address: crate::address::parse("s3://b/k").unwrap(),
        kind: ObjectKind::File,
        etag: None,
        version: None,
        size: None,
        mtime: None,
        checksums: ChecksumSet::new(),
        effective_permissions: None,
        system_metadata: None,
        user_metadata: None,
        modified_by: None,
    };

    let bytes_variant = ReadResult::Bytes {
        bytes: vec![1, 2, 3],
        info: info.clone(),
    };
    let ffi_value = payload::read_result_to_ffi(bytes_variant);
    // SAFETY: just constructed.
    let back = unsafe { payload::read_result_from_ffi(ffi_value).unwrap() };
    match back {
        ReadResult::Bytes {
            bytes,
            info: back_info,
        } => {
            assert_eq!(bytes, vec![1, 2, 3]);
            assert_eq!(back_info, info);
        }
        other => panic!("expected Bytes after round-trip, got {other:?}"),
    }

    let local_variant = ReadResult::LocalDelegate(LocalDelegate {
        path: PathBuf::from("/tmp/x"),
        info: info.clone(),
        guard: None,
    });
    let ffi_value = payload::read_result_to_ffi(local_variant);
    // SAFETY: just constructed.
    let back = unsafe { payload::read_result_from_ffi(ffi_value).unwrap() };
    match back {
        ReadResult::LocalDelegate(delegate) => {
            assert_eq!(delegate.path, PathBuf::from("/tmp/x"));
            assert_eq!(delegate.info, info);
        }
        other => panic!("expected LocalDelegate after round-trip, got {other:?}"),
    }
}

#[tokio::test]
async fn read_result_stream_round_trips_chunks_through_ffi() {
    use futures::StreamExt;
    let info = ObjectInfo {
        address: crate::address::parse("s3://b/k").unwrap(),
        kind: ObjectKind::File,
        etag: None,
        version: None,
        size: None,
        mtime: None,
        checksums: ChecksumSet::new(),
        effective_permissions: None,
        system_metadata: None,
        user_metadata: None,
        modified_by: None,
    };
    let chunks: Vec<Result<bytes::Bytes, Error>> = vec![
        Ok(bytes::Bytes::from_static(&[1, 2, 3])),
        Ok(bytes::Bytes::from_static(&[4, 5])),
        Ok(bytes::Bytes::from_static(&[6, 7, 8, 9])),
    ];
    let stream: crate::ReadStream = Box::pin(futures::stream::iter(chunks));
    let original = ReadResult::Stream {
        stream,
        info: info.clone(),
    };
    let ffi_value = payload::read_result_to_ffi(original);
    // SAFETY: just constructed.
    let back = unsafe { payload::read_result_from_ffi(ffi_value).unwrap() };
    match back {
        ReadResult::Stream {
            stream,
            info: back_info,
        } => {
            assert_eq!(back_info, info);
            let collected: Vec<Vec<u8>> =
                stream.map(|chunk| chunk.unwrap().to_vec()).collect().await;
            assert_eq!(collected, vec![vec![1, 2, 3], vec![4, 5], vec![6, 7, 8, 9]]);
        }
        other => panic!("expected Stream after round-trip, got {other:?}"),
    }
}

#[test]
fn write_step_round_trips_each_variant() {
    let info = ObjectInfo {
        address: crate::address::parse("s3://b/k").unwrap(),
        kind: ObjectKind::File,
        etag: None,
        version: None,
        size: None,
        mtime: None,
        checksums: ChecksumSet::new(),
        effective_permissions: None,
        system_metadata: None,
        user_metadata: None,
        modified_by: None,
    };
    let result = WriteResult { info };

    let done = WriteStep::Done(result);
    let back =
        unsafe { payload::write_step_from_ffi(payload::write_step_to_ffi(done.clone())).unwrap() };
    assert_eq!(done, back);

    let redirects = WriteStep::Redirects(WriteRedirectBatch {
        continuation: vec![],
        redirects: vec![],
    });
    let back = unsafe {
        payload::write_step_from_ffi(payload::write_step_to_ffi(redirects.clone())).unwrap()
    };
    assert_eq!(redirects, back);
}

#[test]
fn access_decision_round_trip_with_reason() {
    let original = AccessDecision {
        allowed: false,
        denied_ops: AccessOps {
            read: false,
            write: true,
            delete: false,
            update_metadata: false,
        },
        reason: Some("not allowed".into()),
    };
    let ffi_value = payload::access_decision_to_ffi(original.clone());
    // SAFETY: just constructed.
    let back = unsafe { payload::access_decision_from_ffi(ffi_value).unwrap() };
    assert_eq!(original, back);
}

#[test]
fn capabilities_round_trip_preserves_every_field() {
    let original = Capabilities {
        supports_if_match_write: true,
        supports_no_overwrite_write: true,
        supports_native_metadata_patch: false,
        supports_metadata_rewrite_emulation: true,
        writes_are_atomic: true,
        supports_copy: true,
        supports_rename: false,
        supports_server_side_copy: false,
        supports_server_side_rename: false,
        supports_atomic_rename: false,
        has_real_directories: true,
        supports_list: true,
        wants_list_backed_stat: false,
        supports_recursive_list: true,
        populates_subdirectory_metadata: false,
        supports_version_listing: true,
        version_list_order: Some(VersionListOrder::Newest),
        populates_effective_permissions_on_stat: false,
        supports_access_check: false,
        supports_watch_directory: true,
        watch_directory_kinds: ChangeKindSet {
            created: true,
            modified: true,
            deleted: true,
            metadata_changed: false,
        },
        watch_directory_resumable: false,
        watch_directory_max_lag: Some(Duration::from_millis(15_000)),
        redirect_size_threshold: Some(8 * 1024 * 1024),
        supports_write: true,
        supports_write_stream: true,
        supports_write_redirect: false,
        supports_delete: true,
        supports_create_directory: false,
        supports_delete_directory: false,
    };
    let ffi_value = capabilities::capabilities_to_ffi(original.clone());
    // SAFETY: just constructed.
    let back = unsafe { capabilities::capabilities_from_ffi(ffi_value).unwrap() };
    assert_eq!(original, back);
}

#[test]
fn connection_id_round_trip_rejects_empty() {
    let original = ConnectionId("00000000-0000-0000-0000-000000000001".to_string());
    let back = unsafe {
        connection::connection_id_from_ffi(connection::connection_id_to_ffi(original.clone()))
            .unwrap()
    };
    assert_eq!(original, back);

    let empty = ffi::ConnectionId {
        id: primitive::str_to_ffi(String::new()),
    };
    let result = unsafe { connection::connection_id_from_ffi(empty) };
    assert!(matches!(
        result,
        Err(ref e) if e.code() == ErrorCode::InvalidArgument
    ));
}

#[test]
fn connection_source_round_trips_each_variant() {
    for original in [
        ConnectionSource::Static {
            layer: ConfigLayer::User,
        },
        ConnectionSource::Runtime { persisted: true },
        ConnectionSource::BrokerDelivered {
            broker_principal: "svc-broker".into(),
        },
    ] {
        let back = unsafe {
            connection::connection_source_from_ffi(connection::connection_source_to_ffi(
                original.clone(),
            ))
            .unwrap()
        };
        assert_eq!(original, back);
    }
}

#[test]
fn config_value_round_trips_each_variant() {
    let cases = [
        ConfigValue::String("text".into()),
        ConfigValue::Int(-12345),
        ConfigValue::Bool(true),
        ConfigValue::Toml("[[policy]]\nid = \"r1\"\n".into()),
    ];
    for original in cases {
        let back = unsafe {
            descriptor::config_value_from_ffi(descriptor::config_value_to_ffi(original.clone()))
                .unwrap()
        };
        assert_eq!(original, back);
    }
}

#[test]
fn config_field_kind_round_trips_each_variant() {
    for original in [
        ConfigFieldKind::Url,
        ConfigFieldKind::Text,
        ConfigFieldKind::Integer,
        ConfigFieldKind::Bool,
        ConfigFieldKind::Path,
        ConfigFieldKind::Enum {
            source: EnumSource::Static(vec!["a".into(), "b".into()]),
        },
        ConfigFieldKind::Enum {
            source: EnumSource::Discovered,
        },
    ] {
        let back = unsafe {
            descriptor::config_field_kind_from_ffi(descriptor::config_field_kind_to_ffi(
                original.clone(),
            ))
            .unwrap()
        };
        assert_eq!(original, back);
    }
}

#[test]
fn descriptor_round_trip_preserves_full_payload() {
    let original = StorageBackendKindDescriptor {
        kind: "s3".into(),
        display_name: "Amazon S3".into(),
        description: Some("AWS S3 backend".into()),
        config_schema: vec![ConfigField {
            key: "bucket".into(),
            display_name: "Bucket".into(),
            kind: ConfigFieldKind::Text,
            required: true,
            default: None,
            help: Some("S3 bucket name".into()),
            example: Some("my-bucket".into()),
            group: None,
            advanced: false,
        }],
        credential_schema: vec![CredentialField {
            key: "access_key".into(),
            display_name: "Access Key".into(),
            default: Some("${AWS_ACCESS_KEY_ID}".into()),
            help: None,
            advanced: false,
        }],
        credential_methods: vec![CredentialMethod {
            key: "static_key".into(),
            display_name: "Static access key".into(),
            fields: vec!["access_key".into()],
            help: None,
            advanced: false,
        }],
        icon: Some(b"icon-bytes".to_vec()),
        supports_runtime_add: true,
        // Exercised in both directions by
        // `each_projection_carries_the_user_metadata_declaration`; a symmetric
        // round trip like this one cannot tell a forwarded value from a
        // constant substituted on both sides.
        supports_user_metadata: true,
    };
    let back = unsafe {
        descriptor::storage_backend_kind_descriptor_from_ffi(
            descriptor::storage_backend_kind_descriptor_to_ffi(original.clone()),
        )
        .unwrap()
    };
    assert_eq!(original, back);
}

#[test]
fn secret_bundle_round_trip_preserves_each_value_kind() {
    let mut fields = HashMap::new();
    fields.insert(
        "password".to_string(),
        SecretValue::Bytes(SecretBytes(b"hunter2".to_vec())),
    );
    fields.insert(
        "oauth".to_string(),
        SecretValue::OAuthToken {
            token: SecretBytes(b"access".to_vec()),
            refresh: Some(SecretBytes(b"refresh".to_vec())),
            expires_at: Some(primitive::system_time_from_unix_ms(1_700_000_000_000)),
        },
    );
    fields.insert("system".to_string(), SecretValue::SystemIdentity);
    let original = SecretBundle { fields };
    let back = unsafe {
        descriptor::secret_bundle_from_ffi(descriptor::secret_bundle_to_ffi(original.clone()))
            .unwrap()
    };
    assert_eq!(original, back);
}

#[test]
fn auth_reason_round_trips_each_variant() {
    for original in [
        AuthReason::NeverAuthenticated,
        AuthReason::RefreshTokenExpired,
        AuthReason::RefreshTokenRevoked,
        AuthReason::CredentialsRotated,
        AuthReason::ManuallyRequested,
        AuthReason::BackendUnreachable,
        AuthReason::Unknown {
            details: "policy-rotated".into(),
        },
    ] {
        let back = unsafe {
            auth::auth_reason_from_ffi(auth::auth_reason_to_ffi(original.clone())).unwrap()
        };
        assert_eq!(original, back);
    }
}

#[test]
fn auth_attempt_round_trip_with_and_without_error() {
    let with_error = AuthAttempt {
        at: primitive::system_time_from_unix_ms(1_700_000_000_000),
        error: Some(Error::new(ErrorCode::AuthCancelled, "user dismissed")),
    };
    let back = unsafe {
        auth::auth_attempt_from_ffi(auth::auth_attempt_to_ffi(with_error.clone())).unwrap()
    };
    assert_eq!(with_error, back);

    let no_error = AuthAttempt {
        at: primitive::system_time_from_unix_ms(1_700_000_001_000),
        error: None,
    };
    let back = unsafe {
        auth::auth_attempt_from_ffi(auth::auth_attempt_to_ffi(no_error.clone())).unwrap()
    };
    assert_eq!(no_error, back);
}

#[test]
fn connection_auth_state_round_trips_each_variant() {
    let cases = [
        ConnectionAuthState::Authenticated {
            last_authenticated_at: primitive::system_time_from_unix_ms(1_700_000_000_000),
            expires_at: Some(primitive::system_time_from_unix_ms(1_700_003_600_000)),
        },
        ConnectionAuthState::AwaitingAuth {
            reason: AuthReason::RefreshTokenExpired,
            last_attempt: Some(AuthAttempt {
                at: primitive::system_time_from_unix_ms(1_699_999_000_000),
                error: None,
            }),
        },
        ConnectionAuthState::AuthFailed {
            error: Error::new(ErrorCode::CredentialUnavailable, "no password in keyring"),
            attempts: 3,
        },
        ConnectionAuthState::Anonymous,
    ];
    for original in cases {
        let back = unsafe {
            auth::connection_auth_state_from_ffi(auth::connection_auth_state_to_ffi(
                original.clone(),
            ))
            .unwrap()
        };
        assert_eq!(original, back);
    }
}

#[test]
fn connection_round_trip_preserves_full_payload() {
    let original = Connection {
        id: ConnectionId("c-1".into()),
        backend_kind: "s3".into(),
        display_name: "Prod S3".into(),
        source: ConnectionSource::Static {
            layer: ConfigLayer::User,
        },
        capabilities: Capabilities::empty(),
        current_addresses: vec![crate::address::parse("s3://b/").unwrap()],
        auth_state: ConnectionAuthState::Anonymous,
        last_probed: Some(primitive::system_time_from_unix_ms(1_700_000_001_000)),
        user_metadata: HashMap::new(),
    };
    let back =
        unsafe { auth::connection_from_ffi(auth::connection_to_ffi(original.clone())).unwrap() };
    assert_eq!(original, back);
}

#[test]
fn auth_event_round_trips_each_variant() {
    let connection = Connection {
        id: ConnectionId("c-1".into()),
        backend_kind: "s3".into(),
        display_name: "Prod S3".into(),
        source: ConnectionSource::Static {
            layer: ConfigLayer::User,
        },
        capabilities: Capabilities::empty(),
        current_addresses: vec![],
        auth_state: ConnectionAuthState::Authenticated {
            last_authenticated_at: primitive::system_time_from_unix_ms(1_700_000_000_000),
            expires_at: None,
        },
        last_probed: None,
        user_metadata: HashMap::new(),
    };
    let cases = [
        AuthEvent::OpenBrowser {
            url: "https://idp.example.com/auth".into(),
            expires_at: primitive::system_time_from_unix_ms(1_700_000_300_000),
        },
        AuthEvent::DeviceCode {
            user_code: "ABC-DEF".into(),
            verification_url: "https://idp.example.com/device".into(),
            expires_at: primitive::system_time_from_unix_ms(1_700_000_300_000),
            interval: Duration::from_secs(5),
        },
        AuthEvent::Progress {
            message: "polling token endpoint".into(),
        },
        AuthEvent::Succeeded {
            connection: Box::new(connection.clone()),
            credentials: None,
        },
        AuthEvent::Succeeded {
            connection: Box::new(connection),
            credentials: Some({
                let mut bundle = SecretBundle::default();
                bundle.fields.insert(
                    "oauth".into(),
                    SecretValue::OAuthToken {
                        token: SecretBytes(b"access-xyz".to_vec()),
                        refresh: Some(SecretBytes(b"refresh-abc".to_vec())),
                        expires_at: Some(primitive::system_time_from_unix_ms(1_700_000_900_000)),
                    },
                );
                bundle.fields.insert(
                    "api_key".into(),
                    SecretValue::Bytes(SecretBytes(b"sk-test".to_vec())),
                );
                bundle
                    .fields
                    .insert("anon".into(), SecretValue::SystemIdentity);
                bundle
            }),
        },
        AuthEvent::Failed {
            error: Error::new(ErrorCode::AuthCancelled, "user dismissed"),
        },
        AuthEvent::Cancelled,
    ];
    for original in cases {
        let back = unsafe {
            auth::auth_event_from_ffi(auth::auth_event_to_ffi(original.clone())).unwrap()
        };
        assert_eq!(original, back);
    }
}

#[test]
fn backend_change_event_round_trips_each_variant() {
    let cases = [
        BackendChangeEvent::Object {
            address: Url::parse("test://root/foo/bar.bin").unwrap(),
            kind: ChangeKind::Created,
            etag: Some("\"abc\"".into()),
            version: None,
            size: None,
            mtime: None,
            at: primitive::system_time_from_unix_ms(1_700_000_000_000),
            cursor: WatchDirectoryCursor(vec![1, 2, 3]),
        },
        BackendChangeEvent::Lapsed {
            since: Some(primitive::system_time_from_unix_ms(1_699_999_000_000)),
            cursor: WatchDirectoryCursor(vec![]),
        },
    ];
    for original in cases {
        let back = unsafe {
            change::backend_change_event_from_ffi(change::backend_change_event_to_ffi(
                original.clone(),
            ))
            .unwrap()
        };
        assert_eq!(original, back);
    }
}

/// End-to-end exercise of the stream adapter: build an
/// `ffi::AuthEventStream` whose plugin-state is a Rust `Vec` of
/// preconstructed events, hand it to `marshal::auth::AuthEventStream`,
/// and assert the iterator yields the expected sequence.
#[test]
fn auth_event_stream_iterator_yields_expected_sequence_then_ends() {
    struct State {
        events: std::vec::IntoIter<AuthEvent>,
    }

    unsafe extern "C" fn next_fn(
        state: *mut std::ffi::c_void,
        out_item: *mut ffi::AuthEvent,
        _out_error: *mut ffi::Error,
    ) -> ffi::StreamStep {
        unsafe {
            let state = &mut *(state as *mut State);
            match state.events.next() {
                Some(event) => {
                    std::ptr::write(out_item, auth::auth_event_to_ffi(event));
                    ffi::StreamStep::Yielded
                }
                None => ffi::StreamStep::Ended,
            }
        }
    }

    unsafe extern "C" fn drop_fn(state: *mut std::ffi::c_void) {
        unsafe {
            drop(Box::from_raw(state as *mut State));
        }
    }

    let events = vec![
        AuthEvent::Progress {
            message: "step 1".into(),
        },
        AuthEvent::Progress {
            message: "step 2".into(),
        },
        AuthEvent::Cancelled,
    ];
    let state = Box::new(State {
        events: events.clone().into_iter(),
    });
    let ffi_stream = ffi::AuthEventStream {
        state: Box::into_raw(state) as *mut std::ffi::c_void,
        next_fn,
        drop_fn,
    };

    let mut iter = unsafe { auth::AuthEventStream::from_ffi(ffi_stream) };
    let collected: Vec<_> = (&mut iter).collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(events, collected);
    assert!(iter.next().is_none());
}

/// A failing stream surfaces the error and short-circuits.
#[test]
fn auth_event_stream_iterator_surfaces_failure_then_ends() {
    struct State {
        yielded: bool,
    }

    unsafe extern "C" fn next_fn(
        state: *mut std::ffi::c_void,
        _out_item: *mut ffi::AuthEvent,
        out_error: *mut ffi::Error,
    ) -> ffi::StreamStep {
        unsafe {
            let state = &mut *(state as *mut State);
            if !state.yielded {
                state.yielded = true;
                std::ptr::write(
                    out_error,
                    error::to_ffi(&Error::new(ErrorCode::Transient, "lost connection")),
                );
                ffi::StreamStep::Failed
            } else {
                ffi::StreamStep::Ended
            }
        }
    }

    unsafe extern "C" fn drop_fn(state: *mut std::ffi::c_void) {
        unsafe {
            drop(Box::from_raw(state as *mut State));
        }
    }

    let state = Box::new(State { yielded: false });
    let ffi_stream = ffi::AuthEventStream {
        state: Box::into_raw(state) as *mut std::ffi::c_void,
        next_fn,
        drop_fn,
    };
    let mut iter = unsafe { auth::AuthEventStream::from_ffi(ffi_stream) };
    let first = iter.next().unwrap();
    assert!(first.is_err());
    assert_eq!(first.unwrap_err().code(), ErrorCode::Transient);
    assert!(iter.next().is_none());
}

/// The stream's `drop_fn` runs even if the iterator is dropped
/// mid-way without exhausting the stream.
#[test]
fn auth_event_stream_drop_fn_runs_on_early_termination() {
    struct State {
        drops_seen: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        events: std::vec::IntoIter<AuthEvent>,
    }

    unsafe extern "C" fn next_fn(
        state: *mut std::ffi::c_void,
        out_item: *mut ffi::AuthEvent,
        _out_error: *mut ffi::Error,
    ) -> ffi::StreamStep {
        unsafe {
            let state = &mut *(state as *mut State);
            match state.events.next() {
                Some(event) => {
                    std::ptr::write(out_item, auth::auth_event_to_ffi(event));
                    ffi::StreamStep::Yielded
                }
                None => ffi::StreamStep::Ended,
            }
        }
    }

    unsafe extern "C" fn drop_fn(state: *mut std::ffi::c_void) {
        unsafe {
            let state = Box::from_raw(state as *mut State);
            state
                .drops_seen
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    let drops_seen = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let state = Box::new(State {
        drops_seen: drops_seen.clone(),
        events: vec![
            AuthEvent::Progress {
                message: "step 1".into(),
            },
            AuthEvent::Progress {
                message: "step 2".into(),
            },
            AuthEvent::Cancelled,
        ]
        .into_iter(),
    });
    let ffi_stream = ffi::AuthEventStream {
        state: Box::into_raw(state) as *mut std::ffi::c_void,
        next_fn,
        drop_fn,
    };
    {
        let mut iter = unsafe { auth::AuthEventStream::from_ffi(ffi_stream) };
        let _first = iter.next().unwrap().unwrap();
    }
    assert_eq!(
        drops_seen.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "drop_fn must run exactly once on early termination",
    );
}

#[test]
fn connection_request_round_trip() {
    let mut config = HashMap::new();
    config.insert(
        "region".to_string(),
        ConfigValue::String("us-west-2".into()),
    );
    config.insert("retries".to_string(), ConfigValue::Int(5));

    let mut creds = HashMap::new();
    creds.insert(
        "access_key".to_string(),
        SecretValue::Bytes(SecretBytes(b"AK".to_vec())),
    );

    let original = ConnectionRequest {
        backend_kind: "s3".into(),
        config,
        credentials: SecretBundle { fields: creds },
        persist: true,
        display_name: Some("Prod S3".into()),
    };
    let back = unsafe {
        descriptor::connection_request_from_ffi(descriptor::connection_request_to_ffi(
            original.clone(),
        ))
        .unwrap()
    };
    assert_eq!(original, back);
}

/// The `Result<T>` constructors set the discriminant correctly
/// and initialize the matching payload. The values drop normally
/// at end of scope; `Result<T>: Drop` releases the active variant
/// (the inline `u32` is trivial; the `Error` payload's message
/// buffer is freed via `Error: Drop`).
#[test]
fn result_constructors_track_discriminant() {
    let ok: ffi::Result<u32> = ffi::Result::ok(42);
    assert_eq!(ok.tag, ffi::ResultTag::Ok);
    assert!(ok.is_ok());

    let err: ffi::Result<u32> =
        ffi::Result::err(error::to_ffi(&Error::new(ErrorCode::Cancelled, "test")));
    assert_eq!(err.tag, ffi::ResultTag::Err);
    assert!(err.is_err());
}

// -----------------------------------------------------------------
// marshal::HostCallbacks
// -----------------------------------------------------------------

use std::cell::Cell;
use std::sync::atomic::{AtomicU32, Ordering};

/// Build a stub `ffi::HostCallbacks` whose function pointers we
/// control so we can drive `marshal::HostCallbacks` deterministically
/// from tests.
struct StubHost {
    secrets: std::sync::Mutex<HashMap<(String, String, String), SecretBytes>>,
    refresh_calls: AtomicU32,
}

impl StubHost {
    fn new() -> Box<Self> {
        Box::new(Self {
            secrets: std::sync::Mutex::new(HashMap::new()),
            refresh_calls: AtomicU32::new(0),
        })
    }

    #[allow(clippy::borrowed_box)]
    fn callbacks(self: &Box<Self>) -> ffi::HostCallbacks {
        ffi::HostCallbacks {
            struct_size: std::mem::size_of::<ffi::HostCallbacks>(),
            host_state: std::ptr::from_ref::<Self>(&**self) as *mut core::ffi::c_void,
            secret_get: stub_secret_get,
            secret_put: stub_secret_put,
            secret_delete: stub_secret_delete,
            auth_refresh_lock_with_refresh: stub_auth_refresh,
            host_kind: ffi::HostKindV1::Library as u32,
            log: stub_log,
        }
    }
}

unsafe extern "C" fn stub_log(
    _state: *mut core::ffi::c_void,
    _level: u8,
    _target: *const ffi::Str,
    _message: *const ffi::Str,
) {
}

unsafe fn read_key(key: *const ffi::SecretKey) -> (String, String, String) {
    unsafe {
        let key = &*key;
        let backend_kind = std::str::from_utf8(std::slice::from_raw_parts(
            key.backend_kind.ptr as *const u8,
            key.backend_kind.len,
        ))
        .unwrap()
        .to_owned();
        let connection_id = std::str::from_utf8(std::slice::from_raw_parts(
            key.connection_id.id.ptr as *const u8,
            key.connection_id.id.len,
        ))
        .unwrap()
        .to_owned();
        let field = std::str::from_utf8(std::slice::from_raw_parts(
            key.field.ptr as *const u8,
            key.field.len,
        ))
        .unwrap()
        .to_owned();
        (backend_kind, connection_id, field)
    }
}

unsafe extern "C" fn stub_secret_get(
    state: *mut core::ffi::c_void,
    key: *const ffi::SecretKey,
    out_value: *mut ffi::Optional<ffi::SecretBytes>,
) -> *mut ffi::Error {
    unsafe {
        let host = &*(state as *const StubHost);
        let parsed = read_key(key);
        let map = host.secrets.lock().unwrap();
        let opt = match map.get(&parsed) {
            Some(secret) => ffi::Optional::some(descriptor::secret_bytes_to_ffi(secret.clone())),
            None => ffi::Optional::none(),
        };
        std::ptr::write(out_value, opt);
        std::ptr::null_mut()
    }
}

unsafe extern "C" fn stub_secret_put(
    state: *mut core::ffi::c_void,
    key: *const ffi::SecretKey,
    value: *const ffi::SecretBytes,
) -> *mut ffi::Error {
    unsafe {
        let host = &*(state as *const StubHost);
        let parsed = read_key(key);
        let bytes = std::slice::from_raw_parts((*value).bytes.ptr, (*value).bytes.len).to_vec();
        host.secrets
            .lock()
            .unwrap()
            .insert(parsed, SecretBytes(bytes));
        std::ptr::null_mut()
    }
}

unsafe extern "C" fn stub_secret_delete(
    state: *mut core::ffi::c_void,
    key: *const ffi::SecretKey,
) -> *mut ffi::Error {
    unsafe {
        let host = &*(state as *const StubHost);
        host.secrets.lock().unwrap().remove(&read_key(key));
        std::ptr::null_mut()
    }
}

unsafe extern "C" fn stub_auth_refresh(
    state: *mut core::ffi::c_void,
    _backend_kind: *const ffi::Str,
    _connection_id: *const ffi::ConnectionId,
    _freshness_window_ms: u64,
    refresh_state: *mut core::ffi::c_void,
    refresh_fn: ffi::HostRefreshFn,
) -> *mut ffi::Error {
    unsafe {
        let host = &*(state as *const StubHost);
        host.refresh_calls.fetch_add(1, Ordering::SeqCst);
        refresh_fn(refresh_state)
    }
}

#[test]
fn host_callbacks_keyring_round_trip() {
    let stub = StubHost::new();
    let cb = stub.callbacks();
    let host = unsafe { HostCallbacks::from_raw(&cb).unwrap() };
    let connection_id = ConnectionId("c-1".into());

    // Miss returns None.
    let miss = host.secret_get("s3", &connection_id, "access_key").unwrap();
    assert!(miss.is_none());

    // Put + get round-trips bytes.
    host.secret_put(
        "s3",
        &connection_id,
        "access_key",
        &SecretBytes(b"hunter2".to_vec()),
    )
    .unwrap();
    let hit = host
        .secret_get("s3", &connection_id, "access_key")
        .unwrap()
        .expect("expected stored secret");
    assert_eq!(hit, SecretBytes(b"hunter2".to_vec()));

    // Delete drops it.
    host.secret_delete("s3", &connection_id, "access_key")
        .unwrap();
    let after_delete = host.secret_get("s3", &connection_id, "access_key").unwrap();
    assert!(after_delete.is_none());
}

#[test]
fn host_callbacks_auth_refresh_invokes_closure_once() {
    let stub = StubHost::new();
    let cb = stub.callbacks();
    let host = unsafe { HostCallbacks::from_raw(&cb).unwrap() };
    let connection_id = ConnectionId("c-1".into());

    let invocations = Cell::new(0u32);
    host.auth_refresh_lock_with_refresh(
        "nucleus",
        &connection_id,
        std::time::Duration::from_secs(60),
        || {
            invocations.set(invocations.get() + 1);
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(invocations.get(), 1);
    assert_eq!(stub.refresh_calls.load(Ordering::SeqCst), 1);
}

#[test]
fn host_callbacks_auth_refresh_propagates_error() {
    let stub = StubHost::new();
    let cb = stub.callbacks();
    let host = unsafe { HostCallbacks::from_raw(&cb).unwrap() };
    let connection_id = ConnectionId("c-1".into());

    let result = host.auth_refresh_lock_with_refresh(
        "nucleus",
        &connection_id,
        std::time::Duration::from_secs(60),
        || Err(Error::new(ErrorCode::Transient, "lost network")),
    );
    let err = result.unwrap_err();
    assert_eq!(err.code(), ErrorCode::Transient);
    assert_eq!(err.message(), "lost network");
}

#[test]
fn ffi_status_constants_distinct_from_error_codes() {
    assert_eq!(ffi::FFI_STATUS_OK, 0);
    assert_ne!(ffi::FFI_STATUS_ERR, ffi::FFI_STATUS_OK);
    assert_ne!(ffi::FFI_STATUS_ERR, ErrorCode::NotFound as i32);
    assert_ne!(ffi::FFI_STATUS_ERR, ErrorCode::AlreadyExists as i32);
}

#[test]
fn write_options_undersized_struct_size_is_rejected() {
    let original = WriteOptions {
        if_dest: IfDestExists::Overwrite,
        size_hint: None,
        user_metadata: None,
        message: None,
    };
    let mut ffi_value = options::write_options_to_ffi(original);
    ffi_value.struct_size = 0x10;
    let err = unsafe { options::write_options_from_ffi(ffi_value).unwrap_err() };
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
    assert!(err.message().contains("WriteOptions"));
}

#[test]
fn delete_options_undersized_struct_size_is_rejected() {
    let original = DeleteOptions { if_match: None };
    let mut ffi_value = options::delete_options_to_ffi(original);
    ffi_value.struct_size = 0x4;
    let err = unsafe { options::delete_options_from_ffi(ffi_value).unwrap_err() };
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
    assert!(err.message().contains("DeleteOptions"));
}

#[test]
fn list_options_undersized_struct_size_is_rejected() {
    let original = ListOptions {
        recursive: false,
        max_results: None,
        page_token: None,
        full_metadata: false,
    };
    let mut ffi_value = options::list_options_to_ffi(original);
    ffi_value.struct_size = 0x10;
    let err = unsafe { options::list_options_from_ffi(ffi_value).unwrap_err() };
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
    assert!(err.message().contains("ListOptions"));
}

#[test]
fn update_metadata_options_undersized_struct_size_is_rejected() {
    let original = UpdateMetadataOptions {
        if_match: None,
        allow_rewrite_emulation: false,
        user_metadata_set: HashMap::new(),
        user_metadata_remove: Vec::new(),
        message: None,
    };
    let mut ffi_value = options::update_metadata_options_to_ffi(original);
    ffi_value.struct_size = 0x10;
    let err = unsafe { options::update_metadata_options_from_ffi(ffi_value).unwrap_err() };
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
    assert!(err.message().contains("UpdateMetadataOptions"));
}

#[test]
fn watch_directory_options_undersized_struct_size_is_rejected() {
    let original = WatchDirectoryOptions {
        recursive: false,
        include_metadata_changes: false,
        since: None,
        poll_interval: std::time::Duration::from_millis(100),
    };
    let mut ffi_value = options::watch_directory_options_to_ffi(original);
    ffi_value.struct_size = 0x10;
    let err = unsafe { options::watch_directory_options_from_ffi(ffi_value).unwrap_err() };
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
    assert!(err.message().contains("WatchDirectoryOptions"));
}

#[test]
fn stat_options_undersized_struct_size_is_rejected() {
    let mut ffi_value = options::stat_options_to_ffi(StatOptions {
        full_metadata: false,
    });
    ffi_value.struct_size = 0x4;
    let err = options::stat_options_from_ffi(ffi_value).unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
    assert!(err.message().contains("StatOptions"));
    assert!(err.message().contains("struct_size"));
}

#[test]
fn list_versions_options_undersized_struct_size_is_rejected() {
    let mut ffi_value = options::list_versions_options_to_ffi(ListVersionsOptions {
        max_results: None,
        page_token: None,
    });
    ffi_value.struct_size = 0x10;
    let err = unsafe { options::list_versions_options_from_ffi(ffi_value).unwrap_err() };
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
    assert!(err.message().contains("ListVersionsOptions"));
}

#[test]
fn create_directory_options_undersized_struct_size_is_rejected() {
    let mut ffi_value = options::create_directory_options_to_ffi(CreateDirectoryOptions {});
    ffi_value.struct_size = 0x4;
    let err = options::create_directory_options_from_ffi(ffi_value).unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
    assert!(err.message().contains("CreateDirectoryOptions"));
}

#[test]
fn delete_directory_options_undersized_struct_size_is_rejected() {
    let mut ffi_value = options::delete_directory_options_to_ffi(DeleteDirectoryOptions);
    ffi_value.struct_size = 0x4;
    let err = unsafe { options::delete_directory_options_from_ffi(ffi_value).unwrap_err() };
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
    assert!(err.message().contains("DeleteDirectoryOptions"));
}

#[test]
fn copy_options_undersized_struct_size_is_rejected() {
    let mut ffi_value = options::copy_options_to_ffi(CopyOptions {
        if_source: None,
        if_dest: IfDestExists::Overwrite,
        message: None,
    });
    ffi_value.struct_size = 0x10;
    let err = unsafe { options::copy_options_from_ffi(ffi_value).unwrap_err() };
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
    assert!(err.message().contains("CopyOptions"));
}

#[test]
fn rename_options_undersized_struct_size_is_rejected() {
    let mut ffi_value = options::rename_options_to_ffi(RenameOptions {
        if_source: None,
        if_dest: IfDestExists::Overwrite,
        message: None,
    });
    ffi_value.struct_size = 0x10;
    let err = unsafe { options::rename_options_from_ffi(ffi_value).unwrap_err() };
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
    assert!(err.message().contains("RenameOptions"));
}

#[test]
fn secret_bytes_from_ffi_round_trips_the_plaintext() {
    let plaintext = vec![0xAA, 0xBB, 0xCC, 0xDD];
    let ffi_value = descriptor::secret_bytes_to_ffi(SecretBytes(plaintext.clone()));
    let secret = unsafe { descriptor::secret_bytes_from_ffi(ffi_value) };
    assert_eq!(secret.as_bytes(), plaintext.as_slice());
}

/// The ABI buffer must carry no cleartext into the allocator's free list.
/// Inspecting it requires holding the `ffi::Bytes` past the copy, so this
/// drives the wipe step directly rather than through
/// `secret_bytes_from_ffi`, which releases the buffer on the way out.
#[test]
fn taking_secret_bytes_wipes_the_abi_buffer() {
    let plaintext = vec![0xAA, 0xBB, 0xCC, 0xDD];
    let mut ffi_value = descriptor::secret_bytes_to_ffi(SecretBytes(plaintext.clone()));
    let taken = unsafe { descriptor::take_secret_bytes(&mut ffi_value.bytes) };
    assert_eq!(taken, plaintext);

    // SAFETY: `ffi_value` still owns its buffer; only the contents changed.
    let residue = unsafe { std::slice::from_raw_parts(ffi_value.bytes.ptr, ffi_value.bytes.len) };
    assert!(
        residue.iter().all(|byte| *byte == 0),
        "secret plaintext survives in the ABI buffer: {residue:02x?}"
    );
}

/// The outbound mirror of `taking_secret_bytes_wipes_the_abi_buffer`: the
/// `Vec` a secret is copied out of must carry no cleartext into the global
/// allocator's free list either. `secret_bytes_to_ffi` consumes its source,
/// so this drives the wipe step directly to keep the source inspectable.
#[test]
fn putting_secret_bytes_wipes_the_source_buffer() {
    let plaintext = vec![0xAA, 0xBB, 0xCC, 0xDD];
    let mut source = plaintext.clone();
    let ffi_bytes = descriptor::put_secret_bytes(&mut source);

    // SAFETY: `ffi_bytes` owns a live ABI buffer of `len` bytes.
    let copied = unsafe { std::slice::from_raw_parts(ffi_bytes.ptr, ffi_bytes.len) };
    assert_eq!(copied, plaintext.as_slice());

    // `Vec::zeroize` clears the whole capacity and truncates, so inspect the
    // spare capacity rather than just the (now empty) live region.
    let residue = unsafe { std::slice::from_raw_parts(source.as_ptr(), source.capacity()) };
    assert!(
        residue.iter().all(|byte| *byte == 0),
        "secret plaintext survives in the source buffer: {residue:02x?}"
    );
}

// ---------------------------------------------------------------------
// Secret residue on release
//
// The wipe lives in `ffi::SecretBytes::drop`, so it covers paths that never
// reach a conversion: a decode that fails partway, and a panic unwinding
// through a partly-consumed structure.
//
// Observation is through `ffi::secrets_auth::released_secrets`, a test-only
// witness that records the buffer from inside `Drop` — after the wipe, while
// the value still owns the allocation. Nothing here reads freed or
// uninitialized memory, and nothing depends on how the allocator recycles a
// block. The record is thread-local, so these tests measure only what they
// themselves released and stay correct under the parallel harness.
// ---------------------------------------------------------------------

// `released_secrets` is the test-only witness inside `ffi::secrets_auth`,
// reached through that module's glob re-export.
use crate::ffi::released_secrets;

/// A plaintext distinctive enough to spot in a recorded buffer.
const SECRET_PROBE: [u8; 128] = [0xA5; 128];

fn probe_secret_bytes() -> ffi::SecretBytes {
    descriptor::secret_bytes_to_ffi(SecretBytes(SECRET_PROBE.to_vec()))
}

/// Every secret this thread released since the last drain, with the plain
/// requirement that there was at least one and none of them held plaintext.
fn assert_released_secrets_are_clean(expected: usize, what: &str) {
    let released = released_secrets::take();
    assert_eq!(
        released.len(),
        expected,
        "expected {expected} secret(s) to be released by {what}, saw {}",
        released.len(),
    );
    for buffer in &released {
        assert!(
            buffer.iter().all(|byte| *byte == 0),
            "secret plaintext survived into release by {what}: {buffer:02x?}"
        );
    }
}

/// `wipe` clears in place without releasing, which is the half `Drop`
/// reuses.
#[test]
fn ffi_secret_bytes_wipe_clears_in_place() {
    let mut secret = probe_secret_bytes();
    secret.wipe();

    // SAFETY: `secret` still owns its buffer; only the contents changed.
    let live = unsafe { std::slice::from_raw_parts(secret.bytes.ptr, secret.bytes.len) };
    assert!(
        live.iter().all(|byte| *byte == 0),
        "wipe left plaintext behind: {live:02x?}"
    );
}

/// Dropping an FFI secret must clear it before the ABI allocator reclaims
/// the block. This is the path `secret_put` takes: it lends the buffer to
/// the host and then drops it, converting nothing.
#[test]
fn dropping_ffi_secret_bytes_clears_the_block_it_releases() {
    let _ = released_secrets::take();
    drop(probe_secret_bytes());
    assert_released_secrets_are_clean(1, "a plain drop");
}

/// A bundle whose field name is invalid UTF-8 fails in `str_from_ffi`
/// before the entry's secret is converted. The unconverted secret is
/// dropped, and must still be cleared.
#[test]
fn secret_bundle_decode_failure_clears_the_unconverted_secret() {
    let _ = released_secrets::take();
    let secret = probe_secret_bytes();

    let entries = primitive::list_to_ffi(vec![secret], |secret| ffi::SecretBundleEntry {
        // Invalid UTF-8: the decode fails on the field name, leaving
        // `value` unconverted.
        field: ffi::Str {
            ptr: crate::ffi::abi_alloc::abi_slice_into_raw(&[0xFFu8, 0xFE])
                as *mut std::os::raw::c_char,
            len: 2,
        },
        value: ffi::SecretValue::from_bytes(secret),
    });
    let error = unsafe { descriptor::secret_bundle_from_ffi(ffi::SecretBundle { entries }) }
        .expect_err("an invalid UTF-8 field name must fail the decode");
    assert_eq!(error.code(), ErrorCode::InvalidArgument);

    assert_released_secrets_are_clean(1, "a failed secret-bundle decode");
}

/// A panic unwinding through a live FFI secret has the same exposure as an
/// early return, and the same cleanup covers it.
///
/// The witness records from inside `Drop`, so this observes the unwind's own
/// cleanup directly — no allocator counter, and nothing the panic
/// machinery's own allocations can perturb.
#[test]
fn panic_unwinding_through_an_ffi_secret_clears_it() {
    let _ = released_secrets::take();

    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _held = probe_secret_bytes();
        panic!("unwind past a live FFI secret");
    }));
    assert!(unwound.is_err(), "the closure must have unwound");

    assert_released_secrets_are_clean(1, "a panic unwind");
}

/// Every `RedirectCredential` value survives the FFI boundary as itself.
///
/// The two `RedirectScope` round-trips above set only `Request` and
/// `Connection`, so `None` and `Unspecified` never cross — and those are the two
/// whose confusion is a disclosure. A swapped arm mapping `Unspecified => None`
/// would make every OpenDAL and Omniverse Storage Service redirect delegable
/// under the default policy, because both declare `Unspecified` precisely
/// *because* they cannot classify what they forward. Both existing round-trips
/// would still pass.
///
/// So this walks all four in both directions, and separately pins the
/// discriminants, since the FFI contract is the numbers and a host on the other
/// side of the boundary reads those rather than the names.
#[test]
fn every_redirect_credential_survives_the_ffi_round_trip_as_itself() {
    let all = [
        (RedirectCredential::Unspecified, 0i32),
        (RedirectCredential::None, 1),
        (RedirectCredential::Request, 2),
        (RedirectCredential::Connection, 3),
    ];

    for (value, discriminant) in all {
        let ffi = super::redirect::redirect_credential_to_ffi(value);
        assert_eq!(
            ffi as i32, discriminant,
            "{value:?} must marshal to discriminant {discriminant}; the wire \
             contract is the number, not the name"
        );
        assert_eq!(
            super::redirect::redirect_credential_from_ffi(ffi),
            value,
            "{value:?} did not survive the round trip"
        );
    }

    // Anti-vacuity: the mapping must be injective. A `to_ffi` that collapsed
    // two values onto one discriminant would still satisfy the round trip if
    // `from_ffi` collapsed them the same way, and the fail-safe distinction
    // between "declared nothing" and "declared no credential" would be gone.
    let mut discriminants: Vec<i32> = all
        .iter()
        .map(|(value, _)| super::redirect::redirect_credential_to_ffi(*value) as i32)
        .collect();
    discriminants.sort_unstable();
    discriminants.dedup();
    assert_eq!(
        discriminants.len(),
        4,
        "two credential values share an FFI discriminant, so one is unrecoverable \
         on the far side of the boundary"
    );
}
