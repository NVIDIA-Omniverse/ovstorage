// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The C-ABI error projection, checked where it is lossy.
//!
//! `marshal::error::code_to_ffi` needs a trailing `_` arm because `ErrorCode`
//! is `#[non_exhaustive]` and defined in another crate. That arm is a hazard,
//! not a safety net: a code added without an explicit arm compiles clean and
//! is silently downgraded to `Internal` on the way across the boundary, which
//! is indistinguishable from a generic internal error and defeats the point of
//! having a distinct code. Nothing in the compiler catches it, so these tests
//! do.

use ovstorage_plugin::marshal::error::{
    code_from_ffi, code_to_ffi, context_from_ffi, context_to_ffi,
};
use ovstorage_plugin::{ErrorCode, ErrorContext, PartialStage, RollbackEffect, StageOutcome, ffi};

/// Every code in `ErrorCode::KNOWN` survives the trip to the C ABI and back.
///
/// This is what catches a missing arm in `code_to_ffi`: without one, the code
/// maps to `ffi::ErrorCode::Internal` and comes back as `ErrorCode::Internal`,
/// so the assertion fails naming the offender.
#[test]
fn every_known_code_round_trips_through_the_ffi() {
    assert!(
        !ErrorCode::KNOWN.is_empty(),
        "KNOWN is empty, so this test asserts nothing",
    );
    for &code in ErrorCode::KNOWN {
        let round_tripped = code_from_ffi(code_to_ffi(code));
        assert_eq!(
            round_tripped, code,
            "{code:?} does not survive the C ABI round trip (it arrived as \
             {round_tripped:?}); `code_to_ffi` is probably missing an arm and \
             fell through to the `_` wildcard",
        );
    }
}

/// The round trip above already forces injectivity over `KNOWN` — a decoder
/// is single-valued, so two codes sharing a discriminant could not both decode
/// back to themselves. This asserts it directly anyway, because the round trip
/// proves it only for the codes `KNOWN` lists: a collision with a code outside
/// that slice would survive it, and the failure message here names both
/// offenders instead of one.
#[test]
fn known_codes_occupy_distinct_ffi_discriminants() {
    let mut seen = std::collections::HashMap::new();
    for &code in ErrorCode::KNOWN {
        let discriminant = code_to_ffi(code) as i32;
        if let Some(previous) = seen.insert(discriminant, code) {
            panic!("{code:?} and {previous:?} share FFI discriminant {discriminant}");
        }
    }
    assert_eq!(seen.len(), ErrorCode::KNOWN.len());
}

/// The wire contract is the discriminant number, not the name. Pin each one
/// so a reordering of the FFI enum is a test failure rather than a silent
/// reinterpretation by an already-built peer.
#[test]
fn partial_completion_discriminants_are_pinned() {
    assert_eq!(ffi::ErrorCode::PartialCompletion as i32, 40);
    assert_eq!(ffi::ErrorContextKindV1::Partial as i32, 2);

    // Zero is `Unspecified` on all three, so a zero-initialised struct asserts
    // nothing. `RollbackEffectV1` is the one that matters: at zero,
    // `RestoresPriorState` would tell a host that deleting durable data is
    // safe. These also match the broker wire enums one-for-one.
    assert_eq!(ffi::PartialStageV1::Unspecified as i32, 0);
    assert_eq!(ffi::PartialStageV1::ObjectData as i32, 1);
    assert_eq!(ffi::PartialStageV1::UserMetadata as i32, 2);
    assert_eq!(ffi::PartialStageV1::SourceRemoval as i32, 3);

    assert_eq!(ffi::StageOutcomeV1::Unspecified as i32, 0);
    assert_eq!(ffi::StageOutcomeV1::NotApplied as i32, 1);
    assert_eq!(ffi::StageOutcomeV1::Unknown as i32, 2);

    assert_eq!(ffi::RollbackEffectV1::Unspecified as i32, 0);
    assert_eq!(ffi::RollbackEffectV1::RestoresPriorState as i32, 1);
    assert_eq!(ffi::RollbackEffectV1::DestroysRequestedWork as i32, 2);
}

/// A C plugin that `memset`s or `calloc`s its `PartialErrorContextV1` must not
/// thereby assert that a destructive rollback is safe.
///
/// Named `Unspecified` rather than "zeroed" because that is what the test
/// constructs: `mem::zeroed` would be UB in exactly the scenario the memory
/// wording implies, since if `Unspecified` ever moved off zero the bytes would
/// be an invalid enum rather than a red test. What ties the two together is
/// `partial_completion_discriminants_are_pinned`, which holds `Unspecified` at
/// zero and reddens if it moves.
#[test]
fn an_all_unspecified_partial_context_is_refused() {
    // Named rather than `mem::zeroed`: zeroing would be UB in precisely the
    // scenario the memory-pattern version claims to catch, because if
    // `Unspecified` ever moved off zero the zeroed bytes would be an invalid
    // enum value rather than a red test. `partial_completion_discriminants_are_pinned`
    // is what holds `Unspecified` at zero, and it goes red on that move — so
    // the pair covers the property soundly and this test need not.
    let zeroed = ffi::ErrorContextV1::from_partial(ffi::PartialErrorContextV1 {
        completed: ffi::PartialStageV1::Unspecified,
        failed: ffi::PartialStageV1::Unspecified,
        failed_outcome: ffi::StageOutcomeV1::Unspecified,
        rollback: ffi::RollbackEffectV1::Unspecified,
    });
    // SAFETY: built by this test through the documented constructor.
    assert!(
        unsafe { context_from_ffi(zeroed) }.is_err(),
        "a zeroed partial context must be refused, not read as \
         RestoresPriorState",
    );

    // Only `rollback` unset, the rest valid — the narrow case, and the
    // dangerous one.
    let unset_rollback = ffi::ErrorContextV1::from_partial(ffi::PartialErrorContextV1 {
        completed: ffi::PartialStageV1::ObjectData,
        failed: ffi::PartialStageV1::SourceRemoval,
        failed_outcome: ffi::StageOutcomeV1::Unknown,
        rollback: ffi::RollbackEffectV1::Unspecified,
    });
    // SAFETY: as above.
    assert!(unsafe { context_from_ffi(unset_rollback) }.is_err());

    // Control: the same shape with `rollback` set does decode, so the
    // assertions above are about the unset field and not about the shape.
    let complete = ffi::ErrorContextV1::from_partial(ffi::PartialErrorContextV1 {
        completed: ffi::PartialStageV1::ObjectData,
        failed: ffi::PartialStageV1::SourceRemoval,
        failed_outcome: ffi::StageOutcomeV1::Unknown,
        rollback: ffi::RollbackEffectV1::RestoresPriorState,
    });
    // SAFETY: as above.
    assert!(unsafe { context_from_ffi(complete) }.is_ok());
}

fn round_trip(context: ErrorContext) -> ErrorContext {
    let encoded = context_to_ffi(&context);
    // SAFETY: `encoded` was produced by `context_to_ffi` immediately above,
    // which is exactly the precondition `context_from_ffi` documents.
    unsafe { context_from_ffi(encoded) }.expect("context decodes")
}

/// Walk every value of all three enums in both directions, rather than
/// spot-checking one shape: a subset round trip would stay green while an
/// unwalked variant was mis-mapped.
#[test]
fn every_partial_context_shape_round_trips_through_the_ffi() {
    let stages = [
        PartialStage::ObjectData,
        PartialStage::UserMetadata,
        PartialStage::SourceRemoval,
    ];
    let outcomes = [StageOutcome::NotApplied, StageOutcome::Unknown];
    let rollbacks = [
        RollbackEffect::RestoresPriorState,
        RollbackEffect::DestroysRequestedWork,
    ];

    let mut checked = 0usize;
    for completed in stages {
        for failed in stages {
            for failed_outcome in outcomes {
                for rollback in rollbacks {
                    let context = ErrorContext::Partial {
                        completed,
                        failed,
                        failed_outcome,
                        rollback,
                    };
                    assert_eq!(round_trip(context.clone()), context);
                    checked += 1;
                }
            }
        }
    }
    // Hardcoded, not recomputed from the same arrays the loop walks — a
    // product of their `len()`s can never disagree with the loop, so it would
    // assert nothing. 3 stages x 3 stages x 2 outcomes x 2 rollbacks. This
    // catches the arrays being SHRUNK; a newly added variant is caught by the
    // exhaustive `match`es in `marshal::error`, which stop compiling.
    assert_eq!(
        checked, 36,
        "the enumeration did not walk every combination"
    );
}

/// The claim the general error code is paying for: a rename emulated as
/// copy-then-delete whose delete failed is expressible in this payload, and
/// crosses the C ABI intact, **without a second error code**.
///
/// No in-tree producer emits this shape — the emulated rename still reports
/// `CommitAmbiguous` — so without this test the generality claim would rest
/// on prose alone.
#[test]
fn a_half_completed_move_crosses_the_abi_intact() {
    let move_case = ErrorContext::Partial {
        completed: PartialStage::ObjectData,
        failed: PartialStage::SourceRemoval,
        failed_outcome: StageOutcome::Unknown,
        rollback: RollbackEffect::RestoresPriorState,
    };
    assert_eq!(round_trip(move_case.clone()), move_case);

    // And it stays distinguishable from the metadata case on the far side —
    // the two want opposite remedies, so a projection that collapsed them
    // would be worse than useless.
    let metadata_case = ErrorContext::Partial {
        completed: PartialStage::ObjectData,
        failed: PartialStage::UserMetadata,
        failed_outcome: StageOutcome::NotApplied,
        rollback: RollbackEffect::DestroysRequestedWork,
    };
    assert_ne!(round_trip(move_case), round_trip(metadata_case));
}

/// The other two context variants must keep working: growing
/// `ErrorContextV1` by a slot moves the struct's layout, and the union's
/// active-slot discipline is hand-written.
#[test]
fn the_existing_context_variants_still_round_trip() {
    let identity = ErrorContext::Identity {
        new_etag: Some("etag-after-mismatch".to_string()),
    };
    assert_eq!(round_trip(identity.clone()), identity);

    let auth = ErrorContext::Auth {
        connection_id: ovstorage_plugin::ConnectionId("conn-7".to_string()),
        reason: Some("token_expired".to_string()),
        expired_at: None,
    };
    assert_eq!(round_trip(auth.clone()), auth);
}
