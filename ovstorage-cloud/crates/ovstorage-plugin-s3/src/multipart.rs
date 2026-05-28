// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Continuation state for the multipart `Write` redirect machine.
//! Encoded as self-describing JSON; the tag string rejects foreign continuations on decode.

use serde::{Deserialize, Serialize};

use ovstorage_plugin::{Error, ErrorCode, Result};

/// Tag used to refuse foreign-plugin continuation payloads.
const CONTINUATION_TAG: &str = "ovstorage-plugin-s3:multipart:1";

/// Envelope captured between batches; `parts` grows one entry per completed part.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultipartContinuation {
    pub tag: String,
    pub key: String,
    pub upload_id: String,
    pub user_metadata: Option<Vec<(String, String)>>,
    pub if_match: Option<String>,
    pub no_overwrite: bool,
    pub parts: Vec<MultipartPart>,
    pub total_parts: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultipartPart {
    pub part_number: u32,
    pub byte_offset: u64,
    pub byte_length: u64,
    pub etag: Option<String>,
}

impl MultipartContinuation {
    pub fn new(
        key: String,
        upload_id: String,
        user_metadata: Option<Vec<(String, String)>>,
        if_match: Option<String>,
        no_overwrite: bool,
        total_parts: u32,
    ) -> Self {
        Self {
            tag: CONTINUATION_TAG.to_string(),
            key,
            upload_id,
            user_metadata,
            if_match,
            no_overwrite,
            parts: Vec::with_capacity(total_parts as usize),
            total_parts,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("serde_json never fails for a struct without floats")
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let parsed: Self = serde_json::from_slice(bytes).map_err(|err| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!("S3 multipart continuation could not be decoded: {err}"),
            )
        })?;
        if parsed.tag != CONTINUATION_TAG {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "S3 multipart continuation tag does not match this plugin",
            ));
        }
        Ok(parsed)
    }
}

/// Target part size when free to choose. 32 MiB sits between common
/// SDK defaults (AWS CLI 8 MiB, aws-sdk-go 5 MiB) and AWS's
/// "100 MB+ for large objects" recommendation — balances per-part
/// RPC overhead against retry granularity and parallelism on
/// multi-GiB uploads.
pub const TARGET_PART_SIZE_BYTES: u64 = 32 * 1024 * 1024;

/// S3 minimum non-final part size (5 MiB); the final part may be smaller.
pub const MIN_PART_SIZE_BYTES: u64 = 5 * 1024 * 1024;

/// S3 single-part cap (5 GiB).
pub const MAX_PART_SIZE_BYTES: u64 = 5 * 1024 * 1024 * 1024;

/// S3 multipart max parts.
pub const S3_MAX_PARTS: u32 = 10_000;

/// Default part size for streaming an unknown-length body.
pub const DEFAULT_PART_SIZE_BYTES: u64 = 8 * 1024 * 1024;

/// `write_redirect` switches to multipart redirects at this size; init+complete round-trips dominate below it.
pub const MULTIPART_REDIRECT_THRESHOLD_BYTES: u64 = 100 * 1024 * 1024;

/// S3 object cap (5 TiB across all parts).
pub const MAX_OBJECT_SIZE_BYTES: u64 = 5 * 1024 * 1024 * 1024 * 1024;

/// Pick the number of parts for a multipart upload of `size` bytes.
///
/// Strategy: aim for ~[`TARGET_PART_SIZE_BYTES`] per part, then clamp
/// the count into the feasibility window:
///
/// - At least `ceil(size / MAX_PART_SIZE_BYTES)` parts so no single
///   part exceeds S3's 5 GiB single-part cap.
/// - At most `floor(size / MIN_PART_SIZE_BYTES)` parts so no
///   non-final part falls below S3's 5 MiB minimum (the final part
///   may be smaller — S3 exempts it — but the balanced split in
///   [`part_sizes`] keeps every part within `[base, base+1]` so the
///   floor bound is what matters).
/// - At most [`S3_MAX_PARTS`] (10 000) per S3's hard cap.
///
/// Returns `InvalidArgument` for uploads exceeding the 5 TiB
/// single-object limit, and `Internal` if part-count somehow
/// overflows `u32` (defensive — the `S3_MAX_PARTS` ceiling makes
/// this unreachable in practice).
pub fn compute_total_parts(size: u64) -> Result<u32> {
    if size > MAX_OBJECT_SIZE_BYTES {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("S3 object size {size} exceeds the 5 TiB single-object limit",),
        ));
    }
    let by_target = size.div_ceil(TARGET_PART_SIZE_BYTES).max(1);
    // Hard lower bound: enough parts so no single part exceeds the
    // 5 GiB single-part cap.
    let min_for_max = size.div_ceil(MAX_PART_SIZE_BYTES).max(1);
    // Hard upper bound: enough headroom so every part is >= 5 MiB
    // (we use `floor(size / min)` so the balanced split's `base`
    // satisfies the minimum). For `size < MIN_PART_SIZE_BYTES`, the
    // floor is 0; clamp to 1 so we always emit at least one part.
    let max_for_min = (size / MIN_PART_SIZE_BYTES).max(1);
    let count = by_target
        .clamp(min_for_max, max_for_min)
        .min(u64::from(S3_MAX_PARTS));
    u32::try_from(count).map_err(|_| Error::new(ErrorCode::Internal, "S3 part count overflows u32"))
}

/// Balanced base/remainder split of `total_size` into `total_parts`
/// pieces. Every part is `base` or `base+1` bytes; the first
/// `remainder` parts get the `+1`. Mirrors AWS's recommended
/// even-as-possible distribution and matches what reviewers expect.
pub fn part_sizes(total_size: u64, total_parts: u32) -> Vec<u64> {
    let n = u64::from(total_parts.max(1));
    let base = total_size / n;
    let rem = total_size % n;
    (0..n)
        .map(|i| if i < rem { base + 1 } else { base })
        .collect()
}

pub fn ensure_streaming_part_limit(next_part_number: u32) -> Result<()> {
    if next_part_number > S3_MAX_PARTS {
        return Err(Error::new(
            ErrorCode::Unsupported,
            "S3 streaming write exceeded the 10000-part limit",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIB: u64 = 1024 * 1024;
    const GIB: u64 = 1024 * MIB;

    #[test]
    fn continuation_round_trip() {
        let c = MultipartContinuation::new(
            "key".into(),
            "upload-id".into(),
            Some(vec![("x".into(), "y".into())]),
            None,
            false,
            3,
        );
        let bytes = c.encode();
        let decoded = MultipartContinuation::decode(&bytes).unwrap();
        assert_eq!(decoded.upload_id, "upload-id");
        assert_eq!(decoded.total_parts, 3);
        assert_eq!(decoded.user_metadata.as_ref().unwrap()[0].0, "x");
    }

    #[test]
    fn continuation_rejects_foreign_tag() {
        let bad = br#"{"tag":"someone-else","key":"k","upload_id":"u","user_metadata":null,"if_match":null,"no_overwrite":false,"parts":[],"total_parts":0}"#;
        let err = MultipartContinuation::decode(bad).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    // === compute_total_parts ===

    /// Sub-target uploads collapse to a single part. The 5 MiB floor
    /// applies only to *non-final* parts, so a 1 KiB upload is one
    /// 1 KiB part — completely legal.
    #[test]
    fn compute_total_parts_small_upload_picks_one_part() {
        assert_eq!(compute_total_parts(1024).unwrap(), 1);
        assert_eq!(compute_total_parts(0).unwrap(), 1);
        assert_eq!(compute_total_parts(1).unwrap(), 1);
    }

    /// An upload exactly equal to the target part size should still
    /// be a single part (`div_ceil(target, target) = 1`).
    #[test]
    fn compute_total_parts_exact_target_picks_one_part() {
        assert_eq!(compute_total_parts(TARGET_PART_SIZE_BYTES).unwrap(), 1);
    }

    /// 64 MiB = 2 × 32 MiB target.
    #[test]
    fn compute_total_parts_two_target_parts() {
        assert_eq!(compute_total_parts(2 * TARGET_PART_SIZE_BYTES).unwrap(), 2);
    }

    #[test]
    fn known_size_redirect_planning_targets_32_mib_parts() {
        let size = 96 * MIB;
        let parts = compute_total_parts(size).unwrap();
        assert_eq!(TARGET_PART_SIZE_BYTES, 32 * MIB);
        assert_eq!(parts, 3);
        assert_eq!(part_sizes(size, parts), vec![32 * MIB; 3]);
    }

    /// Headline case from the plan: 10 GiB / 32 MiB = 320 parts of
    /// ~32 MiB each, all within S3's [5 MiB, 5 GiB] window. The
    /// previous algorithm produced 2 parts of 5 GiB.
    #[test]
    fn compute_total_parts_10_gib_uses_target() {
        let parts = compute_total_parts(10 * GIB).unwrap();
        assert_eq!(parts, 320, "10 GiB / 32 MiB = 320 parts");
        let sizes = part_sizes(10 * GIB, parts);
        assert_eq!(sizes.iter().sum::<u64>(), 10 * GIB);
        assert!(
            sizes
                .iter()
                .all(|&p| (MIN_PART_SIZE_BYTES..=MAX_PART_SIZE_BYTES).contains(&p))
        );
    }

    /// 500 GiB at 32 MiB target wants 16 000 parts; clamp to S3's
    /// 10 000-part cap. Each part is ~50 MiB, still within
    /// [5 MiB, 5 GiB].
    #[test]
    fn compute_total_parts_500_gib_clamps_to_max_parts() {
        let parts = compute_total_parts(500 * GIB).unwrap();
        assert_eq!(parts, S3_MAX_PARTS);
        let sizes = part_sizes(500 * GIB, parts);
        assert_eq!(sizes.iter().sum::<u64>(), 500 * GIB);
        assert!(
            sizes
                .iter()
                .all(|&p| (MIN_PART_SIZE_BYTES..=MAX_PART_SIZE_BYTES).contains(&p))
        );
    }

    /// 5 TiB (S3's object cap) packs into exactly 10 000 parts of
    /// 512 MiB each.
    #[test]
    fn compute_total_parts_5_tib_packs_into_max_parts() {
        let parts = compute_total_parts(MAX_OBJECT_SIZE_BYTES).unwrap();
        assert_eq!(parts, S3_MAX_PARTS);
        let sizes = part_sizes(MAX_OBJECT_SIZE_BYTES, parts);
        assert_eq!(sizes.iter().sum::<u64>(), MAX_OBJECT_SIZE_BYTES);
        assert!(sizes.iter().all(|&p| p <= MAX_PART_SIZE_BYTES));
    }

    /// Above 5 TiB the single-object cap is breached.
    #[test]
    fn compute_total_parts_rejects_above_5_tib() {
        let err = compute_total_parts(MAX_OBJECT_SIZE_BYTES + 1).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    #[test]
    fn unknown_size_streaming_uses_8_mib_parts_and_enforces_part_limit() {
        assert_eq!(DEFAULT_PART_SIZE_BYTES, 8 * MIB);
        assert!(ensure_streaming_part_limit(S3_MAX_PARTS).is_ok());
        let err = ensure_streaming_part_limit(S3_MAX_PARTS + 1).unwrap_err();
        assert_eq!(err.code(), ErrorCode::Unsupported);
        assert!(err.message().contains("10000-part limit"));
    }

    /// 50 GiB at the 32 MiB target overshoots a single 5 GiB part
    /// (would need 10 parts of 5 GiB); the target dominates and we
    /// get 1600 parts.
    #[test]
    fn compute_total_parts_50_gib_uses_target() {
        let parts = compute_total_parts(50 * GIB).unwrap();
        let expected = u32::try_from(50 * GIB / TARGET_PART_SIZE_BYTES).unwrap();
        assert_eq!(parts, expected);
        let sizes = part_sizes(50 * GIB, parts);
        assert!(
            sizes
                .iter()
                .all(|&p| (MIN_PART_SIZE_BYTES..=MAX_PART_SIZE_BYTES).contains(&p))
        );
    }

    // === part_sizes balanced split ===

    /// Plan example: 11 bytes split into 3 parts. Old algorithm
    /// (ceil(11/3)=4 for all-but-last) gave 4/4/3 — final part
    /// below `MIN_PART_SIZE_BYTES`. Balanced split gives 4/4/3 as
    /// well at this small size, but the +1 distribution is what we
    /// want to verify here. base=11/3=3 rem=2 → 4/4/3.
    #[test]
    fn part_sizes_balanced_split_distributes_remainder() {
        assert_eq!(part_sizes(11, 3), vec![4, 4, 3]);
    }

    /// Evenly divisible: no remainder, every part equal.
    #[test]
    fn part_sizes_evenly_divisible() {
        assert_eq!(part_sizes(30, 3), vec![10, 10, 10]);
    }

    /// Sum invariant: regardless of (size, parts), sum of part_sizes
    /// always equals total size.
    #[test]
    fn part_sizes_sum_invariant() {
        for size in [0u64, 1, 100, 1024, 7 * MIB, 13 * GIB, MAX_OBJECT_SIZE_BYTES] {
            let parts = compute_total_parts(size).unwrap();
            assert_eq!(
                part_sizes(size, parts).iter().sum::<u64>(),
                size,
                "part_sizes must sum to {size} for {parts} parts",
            );
        }
    }

    /// All parts within [base, base+1] — the balanced-split
    /// guarantee.
    #[test]
    fn part_sizes_within_one_byte() {
        let sizes = part_sizes(100, 7);
        let base = 100 / 7;
        for s in &sizes {
            assert!(
                *s == base || *s == base + 1,
                "part {s} not in [{base}, {}]",
                base + 1
            );
        }
    }

    /// `total_parts = 0` should be safe (defensive — call sites use
    /// `compute_total_parts` which guarantees `>= 1`, but the helper
    /// itself must not panic on a `0`).
    #[test]
    fn part_sizes_zero_parts_does_not_panic() {
        let _ = part_sizes(10, 0); // treats as 1 part internally
    }

    /// Multipart write part size is never below the S3 minimum
    /// `MIN_PART_SIZE_BYTES` for any non-final part — the balanced
    /// split's `base` value, when `total_parts` was picked by
    /// `compute_total_parts`, satisfies `base >= MIN_PART_SIZE_BYTES`.
    #[test]
    fn compute_total_parts_keeps_base_above_min() {
        for size in [100 * MIB, GIB, 10 * GIB, 100 * GIB, 500 * GIB] {
            let parts = compute_total_parts(size).unwrap();
            let sizes = part_sizes(size, parts);
            let base = size / u64::from(parts);
            assert!(
                base >= MIN_PART_SIZE_BYTES,
                "base part size {base} for size={size} parts={parts} violates {MIN_PART_SIZE_BYTES} floor",
            );
            assert!(sizes.iter().all(|&p| p >= MIN_PART_SIZE_BYTES));
        }
    }

    /// No single part may exceed `MAX_PART_SIZE_BYTES` (5 GiB).
    #[test]
    fn compute_total_parts_never_exceeds_max_part_size() {
        for size in [GIB, 10 * GIB, 100 * GIB, 500 * GIB, MAX_OBJECT_SIZE_BYTES] {
            let parts = compute_total_parts(size).unwrap();
            let sizes = part_sizes(size, parts);
            assert!(
                sizes.iter().all(|&p| p <= MAX_PART_SIZE_BYTES),
                "size={size} parts={parts}: some part exceeds {MAX_PART_SIZE_BYTES}",
            );
        }
    }
}
