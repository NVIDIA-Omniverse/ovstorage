// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The accepted-URL-spellings contract between a backend connection and the
//! alias layer.
//!
//! A storage backend has exactly one canonical address form — `s3://bucket/…`,
//! `azure://account/container/…`, `hf://models/owner/name/…`. The ordinary
//! URLs that name the same data (`https://bucket.s3.us-west-2.amazonaws.com/…`,
//! `https://huggingface.co/owner/name/…`) are the alias layer's job, but only
//! the backend's own config code can derive them correctly: the endpoint
//! shapes live next to the code that signs requests against them.
//! The two sides meet in `Connection.user_metadata`, which already crosses the
//! plugin ABI:
//!
//! - A backend that wants ordinary URLs for its data to resolve stamps
//!   [`ACCEPTED_URL_SPELLINGS_METADATA_KEY`] onto the `Connection` rows it
//!   constructs, valued as the [`encode_url_spellings`] joining of the URL
//!   prefixes it accepts as alternate spellings of its advertised root.
//! - The alias wrapper, when it delegates a registration downward and the
//!   returned row carries the key, installs one **hidden** alias rule per
//!   spelling (`from = spelling`, `to =` the connection's advertised root) and
//!   withdraws them when the connection is removed. Derived rules are marked
//!   with [`ALIAS_DERIVED_FROM_METADATA_KEY`] so a host reading
//!   `list_connections` can tell them from operator-authored rules.
//!
//! The value format is deliberately trivial: canonical URL prefixes joined by
//! `\n`. A canonical URL cannot contain a raw newline (the address layer
//! percent-encodes control bytes), so no quoting is needed. Both sides share
//! [`encode_url_spellings`]/[`decode_url_spellings`] so the framing cannot
//! drift.
//!
//! What belongs in the set is governed by one test — *"what URL could a user
//! plausibly be holding?"* — not "what can an SDK emit". A spelling that names
//! a different resource (an access point, a website endpoint) must never be
//! included: aliasing it to the bucket would be incorrect rather than merely
//! noisy.

use crate::Url;

/// Reserved `Connection.user_metadata` key: the alternate URL prefixes a
/// backend connection accepts as spellings of its advertised root, joined by
/// `\n` ([`encode_url_spellings`]). Read by the alias wrapper at registration
/// to auto-generate hidden alias rules; ignored everywhere else.
pub const ACCEPTED_URL_SPELLINGS_METADATA_KEY: &str =
    "org.omniverse.ovstorage/accepted-url-spellings";

/// Reserved `user_metadata` key stamped by the alias wrapper on the alias-rule
/// connections it derives from a backend's accepted spellings, valued
/// `<owning target>/<connection id>` of the backend connection the rule was
/// derived from. Presence distinguishes a generated rule from an
/// operator-authored one in `list_connections` output.
pub const ALIAS_DERIVED_FROM_METADATA_KEY: &str = "org.omniverse.ovstorage/alias-derived-from";

/// Query keys a generated alias rule carries through to the backend.
///
/// The backends read a version selector off the address query and nothing
/// else — S3 `versionId`, Azure `versionid` (and its `versionId` spelling),
/// GCS `generation`, Hugging Face `revision` (a git ref or commit sha naming
/// one snapshot of the same repository). These name a version of the same
/// object, so a generated rule answering one is still answering for the
/// address it spells, and the anonymous scheme fallback (which consults the
/// same list through [`generated_rule_may_answer`]) still reaches the object a
/// caller pinned. The list decides only whether the address is routed; a
/// backend that does not read a listed key ignores or refuses it on its own
/// terms. The spellings the rules are generated from reach the wrapper under
/// [`ACCEPTED_URL_SPELLINGS_METADATA_KEY`], joined by [`encode_url_spellings`].
pub const CARRIED_QUERY_KEYS: [&str; 4] = ["versionId", "versionid", "generation", "revision"];

/// Whether a GENERATED alias rule may answer `addr`.
///
/// Generated rules are selected on scheme + host + path prefix, and a rewrite
/// carries the caller's query through to the backend — where a cloud plugin
/// reads its version selector and ignores everything else. That combination
/// is safe for the URLs generation exists to serve, and not for one class:
/// a **credential-bearing** URL.
///
/// An S3 presigned URL or an Azure SAS URL authenticates itself with its query
/// (`X-Amz-Signature`, `sig`, …) and grants exactly what it was signed for.
/// Rewritten onto the canonical `s3://` / `azure://` form, those parameters
/// stop meaning anything and the connection's own configured credentials
/// authenticate instead — so an expired, revoked, forged, or deliberately
/// narrow URL would be served as a full privileged read. The caller asked for
/// access *by that signature*; answering with the operator's keys is not a
/// more convenient spelling of the same request, it is a different one.
///
/// So a generated rule stands aside for any query it does not recognize, and
/// the address falls through to whatever else routes it — an HTTP layer that
/// will honour the signature, or no route at all. Withholding costs a
/// convenience; answering would substitute an authority the caller never
/// presented.
///
/// **Operator-authored rules are unaffected.** Writing one is a deliberate act
/// that says "this prefix means that target"; generation is a default applied
/// on the operator's behalf, and a default does not get to make this call.
pub fn generated_rule_may_answer(addr: &Url) -> bool {
    match addr.query() {
        None => true,
        Some(query) => query
            .split('&')
            .filter(|piece| !piece.is_empty())
            .all(|piece| {
                let key = piece.split_once('=').map_or(piece, |(key, _)| key);
                CARRIED_QUERY_KEYS.contains(&key)
            }),
    }
}

/// Join URL prefixes into the [`ACCEPTED_URL_SPELLINGS_METADATA_KEY`] value.
pub fn encode_url_spellings<'a>(urls: impl IntoIterator<Item = &'a Url>) -> String {
    urls.into_iter()
        .map(Url::as_str)
        .collect::<Vec<_>>()
        .join("\n")
}

/// Split an [`ACCEPTED_URL_SPELLINGS_METADATA_KEY`] value back into its
/// entries. Tolerates blank lines and surrounding whitespace so a
/// hand-assembled value (a foreign plugin is free to stamp the key) does not
/// silently drop its neighbours; entries are NOT parsed or validated here —
/// the consumer validates each one exactly as it validates an operator-written
/// alias rule.
pub fn decode_url_spellings(value: &str) -> impl Iterator<Item = &str> {
    value
        .lines()
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn may_answer(spelling: &str) -> bool {
        generated_rule_may_answer(&Url::parse(spelling).unwrap())
    }

    /// A credential-bearing URL authenticates itself; a generated rule that
    /// answered it would substitute the connection's credentials for the
    /// signature the caller presented.
    #[test]
    fn a_generated_rule_declines_a_credential_bearing_url() {
        for signed in [
            // S3 presigned (SigV4), and the shape with the signature last.
            "https://bucket.s3.us-west-2.amazonaws.com/k?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature=deadbeef",
            "https://bucket.s3.us-west-2.amazonaws.com/k?X-Amz-Expires=60",
            // Azure SAS.
            "https://acct.blob.core.windows.net/c/k?sv=2021-08-06&sig=abc",
            "https://acct.blob.core.windows.net/c/k?se=2026-01-01T00:00:00Z",
            // A version selector alongside anything unrecognized still
            // declines: the unrecognized key is the one that matters.
            "https://bucket.s3.us-west-2.amazonaws.com/k?versionId=v1&sig=abc",
            // A Hub download link: `download` is not a version selector, so
            // the rule stands aside even though nothing here is a credential.
            "https://huggingface.co/acme/demo/resolve/main/config.json?download=true",
            "https://huggingface.co/acme/demo/config.json?revision=main&download=true",
        ] {
            assert!(!may_answer(signed), "must decline: {signed}");
        }
    }

    /// A version selector names a version of the same object, which is still
    /// the address the spelling spells.
    #[test]
    fn a_generated_rule_answers_a_plain_or_version_pinned_url() {
        for ordinary in [
            "https://bucket.s3.us-west-2.amazonaws.com/k",
            "https://bucket.s3.us-west-2.amazonaws.com/k?versionId=v1",
            "https://acct.blob.core.windows.net/c/k?versionid=2026-01-01",
            "https://bucket.s3.us-west-2.amazonaws.com/k?versionId=a&versionid=b",
            // GCS pins an object version with `generation`; the anonymous
            // scheme fallback consults this same list, so a pinned `gs://`
            // address must still reach the object the caller named.
            "gs://bucket/k?generation=1700000000000000",
            // Hugging Face pins a repository snapshot with `revision`; the
            // plugin's own pinned list children project back onto the
            // generated spelling and must dereference again through it.
            "https://huggingface.co/acme/demo/config.json?revision=main",
            "hf://models/acme/demo/config.json?revision=refs%2Fpr%2F1",
        ] {
            assert!(may_answer(ordinary), "must answer: {ordinary}");
        }
    }

    /// An empty query is not a credential.
    #[test]
    fn a_generated_rule_answers_an_empty_query() {
        assert!(may_answer("https://bucket.s3.us-west-2.amazonaws.com/k?"));
    }

    #[test]
    fn spellings_round_trip_through_the_metadata_value() {
        let urls = vec![
            Url::parse("https://bucket.s3.us-west-2.amazonaws.com/").unwrap(),
            Url::parse("https://s3.us-west-2.amazonaws.com/bucket/").unwrap(),
        ];
        let encoded = encode_url_spellings(&urls);
        let decoded: Vec<&str> = decode_url_spellings(&encoded).collect();
        assert_eq!(
            decoded,
            urls.iter().map(Url::as_str).collect::<Vec<_>>(),
            "decode(encode(x)) == x"
        );
    }

    #[test]
    fn decode_tolerates_blank_lines_and_padding() {
        let decoded: Vec<&str> =
            decode_url_spellings("\n  https://a.example/ \n\nhttps://b.example/\n").collect();
        assert_eq!(decoded, vec!["https://a.example/", "https://b.example/"]);
    }

    #[test]
    fn empty_value_decodes_to_nothing() {
        assert_eq!(decode_url_spellings("").count(), 0);
        assert_eq!(encode_url_spellings([]), "");
    }
}
