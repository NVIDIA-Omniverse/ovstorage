// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Redaction for values that reach `tracing` events.
//!
//! The transports carry credentials in two shapes. Request and response bodies
//! carry them as JSON fields — `Tokens.auth_with_api_token` sends a literal API
//! token as a parameter, and the corresponding response envelope carries
//! `access_token` and `refresh_token`. Connection URLs carry them as query
//! parameters when a caller splices one in.
//!
//! Both shapes are handled by keeping the body out of the event entirely (the
//! logging sites emit only structured metadata) and by passing every URL
//! through [`redact_url`] before it becomes a field value.
//!
//! `redact_url` is a lexical transform over a URL's userinfo and its delimited
//! parameters, covering both the query and the fragment. It does not parse the
//! URL, and the only thing it decodes is a parameter *name*, which it resolves
//! one percent-decoding pass deep before matching it against the list below.
//! So these all defeat it, each verified by test:
//!
//! - a credential in a path segment, or as the value of a parameter this list
//!   does not name;
//! - the tail of an unencoded credential that itself contains `&` or `#`,
//!   which splits into parameters indistinguishable from real ones;
//! - a userinfo password containing an unencoded `/`, `?` or `#` — the
//!   authority ends at the first of those, so the `@` falls outside it and the
//!   password is not seen at all. `/` is in the base64 alphabet, so this is
//!   reachable with an ordinary secret that was not percent-encoded. It is the
//!   userinfo counterpart of the `&`/`#` case above, and worse: the whole
//!   value survives rather than a tail. Nothing lexical can separate it from
//!   `wss://h/alice@example.com/p`, where the `@` really is in the path;
//! - a parameter name whose escapes survive that one pass
//!   (`access%255Ftoken=`), which decodes to `access%5Ftoken` rather than to a
//!   listed name. One pass is what a server does too, so a name needing two is
//!   not a name a server reads as `access_token` either;
//! - a legacy `;`-delimited query, which is not split into parameters;
//! - a credential nested inside a benign parameter's encoded value.
//!
//! It removes the spelling a caller reaches for by habit. It is not a proof
//! that no credential reaches a log, and a caller must not treat it as a
//! licence to put one in a URL.
//!
//! Being lexical is also what makes it total: every input yields a redacted
//! output. A parse-based redactor needs an answer for the URL it cannot parse,
//! and the tempting answer — log the original — discloses precisely the input
//! nobody modelled.
//!
//! The `ovstorage-layer` crate carries a richer redactor of the same name. The
//! `nucleus-*` crates are omni1 protocol bindings that depend on no ovstorage
//! crate, so this one stands alone deliberately. Its parameter-name list is a
//! superset of that redactor's generic token names, and both redact userinfo.

use tokio_tungstenite::tungstenite::Message;

/// Query-parameter names whose values are replaced in a logged URL.
///
/// Matched case-insensitively against the whole parameter name, so `token`
/// does not stand in for `page_token`: a continuation cursor is not a
/// credential and redacting it would cost real diagnostic value.
///
/// A name belongs here when possessing its value lets a holder authenticate,
/// and it stays out when the value only identifies or paginates. Matching is
/// exact, so a new spelling needs its own entry — adding `bearer_token` does
/// not follow from `token` being present.
///
/// The two costs are not symmetric, which is why the cloud-provider signing
/// parameters are listed even though a Nucleus URL is not expected to carry
/// one: redacting a name that never appears costs nothing, while missing one
/// that does puts a credential in a log. What keeps the list from growing
/// without limit is the other cost — a name whose value a reader of the log
/// needs, such as `page_token`, stays out however token-shaped it reads.
///
/// `every_listed_parameter_is_covered` pins this list against a literal copy,
/// so removing an entry fails a test rather than silently widening what
/// reaches a log.
const CREDENTIAL_PARAMS: &[&str] = &[
    "access_token",
    "api_key",
    "api_token",
    "apikey",
    "auth",
    "auth_token",
    "authorization",
    "client_secret",
    "code",
    "credential",
    "id_token",
    "passwd",
    "password",
    "pw",
    "refresh_token",
    "sas",
    "sas_token",
    "secret",
    "session_token",
    // Azure spells its shared-access signature `sig`; `signature` alone would
    // miss it.
    "sig",
    "signature",
    "token",
];

/// What replaces a credential value. Naming the parameter but not its value
/// keeps the event useful for diagnosis — "the token was present" is the fact
/// a reader of the log actually needs.
const PLACEHOLDER: &str = "REDACTED";

fn names_a_credential(name: &str) -> bool {
    CREDENTIAL_PARAMS
        .iter()
        .any(|candidate| name.eq_ignore_ascii_case(candidate))
}

/// Whether `name` names a credential either as written or once decoded.
///
/// `access%5Ftoken` is the same parameter as `access_token` to any server that
/// reads it, because a server percent-decodes the name before looking it up.
/// Matching only the bytes as written would let that spelling carry a
/// credential past the list and into a log.
///
/// Both spellings are tried rather than only the decoded one: a name is not
/// required to be well-formed percent-encoding, and one that is not gets
/// matched as written.
fn is_credential_param(name: &str) -> bool {
    names_a_credential(name)
        || percent_decoded(name).is_some_and(|decoded| names_a_credential(&decoded))
}

/// `name` with its percent escapes resolved, or `None` when it has none to
/// resolve.
///
/// One pass, and total over arbitrary input: a `%` that does not open a
/// well-formed escape is kept literally rather than treated as an error, so
/// there is no input this refuses and no input on which the caller has to
/// choose between logging the original and logging nothing.
///
/// Only escapes naming ASCII resolve; one naming a byte above `0x7F` is kept
/// as written. That choice cannot change a decision in either direction —
/// every name in [`CREDENTIAL_PARAMS`] is ASCII, and resolving such an escape
/// would yield a non-ASCII character, so neither form can equal a listed name.
/// What it buys is that the decoded name is an ASCII view of what the caller
/// wrote rather than a transliteration of it, and that nothing here has to
/// reassemble a multi-byte sequence spread over several escapes.
///
/// The decoded name is only ever used to *decide*. What goes into the log is
/// the name the caller wrote, so a URL keeps its own spelling.
fn percent_decoded(name: &str) -> Option<String> {
    if !name.contains('%') {
        return None;
    }
    let mut decoded = String::with_capacity(name.len());
    let mut rest = name;
    while let Some(percent) = rest.find('%') {
        decoded.push_str(&rest[..percent]);
        let escape = &rest[percent + 1..];
        match ascii_escape(escape) {
            // Both digits are ASCII hex, so `2` is a char boundary.
            Some(character) => {
                decoded.push(character);
                rest = &escape[2..];
            }
            None => {
                decoded.push('%');
                rest = escape;
            }
        }
    }
    decoded.push_str(rest);
    Some(decoded)
}

/// The ASCII character named by the two hex digits `escape` opens with, if it
/// opens with two that name one.
fn ascii_escape(escape: &str) -> Option<char> {
    let digits = escape.as_bytes().get(..2)?;
    let value = char::from(digits[0]).to_digit(16)? * 16 + char::from(digits[1]).to_digit(16)?;
    (value < 0x80).then(|| char::from(value as u8))
}

/// `url` with the password in its userinfo replaced, if it carries one.
///
/// `wss://alice:secret@host/` puts a credential ahead of the query, where no
/// parameter-name rule can see it, and both transports log the result at INFO.
/// No parsing is needed to find it: the authority is the span between `://`
/// and the next `/`, `?` or `#`, and the userinfo is what precedes an `@`
/// inside it.
///
/// The **last** `@` rather than the first. An `@` is not legal unencoded in
/// userinfo, so a URL containing two is already malformed — but splitting at
/// the first would leave the tail of the password sitting in what this then
/// treats as the host. Splitting at the last cannot do that.
///
/// The username survives: it identifies rather than authenticates, and it is
/// what a reader of the log needs to tell two connections apart.
///
/// A userinfo with no `:` goes whole. `wss://alice@h/p` may be a bare token or
/// may be a username, and nothing here can tell — so it is treated as the
/// former, because over-redacting costs a log its diagnostic value while
/// under-redacting costs a credential.
///
/// The authority ends at the first `/`, `?` or `#`, so a password containing
/// one of those unencoded puts the `@` outside the authority and this sees no
/// userinfo at all. That limitation is enumerated in the module doc and
/// asserted by `the_documented_evasions_are_still_evasions`.
fn redact_userinfo(url: &str) -> std::borrow::Cow<'_, str> {
    // A scheme is not required. `connect_async` refuses a URL without one, so
    // the transports never log such a URL for long — but they log it *before*
    // that refusal, and this function is total over its input.
    let authority_start = url.find("://").map_or(0, |scheme_end| scheme_end + 3);
    let authority_end = url[authority_start..]
        .find(['/', '?', '#'])
        .map_or(url.len(), |offset| authority_start + offset);
    let authority = &url[authority_start..authority_end];
    let Some(at) = authority.rfind('@') else {
        return std::borrow::Cow::Borrowed(url);
    };
    let userinfo = &authority[..at];
    // An empty userinfo has no secret in it, and replacing it would tell a
    // reader of the log that a credential was present when none was.
    if userinfo.is_empty() {
        return std::borrow::Cow::Borrowed(url);
    }
    let name = match userinfo.find(':') {
        Some(colon) => &userinfo[..=colon],
        None => "",
    };
    std::borrow::Cow::Owned(format!(
        "{}{name}{PLACEHOLDER}{}",
        &url[..authority_start],
        &url[authority_start + at..]
    ))
}

/// `url` with the value of every credential-shaped query parameter replaced.
///
/// A URL carrying no query string, and one whose parameters are all benign,
/// come back unchanged — the common case must stay readable in a log.
pub fn redact_url(url: &str) -> String {
    let url = &redact_userinfo(url);
    // The query and the fragment are scanned with the same rules. A caller
    // appending `?k=v` to a URL that already carries a fragment lands the
    // parameter after the `#`, so a redactor that skipped the fragment would
    // miss exactly the credential a caller most plausibly misplaces — and the
    // URL a Nucleus deployment advertises is chosen by the server, which
    // decides whether a fragment is there at all. A fragment is never sent on
    // the wire, so scanning it costs nothing.
    let (head, tail) = match url.find(['?', '#']) {
        Some(split) => url.split_at(split),
        None => return url.to_string(),
    };

    let mut out = String::with_capacity(url.len());
    out.push_str(head);
    // Two different extents, and the asymmetry is the point.
    //
    // `#` is structural: RFC 3986 ends the query there. `&` is not defined by
    // the RFC, but it is the separator every query producer in this protocol's
    // reach uses, so treating it as one is safe in both directions — a value
    // that really contains an unencoded `&` is the split-token case the module
    // doc already enumerates.
    //
    // A `?` is neither. Only the first one separates the path from the query,
    // and a later one is ordinary query data, so `access_token=a?b` is one
    // parameter whose value is `a?b`.
    //
    // So a `?` ends a *candidate*, which is how a credential hiding behind a
    // benign name is found: in `?a=1?access_token=T` the credential is a
    // candidate of its own rather than part of `a`'s value. But it does not end
    // a credential *value*, which runs to the next `&` or `#`; ending it at a
    // `?` would emit `access_token=REDACTED?tail` and disclose the suffix of
    // the very value being redacted.
    //
    // Reading permissively to find a credential and maximally to remove one is
    // what makes both directions safe. The cost is a benign parameter after a
    // `?` that follows a credential, which is swallowed into the placeholder —
    // diagnostic value given up on an input no Nucleus URL is expected to have.
    let mut rest = tail;
    while !rest.is_empty() {
        // Every separator sliced at here is one of the ASCII characters
        // `find` matched, so the byte offsets are char boundaries.
        let separator = &rest[..1];
        let body = &rest[1..];
        let candidate_end = body.find(['&', '#', '?']).unwrap_or(body.len());
        let candidate = &body[..candidate_end];
        out.push_str(separator);
        match candidate.split_once('=') {
            Some((name, _)) if is_credential_param(name) => {
                let value_end = body.find(['&', '#']).unwrap_or(body.len());
                out.push_str(name);
                out.push('=');
                out.push_str(PLACEHOLDER);
                rest = &body[value_end..];
            }
            // A bare flag has no value to disclose, and an unrecognised
            // parameter is left alone rather than guessed at.
            _ => {
                out.push_str(candidate);
                rest = &body[candidate_end..];
            }
        }
    }
    out
}

/// The variant name of a websocket message, carrying none of its payload.
///
/// The unexpected-message arms of both read loops report what arrived. A
/// `Debug` rendering of the message would report the payload with it, and the
/// variant that reaches those arms is `Text` — the shape an auth response
/// envelope takes if a server sends one as text rather than binary. The
/// discriminant and the length are what a reader of the log needs.
pub fn message_kind(message: &Message) -> &'static str {
    match message {
        Message::Text(_) => "text",
        Message::Binary(_) => "binary",
        Message::Ping(_) => "ping",
        Message::Pong(_) => "pong",
        Message::Close(_) => "close",
        Message::Frame(_) => "frame",
    }
}

/// The payload length of a websocket message, carrying none of its content.
pub fn message_len(message: &Message) -> usize {
    message.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_credential_query_parameter_loses_its_value() {
        let redacted = redact_url("wss://nucleus.example/connection?access_token=abcdef");
        assert_eq!(
            redacted,
            "wss://nucleus.example/connection?access_token=REDACTED"
        );
    }

    /// The names this transport promises to redact, written out rather than
    /// read from `CREDENTIAL_PARAMS`.
    ///
    /// Driving the loop from the constant under test would make this an oracle
    /// of itself: deleting `password` from the constant would delete it from
    /// the test's inputs too, so the loop would iterate one fewer name, stay
    /// green, and a password in a URL query would start reaching logs. A
    /// literal copy is what gives the assertion an independent expectation.
    const EXPECTED_PARAMS: &[&str] = &[
        "access_token",
        "api_key",
        "api_token",
        "apikey",
        "auth",
        "auth_token",
        "authorization",
        "client_secret",
        "code",
        "credential",
        "id_token",
        "passwd",
        "password",
        "pw",
        "refresh_token",
        "sas",
        "sas_token",
        "secret",
        "session_token",
        "sig",
        "signature",
        "token",
    ];

    #[test]
    fn every_listed_parameter_is_covered() {
        for name in EXPECTED_PARAMS {
            let url = format!("wss://h/p?{name}=abcdef");
            let redacted = redact_url(&url);
            assert!(
                !redacted.contains("abcdef"),
                "`{name}` left its value in `{redacted}`"
            );
        }
    }

    /// Pins the list in the other direction. Without this, adding a name to
    /// `CREDENTIAL_PARAMS` and forgetting `EXPECTED_PARAMS` would leave the
    /// literal copy drifting into a stale record of what is covered.
    #[test]
    fn the_expected_list_and_the_implementation_list_agree() {
        assert_eq!(
            CREDENTIAL_PARAMS, EXPECTED_PARAMS,
            "the redacted-parameter list changed; update both, deliberately"
        );
    }

    #[test]
    fn matching_ignores_case() {
        let redacted = redact_url("wss://h/p?Access_Token=abcdef");
        assert!(!redacted.contains("abcdef"), "got `{redacted}`");
    }

    // The good input: redaction must not damage the URLs that carry no
    // credential, which is every URL this transport is expected to see.
    #[test]
    fn a_url_without_a_query_is_unchanged() {
        let url = "wss://nucleus.example:3019/connection";
        assert_eq!(redact_url(url), url);
    }

    #[test]
    fn benign_parameters_are_unchanged() {
        let url = "wss://h/p?version=2&page_token=cursor42&user=alice";
        assert_eq!(redact_url(url), url);
    }

    #[test]
    fn a_continuation_cursor_is_not_treated_as_a_credential() {
        let url = "wss://h/p?page_token=cursor42";
        assert_eq!(redact_url(url), url);
    }

    #[test]
    fn benign_parameters_survive_alongside_a_credential() {
        let redacted = redact_url("wss://h/p?version=2&access_token=abcdef&user=alice");
        assert_eq!(
            redacted,
            "wss://h/p?version=2&access_token=REDACTED&user=alice"
        );
    }

    #[test]
    fn a_credential_before_a_fragment_is_redacted() {
        let redacted = redact_url("wss://h/p?access_token=abcdef#frag");
        assert_eq!(redacted, "wss://h/p?access_token=REDACTED#frag");
    }

    #[test]
    fn a_bare_flag_is_left_alone() {
        let url = "wss://h/p?verbose";
        assert_eq!(redact_url(url), url);
    }

    /// A caller appending `?k=v` to a URL that already carries a fragment
    /// lands the parameter after the `#`. The URL being appended to is chosen
    /// by the server, so this is reachable without a local mistake.
    #[test]
    fn a_credential_inside_a_fragment_is_redacted() {
        let redacted = redact_url("wss://h/connection?v=2#f&access_token=abcdef");
        assert_eq!(redacted, "wss://h/connection?v=2#f&access_token=REDACTED");
    }

    #[test]
    fn a_credential_in_a_fragment_with_an_empty_query_is_redacted() {
        let redacted = redact_url("wss://h/connection?#&access_token=abcdef");
        assert!(!redacted.contains("abcdef"), "got `{redacted}`");
    }

    #[test]
    fn a_credential_in_a_fragment_with_no_query_at_all_is_redacted() {
        let redacted = redact_url("wss://h/connection#access_token=abcdef");
        assert_eq!(redacted, "wss://h/connection#access_token=REDACTED");
    }

    /// A second `?` ends a *candidate* parameter. Only the first one separates
    /// the path from the query, so without this the text after a later `?` is
    /// read as part of the preceding parameter's value and a benign name
    /// shelters a credential behind it.
    #[test]
    fn a_credential_after_a_second_question_mark_is_redacted() {
        for url in [
            "wss://h/p?a=1?access_token=abcdef",
            "wss://h/p?a=1#f?access_token=abcdef",
            "wss://h/p?access_token=abcdef?b=2",
        ] {
            let redacted = redact_url(url);
            assert!(
                !redacted.contains("abcdef"),
                "`{url}` left a credential in `{redacted}`"
            );
        }
    }

    /// The other edge of the same rule, and the one that costs a credential if
    /// it is got wrong in the safe-looking direction.
    ///
    /// RFC 3986 allows an unencoded `?` inside a query, so a token may contain
    /// one. Ending the *value* there — as ending the candidate there would —
    /// emits `access_token=REDACTED?secret-tail` and hands over the suffix of
    /// the credential the caller asked to have removed. A credential value
    /// therefore runs to the next `&` or `#`, and to the end of the URL when
    /// there is neither.
    #[test]
    fn a_question_mark_inside_a_credential_value_does_not_end_the_redaction() {
        for url in [
            "wss://h/p?access_token=head?abcdef",
            "wss://h/p?access_token=head?tail?abcdef",
            "wss://h/p?v=2&access_token=head?abcdef",
            "wss://h/p#access_token=head?abcdef",
            "wss://h/p?a=1?access_token=head?abcdef",
        ] {
            let redacted = redact_url(url);
            assert!(
                !redacted.contains("abcdef"),
                "`{url}` disclosed a credential suffix in `{redacted}`"
            );
        }
    }

    /// A credential value stops at a structural delimiter, so what follows one
    /// is still scanned rather than swallowed.
    #[test]
    fn a_structural_delimiter_still_ends_a_credential_value() {
        assert_eq!(
            redact_url("wss://h/p?access_token=head?tail&v=2#f"),
            "wss://h/p?access_token=REDACTED&v=2#f"
        );
        assert_eq!(
            redact_url("wss://h/p?access_token=head?tail#token=second"),
            "wss://h/p?access_token=REDACTED#token=REDACTED"
        );
    }

    #[test]
    fn a_benign_second_question_mark_survives_verbatim() {
        for url in ["wss://h/p?a=1?b=2", "wss://h/p?a=1#f?b=2"] {
            assert_eq!(redact_url(url), url);
        }
    }

    #[test]
    fn a_benign_fragment_is_unchanged() {
        let url = "wss://h/connection?v=2#section-3";
        assert_eq!(redact_url(url), url);
    }

    /// An unencoded token containing `&` or `#` splits into further
    /// parameters. The tail is then either a bare flag or a parameter this
    /// list does not name, and in both cases it is indistinguishable from a
    /// legitimate one. Redaction cannot recover it — the caller must encode
    /// the value, which `connect_url_with_token` in the plugin does. Asserted
    /// so the limitation stays a known property rather than an assumption.
    #[test]
    fn a_split_token_tail_is_beyond_redaction() {
        for tail in ["&abcdef", "&x=abcdef", "#abcdef"] {
            let url = format!("wss://h/p?access_token=head{tail}");
            assert!(
                redact_url(&url).contains("abcdef"),
                "tail `{tail}` is now covered — update the doc, which says it is not"
            );
        }
    }

    /// The documented limitations, asserted so they stay known properties
    /// rather than assumptions. Each of these leaks by construction.
    #[test]
    fn the_documented_evasions_are_still_evasions() {
        for url in [
            "wss://h/abcdef/p?v=2",
            // A userinfo password carrying an unencoded authority delimiter.
            // `/` is in the base64 alphabet, so this is the shape an ordinary
            // secret takes when the caller did not percent-encode it.
            "wss://alice:ab/abcdef@h/p",
            "wss://alice:ab?abcdef@h/p",
            "wss://alice:ab#abcdef@h/p",
            // One decoding pass leaves `access%5Ftoken`, which is not a listed
            // name — and is not what a server reads as `access_token` either.
            "wss://h/p?access%255Ftoken=abcdef",
            "wss://h/p?a=1;access_token=abcdef",
            "wss://h/p?redirect_uri=x%3Faccess_token%3Dabcdef",
        ] {
            assert!(
                redact_url(url).contains("abcdef"),
                "`{url}` is now covered — update the module doc, which claims it is not"
            );
        }
    }

    /// A server decodes a parameter name before reading it, so `access%5Ftoken`
    /// delivers a credential exactly as `access_token` does. Matching only the
    /// bytes as written put that spelling's value in a log.
    #[test]
    fn a_percent_encoded_credential_name_loses_its_value() {
        for url in [
            "wss://h/p?access%5Ftoken=abcdef",
            // Hex digits and the name itself are both case-insensitive.
            "wss://h/p?access%5ftoken=abcdef",
            "wss://h/p?ACCESS%5FTOKEN=abcdef",
            // A fully-escaped name, and one escaped past the query.
            "wss://h/p?%61%63%63%65%73%73%5F%74%6F%6B%65%6E=abcdef",
            "wss://h/p#access%5Ftoken=abcdef",
        ] {
            let redacted = redact_url(url);
            assert!(
                !redacted.contains("abcdef"),
                "`{url}` kept its credential: `{redacted}`"
            );
            assert!(
                redacted.contains(PLACEHOLDER),
                "`{url}` lost its credential without saying so: `{redacted}`"
            );
        }
    }

    /// The name goes into the log as the caller wrote it. Rewriting it to the
    /// decoded spelling would report a URL that was never used.
    #[test]
    fn a_decoded_name_is_matched_but_not_rewritten() {
        assert_eq!(
            redact_url("wss://h/p?access%5Ftoken=abcdef&v=2"),
            "wss://h/p?access%5Ftoken=REDACTED&v=2"
        );
    }

    /// The honest request, which decoding must leave alone. `page_token` is
    /// deliberately absent from the list, and encoding its name must not be
    /// what puts it in the placeholder — a continuation cursor is diagnostic
    /// value a reader of the log needs.
    #[test]
    fn a_benign_name_survives_decoding_encoded_or_not() {
        for url in [
            "wss://h/p?page%5Ftoken=abcdef",
            "wss://h/p?page_token=abcdef",
            "wss://h/p?redirect%5Furi=abcdef",
        ] {
            assert_eq!(redact_url(url), url, "`{url}` lost a benign value");
        }
    }

    /// A name is not required to be well-formed percent-encoding. A truncated
    /// or non-hex escape is kept as written and matched as written, which is
    /// what it was before decoding existed.
    #[test]
    fn a_malformed_escape_neither_panics_nor_redacts() {
        for url in [
            "wss://h/p?access%5token=abcdef",
            "wss://h/p?access%zztoken=abcdef",
            "wss://h/p?access%=abcdef",
            "wss://h/p?access_token%=abcdef",
            "wss://h/p?%=abcdef",
            "wss://h/p?%%%5=abcdef",
            // Well-formed, but it names a non-ASCII byte, so it decodes to no
            // listed name whether or not the escape is resolved.
            "wss://h/p?access%C3%BFtoken=abcdef",
        ] {
            assert_eq!(redact_url(url), url, "`{url}` was rewritten");
        }
    }

    /// A listed name still matches as written when the *value* carries a
    /// stray `%`, so introducing decoding cannot cost a redaction the
    /// as-written comparison already made.
    ///
    /// A `%` in the **name** is the opposite case and is covered by
    /// `a_malformed_escape_neither_panics_nor_redacts`: `access_token%` is not
    /// the listed name and is not redacted.
    #[test]
    fn decoding_never_costs_an_as_written_match() {
        assert_eq!(
            redact_url("wss://h/p?access_token=ab%"),
            "wss://h/p?access_token=REDACTED"
        );
    }

    /// A credential ahead of the authority, which no parameter-name rule can
    /// see. Both transports log this at INFO, so leaving it was a hole in the
    /// property this module exists to give the transport.
    #[test]
    fn a_userinfo_password_is_redacted() {
        assert_eq!(
            redact_url("wss://alice:abcdef@h/p?v=2"),
            "wss://alice:REDACTED@h/p?v=2"
        );
        assert_eq!(redact_url("wss://alice:abcdef@h"), "wss://alice:REDACTED@h");
        assert_eq!(
            redact_url("wss://alice:abcdef@h/p?access_token=abcdef"),
            "wss://alice:REDACTED@h/p?access_token=REDACTED"
        );
    }

    /// A userinfo with no `:` is a bare credential rather than a name, so
    /// keeping "the username" would keep the whole secret.
    #[test]
    fn a_bare_userinfo_is_redacted_whole() {
        assert_eq!(redact_url("wss://abcdef@h/p"), "wss://REDACTED@h/p");
    }

    /// Splitting at the first `@` would leave the tail of the password in what
    /// is then read as the host.
    #[test]
    fn a_userinfo_containing_an_at_sign_is_redacted_whole() {
        let redacted = redact_url("wss://alice:ab@cdef@h/p");
        assert!(!redacted.contains("cdef"), "got `{redacted}`");
    }

    /// The username is diagnostic, not a credential, and losing it would cost
    /// a reader the ability to tell two connections apart.
    #[test]
    fn a_userinfo_username_survives() {
        assert!(redact_url("wss://alice:abcdef@h/p").contains("alice:"));
    }

    /// `connect_async` refuses a URL with no scheme, but both transports log
    /// the URL *before* that refusal, so a scheme is not what makes a
    /// credential worth removing.
    #[test]
    fn a_userinfo_is_redacted_without_a_scheme() {
        assert_eq!(redact_url("alice:abcdef@h/p"), "alice:REDACTED@h/p");
        assert_eq!(
            redact_url("alice:abcdef@h/p?access_token=abcdef"),
            "alice:REDACTED@h/p?access_token=REDACTED"
        );
    }

    /// An empty userinfo has no secret in it. Replacing it would report a
    /// credential that was never there, which costs a reader of the log the
    /// ability to believe the placeholder.
    #[test]
    fn an_empty_userinfo_is_left_alone() {
        for url in ["wss://@h/p", "wss://h/p"] {
            assert_eq!(redact_url(url), url);
        }
    }

    /// The authority ends at the first `/`, `?` or `#`, so an `@` in a path or
    /// a query is not userinfo and must not be treated as one.
    #[test]
    fn an_at_sign_outside_the_authority_is_left_alone() {
        for url in [
            "wss://h/p?contact=alice@example.com",
            "wss://h/alice@example.com/p",
            "wss://h/p#alice@example.com",
        ] {
            assert_eq!(redact_url(url), url);
        }
    }

    #[test]
    fn a_value_containing_an_equals_sign_is_fully_removed() {
        let redacted = redact_url("wss://h/p?access_token=ab=cd=ef");
        assert_eq!(redacted, "wss://h/p?access_token=REDACTED");
    }
    /// `redact_url` slices by byte offset. Every separator it slices at is
    /// ASCII by construction, but that is an argument, and a panic in a
    /// logging path takes down the connection it was describing.
    #[test]
    fn odd_shapes_neither_panic_nor_corrupt() {
        for url in [
            "wss://h/p?",
            "wss://h/p#",
            "wss://h/p?#",
            "wss://h/p??",
            "wss://h/p?a&&b",
            "wss://h/p?a=1#f#g",
            "wss://h/p?\u{00e9}=1",
            "wss://h/p#\u{1f600}",
            "wss://h/\u{00e9}?a=1",
            "wss://h/p?a=\u{1f600}&b=2",
            "",
            "?",
            "#",
        ] {
            assert_eq!(
                redact_url(url),
                url,
                "a URL with no credential must survive verbatim"
            );
        }
    }

    #[test]
    fn redaction_is_idempotent() {
        let once = redact_url("wss://h/p?a=1&access_token=abcdef#f&token=abcdef");
        assert_eq!(redact_url(&once), once);
        assert!(!once.contains("abcdef"), "got `{once}`");
    }

    #[test]
    fn a_multibyte_token_value_is_still_removed() {
        let redacted = redact_url("wss://h/p?access_token=\u{1f600}abcdef\u{00e9}");
        assert!(!redacted.contains("abcdef"), "got `{redacted}`");
    }

    /// Every variant gets its own label, checked against a literal rather than
    /// against the match arm that produces it. A variant taking a neighbour's
    /// label is not a crash and not a leak, so the read loops' warning would
    /// simply mis-describe what arrived, and nothing else would notice.
    ///
    /// The list is exhaustive over `Message` as this dependency spells it: a
    /// new variant makes the function itself fail to compile, and this test
    /// then pins what label the author chose for it.
    #[test]
    fn each_message_variant_has_its_own_label() {
        use tokio_tungstenite::tungstenite::protocol::frame::Frame;

        let cases: [(Message, &str); 6] = [
            (Message::Text("abcdef".to_string()), "text"),
            (Message::Binary(b"abcdef".to_vec()), "binary"),
            (Message::Ping(b"ab".to_vec()), "ping"),
            (Message::Pong(b"ab".to_vec()), "pong"),
            (Message::Close(None), "close"),
            (Message::Frame(Frame::ping(b"ab".to_vec())), "frame"),
        ];
        let mut seen = Vec::new();
        for (message, expected) in cases {
            let label = message_kind(&message);
            assert_eq!(label, expected, "wrong label for `{message:?}`");
            seen.push(label);
        }
        seen.sort_unstable();
        let before = seen.len();
        seen.dedup();
        assert_eq!(seen.len(), before, "two variants share a label: {seen:?}");
    }

    /// The length reported alongside the label carries no payload, which is the
    /// property the read loops rely on — the whole point of reporting a length
    /// instead of a `Debug` rendering.
    #[test]
    fn a_message_length_is_the_payload_length() {
        assert_eq!(message_len(&Message::Text("abcdef".to_string())), 6);
        assert_eq!(message_len(&Message::Binary(b"abcd".to_vec())), 4);
        assert_eq!(message_len(&Message::Close(None)), 0);
    }
}
