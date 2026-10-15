// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Redaction for values that reach `tracing` events.
//!
//! The transports carry credentials in three shapes. Request and response
//! bodies carry them as JSON fields — `Tokens.auth_with_api_token` sends a
//! literal API token as a parameter, and the corresponding response envelope
//! carries `access_token` and `refresh_token`. Connection URLs carry them as
//! query parameters when a caller splices one in. Free-form text chosen by a
//! server can repeat either a credential-bearing URL or a bearer literal.
//!
//! Structured credential fields are handled by keeping their bodies out of an
//! event entirely (the logging sites emit only structured metadata), and
//! standalone URLs pass through [`redact_url`] before becoming field values.
//! [`redact_server_text`] handles free-form text by finding those same URLs in
//! prose, removing bearer literals, and bounding the resulting diagnostic.
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
//! superset of that redactor's list, and both redact userinfo.

use tokio_tungstenite::tungstenite::Message;

/// Query-parameter names whose values are replaced in a logged URL.
///
/// Matched case-insensitively against the whole parameter name, so `token`
/// does not stand in for `page_token`: a continuation cursor is not a
/// credential and redacting it would cost real diagnostic value.
///
/// A name belongs here when its value is a credential or part of a provider's
/// signed-URL authentication material. It stays out when the value only
/// identifies or paginates. Matching is exact, so a new spelling needs its
/// own entry — adding `bearer_token` does not follow from `token` being
/// present.
///
/// The two costs are not symmetric, which is why the cloud-provider signing
/// parameter groups are listed even though a Nucleus URL is not expected to
/// carry one: redacting a name that never appears costs nothing, while
/// retaining one produces a partial signed URL and can put a credential in a
/// log. What keeps the list from growing without limit is the other cost — a
/// name whose value a reader of the log needs, such as `page_token`, stays out
/// however token-shaped it reads.
///
/// `every_listed_parameter_is_covered` pins this list against a literal copy,
/// so removing an entry fails a test rather than silently widening what
/// reaches a log.
const CREDENTIAL_PARAMS: &[&str] = &[
    // S3 SigV4.
    "X-Amz-Signature",
    "X-Amz-Credential",
    "X-Amz-SignedHeaders",
    "X-Amz-Security-Token",
    "X-Amz-Date",
    "X-Amz-Expires",
    "X-Amz-Algorithm",
    // Azure SAS.
    "sig",
    "sv",
    "se",
    "st",
    "sp",
    "sip",
    "srt",
    "ss",
    "tn",
    "skoid",
    "sktid",
    "skt",
    "ske",
    "sks",
    "skv",
    // GCS V4 signed URLs.
    "X-Goog-Signature",
    "X-Goog-Credential",
    "X-Goog-SignedHeaders",
    "X-Goog-Date",
    "X-Goog-Expires",
    "X-Goog-Algorithm",
    // Generic token names, including the standalone transport's additional
    // Nucleus and authentication spellings.
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
    "signature",
    "token",
];

/// What replaces a credential value. Naming the parameter but not its value
/// keeps the event useful for diagnosis — "the token was present" is the fact
/// a reader of the log actually needs.
const PLACEHOLDER: &str = "REDACTED";

/// Maximum bytes of redacted server prose retained before a truncation marker.
///
/// Real Nucleus error prose fits within 512 bytes. Text chosen by a server
/// must not be able to fill a log or an error handed to a caller.
const MAX_SERVER_TEXT_BYTES: usize = 512;

/// Maximum bytes of server prose inspected for credential shapes.
///
/// The scan allowance is deliberately larger than the retained diagnostic so
/// an ordinary URL or bearer literal crossing the output boundary is still
/// seen whole. Bounding it prevents a multi-megabyte server frame from making
/// either synchronous scanner monopolize the shared transport runtime.
const MAX_SERVER_TEXT_SCAN_BYTES: usize = MAX_SERVER_TEXT_BYTES * 8;

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

/// Redact credential shapes in server-chosen prose and bound its length.
///
/// The lexical scan recognises conventional `scheme://` URLs embedded in
/// prose, including URLs stopped by whitespace, quotes, closing prose
/// brackets, commas, and semicolons. A closing bracket belonging to an IPv6
/// authority remains part of its URL. Each span is passed through this
/// module's [`redact_url`]. It also replaces the token after a
/// case-insensitive `bearer` word and whitespace with `PLACEHOLDER`.
///
/// This covers ordinary URL query credentials, URL userinfo, and bearer
/// authorization literals. It does not infer that arbitrary secret-looking
/// prose is a credential, and the evasions documented for [`redact_url`]
/// remain evasions here. A split or obfuscated `bearer` spelling, or a token
/// with no separating whitespace, is likewise outside what the lexical scan
/// can identify.
///
/// Redaction deliberately runs over a working prefix eight times larger than
/// the retained diagnostic before the final truncation. Truncating directly
/// to the output bound could cut an ordinary URL before the scanner has seen
/// its complete credential-bearing shape while leaving credential bytes in
/// the retained prefix. The working prefix itself is bounded so a
/// multi-megabyte server frame cannot monopolize the shared I/O runtime with
/// synchronous diagnostic work. At most `MAX_SERVER_TEXT_BYTES` redacted
/// bytes are retained, walking backward to a UTF-8 character boundary, and a
/// marker names the original input's byte length whenever either bound cuts
/// the diagnostic.
///
/// This helper is total over arbitrary `str` input: it performs no parsing,
/// every byte offset used for slicing is either an ASCII delimiter or a known
/// UTF-8 boundary, and truncation checks [`str::is_char_boundary`] before it
/// slices. It has no input-dependent panic path, which is required because it
/// runs while constructing diagnostics for an already failing connection.
pub fn redact_server_text(text: &str) -> String {
    let original_len = text.len();
    let mut scan_end = original_len.min(MAX_SERVER_TEXT_SCAN_BYTES);
    while !text.is_char_boundary(scan_end) {
        scan_end -= 1;
    }
    let urls_redacted = redact_urls_in_text(&text[..scan_end]);
    let mut redacted = redact_bearer_literals(&urls_redacted);

    let working_prefix_was_cut = scan_end < original_len;
    if !working_prefix_was_cut && redacted.len() <= MAX_SERVER_TEXT_BYTES {
        return redacted;
    }

    if redacted.len() > MAX_SERVER_TEXT_BYTES {
        let mut end = MAX_SERVER_TEXT_BYTES;
        while !redacted.is_char_boundary(end) {
            end -= 1;
        }
        redacted.truncate(end);
    }
    redacted.push_str(&format!(
        "… [truncated; original length: {original_len} bytes]"
    ));
    redacted
}

/// Replace credential-bearing URL spans while preserving surrounding prose.
fn redact_urls_in_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0;

    while cursor < text.len() {
        match scan_url_at(text, cursor) {
            UrlScan::Url(end) => {
                out.push_str(&redact_url(&text[cursor..end]));
                cursor = end;
                continue;
            }
            UrlScan::SchemeRun(end) => {
                // Every offset inside this run reaches the same end before it
                // can look for `://`, so none can begin a URL. Copying the run
                // in one step keeps this scan linear in server-chosen input.
                out.push_str(&text[cursor..end]);
                cursor = end;
                continue;
            }
            UrlScan::None => {}
        }

        // `cursor` starts at zero and advances by complete characters or a URL
        // end returned by `scan_url_at`, so this slice always starts on a
        // character boundary. `next` exists because the loop excludes `len`.
        let Some(character) = text[cursor..].chars().next() else {
            break;
        };
        let end = cursor + character.len_utf8();
        out.push_str(&text[cursor..end]);
        cursor = end;
    }

    out
}

/// Replace bearer tokens while preserving their label and separating space.
fn redact_bearer_literals(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0;

    while cursor < text.len() {
        if let Some((token_start, token_end)) = scan_bearer_at(text, cursor) {
            out.push_str(&text[cursor..token_start]);
            out.push_str(PLACEHOLDER);
            cursor = token_end;
            continue;
        }

        // The same boundary invariant as `redact_urls_in_text` applies here.
        let Some(character) = text[cursor..].chars().next() else {
            break;
        };
        let end = cursor + character.len_utf8();
        out.push_str(&text[cursor..end]);
        cursor = end;
    }

    out
}

/// If a bearer literal starts at `start`, return its token's byte range.
fn scan_bearer_at(text: &str, start: usize) -> Option<(usize, usize)> {
    let before = text.get(..start)?.chars().next_back();
    if before.is_some_and(|character| character.is_alphanumeric() || character == '_') {
        return None;
    }

    let bearer_end = start.checked_add("bearer".len())?;
    if !text.get(start..bearer_end)?.eq_ignore_ascii_case("bearer") {
        return None;
    }

    let mut token_start = bearer_end;
    for (offset, character) in text.get(bearer_end..)?.char_indices() {
        if !character.is_whitespace() {
            break;
        }
        token_start = bearer_end + offset + character.len_utf8();
    }
    if token_start == bearer_end || token_start == text.len() {
        return None;
    }

    let token_end = text[token_start..]
        .char_indices()
        .find_map(|(offset, character)| {
            (character.is_whitespace() || character == ',').then_some(token_start + offset)
        })
        .unwrap_or(text.len());
    (token_end > token_start).then_some((token_start, token_end))
}

/// Result of looking for a URL at one character boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UrlScan {
    /// A URL was found; the value is its exclusive end.
    Url(usize),
    /// An ASCII scheme-character run was found but was not followed by `://`.
    ///
    /// No later offset within the run can be a URL start: scanning from one
    /// reaches the same run end and rejects the same following bytes. The
    /// caller can therefore copy the whole run rather than rescan every
    /// suffix, which prevents quadratic work on a long server-chosen word.
    SchemeRun(usize),
    /// The character at this position cannot begin an ASCII URL scheme.
    None,
}

/// Classify a possible URL starting at `start` and return its exclusive end.
fn scan_url_at(text: &str, start: usize) -> UrlScan {
    let bytes = text.as_bytes();
    let Some(scheme_end) = scan_scheme(bytes, start) else {
        return UrlScan::None;
    };
    if bytes.get(scheme_end) != Some(&b':')
        || bytes.get(scheme_end + 1) != Some(&b'/')
        || bytes.get(scheme_end + 2) != Some(&b'/')
    {
        return UrlScan::SchemeRun(scheme_end);
    }

    let mut end = scheme_end + 3;
    let mut in_authority = true;
    let mut in_bracketed_authority = false;
    while end < bytes.len() {
        let byte = bytes[end];
        if byte.is_ascii_whitespace()
            || matches!(
                byte,
                b'"' | b'<' | b'>' | b'`' | b'\'' | b')' | b'}' | b',' | b';'
            )
        {
            break;
        }

        if byte == b']' {
            if in_authority && in_bracketed_authority {
                // The closing bracket is structural host syntax in an IPv6
                // authority, not punctuation closing the surrounding prose.
                in_bracketed_authority = false;
                end += 1;
                continue;
            }
            break;
        }

        if in_authority {
            match byte {
                b'[' => in_bracketed_authority = true,
                b'/' | b'?' | b'#' if !in_bracketed_authority => in_authority = false,
                _ => {}
            }
        }
        end += 1;
    }

    // Sentence punctuation is not part of a URL, but must remain in the
    // surrounding prose. `redact_urls_in_text` copies it on the next pass.
    while end > scheme_end + 3 {
        match bytes[end - 1] {
            b'.' | b',' | b':' | b';' | b'!' | b'?' => end -= 1,
            _ => break,
        }
    }

    UrlScan::Url(end)
}

/// Return the end of an ASCII URL scheme starting at `start`.
fn scan_scheme(bytes: &[u8], start: usize) -> Option<usize> {
    let first = *bytes.get(start)?;
    if !first.is_ascii_alphabetic() {
        return None;
    }

    let mut end = start + 1;
    while end < bytes.len() {
        let byte = bytes[end];
        if byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'.' | b'-') {
            end += 1;
        } else {
            break;
        }
    }
    Some(end)
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
    fn a_url_in_server_prose_is_redacted() {
        let redacted = redact_server_text(
            "request failed at wss://nucleus.example/p?access_token=abcdef&v=2 during login",
        );
        assert_eq!(
            redacted,
            "request failed at wss://nucleus.example/p?access_token=REDACTED&v=2 during login"
        );
    }

    #[test]
    fn a_serde_quoted_url_is_redacted_without_losing_the_quote() {
        let redacted = redact_server_text(
            "invalid value: \"https://nucleus.example/p?api_token=abcdef\", expected metadata",
        );
        assert_eq!(
            redacted,
            "invalid value: \"https://nucleus.example/p?api_token=REDACTED\", expected metadata"
        );
    }

    #[test]
    fn cloud_signing_credentials_in_server_prose_are_redacted() {
        for url in [
            "https://bucket.example/k?X-Amz-Signature=cloud-signing-secret&versionId=7",
            "https://storage.example/k?X-Goog-Signature=cloud-signing-secret&generation=7",
            "https://account.example/c/k?sv=2026-01-01&sig=cloud-signing-secret",
        ] {
            let redacted = redact_server_text(&format!("server rejected {url}"));
            assert!(
                redacted.contains(PLACEHOLDER),
                "`{url}` lost no value, so the assertion premise failed: `{redacted}`"
            );
            assert!(
                !redacted.contains("cloud-signing-secret"),
                "`{url}` retained its signing credential: `{redacted}`"
            );
        }
    }

    #[test]
    fn a_url_with_a_bracketed_ipv6_authority_is_redacted() {
        let redacted = redact_server_text(
            "denied wss://[::1]/p?access_token=ipv6-secret], expected authorization",
        );
        assert_eq!(
            redacted,
            "denied wss://[::1]/p?access_token=REDACTED], expected authorization"
        );
    }

    #[test]
    fn a_bearer_literal_is_redacted_case_insensitively() {
        let redacted = redact_server_text("authorization failed for BeArEr\tabcdef, retry denied");
        assert_eq!(
            redacted,
            "authorization failed for BeArEr\tREDACTED, retry denied"
        );
        assert_eq!(
            redact_server_text("unbearer abcdef"),
            "unbearer abcdef",
            "bearer must begin at a word boundary"
        );
    }

    #[test]
    fn short_plain_server_prose_is_unchanged() {
        let prose = "the requested object does not exist";
        assert_eq!(redact_server_text(prose), prose);
    }

    #[test]
    fn oversized_server_prose_is_bounded_and_names_its_original_length() {
        let prose = "x".repeat(600);
        let marker = "… [truncated; original length: 600 bytes]";
        let redacted = redact_server_text(&prose);

        assert_eq!(&redacted[..MAX_SERVER_TEXT_BYTES], "x".repeat(512));
        assert_eq!(&redacted[MAX_SERVER_TEXT_BYTES..], marker);
        assert_eq!(redacted.len(), MAX_SERVER_TEXT_BYTES + marker.len());
    }

    #[test]
    fn multibyte_server_prose_truncates_at_a_character_boundary() {
        // Byte 512 falls in the middle of `é`.
        let prose = format!("{}étail", "a".repeat(511));
        assert!(!prose.is_char_boundary(MAX_SERVER_TEXT_BYTES));

        let redacted = redact_server_text(&prose);
        let marker = format!("… [truncated; original length: {} bytes]", prose.len());
        assert_eq!(&redacted[..511], "a".repeat(511));
        assert_eq!(&redacted[511..], marker);
    }

    #[test]
    fn the_working_prefix_ends_at_a_character_boundary() {
        // Byte 4096 falls in the middle of `é`, independently of the final
        // 512-byte output cutoff exercised by the test above.
        let prose = format!("{}étail{}", "a".repeat(4095), "z".repeat(4096));
        assert!(!prose.is_char_boundary(MAX_SERVER_TEXT_SCAN_BYTES));

        let redacted = redact_server_text(&prose);
        let marker = format!("… [truncated; original length: {} bytes]", prose.len());
        assert_eq!(&redacted[..MAX_SERVER_TEXT_BYTES], "a".repeat(512));
        assert_eq!(&redacted[MAX_SERVER_TEXT_BYTES..], marker);
    }

    /// Redacting one credential can shrink an oversized working prefix below
    /// the output bound. The unscanned tail still has to be disclosed as a
    /// truncation, with the length of the complete server input rather than
    /// the prefix or the redacted intermediate string.
    #[test]
    fn a_shrunk_working_prefix_still_reports_the_original_length() {
        let prose = format!(
            "wss://h/p?access_token={}",
            "x".repeat(MAX_SERVER_TEXT_SCAN_BYTES * 2)
        );
        let marker = format!("… [truncated; original length: {} bytes]", prose.len());
        let redacted = redact_server_text(&prose);

        assert_eq!(
            redacted,
            format!("wss://h/p?access_token={PLACEHOLDER}{marker}")
        );
    }

    /// The URL begins before the cap and its credential begins within the raw
    /// prefix that a truncate-first implementation would retain. Seeing the
    /// placeholder proves the complete input was redacted before it was cut.
    #[test]
    fn a_credential_crossing_the_cap_is_redacted_before_truncation() {
        let credential = "credential-that-must-not-survive";
        let prose = format!(
            "{} wss://h/p?access_token={credential} {}",
            "x".repeat(469),
            "tail".repeat(200)
        );
        let redacted = redact_server_text(&prose);

        assert!(redacted.contains(PLACEHOLDER), "got `{redacted}`");
        assert!(!redacted.contains(credential), "got `{redacted}`");
        assert!(redacted.contains("original length:"), "got `{redacted}`");
    }

    /// Every shape here is valid UTF-8 but awkward for one of the lexical
    /// scanners. Diagnostic redaction must return a bounded string for all of
    /// them rather than turning an existing connection failure into a panic.
    #[test]
    fn odd_server_text_shapes_neither_panic_nor_exceed_the_bound() {
        let shapes = [
            ("", ""),
            ("://", "://"),
            ("x://", "x://"),
            ("\"wss://h/p?\"", "\"wss://h/p?\""),
            ("bearer", "bearer"),
            ("bearer ", "bearer "),
            ("bearer\t,", "bearer\t,"),
            ("ébearer secret", "ébearer secret"),
            ("😀://?token=secret", "😀://?token=secret"),
            (
                "wss://h/p?access_token=😀",
                "wss://h/p?access_token=REDACTED",
            ),
            ("\0bearer\nsecret", "\0bearer\nREDACTED"),
        ];

        for (text, expected) in shapes {
            let redacted = redact_server_text(text);
            let marker = format!("… [truncated; original length: {} bytes]", text.len());
            assert_eq!(redacted, expected, "`{text:?}` was corrupted");
            assert!(
                redacted.len() <= MAX_SERVER_TEXT_BYTES + marker.len(),
                "`{text:?}` produced {} bytes",
                redacted.len()
            );
        }
        assert_eq!(redact_server_text(""), "");
    }

    #[test]
    fn server_text_output_is_bounded_for_varied_inputs() {
        for repetitions in [0, 1, 63, 127, 128, 255, 511, 512, 513, 1024] {
            for unit in ["a", "é", "😀", "wss://h/p?token=x ", "Bearer x "] {
                let text = unit.repeat(repetitions);
                let redacted = redact_server_text(&text);
                let marker = format!("… [truncated; original length: {} bytes]", text.len());
                assert!(
                    redacted.len() <= MAX_SERVER_TEXT_BYTES + marker.len(),
                    "unit `{unit}` repeated {repetitions} times produced {} bytes",
                    redacted.len()
                );
            }
        }
    }

    /// A failed URL probe reports the whole ASCII scheme-character run to the
    /// caller. If the caller resumed one byte later, a word this large would
    /// rescan every suffix and turn server-chosen input into quadratic work.
    #[test]
    fn a_long_non_url_scheme_run_is_skipped_as_one_span() {
        let text = "a".repeat(1024 * 1024);
        assert_eq!(scan_url_at(&text, 0), UrlScan::SchemeRun(text.len()));

        let redacted = redact_server_text(&text);
        let marker = format!("… [truncated; original length: {} bytes]", text.len());
        assert_eq!(&redacted[..MAX_SERVER_TEXT_BYTES], "a".repeat(512));
        assert_eq!(&redacted[MAX_SERVER_TEXT_BYTES..], marker);
    }

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
        "X-Amz-Signature",
        "X-Amz-Credential",
        "X-Amz-SignedHeaders",
        "X-Amz-Security-Token",
        "X-Amz-Date",
        "X-Amz-Expires",
        "X-Amz-Algorithm",
        "sig",
        "sv",
        "se",
        "st",
        "sp",
        "sip",
        "srt",
        "ss",
        "tn",
        "skoid",
        "sktid",
        "skt",
        "ske",
        "sks",
        "skv",
        "X-Goog-Signature",
        "X-Goog-Credential",
        "X-Goog-SignedHeaders",
        "X-Goog-Date",
        "X-Goog-Expires",
        "X-Goog-Algorithm",
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
