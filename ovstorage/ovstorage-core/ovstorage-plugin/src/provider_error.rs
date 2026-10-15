// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Allowlist sanitizer for provider error bodies.
//!
//! The invariant: a provider response body is never interpolated into error
//! text. Only an allowlisted token escapes — the provider's short error code —
//! and only when the *whole* value is one.
//!
//! This exists because provider bodies carry credential-derived material. An
//! Azure `AuthenticationFailed` body echoes the request MAC and the canonical
//! string-to-sign inside `<AuthenticationErrorDetail>`; S3 and GCS bodies carry
//! their own request signatures. A body that reached an exception would put
//! that material into every log that renders it.
//!
//! # For plugin authors
//!
//! Two steps, in order, and the first one is yours:
//!
//! 1. **Structurally isolate the error-code field.** [`validate_code_token`]
//!    checks a value's *grammar*, and grammar alone cannot tell a short error
//!    code from a token-shaped secret — a 64-character hex signature is a valid
//!    token. Pass it a field you have already located by structure: a
//!    `x-ms-error-code` header, a JSON `/error/code` pointer. Never a whole
//!    body, a free-text message, or an arbitrary header.
//! 2. **Report `None` as a length, not as text.** When either function returns
//!    `None`, the value was not a code. Say so with the body's length — `"no
//!    provider error code; 412 byte body suppressed"` — which distinguishes a
//!    proxy's HTML error page from a silent endpoint without quoting a byte of
//!    it. Do not fall back to printing the body, the message, or a truncation
//!    of either.
//!
//! [`xml_code`] does step 1 for you for XML error documents: it locates the
//! `<Code>` element that is a direct child of the document root, then applies
//! [`validate_code_token`] to its text.
//!
//! # Why this is shared rather than per-plugin
//!
//! The S3, GCS and Azure plugins each carried their own copy, and the copies
//! had already drifted: S3's `<Code>` scan was unbounded while the other two
//! capped it, and only one operated on bytes. Because the code exists to keep
//! provider secrets out of surfaced errors, hardening one copy and not the
//! others is a silent security regression — the failure mode is that the fix
//! looks done.
//!
//! It is public rather than internal because a third-party plugin author
//! surfacing provider errors faces exactly this hazard, and a vetted sanitizer
//! is more useful to them than a warning.
//!
//! # Why bytes
//!
//! Everything here takes `&[u8]` and filters to ASCII, so the length cap is
//! boundary-safe by construction: there is no `&str` slice to panic on a
//! multi-byte sequence. `&str` callers pass `.as_bytes()`.
//!
//! Callers must pass the bytes they received, not a lossy string conversion.
//! `String::from_utf8_lossy` expands each invalid byte to a three-byte U+FFFD,
//! which inflates offsets and can push a `<Code>` that sits well inside
//! [`SCAN_LIMIT`] raw bytes past the window.
//!
//! This is also marginally STRICTER than a `&str` implementation using
//! `trim()`, which strips Unicode whitespace: a value padded with U+00A0 is
//! trimmed and accepted there, and rejected here. Strictness in that direction
//! is the correct bias for a filter whose failure mode is disclosure.

/// Longest token that escapes. Real provider codes are short PascalCase
/// identifiers; the cap bounds what a hostile body can push into a log line.
///
/// Not part of the plugin C ABI — this is a host-side Rust helper, and a
/// generically-named `#define` in the ABI header would be surface nobody asked
/// for.
///
/// cbindgen:ignore
pub const MAX_TOKEN_CHARS: usize = 64;

/// How much of a body a structured scan looks at. Provider error documents put
/// their code first, well inside this window. Bounding it keeps a large or
/// hostile body from turning error construction into a long scan or a full
/// parse.
///
/// Not part of the plugin C ABI; see [`MAX_TOKEN_CHARS`].
///
/// cbindgen:ignore
pub const SCAN_LIMIT: usize = 8192;

/// Accept `raw` only if the WHOLE value is one provider error-code token: a
/// leading ASCII letter, then ASCII alphanumerics and `.`, `_`, `-`, no longer
/// than [`MAX_TOKEN_CHARS`]. Surrounding ASCII whitespace is trimmed first,
/// because a pretty-printed document indents the element's text.
///
/// VALIDATING the whole value, rather than filtering characters out of it, is
/// the property this rests on. Filtering would keep whatever survives:
/// `<Code>AuthenticationFailed 7hK4wQ2mZ9pR1tY6uXbN5cJfA8sVdE3o=</Code>` yields
/// the code with most of the MAC welded onto it, which is precisely the
/// disclosure this exists to prevent. A value that is not a clean token is not
/// a code, so it is rejected whole and the caller reports the body by length
/// instead.
///
/// Over-long values are rejected rather than truncated, for the same reason: a
/// truncated value is still a prefix of whatever is in the field.
///
/// # This checks grammar, not provenance
///
/// A token-shaped secret passes: a 64-character hex signature is a valid token
/// by every rule above. Call this only on a value you have already isolated
/// structurally as the provider's error-code field — never on a whole body, a
/// free-text message, or an arbitrary header. See the module docs.
pub fn validate_code_token(raw: &[u8]) -> Option<String> {
    let token = raw.trim_ascii();
    if token.is_empty() || token.len() > MAX_TOKEN_CHARS {
        return None;
    }
    if !token[0].is_ascii_alphabetic() {
        return None;
    }
    token
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        .then(|| token.iter().copied().map(char::from).collect())
}

/// The code at `pointer` in a JSON provider error document, within
/// [`SCAN_LIMIT`].
///
/// Does step 1 of the module contract for JSON bodies: the field is isolated
/// structurally by pointer — `/error` for an OAuth error response, `/error/code`
/// for an Azure DFS one — and only then validated. Parsing is bounded to the
/// window because it builds a whole `serde_json::Value` tree, so an endpoint
/// answering a failed request with a multi-megabyte document would otherwise
/// allocate well past the already-buffered body to recover one short token.
///
/// Returns `None` when the body does not parse within the window, the pointer
/// is absent or not a string, or the value is not a clean token — all of which
/// the caller reports as a body length.
///
/// # The pointer is the security decision, and it is yours
///
/// This validates the value's grammar; it cannot check that the pointer names a
/// code field. Point it at free text and a token-shaped secret comes straight
/// back out — `json_code(br#"{"error_description":"AQEBk7h2secretHANDLE"}"#,
/// "/error_description")` returns that handle, because it is a valid token by
/// every rule [`validate_code_token`] applies. Name the provider's documented
/// error-code field and nothing else: `/error` for an OAuth response,
/// `/error/code` for an Azure DFS one. Never a `message`, a `description`, or a
/// pointer built from caller input.
///
/// Fields with a different grammar need a different validator. A
/// `correlation_id` is a GUID and legitimately begins with a digit, so this
/// would reject every real one — see the Azure plugin's `correlation_token`.
pub fn json_code(body: &[u8], pointer: &str) -> Option<String> {
    let window = &body[..body.len().min(SCAN_LIMIT)];
    let value: serde_json::Value = serde_json::from_slice(window).ok()?;
    validate_code_token(value.pointer(pointer)?.as_str()?.as_bytes())
}

/// The code from an XML provider error document, within [`SCAN_LIMIT`].
///
/// Takes the first `<Code>` element that is a direct child of a root `<Error>`
/// element, and returns its text through [`validate_code_token`].
///
/// # The structural rule is the security property
///
/// A scan for the first literal `<Code>` anywhere in the window also matches one
/// written inside a comment, inside `<![CDATA[…]]>`, or nested in the free-text
/// `<Message>` — all places provider- or proxy-controlled content lands. Any
/// token-shaped material there would then be surfaced *ahead of* the document's
/// real code:
///
/// ```text
/// <Error><Message><![CDATA[<Code>abcdef0123…</Code>]]></Message>
///        <Code>AuthenticationFailed</Code></Error>
/// ```
///
/// AWS, Azure and GCS all emit `<Code>` as a direct child of a root `<Error>`,
/// so requiring exactly that costs nothing and makes those spans inert. The root
/// name is checked too: `validate_code_token` accepts token-shaped secrets by
/// design, so without it a `<ProxyError><Code>AKIA…</Code></ProxyError>` from an
/// intermediary would be reported as a provider code.
///
/// # It fails closed
///
/// This reads a deliberately narrow grammar rather than parsing XML. Elements
/// are tracked on a name stack, so a closing tag that does not match the element
/// it closes is a malformation, not a level; start tags are scanned with quote
/// awareness, so a `/>` inside an attribute value does not fake a self-closing
/// element; comments, CDATA sections, processing instructions and doctype
/// declarations (including an internal subset) are skipped whole rather than
/// scanned into. Anything that does not fit — an unterminated tag or span, a
/// mismatched or unbalanced close, markup inside the code element — yields
/// `None`, and the caller reports the body by length.
///
/// Failing closed costs a diagnostic, never a disclosure: the worst outcome is
/// `no provider error code; N byte body suppressed` for a document this does not
/// recognise. One deliberate exception keeps a common case working — a bare `<`
/// in element content (an unescaped `a < b` inside `<Message>`) is treated as
/// text rather than as a malformation, because a gateway emitting one should not
/// cost an operator the real code.
///
/// # One limit worth stating
///
/// A CDATA section ends at its first `]]>`, as XML requires. A provider that
/// interpolates untrusted text into one without escaping `]]>` emits different
/// markup than it intended, and the bytes after the escape really are elements —
/// any conforming parser reads them the same way, so a planted `<Code>` there is
/// structurally a child of the root. That is the provider's escaping bug rather
/// than something this can second-guess. The cost is bounded to a spoofed code
/// in a log: the value still has to pass [`validate_code_token`], so no secret
/// that is not already token-shaped can ride out on it.
///
/// Pass the raw response bytes, not a `String::from_utf8_lossy` of them; see
/// the module docs on why lossy conversion breaks the [`SCAN_LIMIT`] bound.
pub fn xml_code(body: &[u8]) -> Option<String> {
    let window = &body[..body.len().min(SCAN_LIMIT)];

    // Prolog: an XML declaration, comments or a doctype may precede the root.
    let mut pos = 0;
    let root = loop {
        let at = next_markup(window, pos)?;
        match markup_span(window, at) {
            Span::Ends(end) => pos = end,
            Span::Unterminated => return None,
            Span::Element => {
                pos = at;
                break read_tag(window, &mut pos)?;
            }
        }
    };
    if root.closing || root.self_closing || root.name != b"Error" {
        return None;
    }

    // Direct children of the root, and nothing deeper.
    loop {
        let at = next_markup(window, pos)?;
        match markup_span(window, at) {
            Span::Ends(end) => {
                pos = end;
                continue;
            }
            Span::Unterminated => return None,
            Span::Element => pos = at,
        }
        let tag = read_tag(window, &mut pos)?;
        if tag.closing {
            // The root closed without a code, or the document is unbalanced.
            return None;
        }
        if tag.name == b"Code" {
            return (!tag.self_closing)
                .then(|| code_element_text(window, pos))
                .flatten();
        }
        if !tag.self_closing {
            pos = skip_element(window, pos, tag.name)?;
        }
    }
}

/// The text of a `<Code>` element that opened at `from`, if it holds no markup.
///
/// The element must be closed by `</Code>` with nothing but text between, so a
/// `<Code>` carrying a nested element or a CDATA section is rejected outright
/// rather than having its markup stripped.
fn code_element_text(window: &[u8], from: usize) -> Option<String> {
    let rest = window.get(from..)?;
    let text_end = find(rest, b"<")?;
    if !rest[text_end..].starts_with(b"</Code>") {
        return None;
    }
    validate_code_token(&rest[..text_end])
}

/// Consume an element opened at `pos` whose name is `name`, yielding the index
/// just past its closing tag.
///
/// Names are stacked, and a close that does not match the top of the stack ends
/// the scan rather than being counted as a level. Without that, unbalanced
/// markup could return the depth counter to 1 mid-document and present a nested
/// element as a direct child of the root — including a payload that escapes a
/// CDATA section at its first `]]>` and continues with a stray close.
fn skip_element(window: &[u8], mut pos: usize, name: &[u8]) -> Option<usize> {
    let mut stack = vec![name];
    loop {
        let at = next_markup(window, pos)?;
        match markup_span(window, at) {
            Span::Ends(end) => {
                pos = end;
                continue;
            }
            Span::Unterminated => return None,
            Span::Element => pos = at,
        }
        let tag = read_tag(window, &mut pos)?;
        if tag.closing {
            if stack.pop()? != tag.name {
                return None;
            }
            if stack.is_empty() {
                return Some(pos);
            }
        } else if !tag.self_closing {
            stack.push(tag.name);
        }
    }
}

/// A start or end tag.
struct Tag<'a> {
    name: &'a [u8],
    closing: bool,
    self_closing: bool,
}

/// Read the tag beginning at `*pos`, advancing `*pos` past its `>`.
///
/// The scan for `>` and for the self-closing `/` is quote-aware: an attribute
/// value may legitimately contain either, and treating a quoted `/>` as the end
/// of the tag is what would let an open element pass for a self-closing one and
/// leave the nesting depth wrong. An unterminated or nameless tag yields `None`.
fn read_tag<'a>(window: &'a [u8], pos: &mut usize) -> Option<Tag<'a>> {
    let mut at = *pos + 1;
    let closing = window.get(at) == Some(&b'/');
    if closing {
        at += 1;
    }
    let name_start = at;
    while window.get(at).is_some_and(|byte| is_name_byte(*byte)) {
        at += 1;
    }
    let name = window.get(name_start..at)?;
    if name.is_empty() {
        return None;
    }
    // XML names may contain non-ASCII, which this grammar does not model.
    // Stopping the scan there and carrying on would TRUNCATE the name, so
    // `<Erroré>` would read as `Error` and pass the root check. A name that
    // runs into a byte this cannot classify is not a name it can judge.
    if window.get(at).is_some_and(|byte| !byte.is_ascii()) {
        return None;
    }

    let mut quote: Option<u8> = None;
    let mut last_solid = 0u8;
    while at < window.len() {
        let byte = window[at];
        match quote {
            Some(open) if byte == open => quote = None,
            Some(_) => {}
            None if byte == b'"' || byte == b'\'' => quote = Some(byte),
            None if byte == b'>' => {
                *pos = at + 1;
                return Some(Tag {
                    name,
                    closing,
                    self_closing: last_solid == b'/',
                });
            }
            None => {}
        }
        if quote.is_none() && !byte.is_ascii_whitespace() {
            last_solid = byte;
        }
        at += 1;
    }
    None
}

/// The next `<` that begins markup.
///
/// A `<` not followed by a name start, `/`, `!` or `?` is ordinary text — an
/// unescaped `a < b` in a message — and is stepped over rather than treated as a
/// tag. Consuming it as one would swallow the genuine closing tag that follows
/// and lose the document's real code.
///
/// A `<` followed by a non-ASCII byte is neither: it opens an element whose name
/// this grammar cannot model. It is returned as markup so [`read_tag`] rejects it
/// and the scan fails closed, because stepping over it as text would let a
/// wrapper like `<Échec>` be ignored and promote the element inside it to
/// document root.
fn next_markup(window: &[u8], mut pos: usize) -> Option<usize> {
    while pos < window.len() {
        if window[pos] == b'<'
            && window.get(pos + 1).is_some_and(|byte| {
                is_name_byte(*byte) || matches!(byte, b'/' | b'!' | b'?') || !byte.is_ascii()
            })
        {
            return Some(pos);
        }
        pos += 1;
    }
    None
}

/// A markup span that is not an element.
enum Span {
    /// `at` begins an element, not one of these.
    Element,
    /// The index just past it.
    Ends(usize),
    /// It never closes inside the window.
    Unterminated,
}

/// Classify the span at `at`: a comment, CDATA section, processing instruction
/// or declaration, none of whose contents are ever scanned as markup.
///
/// An unterminated span is reported rather than skipped to the window's end, so
/// the caller stops instead of resuming inside content it cannot delimit.
fn markup_span(window: &[u8], at: usize) -> Span {
    let rest = &window[at..];
    let (opener, closer): (&[u8], &[u8]) = if rest.starts_with(b"<!--") {
        (b"<!--", b"-->")
    } else if rest.starts_with(b"<![CDATA[") {
        (b"<![CDATA[", b"]]>")
    } else if rest.starts_with(b"<?") {
        (b"<?", b"?>")
    } else if rest.starts_with(b"<!") {
        return declaration_span(window, at);
    } else {
        return Span::Element;
    };
    match find(&rest[opener.len()..], closer) {
        Some(end) => Span::Ends(at + opener.len() + end + closer.len()),
        None => Span::Unterminated,
    }
}

/// A `<!…>` declaration, including a doctype carrying an internal subset.
///
/// The subset is delimited by `[`…`]` and may itself contain markup, so ending
/// the declaration at the first `>` would resume the scan *inside* it — where an
/// entity's replacement text could present a planted `<Code>` as a child of the
/// root. Quoted values are skipped for the same reason.
///
/// A subset may also hold comments, processing instructions and conditional
/// sections, whose contents are unrestricted. Those are skipped whole rather
/// than walked, because a `]` or `>` inside one is content, not structure —
/// a comment reading `<!-- ]> <Error><Code>…</Code> -->` would otherwise close
/// the declaration early and hand the scan a planted root. Brackets are counted
/// rather than flagged so a conditional section's own `[` does not unbalance it.
fn declaration_span(window: &[u8], at: usize) -> Span {
    let mut pos = at + 2;
    let mut quote: Option<u8> = None;
    let mut depth = 0usize;
    while pos < window.len() {
        let byte = window[pos];
        if quote.is_none() && depth > 0 {
            // Inside the subset, an inner span's contents are not structure.
            let rest = &window[pos..];
            let inner: Option<(usize, &[u8])> = if rest.starts_with(b"<!--") {
                Some((4, b"-->"))
            } else if rest.starts_with(b"<![") {
                Some((3, b"]]>"))
            } else if rest.starts_with(b"<?") {
                Some((2, b"?>"))
            } else {
                None
            };
            if let Some((opener, closer)) = inner {
                match find(&rest[opener..], closer) {
                    Some(end) => {
                        pos += opener + end + closer.len();
                        continue;
                    }
                    None => return Span::Unterminated,
                }
            }
        }
        match quote {
            Some(open) if byte == open => quote = None,
            Some(_) => {}
            None if byte == b'"' || byte == b'\'' => quote = Some(byte),
            None if byte == b'[' => depth += 1,
            None if byte == b']' => depth = depth.saturating_sub(1),
            None if byte == b'>' && depth == 0 => return Span::Ends(pos + 1),
            None => {}
        }
        pos += 1;
    }
    Span::Unterminated
}

/// Bytes that may appear in an element name. `:` is included so a namespaced
/// `<ns:Code>` reads as the name `ns:Code`, which is not `Code`.
fn is_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':')
}

/// First index of `needle` in `haystack`.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// The reportable detail from a failed OAuth token-endpoint response.
///
/// An OAuth error document's `error_description` echoes the material the IDP
/// rejected — a client secret, or a federated workload identity's projected
/// token — so the body never reaches an error message. Only the `error` field
/// does, and only when it validates as a provider error-code token; anything
/// else is reported as a length.
///
/// This is the wrapper for legs that need nothing around the body-shaped
/// filter: the interactive and device flows and the credential provider in
/// `ovstorage`, and the token grants in the broker and Omniverse Storage
/// Service client plugins. It lives here rather than beside any one of them
/// because the first fix closed the plugin-crate legs and left the ones in the
/// crate below them open.
///
/// **It is not the chokepoint, and a sweep for closure must not grep this
/// symbol.** Other legs reach the same guarantee by other routes: the Azure and
/// GCS token legs call [`json_code`] directly, because each wraps it in
/// provider-specific context (a correlation token, a length fallback), and the
/// device flow's terminal poll arm calls [`validate_code_token`] directly,
/// because it already has the field and needs no document scan. The shared
/// floor under all three is [`validate_code_token`] — [`json_code`] isolates a
/// field and then calls it. **Grep that.**
pub fn oauth_error_detail(body: &[u8]) -> String {
    json_code(body, "/error").unwrap_or_else(|| {
        format!(
            "no provider error code; {} byte body suppressed",
            body.len()
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The OAuth chokepoint keeps the code token and drops everything else.
    ///
    /// `error_description` is the field that echoes the rejected assertion —
    /// a client secret, or a projected workload-identity token — so it must
    /// not survive, while `error` must, or an operator loses the only usable
    /// diagnostic.
    #[test]
    fn oauth_error_detail_keeps_the_code_and_drops_the_description() {
        let body = br#"{"error":"invalid_client","error_description":"rejected: s3cr3t"}"#;
        let detail = oauth_error_detail(body);
        assert_eq!(detail, "invalid_client");
        assert!(!detail.contains("s3cr3t"));
    }

    /// Anything that does not yield a valid code token is reported as a
    /// length, never as text — an IDP answering with an HTML error page must
    /// not put that page into the message.
    #[test]
    fn oauth_error_detail_reports_an_unusable_body_as_a_length() {
        let detail = oauth_error_detail(b"<html>Bearer eyJleaked</html>");
        assert!(!detail.contains("eyJleaked"));
        assert!(detail.contains("byte body suppressed"));
    }

    #[test]
    fn a_whole_clean_token_is_accepted() {
        assert_eq!(
            validate_code_token(b"AuthenticationFailed").as_deref(),
            Some("AuthenticationFailed")
        );
        assert_eq!(
            validate_code_token(b"  \n NoSuchKey \t ").as_deref(),
            Some("NoSuchKey")
        );
        assert_eq!(
            validate_code_token(b"invalid.grant_1-x").as_deref(),
            Some("invalid.grant_1-x")
        );
    }

    /// The disclosure this module exists to prevent: a code with credential
    /// material welded on must be rejected WHOLE, not filtered down to the
    /// code. Filtering would surface the MAC.
    #[test]
    fn a_token_carrying_credential_material_is_rejected_whole() {
        let mac = b"AuthenticationFailed 7hK4wQ2mZ9pR1tY6uXbN5cJfA8sVdE3o=";
        assert_eq!(validate_code_token(mac), None);
        // ... and the same value inside a document yields nothing either.
        let body =
            b"<Error><Code>AuthenticationFailed 7hK4wQ2mZ9pR1tY6uXbN5cJfA8sVdE3o=</Code></Error>";
        assert_eq!(xml_code(body), None);
    }

    #[test]
    fn a_non_token_is_rejected() {
        assert_eq!(validate_code_token(b""), None);
        assert_eq!(validate_code_token(b"   "), None);
        // Must start with a letter.
        assert_eq!(validate_code_token(b"1NoSuchKey"), None);
        assert_eq!(validate_code_token(b"-NoSuchKey"), None);
        // No spaces, slashes, equals, or non-ASCII.
        assert_eq!(validate_code_token(b"No Such Key"), None);
        assert_eq!(validate_code_token(b"a/b"), None);
        assert_eq!(validate_code_token("Codé".as_bytes()), None);
        // A value whose FIRST byte is a UTF-8 lead byte, so the leading-letter
        // check is what rejects it rather than the character-class sweep.
        assert_eq!(validate_code_token("é".repeat(8).as_bytes()), None);
    }

    /// `trim_ascii` is what makes this stricter than a `&str` implementation
    /// using `trim()`, which would strip these and accept the value.
    #[test]
    fn unicode_whitespace_padding_is_not_trimmed_away() {
        assert_eq!(validate_code_token("\u{00A0}SlowDown".as_bytes()), None);
        assert_eq!(validate_code_token("SlowDown\u{3000}".as_bytes()), None);
    }

    /// Rejected, not truncated: a truncated value is still a prefix of
    /// whatever was in the field.
    #[test]
    fn an_over_long_token_is_rejected_rather_than_truncated() {
        let long = vec![b'A'; MAX_TOKEN_CHARS + 1];
        assert_eq!(validate_code_token(&long), None);
        let at_cap = vec![b'A'; MAX_TOKEN_CHARS];
        assert_eq!(
            validate_code_token(&at_cap).map(|s| s.len()),
            Some(MAX_TOKEN_CHARS)
        );
    }

    #[test]
    fn the_first_code_child_of_the_root_is_taken() {
        let body = b"<Error><Code>NoSuchKey</Code><Code>Second</Code></Error>";
        assert_eq!(xml_code(body).as_deref(), Some("NoSuchKey"));
    }

    /// Real documents from all three providers, including the shapes that
    /// motivated the structural rule: an XML declaration ahead of the root, and
    /// sibling elements before the code.
    #[test]
    fn real_provider_documents_still_yield_their_code() {
        let s3 = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>SignatureDoesNotMatch</Code><Message>...</Message><StringToSign>AWS4-HMAC</StringToSign></Error>";
        assert_eq!(xml_code(s3).as_deref(), Some("SignatureDoesNotMatch"));

        let azure = b"<?xml version=\"1.0\" encoding=\"utf-8\"?><Error><Code>AuthenticationFailed</Code><Message>Server failed to authenticate.</Message><AuthenticationErrorDetail>sig=7hK4wQ2m</AuthenticationErrorDetail></Error>";
        assert_eq!(xml_code(azure).as_deref(), Some("AuthenticationFailed"));

        let indented = b"<Error>\n  <Code>\n    BlobNotFound\n  </Code>\n</Error>";
        assert_eq!(xml_code(indented).as_deref(), Some("BlobNotFound"));
    }

    /// A `<Code>` written inside a comment, inside CDATA, or nested in the
    /// free-text `<Message>` is provider- or proxy-controlled content, and
    /// token-shaped material there must NOT be surfaced ahead of the real code.
    ///
    /// Each case pairs the hostile span with a genuine code afterwards, so the
    /// assertion proves the scan skipped the span and went on to find the real
    /// one -- not that it merely gave up.
    #[test]
    fn a_code_in_a_comment_cdata_or_message_is_not_read() {
        let sig = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

        let cdata = format!(
            "<Error><Message><![CDATA[<Code>{sig}</Code>]]></Message><Code>AuthenticationFailed</Code></Error>"
        );
        assert_eq!(
            xml_code(cdata.as_bytes()).as_deref(),
            Some("AuthenticationFailed")
        );

        let comment = format!("<Error><!-- <Code>{sig}</Code> --><Code>NoSuchKey</Code></Error>");
        assert_eq!(xml_code(comment.as_bytes()).as_deref(), Some("NoSuchKey"));

        let nested = format!(
            "<Error><Message>see <Code>{sig}</Code></Message><Code>SlowDown</Code></Error>"
        );
        assert_eq!(xml_code(nested.as_bytes()).as_deref(), Some("SlowDown"));

        // The signature must not appear in ANY of the three results.
        for body in [cdata, comment, nested] {
            assert_ne!(xml_code(body.as_bytes()).as_deref(), Some(sig));
        }
    }

    /// The JSON path isolates the field by pointer, then validates it — the two
    /// steps of the module contract. An OAuth body's `error_description` echoes
    /// the rejected assertion and must never be reachable.
    #[test]
    fn a_json_code_is_isolated_by_pointer_then_validated() {
        let oauth = br#"{"error":"invalid_grant","error_description":"assertion=eyJ.SECRET"}"#;
        assert_eq!(json_code(oauth, "/error").as_deref(), Some("invalid_grant"));
        // This fixture's free-text field is rejected because it is not
        // token-shaped -- NOT because the function knows it is free text. It
        // cannot: see below.
        assert_eq!(json_code(oauth, "/error_description"), None);

        let azure = br#"{"error":{"code":"BlobNotFound","message":"nope"}}"#;
        assert_eq!(
            json_code(azure, "/error/code").as_deref(),
            Some("BlobNotFound")
        );

        // A code with credential material welded on is rejected WHOLE.
        let hostile = br#"{"error":"invalid_grant sig=7hK4wQ2mZ9pR1tY6uXbN5cJfA8sVdE3o="}"#;
        assert_eq!(json_code(hostile, "/error"), None);

        // Absent pointer, non-string value, and unparseable body.
        assert_eq!(json_code(oauth, "/nope"), None);
        assert_eq!(json_code(br#"{"error":{"code":7}}"#, "/error/code"), None);
        assert_eq!(json_code(b"<html>not json</html>", "/error"), None);
        assert_eq!(json_code(b"", "/error"), None);
    }

    /// The pointer is the caller's decision and this cannot second-guess it: a
    /// pointer aimed at free text returns whatever token-shaped material is
    /// there. Pinned so the limit is a stated property rather than a surprise,
    /// and so the docs that warn about it cannot quietly stop being true.
    #[test]
    fn a_pointer_at_free_text_returns_whatever_is_token_shaped() {
        let handle = br#"{"error_description":"AQEBk7h2secretHANDLE"}"#;
        assert_eq!(
            json_code(handle, "/error_description").as_deref(),
            Some("AQEBk7h2secretHANDLE")
        );
        let hex = br#"{"error":{"message":"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"}}"#;
        assert_eq!(
            json_code(hex, "/error/message").as_deref(),
            Some("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4")
        );
    }

    /// The JSON parse takes the same window as the XML scan, so a huge document
    /// is not parsed whole to recover one short token.
    #[test]
    fn a_json_body_past_the_scan_limit_is_not_parsed() {
        // `{"pad":"` (8) + padding + `","error":"invalid_grant"}` (26).
        const OVERHEAD: usize = 34;
        let far = format!(
            r#"{{"pad":"{}","error":"invalid_grant"}}"#,
            " ".repeat(SCAN_LIMIT)
        );
        assert_eq!(json_code(far.as_bytes(), "/error"), None);
        // The control sits JUST under the boundary rather than comfortably
        // inside it, so the pair brackets SCAN_LIMIT itself. A control of a few
        // dozen bytes would pass for any window between its own size and the
        // real one, proving only that some bound exists.
        let inside = format!(
            r#"{{"pad":"{}","error":"invalid_grant"}}"#,
            " ".repeat(SCAN_LIMIT - OVERHEAD)
        );
        assert_eq!(
            inside.len(),
            SCAN_LIMIT,
            "the control must straddle the bound"
        );
        assert_eq!(
            json_code(inside.as_bytes(), "/error").as_deref(),
            Some("invalid_grant")
        );
    }

    /// The root element name is checked, not just the shape. `validate_code_token`
    /// accepts token-shaped secrets by design, so an intermediary's own error
    /// envelope must not be read as a provider error document.
    #[test]
    fn a_document_with_another_root_is_not_a_provider_error() {
        assert_eq!(
            xml_code(b"<ProxyError><Code>AKIAIOSFODNN7EXAMPLE</Code></ProxyError>"),
            None
        );
        assert_eq!(xml_code(b"<Code>NoSuchKey</Code>"), None);
    }

    /// Scanning must stop when the root closes. Otherwise concatenated or
    /// malformed input presents a second top-level element's content as though
    /// it were a child of the error envelope.
    #[test]
    fn a_code_after_the_root_closes_is_not_read() {
        let sig = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let body = format!("<Error></Error><Tail><Code>{sig}</Code></Tail>");
        assert_eq!(xml_code(body.as_bytes()), None);
    }

    /// A `/>` inside a quoted attribute value must not make an open element look
    /// self-closing — that would leave the depth wrong and present the nested
    /// `<Code>` as a direct child of the root.
    #[test]
    fn a_slash_inside_an_attribute_does_not_fake_a_self_closing_tag() {
        let sig = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let body = format!(
            "<Error><Message data=\"/>\"><Code>{sig}</Code></Message><Code>AuthenticationFailed</Code></Error>"
        );
        assert_eq!(
            xml_code(body.as_bytes()).as_deref(),
            Some("AuthenticationFailed")
        );
    }

    /// A doctype's internal subset may contain markup. Ending the declaration at
    /// its first `>` would resume the scan inside the subset, where an entity's
    /// replacement text can plant a `<Code>`.
    #[test]
    fn a_code_inside_a_doctype_subset_is_not_read() {
        let sig = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let body = format!(
            "<!DOCTYPE E [<!ENTITY e \"<X><Y><Code>{sig}</Code>\">]><Error><Code>Real</Code></Error>"
        );
        assert_eq!(xml_code(body.as_bytes()).as_deref(), Some("Real"));
    }

    /// A doctype's internal subset may legally contain comments and processing
    /// instructions, whose contents are unrestricted. A `]` inside one must not
    /// end the subset, or the scan resumes inside markup it was meant to skip
    /// and reads a planted root.
    #[test]
    fn a_code_inside_a_subset_comment_or_pi_is_not_read() {
        let sig = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

        let comment = format!(
            "<!DOCTYPE Error [<!-- ]> <Error><Code>{sig}</Code> -->]><Error><Code>Real</Code></Error>"
        );
        assert_eq!(xml_code(comment.as_bytes()).as_deref(), Some("Real"));

        let pi = format!(
            "<!DOCTYPE Error [<?p ]><Error><Code>{sig}</Code>?>]><Error><Code>Real</Code></Error>"
        );
        assert_eq!(xml_code(pi.as_bytes()).as_deref(), Some("Real"));

        // A conditional section nests brackets, so a single flag would clear on
        // the inner `]`.
        let conditional = format!(
            "<!DOCTYPE Error [<![INCLUDE[ ]> <Error><Code>{sig}</Code> ]]>]><Error><Code>Real</Code></Error>"
        );
        assert_eq!(xml_code(conditional.as_bytes()).as_deref(), Some("Real"));
    }

    /// Element names may legally contain non-ASCII, which this grammar does not
    /// model. Truncating a name at the first non-ASCII byte would make
    /// `<Erroré>` pass the root check, so such a name fails closed instead.
    #[test]
    fn a_non_ascii_element_name_fails_closed() {
        let sig = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

        let truncated = format!("<Erroré><Code>{sig}</Code></Erroré>");
        assert_eq!(xml_code(truncated.as_bytes()), None);

        // ... and a non-ASCII-leading wrapper must not be stepped over as text,
        // which would promote the element inside it to document root.
        let wrapper = format!("<Échec><Error><Code>{sig}</Code></Error></Échec>");
        assert_eq!(xml_code(wrapper.as_bytes()), None);
    }

    /// Same hazard in a processing instruction.
    #[test]
    fn a_code_inside_a_processing_instruction_is_not_read() {
        let sig = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let body = format!("<?php echo \"<Code>{sig}</Code>\"; ?><Error><Code>Real</Code></Error>");
        assert_eq!(xml_code(body.as_bytes()).as_deref(), Some("Real"));
    }

    /// Unbalanced markup must not be able to walk the nesting back to the root's
    /// level and present a nested element as a direct child.
    #[test]
    fn unbalanced_markup_fails_closed() {
        assert_eq!(
            xml_code(
                b"<Error><Message></Bogus><Code>Injected</Code></Message><Code>Real</Code></Error>"
            ),
            None
        );
        // A close that matches nothing at all, for the same reason.
        assert_eq!(
            xml_code(b"<Error></Message><Code>Injected</Code></Error>"),
            None
        );
    }

    /// A CDATA section ends at its FIRST `]]>`, as XML requires. A provider that
    /// interpolates untrusted text into one without escaping `]]>` therefore
    /// emits different markup than it intended, and the bytes after the escape
    /// really are elements — a conforming parser reads them the same way.
    ///
    /// Pinned so the limit is a stated property rather than an accident: this is
    /// the provider's escaping bug, not something the scanner can second-guess,
    /// and it costs a spoofed code in a log rather than a disclosed secret,
    /// because the value still has to pass [`validate_code_token`].
    #[test]
    fn a_payload_escaping_its_cdata_section_is_read_as_markup() {
        let body = "<Error><Message><![CDATA[]]></Message><Code>Injected</Code>]]></Message><Code>Real</Code></Error>";
        assert_eq!(xml_code(body.as_bytes()).as_deref(), Some("Injected"));
    }

    /// The one place malformation is tolerated rather than fatal: an unescaped
    /// `<` in element content is text. Consuming it as a tag would swallow the
    /// closing tag after it and lose a code the old scanners found.
    #[test]
    fn a_bare_left_angle_in_content_is_text() {
        assert_eq!(
            xml_code(b"<Error><Message>a < b</Message><Code>NoSuchKey</Code></Error>").as_deref(),
            Some("NoSuchKey")
        );
    }

    /// A `<Code>` element carrying markup is rejected outright rather than
    /// having its markup stripped, on the same reject-whole principle as
    /// [`validate_code_token`].
    #[test]
    fn a_code_element_containing_markup_is_rejected() {
        assert_eq!(
            xml_code(b"<Error><Code><![CDATA[NoSuchKey]]></Code></Error>"),
            None
        );
        assert_eq!(
            xml_code(b"<Error><Code>No<b>Such</b>Key</Code></Error>"),
            None
        );
    }

    #[test]
    fn an_unterminated_or_absent_code_yields_nothing() {
        assert_eq!(xml_code(b"<Error><Code>NoSuchKey</Error>"), None);
        assert_eq!(xml_code(b"<Error><Message>nope</Message></Error>"), None);
        assert_eq!(xml_code(b""), None);
        assert_eq!(xml_code(b"<Co"), None);
        // An unterminated tag or span stops the scan rather than resuming
        // inside it.
        assert_eq!(xml_code(b"<Error><Code"), None);
        assert_eq!(xml_code(b"<Error><!-- <Code>NoSuchKey</Code>"), None);
    }

    /// Element names that merely start with, or contain, `Code`.
    #[test]
    fn a_differently_named_element_is_not_a_code() {
        assert_eq!(
            xml_code(b"<Error><CodePoint>NoSuchKey</CodePoint></Error>"),
            None
        );
        assert_eq!(
            xml_code(b"<Error><ns:Code>NoSuchKey</ns:Code></Error>"),
            None
        );
        assert_eq!(xml_code(b"<Error><Code/></Error>"), None);
    }

    /// The bound is on the WINDOW, so a code pushed past it is not found --
    /// which is the point: the scan must not walk a hostile body.
    ///
    /// This is the behaviour S3's copy lacked; it scanned the whole body.
    #[test]
    fn a_code_past_the_scan_limit_is_not_found() {
        let mut body = b"<Error>".to_vec();
        body.resize(SCAN_LIMIT, b' ');
        body.extend_from_slice(b"<Code>NoSuchKey</Code></Error>");
        assert_eq!(xml_code(&body), None);

        // Just inside the window it is still found, so the test above is
        // measuring the bound rather than a broken scanner.
        let mut inside = b"<Error>".to_vec();
        inside.resize(SCAN_LIMIT - 32, b' ');
        inside.extend_from_slice(b"<Code>NoSuchKey</Code></Error>");
        assert_eq!(xml_code(&inside).as_deref(), Some("NoSuchKey"));
    }
}
