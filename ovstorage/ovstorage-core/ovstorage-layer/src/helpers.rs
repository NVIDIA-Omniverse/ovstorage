// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};

use futures::Stream;

use crate::{CancellationToken, Error, ErrorCode, EtagStrength, ListStream};

struct CancelListStream {
    inner: Option<ListStream>,
    cancelled: Pin<Box<dyn Future<Output = ()> + Send>>,
    terminal: bool,
}

impl Stream for CancelListStream {
    type Item = crate::Result<crate::ObjectInfo>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.terminal {
            return Poll::Ready(None);
        }
        if this.cancelled.as_mut().poll(cx).is_ready() {
            this.terminal = true;
            drop(this.inner.take());
            return Poll::Ready(Some(Err(Error::new(
                ErrorCode::Cancelled,
                "list_stream cancelled",
            ))));
        }
        let next = this
            .inner
            .as_mut()
            .expect("non-terminal cancel wrapper retains its source")
            .as_mut()
            .poll_next(cx);
        match next {
            Poll::Ready(Some(Err(error))) => {
                this.terminal = true;
                drop(this.inner.take());
                Poll::Ready(Some(Err(error)))
            }
            Poll::Ready(None) => {
                this.terminal = true;
                drop(this.inner.take());
                Poll::Ready(None)
            }
            other => other,
        }
    }
}

/// Bind the token supplied while opening a listing to every yielded entry.
///
/// Cancellation wins before any entry already buffered by a downstream fold
/// or transform and produces exactly one terminal [`ErrorCode::Cancelled`]
/// item. Without a token, this returns `stream` unchanged.
#[must_use]
pub fn cancel_list_stream(stream: ListStream, cancel: Option<CancellationToken>) -> ListStream {
    let Some(cancel) = cancel else {
        return stream;
    };
    Box::pin(CancelListStream {
        inner: Some(stream),
        cancelled: Box::pin(cancel.cancelled_owned()),
        terminal: false,
    })
}

/// Construct the canonical bounded-read failure shared by hosts and cache
/// Layers.
pub fn read_bytes_max_bytes_error(cap: u64) -> Error {
    Error::new(
        ErrorCode::ResourceExhausted,
        format!("read exceeded max_bytes cap of {cap} bytes"),
    )
    .with_next_action(
        "Increase ReadOptions::max_bytes, narrow the read range \
         via ReadOptions::range, or use read_stream to consume \
         the object incrementally.",
    )
}

/// Synthesize the canonical validator for a file's size and modification time.
///
/// File stat, watch events, and followed `file://` redirects use this one
/// implementation so validators round-trip across those paths.
pub fn synthesize_file_etag(size: u64, mtime: Option<SystemTime>) -> String {
    let nanos = mtime
        .and_then(|mtime| mtime.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    format!("size:{size},mtime:{nanos}")
}

/// Normalize an entity-tag received from an HTTP header and retain its
/// declared validator strength out of band.
///
/// Only a nonempty, syntactically valid quoted HTTP entity-tag is declared
/// [`EtagStrength::Strong`]. An explicit `W/` marker is declared
/// [`EtagStrength::Weak`], while an unmarked bare or malformed value is
/// [`EtagStrength::Unspecified`]. The token remains available for opaque
/// backend comparisons even when its syntax makes no strength promise.
/// Provider schema fields that encode a strong validator without HTTP quotes
/// declare that strength at their provider boundary instead of relying on
/// this HTTP entity-tag parser: redirect producers set
/// `ResponseParsing::etag_strength` for custom validator headers, while direct
/// metadata producers set `ObjectInfo::etag_strength` in their constructor.
pub fn normalize_wire_etag(raw: &str) -> (String, EtagStrength) {
    let raw = raw.trim();
    let (etag, explicitly_weak) = if let Some(etag) = raw.strip_prefix("W/") {
        (etag.trim(), true)
    } else {
        (raw, false)
    };

    let normalized = etag
        .strip_prefix('"')
        .and_then(|etag| etag.strip_suffix('"'))
        .unwrap_or(etag);
    let strength = if explicitly_weak {
        EtagStrength::Weak
    } else if is_nonempty_http_entity_tag(etag) {
        EtagStrength::Strong
    } else {
        // RFC 9110 §8.8.3 requires DQUOTE-delimited entity-tags; bare or
        // malformed syntax carries no strength evidence.
        EtagStrength::Unspecified
    };
    (normalized.to_owned(), strength)
}

/// Whether `raw` is a nonempty quoted entity-tag under RFC 9110's `etagc`
/// grammar. HTTP header decoding has already produced UTF-8, whose non-ASCII
/// bytes all fall in the grammar's `obs-text` range.
fn is_nonempty_http_entity_tag(raw: &str) -> bool {
    let Some(opaque) = raw
        .strip_prefix('"')
        .and_then(|etag| etag.strip_suffix('"'))
    else {
        return false;
    };
    !opaque.is_empty()
        && opaque
            .bytes()
            .all(|byte| byte == 0x21 || (0x23..=0x7e).contains(&byte) || byte >= 0x80)
}

/// Normalize an optional etag received from a wire protocol and retain its
/// declared validator strength out of band.
pub fn normalize_optional_wire_etag(raw: Option<&str>) -> (Option<String>, EtagStrength) {
    raw.map(normalize_wire_etag)
        .map_or((None, EtagStrength::Unspecified), |(etag, strength)| {
            (Some(etag), strength)
        })
}

#[cfg(test)]
mod tests {
    use futures::StreamExt as _;

    use super::*;
    use crate::{ChecksumSet, ObjectInfo, ObjectKind, Url};

    fn item(path: &str) -> ObjectInfo {
        ObjectInfo {
            etag_strength: EtagStrength::Unspecified,
            address: Url::parse(path).unwrap(),
            kind: ObjectKind::File,
            etag: None,
            version: None,
            size: Some(1),
            mtime: None,
            checksums: ChecksumSet::default(),
            effective_permissions: None,
            system_metadata: None,
            user_metadata: None,
            modified_by: None,
            versioned_address: None,
        }
    }

    #[tokio::test]
    async fn cancellation_preempts_an_already_buffered_entry() {
        let cancel = CancellationToken::new();
        let source: ListStream = Box::pin(futures::stream::iter([
            Ok(item("test://root/first")),
            Ok(item("test://root/second")),
        ]));
        let mut stream = cancel_list_stream(source, Some(cancel.clone()));

        assert_eq!(
            stream.next().await.unwrap().unwrap().address.as_str(),
            "test://root/first"
        );
        cancel.cancel();
        assert_eq!(
            stream.next().await.unwrap().unwrap_err().code(),
            ErrorCode::Cancelled
        );
        assert!(stream.next().await.is_none(), "cancellation is terminal");
    }

    #[test]
    fn normalize_wire_etag_preserves_strength_out_of_band() {
        assert_eq!(
            normalize_wire_etag("W/\"abc\""),
            ("abc".to_owned(), EtagStrength::Weak)
        );
        assert_eq!(
            normalize_wire_etag("\"abc\""),
            ("abc".to_owned(), EtagStrength::Strong)
        );
        assert_eq!(
            normalize_wire_etag("abc"),
            ("abc".to_owned(), EtagStrength::Unspecified)
        );
        assert_eq!(
            normalize_wire_etag("W/abc"),
            ("abc".to_owned(), EtagStrength::Weak)
        );
        assert_eq!(
            normalize_wire_etag("\"\""),
            ("".to_owned(), EtagStrength::Unspecified)
        );
        assert_eq!(
            normalize_wire_etag("\"not an entity tag\""),
            ("not an entity tag".to_owned(), EtagStrength::Unspecified)
        );
        assert_eq!(
            normalize_wire_etag("\"unterminated"),
            ("\"unterminated".to_owned(), EtagStrength::Unspecified)
        );
        assert_eq!(
            normalize_wire_etag(""),
            ("".to_owned(), EtagStrength::Unspecified)
        );
    }

    #[test]
    fn normalize_optional_wire_etag_preserves_absence_and_strength() {
        assert_eq!(
            normalize_optional_wire_etag(None),
            (None, EtagStrength::Unspecified)
        );
        assert_eq!(
            normalize_optional_wire_etag(Some("")),
            (Some("".to_owned()), EtagStrength::Unspecified)
        );
        assert_eq!(
            normalize_optional_wire_etag(Some("W/\"abc\"")),
            (Some("abc".to_owned()), EtagStrength::Weak)
        );
        assert_eq!(
            normalize_optional_wire_etag(Some("\"abc\"")),
            (Some("abc".to_owned()), EtagStrength::Strong)
        );
    }
}
