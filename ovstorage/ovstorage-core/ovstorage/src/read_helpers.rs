// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::*;

pub(crate) fn read_bytes_max_bytes_error(cap: u64) -> Error {
    ovstorage_layer::read_bytes_max_bytes_error(cap)
}

fn read_stream_max_bytes_error(cap: u64) -> Error {
    Error::new(
        ErrorCode::ResourceExhausted,
        format!("read_stream exceeded max_bytes cap of {cap} bytes"),
    )
    .with_next_action(
        "Increase ReadOptions::max_bytes or narrow the read range \
         via ReadOptions::range.",
    )
}

pub(crate) fn ensure_read_bytes_within_max_bytes(len: usize, max_bytes: Option<u64>) -> Result<()> {
    if let Some(cap) = max_bytes
        && (len as u64) > cap
    {
        return Err(read_bytes_max_bytes_error(cap));
    }
    Ok(())
}

fn cap_read_stream(inner: ReadStream, cap: u64) -> ReadStream {
    use futures::StreamExt;
    Box::pin(futures::stream::unfold(
        (inner, 0u64, false),
        move |(mut inner, mut total, done)| async move {
            if done {
                return None;
            }
            let chunk_res = inner.next().await?;
            match chunk_res {
                Ok(chunk) => {
                    total = total.saturating_add(chunk.len() as u64);
                    if total > cap {
                        Some((Err(read_stream_max_bytes_error(cap)), (inner, total, true)))
                    } else {
                        Some((Ok(chunk), (inner, total, false)))
                    }
                }
                Err(error) => Some((Err(error), (inner, total, true))),
            }
        },
    ))
}

pub(crate) fn maybe_cap_read_stream(stream: ReadStream, max_bytes: Option<u64>) -> ReadStream {
    match max_bytes {
        Some(cap) => cap_read_stream(stream, cap),
        None => stream,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt as _;

    #[test]
    fn read_bytes_limit_accepts_under_cap_and_unbounded() {
        ensure_read_bytes_within_max_bytes(4, Some(4)).unwrap();
        ensure_read_bytes_within_max_bytes(100_000, None).unwrap();
    }

    #[test]
    fn read_bytes_limit_rejects_over_cap() {
        let error = ensure_read_bytes_within_max_bytes(4, Some(3)).unwrap_err();
        assert_eq!(error.code(), ErrorCode::ResourceExhausted);
        assert!(error.message().contains("max_bytes"));
        assert!(error.next_action().is_some());
    }

    #[tokio::test]
    async fn read_stream_limit_emits_error_after_cap() {
        let stream: ReadStream = Box::pin(futures::stream::iter([
            Ok(bytes::Bytes::from_static(b"ab")),
            Ok(bytes::Bytes::from_static(b"cd")),
        ]));
        let mut stream = maybe_cap_read_stream(stream, Some(3));
        assert_eq!(stream.next().await.unwrap().unwrap(), b"ab"[..]);
        let error = stream.next().await.unwrap().unwrap_err();
        assert_eq!(error.code(), ErrorCode::ResourceExhausted);
        assert!(stream.next().await.is_none());
    }
}
