// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Frame codec for the hub wire protocol.
//!
//! Each message is a 4-byte big-endian length prefix followed by a
//! protobuf-encoded `Request` or `Response` body, sent over a persistent
//! TCP connection. This is not gRPC: there is no HTTP/2 framing, no
//! trailers, just a length prefix and a body.

use prost::Message;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// The hub caps a single frame at 32 MiB; anything larger is a protocol
/// violation rather than a legitimately large message.
pub(crate) const MAX_FRAME_LEN: usize = 32 * 1024 * 1024;

/// Encodes `msg` and writes it to `w` as a length-prefixed frame, then
/// flushes so the peer observes the write promptly.
///
/// An over-cap body is an error rather than a panic: the frame body embeds
/// caller-derived strings (a compat cache key carries a whole URL), and a
/// panic here would kill the connection task without running its teardown,
/// leaving a dead connection installed with nothing left to retire it.
pub async fn write_frame<W: AsyncWrite + Unpin>(
    w: &mut W,
    msg: &impl Message,
) -> std::io::Result<()> {
    let body = msg.encode_to_vec();
    if body.len() > MAX_FRAME_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "hub frame body of {} bytes exceeds the {MAX_FRAME_LEN}-byte cap",
                body.len()
            ),
        ));
    }
    let len =
        u32::try_from(body.len()).expect("frame body fits in u32 given the MAX_FRAME_LEN cap");
    w.write_all(&len.to_be_bytes()).await?;
    w.write_all(&body).await?;
    w.flush().await
}

/// Reads one length-prefixed frame from `r` and decodes it as `M`.
///
/// A clean EOF before any byte of the length prefix arrives is reported as
/// `Ok(None)`: the peer closed the connection at a frame boundary. Any
/// other EOF (a partial length prefix or a truncated body), an oversize
/// length prefix, or a decode failure is an `InvalidData`/`UnexpectedEof`
/// error.
pub async fn read_frame<R: AsyncRead + Unpin, M: Message + Default>(
    r: &mut R,
) -> std::io::Result<Option<M>> {
    let mut len_buf = [0u8; 4];
    if !read_exact_or_eof(r, &mut len_buf).await? {
        return Ok(None);
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("hub frame length {len} exceeds the {MAX_FRAME_LEN}-byte cap"),
        ));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await?;
    M::decode(body.as_slice()).map(Some).map_err(|err| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("hub frame decode: {err}"),
        )
    })
}

/// Fills `buf` from `r`, distinguishing a clean EOF at the very start
/// (`Ok(false)`, nothing consumed yet) from an EOF after some bytes have
/// already been read (an error: the peer closed mid-frame).
async fn read_exact_or_eof<R: AsyncRead + Unpin>(
    r: &mut R,
    buf: &mut [u8],
) -> std::io::Result<bool> {
    let mut read = 0;
    while read < buf.len() {
        let n = r.read(&mut buf[read..]).await?;
        if n == 0 {
            if read == 0 {
                return Ok(false);
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "hub connection closed mid-frame",
            ));
        }
        read += n;
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto;

    fn sample_request() -> proto::Request {
        proto::Request {
            request_id: 42,
            params: Some(proto::RequestParams {
                params: Some(proto::request_params::Params::CacheAsideOpenForRead(
                    proto::CacheAsideOpenForReadParams {
                        key: "some-key".to_string(),
                        provider: "s3".to_string(),
                        extension: "usd".to_string(),
                    },
                )),
            }),
        }
    }

    #[tokio::test]
    async fn round_trips_a_request_through_an_in_memory_duplex() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let sent = sample_request();

        write_frame(&mut client, &sent)
            .await
            .expect("write succeeds");
        let received: proto::Request = read_frame(&mut server)
            .await
            .expect("read succeeds")
            .expect("frame present");

        assert_eq!(received, sent);
    }

    #[tokio::test]
    async fn decodes_a_frame_split_across_many_tiny_reads() {
        // A one-byte duplex buffer forces every write to cross the pipe as
        // a separate single-byte read, exercising read_frame's internal
        // reassembly loop rather than relying on one big read.
        let (mut client, mut server) = tokio::io::duplex(1);
        let sent = sample_request();

        let writer = tokio::spawn(async move {
            write_frame(&mut client, &sent)
                .await
                .expect("write succeeds");
            client
        });
        let received: proto::Request = read_frame(&mut server)
            .await
            .expect("read succeeds")
            .expect("frame present");
        writer.await.expect("writer task completes");

        assert_eq!(received, sample_request());
    }

    #[tokio::test]
    async fn rejects_an_oversize_length_prefix() {
        let (mut client, mut server) = tokio::io::duplex(64);

        let over_cap = (MAX_FRAME_LEN as u32) + 1;
        client
            .write_all(&over_cap.to_be_bytes())
            .await
            .expect("write succeeds");
        drop(client);

        let err = read_frame::<_, proto::Request>(&mut server)
            .await
            .expect_err("length rejected");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn eof_mid_frame_is_an_error() {
        let (mut client, mut server) = tokio::io::duplex(64);

        // Two of the four length-prefix bytes, then the peer disappears.
        client.write_all(&[0, 0]).await.expect("write succeeds");
        drop(client);

        let err = read_frame::<_, proto::Request>(&mut server)
            .await
            .expect_err("eof is an error");
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn eof_at_frame_boundary_is_ok_none() {
        let (client, mut server) = tokio::io::duplex(64);
        drop(client);

        let frame = read_frame::<_, proto::Request>(&mut server)
            .await
            .expect("read succeeds");
        assert!(frame.is_none());
    }
}
