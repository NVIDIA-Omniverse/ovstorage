// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Broker upload body selection after listener authentication.

use std::sync::Arc;

use async_trait::async_trait;
use ovstorage::{
    Body, BodyStream, CancellationToken, Layer, LayerHandle, LayerKindDescriptor, Request, Result,
    WriteRequest, WriteResult,
};

/// Aggregate body cap; tonic bounds each frame, not their cumulative length.
pub(crate) const WRITE_BODY_BYTE_CAP: usize = 64 * 1024 * 1024;

/// Largest upload the broker dispatches as replayable [`Body::Bytes`].
pub(crate) const WRITE_STREAM_THRESHOLD: usize = 1024 * 1024;

/// Disposition of one drained sub-threshold write chunk.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ChunkDisposition {
    /// Empty frame: drop without retaining an allocation.
    Discard,
    /// Retain in the small-body buffer.
    Buffer,
    /// Crosses the streaming threshold: this frame seeds the streaming path.
    Overflow,
    /// Exceeds the absolute cumulative body cap: reject the write.
    CapExceeded,
}

/// Classify a write chunk against the running buffered length.
pub(crate) fn classify_write_chunk(
    chunk_len: usize,
    buffered_len: usize,
    threshold: usize,
    cap: usize,
) -> ChunkDisposition {
    if chunk_len == 0 {
        return ChunkDisposition::Discard;
    }
    let projected = buffered_len.saturating_add(chunk_len);
    if projected > cap {
        ChunkDisposition::CapExceeded
    } else if projected > threshold {
        ChunkDisposition::Overflow
    } else {
        ChunkDisposition::Buffer
    }
}

/// Result of feeding one source chunk into [`WriteBodyAccumulator`].
pub(crate) enum AccumulateWriteChunk {
    /// Continue reading; the body remains at or below the byte threshold.
    Continue,
    /// The threshold was crossed. These chunks are the complete prefix to
    /// replay before the unread source tail.
    Stream(Vec<Vec<u8>>),
    /// The configured cumulative cap was crossed.
    CapExceeded,
}

/// Shared small-vs-streaming body-selection state machine.
///
/// The gRPC handler feeds it asynchronously after built-in preflight, while
/// the beneath-auth normalizer feeds it synchronously after a plugin delegates.
/// Threshold transitions, empty-chunk handling, prefix preservation, cap
/// accounting, and final byte assembly therefore have one implementation.
pub(crate) struct WriteBodyAccumulator {
    chunks: Vec<Vec<u8>>,
    len: usize,
    threshold: usize,
    cap: usize,
}

impl WriteBodyAccumulator {
    pub(crate) fn new(threshold: usize, cap: usize) -> Self {
        Self {
            chunks: Vec::new(),
            len: 0,
            threshold,
            cap,
        }
    }

    pub(crate) fn push(&mut self, chunk: Vec<u8>) -> AccumulateWriteChunk {
        match classify_write_chunk(chunk.len(), self.len, self.threshold, self.cap) {
            ChunkDisposition::Discard => AccumulateWriteChunk::Continue,
            ChunkDisposition::Buffer => {
                self.len += chunk.len();
                self.chunks.push(chunk);
                AccumulateWriteChunk::Continue
            }
            ChunkDisposition::Overflow => {
                self.len += chunk.len();
                self.chunks.push(chunk);
                AccumulateWriteChunk::Stream(std::mem::take(&mut self.chunks))
            }
            ChunkDisposition::CapExceeded => AccumulateWriteChunk::CapExceeded,
        }
    }

    pub(crate) fn finish(self) -> Vec<u8> {
        let mut whole = Vec::with_capacity(self.len);
        for chunk in self.chunks {
            whole.extend_from_slice(&chunk);
        }
        whole
    }
}

/// Convert a pull-driven upload to replayable bytes when it ends below the
/// broker's threshold. The first over-threshold chunk is chained back together
/// with the buffered prefix and unread tail, so large bodies remain bounded and
/// preserve their original chunk boundaries.
pub(crate) fn normalize_post_auth_body(body: Body) -> Result<Body> {
    let Body::Stream(mut stream) = body else {
        return Ok(body);
    };

    let mut accumulator = WriteBodyAccumulator::new(WRITE_STREAM_THRESHOLD, usize::MAX);
    while let Some(chunk) = stream.next_chunk() {
        let chunk = chunk?;
        match accumulator.push(chunk) {
            AccumulateWriteChunk::Continue => {}
            AccumulateWriteChunk::Stream(prefix) => {
                let chunks = prefix.into_iter().map(Ok).chain(stream);
                return Ok(Body::Stream(BodyStream::from_iter(chunks)));
            }
            AccumulateWriteChunk::CapExceeded => {
                unreachable!("usize::MAX is an unreachable body-normalization cap")
            }
        }
    }
    Ok(Body::Bytes(accumulator.finish()))
}

/// Transparent broker-only layer immediately beneath a listener-auth wrapper.
/// The auth layer receives the lazy body first and can deny without pulling it;
/// only an authenticated delegation reaches this layer and applies the
/// broker's ordinary small-body selection policy.
struct PostAuthWriteNormalizer {
    inner: LayerHandle,
}

impl PostAuthWriteNormalizer {
    fn normalize_request(mut request: Request<WriteRequest>) -> Result<Request<WriteRequest>> {
        request.input.body = normalize_post_auth_body(request.input.body)?;
        Ok(request)
    }
}

#[async_trait]
impl Layer for PostAuthWriteNormalizer {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn descriptor(&self) -> LayerKindDescriptor {
        self.inner.descriptor()
    }

    fn inner_layer(&self) -> Option<&LayerHandle> {
        Some(&self.inner)
    }

    fn owned_targets(&self) -> Vec<String> {
        self.inner.owned_targets()
    }

    fn list_kinds(&self, cx: &ovstorage::Extensions) -> Result<Vec<LayerKindDescriptor>> {
        self.inner.list_kinds(cx)
    }

    async fn write(
        &self,
        request: Request<WriteRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        self.inner
            .write(Self::normalize_request(request)?, cancel)
            .await
    }

    async fn write_stream(
        &self,
        request: Request<WriteRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        self.inner
            .write(Self::normalize_request(request)?, cancel)
            .await
    }
}

/// Place bounded body normalization beneath a listener-auth wrapper.
pub(crate) fn normalize_listener_auth_writes(inner: LayerHandle) -> LayerHandle {
    Arc::new(PostAuthWriteNormalizer { inner })
}

#[cfg(test)]
mod tests {
    use ovstorage::{Error, ErrorCode};

    use super::*;

    fn stream(chunks: Vec<Result<Vec<u8>>>) -> Body {
        Body::Stream(BodyStream::from_iter(chunks.into_iter()))
    }

    #[test]
    fn post_auth_normalization_preserves_small_and_large_body_contracts() {
        assert!(matches!(
            normalize_post_auth_body(stream(Vec::new())).unwrap(),
            Body::Bytes(bytes) if bytes.is_empty()
        ));
        assert!(matches!(
            normalize_post_auth_body(stream(vec![Ok(Vec::new()), Ok(vec![1, 2])])).unwrap(),
            Body::Bytes(bytes) if bytes == [1, 2]
        ));

        let prefix = vec![1; WRITE_STREAM_THRESHOLD];
        let Body::Stream(mut large) =
            normalize_post_auth_body(stream(vec![Ok(prefix.clone()), Ok(vec![2])])).unwrap()
        else {
            panic!("over-threshold body must remain a stream");
        };
        assert_eq!(large.next_chunk().unwrap().unwrap(), prefix);
        assert_eq!(large.next_chunk().unwrap().unwrap(), vec![2]);
        assert!(large.next_chunk().is_none());

        let error = Error::new(ErrorCode::Transient, "body failed");
        let normalized = normalize_post_auth_body(stream(vec![Err(error)])).unwrap_err();
        assert_eq!(normalized.code(), ErrorCode::Transient);
    }
}
