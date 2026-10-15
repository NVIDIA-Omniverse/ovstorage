// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use ovstorage_plugin::*;

pub(crate) async fn stage_read_result_to_local_delegate(
    result: ReadResult,
    cancel: Option<CancellationToken>,
) -> Result<LocalDelegate> {
    match result {
        ReadResult::LocalDelegate(local) => Ok(local),
        ReadResult::Bytes { bytes, info } => {
            let stream: ReadStream = Box::pin(futures::stream::once(async move {
                Ok(bytes::Bytes::from(bytes))
            }));
            Ok(LocalDelegate {
                path: materialize(stream, cancel).await?,
                info,
                guard: None,
            })
        }
        ReadResult::Stream { stream, info } => Ok(LocalDelegate {
            path: materialize(stream, cancel).await?,
            info,
            guard: None,
        }),
        ReadResult::Redirect(_) => Err(Error::new(
            ErrorCode::Unsupported,
            "materialize could not follow the backend read redirect",
        )),
    }
}

async fn materialize(
    stream: ReadStream,
    cancel: Option<CancellationToken>,
) -> Result<std::path::PathBuf> {
    let named = tempfile::NamedTempFile::new().map_err(ovstorage_layer::io_error)?;
    let (_file, path) = named
        .keep()
        .map_err(|error| ovstorage_layer::io_error(error.error))?;
    materialize_to_path(stream, cancel, path).await
}

async fn materialize_to_path(
    mut stream: ReadStream,
    cancel: Option<CancellationToken>,
    path: std::path::PathBuf,
) -> Result<std::path::PathBuf> {
    use futures::StreamExt as _;
    use tokio::io::AsyncWriteExt as _;

    let mut guard = TempPathGuard(Some(path));
    let mut file = tokio::fs::File::create(guard.path())
        .await
        .map_err(ovstorage_layer::io_error)?;
    check_cancelled(&cancel)?;
    loop {
        let next = match cancel.as_ref() {
            Some(cancel) => {
                tokio::select! {
                    biased;
                    _ = cancel.cancelled() => {
                        return Err(Error::new(ErrorCode::Cancelled, "cancelled by caller"));
                    }
                    next = stream.next() => next,
                }
            }
            None => stream.next().await,
        };
        let Some(chunk) = next else {
            break;
        };
        file.write_all(&chunk?)
            .await
            .map_err(ovstorage_layer::io_error)?;
        check_cancelled(&cancel)?;
    }
    check_cancelled(&cancel)?;
    file.sync_all().await.map_err(ovstorage_layer::io_error)?;
    check_cancelled(&cancel)?;
    drop(file);
    Ok(guard.take())
}

fn check_cancelled(cancel: &Option<CancellationToken>) -> Result<()> {
    if cancel.as_ref().is_some_and(CancellationToken::is_cancelled) {
        return Err(Error::new(ErrorCode::Cancelled, "cancelled by caller"));
    }
    Ok(())
}

struct TempPathGuard(Option<std::path::PathBuf>);

impl TempPathGuard {
    fn path(&self) -> &std::path::Path {
        self.0.as_deref().expect("temporary path is present")
    }

    fn take(&mut self) -> std::path::PathBuf {
        self.0.take().expect("temporary path is present")
    }
}

impl Drop for TempPathGuard {
    fn drop(&mut self) {
        if let Some(path) = self.0.take() {
            let _ = std::fs::remove_file(path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn materialize_removes_partial_file_after_stream_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("partial-error.tmp");
        let stream: ReadStream = Box::pin(futures::stream::iter([
            Ok(bytes::Bytes::from_static(b"partial")),
            Err(Error::new(ErrorCode::Transient, "stream failed")),
        ]));

        let error = materialize_to_path(stream, None, path.clone())
            .await
            .unwrap_err();
        assert_eq!(error.code(), ErrorCode::Transient);
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn materialize_prioritizes_cancel_and_removes_partial_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("partial-cancel.tmp");
        let token = CancellationToken::new();
        let cancel_in_stream = token.clone();
        let stream: ReadStream = Box::pin(futures::stream::once(async move {
            cancel_in_stream.cancel();
            Ok(bytes::Bytes::from_static(b"partial"))
        }));

        let error = materialize_to_path(stream, Some(token), path.clone())
            .await
            .unwrap_err();
        assert_eq!(error.code(), ErrorCode::Cancelled);
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn materialize_rejects_pre_cancelled_ready_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pre-cancelled.tmp");
        let token = CancellationToken::new();
        token.cancel();
        let stream: ReadStream = Box::pin(futures::stream::once(async {
            Ok(bytes::Bytes::from_static(b"ready"))
        }));

        let error = materialize_to_path(stream, Some(token), path.clone())
            .await
            .unwrap_err();
        assert_eq!(error.code(), ErrorCode::Cancelled);
        assert!(!path.exists());
    }
}
