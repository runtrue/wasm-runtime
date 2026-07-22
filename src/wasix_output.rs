//! Bounded output capture for isolated WASIX workers.

use std::{
    io::{self, IoSlice, SeekFrom},
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    task::{Context, Poll},
};

use wasmer_wasix::virtual_fs::{AsyncRead, AsyncSeek, AsyncWrite, FsError, ReadBuf, VirtualFile};

const VIRTUAL_FILE_TIMESTAMP: u64 = 1_000_000_000;

#[derive(Debug)]
struct OutputState {
    bytes: Vec<u8>,
    limit: usize,
    overflowed: bool,
    closed: bool,
}

/// A cloneable, in-memory output sink with a hard byte limit.
///
/// The sink rejects an entire write when it would exceed the limit and keeps a
/// sticky overflow flag. Callers must check [`Self::finish`] after the guest
/// exits because WASIX may report a short write when an earlier iovec from the
/// same syscall was accepted.
#[derive(Clone, Debug)]
pub(crate) struct BoundedWasixOutput {
    state: Arc<Mutex<OutputState>>,
}

impl BoundedWasixOutput {
    /// Creates a sink and reserves its complete byte budget up front.
    pub(crate) fn new(limit: usize) -> io::Result<Self> {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(limit)
            .map_err(|error| output_allocation_error(&error))?;

        Ok(Self {
            state: Arc::new(Mutex::new(OutputState {
                bytes,
                limit,
                overflowed: false,
                closed: false,
            })),
        })
    }

    /// Returns a bounded copy of the captured bytes after a successful run.
    ///
    /// This fails if any guest write exceeded the configured byte limit, even
    /// when the guest ignored the corresponding I/O error.
    pub(crate) fn finish(&self) -> io::Result<Vec<u8>> {
        let state = self.lock_state();
        if state.overflowed {
            return Err(output_limit_error(state.limit));
        }

        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(state.bytes.len())
            .map_err(|error| output_allocation_error(&error))?;
        bytes.extend_from_slice(&state.bytes);
        Ok(bytes)
    }

    fn lock_state(&self) -> MutexGuard<'_, OutputState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

fn output_limit_error(limit: usize) -> io::Error {
    io::Error::other(format!(
        "WASIX output exceeded its {limit}-byte capture limit"
    ))
}

fn output_allocation_error(error: &std::collections::TryReserveError) -> io::Error {
    io::Error::new(
        io::ErrorKind::OutOfMemory,
        format!("failed to allocate WASIX output capture: {error}"),
    )
}

impl AsyncWrite for BoundedWasixOutput {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buffer.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let mut state = self.lock_state();
        if state.closed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if state.overflowed {
            return Poll::Ready(Err(output_limit_error(state.limit)));
        }

        let Some(new_len) = state.bytes.len().checked_add(buffer.len()) else {
            state.overflowed = true;
            return Poll::Ready(Err(output_limit_error(state.limit)));
        };
        if new_len > state.limit {
            state.overflowed = true;
            return Poll::Ready(Err(output_limit_error(state.limit)));
        }

        state.bytes.extend_from_slice(buffer);
        Poll::Ready(Ok(buffer.len()))
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buffers: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let Some(write_len) = buffers
            .iter()
            .try_fold(0_usize, |total, buffer| total.checked_add(buffer.len()))
        else {
            let mut state = self.lock_state();
            state.overflowed = true;
            return Poll::Ready(Err(output_limit_error(state.limit)));
        };
        if write_len == 0 {
            return Poll::Ready(Ok(0));
        }

        let mut state = self.lock_state();
        if state.closed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if state.overflowed {
            return Poll::Ready(Err(output_limit_error(state.limit)));
        }

        let Some(new_len) = state.bytes.len().checked_add(write_len) else {
            state.overflowed = true;
            return Poll::Ready(Err(output_limit_error(state.limit)));
        };
        if new_len > state.limit {
            state.overflowed = true;
            return Poll::Ready(Err(output_limit_error(state.limit)));
        }

        for buffer in buffers {
            state.bytes.extend_from_slice(buffer);
        }
        Poll::Ready(Ok(write_len))
    }

    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.lock_state().closed = true;
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for BoundedWasixOutput {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncSeek for BoundedWasixOutput {
    fn start_seek(self: Pin<&mut Self>, _position: SeekFrom) -> io::Result<()> {
        Ok(())
    }

    fn poll_complete(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<u64>> {
        Poll::Ready(Ok(0))
    }
}

impl VirtualFile for BoundedWasixOutput {
    fn last_accessed(&self) -> u64 {
        VIRTUAL_FILE_TIMESTAMP
    }

    fn last_modified(&self) -> u64 {
        VIRTUAL_FILE_TIMESTAMP
    }

    fn created_time(&self) -> u64 {
        VIRTUAL_FILE_TIMESTAMP
    }

    fn size(&self) -> u64 {
        u64::try_from(self.lock_state().bytes.len()).unwrap_or(u64::MAX)
    }

    fn set_len(&mut self, _new_size: u64) -> Result<(), FsError> {
        Err(FsError::Unsupported)
    }

    fn unlink(&mut self) -> Result<(), FsError> {
        Err(FsError::Unsupported)
    }

    fn is_open(&self) -> bool {
        !self.lock_state().closed
    }

    fn poll_read_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(0))
    }

    fn poll_write_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let state = self.lock_state();
        if state.closed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if state.overflowed {
            return Poll::Ready(Err(output_limit_error(state.limit)));
        }

        Poll::Ready(Ok(state.limit - state.bytes.len()))
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncWriteExt;

    use super::BoundedWasixOutput;

    #[tokio::test]
    async fn captures_output_at_the_exact_limit() {
        let output = BoundedWasixOutput::new(6).expect("capture allocation must succeed");
        let mut writer = output.clone();

        writer
            .write_all(b"424242")
            .await
            .expect("write at the exact limit must succeed");

        assert_eq!(output.finish().unwrap(), b"424242");
    }

    #[tokio::test]
    async fn overflow_is_atomic_and_sticky() {
        let output = BoundedWasixOutput::new(6).expect("capture allocation must succeed");
        let mut writer = output.clone();

        writer.write_all(b"42").await.unwrap();
        assert!(writer.write_all(b"42424").await.is_err());
        assert!(writer.write_all(b"1").await.is_err());
        assert!(output.finish().is_err());

        let state = output.lock_state();
        assert_eq!(state.bytes, b"42");
    }

    #[tokio::test]
    async fn shutdown_closes_all_clones_without_losing_output() {
        let output = BoundedWasixOutput::new(6).expect("capture allocation must succeed");
        let mut writer = output.clone();

        writer.write_all(b"42").await.unwrap();
        writer.shutdown().await.unwrap();

        assert!(output.clone().write_all(b"1").await.is_err());
        assert_eq!(output.finish().unwrap(), b"42");
    }
}
