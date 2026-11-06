//! Streaming between async I/O and blocking encoders and decoders.
//!
//! Encoders and decoders such as [`ciborium`](coset::cbor) only work with blocking
//! [`std::io::Write`] and [`std::io::Read`], so they must run on the blocking thread pool, which
//! requires them to be `'static`. The async writer or reader passed in by the caller is usually
//! borrowed, so it can't be moved there.
//!
//! Instead, the borrowed stream stays on the async side, and is connected to the blocking side by
//! an in-memory pipe of bounded capacity. The data is streamed through the pipe, so at most
//! [`PIPE_CAPACITY`] bytes of it are buffered at a time, and neither side blocks the async runtime.
//!
//! Both functions drive both of their sides to completion, so they never drop any of their
//! internal futures partway through.
//!
//! # Cancellation
//!
//! Dropping the future returned by [`encode_blocking`] or [`decode_blocking`] before it completes
//! cancels the operation:
//!
//! - If the blocking task has not started yet, it is aborted, so it never runs.
//! - A blocking task that has already started can't be aborted, as it isn't async. Instead, the
//!   async side is dropped with the future, so the blocking side's next write fails with
//!   [`ErrorKind::BrokenPipe`], or its next read reaches the end of the input, and it can finish
//!   promptly. It may keep running until then, but it no longer has access to the caller's
//!   stream, which is released as soon as the future is dropped.
//!
//! Neither function is cancel safe: an unspecified amount of data may already have been written
//! to or read from the caller's stream, and data read from it is lost.

use std::io::ErrorKind;

use tokio::io::{AsyncRead, AsyncWrite, DuplexStream};
use tokio_util::io::SyncIoBridge;
use tokio_util::task::AbortOnDropHandle;

use crate::error::Result;

/// The maximum number of bytes buffered between the async and the blocking side.
const PIPE_CAPACITY: usize = 8 * 1024;

/// The blocking end of the pipe, implementing [`std::io::Write`] or [`std::io::Read`].
pub(crate) type BlockingPipe = SyncIoBridge<DuplexStream>;

/// Runs `encode` on the blocking thread pool, and streams everything it writes to `write`.
///
/// Not cancel safe. See [the module documentation](self#cancellation).
pub(crate) async fn encode_blocking<T>(
    mut write: impl AsyncWrite + Unpin + Send,
    encode: impl FnOnce(&mut BlockingPipe) -> Result<T> + Send + 'static,
) -> Result<T>
where
    T: Send + 'static,
{
    let (mut pipe_read, pipe_write) = tokio::io::duplex(PIPE_CAPACITY);
    let mut pipe_write = SyncIoBridge::new(pipe_write);
    let encode_task =
        AbortOnDropHandle::new(tokio::task::spawn_blocking(move || encode(&mut pipe_write)));
    // Reading from the pipe never fails, so errors come from `write`.
    // `copy` flushes `write` once all data has been written.
    let drain = async move {
        let result = tokio::io::copy(&mut pipe_read, &mut write).await;
        drop(pipe_read);
        result
    };
    let (drain_result, encode_result) = tokio::join!(drain, encode_task);

    // A failure to write is the root cause of a failure of `encode`, if there is one.
    drain_result?;
    encode_result?
}

/// Runs `decode` on the blocking thread pool, streaming to it everything read from `read`.
///
/// `read` may be read past the end of what `decode` consumes.
///
/// Once `decode` has finished, the read from `read` that is in progress, if any, is completed
/// before returning. So if `read` stalls without reaching its end, so does this function.
///
/// Not cancel safe. See [the module documentation](self#cancellation).
pub(crate) async fn decode_blocking<T>(
    mut read: impl AsyncRead + Unpin + Send,
    decode: impl FnOnce(&mut BlockingPipe) -> Result<T> + Send + 'static,
) -> Result<T>
where
    T: Send + 'static,
{
    let (pipe_read, mut pipe_write) = tokio::io::duplex(PIPE_CAPACITY);
    let mut pipe_read = SyncIoBridge::new(pipe_read);
    let decode_task =
        AbortOnDropHandle::new(tokio::task::spawn_blocking(move || decode(&mut pipe_read)));
    // Once `decode` has finished, its end of the pipe is dropped, so the next write to the pipe
    // fails with `BrokenPipe`, which ends `copy`.
    let feed = async move {
        let result = tokio::io::copy(&mut read, &mut pipe_write).await;
        // Signals the end of the input to `decode`.
        drop(pipe_write);
        result
    };
    let (feed_result, decode_result) = tokio::join!(feed, decode_task);

    match (decode_result?, feed_result) {
        (Ok(value), _) => Ok(value),
        // A failure to read is the root cause of the failure of `decode`. Writing to the pipe
        // fails with `BrokenPipe` only once `decode` has stopped reading, so that error is not.
        (Err(_), Err(read_error)) if read_error.kind() != ErrorKind::BrokenPipe => {
            Err(read_error.into())
        }
        (Err(decode_error), _) => Err(decode_error),
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::time::Duration;

    use tokio::io::AsyncWriteExt;
    use tokio::sync::oneshot;
    use tokio::time::timeout;
    use tokio_util::io::StreamReader;

    use super::*;
    use crate::error::Error;

    #[tokio::test]
    async fn encode_streams_more_than_the_pipe_capacity() {
        let data: Vec<u8> = (0..PIPE_CAPACITY * 5 + 3).map(|i| i as u8).collect();
        let mut output = Vec::new();
        let data_cloned = data.clone();

        encode_blocking(&mut output, move |pipe| Ok(pipe.write_all(&data_cloned)?))
            .await
            .unwrap();

        assert_eq!(output, data);
    }

    #[tokio::test]
    async fn decode_streams_more_than_the_pipe_capacity() {
        let data: Vec<u8> = (0..PIPE_CAPACITY * 5 + 3).map(|i| i as u8).collect();
        let decoded = decode_blocking(data.as_slice(), |pipe| {
            let mut decoded = Vec::new();
            pipe.read_to_end(&mut decoded)?;
            Ok(decoded)
        })
        .await
        .unwrap();

        assert_eq!(decoded, data);
    }

    #[tokio::test]
    async fn decode_reports_read_errors_as_the_root_cause() {
        let failing_read = StreamReader::new(futures::stream::iter([Err::<&[u8], _>(
            std::io::Error::from(ErrorKind::PermissionDenied),
        )]));
        let result = decode_blocking(failing_read, |reader| {
            reader
                .read_exact(&mut [0_u8; 1])
                .map_err(|_| Error::MalformedRecord)
        })
        .await;

        assert!(
            matches!(&result, Err(Error::Io(error)) if error.kind() == ErrorKind::PermissionDenied),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn encode_reports_write_errors() {
        // The reading half is dropped, so writing fails.
        let (output, _) = tokio::io::duplex(16);
        let result = encode_blocking(output, |pipe| {
            Ok(pipe.write_all(&[0_u8; PIPE_CAPACITY * 2])?)
        })
        .await;

        assert!(
            matches!(&result, Err(Error::Io(error)) if error.kind() == ErrorKind::BrokenPipe),
            "{result:?}"
        );
    }

    /// How long to wait for a blocking task to report its result, before failing the test.
    const REPORT_TIMEOUT: Duration = Duration::from_secs(10);

    #[tokio::test]
    async fn cancelling_decode_ends_the_input_of_a_running_decoder() {
        // The writing half is kept open, so the input never ends.
        let (mut input_write, input_read) = tokio::io::duplex(16);
        input_write.write_all(b"abc").await.unwrap();

        let (started_sender, started_receiver) = oneshot::channel();
        let (result_sender, result_receiver) = oneshot::channel();
        let decoding = decode_blocking(input_read, move |pipe| {
            pipe.read_exact(&mut [0_u8; 3])?;
            started_sender.send(()).unwrap();
            // Waits for input that never comes, until the decoding is cancelled.
            let result = pipe.read_exact(&mut [0_u8; 1]);
            result_sender
                .send(result.map_err(|error| error.kind()))
                .unwrap();
            Ok(())
        });

        // Cancels the decoding once the decoder is running, by dropping `decoding`.
        tokio::select! {
            _ = decoding => panic!("the decoding should not finish, as its input never ends"),
            started = started_receiver => started.unwrap(),
        }

        assert_eq!(
            timeout(REPORT_TIMEOUT, result_receiver).await,
            Ok(Ok(Err(ErrorKind::UnexpectedEof)))
        );
    }

    #[tokio::test]
    async fn cancelling_encode_fails_the_writes_of_a_running_encoder() {
        // The reading half is kept open, but never read from, so the output fills up.
        let (output, _output_read) = tokio::io::duplex(16);

        let (started_sender, started_receiver) = oneshot::channel();
        let (result_sender, result_receiver) = oneshot::channel();
        let encoding = encode_blocking(output, move |pipe| {
            pipe.write_all(b"abc")?;
            started_sender.send(()).unwrap();
            // Waits for the output to be drained, until the encoding is cancelled.
            let result = pipe.write_all(&[0_u8; PIPE_CAPACITY * 4]);
            result_sender
                .send(result.map_err(|error| error.kind()))
                .unwrap();
            Ok(())
        });

        // Cancels the encoding once the encoder is running, by dropping `encoding`.
        tokio::select! {
            _ = encoding => panic!("the encoding should not finish, as its output is never read"),
            started = started_receiver => started.unwrap(),
        }

        assert_eq!(
            timeout(REPORT_TIMEOUT, result_receiver).await,
            Ok(Ok(Err(ErrorKind::BrokenPipe)))
        );
    }

    #[test]
    fn cancelling_decode_before_the_decoder_starts_prevents_it_from_running() {
        // A single blocking thread, so that a blocking task can be kept from starting by occupying
        // that thread.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .max_blocking_threads(1)
            .enable_time()
            .build()
            .unwrap();
        runtime.block_on(async {
            let (release_sender, release_receiver) = oneshot::channel::<()>();
            let occupying_task =
                tokio::task::spawn_blocking(move || release_receiver.blocking_recv());
            let (ran_sender, ran_receiver) = oneshot::channel::<()>();
            let mut decoding = Box::pin(decode_blocking(&[][..], move |_| {
                ran_sender.send(()).unwrap();
                Ok(())
            }));

            // Spawns the decoder, which has to wait for the occupied blocking thread.
            assert!(futures::poll!(decoding.as_mut()).is_pending());
            drop(decoding);

            release_sender.send(()).unwrap();
            occupying_task.await.unwrap().unwrap();

            // Tokio documents that aborting a blocking task which hasn't started "may prevent the
            // task from starting". The aborted decoder is dropped without running, which closes
            // the channel without sending.
            assert!(matches!(
                timeout(REPORT_TIMEOUT, ran_receiver).await,
                Ok(Err(oneshot::error::RecvError { .. }))
            ));
        });
    }
}
