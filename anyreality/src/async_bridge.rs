//! Bridge between blocking REALITY `StreamOwned` and async tokio streams.
//!
//! Our forked rustls cannot use `tokio-rustls`, so the REALITY TLS layer is
//! driven through `rustls_util::StreamOwned` on a `std::net::TcpStream`. This
//! module wraps that blocking object behind an async [`BridgeStream`] so it can
//! be plugged into anytls (which expects `AsyncRead + AsyncWrite`).
//!
//! A single dedicated OS worker thread owns the TLS stream and shuttles bytes
//! between it and two channels. Two properties matter:
//!
//! * The worker **parks in the kernel** (a blocking socket read with a short
//!   timeout) when idle instead of spinning, so many live carriers do not
//!   starve the async runtime of CPU.
//! * The outbound (app -> TLS) channel is **bounded**, so the anytls writer is
//!   backpressured and cannot pile megabytes of bulk stream data ahead of a
//!   freshly produced control frame (e.g. a SYNACK). Without this bound, new
//!   streams' SYNACKs queue behind unrelated downloads and time out.

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};
use core::time::Duration;
use std::io::{Read, Write};

use rustls::Connection;
use rustls_util::StreamOwned;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;

const PUMP_BUFFER: usize = 64 * 1024;
/// Soft cap on outbound bytes buffered inside the worker before it stops
/// pulling more from the channel. Kept small so control frames stay near the
/// front of the byte stream.
const OUTBOUND_HIGH_WATER: usize = 64 * 1024;
/// Inbound (TLS -> app) chunk backlog before the bridge applies TCP
/// backpressure by pausing socket reads. Bounds per-carrier inbound memory.
const INBOUND_CHANNEL_CAP: usize = 16;
/// Outbound (app -> TLS) chunk backlog. Small so the anytls writer blocks once
/// the carrier is behind, preserving its control-before-data priority.
const OUTBOUND_CHANNEL_CAP: usize = 8;
/// Blocking socket read/write timeout. Bounds how long the worker parks in the
/// kernel before it re-checks the outbound queue, i.e. the worst-case app->TLS
/// wakeup latency. Small enough to stay responsive, large enough to avoid a
/// busy loop.
const SOCKET_POLL: Duration = Duration::from_millis(5);
/// Poll interval used only while inbound delivery is backpressured (the app is
/// not reading), so outbound traffic keeps flowing without a tight spin.
const BACKPRESSURE_POLL: Duration = Duration::from_millis(1);

type Reservation = Pin<Box<dyn Future<Output = Result<mpsc::OwnedPermit<Vec<u8>>, mpsc::error::SendError<()>>> + Send>>;

fn would_block(error: &std::io::Error) -> bool {
    matches!(error.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut)
}

/// Async view over the REALITY TLS carrier. Reads pull decrypted bytes produced
/// by the worker thread; writes hand plaintext to the worker thread under
/// bounded backpressure.
pub struct BridgeStream {
    inbound: mpsc::Receiver<Vec<u8>>,
    leftover: Vec<u8>,
    leftover_pos: usize,
    outbound: Option<mpsc::Sender<Vec<u8>>>,
    // Boxed reservation future is Send but not Sync; the Mutex makes the whole
    // stream Sync (required by `AsyncReadWrite`) without ever being contended,
    // since writes only ever touch it through `&mut self`.
    reserving: std::sync::Mutex<Option<Reservation>>,
}

/// Convert a fully handshaken blocking REALITY TLS stream into an async stream
/// usable as `Box<dyn AsyncReadWrite>`.
pub fn into_async<C>(tls: StreamOwned<C, std::net::TcpStream>) -> std::io::Result<BridgeStream>
where
    C: Connection + Send + 'static,
{
    let (inbound_tx, inbound_rx) = mpsc::channel::<Vec<u8>>(INBOUND_CHANNEL_CAP);
    let (outbound_tx, outbound_rx) = mpsc::channel::<Vec<u8>>(OUTBOUND_CHANNEL_CAP);
    std::thread::spawn(move || {
        if let Err(error) = pump(tls, inbound_tx, outbound_rx) {
            log::trace!("REALITY async bridge pump exited: {error:#}");
        }
    });
    Ok(BridgeStream {
        inbound: inbound_rx,
        leftover: Vec::new(),
        leftover_pos: 0,
        outbound: Some(outbound_tx),
        reserving: std::sync::Mutex::new(None),
    })
}

fn pump<C>(
    mut tls: StreamOwned<C, std::net::TcpStream>,
    inbound_tx: mpsc::Sender<Vec<u8>>,
    mut outbound_rx: mpsc::Receiver<Vec<u8>>,
) -> std::io::Result<()>
where
    C: Connection + Send + 'static,
{
    // Blocking socket with short read/write timeouts: the worker parks in the
    // kernel while idle instead of busy-polling, and a timeout simply surfaces
    // as WouldBlock (EAGAIN on Linux) which the loop treats as "no progress".
    tls.sock.set_nonblocking(false)?;
    tls.sock.set_read_timeout(Some(SOCKET_POLL))?;
    tls.sock.set_write_timeout(Some(SOCKET_POLL))?;

    let result = pump_io(&mut tls, &inbound_tx, &mut outbound_rx);

    tls.conn.send_close_notify();
    let _ = tls.flush();
    let _ = tls.sock.shutdown(std::net::Shutdown::Both);
    result
}

fn pump_io<T: Read + Write>(tls: &mut T, inbound_tx: &mpsc::Sender<Vec<u8>>, out_rx: &mut mpsc::Receiver<Vec<u8>>) -> std::io::Result<()> {
    let mut buf = vec![0u8; PUMP_BUFFER];
    let mut out_buf: Vec<u8> = Vec::new();
    let mut inbound_pending: Option<Vec<u8>> = None;
    let mut app_closed = false;

    loop {
        // 1) Collect queued app -> TLS bytes, bounded so the worker never holds
        //    much ahead of what it has flushed (keeps control frames near front).
        while out_buf.len() < OUTBOUND_HIGH_WATER {
            match out_rx.try_recv() {
                Ok(chunk) => out_buf.extend_from_slice(&chunk),
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    app_closed = true;
                    break;
                }
            }
        }

        // 2) Push outbound bytes into the TLS stream.
        if !out_buf.is_empty() {
            match tls.write(&out_buf) {
                Ok(0) => return Ok(()),
                Ok(count) => {
                    out_buf.drain(..count);
                }
                Err(error) if would_block(&error) => {}
                Err(error) => return Err(error),
            }
        }
        match tls.flush() {
            Ok(()) => {}
            Err(error) if would_block(&error) => {}
            Err(error) => return Err(error),
        }

        // 3) Once the app half is closed and everything is flushed, stop.
        if app_closed && out_buf.is_empty() {
            return Ok(());
        }

        // 4) Deliver any inbound chunk that did not fit last time.
        if let Some(chunk) = inbound_pending.take() {
            match inbound_tx.try_send(chunk) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(chunk)) => inbound_pending = Some(chunk),
                Err(mpsc::error::TrySendError::Closed(_)) => return Ok(()),
            }
        }

        // 5) Read more from TLS only when the inbound queue has room; otherwise
        //    leave bytes in the socket (TCP backpressure) and keep servicing the
        //    outbound direction without a tight spin.
        if inbound_pending.is_none() {
            match tls.read(&mut buf) {
                Ok(0) => return Ok(()),
                Ok(count) => match inbound_tx.try_send(buf[..count].to_vec()) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(chunk)) => inbound_pending = Some(chunk),
                    Err(mpsc::error::TrySendError::Closed(_)) => return Ok(()),
                },
                Err(error) if would_block(&error) => {}
                Err(error) => return Err(error),
            }
        } else {
            std::thread::sleep(BACKPRESSURE_POLL);
        }
    }
}

impl AsyncRead for BridgeStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if self.leftover_pos < self.leftover.len() {
            let start = self.leftover_pos;
            let count = buf.remaining().min(self.leftover.len() - start);
            buf.put_slice(&self.leftover[start..start + count]);
            self.leftover_pos += count;
            if self.leftover_pos == self.leftover.len() {
                self.leftover.clear();
                self.leftover_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }
        match self.inbound.poll_recv(cx) {
            Poll::Ready(Some(chunk)) => {
                let count = buf.remaining().min(chunk.len());
                buf.put_slice(&chunk[..count]);
                if count < chunk.len() {
                    self.leftover = chunk;
                    self.leftover_pos = count;
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for BridgeStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if this.outbound.is_none() {
            return Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "write after shutdown")));
        }
        let mut reserving = this.reserving.lock().expect("bridge reservation lock poisoned");
        loop {
            if let Some(reservation) = reserving.as_mut() {
                return match reservation.as_mut().poll(cx) {
                    Poll::Ready(Ok(permit)) => {
                        *reserving = None;
                        // Returned sender is a temporary clone; drop it.
                        let _ = permit.send(buf.to_vec());
                        Poll::Ready(Ok(buf.len()))
                    }
                    Poll::Ready(Err(_)) => {
                        *reserving = None;
                        Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "REALITY bridge closed")))
                    }
                    Poll::Pending => Poll::Pending,
                };
            }
            // Acquire capacity before committing to a write so the anytls writer
            // is backpressured when the carrier falls behind.
            let sender = this.outbound.as_ref().expect("checked above").clone();
            *reserving = Some(Box::pin(sender.reserve_owned()));
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        // Dropping the sender signals end-of-stream to the worker, which then
        // sends a TLS close_notify.
        *this.reserving.lock().expect("bridge reservation lock poisoned") = None;
        this.outbound = None;
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc as std_mpsc;
    use tokio::io::AsyncReadExt;

    /// Transport that yields a fixed amount of readable bytes and records every
    /// write, so a test can observe the outbound direction independently.
    struct CountingTransport {
        remaining: usize,
        written: std_mpsc::Sender<Vec<u8>>,
    }

    impl Read for CountingTransport {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            if self.remaining == 0 {
                return Err(std::io::ErrorKind::WouldBlock.into());
            }
            let count = buffer.len().min(self.remaining);
            buffer[..count].fill(42);
            self.remaining -= count;
            Ok(count)
        }
    }

    impl Write for CountingTransport {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            self.written.send(buffer.to_vec()).unwrap();
            Ok(buffer.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pending_tls_flush_is_retried_without_new_app_data() {
        struct BufferedTransport {
            pending: Vec<u8>,
            blocked_once: bool,
            flushed: std_mpsc::Sender<Vec<u8>>,
        }

        impl Read for BufferedTransport {
            fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::ErrorKind::WouldBlock.into())
            }
        }

        impl Write for BufferedTransport {
            fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
                self.pending.extend_from_slice(buffer);
                Ok(buffer.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                if !self.pending.is_empty() {
                    if !self.blocked_once {
                        self.blocked_once = true;
                        return Err(std::io::ErrorKind::WouldBlock.into());
                    }
                    self.flushed.send(core::mem::take(&mut self.pending)).unwrap();
                }
                Ok(())
            }
        }

        let (inbound_tx, _inbound_rx) = mpsc::channel::<Vec<u8>>(INBOUND_CHANNEL_CAP);
        let (outbound_tx, mut outbound_rx) = mpsc::channel::<Vec<u8>>(OUTBOUND_CHANNEL_CAP);
        let (flushed, received) = std_mpsc::channel();
        let worker = std::thread::spawn(move || {
            let mut transport = BufferedTransport {
                pending: Vec::new(),
                blocked_once: false,
                flushed,
            };
            pump_io(&mut transport, &inbound_tx, &mut outbound_rx)
        });

        outbound_tx.send(b"pending".to_vec()).await.unwrap();
        let result = received.recv_timeout(Duration::from_secs(1));
        drop(outbound_tx);
        worker.join().unwrap().unwrap();
        assert_eq!(result.expect("pending TLS output must be retried without new app data"), b"pending");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stalled_app_reader_does_not_block_outbound_data() {
        let (inbound_tx, inbound_rx) = mpsc::channel::<Vec<u8>>(INBOUND_CHANNEL_CAP);
        let (outbound_tx, mut outbound_rx) = mpsc::channel::<Vec<u8>>(OUTBOUND_CHANNEL_CAP);
        let (written, received) = std_mpsc::channel();
        let worker = std::thread::spawn(move || {
            let mut transport = CountingTransport {
                remaining: PUMP_BUFFER * 4,
                written,
            };
            pump_io(&mut transport, &inbound_tx, &mut outbound_rx)
        });

        // The app never reads inbound; once the inbound channel fills, the
        // worker must still deliver queued outbound writes.
        outbound_tx.send(b"first".to_vec()).await.unwrap();
        assert_eq!(received.recv_timeout(Duration::from_secs(1)).unwrap(), b"first");
        tokio::time::sleep(Duration::from_millis(20)).await;
        outbound_tx.send(b"next".to_vec()).await.unwrap();
        let next = received.recv_timeout(Duration::from_secs(1));

        // Draining the inbound side lets the worker resume reading the transport.
        let mut stream = BridgeStream {
            inbound: inbound_rx,
            leftover: Vec::new(),
            leftover_pos: 0,
            outbound: Some(outbound_tx.clone()),
            reserving: std::sync::Mutex::new(None),
        };
        let mut drained = 0usize;
        let mut scratch = vec![0u8; PUMP_BUFFER];
        while drained < PUMP_BUFFER {
            match tokio::time::timeout(Duration::from_secs(1), stream.read(&mut scratch)).await {
                Ok(Ok(0)) | Err(_) => break,
                Ok(Ok(count)) => drained += count,
                Ok(Err(_)) => break,
            }
        }

        drop(outbound_tx);
        drop(stream);
        worker.join().unwrap().unwrap();
        assert_eq!(
            next.expect("outbound traffic must progress even while the app is not reading"),
            b"next"
        );
        assert!(drained >= PUMP_BUFFER);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn outbound_writes_are_backpressured_when_transport_stalls() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};
        use tokio::io::AsyncWriteExt;

        // A transport whose writes block (WouldBlock) until `fail` is set, at
        // which point they error so the worker can exit cleanly.
        struct StalledTransport {
            fail: Arc<AtomicBool>,
        }
        impl Read for StalledTransport {
            fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::ErrorKind::WouldBlock.into())
            }
        }
        impl Write for StalledTransport {
            fn write(&mut self, _buffer: &[u8]) -> std::io::Result<usize> {
                if self.fail.load(Ordering::Acquire) {
                    return Err(std::io::ErrorKind::BrokenPipe.into());
                }
                Err(std::io::ErrorKind::WouldBlock.into())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let fail = Arc::new(AtomicBool::new(false));
        let (inbound_tx, _inbound_rx) = mpsc::channel::<Vec<u8>>(INBOUND_CHANNEL_CAP);
        let (outbound_tx, mut outbound_rx) = mpsc::channel::<Vec<u8>>(OUTBOUND_CHANNEL_CAP);
        let worker_fail = fail.clone();
        let worker = std::thread::spawn(move || {
            let mut transport = StalledTransport { fail: worker_fail };
            let _ = pump_io(&mut transport, &inbound_tx, &mut outbound_rx);
        });

        let mut stream = BridgeStream {
            inbound: {
                let (_tx, rx) = mpsc::channel::<Vec<u8>>(1);
                rx
            },
            leftover: Vec::new(),
            leftover_pos: 0,
            outbound: Some(outbound_tx.clone()),
            reserving: std::sync::Mutex::new(None),
        };

        // The worker absorbs up to OUTBOUND_HIGH_WATER plus the channel before
        // it must apply backpressure; writing well beyond that must block.
        let max_absorbed = OUTBOUND_HIGH_WATER / 4096 + OUTBOUND_CHANNEL_CAP;
        let mut blocked = false;
        for _ in 0..(max_absorbed + 16) {
            match tokio::time::timeout(Duration::from_millis(200), stream.write_all(&[7u8; 4096])).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) => break,
                Err(_) => {
                    blocked = true;
                    break;
                }
            }
        }
        assert!(blocked, "writer must be backpressured by a stalled transport");

        // Let the worker terminate instead of spinning on the stalled transport.
        fail.store(true, Ordering::Release);
        drop(outbound_tx);
        drop(stream);
        let _ = worker.join();
    }
}
