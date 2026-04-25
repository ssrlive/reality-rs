//! Bridge between blocking REALITY `StreamOwned` and async tokio streams.
//!
//! Our forked rustls cannot use `tokio-rustls`, so the REALITY TLS layer
//! is driven through `rustls_util::StreamOwned` on a `std::net::TcpStream`.
//! This module wraps that blocking object behind a `tokio::io::DuplexStream`
//! so it can be plugged into anytls (which expects `AsyncRead + AsyncWrite`).
//!
//! A dedicated OS worker thread pumps bytes between the TLS stream and the
//! "remote" half of an in-process tokio duplex pipe, using the same
//! non-blocking polling pattern already used for the SOCKS relay loop.

use core::time::Duration;
use std::io::{Read, Write};

use anyhow::Result;
use rustls::Connection;
use rustls_util::StreamOwned;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::runtime::Handle;

const PUMP_BUFFER: usize = 64 * 1024;
const RELAY_HIGH_WATER: usize = 256 * 1024;

/// Convert a fully handshaken blocking REALITY TLS stream into an
/// async duplex usable as `Box<dyn AsyncReadWrite>`.
///
/// Must be called from inside a tokio runtime; the captured runtime
/// handle is used by the worker thread to drive the async side.
pub(crate) fn into_async<C>(
    tls: StreamOwned<C, std::net::TcpStream>,
) -> std::io::Result<DuplexStream>
where
    C: Connection + Send + 'static,
{
    let (local, remote) = tokio::io::duplex(PUMP_BUFFER);
    let handle = Handle::current();
    std::thread::spawn(move || {
        if let Err(error) = pump(handle, tls, remote) {
            log::debug!("REALITY async bridge pump exited: {error:#}");
        }
    });
    Ok(local)
}

fn pump<C>(
    handle: Handle,
    mut tls: StreamOwned<C, std::net::TcpStream>,
    duplex: DuplexStream,
) -> Result<()>
where
    C: Connection + Send + 'static,
{
    tls.sock.set_nonblocking(true)?;
    let (mut duplex_read, mut duplex_write) = tokio::io::split(duplex);

    let mut tls_to_app: Vec<u8> = Vec::with_capacity(PUMP_BUFFER);
    let mut app_to_tls: Vec<u8> = Vec::with_capacity(PUMP_BUFFER);
    let mut buf = vec![0u8; PUMP_BUFFER];
    let mut tls_eof = false;
    let mut app_eof = false;

    loop {
        let mut progressed = false;

        // TLS -> app (async duplex write)
        if !tls_eof && tls_to_app.len() < RELAY_HIGH_WATER {
            match tls.read(&mut buf) {
                Ok(0) => {
                    tls_eof = true;
                    progressed = true;
                }
                Ok(read) => {
                    tls_to_app.extend_from_slice(&buf[..read]);
                    progressed = true;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => {
                    log::debug!("bridge: tls read error: {error}");
                    tls_eof = true;
                }
            }
        }

        if !tls_to_app.is_empty() {
            let written = handle.block_on(async { duplex_write.write(&tls_to_app).await });
            match written {
                Ok(0) => app_eof = true,
                Ok(n) => {
                    tls_to_app.drain(..n);
                    progressed = true;
                }
                Err(error) => {
                    log::debug!("bridge: duplex write error: {error}");
                    app_eof = true;
                }
            }
        }

        // app -> TLS (async duplex read)
        if !app_eof && app_to_tls.len() < RELAY_HIGH_WATER {
            // Use a short timeout so we don't starve the TLS side.
            let res = handle.block_on(async {
                tokio::time::timeout(Duration::from_millis(2), duplex_read.read(&mut buf)).await
            });
            match res {
                Ok(Ok(0)) => {
                    app_eof = true;
                    tls.conn.send_close_notify();
                    progressed = true;
                }
                Ok(Ok(n)) => {
                    app_to_tls.extend_from_slice(&buf[..n]);
                    progressed = true;
                }
                Ok(Err(error)) => {
                    log::debug!("bridge: duplex read error: {error}");
                    app_eof = true;
                }
                Err(_) => {
                    // timeout — no app data right now
                }
            }
        }

        if !app_to_tls.is_empty() {
            match tls.write(&app_to_tls) {
                Ok(0) => tls_eof = true,
                Ok(n) => {
                    app_to_tls.drain(..n);
                    progressed = true;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => {
                    log::debug!("bridge: tls write error: {error}");
                    tls_eof = true;
                }
            }
            let _ = tls.flush();
        }

        if (tls_eof || app_eof) && tls_to_app.is_empty() && app_to_tls.is_empty() {
            break;
        }

        if !progressed {
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    tls.conn.send_close_notify();
    let _ = tls.flush();
    Ok(())
}
