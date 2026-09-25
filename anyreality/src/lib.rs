pub mod async_bridge;

use anytls::Stream as AnytlsStream;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

type ReadFuture = core::pin::Pin<Box<dyn Future<Output = std::io::Result<Vec<u8>>> + Send>>;

pub struct AnytlsStreamReader {
    stream: Arc<AnytlsStream>,
    reading: Option<ReadFuture>,
    buffered: Vec<u8>,
    consumed: usize,
}

impl AnytlsStreamReader {
    pub fn new(stream: Arc<AnytlsStream>) -> Self {
        Self {
            stream,
            reading: None,
            buffered: Vec::new(),
            consumed: 0,
        }
    }
}

impl AsyncRead for AnytlsStreamReader {
    fn poll_read(
        mut self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> core::task::Poll<std::io::Result<()>> {
        use core::task::Poll;
        if buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if self.consumed < self.buffered.len() {
                let count = buffer.remaining().min(self.buffered.len() - self.consumed);
                buffer.put_slice(&self.buffered[self.consumed..self.consumed + count]);
                self.consumed += count;
                return Poll::Ready(Ok(()));
            }
            if let Some(reading) = self.reading.as_mut() {
                match reading.as_mut().poll(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(result) => {
                        self.reading = None;
                        self.buffered = result?;
                        self.consumed = 0;
                        if self.buffered.is_empty() {
                            return Poll::Ready(Ok(()));
                        }
                    }
                }
            } else {
                let stream = self.stream.clone();
                self.reading = Some(Box::pin(async move {
                    let mut bytes = vec![0; 16 * 1024];
                    let count = stream.read(&mut bytes).await?;
                    bytes.truncate(count);
                    Ok(bytes)
                }));
            }
        }
    }
}

pub async fn relay_tcp<T>(local: T, stream: Arc<AnytlsStream>, reader: &mut AnytlsStreamReader) -> std::io::Result<()>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let (mut local_read, mut local_write) = tokio::io::split(local);
    let upload = async {
        let mut buffer = vec![0; 16 * 1024];
        loop {
            let count = local_read.read(&mut buffer).await?;
            if count == 0 {
                return stream.shutdown_write().await;
            }
            stream.write(&buffer[..count]).await?;
        }
    };
    let download = async {
        let mut buffer = vec![0; 16 * 1024];
        loop {
            let count = reader.read(&mut buffer).await?;
            if count == 0 {
                return local_write.shutdown().await;
            }
            local_write.write_all(&buffer[..count]).await?;
        }
    };
    tokio::try_join!(upload, download).map(|_| ())
}

pub async fn relay_uot(
    udp: &tokio::net::UdpSocket,
    stream: &Arc<AnytlsStream>,
    reader: &mut AnytlsStreamReader,
    mode: anytls::UotMode,
) -> std::io::Result<()> {
    use anytls::{UotMode, uot_encode_packet, uot_get_packet_from_stream};
    use socks5_impl::protocol::Address;
    use std::io::{Error, ErrorKind::InvalidData};
    let outbound = async {
        loop {
            let (destination, payload) = uot_get_packet_from_stream(mode, reader).await?;
            match mode {
                UotMode::Datagram => {
                    let destination = destination.ok_or_else(|| Error::new(InvalidData, "UoT datagram missing destination"))?;
                    udp.send_to(&payload, destination.to_string()).await?;
                }
                UotMode::Connected => {
                    udp.send(&payload).await?;
                }
            }
        }
        #[allow(unreachable_code)]
        Ok::<(), Error>(())
    };
    let inbound = async {
        let mut buffer = vec![0; 65_535];
        loop {
            let frame = match mode {
                UotMode::Datagram => {
                    let (count, source) = udp.recv_from(&mut buffer).await?;
                    uot_encode_packet(mode, Some(&Address::from(source)), &buffer[..count])?
                }
                UotMode::Connected => {
                    let count = udp.recv(&mut buffer).await?;
                    uot_encode_packet(mode, None, &buffer[..count])?
                }
            };
            stream.write(&frame).await?;
        }
        #[allow(unreachable_code)]
        Ok::<(), Error>(())
    };
    tokio::select! {
        result = outbound => result,
        result = inbound => result,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anytls::Session;
    use core::future::Future;
    use core::time::Duration;
    use tokio::time::timeout;

    async fn stream_pair() -> (Arc<Session>, Arc<Session>, Arc<AnytlsStream>, Arc<AnytlsStream>) {
        let (client_io, server_io) = tokio::io::duplex(8192);
        let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
        let padding = || {
            Arc::new(tokio::sync::RwLock::new(
                anytls::PaddingFactory::new(anytls::DEFAULT_SCHEME).unwrap(),
            ))
        };
        let server = Session::new_server(2, Box::new(server_io), padding(), 8);
        let server_accept = server.clone();
        tokio::spawn(async move {
            while let Ok(stream) = server_accept.accept_stream().await {
                sender.send(Arc::new(stream)).unwrap();
            }
        });
        let client = Session::new_client(1, Box::new(client_io), padding(), 8);
        client.run().await.unwrap();
        server.run().await.unwrap();
        let local = Arc::new(client.open_stream().await.unwrap());
        let remote = receiver.recv().await.unwrap();
        (client, server, local, remote)
    }

    #[tokio::test]
    async fn uot_partial_packet_survives_reverse_traffic() {
        use anytls::{UotMode, uot_encode_packet, uot_get_packet_from_stream};
        use socks5_impl::protocol::Address;
        timeout(Duration::from_secs(5), async {
            for mode in [UotMode::Datagram, UotMode::Connected] {
                let (client, server, local, remote) = stream_pair().await;
                let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
                let target = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
                let relay_addr = udp.local_addr().unwrap();
                let destination = Address::from(target.local_addr().unwrap());
                let destination_arg = match mode {
                    UotMode::Datagram => Some(&destination),
                    UotMode::Connected => {
                        udp.connect(target.local_addr().unwrap()).await.unwrap();
                        None
                    }
                };
                let packet = uot_encode_packet(mode, destination_arg, b"fragmented").unwrap();
                let split = packet.len() - 5;
                local.write(&packet[..split]).await.unwrap();
                let task = tokio::spawn(async move {
                    let mut reader = AnytlsStreamReader::new(remote.clone());
                    relay_uot(&udp, &remote, &mut reader, mode).await
                });
                let mut response_reader = AnytlsStreamReader::new(local.clone());
                for _ in 0..3 {
                    target.send_to(b"reverse", relay_addr).await.unwrap();
                    let (_, bytes) = uot_get_packet_from_stream(mode, &mut response_reader).await.unwrap();
                    assert_eq!(bytes, b"reverse");
                }
                local.write(&packet[split..]).await.unwrap();
                let mut buffer = [0; 32];
                let (count, _) = target.recv_from(&mut buffer).await.unwrap();
                assert_eq!(&buffer[..count], b"fragmented");
                local.shutdown_write().await.unwrap();
                task.await.unwrap().unwrap_err();
                client.shutdown().await.unwrap();
                server.shutdown().await.unwrap();
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn cancelled_large_read_preserves_bytes_for_smaller_buffers() {
        timeout(Duration::from_secs(3), async {
            let (client, server, stream, remote) = stream_pair().await;
            let mut reader = AnytlsStreamReader::new(stream.clone());
            let mut large = [0; 128];
            {
                let reading = reader.read(&mut large);
                tokio::pin!(reading);
                core::future::poll_fn(|cx| {
                    assert!(reading.as_mut().poll(cx).is_pending());
                    core::task::Poll::Ready(())
                })
                .await;
            }
            remote.write(b"abcdefgh").await.unwrap();
            let mut empty = [];
            assert_eq!(reader.read(&mut empty).await.unwrap(), 0);
            let mut small = [0; 2];
            reader.read_exact(&mut small).await.unwrap();
            assert_eq!(&small, b"ab");
            let mut rest = [0; 6];
            reader.read_exact(&mut rest).await.unwrap();
            assert_eq!(&rest, b"cdefgh");
            client.shutdown().await.unwrap();
            server.shutdown().await.unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn tcp_relay_forwards_bytes_buffered_while_reading_destination() {
        use socks5_impl::protocol::{Address, AsyncStreamOperation};

        timeout(Duration::from_secs(3), async {
            let (client, server, stream, remote) = stream_pair().await;
            let destination = Address::from("127.0.0.1:443".parse::<core::net::SocketAddr>().unwrap());
            let mut payload: Vec<u8> = destination.into();
            let request = b"GET / HTTP/1.0\r\n\r\n";
            payload.extend_from_slice(request);
            stream.write(&payload).await.unwrap();

            let mut reader = AnytlsStreamReader::new(remote.clone());
            let parsed = Address::retrieve_from_async_stream(&mut reader).await.unwrap();
            assert_eq!(parsed.to_string(), "127.0.0.1:443");

            let (mut target, target_io) = tokio::io::duplex(1024);
            let relay = tokio::spawn(async move { relay_tcp(target_io, remote, &mut reader).await });
            let mut forwarded = vec![0; request.len()];
            timeout(Duration::from_secs(1), target.read_exact(&mut forwarded))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(forwarded, request);

            relay.abort();
            let _ = relay.await;
            client.shutdown().await.unwrap();
            server.shutdown().await.unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn relay_preserves_both_half_close_directions() {
        timeout(Duration::from_secs(3), async {
            for local_first in [true, false] {
                let (client, server, stream, remote) = stream_pair().await;
                let (mut app, local) = tokio::io::duplex(1024);
                let mut reader = AnytlsStreamReader::new(stream.clone());
                let relay = tokio::spawn(async move { relay_tcp(local, stream, &mut reader).await });
                let mut buffer = [0; 32];
                if local_first {
                    app.write_all(b"request").await.unwrap();
                    app.shutdown().await.unwrap();
                    let count = remote.read(&mut buffer).await.unwrap();
                    assert_eq!(&buffer[..count], b"request");
                    assert_eq!(remote.read(&mut buffer).await.unwrap(), 0);
                    remote.write(b"response").await.unwrap();
                    remote.shutdown_write().await.unwrap();
                    let mut response = Vec::new();
                    app.read_to_end(&mut response).await.unwrap();
                    assert_eq!(response, b"response");
                } else {
                    remote.shutdown_write().await.unwrap();
                    assert_eq!(app.read(&mut buffer).await.unwrap(), 0);
                    app.write_all(b"still uploading").await.unwrap();
                    app.shutdown().await.unwrap();
                    let count = remote.read(&mut buffer).await.unwrap();
                    assert_eq!(&buffer[..count], b"still uploading");
                    assert_eq!(remote.read(&mut buffer).await.unwrap(), 0);
                }
                relay.await.unwrap().unwrap();
                client.shutdown().await.unwrap();
                server.shutdown().await.unwrap();
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn session_shutdown_rejects_stream_writes() {
        timeout(Duration::from_secs(3), async {
            let (client, server, stream, _remote) = stream_pair().await;
            client.shutdown().await.unwrap();
            let error = stream.write(b"after shutdown").await.unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
            server.shutdown().await.unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn relay_write_failure_cancels_pending_upload() {
        struct FailedWriter;
        impl AsyncRead for FailedWriter {
            fn poll_read(
                self: core::pin::Pin<&mut Self>,
                _: &mut core::task::Context<'_>,
                _: &mut tokio::io::ReadBuf<'_>,
            ) -> core::task::Poll<std::io::Result<()>> {
                core::task::Poll::Pending
            }
        }
        impl AsyncWrite for FailedWriter {
            fn poll_write(
                self: core::pin::Pin<&mut Self>,
                _: &mut core::task::Context<'_>,
                _: &[u8],
            ) -> core::task::Poll<std::io::Result<usize>> {
                core::task::Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()))
            }
            fn poll_flush(self: core::pin::Pin<&mut Self>, _: &mut core::task::Context<'_>) -> core::task::Poll<std::io::Result<()>> {
                core::task::Poll::Ready(Ok(()))
            }
            fn poll_shutdown(self: core::pin::Pin<&mut Self>, _: &mut core::task::Context<'_>) -> core::task::Poll<std::io::Result<()>> {
                core::task::Poll::Ready(Ok(()))
            }
        }
        timeout(Duration::from_secs(3), async {
            let (client, server, stream, remote) = stream_pair().await;
            remote.write(b"response").await.unwrap();
            let mut reader = AnytlsStreamReader::new(stream.clone());
            let error = relay_tcp(FailedWriter, stream, &mut reader).await.unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
            client.shutdown().await.unwrap();
            server.shutdown().await.unwrap();
        })
        .await
        .unwrap();
    }
}
