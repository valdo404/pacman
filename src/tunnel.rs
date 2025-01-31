use hyper::upgrade::Upgraded;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;

use std::pin::Pin;
use std::task::{Context, Poll};
use hyper::rt::{Read, Write};
use std::mem::MaybeUninit;
use tls_parser::{TlsCipherSuiteID, TlsExtension, TlsExtensionType, TlsMessage, TlsMessageHandshake, TlsVersion};

#[derive(Debug)]
pub struct OwnedClientHello {
    pub version: TlsVersion,
    pub sni: Option<String>,
    pub alpn: Vec<Vec<u8>>,
    pub cipher_suites: Vec<TlsCipherSuiteID>,
    pub extensions: Vec<u16>,
}

pub struct UpgradedIo(Upgraded);

impl AsyncRead for UpgradedIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let slice = buf.initialized_mut();
        let uninit: &mut [MaybeUninit<u8>] = unsafe {
            std::slice::from_raw_parts_mut(
                slice.as_mut_ptr() as *mut MaybeUninit<u8>,
                slice.len(),
            )
        };
        let mut hyper_buf = hyper::rt::ReadBuf::uninit(uninit);
        let cursor = hyper_buf.unfilled();
        
        match Pin::new(&mut self.0).poll_read(cx, cursor) {
            Poll::Ready(Ok(())) => {
                let n = hyper_buf.filled().len();
                unsafe { buf.assume_init(n) };
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for UpgradedIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

pub fn extract_tls_info(data: &[u8]) -> Option<OwnedClientHello> {
    let (_, record_header) = tls_parser::parse_tls_record_header(data).ok()?;
    if record_header.record_type != tls_parser::TlsRecordType::Handshake {
        return None;
    }

    let (_, msgs) = tls_parser::parse_tls_plaintext(data).ok()?;
    let msg = msgs.msg.first()?;

    if let TlsMessage::Handshake(TlsMessageHandshake::ClientHello(hello)) = msg {
        let mut owned = OwnedClientHello {
            version: hello.version,
            sni: None,
            alpn: Vec::new(),
            cipher_suites: hello.ciphers.to_vec(),
            extensions: Vec::new(),
        };

        if let Some(ext_data) = hello.ext {
            if let Ok((_, exts)) = tls_parser::parse_tls_extensions(ext_data) {
                for ext in exts {
                    let ext_id = TlsExtensionType::from(&ext).0;
                    owned.extensions.push(ext_id);

                    match ext {
                        TlsExtension::SNI(sni) => {
                            if let Some(name) = sni.first() {
                                owned.sni = String::from_utf8(name.1.to_vec()).ok();
                            }
                        },
                        TlsExtension::ALPN(alpn) => {
                            owned.alpn = alpn.iter().map(|p| p.to_vec()).collect();
                        },
                        _ => {}
                    }
                }
            }
        }

        Some(owned)
    } else {
        None
    }
}

pub async fn tunnel(upgraded: Upgraded, addr: String) -> std::io::Result<()> {
    let upstream = TcpStream::connect(&addr).await?;
    let io = UpgradedIo(upgraded);
    
    let (mut client_read, mut client_write) = tokio::io::split(io);
    let (mut upstream_read, mut upstream_write) = upstream.into_split();

    let mut peek_buffer = [0u8; 1024];
    match client_read.read(&mut peek_buffer).await {
        Ok(n) if n > 0 => {
            if peek_buffer[0] == 0x16 {
                if let Some(sni) = extract_tls_info(&peek_buffer[..n]) {
                    println!("Detected SNI in CONNECT tunnel: {:?}", sni);
                }
            }
            upstream_write.write_all(&peek_buffer[..n]).await?
        }
        _ => println!("Unable to read initial TLS handshake data"),
    }

    let client_to_server = async {
        let result = tokio::io::copy(&mut client_read, &mut upstream_write).await;
        println!("Client to server copy finished for {}: {:?}", addr, result);
        result
    };

    let server_to_client = async {
        let result = tokio::io::copy(&mut upstream_read, &mut client_write).await;
        println!("Server to client copy finished for {}: {:?}", addr, result);
        result
    };

    match tokio::try_join!(client_to_server, server_to_client) {
        Ok((from_client, from_server)) => {
            println!("Tunnel closed for {}. Bytes client->server: {}, server->client: {}",
                     addr, from_client, from_server);
        }
        Err(e) => eprintln!("Error in tunnel for {}: {}", addr, e),
    }

    Ok(())
}
