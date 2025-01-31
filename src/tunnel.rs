use hyper::upgrade::Upgraded;
use tokio::io::copy_bidirectional;
use tokio::net::TcpStream;

use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use hyper::rt::{Read, Write};
use std::mem::MaybeUninit;

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

pub async fn tunnel(upgraded: Upgraded, addr: String) -> std::io::Result<()> {
    let mut stream = TcpStream::connect(&addr).await?;
    let mut io = UpgradedIo(upgraded);

    copy_bidirectional(&mut io, &mut stream).await?;
    Ok(())
}
