use base32::{decode, encode, Alphabet};
use bytes::{Bytes, BytesMut};
use futures::Stream;
use http_body_util::StreamBody;
use std::error::Error as StdError;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use futures::stream::Once;
use futures::StreamExt;
use hyper::body::Frame;

pub type ConcreteFuture = Pin<Box<dyn Future<Output = Result<Bytes, Box<dyn StdError + Send + Sync>>> + Send + 'static>>;
pub type ConcreteEncryptedStream = EncryptedStream<Pin<Box<Once<ConcreteFuture>>>>;
pub type ByteStreamBody = StreamBody<Pin<Box<dyn Stream<Item = Result<Frame<Bytes>, Box<dyn StdError + Send + Sync>>> + Send + 'static>>>;

pub fn encrypt_text(
    request_text: &str,
    encryption_layer: EncryptionLayer,
) -> ConcreteEncryptedStream {
    let text = request_text.to_string();

    let stream: Once<ConcreteFuture> = futures::stream::once(Box::pin(async move {
        Ok::<Bytes, Box<dyn StdError + Send + Sync>>(Bytes::from(text))
    }) as ConcreteFuture);

    EncryptedStream::new(Box::pin(stream), encryption_layer, true)
}

pub fn to_transformed_body(
    encrypted_stream: ConcreteEncryptedStream,
) -> ByteStreamBody {
    let mapped_stream = encrypted_stream.map(|result| {
        result
            .map(hyper::body::Frame::data)
            .map_err(|enc_err| enc_err)
    });

    StreamBody::new(
        Box::pin(mapped_stream)
            as Pin<Box<dyn Stream<Item = Result<Frame<Bytes>, Box<dyn StdError + Send + Sync>>> + Send>>
    )
}

/// EncryptionLayer provides a simple Caesar cipher style shifting mechanism
/// and Base32 encoding for demonstration purposes.
///
/// This struct can be used to encrypt and decrypt data using a fixed shift value.
#[derive(Clone)]
pub struct EncryptionLayer {
    /// The shift value used for the Caesar cipher-based encryption.
    shift: u8,
}

impl EncryptionLayer {
    /// Creates a new `EncryptionLayer` with a specified shift value.
    ///
    /// # Arguments
    /// - `shift`: The number of positions to shift each character during encryption.
    ///
    /// # Examples
    /// ```
    /// let encryption = EncryptionLayer::new(3);
    /// ```
    pub fn new(shift: u8) -> Self {
        Self { shift }
    }

    /// Encrypts a chunk of data using a Caesar cipher combined with Base32 encoding.
    ///
    /// # Arguments
    /// - `data`: A slice of bytes to encrypt.
    ///
    /// # Returns
    /// A `Vec<u8>` containing the encrypted data.
    pub fn encrypt_chunk(&self, data: &[u8]) -> Vec<u8> {
        let base32_str = encode(Alphabet::Rfc4648 { padding: true }, data);

        base32_str
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() {
                    let base = if c.is_ascii_uppercase() { b'A' } else if c.is_ascii_digit() { b'0' } else { b'a' };
                    let range = if c.is_ascii_digit() { 10 } else { 26 };
                    let current = (c as u8 - base) as u8;
                    let shifted = (current + self.shift) % range;
                    (shifted + base) as u8
                } else {
                    c as u8
                }
            })
            .collect()
    }

    /// Attempts to decrypt a chunk of data using the reverse Caesar cipher and Base32 decoding.
    ///
    /// # Arguments
    /// - `data`: A slice of bytes to decrypt.
    ///
    /// # Returns
    /// - `Some(Vec<u8>)` if decryption is successful.
    /// - `None` if decryption fails.
    pub fn decrypt_chunk(&self, data: &[u8]) -> Option<Vec<u8>> {
        let unshifted: String = data
            .iter()
            .map(|&b| {
                if b.is_ascii_alphanumeric() {
                    let base = if b.is_ascii_uppercase() { b'A' } else if b.is_ascii_digit() { b'0' } else { b'a' };
                    let range = if b.is_ascii_digit() { 10 } else { 26 };
                    let current = (b - base) as u8;
                    let unshifted = (current + range - self.shift) % range;
                    (unshifted + base) as char
                } else {
                    b as char
                }
            })
            .collect();

        decode(Alphabet::Rfc4648 { padding: true }, &unshifted)
    }
}

/// A stream wrapper that encrypts or decrypts data on the fly while processing chunks.
///
/// This struct is useful for handling streaming data where encryption or decryption is required.
pub struct EncryptedStream<S> {
    /// The underlying stream of data being processed.
    inner: S,
    /// The encryption layer used for encryption or decryption.
    encryption: EncryptionLayer,
    /// Determines whether the stream should encrypt (`true`) or decrypt (`false`).
    encrypting: bool,
    #[allow(dead_code)]
    buffer: BytesMut,
}

impl<S> EncryptedStream<S> {
    /// Creates a new `EncryptedStream`.
    ///
    /// # Arguments
    /// - `inner`: The inner stream providing the data.
    /// - `encryption`: The `EncryptionLayer` for processing the data.
    /// - `encrypting`: A boolean indicating whether to encrypt or decrypt the stream.
    pub fn new(inner: S, encryption: EncryptionLayer, encrypting: bool) -> Self {
        Self {
            inner,
            encryption,
            buffer: BytesMut::new(),
            encrypting,
        }
    }
}

impl<S> Stream for EncryptedStream<S>
where
    S: Stream<Item = Result<Bytes, Box<dyn StdError + Send + Sync>>> + Unpin,
{
    type Item = Result<Bytes, Box<dyn StdError + Send + Sync>>;

    /// Polls the next chunk of data from the stream and processes it.
    ///
    /// - If `encrypting` is true, it encrypts the data.
    /// - If `encrypting` is false, it attempts to decrypt the data.
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match Pin::new(&mut self.inner).poll_next(cx) {
            Poll::Ready(Some(Ok(data))) => {
                let processed = if self.encrypting {
                    Bytes::from(self.encryption.encrypt_chunk(&data))
                } else {
                    match self.encryption.decrypt_chunk(&data) {
                        Some(decrypted) => Bytes::from(decrypted),
                        None => return Poll::Ready(Some(Err(Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, "Decryption failed"))))),
                    }
                };
                Poll::Ready(Some(Ok(processed)))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}