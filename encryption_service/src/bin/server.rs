use bytes::Bytes;
use encryption::{to_transformed_body, ByteStreamBody, EncryptedStream, EncryptionLayer};
use futures::stream;
use futures::Future;
use http_body_util::StreamBody;
use std::error::Error;
use std::pin::Pin;

use hyper::body::Incoming;
use hyper::body::Frame;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));

    // Bind the TCP listener to the address
    let listener = TcpListener::bind(addr).await?;
    println!("Server running at http://{}", addr);

    // Continuously accept connections
    loop {
        let (stream, _) = listener.accept().await?;

        // Adapt the stream for hyper
        let io = TokioIo::new(stream);

        // Spawn a task to handle the connection
        tokio::task::spawn(async move {
            if let Err(err) = http1::Builder::new()
                .serve_connection(io, service_fn(handle_request))
                .await
            {
                eprintln!("Error serving connection: {:?}", err);
            }
        });
    }
}

async fn handle_request(
    req: Request<Incoming>,
) -> Result<Response<ByteStreamBody>, Box<dyn Error + Send + Sync>> {
    // Example encryption layer, replace with actual logic
    let encryption_layer = EncryptionLayer::new(3);

    match req.uri().path() {
        "/health" => Ok(Response::new(string_to_byte_stream_body("OK".to_string()))),
        _ => handle_encrypted_request(req, encryption_layer).await,
    }
}

fn string_to_byte_stream_body(input: String) -> ByteStreamBody {
    let stream = stream::once(async move {
        Ok::<Frame<Bytes>, Box<dyn Error + Send + Sync>>(Frame::data(Bytes::from(input)))
    });

    StreamBody::new(Box::pin(stream))
}

/// Handle encrypted requests
async fn handle_encrypted_request(
    req: Request<Incoming>,
    encryption_layer: EncryptionLayer,
) -> Result<Response<ByteStreamBody>, Box<dyn Error + Send + Sync>> {
    println!("Server received a request!");

    // Decrypt the request body
    let (_, body) = req.into_parts();

    let decrypted_stream = Box::pin(EncryptedStream::new(
        Box::pin(body.map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)),
        encryption_layer.clone(),
        false, // Decrypt mode
    ));

    let mut decrypted_body = Vec::new();
    while let Some(chunk) = decrypted_stream.next().await {
        match chunk {
            Ok(data) => decrypted_body.extend_from_slice(&data.to_vec()),
            Err(e) => {
                return Err(Box::new(e));
            }
        }
    }

    println!("Decrypted Request: {:?}", String::from_utf8_lossy(&decrypted_body));

    // Encrypt the response body
    let response_text: &'static str = "Hello, this is a secure response!";
    let encrypted_stream = EncryptedStream::new(
        Box::pin(stream::once(Box::pin(async move { Ok(Bytes::from(response_text)) }) as Pin<Box<dyn Future<Output = Result<Bytes, Box<dyn Error + Send + Sync>>> + Send>>)),
        encryption_layer,
        true, // Encrypt mode
    );

    Ok(Response::new(to_transformed_body(encrypted_stream)))
}
