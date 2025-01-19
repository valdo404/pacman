use crate::encryption::{EncryptedStream, EncryptionLayer};
use bytes::Bytes;
use futures::stream::Stream;
use futures::{StreamExt, TryStreamExt};
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server};
use std::convert::Infallible;

mod encryption;

#[tokio::main]
async fn main() {
    let encryption_layer = EncryptionLayer::new(3); // Shift = 3 for Caesar cipher example
    let addr = ([127, 0, 0, 1], 3000).into();

    let server = Server::bind(&addr).serve(make_service_fn(move |_| {
        let encryption_layer = encryption_layer.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |req| handle_request(req, encryption_layer.clone())))
        }
    }));

    println!("Server running at http://127.0.0.1:3000");
    server.await.unwrap();
}

async fn handle_request(
    req: Request<Body>,
    encryption_layer: EncryptionLayer
) -> Result<Response<Body>, hyper::Error> {
    match req.uri().path() {
        "/health" => {
            Ok(Response::new(Body::from("OK")))
        }
        _ => {
            handle_encrypted_request(req, encryption_layer).await
        }
    }
}

/// Handles incoming encrypted requests
async fn handle_encrypted_request(
    req: Request<Body>,
    encryption_layer: EncryptionLayer
) -> Result<Response<Body>, hyper::Error> {
    println!("Server received a request!");

    // **Decrypt the request**
    let (parts, body) = req.into_parts();
    let decrypted_stream = EncryptedStream::new(
        body.into_stream().map_err(|_| encryption::EncryptionError::Decryption("Decryption failed".into())),
        encryption_layer.clone(),
        false,
    );

    let mut decrypted_body = Vec::new();
    let mut stream = decrypted_stream;
    while let Some(chunk) = stream.next().await {
        match chunk {
            Ok(data) => decrypted_body.extend_from_slice(&data),
            Err(e) => println!("Decryption error: {:?}", e),
        }
    }

    println!("Decrypted Request: {:?}", String::from_utf8_lossy(&decrypted_body));

    // **Encrypt the response body**
    let response_text = "Hello, this is a secure response!";
    let stream = futures::stream::once(async move { Ok(Bytes::from(response_text)) });
    let encrypted_stream = EncryptedStream::new(
        Box::pin(stream),
        encryption_layer.clone(),
        true,
    );

    Ok(Response::new(Body::wrap_stream(encrypted_stream)))
}
