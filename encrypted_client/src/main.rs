use encryption::{encrypt_text, to_transformed_body, EncryptedStream, EncryptionError, EncryptionLayer, ByteStreamBody};
use http::{Method, Request, Response};
use http_body_util::BodyExt;
use hyper_tls::HttpsConnector;
use hyper_util::rt::TokioExecutor;

use futures_util::stream::StreamExt;
use futures_util::TryStreamExt;
use http::request::Parts;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use request_analysis::request_to_curl_command;

#[tokio::main]
async fn main() {
    let encryption_layer: EncryptionLayer = EncryptionLayer::new(3);
    let https: HttpsConnector<HttpConnector> = HttpsConnector::new();
    let client: Client<HttpsConnector<HttpConnector>, ByteStreamBody> =
        Client::builder(TokioExecutor::new())
            .build::<_, ByteStreamBody>(https);

    let request_text: &str = "This is a secure request but a bit different !";

    // Create first stream for curl command
    let encrypted_stream = encrypt_text(request_text, encryption_layer.clone());
    let first_body: ByteStreamBody = to_transformed_body(encrypted_stream);
    let (parts, _): (Parts, ByteStreamBody) = prepare_request(first_body).into_parts();

    // Create new bodies for both requests
    let encrypted_stream = encrypt_text(request_text, encryption_layer.clone());
    let curl_body: ByteStreamBody = to_transformed_body(encrypted_stream);

    let encrypted_stream = encrypt_text(request_text, encryption_layer.clone());
    let real_body: ByteStreamBody = to_transformed_body(encrypted_stream);

    // Create both requests
    let curl_req: Request<ByteStreamBody> = Request::from_parts(parts.clone(), curl_body);
    let real_req: Request<ByteStreamBody> = Request::from_parts(parts, real_body);

    println!("Equivalent curl command:");
    println!("{}", request_to_curl_command(curl_req).await);
    println!("Sending encrypted request to server...");

    match client.request(real_req).await {
        Ok(resp) => {
            println!("Request sent successfully");
            process_response(encryption_layer, resp).await;
        }
        Err(e) => println!("Error sending request: {:?}", e),
    }
}


fn prepare_request(encrypted_stream: ByteStreamBody) -> Request<ByteStreamBody> {
    Request::builder()
        .method(Method::POST)
        .uri("https://dusty-perri-lapoule-dev-63b55446.koyeb.app/")
        .header("Content-Type", "application/base32")
        .body(encrypted_stream) // Use the stream directly
        .unwrap()
}


async fn process_response(encryption_layer: EncryptionLayer, resp: Response<hyper::body::Incoming>) {
    println!("Response received, decrypting...");

    let (_, body) = resp.into_parts();
    let stream = body
        .into_data_stream()
        .map_err(|_| EncryptionError::Decryption("Decryption failed".into()));

    let decrypted_stream = EncryptedStream::new(
        Box::pin(stream),
        encryption_layer.clone(),
        false, // Decrypt incoming response
    );

    let mut decrypted_response_body = Vec::new();
    let mut stream = decrypted_stream;

    while let Some(chunk) = stream.next().await {
        match chunk {
            Ok(data) => decrypted_response_body.extend_from_slice(&data),
            Err(e) => println!("Decryption error: {:?}", e),
        }
    }

    println!(
        "Decrypted Response: {:?}",
        String::from_utf8_lossy(&decrypted_response_body)
    );
}
