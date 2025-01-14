use crate::encryption::{EncryptedStream, EncryptionError, EncryptionLayer};
use bytes::Bytes;
use futures::{StreamExt, TryStreamExt};
use hyper::{Body, Client, Method, Request};

mod encryption;

async fn request_to_curl_command(req: &mut Request<Body>) -> String {
    let mut curl = format!("curl -X {} '{}'",
                           req.method(),
                           req.uri()
    );

    // Add headers
    for (name, value) in req.headers() {
        curl.push_str(&format!(" \\\n  -H '{}: {}'",
                               name,
                               value.to_str().unwrap_or_default()
        ));
    }

    // Add body indication for POST/PUT
    if req.method() == Method::POST || req.method() == Method::PUT {
        // Take the body and collect it
        let old_body = std::mem::replace(req.body_mut(), Body::empty());
        let mut bytes = Vec::new();
        let mut stream = old_body.into_stream();

        while let Some(chunk) = stream.next().await {
            if let Ok(chunk) = chunk {
                bytes.extend_from_slice(&chunk);
            }
        }

        // Create the escaped data string
        let data_str = String::from_utf8_lossy(&bytes)
            .replace("'", "'\\''");  // Escape single quotes for shell

        curl.push_str(&format!(" \\\n  --data '{}'", data_str));

        // Recreate the body for the actual request
        *req.body_mut() = Body::from(bytes);
    }

    curl
}

#[tokio::main]
async fn main() {
    let encryption_layer = EncryptionLayer::new(3); // Shift = 3 for Caesar cipher example
    let client = Client::new();

    // **Encrypt the request body**
    let request_text = "This is a secure request but a bit different !";
    let stream = futures::stream::once(async move { Ok(Bytes::from(request_text)) });
    let encrypted_stream = EncryptedStream::new(
        Box::pin(stream),
        encryption_layer.clone(),
        true, // Encrypt outgoing request
    );

    let mut req = Request::builder()
        .method(Method::POST)
        .uri("http://127.0.0.1:3000")
        .header("Content-Type", "application/base32")
        .body(Body::wrap_stream(encrypted_stream))
        .unwrap();

    println!("Equivalent curl command:");
    println!("{}", request_to_curl_command(&mut req).await);
    println!("Sending encrypted request to server...");

    // **Send the encrypted request to the server**
    match client.request(req).await {
        Ok(resp) => {
            println!("Response received, decrypting...");

            let (parts, body) = resp.into_parts();
            let stream = body.into_stream()
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

            println!("Decrypted Response: {:?}", String::from_utf8_lossy(&decrypted_response_body));
        }
        Err(e) => println!("Error sending request: {:?}", e),
    }
}