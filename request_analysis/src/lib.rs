use std::pin::Pin;
use bytes::{Bytes, BytesMut};
use futures::Stream;
use futures_util::StreamExt;
use http::{Method, Request};
use http_body_util::StreamBody;
use hyper::body::Frame;

async fn collect_body(
    mut req_body: StreamBody<Pin<Box<dyn Stream<Item=Result<Frame<Bytes>, hyper::Error>> + Send>>>,
    size_limit: usize,
) -> Result<BytesMut, String> {
    let mut body = BytesMut::new();
    while let Some(chunk_result) = req_body.next().await {
        match chunk_result {
            Ok(chunk) => {
                if let Ok(data) = chunk.into_data() {
                    if body.len() + data.len() > size_limit {
                        return Err("Body size exceeds the limit".to_string());
                    }
                    body.extend_from_slice(&data);
                }
            }
            Err(e) => return Err(format!("Error reading stream: {}", e)),
        }
    }
    Ok(body)
}

pub async fn request_to_curl_command(
    req: Request<StreamBody<Pin<Box<dyn Stream<Item=Result<Frame<Bytes>, hyper::Error>> + Send>>>>,
) -> String {
    let mut curl = format!("curl -X {} '{}'", req.method(), req.uri());

    for (name, value) in req.headers() {
        curl.push_str(&format!(
            " \\\n  -H '{}: {}'",
            name,
            value.to_str().unwrap_or_default()
        ));
    }

    if req.method() == Method::POST || req.method() == Method::PUT {
        let size_limit = 1 * 1024 * 1024; // 1 MB size limit
        let (_, body) = req.into_parts();

        match collect_body(body, size_limit).await {
            Ok(body_bytes) => {
                let data_str = String::from_utf8_lossy(&body_bytes).replace("'", "'\\''");
                curl.push_str(&format!(" \\\n  --data '{}'", data_str));
            }
            Err(e) => {
                println!("Failed to read body: {}", e);
            }
        }
    }

    curl
}