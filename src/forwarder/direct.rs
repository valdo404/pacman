use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{body::Incoming, Request, Response};
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use hyper_util::client::legacy::connect::HttpConnector;

use super::Forwarder;

/// DirectForwarder forwards requests directly to their target URL
pub struct DirectForwarder {
    client: Client<HttpConnector, Incoming>,
}

impl DirectForwarder {
    pub fn new() -> Self {
        Self {
            client: Client::builder(TokioExecutor::new())
                .build::<_, hyper::body::Incoming>(HttpConnector::new()),
        }
    }
}

impl Default for DirectForwarder {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Forwarder for DirectForwarder {
    async fn forward(&self, req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Box<dyn std::error::Error + Send + Sync>> {
        println!("[DIRECT] Forwarding {} {} to {}", req.method(), req.uri(), req.uri().host().unwrap_or("unknown"));
        println!("[DIRECT] Request headers: {:?}", req.headers());
        let response = self.client.request(req).await?;
        println!("[DIRECT] Received response: {} from upstream", response.status());
        println!("[DIRECT] Response headers: {:?}", response.headers());
        let (parts, body) = response.into_parts();
        let bytes = body.collect().await?.to_bytes();
        let response = Response::from_parts(parts, Full::new(bytes));
        println!("[DIRECT] Forwarding response to client");
        Ok(response)
    }
}
