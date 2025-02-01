//! Proxy forwarding implementation for HTTP requests

use bytes::Bytes;
use http::header::HeaderMap;
use http_body_util::{BodyExt, Full};
use hyper::{body::Incoming, Request, Response, Uri};
use hyper_util::{client::legacy::{connect::HttpConnector, Client}, rt::TokioExecutor};
use std::{error::Error, fmt};

use super::{ByteStreamBody, Forwarder};

#[derive(Debug)]
pub enum ProxyError {
    Configuration(String),
}

impl fmt::Display for ProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProxyError::Configuration(msg) => write!(f, "Proxy configuration error: {}", msg),
        }
    }
}

impl Error for ProxyError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forwarder::convert_request_body;
    use bytes::Bytes;
    use http_body_util::combinators::BoxBody;
    use http_body_util::{BodyExt, Empty};
    use std::convert::Infallible;

    #[tokio::test]
    async fn test_proxy_forwarding() {
        let proxy = ProxyForwarder::new(
            "http://127.0.0.1:8080".parse().unwrap(),
            HeaderMap::new()
        );

        // Create an empty body that implements Body trait
        let empty_body: BoxBody<Bytes, Infallible> = Empty::<Bytes>::new().boxed();

        let request: Request<BoxBody<Bytes, Infallible>> = Request::builder()
            .method("GET")
            .uri("http://www.google.com")
            .body(empty_body)
            .unwrap();

        let response = proxy.forward(convert_request_body(request)).await.unwrap();
        assert!(response.status().is_success());
        
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert!(!body.is_empty());
    }
}

pub struct ProxyForwarder {
    client: Client<HttpConnector, ByteStreamBody>,
    proxy_uri: Uri,
    proxy_headers: HeaderMap,
}


#[async_trait::async_trait]
impl Forwarder for ProxyForwarder {
    async fn forward(&self, req: Request<ByteStreamBody>) -> Result<hyper::Response<Full<Bytes>>, Box<dyn Error + Send + Sync>> {
        println!("[PROXY] Forwarding {} {} via proxy to {}",
                 req.method(),
                 req.uri(),
                 req.uri().host().unwrap_or("unknown")
        );

        let rewritten_req: Request<ByteStreamBody> = self.rewrite_request(req)?;
        println!("[PROXY] Rewritten request URI: {}", rewritten_req.uri());

        let incoming_response: Response<Incoming> = self.client.request(rewritten_req).await?;
        println!("[PROXY] Received response: {}", incoming_response.status());

        let (parts, body) = incoming_response.into_parts();
        let bytes = body.collect().await?.to_bytes();
        Ok(Response::from_parts(parts, Full::new(bytes)))
    }
}

impl ProxyForwarder {
    pub fn new(proxy_uri: Uri, proxy_headers: HeaderMap) -> Self {
        Self {
            client: Client::builder(TokioExecutor::new())
                .build::<_, ByteStreamBody>(HttpConnector::new()),
            proxy_uri,
            proxy_headers,
        }
    }

    fn rewrite_request(&self, mut req: Request<ByteStreamBody>) -> Result<Request<ByteStreamBody>, ProxyError> {
        let uri = req.uri();

        // Get the host from headers or return error
        let host = req.headers()
            .get("host")
            .and_then(|h| h.to_str().ok())
            .or_else(|| req.uri().host())
            .ok_or_else(|| ProxyError::Configuration("Missing host header and unable to extract from URI".to_string()))?;

        // Construct the target URL using the host and the original path
        let path_and_query = uri.path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");

        // Construct absolute URI with scheme, host, and path
        let target_uri = format!("http://{}{}", host, path_and_query)
            .parse::<Uri>()
            .map_err(|e| ProxyError::Configuration(e.to_string()))?;

        *req.uri_mut() = target_uri;
        req.headers_mut().extend(self.proxy_headers.clone());

        Ok(req)
    }
}
