//! Proxy forwarding implementation for HTTP requests

use bytes::Bytes;
use http::header::HeaderMap;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, Uri};
use hyper_http_proxy::{Proxy, ProxyConnector, Intercept};
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
    client: Client<ProxyConnector<HttpConnector>, ByteStreamBody>,
    proxy: Proxy,
    proxy_headers: HeaderMap,
}


#[async_trait::async_trait]
impl Forwarder for ProxyForwarder {
    async fn forward(&self, mut req: Request<ByteStreamBody>) -> Result<hyper::Response<Full<Bytes>>, Box<dyn Error + Send + Sync>> {
        println!("[PROXY] Forwarding {} {} via proxy",
                 req.method(),
                 req.uri()
        );

        // Add proxy-specific headers if needed for HTTP requests
        if req.method() != hyper::Method::CONNECT {
            req.headers_mut().extend(self.proxy.headers().clone());
        }

        // Add any additional headers
        req.headers_mut().extend(self.proxy_headers.clone());

        println!("[PROXY] Request URI: {}", req.uri());
        let incoming_response = self.client.request(req).await?;
        println!("[PROXY] Received response: {}", incoming_response.status());

        let (parts, body) = incoming_response.into_parts();
        let bytes = body.collect().await?.to_bytes();
        Ok(Response::from_parts(parts, Full::new(bytes)))
    }
}

impl ProxyForwarder {
    pub fn new(proxy_uri: Uri, proxy_headers: HeaderMap, _insecure: bool) -> Self {
        let proxy = Proxy::new(Intercept::All, proxy_uri.clone());
        let connector = HttpConnector::new();
        let proxy_connector = ProxyConnector::from_proxy(connector, proxy.clone())
            .expect("Failed to create proxy connector");

        Self {
            client: Client::builder(TokioExecutor::new())
                .pool_idle_timeout(std::time::Duration::from_secs(30))
                .build::<_, ByteStreamBody>(proxy_connector),
            proxy,
            proxy_headers,
        }
    }

    // No longer needed as the logic is now in forward()
    fn rewrite_request(&self, req: Request<ByteStreamBody>) -> Result<Request<ByteStreamBody>, ProxyError> {
        Ok(req)
    }
}
