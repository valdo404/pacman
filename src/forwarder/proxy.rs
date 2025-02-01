//! Proxy forwarding implementation for HTTP requests

use bytes::Bytes;
use http::header::HeaderMap;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, Uri};
use hyper_util::{client::legacy::{connect::HttpConnector, Client}, rt::TokioExecutor};
use hyper_tls::HttpsConnector;
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
    client: Client<HttpsConnector<HttpConnector>, ByteStreamBody>,
    proxy_uri: Uri,
    proxy_headers: HeaderMap,
}


#[async_trait::async_trait]
impl Forwarder for ProxyForwarder {
    async fn forward(&self, mut req: Request<ByteStreamBody>) -> Result<hyper::Response<Full<Bytes>>, Box<dyn Error + Send + Sync>> {
        use http::header::HOST;

        println!("[PROXY] Forwarding {} {} via proxy {}",
                 req.method(),
                 req.uri(),
                 self.proxy_uri
        );

        // For CONNECT requests, forward them as-is to the upstream proxy
        if req.method() == hyper::Method::CONNECT {
            req.headers_mut().extend(self.proxy_headers.clone());
            let incoming_response = self.client.request(req).await?;
            let (parts, body) = incoming_response.into_parts();
            let bytes = body.collect().await?.to_bytes();
            return Ok(Response::from_parts(parts, Full::new(bytes)));
        }

        // For other requests, preserve the original URI but send through proxy
        let original_uri = req.uri().clone();
        
        // Ensure host header is set
        if !req.headers().contains_key(HOST) {
            if let Some(host) = original_uri.host() {
                let mut host_value = host.to_string();
                if let Some(port) = original_uri.port_u16() {
                    host_value.push(':');
                    host_value.push_str(&port.to_string());
                }
                req.headers_mut().insert(HOST, host_value.parse().unwrap());
            }
        }

        // Add proxy headers
        req.headers_mut().extend(self.proxy_headers.clone());

        // Make sure we have an absolute URI
        if original_uri.scheme().is_none() || original_uri.authority().is_none() {
            // If URI is not absolute, make it absolute using the Host header
            let host = req.headers().get(HOST)
                .and_then(|h| h.to_str().ok())
                .ok_or_else(|| ProxyError::Configuration("Missing Host header".to_string()))?;

            let scheme = original_uri.scheme_str().unwrap_or("http");
            let path_and_query = original_uri.path_and_query()
                .map(|p| p.as_str())
                .unwrap_or("/");

            let absolute_uri = format!("{scheme}://{}{}", host, path_and_query)
                .parse::<Uri>()
                .map_err(|e| ProxyError::Configuration(e.to_string()))?;

            *req.uri_mut() = absolute_uri;
        }

        println!("[PROXY] Request URI: {}", req.uri());
        let incoming_response = self.client.request(req).await?;
        println!("[PROXY] Received response: {}", incoming_response.status());

        let (parts, body) = incoming_response.into_parts();
        let bytes = body.collect().await?.to_bytes();
        Ok(Response::from_parts(parts, Full::new(bytes)))
    }
}

impl ProxyForwarder {
    pub fn new(proxy_uri: Uri, proxy_headers: HeaderMap, insecure: bool) -> Self {
        let mut http = HttpConnector::new();
        http.enforce_http(false);
        let https = HttpsConnector::new_with_connector(http);
        Self {
            client: Client::builder(TokioExecutor::new())
                .pool_idle_timeout(std::time::Duration::from_secs(30))
                .build::<_, ByteStreamBody>(https),
            proxy_uri,
            proxy_headers,
        }
    }

    // No longer needed as the logic is now in forward()
    fn rewrite_request(&self, req: Request<ByteStreamBody>) -> Result<Request<ByteStreamBody>, ProxyError> {
        Ok(req)
    }
}
