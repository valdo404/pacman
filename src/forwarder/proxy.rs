//! Proxy forwarding implementation for HTTP requests
//! 
//! # Overview
//! This module implements a proxy forwarder that attempts to forward HTTP requests through
//! another proxy server. The current implementation has several limitations and is primarily
//! intended for basic HTTP proxying scenarios.
//!
//! # Limitations
//! - Only supports HTTP (no HTTPS/TLS support)
//! - No proxy authentication support
//! - Uses basic URL rewriting instead of proper proxy protocol implementation
//! - Limited error handling with potential panics
//! - No support for proxy-specific headers (e.g., Proxy-Authorization)
//!
//! # Future Improvements
//! - Implement proper proxy protocol support using a proxy-aware connector
//! - Add TLS support for HTTPS connections
//! - Add proxy authentication support
//! - Improve error handling with custom error types
//! - Add support for proxy-specific headers
//! - Handle CONNECT method for HTTPS tunneling
//!
//! # Example
//! ```no_run
//! use hyper::Uri;
//! let proxy = ProxyForwarder::new("http://proxy.example.com:8080".parse().unwrap());
//! // proxy can now be used to forward requests
//! ```

use std::error::Error;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{body::Incoming, Request, Response, Uri};
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use hyper_util::client::legacy::connect::HttpConnector;

use super::Forwarder;

/// A forwarder that sends requests through another proxy server.
///
/// # Warning
/// This implementation is currently limited and should not be used in production
/// without significant improvements. See the module documentation for details.
pub struct ProxyForwarder {
    client: Client<HttpConnector, Incoming>,
    proxy_uri: Uri,
}

impl ProxyForwarder {
    /// Creates a new ProxyForwarder that will forward requests through the specified proxy URI.
    ///
    /// # Arguments
    /// * `proxy_uri` - The URI of the proxy server (e.g., "http://proxy.example.com:8080")
    ///
    /// # Limitations
    /// * Currently only supports HTTP proxies
    /// * Does not support proxy authentication
    /// * Does not validate the proxy URI format
    ///
    /// # Panics
    /// * May panic if the proxy URI is malformed when used
    pub fn new(proxy_uri: Uri) -> Self {
        Self {
            client: Client::builder(TokioExecutor::new())
                .build::<_, hyper::body::Incoming>(HttpConnector::new()),
            proxy_uri,
        }
    }

    /// Rewrites the request URI to be forwarded through the proxy.
    ///
    /// # Arguments
    /// * `req` - The original request to be rewritten
    ///
    /// # Returns
    /// A new request with rewritten URI
    ///
    /// # Implementation Notes
    /// * Currently uses basic URL concatenation which may not handle all cases correctly
    /// * Does not preserve the original scheme (http/https)
    /// * May panic on malformed URIs
    /// * Does not handle requests that already have absolute URIs
    ///
    /// # Todo
    /// * Implement proper URI rewriting according to RFC 7230
    /// * Handle HTTPS requests correctly
    /// * Add error handling for malformed URIs
    /// * Preserve original request properties
    fn rewrite_request(&self, mut req: Request<Incoming>) -> Request<Incoming> {
        // Convert the request URI to an absolute form
        let uri = req.uri();
        let path_and_query = uri.path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");

        let mut new_uri = format!("{}{}", self.proxy_uri, path_and_query);
        if !new_uri.starts_with("http") {
            new_uri = format!("http://{}", new_uri);
        }

        *req.uri_mut() = new_uri.parse().unwrap();
        req
    }
}

#[async_trait::async_trait]
impl Forwarder for ProxyForwarder {
    /// Forwards a request through the proxy server.
    ///
    /// # Arguments
    /// * `req` - The HTTP request to forward
    ///
    /// # Returns
    /// * `Ok(Response)` - The response from the target server
    /// * `Err(Box<dyn Error>)` - Any error that occurred during forwarding
    ///
    /// # Implementation Notes
    /// * Currently logs all requests and responses for debugging
    /// * Uses a basic HTTP connector without proxy protocol support
    /// * Does not handle HTTPS requests properly
    /// * May not handle all error cases appropriately
    ///
    /// # Todo
    /// * Implement proper proxy protocol support
    /// * Add HTTPS/TLS support
    /// * Improve error handling with specific error types
    /// * Add support for proxy authentication
    /// * Handle streaming responses more efficiently
    async fn forward(&self, req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Box<dyn Error + Send + Sync>> {
        println!("[PROXY] Forwarding {} {} via proxy to {}", req.method(), req.uri(), req.uri().host().unwrap_or("unknown"));
        println!("[PROXY] Request headers: {:?}", req.headers());
        let req = self.rewrite_request(req);
        println!("[PROXY] Rewritten request URI: {}", req.uri());
        let response = self.client.request(req).await?;
        println!("[PROXY] Received response: {} from upstream", response.status());
        println!("[PROXY] Response headers: {:?}", response.headers());
        let (parts, body) = response.into_parts();
        let bytes = body.collect().await?.to_bytes();
        let response = Response::from_parts(parts, Full::new(bytes));
        println!("[PROXY] Forwarding response to client");
        Ok(response)
    }
}
