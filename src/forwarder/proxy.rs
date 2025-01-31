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

use std::{error::Error, fmt, pin::Pin, sync::Arc, task::{Context, Poll}};
use bytes::Bytes;
use futures_util::future::BoxFuture;
use http::{header::{HeaderMap, HeaderValue}, Method};
use http_body_util::{BodyExt, Full};
use hyper::{body::Incoming, upgrade::Upgraded, Request, Response, Uri};
use hyper_util::{client::legacy::{connect::{HttpConnector, Connect}, Client}, rt::TokioExecutor};
use tokio::io::{AsyncRead, AsyncWrite};
use tower_service::Service;

use super::Forwarder;

/// Custom error type for proxy-related errors
#[derive(Debug)]
pub enum ProxyError {
    /// Error during connection to proxy
    Connection(String),
    /// Error during request processing
    Request(String),
    /// Error during CONNECT tunnel setup
    Tunnel(String),
    /// Invalid URI or configuration
    Configuration(String),
}

impl fmt::Display for ProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProxyError::Connection(msg) => write!(f, "Proxy connection error: {}", msg),
            ProxyError::Request(msg) => write!(f, "Proxy request error: {}", msg),
            ProxyError::Tunnel(msg) => write!(f, "Proxy tunnel error: {}", msg),
            ProxyError::Configuration(msg) => write!(f, "Proxy configuration error: {}", msg),
        }
    }
}

impl Error for ProxyError {}

/// A forwarder that sends requests through another proxy server with support for both
/// HTTP and HTTPS connections. For HTTPS, it establishes a tunnel using the HTTP CONNECT method.
pub struct ProxyForwarder {
    /// HTTP client for making requests
    client: Client<ProxyConnector, Incoming>,
    /// URI of the proxy server
    proxy_uri: Uri,
    /// Optional proxy authentication headers
    proxy_headers: HeaderMap,
}

/// Custom connector that handles both direct and proxied connections
#[derive(Clone)]
struct ProxyConnector {
    /// Inner HTTP connector
    inner: HttpConnector,
    /// Proxy server URI
    proxy_uri: Uri,
    /// Optional proxy authentication headers
    proxy_headers: HeaderMap,
}

impl ProxyConnector {
    fn new(proxy_uri: Uri, proxy_headers: HeaderMap) -> Self {
        let mut inner = HttpConnector::new();
        inner.enforce_http(false); // Allow HTTPS URLs
        Self {
            inner,
            proxy_uri,
            proxy_headers,
        }
    }

    /// Creates a tunnel for HTTPS connections using HTTP CONNECT
    async fn establish_tunnel<T>(
        client: &Client<T, Incoming>,
        uri: &Uri,
        proxy_headers: &HeaderMap,
    ) -> Result<Upgraded, ProxyError>
    where
        T: Connect + Clone + Send + Sync + 'static,
    {
        let host = uri.host().ok_or_else(|| {
            ProxyError::Configuration("Missing host in URI".to_string())
        })?;
        let port = uri.port_u16().unwrap_or(443);
        let addr = format!("{host}:{port}");

        let mut request = Request::builder()
            .method(Method::CONNECT)
            .uri(addr)
            .body(Full::new(Bytes::new()))
            .map_err(|e| ProxyError::Request(e.to_string()))?;

        // Add proxy authentication headers if present
        request.headers_mut().extend(proxy_headers.clone());

        let response = client
            .request(request)
            .await
            .map_err(|e| ProxyError::Request(e.to_string()))?;

        if !response.status().is_success() {
            return Err(ProxyError::Tunnel(format!(
                "Tunnel connection failed: {}",
                response.status()
            )));
        }

        hyper::upgrade::on(response)
            .await
            .map_err(|e| ProxyError::Tunnel(e.to_string()))
    }
}
pub struct ProxyForwarder {
    client: Client<HttpConnector, Incoming>,
    proxy_uri: Uri,
}

impl Service<Uri> for ProxyConnector {
    type Response = Box<dyn AsyncRead + AsyncWrite + Send + Unpin>;
    type Error = Box<dyn Error + Send + Sync>;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let proxy_uri = self.proxy_uri.clone();
        let proxy_headers = self.proxy_headers.clone();
        let mut inner = self.inner.clone();

        Box::pin(async move {
            let stream = inner.call(proxy_uri).await?;
            Ok(Box::new(stream) as Box<dyn AsyncRead + AsyncWrite + Send + Unpin>)
        })
    }
}

impl ProxyForwarder {
    /// Creates a new ProxyForwarder that will forward requests through the specified proxy URI.
    ///
    /// # Arguments
    /// * `proxy_uri` - The URI of the proxy server (e.g., "http://proxy.example.com:8080")
    /// * `proxy_headers` - Optional headers for proxy authentication
    ///
    /// # Returns
    /// A new ProxyForwarder instance configured with the specified proxy settings
    pub fn new(proxy_uri: Uri, proxy_headers: HeaderMap) -> Self {
        let connector = ProxyConnector::new(proxy_uri.clone(), proxy_headers.clone());
        Self {
            client: Client::builder(TokioExecutor::new())
                .build::<_, Incoming>(connector),
            proxy_uri,
            proxy_headers,
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
    /// Rewrites the request URI for HTTP requests to be forwarded through the proxy.
    /// For HTTPS requests, this is not needed as they use a tunnel.
    fn rewrite_request(&self, mut req: Request<Incoming>) -> Result<Request<Incoming>, ProxyError> {
        if req.uri().scheme_str() == Some("https") {
            return Ok(req); // HTTPS requests don't need rewriting, they use CONNECT
        }

        // Convert the request URI to an absolute form
        let uri = req.uri();
        let authority = uri.authority().ok_or_else(|| {
            ProxyError::Configuration("Missing authority in URI".to_string())
        })?;
        let path_and_query = uri.path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");

        // Construct the absolute URI
        let new_uri = format!("http://{}{}", authority, path_and_query)
            .parse()
            .map_err(|e| ProxyError::Configuration(e.to_string()))?;

        *req.uri_mut() = new_uri;

        // Add proxy headers if any
        req.headers_mut().extend(self.proxy_headers.clone());

        Ok(req)
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
        println!("[PROXY] Forwarding {} {} via proxy to {}", 
            req.method(), 
            req.uri(), 
            req.uri().host().unwrap_or("unknown")
        );
        println!("[PROXY] Request headers: {:?}", req.headers());

        let response = if req.uri().scheme_str() == Some("https") {
            // For HTTPS, establish a tunnel first
            println!("[PROXY] Establishing HTTPS tunnel");
            let upgraded = ProxyConnector::establish_tunnel(&self.client, req.uri(), &self.proxy_headers).await?;
            println!("[PROXY] HTTPS tunnel established");
            
            // Create a new client with the tunneled connection
            let mut req = req;
            req.headers_mut().extend(self.proxy_headers.clone());
            self.client.request(req).await?
        } else {
            // For HTTP, rewrite the request and forward it
            let req = self.rewrite_request(req)?;
            println!("[PROXY] Rewritten request URI: {}", req.uri());
            self.client.request(req).await?
        };

        println!("[PROXY] Received response: {} from upstream", response.status());
        println!("[PROXY] Response headers: {:?}", response.headers());

        let (parts, body) = response.into_parts();
        let bytes = body.collect().await?.to_bytes();
        let response = Response::from_parts(parts, Full::new(bytes));
        
        println!("[PROXY] Forwarding response to client");
        Ok(response)
    }
}
