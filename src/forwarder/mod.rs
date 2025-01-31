use std::error::Error;
use http_body_util::Full;
use bytes::Bytes;
use hyper::Request;
use hyper::body::Incoming;

/// Trait defining the behavior of a request forwarder
#[async_trait::async_trait]
pub trait Forwarder: Send + Sync {
    /// Forward an HTTP request according to the forwarder's strategy
    async fn forward(&self, req: Request<Incoming>) -> Result<hyper::Response<Full<Bytes>>, Box<dyn Error + Send + Sync>>;
}

mod direct;
mod proxy;

pub use direct::DirectForwarder;
pub use proxy::ProxyForwarder;
