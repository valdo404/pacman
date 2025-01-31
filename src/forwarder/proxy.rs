use std::error::Error;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{body::Incoming, Request, Response, Uri};
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use hyper_util::client::legacy::connect::HttpConnector;

use super::Forwarder;

/// ProxyForwarder forwards requests through another proxy server
pub struct ProxyForwarder {
    client: Client<HttpConnector, Incoming>,
    proxy_uri: Uri,
}

impl ProxyForwarder {
    pub fn new(proxy_uri: Uri) -> Self {
        Self {
            client: Client::builder(TokioExecutor::new())
                .build::<_, hyper::body::Incoming>(HttpConnector::new()),
            proxy_uri,
        }
    }

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
    async fn forward(&self, req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Box<dyn Error + Send + Sync>> {
        let req = self.rewrite_request(req);
        let response = self.client.request(req).await?;
        let (parts, body) = response.into_parts();
        let bytes = body.collect().await?.to_bytes();
        Ok(Response::from_parts(parts, Full::new(bytes)))
    }
}
