use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Client, Error, Request, Response, Server};
use std::fmt::{Debug, Display, Formatter};
use std::net::SocketAddr;

enum ProxyError {
    HyperError(hyper::Error),
    HttpError(hyper::http::Error),
}

impl From<hyper::Error> for ProxyError {
    fn from(err: hyper::Error) -> Self {
        ProxyError::HyperError(err)
    }
}

impl Debug for ProxyError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

impl Display for ProxyError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Proxy error occurred")
    }
}

impl std::error::Error for ProxyError {}

impl From<hyper::http::Error> for ProxyError {
    fn from(err: hyper::http::Error) -> Self {
        ProxyError::HttpError(err)
    }
}

async fn handle_request(req: Request<Body>, client: Client<hyper::client::HttpConnector>) -> Result<Response<Body>, ProxyError> {
    let forwarded_req = Request::builder()
        .method(req.method())
        .uri(req.uri())
        .body(req.into_body())?;

    let resp = client.request(forwarded_req).await?;
    Ok(resp)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    let make_svc = make_service_fn(|_conn| {
        let client = Client::new();
        async {
            Ok::<_, Error>(service_fn(move |req| handle_request(req, client.clone())))
        }
    });

    let server = Server::bind(&addr).serve(make_svc);
    println!("Listening on http://{}", addr);
    server.await?;

    Ok(())
}
