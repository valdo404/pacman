use hyper::{Body, Client, Error, Request, Response, Server};
use hyper::service::{make_service_fn, service_fn};
use std::convert::Infallible;
use std::fmt::{Debug, Display, Formatter};
use std::net::SocketAddr;
use tokio::net::TcpListener;
use hyper::server::conn::Http;

enum MyError {
    HyperError(hyper::Error),
    HttpError(hyper::http::Error),
    // ... add more error types if needed
}

impl From<hyper::Error> for MyError {
    fn from(err: hyper::Error) -> Self {
        MyError::HyperError(err)
    }
}

impl Debug for MyError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

impl Display for MyError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "My custom error")
    }
}

impl std::error::Error for MyError {}

impl From<hyper::http::Error> for MyError {
    fn from(err: hyper::http::Error) -> Self {
        MyError::HttpError(err)
    }
}

async fn handle_request(req: Request<Body>, client: Client<hyper::client::HttpConnector>) -> Result<Response<Body>, MyError> {
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
