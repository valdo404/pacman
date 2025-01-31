use bytes::Bytes;
use http_body_util::Empty;
use hyper::body::Incoming;
use hyper::http::response::Builder;
use hyper::{Method, StatusCode};
use std::error::Error;
use crate::tunnel::tunnel;

#[derive(Debug)]
pub enum ProxyError {
    Hyper(hyper::Error),
    Http(hyper::http::Error),
    Io(std::io::Error),
}

impl From<hyper::Error> for ProxyError {
    fn from(err: hyper::Error) -> Self {
        ProxyError::Hyper(err)
    }
}

impl From<hyper::http::Error> for ProxyError {
    fn from(err: hyper::http::Error) -> Self {
        ProxyError::Http(err)
    }
}

impl From<std::io::Error> for ProxyError {
    fn from(err: std::io::Error) -> Self {
        ProxyError::Io(err)
    }
}

impl std::fmt::Display for ProxyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProxyError::Hyper(e) => write!(f, "Hyper error: {}", e),
            ProxyError::Http(e) => write!(f, "HTTP error: {}", e),
            ProxyError::Io(e) => write!(f, "IO error: {}", e),
        }
    }
}

impl Error for ProxyError {}

fn error_response(status: StatusCode) -> Result<hyper::Response<Empty<Bytes>>, hyper::http::Error> {
    Builder::new()
        .status(status)
        .body(Empty::new())
}

pub async fn handle_request(
    req: hyper::Request<Incoming>,
    client: hyper_util::client::legacy::Client<hyper_util::client::legacy::connect::HttpConnector, Incoming>,
) -> Result<hyper::Response<Empty<Bytes>>, ProxyError> {
    if Method::CONNECT == req.method() {
        if let Some(addr) = req.uri().authority().map(|auth| auth.to_string()) {
            tokio::task::spawn(async move {
                match hyper::upgrade::on(req).await {
                    Ok(upgraded) => {
                        if let Err(e) = tunnel(upgraded, addr).await {
                            eprintln!("server io error: {}", e);
                        };
                    }
                    Err(e) => eprintln!("upgrade error: {}", e),
                }
            });

            Ok(error_response(StatusCode::OK)?)
        } else {
            eprintln!("CONNECT host is not socket addr: {:?}", req.uri());
            Ok(error_response(StatusCode::BAD_REQUEST)?)
        }
    } else {
        match client.request(req).await {
            Ok(response) => {
                let (parts, _) = response.into_parts();
                Ok(hyper::Response::from_parts(parts, Empty::new()))
            },
            Err(e) => {
                eprintln!("Error forwarding request: {}", e);
                Ok(error_response(StatusCode::BAD_GATEWAY)?)
            }
        }
    }
}
