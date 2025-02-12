use crate::forwarder::{convert_request_body, Forwarder};
use crate::tunnel::tunnel;
use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::http::response::Builder;
use hyper::{Method, StatusCode};
use std::error::Error;
use std::sync::Arc;

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

fn error_response(status: StatusCode) -> Result<hyper::Response<Full<Bytes>>, hyper::http::Error> {
    Builder::new()
        .status(status)
        .body(Full::new(Bytes::new()))
}

pub async fn handle_request(
    req: hyper::Request<Incoming>,
    forwarder: Arc<dyn Forwarder>,
) -> Result<hyper::Response<Full<Bytes>>, ProxyError> {
    println!("[HANDLER] {} {} from {}", 
        req.method(), 
        req.uri(),
        req.headers().get("x-forwarded-for")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("direct")
    );
    println!("[HANDLER] Headers: {:?}", req.headers());
    println!("[HANDLER] Version: {:?}", req.version());
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
        
        
        match forwarder.forward(convert_request_body(req)).await {
            Ok(response) => Ok(response),
            Err(e) => {
                eprintln!("Error forwarding request: {}", e);
                Ok(error_response(StatusCode::BAD_GATEWAY)?)
            }
        }
    }
}


