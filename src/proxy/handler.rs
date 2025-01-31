use http_body_util::Empty;
use hyper::body::Incoming;
use hyper::{Method, StatusCode};
use bytes;
use crate::tunnel::tunnel;

pub async fn handle_request(
    req: hyper::Request<Incoming>,
    client: hyper_util::client::legacy::Client<hyper_util::client::legacy::connect::HttpConnector, Incoming>,
) -> Result<hyper::Response<Empty<bytes::Bytes>>, hyper::Error> {
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

            Ok(hyper::Response::builder()
                .status(StatusCode::OK)
                .body(Empty::new())
                .unwrap())
        } else {
            eprintln!("CONNECT host is not socket addr: {:?}", req.uri());
            let mut resp = hyper::Response::new(Empty::new());
            *resp.status_mut() = StatusCode::BAD_REQUEST;
            Ok(resp)
        }
    } else {
        match client.request(req).await {
            Ok(response) => {
                // Convert the Incoming body to Empty for consistency
                let (parts, _) = response.into_parts();
                Ok(hyper::Response::from_parts(parts, Empty::new()))
            },
            Err(e) => {
                eprintln!("Error forwarding request: {}", e);
                Ok(hyper::Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(Empty::new())
                    .unwrap())
            }
        }
    }
}
