use std::fmt::{Display, Formatter};
use http::{Request, Response};
use hyper::{Body, Client};
use rustls::{PrivateKey, ServerConfig};

#[derive(Debug)]
pub enum ProxyError {
    HyperError(hyper::Error),
    HttpError(hyper::http::Error),
}

impl From<hyper::Error> for ProxyError {
    fn from(err: hyper::Error) -> Self {
        ProxyError::HyperError(err)
    }
}

impl Display for ProxyError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ProxyError::HyperError(e) => write!(f, "Hyper error: {}", e),
            ProxyError::HttpError(e) => write!(f, "HTTP error: {}", e),
        }
    }
}

impl std::error::Error for ProxyError {}

impl From<hyper::http::Error> for ProxyError {
    fn from(err: hyper::http::Error) -> Self {
        ProxyError::HttpError(err)
    }
}


pub fn create_tls_config(
    cert_path: &str,
    key_path: &str,
) -> Result<ServerConfig, Box<dyn std::error::Error + Send + Sync>> {
    let cert_file = std::fs::File::open(cert_path)?;
    let key_file = std::fs::File::open(key_path)?;

    let cert_chain = rustls_pemfile::certs(&mut std::io::BufReader::new(cert_file))?
        .into_iter()
        .map(rustls::Certificate)
        .collect();

    let key = rustls_pemfile::pkcs8_private_keys(&mut std::io::BufReader::new(key_file))?
        .into_iter()
        .map(PrivateKey)
        .next()
        .ok_or("no private key found")?;

    let mut config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)?;

    config.alpn_protocols = vec![];
    Ok(config)
}


async fn handle_connect(
    mut req: Request<Body>,
    addr: String,
) -> Result<Response<Body>, ProxyError> {
    println!("Starting CONNECT tunnel to {}", addr);
    match tokio::net::TcpStream::connect(&addr).await {
        Ok(upstream) => {
            println!("Successfully connected to upstream {}", addr);
            let response = Response::builder()
                .status(hyper::StatusCode::OK)
                .body(Body::empty())?;

            tokio::spawn(async move {
                match hyper::upgrade::on(&mut req).await {
                    Ok(upgraded) => {
                        println!("Connection upgraded for {}", addr);
                        let (mut client_read, mut client_write) =
                            tokio::io::split(upgraded);
                        let (mut upstream_read, mut upstream_write) =
                            upstream.into_split();

                        let client_to_server = async {
                            let result = tokio::io::copy(&mut client_read, &mut upstream_write).await;
                            println!("Client to server copy finished for {}: {:?}", addr, result);
                            result
                        };

                        let server_to_client = async {
                            let result = tokio::io::copy(&mut upstream_read, &mut client_write).await;
                            println!("Server to client copy finished for {}: {:?}", addr, result);
                            result
                        };

                        match tokio::try_join!(client_to_server, server_to_client) {
                            Ok((from_client, from_server)) => {
                                println!("Tunnel closed for {}. Bytes client->server: {}, server->client: {}",
                                         addr, from_client, from_server);
                            }
                            Err(e) => eprintln!("Error in tunnel for {}: {}", addr, e),
                        }
                    }
                    Err(e) => eprintln!("Upgrade error for {}: {}", addr, e),
                }
            });

            Ok(response)
        }
        Err(e) => {
            eprintln!("Failed to connect to upstream {}: {}", addr, e);
            Ok(Response::builder()
                .status(hyper::StatusCode::BAD_GATEWAY)
                .body(Body::empty())?)
        }
    }
}

pub async fn handle_request(
    mut req: Request<Body>,
    client: Client<hyper::client::HttpConnector>
) -> Result<Response<Body>, ProxyError> {
    if req.method() == hyper::Method::CONNECT {
        if let Some(addr) = req.uri().authority().map(|auth| auth.to_string()) {
            println!("CONNECT request to {}", addr);
            return handle_connect(req, addr).await;
        }
        return Ok(Response::builder()
            .status(hyper::StatusCode::BAD_REQUEST)
            .body(Body::empty())?);
    }

    let mut builder = Request::builder()
        .method(req.method())
        .uri(req.uri());

    if let Some(headers) = builder.headers_mut() {
        for (name, value) in req.headers() {
            headers.insert(name, value.clone());
        }
    }

    let forwarded_req = builder.body(req.into_body())?;
    let resp = client.request(forwarded_req).await?;
    Ok(resp)
}