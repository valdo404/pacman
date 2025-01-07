use hyper::{
    service::{make_service_fn, service_fn},
    Body, Client, Error, Request, Response, Server,
};
use rustls::{PrivateKey, ServerConfig};
use std::{
    fmt::{Debug, Display, Formatter},
    net::SocketAddr,
    sync::Arc,
};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

#[derive(Debug)]
enum ProxyError {
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

async fn handle_request(
    req: Request<Body>,
    client: Client<hyper::client::HttpConnector>
) -> Result<Response<Body>, ProxyError> {
    let forwarded_req = Request::builder()
        .method(req.method())
        .uri(req.uri())
        .body(req.into_body())?;

    let resp = client.request(forwarded_req).await?;
    Ok(resp)
}

async fn run_http_server(
    addr: SocketAddr,
    client: Client<hyper::client::HttpConnector>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let server = Server::bind(&addr).serve(make_service_fn(move |_| {
        let client = client.clone();
        async move {
            Ok::<_, Error>(service_fn(move |req| handle_request(req, client.clone())))
        }
    }));

    println!("HTTP Listening on http://{}", addr);
    server.await?;
    Ok(())
}

async fn run_https_server(
    addr: SocketAddr,
    tls_config: ServerConfig,
    client: Client<hyper::client::HttpConnector>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));
    let listener = TcpListener::bind(addr).await?;
    println!("HTTPS Listening on https://{}", addr);

    while let Ok((stream, addr)) = listener.accept().await {
        println!("Accepted connection from {}", addr);
        let tls_acceptor = tls_acceptor.clone();
        let client = client.clone();

        tokio::spawn(async move {
            match tls_acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    let service = service_fn(move |req| handle_request(req, client.clone()));
                    if let Err(e) = hyper::server::conn::Http::new()
                        .serve_connection(tls_stream, service)
                        .await
                    {
                        eprintln!("Error serving TLS connection: {}", e);
                    }
                }
                Err(e) => eprintln!("TLS handshake failed: {}", e),
            }
        });
    }

    Ok(())
}

fn create_tls_config(
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let http_addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    let https_addr = SocketAddr::from(([127, 0, 0, 1], 3001));
    let tls_config = create_tls_config("cert.pem", "key.pem")?;

    tokio::select! {
        result = run_http_server(http_addr, Client::new()) => {
            if let Err(e) = result {
                eprintln!("HTTP server error: {}", e);
            }
        }
        result = run_https_server(https_addr, tls_config, Client::new()) => {
            if let Err(e) = result {
                eprintln!("HTTPS server error: {}", e);
            }
        }
    }

    Ok(())
}