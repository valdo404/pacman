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

use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long, default_value = "3000")]
    http_port: u16,

    #[arg(long, default_value = "3001")]
    https_port: u16,

    #[arg(long, default_value = "cert.pem")]
    cert: String,

    #[arg(long, default_value = "key.pem")]
    key: String,

    #[arg(long, default_value = "127.0.0.1")]
    bind: String,
}

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

async fn handle_request(
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

    // Regular proxy request handling
    let mut builder = Request::builder()
        .method(req.method())
        .uri(req.uri());

    // Copy headers from original request
    if let Some(headers) = builder.headers_mut() {
        for (name, value) in req.headers() {
            headers.insert(name, value.clone());
        }
    }

    let forwarded_req = builder.body(req.into_body())?;
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
                        .with_upgrades()  // Add this line
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
    let args = Args::parse();

    let http_addr: SocketAddr = format!("{}:{}", args.bind, args.http_port)
        .parse()
        .expect("Invalid HTTP address");
    let https_addr: SocketAddr = format!("{}:{}", args.bind, args.https_port)
        .parse()
        .expect("Invalid HTTPS address");

    let tls_config = create_tls_config(&args.cert, &args.key)?;

    println!("Starting proxy server:");
    println!("  HTTP on {}", http_addr);
    println!("  HTTPS on {}", https_addr);
    println!("  Using cert: {}", args.cert);
    println!("  Using key: {}", args.key);

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