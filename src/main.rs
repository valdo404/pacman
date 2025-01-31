mod proxy;
mod pac;
mod logic;
mod conditions;
mod proxy_types;
mod tunnel;
mod tls;

use rustls::ServerConfig;
use std::{
    fmt::Debug,
    net::SocketAddr,
    sync::Arc,
};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use crate::proxy::handle_request;
use clap::Parser;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tls::create_tls_config;

#[derive(Parser, Debug)]
#[command(name = "pacman")]
#[command(about = "A proxy auto-config (PAC) file parser and proxy server")]
struct Args {
    /// Path to the certificate file
    #[arg(short, long)]
    cert: String,

    /// Path to the private key file
    #[arg(short, long)]
    key: String,

    /// HTTP proxy listen address
    #[arg(long, default_value = "127.0.0.1:8080")]
    http_addr: String,

    /// HTTPS proxy listen address
    #[arg(long, default_value = "127.0.0.1:8443")]
    https_addr: String,
}

async fn run_http_server(
    addr: SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind(addr).await?;
    println!("HTTP Listening on http://{}", addr);

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let client = Client::builder(TokioExecutor::new())
            .build::<_, hyper::body::Incoming>(HttpConnector::new());

        tokio::spawn(async move {
            if let Err(err) = http1::Builder::new()
                .serve_connection(
                    io,
                    service_fn(move |req| handle_request(req, client.clone())),
                )
                .with_upgrades()
                .await
            {
                eprintln!("Error serving connection: {}", err);
            }
        });
    }
}

async fn run_https_server(
    addr: SocketAddr,
    tls_config: ServerConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));
    let listener = TcpListener::bind(addr).await?;
    println!("HTTPS Listening on https://{}", addr);

    while let Ok((stream, addr)) = listener.accept().await {
        println!("Accepted connection from {}", addr);
        let tls_acceptor = tls_acceptor.clone();
        let client = Client::builder(TokioExecutor::new())
            .build::<_, hyper::body::Incoming>(HttpConnector::new());

        tokio::spawn(async move {
            match tls_acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    let (_, session) = tls_stream.get_ref();
                    let sni = session
                        .server_name()
                        .map_or("None".to_string(), |s| s.to_string());
                    let protocol = session
                        .alpn_protocol()
                        .map_or("None".to_string(), |p| String::from_utf8_lossy(p).to_string());
                    let version = session
                        .protocol_version()
                        .map_or("Unknown".to_string(), |v| format!("{:?}", v));

                    println!("New TLS connection from {}: SNI: {}, Protocol: {:?}, Version: {:?}",
                             addr, sni, protocol, version);

                    let io = TokioIo::new(tls_stream);
                    if let Err(err) = http1::Builder::new()
                        .serve_connection(
                            io,
                            service_fn(move |req| handle_request(req, client.clone())),
                        )
                        .with_upgrades()
                        .await
                    {
                        eprintln!("Error serving TLS connection: {}", err);
                    }
                }
                Err(e) => eprintln!("TLS handshake failed: {}", e),
            }
        });
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args = Args::parse();

    let http_addr: SocketAddr = args
        .http_addr
        .parse()
        .expect("Invalid HTTP address");

    let https_addr: SocketAddr = args
        .https_addr
        .parse()
        .expect("Invalid HTTPS address");

    let tls_config = create_tls_config(&args.cert, &args.key)?;

    println!("Starting proxy server:");
    println!("  HTTP on {}", http_addr);
    println!("  HTTPS on {}", https_addr);
    println!("  Using cert: {}", args.cert);
    println!("  Using key: {}", args.key);

    tokio::select! {
        result = run_http_server(http_addr) => {
            if let Err(e) = result {
                eprintln!("HTTP server error: {}", e);
            }
        }
        result = run_https_server(https_addr, tls_config) => {
            if let Err(e) = result {
                eprintln!("HTTPS server error: {}", e);
            }
        }
    }

    Ok(())
}