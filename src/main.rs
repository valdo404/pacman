mod pac;
mod logic;
mod conditions;
mod proxy_types;
mod tunnel;
mod forwarder;

use rustls::ServerConfig;
use std::{
    fmt::Debug,
    net::SocketAddr,
    sync::Arc,
};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use clap::Parser;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;

use forwarder::{Forwarder, DirectForwarder, ProxyForwarder};
use http::header::HeaderMap;
use hyper::Uri;

mod handler;
mod config;

use handler::handle_request;
use config::create_tls_config;

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

    /// Upstream proxy to forward requests to
    #[arg(long)]
    proxy: Option<String>,

    /// Skip TLS verification when connecting to upstream proxy
    #[arg(long)]
    insecure: bool,
}

async fn run_http_server(
    addr: SocketAddr,
    proxy_uri: Option<String>,
    insecure: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind(addr).await?;
    println!("HTTP Listening on http://{}", addr);

    let forwarder: Arc<dyn Forwarder> = if let Some(proxy_uri) = proxy_uri {
        println!("Using upstream proxy: {}", proxy_uri);
        Arc::new(ProxyForwarder::new(
            proxy_uri.parse::<Uri>().expect("Invalid proxy URI"),
            HeaderMap::new(),
            insecure
        ))
    } else {
        Arc::new(DirectForwarder::new())
    };

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let forwarder = forwarder.clone();

        tokio::spawn(async move {
            if let Err(err) = http1::Builder::new()
                .serve_connection(
                    io,
                    service_fn(move |req| handle_request(req, forwarder.clone())),
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
        let forwarder = Arc::new(DirectForwarder::new()) as Arc<dyn Forwarder>;

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
                            service_fn(move |req| handle_request(req, forwarder.clone())),
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
        result = run_http_server(http_addr, args.proxy, args.insecure) => {
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