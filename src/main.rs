mod proxy;
mod pac;
mod logic;
mod conditions;
mod proxy_types;
mod encryption;
// mod encrypted_client;

use hyper::{
    service::{make_service_fn, service_fn}
    , Client, Error, Server,
};
use rustls::ServerConfig;
use std::{
    fmt::{Debug},
    net::SocketAddr,
    sync::Arc,
};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::proxy::{create_tls_config, handle_request};
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "pacman")]
#[command(author = "Laurent Valdes")]
#[command(version = "0.1.0")]
#[command(about = "A simple HTTP/HTTPS proxy", long_about = None)]
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
                    let connection_info = tls_stream.get_ref();
                    let protocol = connection_info.1.alpn_protocol();
                    let version = connection_info.1.protocol_version();

                    // Extract SNI
                    let sni = if let Some(server_name) = connection_info.1.server_name() {
                        server_name
                    } else {
                        "No SNI"
                    };

                    println!("New TLS connection from {}: SNI: {}, Protocol: {:?}, Version: {:?}",
                             addr, sni, protocol, version);

                    let service = service_fn(move |req| handle_request(req, client.clone()));
                    if let Err(e) = hyper::server::conn::Http::new()
                        .serve_connection(tls_stream, service)
                        .with_upgrades()
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


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args = Args::parse();

    let http_addr: SocketAddr = format!("{}:{}", args.bind, args.http_port)
        .parse()
        .expect("Invalid HTTP address");
    let https_addr: SocketAddr = format!("{}:{}", args.bind, args.https_port)
        .parse()
        .expect("Invalid HTTPS address");

    let tls_config: ServerConfig = create_tls_config(&args.cert, &args.key)?;

    println!("Starting proxy server:");
    println!("  HTTP on {}", http_addr);
    println!("  HTTPS on {}", https_addr);
    println!("  Using cert: {}", args.cert);
    println!("  Using key: {}", args.key);

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