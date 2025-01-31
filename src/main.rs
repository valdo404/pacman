mod pac;
mod logic;
mod conditions;
mod proxy_types;

use rustls::ServerConfig;
use std::{
    fmt::Debug,
    net::SocketAddr,
    sync::Arc,
};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
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
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind(addr).await?;
    println!("HTTP Listening on http://{}", addr);
    
    while let Ok((stream, _)) = listener.accept().await {
        println!("Accepted HTTP connection from {}", stream.peer_addr()?);
        // TODO: Implement HTTP request handling
    }
    
    Ok(())
}

#[allow(dead_code)]
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
    }

    Ok(())
}