use http::{Request, Response};
use hyper::{Body, Client};
use nom::Parser;
use rustls::{Certificate, PrivateKey, ServerConfig};
use std::any::{Any, TypeId};
use std::fmt::{Display, Formatter};
use tls_parser::{TlsCipherSuiteID, TlsExtension, TlsExtensionType, TlsMessage, TlsMessageHandshake, TlsVersion};
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;

#[derive(Debug)]
struct TlsHandshakeInfo {
    sni: Option<String>,
    version: Option<TlsVersion>,
    cipher_suites: Vec<TlsCipherSuiteID>,
    alpn_protocols: Vec<Vec<u8>>,
    supported_versions: Vec<TlsVersion>,
    signature_algorithms: Vec<u16>,
    extensions: Vec<TypeId>,
}


#[derive(Debug)]
pub struct OwnedClientHello {
    pub version: TlsVersion,
    pub sni: Option<String>,
    pub alpn: Vec<Vec<u8>>,
    pub cipher_suites: Vec<TlsCipherSuiteID>,
    pub extensions: Vec<u16>,
}

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

    let cert_chain: Vec<Certificate> = rustls_pemfile::certs(&mut std::io::BufReader::new(cert_file))?
        .into_iter()
        .map(rustls::Certificate)
        .collect();

    let key: PrivateKey = rustls_pemfile::pkcs8_private_keys(&mut std::io::BufReader::new(key_file))?
        .into_iter()
        .map(PrivateKey)
        .next()
        .ok_or("no private key found")?;

    let mut config: ServerConfig = ServerConfig::builder()
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
                        let (mut client_read, mut client_write) = tokio::io::split(upgraded);
                        let (mut upstream_read, mut upstream_write) = upstream.into_split();

                        let mut peek_buffer = [0u8; 1024];

                        match client_read.read(&mut peek_buffer).await {
                            Ok(n) if n > 0 => {
                                if peek_buffer[0] == 0x16 {
                                    if let Some(sni) = extract_tls_info(&peek_buffer[..n]) {
                                        println!("Detected SNI in CONNECT tunnel: {:?}", sni);
                                    }
                                }
                                if let Err(e) = upstream_write.write_all(&peek_buffer[..n]).await {
                                    eprintln!("Failed to forward initial data: {}", e);
                                    return;
                                }
                            }
                            _ => println!("Unable to read initial TLS handshake data"),
                        }

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

fn extract_tls_info(data: &[u8]) -> Option<OwnedClientHello> {
    let (_, record_header) = tls_parser::parse_tls_record_header(data).ok()?;
    if record_header.record_type != tls_parser::TlsRecordType::Handshake {
        return None;
    }

    let (_, msgs) = tls_parser::parse_tls_plaintext(data).ok()?;
    let msg = msgs.msg.first()?;

    if let TlsMessage::Handshake(TlsMessageHandshake::ClientHello(hello)) = msg {
        let mut owned = OwnedClientHello {
            version: hello.version,
            sni: None,
            alpn: Vec::new(),
            cipher_suites: hello.ciphers.to_vec(),
            extensions: Vec::new(),
        };

        if let Some(ext_data) = hello.ext {
            if let Ok((_, exts)) = tls_parser::parse_tls_extensions(ext_data) {
                for ext in exts {
                    let ext_id = TlsExtensionType::from(&ext).0;
                    owned.extensions.push(ext_id);

                    match ext {
                        TlsExtension::SNI(sni) => {
                            if let Some(name) = sni.first() {
                                owned.sni = String::from_utf8(name.1.to_vec()).ok();
                            }
                        },
                        TlsExtension::ALPN(alpn) => {
                            owned.alpn = alpn.iter().map(|p| p.to_vec()).collect();
                        },
                        _ => {}
                    }
                }
            }
        }

        Some(owned)
    } else {
        None
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