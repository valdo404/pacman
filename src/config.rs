use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use std::error::Error;
use std::fs::File;
use std::io::BufReader;

pub fn create_tls_config(cert_path: &str, key_path: &str) -> Result<ServerConfig, Box<dyn Error + Send + Sync>> {
    let cert_file = File::open(cert_path)?;
    let mut cert_reader = BufReader::new(cert_file);

    let key_file = File::open(key_path)?;
    let mut key_reader = BufReader::new(key_file);

    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .filter_map(|result| result.ok())
        .collect();

    let key = rustls_pemfile::pkcs8_private_keys(&mut key_reader)
        .filter_map(|result| result.ok())
        .next()
        .ok_or("no private key found")?;

    let key = PrivateKeyDer::Pkcs8(key);

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    Ok(config)
}
