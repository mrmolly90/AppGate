//! AppGate Gateway — TLS Configuration
//!
//! Loads PEM-encoded certificates and private keys using rustls 0.23.

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::fs;
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;

/// Load TLS server configuration from PEM files.
#[allow(dead_code)]
pub async fn load_tls_config(
    cert_path: &str,
    key_path: &str,
) -> Result<TlsAcceptor, Box<dyn std::error::Error + Send + Sync>> {
    let cert_pem = fs::read_to_string(cert_path)?;
    let key_pem = fs::read_to_string(key_path)?;

    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()?;

    let keys: Vec<PrivateKeyDer<'static>> =
        rustls_pemfile::private_key(&mut key_pem.as_bytes())?
            .into_iter()
            .collect();

    let key = keys.into_iter().next().ok_or("No private key found")?;

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}