use std::fs;
use std::sync::Arc;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls_pemfile::{certs, pkcs8_private_keys};
use tokio_rustls::TlsAcceptor;
use tracing::info;

fn ensure_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

pub async fn load_tls_config(cert_path: &str, key_path: &str) -> anyhow::Result<TlsAcceptor> {
    ensure_crypto_provider();
    let cert_file = fs::File::open(cert_path)?;
    let mut cert_reader = std::io::BufReader::new(cert_file);
    let cert_chain: Vec<CertificateDer> = certs(&mut cert_reader).collect::<Result<Vec<_>, _>>()?;
    
    let key_file = fs::File::open(key_path)?;
    let mut key_reader = std::io::BufReader::new(key_file);
    let keys: Vec<_> = pkcs8_private_keys(&mut key_reader).collect::<Result<Vec<_>, _>>()?;
    let key: PrivateKeyDer = keys.into_iter().next()
        .ok_or_else(|| anyhow::anyhow!("No private key"))?
        .into();
    
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)?;
    
    info!("TLS config loaded from {}", cert_path);
    Ok(TlsAcceptor::from(Arc::new(config)))
}
