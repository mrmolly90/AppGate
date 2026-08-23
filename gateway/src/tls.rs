// =============================================================================
// AppGate Gateway — TLS Configuration (rustls)
// =============================================================================
//
// TLS 1.3 only. Uses rustls (ring-backed) — NO OpenSSL dependency.
// =============================================================================

use anyhow::{Context, Result};
use rustls::crypto::ring as provider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::ServerConfig;
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;
use tracing::info;

/// Load TLS configuration from PEM files.
pub async fn load_tls_config(cert_path: &str, key_path: &str) -> Result<TlsAcceptor> {
    let config = build_server_config(cert_path, key_path)?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

fn build_server_config(cert_path: &str, key_path: &str) -> Result<ServerConfig> {
    let crypto_provider = Arc::new(provider::default_provider());

    let cert_file = File::open(cert_path)
        .with_context(|| format!("Failed to open certificate file: {cert_path}"))?;
    let mut cert_reader = BufReader::new(cert_file);
    let cert_chain: Vec<CertificateDer> = certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .context("Failed to parse certificate PEM")?;
    if cert_chain.is_empty() {
        anyhow::bail!("No certificates found in {cert_path}");
    }

    let key_file = File::open(key_path)
        .with_context(|| format!("Failed to open key file: {key_path}"))?;
    let mut key_reader = BufReader::new(key_file);
    let keys: Vec<PrivateKeyDer> = pkcs8_private_keys(&mut key_reader)
        .collect::<Result<Vec<_>, _>>()
        .context("Failed to parse private key PEM")?;
    let private_key = keys.into_iter().next()
        .ok_or_else(|| anyhow::anyhow!("No private keys found in {key_path}"))?;

    let mut config = ServerConfig::builder_with_provider(crypto_provider)
        .with_safe_default_protocol_versions()
        .context("Failed to set protocol versions")?
        .with_client_cert_verifier(WebPkiClientVerifier::no_client_auth())
        .with_single_cert(cert_chain, private_key)
        .context("Failed to build server config")?;

    config.max_early_data_size = 0;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    info!(target: "appgate::tls", cert = cert_path, alpn = ?config.alpn_protocols, "TLS configuration loaded");
    Ok(config)
}