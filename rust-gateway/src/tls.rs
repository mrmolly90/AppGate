use std::sync::Arc;
use std::path::Path;
use rustls::ServerConfig;
use tokio::fs;

pub async fn load_tls_config(
    cert_path: impl AsRef<Path>,
    key_path: impl AsRef<Path>,
) -> anyhow::Result<Arc<ServerConfig>> {
    let cert_pem = fs::read(cert_path).await?;
    let key_pem = fs::read(key_path).await?;

    let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
        rustls_pemfile::certs(&mut &*cert_pem).collect::<Result<Vec<_>, _>>()?;

    let key = rustls_pemfile::private_key(&mut &*key_pem)?
        .ok_or_else(|| anyhow::anyhow!("no valid private key found in key file"))?;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    Ok(Arc::new(config))
}