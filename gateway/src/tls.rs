use rustls::ServerConfig;
use std::path::Path;
use tokio::fs;

pub async fn load_tls_config(
    cert_path: impl AsRef<Path>,
    key_path: impl AsRef<Path>,
) -> Result<ServerConfig, Box<dyn std::error::Error + Send + Sync>> {
    let cert_data = fs::read(cert_path).await?;
    let key_data = fs::read(key_path).await?;

    let certs = rustls_pemfile::certs(&mut cert_data.as_slice())
        .collect::<Result<Vec<_>, _>>()?;

    let key = rustls_pemfile::private_key(&mut key_data.as_slice())?
        .ok_or("no private key found")?;

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    config.alpn_protocols = vec![
        b"h2".to_vec(),
        b"http/1.1".to_vec(),
    ];

    Ok(config)
}