//! Gateway configuration

use std::path::PathBuf;
use crate::Args;

/// Gateway configuration
#[derive(Clone, Debug)]
pub struct Config {
    pub listen_addr: String,
    pub listen_port: u16,
    pub control_plane_url: String,
    pub jwt_key_path: PathBuf,
    pub jwt_issuer: String,
    pub jwt_audience: String,
    pub allowed_algorithms: Vec<String>,
    pub clock_skew_seconds: i64,
}

impl Config {
    /// Load configuration from CLI args and environment
    pub fn load(args: Args) -> anyhow::Result<Self> {
        Ok(Self {
            listen_addr: args.listen_addr,
            listen_port: args.listen_port,
            control_plane_url: args.control_plane_url,
            jwt_key_path: PathBuf::from(&args.jwt_key_path),
            jwt_issuer: args.jwt_issuer,
            jwt_audience: args.jwt_audience,
            allowed_algorithms: vec!["RS256".into(), "ES256".into()],
            clock_skew_seconds: 30,
        })
    }
}