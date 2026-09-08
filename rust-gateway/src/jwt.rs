//! AppGate Gateway — JWT Authentication

use jsonwebtoken::{decode, Algorithm, DecodingKey, TokenData, Validation};
use serde::{Deserialize, Serialize};
use tracing::debug;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub iss: String,
    pub aud: String,
    pub exp: usize,
    pub iat: usize,
}

pub struct JwtValidator {
    decoding_key: DecodingKey,
    validation: Validation,
}

impl JwtValidator {
    pub fn new(config: &crate::config::JwtConfig) -> anyhow::Result<Self> {
        let issuer = config.issuer.clone()
            .unwrap_or_else(|| "appgate".to_string());
        let audience = config.audience.clone()
            .unwrap_or_else(|| "appgate-gateway".to_string());

        // Prefer a PEM key file when configured; otherwise use JWKS URL
        if let Some(key_path) = &config.key_path {
            let pem = std::fs::read(key_path)
                .map_err(|e| anyhow::anyhow!("Failed to read JWT public key {}: {e}", key_path))?;
            return Self::from_pem(&pem, &issuer, &audience);
        }

        if let Some(jwks_url) = &config.jwks_url {
            anyhow::bail!("JWKS loading from {} is not supported in this build (auto-start disabled); configure APPGATE_JWT_KEY_PATH with the PEM public key", jwks_url);
        }

        anyhow::bail!(
            "no JWT key source configured (set APPGATE_JWT_KEY_PATH or APPGATE_JWT_JWKS_URL)"
        )
    }

    pub fn from_pem(pem: &[u8], issuer: &str, audience: &str) -> anyhow::Result<Self> {
        let decoding_key = DecodingKey::from_ed_pem(pem)
            .or_else(|_| DecodingKey::from_rsa_pem(pem))
            .or_else(|_| DecodingKey::from_ec_pem(pem))
            .map_err(|e| anyhow::anyhow!("Unsupported PEM format: {e}"))?;

        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&[issuer]);
        validation.set_audience(&[audience]);
        validation.validate_exp = true;
        validation.validate_nbf = false;

        Ok(Self {
            decoding_key,
            validation,
        })
    }

    pub fn validate(&self, token: &str) -> anyhow::Result<TokenData<Claims>> {
        debug!("Validating JWT token");
        decode::<Claims>(token, &self.decoding_key, &self.validation)
            .map_err(|e| anyhow::anyhow!("JWT validation failed: {e}"))
    }
}