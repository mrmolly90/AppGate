//! JWT validation with strict security checks

use std::fs;
use std::sync::Arc;

use jsonwebtoken::{Algorithm, DecodingKey, Validation, TokenData};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub iss: String,
    pub aud: serde_json::Value,
    pub exp: usize,
    pub iat: usize,
    pub nbf: Option<usize>,
    pub jti: Option<String>,
    pub roles: Option<Vec<String>>,
    pub scope: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ValidatedToken {
    pub identity_id: String,
    pub roles: Vec<String>,
    pub scope: String,
    pub token_id: String,
}

pub struct JwtValidator {
    decoding_key: Arc<DecodingKey>,
    validation: Validation,
    enabled: bool,
}

impl JwtValidator {
    pub fn noop() -> Self {
        Self {
            decoding_key: Arc::new(DecodingKey::from_secret(b"noop")),
            validation: Validation::default(),
            enabled: false,
        }
    }

    pub fn validate(&self, token: &str) -> anyhow::Result<ValidatedToken> {
        if !self.enabled {
            return Ok(ValidatedToken {
                identity_id: "anonymous".into(),
                roles: vec![],
                scope: "".into(),
                token_id: "".into(),
            });
        }

        let token_data: TokenData<Claims> = jsonwebtoken::decode(
            token,
            &self.decoding_key,
            &self.validation,
        )?;

        let claims = token_data.claims;

        Ok(ValidatedToken {
            identity_id: claims.sub,
            roles: claims.roles.unwrap_or_default(),
            scope: claims.scope.unwrap_or_default(),
            token_id: claims.jti.unwrap_or_default(),
        })
    }

    pub fn from_config(cfg: &crate::config::JwtConfig) -> anyhow::Result<Self> {
        if !cfg.enabled {
            return Ok(Self::noop());
        }
        match (&cfg.key_path, &cfg.jwks_url) {
            (Some(path), _) => {
                let pem = fs::read_to_string(path)?;
                let decoding_key = DecodingKey::from_rsa_pem(pem.as_bytes())?;
                let mut validation = Validation::new(Algorithm::RS256);
                validation.set_issuer(&[cfg.issuer.as_deref().unwrap_or("appgate")]);
                validation.set_audience(&[cfg.audience.as_deref().unwrap_or("appgate-gateway")]);
                validation.set_required_spec_claims(&["sub", "iss", "aud", "exp", "iat"]);
                validation.leeway = 30;
                validation.validate_exp = true;
                validation.validate_nbf = true;
                validation.algorithms = vec![Algorithm::RS256];
                Ok(Self {
                    decoding_key: Arc::new(decoding_key),
                    validation,
                    enabled: true,
                })
            }
            (None, Some(jwks)) => {
                anyhow::bail!("JWKS endpoint not yet implemented: {}", jwks)
            }
            (None, None) => anyhow::bail!("JWT enabled but no key_path or jwks_url configured"),
        }
    }
}