use std::collections::HashSet;
// =============================================================================
// AppGate Gateway — JWT Authentication
// =============================================================================
//
// Validates JWT tokens using RSA public keys loaded from PEM files.
// Supports RS256 and ES256 algorithms with configurable leeway.
// =============================================================================

use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::fs;


/// Claims extracted from a validated JWT
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatedToken {
    /// Identity ID (sub claim)
    pub identity_id: String,
    /// Roles assigned to the identity
    pub roles: Vec<String>,
    /// Scope of access
    pub scope: String,
    /// Token ID (jti claim)
    pub token_id: String,
}

/// JWT claims structure matching the control plane's token format
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    iss: String,
    aud: String,
    exp: usize,
    iat: usize,
    jti: String,
    roles: Vec<String>,
    scope: String,
}

/// JWT Validator with key caching
pub struct JwtValidator {
    decoding_key: DecodingKey,
    validation: Validation,
}

impl JwtValidator {
    /// Create a new JWT validator from a PEM-encoded public key.
    ///
    /// # Arguments
    /// * `key_path` - Path to the PEM-encoded RSA public key
    /// * `issuer` - Expected JWT issuer
    /// * `audience` - Expected JWT audience
    ///
    /// # Errors
    /// Returns an error if the key file cannot be read or parsed.
    pub fn new(key_path: &str, issuer: &str, audience: &str) -> anyhow::Result<Self> {
        let key_pem = fs::read_to_string(key_path)
            .map_err(|e| anyhow::anyhow!("Failed to read JWT key file: {e}"))?;

        let decoding_key = DecodingKey::from_rsa_pem(key_pem.as_bytes())
            .map_err(|e| anyhow::anyhow!("Failed to parse RSA public key: {e}"))?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[issuer]);
        validation.set_audience(&[audience]);
        validation.leeway = 30; // 30 seconds clock skew tolerance
validation.required_spec_claims = HashSet::from([
    "sub".to_string(), 
    "exp".to_string(), 
    "iat".to_string(), 
    "jti".to_string(), 
    "roles".to_string(), 
    "scope".to_string()
]);

        Ok(Self {
            decoding_key,
            validation,
        })
    }

    /// Validate a JWT token and extract claims.
    ///
    /// # Arguments
    /// * `token` - The JWT string to validate
    ///
    /// # Returns
    /// `ValidatedToken` with extracted claims, or an error.
    pub fn validate(&self, token: &str) -> anyhow::Result<ValidatedToken> {
        let token_data = decode::<Claims>(token, &self.decoding_key, &self.validation)?;

        Ok(ValidatedToken {
            identity_id: token_data.claims.sub,
            roles: token_data.claims.roles,
            scope: token_data.claims.scope,
            token_id: token_data.claims.jti,
        })
    }
}
