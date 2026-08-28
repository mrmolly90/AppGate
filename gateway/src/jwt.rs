use std::fs;
use anyhow::Context;
use jsonwebtoken::{Algorithm, DecodingKey, TokenData, Validation};
use serde::{Deserialize, Deserializer, Serialize};
use serde::de;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub iss: String,
    #[serde(deserialize_with = "deserialize_audience")]
    pub aud: Vec<String>,
    pub exp: usize,
    pub iat: usize,
    pub nbf: Option<usize>,
    pub jti: Option<String>,
    pub roles: Option<Vec<String>>,
    pub scope: Option<String>,
    pub tenant_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ValidatedToken {
    pub identity_id: String,
    pub roles: Vec<String>,
    pub scope: String,
    pub token_id: String,
    pub tenant_id: Option<String>,
    pub expiry: usize,
}

fn deserialize_audience<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where D: Deserializer<'de> {
    struct AudienceVisitor;
    impl<'de> de::Visitor<'de> for AudienceVisitor {
        type Value = Vec<String>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("string or array of strings")
        }
        fn visit_str<E>(self, value: &str) -> Result<Vec<String>, E> where E: de::Error {
            Ok(vec![value.to_string()])
        }
        fn visit_seq<A>(self, seq: A) -> Result<Vec<String>, A::Error>
        where A: de::SeqAccess<'de> {
            Deserialize::deserialize(de::value::SeqAccessDeserializer::new(seq))
        }
    }
    deserializer.deserialize_any(AudienceVisitor)
}

pub struct JwtValidator {
    static_key: Option<DecodingKey>,
    validation: Validation,
}

impl JwtValidator {
    pub fn new(key_path: &str, issuer: &str, audience: &str, _jwks_url: Option<&str>) -> anyhow::Result<Self> {
        let static_key = if !key_path.is_empty() && std::path::Path::new(key_path).exists() {
            let pem = fs::read_to_string(key_path)
                .with_context(|| format!("Failed to read JWT key: {}", key_path))?;
            Some(DecodingKey::from_rsa_pem(pem.as_bytes())?)
        } else { None };
        
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[issuer]);
        validation.set_audience(&[audience]);
        validation.leeway = 0;
        
        Ok(Self { static_key, validation })
    }
    
    pub fn validate(&self, token: &str) -> anyhow::Result<ValidatedToken> {
        let header = jsonwebtoken::decode_header(token)?;
        let key = match &self.static_key {
            Some(k) => k,
            None => anyhow::bail!("No key available"),
        };
        let mut val = self.validation.clone();
        val.algorithms = vec![header.alg];
        let td: TokenData<Claims> = jsonwebtoken::decode(token, key, &val)?;
        Ok(ValidatedToken {
            identity_id: td.claims.sub,
            roles: td.claims.roles.unwrap_or_default(),
            scope: td.claims.scope.unwrap_or_default(),
            token_id: td.claims.jti.unwrap_or_default(),
            tenant_id: td.claims.tenant_id,
            expiry: td.claims.exp,
        })
    }
}