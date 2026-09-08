//! JWT and API key authentication
//!
//! Provides middleware to validate JWTs from incoming requests,
//! extract claims, and make them available to downstream handlers.
//! Uses RS256 (RSA) for production - never HS256 with shared secrets.

use axum::{
    extract::Request,
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
use serde::{Deserialize, Serialize};
use std::fs;
use tracing::warn;

/// JWT claims supported by the gateway.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
    pub iat: usize,
    #[serde(default)]
    pub roles: Vec<String>,
}

/// Authentication middleware — validates Bearer tokens using RS256.
pub async fn auth_middleware(mut request: Request, next: Next) -> Response {
    let jwt_enabled = std::env::var("APPGATE_JWT_ENABLED")
        .ok()
        .and_then(|v| v.parse::<bool>().ok())
        .unwrap_or(false);

    if !jwt_enabled {
        request.extensions_mut().insert(Claims {
            sub: "anonymous".into(),
            exp: 0,
            iat: 0,
            roles: vec![],
        });
        return next.run(request).await;
    }

    let auth_header = request.headers().get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok());

    let token = match auth_header {
        Some(h) if h.starts_with("Bearer ") => &h[7..],
        _ => {
            warn!("Missing or malformed Authorization header");
            return (StatusCode::UNAUTHORIZED, axum::Json(serde_json::json!({
                "error": "missing bearer token"
            }))).into_response();
        }
    };

    // Load public key from file or env
    let decoding_key = match load_public_key() {
        Some(key) => key,
        None => {
            warn!("No JWT public key configured, auth disabled");
            request.extensions_mut().insert(Claims {
                sub: "anonymous".into(),
                exp: 0,
                iat: 0,
                roles: vec![],
            });
            return next.run(request).await;
        }
    };

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&["appgate"]);
    validation.set_audience(&["appgate-gateway"]);
    validation.validate_exp = true;
    validation.validate_nbf = true;
    validation.leeway = 30;

    match decode::<Claims>(token, &decoding_key, &validation) {
        Ok(token_data) => {
            request.extensions_mut().insert(token_data.claims);
            next.run(request).await
        }
        Err(e) => {
            warn!("JWT validation failed: {}", e);
            (StatusCode::UNAUTHORIZED, axum::Json(serde_json::json!({
                "error": "invalid token"
            }))).into_response()
        }
    }
}

fn load_public_key() -> Option<DecodingKey> {
    // Try file path first
    if let Ok(path) = std::env::var("APPGATE_JWT_PUBLIC_KEY_PATH") {
        if let Ok(pem) = fs::read_to_string(&path) {
            if let Ok(key) = DecodingKey::from_rsa_pem(pem.as_bytes()) {
                return Some(key);
            }
            warn!("Failed to parse RSA public key from {}", path);
        }
    }
    // Try inline key from env
    if let Ok(pem) = std::env::var("APPGATE_JWT_PUBLIC_KEY") {
        if let Ok(key) = DecodingKey::from_rsa_pem(pem.as_bytes()) {
            return Some(key);
        }
    }
    None
}