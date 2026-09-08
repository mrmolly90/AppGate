//! Security and operational middleware

use axum::{
    extract::Request,
    http::header,
    middleware::Next,
    response::Response,
};
use std::time::Instant;
use tracing::{info, warn};

/// Security headers middleware
pub async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;

    let headers = response.headers_mut();
    headers.insert(header::STRICT_TRANSPORT_SECURITY, "max-age=31536000; includeSubDomains".parse().unwrap());
    headers.insert(header::X_CONTENT_TYPE_OPTIONS, "nosniff".parse().unwrap());
    headers.insert(header::X_FRAME_OPTIONS, "DENY".parse().unwrap());
    headers.insert(header::CONTENT_SECURITY_POLICY, "default-src 'self'".parse().unwrap());
    headers.insert(header::REFERRER_POLICY, "strict-origin-when-cross-origin".parse().unwrap());
    headers.insert("X-Proxy-By", "AppGate".parse().unwrap());

    response
}

/// Request timing and logging middleware
pub async fn request_timer(req: Request, next: Next) -> Response {
    let start = Instant::now();
    let method = req.method().clone();
    let uri = req.uri().clone();

    let response = next.run(req).await;

    let duration = start.elapsed();
    let status = response.status();

    if status.is_server_error() {
        warn!(
            method = %method,
            path = %uri.path(),
            status = %status,
            duration_ms = %duration.as_millis(),
            "Request completed with server error"
        );
    } else {
        info!(
            method = %method,
            path = %uri.path(),
            status = %status,
            duration_ms = %duration.as_millis(),
            "Request completed"
        );
    }

    response
}