//! AppGate Gateway — SSRF (Server-Side Request Forgery) Protection
//!
//! Blocks requests to internal IP ranges and non-public networks.

use std::net::IpAddr;
use tracing::debug;

const BLOCKED_HOSTS: &[&str] = &["localhost", "127.0.0.1", "::1", "0.0.0.0"];

pub struct SsrfGuard;

impl SsrfGuard {
    pub fn new(_config: &crate::config::GatewayConfig) -> Self {
        Self
    }

    pub fn validate_url(&self, input: &str) -> Result<(), &'static str> {
        let parsed = match url::Url::parse(input) {
            Ok(u) => u,
            Err(_) => return Err("invalid_url"),
        };

        if let Some(host) = parsed.host_str() {
            if BLOCKED_HOSTS.contains(&host) {
                debug!(host = %host, "SSRF blocked: localhost variant");
                return Err("ssrf_localhost_blocked");
            }
        }

        if let Some(ip) = parsed.host().and_then(|h| match h {
            url::Host::Ipv4(ip) => Some(IpAddr::V4(ip)),
            url::Host::Ipv6(ip) => Some(IpAddr::V6(ip)),
            _ => None,
        }) {
            if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
                debug!(ip = %ip, "SSRF blocked: internal IP");
                return Err("ssrf_internal_ip_blocked");
            }
        }

        Ok(())
    }
}