//! AppGate Gateway — SSRF (Server-Side Request Forgery) Protection
//!
//! Blocks requests to internal IP ranges and non-public networks.

use std::collections::HashSet;
use std::net::IpAddr;
use tracing::debug;

const BLOCKED_HOSTS: &[&str] = &["localhost", "127.0.0.1", "::1", "0.0.0.0"];

pub struct SSRFDefense {
    approved_domains: HashSet<String>,
    enabled: bool,
}

impl SSRFDefense {
    pub fn new_with_defaults() -> Self {
        let mut domains = HashSet::new();
        domains.insert("api.openai.com".into());
        domains.insert("api.anthropic.com".into());
        Self {
            approved_domains: domains,
            enabled: true,
        }
    }

    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    pub fn approve_domain(&mut self, domain: &str) {
        self.approved_domains.insert(domain.into());
    }

    pub fn validate_upstream(&self, url: &str) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }

        let parsed = url::Url::parse(url).map_err(|_| "invalid_url".to_string())?;

        if let Some(host) = parsed.host_str() {
            if BLOCKED_HOSTS.contains(&host) {
                debug!(host = %host, "SSRF blocked: localhost variant");
                return Err("ssrf_localhost_blocked".to_string());
            }
        }

        if let Some(ip) = parsed.host().and_then(|h| match h {
            url::Host::Ipv4(ip) => Some(IpAddr::V4(ip)),
            url::Host::Ipv6(ip) => Some(IpAddr::V6(ip)),
            _ => None,
        }) {
            if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
                debug!(ip = %ip, "SSRF blocked: internal IP");
                return Err("ssrf_internal_ip_blocked".to_string());
            }

            // Block private IP ranges
            if let IpAddr::V4(v4) = ip {
                if v4.is_private() {
                    debug!(ip = %ip, "SSRF blocked: private IP");
                    return Err("ssrf_private_ip_blocked".to_string());
                }
                if v4.is_link_local() {
                    debug!(ip = %ip, "SSRF blocked: link-local IP");
                    return Err("ssrf_link_local_blocked".to_string());
                }
            }
        }

        // Check approved domains if the list is non-empty
        if !self.approved_domains.is_empty() {
            if let Some(host) = parsed.host_str() {
                if !self.approved_domains.iter().any(|d| host == d || host.ends_with(&format!(".{}", d))) {
                    debug!(host = %host, "SSRF blocked: domain not approved");
                    return Err("ssrf_domain_not_approved".to_string());
                }
            }
        }

        Ok(())
    }
}
