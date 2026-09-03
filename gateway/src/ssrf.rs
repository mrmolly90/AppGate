// =============================================================================
// AppGate Gateway â€” SSRF Defense (Production)
// =============================================================================
//
// Validates upstream URLs against:
//   â€¢ Approved domain allowlist
//   â€¢ Private IP range blocking (RFC 1918, loopback, link-local)
//   â€¢ Metadata endpoint blocking (AWS, GCP, Azure)
//   â€¢ Scheme enforcement (HTTPS only in production)
// =============================================================================

use std::collections::HashSet;
use std::net::IpAddr;
use tracing::debug;

pub struct SSRFDefense {
    approved_domains: HashSet<String>,
    block_private_ips: bool,
    require_https: bool,
}

impl SSRFDefense {
    pub fn new_with_defaults() -> Self {
        let mut domains = HashSet::new();
        domains.insert("api.openai.com".into());
        domains.insert("api.anthropic.com".into());
        domains.insert("api.groq.com".into());
        domains.insert("api.cohere.com".into());
        domains.insert("api.mistral.ai".into());

        Self {
            approved_domains: domains,
            block_private_ips: true,
            require_https: true,
        }
    }

    pub fn approve_domain(&mut self, domain: &str) {
        self.approved_domains.insert(domain.to_lowercase());
    }

    pub fn validate_upstream(&self, url: &str) -> Result<(), String> {
        let parsed = match url::Url::parse(url) {
            Ok(u) => u,
            Err(_) => return Err("Invalid URL format".into()),
        };

        // Scheme check
        if self.require_https && parsed.scheme() != "https" {
            return Err("HTTPS required for upstream URLs".into());
        }

        let host = parsed.host_str().ok_or("URL missing host")?;
        let host_lower = host.to_lowercase();

        // Domain allowlist check
        let domain_approved = self.approved_domains.iter().any(|d| {
            host_lower == *d || host_lower.ends_with(&format!(".{}", d))
        });

        if !domain_approved {
            return Err(format!("Domain '{}' not in approved allowlist", host));
        }

        // IP-based checks (if host is an IP address)
        if let Ok(ip) = host.parse::<IpAddr>() {
            if self.block_private_ips && Self::is_private_ip(ip) {
                return Err("Private IP addresses are blocked".into());
            }
            if Self::is_metadata_endpoint(ip) {
                return Err("Cloud metadata endpoints are blocked".into());
            }
        }

        // Block localhost by name
        if host_lower == "localhost" || host_lower == "127.0.0.1" || host_lower == "::1" {
            return Err("Localhost is blocked".into());
        }

        debug!(target: "appgate::ssrf", url = %url, "SSRF validation passed");
        Ok(())
    }

    fn is_private_ip(ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(ip) => {
                ip.is_private()
                    || ip.is_loopback()
                    || ip.is_link_local()
                    || ip.is_multicast()
                    || ip.is_broadcast()
                    || ip.is_documentation()
                    || ip.octets()[0] == 0
                    || (ip.octets()[0] == 100 && (ip.octets()[1] & 0b1100_0000) == 0b0100_0000) // CGNAT
            }
            IpAddr::V6(ip) => {
                ip.is_loopback()
                    || ip.is_multicast()
                    || (ip.segments()[0] & 0xFE00) == 0xFC00 // Unique local
            }
        }
    }

    fn is_metadata_endpoint(ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(ip) => {
                // AWS: 169.254.169.254, GCP: 169.254.169.254, Azure: 169.254.169.254
                ip.octets() == [169, 254, 169, 254]
            }
            IpAddr::V6(_) => false,
        }
    }
}