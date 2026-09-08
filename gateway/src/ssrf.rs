//! SSRF defense — prevent gateway from being used to access internal services

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};

pub struct SSRFDefense {
    approved_domains: Vec<String>,
    approved_ips: Vec<IpAddr>,
}

impl Default for SSRFDefense {
    fn default() -> Self {
        Self::new()
    }
}

impl SSRFDefense {
    pub fn new() -> Self {
        Self {
            approved_domains: Vec::new(),
            approved_ips: Vec::new(),
        }
    }

    pub fn from_config(_cfg: &crate::config::GatewayConfig) -> Self {
        let mut defense = Self::new();
        if let Ok(domains) = std::env::var("APPGATE_APPROVED_DOMAINS") {
            for d in domains.split(',') {
                defense.approve_domain(d);
            }
        }
        if let Ok(ips) = std::env::var("APPGATE_APPROVED_IPS") {
            for ip in ips.split(',') {
                if let Ok(addr) = ip.parse() {
                    defense.approve_ip(addr);
                }
            }
        }
        // Default LLM providers
        defense.approve_domain("api.openai.com");
        defense.approve_domain("api.anthropic.com");
        defense.approve_domain("generativelanguage.googleapis.com");
        defense
    }

    pub fn approve_domain(&mut self, domain: &str) {
        let domain = domain.trim().to_lowercase();
        if !domain.is_empty() && !self.approved_domains.contains(&domain) {
            self.approved_domains.push(domain);
        }
    }

    pub fn approve_ip(&mut self, ip: IpAddr) {
        if !self.approved_ips.contains(&ip) {
            self.approved_ips.push(ip);
        }
    }

    pub fn is_host_allowed(&self, host: &str) -> bool {
        if self.approved_domains.iter().any(|d| host == d || host.ends_with(&format!(".{}", d))) {
            return true;
        }
        if let Ok(ip) = host.parse::<IpAddr>() {
            if self.approved_ips.contains(&ip) {
                return true;
            }
        }
        false
    }

    /// Resolve a hostname to IPs and check if any resolved IP is private.
    /// This prevents DNS rebinding attacks where a hostname resolves to
    /// a public IP at check time but a private IP at request time.
    fn check_dns_rebinding(host: &str) -> Result<(), String> {
        // Only check if it looks like a hostname (not an IP)
        if host.parse::<IpAddr>().is_ok() {
            return Ok(());
        }

        // Resolve the hostname to check for private IPs
        let addr_str = format!("{}:0", host);
        match addr_str.to_socket_addrs() {
            Ok(addrs) => {
                for addr in addrs {
                    let ip = addr.ip();
                    if Self::is_private_ip(ip) {
                        return Err(format!(
                            "DNS rebinding detected: {} resolves to private IP {}",
                            host, ip
                        ));
                    }
                }
                Ok(())
            }
            Err(_) => {
                // DNS resolution failed — allow through, the connection will fail anyway
                tracing::warn!("DNS resolution failed for {}, allowing through", host);
                Ok(())
            }
        }
    }

    pub fn validate_upstream(&self, url: &str) -> Result<(), String> {
        let parsed = match url::Url::parse(url) {
            Ok(u) => u,
            Err(e) => return Err(format!("invalid upstream URL: {}", e)),
        };

        let scheme = parsed.scheme();
        if scheme != "https" && scheme != "http" {
            return Err(format!("unsupported scheme: {}", scheme));
        }

        let host = match parsed.host_str() {
            Some(h) => h.to_lowercase(),
            None => return Err("upstream URL has no host".into()),
        };

        // Check for private IP directly
        if let Ok(ip) = host.parse::<IpAddr>() {
            if Self::is_private_ip(ip) {
                return Err(format!("upstream host {} is a private IP (SSRF blocked)", host));
            }
        }

        // DNS rebinding protection: resolve hostname and check resolved IPs
        Self::check_dns_rebinding(&host)?;

        if !self.is_host_allowed(&host) {
            return Err(format!("upstream host {} is not in the approved allowlist (SSRF blocked)", host));
        }

        Ok(())
    }

    pub fn is_private_ip(ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => Self::is_private_ipv4(v4),
            IpAddr::V6(v6) => Self::is_private_ipv6(v6),
        }
    }

    fn is_private_ipv4(ip: Ipv4Addr) -> bool {
        ip.is_loopback()
            || ip.is_private()
            || ip.is_link_local()
            || ip.is_unspecified()
            || ip.is_multicast()
            || ip.is_broadcast()
            // CGNAT (100.64.0.0/10)
            || (ip.octets()[0] == 100 && (ip.octets()[1] & 0b11000000) == 0b1000000)
            // Benchmarking (198.18.0.0/15)
            || (ip.octets()[0] == 198 && (ip.octets()[1] & 0b11111110) == 0b00010010)
    }

    fn is_private_ipv6(ip: Ipv6Addr) -> bool {
        ip.is_loopback()
            || ip.is_unspecified()
            || ip.is_multicast()
            || ip.is_unique_local()
            || ip.is_unicast_link_local()
    }
}