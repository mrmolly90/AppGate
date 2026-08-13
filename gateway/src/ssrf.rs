//! SSRF defense — prevent gateway from being used to access internal services
//!
//! Maintains an explicit allowlist of approved LLM provider endpoints.
//! Rejects any destination that is not explicitly approved.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// SSRF defense configuration
pub struct SSRFDefense {
    approved_domains: Vec<String>,
    approved_ips: Vec<IpAddr>,
}

impl SSRFDefense {
    pub fn new() -> Self {
        Self {
            approved_domains: Vec::new(),
            approved_ips: Vec::new(),
        }
    }

    /// Check if a host is allowed
    /// Returns true if the host is explicitly approved
    pub fn is_host_allowed(&self, host: &str) -> bool {
        // Check approved domains
        if self.approved_domains.iter().any(|d| host == d || host.ends_with(&format!(".{}", d))) {
            return true;
        }

        // Check approved IPs
        if let Ok(ip) = host.parse::<IpAddr>() {
            if self.approved_ips.contains(&ip) {
                return true;
            }
        }

        false
    }

    /// Check if an IP address is a private or reserved address
    /// This is a key SSRF defense: reject any private IP ranges
    pub fn is_private_ip(ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => Self::is_private_ipv4(v4),
            IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified() || v6.is_multicast(),
        }
    }

    fn is_private_ipv4(ip: Ipv4Addr) -> bool {
        ip.is_loopback()
            || ip.is_private()
            || ip.is_link_local()
            || ip.is_unspecified()
            || ip.is_multicast()
            || ip.is_broadcast()
            || ip.octets()[0] == 100 && (ip.octets()[1] & 0b11000000) == 0b10000000 // Carrier-grade NAT
            || ip.octets()[0] == 198 && (ip.octets()[1] & 0b11111110) == 0b10100000 // 198.18.0.0/15
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_private_ip_rejection() {
        assert!(SSRFDefense::is_private_ip("127.0.0.1".parse().unwrap()));
        assert!(SSRFDefense::is_private_ip("10.0.0.1".parse().unwrap()));
        assert!(SSRFDefense::is_private_ip("172.16.0.1".parse().unwrap()));
        assert!(SSRFDefense::is_private_ip("192.168.1.1".parse().unwrap()));
        assert!(SSRFDefense::is_private_ip("169.254.1.1".parse().unwrap()));
        assert!(SSRFDefense::is_private_ip("::1".parse().unwrap()));
    }

    #[test]
    fn test_public_ip_allowed() {
        assert!(!SSRFDefense::is_private_ip("8.8.8.8".parse().unwrap()));
        assert!(!SSRFDefense::is_private_ip("1.1.1.1".parse().unwrap()));
    }
}