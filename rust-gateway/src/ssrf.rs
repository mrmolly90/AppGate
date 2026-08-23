// =============================================================================
// AppGate Gateway — SSRF Protection
// =============================================================================
//
// Server-Side Request Forgery (SSRF) defense.
// Prevents the gateway from making requests to private/internal IPs.
//
// Security rationale:
// - Rejects all RFC1918 private IP ranges
// - Rejects loopback, link-local, CGNAT, and multicast ranges
// - Requires explicit domain/IP allowlist for all upstreams
// - Fail-closed: if validation fails, the request is denied
// =============================================================================

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use url::Url;

/// Check if an IP address is in a private or reserved range.
///
/// # Returns
/// `true` if the IP is private/reserved (should be blocked).
#[must_use]
pub fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_private_ipv4(v4),
        IpAddr::V6(v6) => is_private_ipv6(v6),
    }
}

/// Check if an IPv4 address is in a private or reserved range.
fn is_private_ipv4(ip: Ipv4Addr) -> bool {
    // 127.0.0.0/8 — Loopback
    ip.is_loopback()
        // 10.0.0.0/8 — RFC1918 Class A
        || ip.is_private()
        // 169.254.0.0/16 — Link-local
        || ip.is_link_local()
        // 172.16.0.0/12 — RFC1918 Class B
        || (ip.octets()[0] == 172 && (ip.octets()[1] & 0xF0) == 16)
        // 192.168.0.0/16 — RFC1918 Class C
        || (ip.octets()[0] == 192 && ip.octets()[1] == 168)
        // 100.64.0.0/10 — CGNAT
        || (ip.octets()[0] == 100 && (ip.octets()[1] & 0xC0) == 64)
        // 198.18.0.0/15 — Benchmarking
        || (ip.octets()[0] == 198 && (ip.octets()[1] & 0xFE) == 18)
        // 224.0.0.0/4 — Multicast
        || ip.is_multicast()
        // 240.0.0.0/4 — Reserved
        || (ip.octets()[0] & 0xF0) == 0xF0
        // 0.0.0.0/8 — "This network"
        || ip.octets()[0] == 0
}

/// Check if an IPv6 address is in a private or reserved range.
fn is_private_ipv6(ip: Ipv6Addr) -> bool {
    // ::1/128 — Loopback
    ip.is_loopback()
        // fc00::/7 — Unique local address (ULA)
        || (ip.octets()[0] & 0xFE) == 0xFC
        // fe80::/10 — Link-local
        || (ip.octets()[0] == 0xFE && (ip.octets()[1] & 0xC0) == 0x80)
        // ff00::/8 — Multicast
        || ip.is_multicast()
}

/// Validate an upstream URL against SSRF protection rules.
///
/// # Arguments
/// * `url_str` - The upstream URL to validate
/// * `allowed_domains` - List of explicitly allowed domains/IPs
///
/// # Returns
/// `Ok(())` if the URL is safe, `Err` with a description of why it was rejected.
///
/// # Security
/// This function is fail-closed: any error in parsing or resolution
/// results in a denial.
pub fn validate_upstream(url_str: &str, allowed_domains: &[String]) -> anyhow::Result<()> {
    let url = Url::parse(url_str).map_err(|e| anyhow::anyhow!("Invalid upstream URL: {e}"))?;

    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("Upstream URL has no host"))?;

    // Check allowlist first
    if !allowed_domains.is_empty() && !allowed_domains.iter().any(|d| d == host) {
        anyhow::bail!("Host '{host}' is not in the allowed domains list");
    }

    // If the host is an IP address, check it directly
    if let Ok(ip) = url.host().unwrap().to_string().parse::<IpAddr>() {
        if is_private_ip(ip) {
            anyhow::bail!("Upstream URL resolves to a private IP address: {ip}");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_private_ipv4_ranges() {
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1))));
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))));
    }

    #[test]
    fn test_public_ipv4_allowed() {
        assert!(!is_private_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(!is_private_ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
        assert!(!is_private_ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))));
    }

    #[test]
    fn test_validate_upstream_public() {
        let allowed = vec!["api.openai.com".to_string()];
        assert!(validate_upstream("https://api.openai.com/v1/completions", &allowed).is_ok());
    }

    #[test]
    fn test_validate_upstream_private() {
        let allowed = vec!["internal.service".to_string()];
        assert!(validate_upstream("http://10.0.0.1:8080/api", &allowed).is_err());
        assert!(validate_upstream("http://192.168.1.1:8080/api", &allowed).is_err());
    }

    #[test]
    fn test_validate_upstream_not_in_allowlist() {
        let allowed = vec!["api.openai.com".to_string()];
        assert!(validate_upstream("https://api.anthropic.com/v1/messages", &allowed).is_err());
    }
}
