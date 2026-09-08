use serde::Deserialize;

/// Production gateway configuration loaded from environment variables.
/// All fields have sensible defaults for immediate deployment.
#[derive(Clone, Debug, Deserialize)]
pub struct GatewayConfig {
    #[serde(default = "default_bind")]
    pub bind_addr: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default)]
    pub tls: TlsConfig,
    #[serde(default)]
    pub jwt: JwtConfig,
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
    #[serde(default)]
    pub upstream: UpstreamConfig,
    #[serde(default)]
    pub audit: AuditConfig,
    #[serde(default)]
    pub cache: CacheConfig,
    #[serde(default)]
    pub circuit_breaker: CircuitBreakerConfig,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default = "default_control_plane_url")]
    pub control_plane_url: String,
    #[serde(default = "default_environment")]
    pub environment: String,
}

#[derive(Clone, Debug, Deserialize, Default)]
pub struct TlsConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
    pub min_version: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Default)]
pub struct JwtConfig {
    pub enabled: bool,
    pub jwks_url: Option<String>,
    pub issuer: Option<String>,
    pub audience: Option<String>,
    pub key_path: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Default)]
pub struct RateLimitConfig {
    pub enabled: bool,
    #[serde(default = "default_rps")]
    pub requests_per_second: u64,
    #[serde(default = "default_burst")]
    pub burst_size: u32,
    #[serde(default = "default_window")]
    pub window_secs: u64,
}

#[derive(Clone, Debug, Deserialize, Default)]
pub struct UpstreamConfig {
    #[serde(default = "default_upstream_url")]
    pub default_url: String,
    pub connect_timeout_ms: Option<u64>,
    pub read_timeout_ms: Option<u64>,
    pub keepalive_duration_secs: Option<u64>,
    pub max_connections: Option<usize>,
}

#[derive(Clone, Debug, Deserialize, Default)]
pub struct AuditConfig {
    #[serde(default = "default_audit_endpoint")]
    pub endpoint: String,
}

#[derive(Clone, Debug, Deserialize, Default)]
pub struct CacheConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub ttl_secs: Option<u64>,
    pub max_size: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Default)]
pub struct CircuitBreakerConfig {
    #[serde(default = "default_failure_threshold")]
    pub failure_threshold: u32,
    #[serde(default = "default_recovery_timeout_ms")]
    pub recovery_timeout_ms: u64,
    #[serde(default = "default_half_open_max_calls")]
    pub half_open_max_calls: u32,
}

impl GatewayConfig {
    pub fn from_env() -> Self {
        envy::from_env::<GatewayConfig>().unwrap_or_else(|e| {
            tracing::warn!("Failed to load config from env: {}. Using defaults.", e);
            GatewayConfig::default()
        })
    }
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            bind_addr: default_bind(),
            port: default_port(),
            tls: TlsConfig::default(),
            jwt: JwtConfig::default(),
            rate_limit: RateLimitConfig::default(),
            upstream: UpstreamConfig::default(),
            audit: AuditConfig::default(),
            cache: CacheConfig::default(),
            circuit_breaker: CircuitBreakerConfig::default(),
            log_level: default_log_level(),
            control_plane_url: default_control_plane_url(),
            environment: default_environment(),
        }
    }
}

fn default_bind() -> String { "0.0.0.0".into() }
fn default_port() -> u16 { 8080 }
fn default_log_level() -> String { "info".into() }
fn default_control_plane_url() -> String { "http://appgate-control-plane:8080".into() }
fn default_environment() -> String { "production".into() }
fn default_true() -> bool { true }
fn default_rps() -> u64 { 100 }
fn default_burst() -> u32 { 150 }
fn default_window() -> u64 { 60 }
fn default_upstream_url() -> String { "".into() }
fn default_audit_endpoint() -> String { "/v1/audit/batch".into() }
fn default_failure_threshold() -> u32 { 5 }
fn default_recovery_timeout_ms() -> u64 { 30000 }
fn default_half_open_max_calls() -> u32 { 3 }