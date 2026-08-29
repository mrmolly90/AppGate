//! AppGate Gateway Library
#![deny(unsafe_code)]
#![allow(dead_code)]

pub mod config;
pub mod metrics;
pub mod policy;
pub mod server;
pub mod telemetry;
pub mod tls;

#[cfg(feature = "audit")]
pub mod audit;
#[cfg(feature = "jwt-auth")]
pub mod jwt;
#[cfg(feature = "policy-engine")]
pub mod policy;
#[cfg(feature = "ratelimit")]
pub mod rate_limit;
#[cfg(feature = "ssrf-protection")]
pub mod ssrf;