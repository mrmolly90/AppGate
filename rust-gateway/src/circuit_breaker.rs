use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{info, warn};

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

pub struct CircuitBreaker {
    state: CircuitState,
    failures: u32,
    last_failure: Option<Instant>,
    success_count: u32,
    config: crate::config::CircuitBreakerConfig,
}

impl CircuitBreaker {
    pub fn new(config: &crate::config::CircuitBreakerConfig) -> Self {
        Self {
            state: CircuitState::Closed,
            failures: 0,
            last_failure: None,
            success_count: 0,
            config: config.clone(),
        }
    }

    pub fn allow(&mut self) -> bool {
        match self.state {
            CircuitState::Closed => true,
            CircuitState::Open => {
                if let Some(last) = self.last_failure {
                    if last.elapsed() > Duration::from_millis(self.config.recovery_timeout_ms) {
                        info!("circuit breaker entering half-open");
                        self.state = CircuitState::HalfOpen;
                        self.success_count = 0;
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            CircuitState::HalfOpen => self.success_count < self.config.half_open_max_calls,
        }
    }

    pub fn record_success(&mut self) {
        match self.state {
            CircuitState::HalfOpen => {
                self.success_count += 1;
                if self.success_count >= self.config.half_open_max_calls {
                    info!("circuit breaker closed after recovery");
                    self.state = CircuitState::Closed;
                    self.failures = 0;
                    self.success_count = 0;
                }
            }
            CircuitState::Closed => {
                self.failures = self.failures.saturating_sub(1);
            }
            _ => {}
        }
    }

    pub fn record_failure(&mut self) {
        self.failures += 1;
        self.last_failure = Some(Instant::now());
        if self.failures >= self.config.failure_threshold {
            warn!("circuit breaker opened after {} failures", self.failures);
            self.state = CircuitState::Open;
        }
    }

    pub fn state(&self) -> CircuitState { self.state }
}

pub struct CircuitBreakerRegistry {
    breakers: Arc<RwLock<HashMap<String, Arc<RwLock<CircuitBreaker>>>>>,
    config: crate::config::CircuitBreakerConfig,
}

impl CircuitBreakerRegistry {
    pub fn new(config: &crate::config::CircuitBreakerConfig) -> Self {
        Self {
            breakers: Arc::new(RwLock::new(HashMap::new())),
            config: config.clone(),
        }
    }

    pub async fn get(&self, key: &str) -> Option<Arc<RwLock<CircuitBreaker>>> {
        let read = self.breakers.read().await;
        read.get(key).cloned()
    }

    pub async fn get_or_create(&self, key: &str) -> Arc<RwLock<CircuitBreaker>> {
        if let Some(cb) = self.get(key).await {
            return cb;
        }
        let mut write = self.breakers.write().await;
        write.entry(key.to_string()).or_insert_with(|| {
            Arc::new(RwLock::new(CircuitBreaker::new(&self.config)))
        }).clone()
    }
}