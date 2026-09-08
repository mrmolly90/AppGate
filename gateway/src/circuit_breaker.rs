use std::sync::Arc;
use std::time::{Duration, Instant};
use dashmap::DashMap;
use tokio::sync::Semaphore;
use tracing::{info, warn};

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum State {
    Closed,
    Open,
    HalfOpen,
}

pub struct CircuitBreaker {
    state: tokio::sync::RwLock<State>,
    failures: tokio::sync::RwLock<u32>,
    last_failure: tokio::sync::RwLock<Option<Instant>>,
    success_count: tokio::sync::RwLock<u32>,
    half_open_semaphore: Semaphore,
    config: crate::config::CircuitBreakerConfig,
}

impl CircuitBreaker {
    pub fn new(config: &crate::config::CircuitBreakerConfig) -> Self {
        Self {
            state: tokio::sync::RwLock::new(State::Closed),
            failures: tokio::sync::RwLock::new(0),
            last_failure: tokio::sync::RwLock::new(None),
            success_count: tokio::sync::RwLock::new(0),
            half_open_semaphore: Semaphore::new(config.half_open_max_calls as usize),
            config: config.clone(),
        }
    }

    pub async fn allow(&self) -> bool {
        let state = *self.state.read().await;
        match state {
            State::Closed => true,
            State::Open => {
                let last = *self.last_failure.read().await;
                if let Some(l) = last {
                    if l.elapsed() > Duration::from_millis(self.config.recovery_timeout_ms) {
                        info!("circuit breaker entering half-open");
                        let mut s = self.state.write().await;
                        *s = State::HalfOpen;
                        let mut sc = self.success_count.write().await;
                        *sc = 0;
                        drop(s);
                        drop(sc);
                        // Acquire permit to limit half-open calls
                        self.half_open_semaphore.try_acquire().is_ok()
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            State::HalfOpen => self.half_open_semaphore.try_acquire().is_ok(),
        }
    }

    pub async fn record_success(&self) {
        let state = *self.state.read().await;
        match state {
            State::HalfOpen => {
                let mut sc = self.success_count.write().await;
                *sc += 1;
                if *sc >= self.config.half_open_max_calls {
                    info!("circuit breaker closed after recovery");
                    let mut s = self.state.write().await;
                    *s = State::Closed;
                    let mut f = self.failures.write().await;
                    *f = 0;
                    *sc = 0;
                }
            }
            State::Closed => {
                let mut f = self.failures.write().await;
                *f = f.saturating_sub(1);
            }
            _ => {}
        }
    }

    pub async fn record_failure(&self) {
        let mut f = self.failures.write().await;
        *f += 1;
        let mut lf = self.last_failure.write().await;
        *lf = Some(Instant::now());
        if *f >= self.config.failure_threshold {
            warn!("circuit breaker opened after {} failures", *f);
            let mut s = self.state.write().await;
            *s = State::Open;
        }
    }

    pub async fn state(&self) -> State {
        *self.state.read().await
    }
}

/// Registry of circuit breakers keyed by upstream (provider:model).
pub struct CircuitBreakerRegistry {
    breakers: DashMap<String, Arc<CircuitBreaker>>,
    config: crate::config::CircuitBreakerConfig,
}

impl CircuitBreakerRegistry {
    pub fn new(config: &crate::config::CircuitBreakerConfig) -> Self {
        Self {
            breakers: DashMap::new(),
            config: config.clone(),
        }
    }

    pub async fn get_or_create(&self, key: &str) -> Arc<CircuitBreaker> {
        if let Some(cb) = self.breakers.get(key) {
            return cb.clone();
        }
        let cb = Arc::new(CircuitBreaker::new(&self.config));
        self.breakers.insert(key.to_string(), cb.clone());
        cb
    }

    pub fn len(&self) -> usize {
        self.breakers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.breakers.is_empty()
    }
}